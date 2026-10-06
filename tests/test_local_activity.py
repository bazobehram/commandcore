"""Observable execution and security gates for the local terminal timeline."""

import asyncio
import json
import sys
import uuid
from types import SimpleNamespace

import pytest

from commandcore_agent import activity, cli


@pytest.fixture(autouse=True)
def private_redactor():
    saved = activity.KNOWN.copy()
    activity.KNOWN.clear()
    yield
    activity.KNOWN.clear()
    activity.KNOWN.update(saved)


def message(tool, **args):
    return {
        "tool": tool,
        "request_id": str(uuid.uuid4()),
        "execution_id": str(uuid.uuid4()),
        "arguments": args,
        "activity": {"source": {"channel": "mcp", "client_id": "fixture-client"}},
    }


@pytest.mark.parametrize(
    "command",
    [
        "python train.py",
        "python scripts/migrate.py",
        "pytest tests/test_api.py",
        "npm test",
        "cargo test",
        "git diff",
        "docker compose ps",
        "python -u scripts/check.py",
    ],
)
def test_useful_commands_stay_visible(command):
    msg = message(
        "shell.exec", command=command, cwd="/home/user/project", timeout_ms=120000
    )
    activity.emit("REQUEST", activity.request(msg))
    safe = activity.sanitize(activity.request(msg))
    assert safe["command"] == command
    assert safe["cwd"] == "/home/user/project"
    assert safe["request_id"] == msg["request_id"]
    assert safe["source"]["client_id"] == "fixture-client"


@pytest.mark.parametrize(
    "raw,secret",
    [
        ("TOKEN=commandsecret python check.py", "commandsecret"),
        ('python check.py --password "secret with spaces"', "secret with spaces"),
        ("curl -u user:basicsecret https://example.org", "user:basicsecret"),
        ("Authorization: Bearer headersecret", "headersecret"),
        ("Cookie: session=cookiesecret", "cookiesecret"),
        ('{"api_key": "jsonsecret"}', "jsonsecret"),
        ("https://user:urlsecret@example.org/path", "urlsecret"),
        (
            "-----BEGIN "
            + "RSA PRIVATE KEY-----\nprivatefixture\n-----END RSA PRIVATE KEY-----",
            "privatefixture",
        ),
        ("eyJ" + "a" * 50 + ".encodedvalue", "a" * 50),
    ],
)
def test_secrets_never_reach_journal_or_either_renderer(raw, secret, capsys):
    activity.emit("RESULT", {"stdout": raw, "status": "ok"})
    journal = capsys.readouterr().out.strip()
    assert secret not in journal
    for as_json in [True, False]:
        assert secret not in activity.render(journal, as_json)


def test_known_env_and_split_argument_secrets():
    msg = message(
        "shell.exec",
        command="python check.py",
        argv=["curl", "--password", "argvfixture"],
        env={"MY_TOKEN": "envfixture"},
    )
    safe = activity.sanitize(activity.request(msg))
    assert "envfixture" not in json.dumps(safe)
    assert "argvfixture" not in json.dumps(safe)
    assert "envfixture" not in activity.text("program returned envfixture")
    activity.request(
        message("shell.exec", command="TOKEN=shortfixture python check.py")
    )
    assert "shortfixture" not in activity.text("shortfixture")


@pytest.mark.parametrize(
    "tool",
    [
        "fs.write",
        "fs.patch",
        "keyboard.type",
        "clipboard.read",
        "clipboard.write",
        "transfer.upload",
    ],
)
def test_payloads_are_metadata_only(tool):
    msg = message(
        tool,
        path="/tmp/config.py",
        data="payloadfixture",
        text="payloadfixture",
        patches=[{"search": "payloadfixture", "replace": "payloadfixture"}],
    )
    safe = activity.sanitize(activity.request(msg))
    assert "payloadfixture" not in json.dumps(safe)
    if tool == "fs.write":
        assert safe["bytes"] == len("payloadfixture")
    if tool == "fs.patch":
        assert safe["patch_count"] == 1
    outcome = {
        "status": "ok",
        "result": {
            "data": "payloadfixture",
            "text": "payloadfixture",
            "bytes_written": 14,
            "replacements": 1,
        },
    }
    safe = activity.sanitize(activity.result(msg, outcome, 10))
    assert "payloadfixture" not in json.dumps(safe)
    if tool.startswith("fs."):
        assert safe["changed"] is True


@pytest.mark.parametrize(
    "path,encoding,data",
    [
        ("/tmp/.env", "text", "hiddenfixture"),
        ("/home/user/.ssh/id_ed25519", "text", "hiddenfixture"),
        ("/tmp/state.json", "text", "hiddenfixture"),
        ("/tmp/binary", "base64", "hiddenfixture"),
        ("/tmp/binary", "text", "binary\x00fixture"),
    ],
)
def test_sensitive_and_binary_read_preview_suppressed(path, encoding, data):
    msg = message("fs.read", path=path, encoding=encoding)
    value = activity.sanitize(
        activity.result(
            msg,
            {
                "status": "ok",
                "result": {"data": data, "bytes": 13, "encoding": encoding},
            },
            1,
        )
    )
    assert "preview" not in value
    assert value["bytes_returned"] == 13


def test_bounds_controls_and_untrusted_journal():
    value = activity.sanitize(
        {"stdout": "line\n" * 5000 + "TOKEN=neverprint", "Authorization": "neverprint"}
    )
    assert len(value["stdout"]) < 2100
    assert "truncated" in value["stdout"]
    assert "neverprint" not in json.dumps(value)
    assert activity.render("legacy raw secret", True) is None
    assert activity.render(activity.PREFIX + "[]", True) is None
    assert (
        activity.render(activity.PREFIX + '{"event":"debug","stdout":"secret"}', True)
        is None
    )
    assert "\x1b" not in activity.text("\x1b[31mhello")


@pytest.mark.asyncio
async def test_agent_emits_real_read_edit_command_pipeline(
    tmp_path, monkeypatch, capsys
):
    path = tmp_path / "config.py"
    path.write_text("value = 1\n")
    jobs = [
        message("fs.read", path=str(path), offset=0, length=8192),
        message(
            "fs.patch",
            path=str(path),
            patches=[{"search": "value = 1", "replace": "value = 2"}],
        ),
        message("fs.read", path=str(path)),
        message(
            "shell.exec",
            cwd=str(tmp_path),
            command=f'"{sys.executable}" -c "print(\'tests pass\')"',
            timeout_ms=5000,
        ),
    ]
    for job in jobs:
        job["type"] = "job.request"
        job["permission_profile"] = "STANDARD"

    class Socket:
        close_code = None

        def __init__(self):
            self.done = asyncio.Event()
            self.results = []
            self.i = 0

        def __aiter__(self):
            return self

        async def __anext__(self):
            if self.i:
                await asyncio.wait_for(self.done.wait(), 10)
            self.done.clear()
            if self.i == len(jobs):
                raise RuntimeError("fixture complete")
            job = jobs[self.i]
            self.i += 1
            return json.dumps(job)

        async def send(self, data):
            value = json.loads(data)
            if value["type"] == "job.result":
                self.results.append(value)
                self.done.set()

        async def close(self):
            pass

    socket = Socket()
    state = SimpleNamespace(
        device_id="fixture",
        device_token="private-device-fixture",
        private_key_b64="private-key-fixture",
        pending_private_key_b64=None,
        key_generation=1,
    )

    async def connect(*_):
        return socket, {}

    monkeypatch.setattr(cli, "load", lambda _: state)
    monkeypatch.setattr(cli, "write_health", lambda *a, **k: None)
    monkeypatch.setattr(cli, "_connect_authenticated", connect)
    monkeypatch.setenv(
        "COMMANDCORE_AGENT_POLICY", str(tmp_path / "missing-policy.json")
    )
    assert (
        await cli.run_agent(
            SimpleNamespace(state=str(tmp_path / "state.json"), once=True)
        )
        == 1
    )
    lines = capsys.readouterr().out.splitlines()
    events = [
        json.loads(activity.render(line, True))
        for line in lines
        if line.startswith(activity.PREFIX)
    ]
    requests = [v for v in events if v["event"] == "REQUEST"]
    results = [v for v in events if v["event"] == "RESULT"]
    assert len(requests) == len(results) == 4
    assert all(v["status"] == "ok" for v in results)
    assert results[0]["preview"] == "value = 1\n"
    assert results[1]["changed"] is True
    assert results[2]["preview"] == "value = 2\n"
    assert results[3]["stdout"] == "tests pass\n"
    assert results[3]["exit_code"] == 0
    assert requests[3]["cwd"] == str(tmp_path)
    assert all(a["request_id"] == b["request_id"] for a, b in zip(requests, results))
    assert "private-device-fixture" not in json.dumps(events)


def test_long_paths_and_nonzero_exit_filter():
    path = "/home/operator/projects/a-reasonably-long-directory-name/src/config.py"
    assert activity.sanitize({"path": path})["path"] == path
    event = {"event": "RESULT", "status": "ok", "exit_code": 1, "timestamp_unix": 1}
    assert activity.render(activity.PREFIX + json.dumps(event), True, True)


def test_total_event_bound():
    value = activity.sanitize(
        {
            "argv": ["argument " * 500] * 32,
            "stdout": "line\n" * 5000,
            "event": "REQUEST",
            "tool": "shell.exec",
        }
    )
    assert len(json.dumps(value)) <= 16384
    assert value["tool"] == "shell.exec"
    assert value["truncated"] is True


def test_registered_secret_does_not_consume_next_line():
    activity.register_secrets(["canary-secret-must-not-display"])
    assert (
        activity.text("canary-secret-must-not-display\nresult row\n")
        == "[REDACTED]\nresult row\n"
    )


def test_unknown_tool_has_no_payload_in_either_view():
    msg = message(
        "future.unreviewed",
        command="opaque-dummy-payload",
        preview="opaque-dummy-payload",
    )
    value = {**activity.request(msg), "event": "REQUEST", "timestamp_unix": 1}
    for as_json in (True, False):
        display = activity.render(activity.PREFIX + json.dumps(value), as_json)
        assert "opaque-dummy-payload" not in display
        assert msg["request_id"] in display
        assert "unreviewed tool payload suppressed" in display


def test_python_zipapp_loads_shared_redaction_policy(tmp_path):
    import shutil
    import subprocess
    import zipapp
    from pathlib import Path

    source = tmp_path / "package"
    source.mkdir()
    shutil.copytree(
        Path(activity.__file__).parent,
        source / "commandcore_agent",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    (source / "__main__.py").write_text(
        "from commandcore_agent.cli import main\nraise SystemExit(main())\n"
    )
    artifact = tmp_path / "agent.pyz"
    zipapp.create_archive(source, artifact, compressed=True)
    result = subprocess.run(
        [sys.executable, str(artifact), "--version"], capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == cli.__version__
