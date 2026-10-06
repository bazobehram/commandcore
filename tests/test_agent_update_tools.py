import asyncio
from pathlib import Path


from commandcore_agent.executor import Executor
from commandcore_agent import executor as executor_module


async def _sink(stream, data):
    return None


def test_update_status_is_read_only(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("COMMANDCORE_AGENT_INSTALL_ROOT", str(tmp_path / "install"))
    monkeypatch.setenv("COMMANDCORE_UPDATE_PUBLIC_KEY_B64", "test-public-key")
    ex = Executor(delegate_full_control=False, enforce_local_ceiling=False)
    out = asyncio.run(ex.execute("e", "READ_ONLY", "agent.update.status", {}, _sink))
    assert out["status"] == "ok"
    assert out["result"]["trusted_release_key_configured"] is True


def test_update_stage_requires_full_control():
    ex = Executor(delegate_full_control=False, enforce_local_ceiling=False)
    out = asyncio.run(
        ex.execute(
            "e", "STANDARD", "agent.update.stage", {"manifest_url": "https://x"}, _sink
        )
    )
    assert out["status"] == "error"
    assert "permission_denied" in out["error"]


def test_update_activate_rejects_stage_path_outside_root(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("COMMANDCORE_UPDATE_PUBLIC_KEY_B64", "test-key")
    monkeypatch.setenv("COMMANDCORE_UPDATE_STAGE_DIR", str(tmp_path / "stage"))
    monkeypatch.setenv("COMMANDCORE_AGENT_INSTALL_ROOT", str(tmp_path / "install"))
    ex = Executor(delegate_full_control=False, enforce_local_ceiling=False)
    out = asyncio.run(
        ex.execute(
            "e",
            "FULL_CONTROL",
            "agent.update.activate",
            {"stage_metadata_path": str(tmp_path / "elsewhere" / "stage.json")},
            _sink,
        )
    )
    assert out["status"] == "error"
    assert "outside_configured_root" in out["error"]


def test_update_stage_uses_device_local_trust(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("COMMANDCORE_UPDATE_PUBLIC_KEY_B64", "LOCAL-TRUST")
    monkeypatch.setenv("COMMANDCORE_UPDATE_MANIFEST_ORIGIN", "https://updates.example")
    monkeypatch.setenv("COMMANDCORE_UPDATE_STAGE_DIR", str(tmp_path / "stage"))
    monkeypatch.setenv("COMMANDCORE_AGENT_INSTALL_ROOT", str(tmp_path / "install"))
    seen = {}

    def fake_fetch(url, allow_insecure_http=False):
        seen["url"] = url
        seen["allow"] = allow_insecure_http
        return {"version": "9.0.0"}

    def fake_verify(manifest, key):
        seen["key"] = key

    def fake_select(manifest):
        return {
            "platform": "linux",
            "architecture": "x86_64",
            "url": "https://x/a",
            "sha256": "0" * 64,
            "filename": "a",
            "size": 1,
        }

    def fake_stage(manifest, artifact, **kwargs):
        seen["root"] = kwargs["root"]
        return {"metadata_path": str(Path(kwargs["root"]) / "9.0.0" / "stage.json")}

    monkeypatch.setattr(executor_module, "fetch_manifest", fake_fetch)
    monkeypatch.setattr(executor_module, "verify_manifest", fake_verify)
    monkeypatch.setattr(executor_module, "select_artifact", fake_select)
    monkeypatch.setattr(executor_module, "stage_artifact", fake_stage)
    ex = Executor(delegate_full_control=False, enforce_local_ceiling=False)
    out = asyncio.run(
        ex.execute(
            "e",
            "FULL_CONTROL",
            "agent.update.stage",
            {"manifest_url": "https://updates.example/manifest.json"},
            _sink,
        )
    )
    assert out["status"] == "ok"
    assert seen["key"] == "LOCAL-TRUST"
    assert seen["allow"] is False


def test_update_stage_rejects_untrusted_origin(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("COMMANDCORE_UPDATE_PUBLIC_KEY_B64", "LOCAL-TRUST")
    monkeypatch.setenv("COMMANDCORE_UPDATE_MANIFEST_ORIGIN", "https://updates.example")
    monkeypatch.setenv("COMMANDCORE_UPDATE_STAGE_DIR", str(tmp_path / "stage"))
    ex = Executor(delegate_full_control=False, enforce_local_ceiling=False)
    out = asyncio.run(
        ex.execute(
            "e",
            "FULL_CONTROL",
            "agent.update.stage",
            {"manifest_url": "https://evil.example/manifest.json"},
            _sink,
        )
    )
    assert out["status"] == "error"
    assert "origin_not_allowed" in out["error"]
