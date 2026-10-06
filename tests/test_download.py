import http.server
import subprocess
import threading

import pytest

from commandcore_agent.download import DownloadFailure, download, download_bytes


@pytest.fixture
def origin():
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(500 if self.path.startswith("/error") else 200)
            self.end_headers()
            self.wfile.write(b"bounded download")

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    server.server_close()
    thread.join()


def test_download_real_http(origin):
    assert (
        download_bytes(origin, max_bytes=100, allow_loopback=True)
        == b"bounded download"
    )


def test_download_http_error_is_sanitized(origin, tmp_path):
    with pytest.raises(DownloadFailure, match="stage=HTTP") as error:
        download(
            origin + "/error?secret=never-print",
            tmp_path / "out",
            max_bytes=100,
            allow_loopback=True,
        )
    assert "secret" not in str(error.value)
    assert not (tmp_path / "out").exists()


def test_download_limit(origin):
    with pytest.raises(DownloadFailure, match="stage=HTTP_size"):
        download_bytes(origin, max_bytes=2, allow_loopback=True)


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com",
        "https://user:password@example.com",
        "https://example.com/#fragment",
        "file:///tmp/x",
    ],
)
def test_download_safe_url(url):
    with pytest.raises(ValueError, match="download_requires_https"):
        download_bytes(url, max_bytes=100)


@pytest.mark.parametrize(
    "code,stage", [(6, "DNS"), (7, "TCP"), (60, "TLS"), (28, "deadline")]
)
def test_failure_diagnostics(monkeypatch, tmp_path, code, stage):
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, code)
    )
    with pytest.raises(DownloadFailure, match="stage=" + stage):
        download("https://example.com/?token=secret", tmp_path / "out", max_bytes=100)


def test_curl_policy_and_outer_deadline(monkeypatch, tmp_path):
    def timeout(command, **kwargs):
        assert "--happy-eyeballs-timeout-ms" in command
        assert command[command.index("--happy-eyeballs-timeout-ms") + 1] == "250"
        assert "--insecure" not in command and "--location" not in command
        assert kwargs["timeout"] == 4
        raise subprocess.TimeoutExpired(command, 4)

    monkeypatch.setattr(subprocess, "run", timeout)
    with pytest.raises(DownloadFailure, match="overall_timeout"):
        download("https://example.com", tmp_path / "out", max_bytes=100, timeout=2)
