import json
from commandcore_agent.runtime_health import write_health


def test_runtime_health_marker_is_atomic_and_secret_free(tmp_path):
    path = tmp_path / "health.json"
    write_health(
        path,
        version="0.6.0",
        device_id="dev-1",
        protocol_version="1",
        key_generation=2,
        connected=True,
    )
    data = json.loads(path.read_text())
    assert data["version"] == "0.6.0"
    assert data["connected"] is True
    assert data["device_id"] == "dev-1"
    assert "token" not in data and "private" not in data
