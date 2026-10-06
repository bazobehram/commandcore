from argparse import Namespace
from io import StringIO

from commandcore_agent.cli import set_token
from commandcore_agent.state import AgentState, load, save


def test_set_token_from_stdin_avoids_command_argument(tmp_path, monkeypatch):
    path = tmp_path / "agent.json"
    save(
        AgentState(
            device_id="device-1",
            device_token="old-token-value-that-is-long-enough",
            private_key_b64="a",
            public_key_b64="b",
            control_url="https://api.example",
            agent_url="wss://agent.example/agent",
            display_name="box",
        ),
        path,
    )
    new_token = "new-device-token-value-that-is-long-enough-123456"
    monkeypatch.setattr("sys.stdin", StringIO(new_token + "\n"))
    assert set_token(Namespace(state=str(path), stdin=True)) == 0
    assert load(path).device_token == new_token
