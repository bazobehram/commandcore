import importlib.util
from pathlib import Path
import pytest

script = Path(__file__).resolve().parents[1] / "scripts/helper_identity_guard.py"
spec = importlib.util.spec_from_file_location("guard", script)
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


def fixture(tmp_path):
    home = tmp_path / "user"
    (home / ".local/bin").mkdir(parents=True)
    (home / ".local/share/commandcore-agent/releases").mkdir(parents=True)
    (home / ".local/bin/commandcore-agent").write_text("existing")
    return home


def test_existing_agent_is_preserved(tmp_path):
    home = fixture(tmp_path)
    result = guard.inspect_agent(home, "ortamzeka")
    assert result["agent_replacement_allowed"] is False
    assert result["reenrollment_allowed"] is False
    assert result["service_restart_allowed"] is False
    assert (home / ".local/bin/commandcore-agent").read_text() == "existing"


def test_missing_agent_refused(tmp_path):
    home = tmp_path / "empty"
    home.mkdir()
    with pytest.raises(ValueError, match="existing user Agent"):
        guard.inspect_agent(home, "ortamzeka")


def test_untrusted_username_refused(tmp_path):
    home = fixture(tmp_path)
    with pytest.raises(ValueError, match="username"):
        guard.inspect_agent(home, "../root")


def test_symlinked_home_refused(tmp_path):
    home = fixture(tmp_path)
    link = tmp_path / "linked"
    link.symlink_to(home, target_is_directory=True)
    with pytest.raises(ValueError, match="home"):
        guard.inspect_agent(link, "ortamzeka")
