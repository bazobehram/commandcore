from pathlib import Path


def test_operator_explicit_gate():
    script = (
        Path(__file__).resolve().parents[1] / "scripts/bootstrap_runner_account.sh"
    ).read_text()
    assert '"--apply"' in script
    assert "EUID" in script
    assert "useradd --create-home" in script
    assert "docker sudo wheel lxd adm" in script
    assert "No token, service or Docker permissions configured." in script
