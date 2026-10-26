import importlib.util
import zipfile
from pathlib import Path
import pytest

p = Path(__file__).resolve().parents[1] / "scripts/check_helper_offline_dependencies.py"
spec = importlib.util.spec_from_file_location("check_wheels", p)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def wheel(root, name, version, req=None):
    dist = name.replace("-", "_")
    filename = root / f"{dist}-{version}-py3-none-any.whl"
    with zipfile.ZipFile(filename, "w") as z:
        value = f"Name: {name}\nVersion: {version}\n"
        if req:
            value += f"Requires-Dist: {req}\n"
        z.writestr(f"{dist}-{version}.dist-info/METADATA", value)
    return filename


def test_missing_transitive_dependency_rejected(tmp_path):
    wheel(tmp_path, "commandcore-agent", "1.0", "cryptography>=50")
    with pytest.raises(ValueError, match="offline dependency"):
        module.check(tmp_path)


def test_closed_dependency_set_passes(tmp_path):
    wheel(tmp_path, "commandcore-agent", "1.0", "cryptography>=50")
    wheel(tmp_path, "cryptography", "50.0")
    assert module.check(tmp_path)["complete"] is True


def test_incompatible_version_rejected(tmp_path):
    wheel(tmp_path, "commandcore-agent", "1.0", "cryptography>=50")
    wheel(tmp_path, "cryptography", "49.0")
    with pytest.raises(ValueError, match="incompatible"):
        module.check(tmp_path)


def test_untrusted_extra_file_rejected(tmp_path):
    wheel(tmp_path, "commandcore-agent", "1.0")
    (tmp_path / "install.sh").write_text("echo bad")
    with pytest.raises(ValueError, match="regular wheels"):
        module.check(tmp_path)
