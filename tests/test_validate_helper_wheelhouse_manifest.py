import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

path = (
    Path(__file__).resolve().parents[1]
    / "scripts/validate_helper_wheelhouse_manifest.py"
)
spec = importlib.util.spec_from_file_location("inventory", path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def example(tmp_path):
    wheelhouse = tmp_path / "wheels"
    wheelhouse.mkdir()
    wheel = wheelhouse / "commandcore_agent-1.0-py3-none-any.whl"
    wheel.write_bytes(b"fixture")
    inventory = tmp_path / "inventory.json"
    inventory.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "product": "commandcore-helper-wheelhouse",
                "wheels": [
                    {
                        "name": wheel.name,
                        "sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
                        "size": wheel.stat().st_size,
                    }
                ],
            }
        )
    )
    return wheelhouse, inventory, wheel


def test_valid_inventory(tmp_path):
    root, manifest, _ = example(tmp_path)
    assert module.validate(root, manifest)["wheel_count"] == 1


def test_tamper_rejected(tmp_path):
    root, manifest, wheel = example(tmp_path)
    wheel.write_bytes(b"changed")
    with pytest.raises(ValueError, match="checksum"):
        module.validate(root, manifest)


def test_unexpected_file_rejected(tmp_path):
    root, manifest, _ = example(tmp_path)
    (root / "extra.sh").write_text("invalid")
    with pytest.raises(ValueError, match="unexpected"):
        module.validate(root, manifest)


def test_symlink_rejected(tmp_path):
    root, manifest, wheel = example(tmp_path)
    wheel.unlink()
    target = tmp_path / "external"
    target.write_bytes(b"fixture")
    wheel.symlink_to(target)
    with pytest.raises(ValueError, match="unsafe"):
        module.validate(root, manifest)


def test_duplicate_inventory_rejected(tmp_path):
    root, manifest, _ = example(tmp_path)
    data = json.loads(manifest.read_text())
    data["wheels"].append(data["wheels"][0])
    manifest.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="duplicate"):
        module.validate(root, manifest)
