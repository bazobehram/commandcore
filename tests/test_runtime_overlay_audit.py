"""No privileged Docker access is needed for these source-overlay gate tests."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


def gate():
    path = Path(__file__).resolve().parents[1] / "scripts/runtime_overlay_audit.py"
    spec = importlib.util.spec_from_file_location("runtime_overlay_audit", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def source_root(tmp_path):
    root = tmp_path / "repo"
    (root / "apps/server/commandcore_server").mkdir(parents=True)
    (root / "apps/web").mkdir(parents=True)
    return root


def mount(file: Path, name: str = "tools.py", *, target: str | None = None):
    return {
        "Type": "bind",
        "Source": str(file),
        "Destination": target
        or "/usr/local/lib/python3.13/site-packages/commandcore_server/" + name,
    }


def test_identical_mount_is_reported_but_not_clean_immutable(tmp_path, monkeypatch):
    m = gate()
    root = source_root(tmp_path)
    source = root / "apps/server/commandcore_server/tools.py"
    source.write_text("identical")
    override = tmp_path / "hotfix.py"
    override.write_text("identical")
    records = [mount(override)]
    monkeypatch.setattr(m, "inspect_mounts", lambda _container: records)
    report, blocked = m.audit("demo", root, strict=False)
    assert report["overrides"] == [
        {
            "target": "apps/server/commandcore_server/tools.py",
            "status": "matches_source",
        }
    ]
    assert blocked is False
    report, blocked = m.audit("demo", root, strict=True)
    assert blocked is True
    assert report["immutable_code_gate"] == "BLOCK"


def test_changed_file_blocks_even_without_strict(tmp_path, monkeypatch):
    m = gate()
    root = source_root(tmp_path)
    (root / "apps/server/commandcore_server/tools.py").write_text("new")
    override = tmp_path / "tools.py"
    override.write_text("old")
    monkeypatch.setattr(m, "inspect_mounts", lambda _container: [mount(override)])
    report, blocked = m.audit("demo", root, strict=False)
    assert blocked
    assert report["nonmatching_override_count"] == 1
    assert report["overrides"][0]["status"] == "differs_from_source"


def test_removed_or_unknown_source_blocks(tmp_path):
    m = gate()
    root = source_root(tmp_path)
    override = tmp_path / "old.py"
    override.write_text("legacy")
    findings = m.classify_overrides([mount(override, name="old.py")], root)
    assert findings[0]["status"] == "not_in_source"
    missing_override = m.classify_overrides([mount(tmp_path / "missing.py")], root)
    assert missing_override[0]["status"] == "missing_override_file"


def test_data_mounts_are_not_code_overrides(tmp_path):
    m = gate()
    root = source_root(tmp_path)
    mounts = [
        {"Type": "volume", "Source": "data", "Destination": "/data"},
        {
            "Type": "bind",
            "Source": str(tmp_path / "host"),
            "Destination": "/distribution",
        },
        {"Type": "tmpfs", "Source": "", "Destination": "/tmp"},
    ]
    assert m.classify_overrides(mounts, root) == []


def test_web_overlay_maps_to_web_source(tmp_path):
    m = gate()
    root = source_root(tmp_path)
    page = root / "apps/web/panel.js"
    page.write_text("source")
    override = tmp_path / "panel.js"
    override.write_text("source")
    finding = m.classify_overrides(
        [
            mount(
                override,
                target="/usr/local/share/commandcore/web/panel.js",
            )
        ],
        root,
    )
    assert finding[0]["target"] == "apps/web/panel.js"
    assert finding[0]["status"] == "matches_source"


def test_bad_target_rejected_without_reading_files():
    m = gate()
    with pytest.raises(ValueError):
        m.app_relative_path("/usr/local/share/commandcore/web/../../secret")


def test_no_overlays_passes_without_proving_image_parity(tmp_path, monkeypatch):
    m = gate()
    root = source_root(tmp_path)
    monkeypatch.setattr(m, "inspect_mounts", lambda _container: [])
    report, blocked = m.audit("demo", root, strict=True)
    assert blocked is False
    assert "image identity" in report["note"]
