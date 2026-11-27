"""Runtime parity gate tests; no Docker privileges required."""

import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/runtime_release_parity.py"
SPEC = importlib.util.spec_from_file_location("runtime_release_parity", SCRIPT)
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)
IMAGE = "sha256:" + "a" * 64
REVISION = "b" * 40


def test_inventory_reads_source_and_web_but_ignores_cache(tmp_path):
    (tmp_path / "__pycache__").mkdir()
    (tmp_path / "__pycache__" / "x.pyc").write_bytes(b"cache")
    (tmp_path / "mcp.py").write_text("source")
    result = gate.inventory({"apps/server/commandcore_server": tmp_path})
    assert list(result) == ["apps/server/commandcore_server/mcp.py"]
    assert len(next(iter(result.values()))) == 64


def test_inventory_rejects_symlink(tmp_path):
    (tmp_path / "real").write_text("content")
    (tmp_path / "alias").symlink_to(tmp_path / "real")
    with pytest.raises(ValueError, match="nonregular"):
        gate.inventory({"apps/web": tmp_path})


@pytest.mark.parametrize(
    "destination",
    [
        "/usr",
        "/usr/local/share/commandcore/web",
        "/usr/local/share/commandcore/web/panel.js",
        "/usr/local/lib/python3.13/site-packages",
    ],
)
def test_application_parent_and_child_mounts_block(destination):
    roots = [
        "/usr/local/share/commandcore/web",
        "/usr/local/lib/python3.13/site-packages/commandcore_server",
    ]
    assert gate.intersecting_mounts([{"Destination": destination}], roots)


def test_data_and_distribution_mounts_are_permitted():
    assert not gate.intersecting_mounts(
        [{"Destination": "/data"}, {"Destination": "/distribution"}],
        ["/usr/local/share/commandcore/web"],
    )


def test_compare_detects_changed_missing_and_extra():
    assert gate.compare({"a": "1", "b": "2"}, {"a": "3", "c": "4"}) == {
        "changed": ["a"],
        "missing": ["b"],
        "extra": ["c"],
    }


def fixture(monkeypatch, image=IMAGE, label=REVISION, mounts=(), actual=None):
    expected = {"apps/web/widget.html": "hash"}
    monkeypatch.setattr(gate, "source_inventory", lambda _: (REVISION, expected))
    monkeypatch.setattr(
        gate,
        "container_identity",
        lambda _: ("container", image, "start", list(mounts)),
    )
    monkeypatch.setattr(
        gate,
        "live_inventory",
        lambda _: {
            "roots": ["/usr/local/share/commandcore/web", "/server"],
            "files": expected if actual is None else actual,
        },
    )
    monkeypatch.setattr(gate, "run", lambda *_: label)


def test_exact_image_source_and_assets_pass(monkeypatch, tmp_path):
    fixture(monkeypatch)
    assert gate.audit("demo", tmp_path, IMAGE)["gate"] == "PASS"


@pytest.mark.parametrize(
    "kwargs, problem",
    [
        ({"image": "sha256:" + "c" * 64}, "image_id_mismatch"),
        ({"label": "wrong"}, "source_revision_mismatch"),
        ({"mounts": [{"Destination": "/usr/local/share"}]}, "application_mounts"),
        (
            {"actual": {"apps/web/widget.html": "different"}},
            "application_bytes_mismatch",
        ),
    ],
)
def test_gate_blocks_each_drift_independently(monkeypatch, tmp_path, kwargs, problem):
    fixture(monkeypatch, **kwargs)
    report = gate.audit("demo", tmp_path, IMAGE)
    assert report["gate"] == "BLOCK"
    assert problem in report["problems"]


def test_restarted_container_fails_closed(monkeypatch, tmp_path):
    fixture(monkeypatch)
    identities = iter([("id", IMAGE, "start", []), ("id", IMAGE, "restart", [])])
    monkeypatch.setattr(gate, "container_identity", lambda _: next(identities))
    with pytest.raises(ValueError, match="identity changed"):
        gate.audit("demo", tmp_path, IMAGE)
