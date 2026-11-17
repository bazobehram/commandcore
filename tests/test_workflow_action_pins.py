"""Regression coverage for immutable GitHub Actions references."""

import runpy
from pathlib import Path

scan_workflows = runpy.run_path(
    str(Path(__file__).resolve().parents[1] / "scripts" / "check_workflow_action_pins.py")
)["scan_workflows"]


def test_accepts_full_sha_and_local_actions(tmp_path: Path) -> None:
    (tmp_path / "ok.yml").write_text(
        "jobs:\n  test:\n    steps:\n"
        "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4\n"
        "      - uses: ./local-action\n",
        encoding="utf-8",
    )
    assert scan_workflows(tmp_path) == []


def test_rejects_tag_and_container_actions(tmp_path: Path) -> None:
    (tmp_path / "unsafe.yml").write_text(
        "steps:\n  - uses: actions/checkout@v4\n"
        "  - uses: docker://alpine:latest\n",
        encoding="utf-8",
    )
    failures = scan_workflows(tmp_path)
    assert len(failures) == 2
    assert all("full commit SHA" in failure for failure in failures)


def test_rejects_empty_workflow_directory(tmp_path: Path) -> None:
    assert "no workflow YAML files" in scan_workflows(tmp_path)[0]
