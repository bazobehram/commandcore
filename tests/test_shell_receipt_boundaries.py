"""Redaction must operate before bounded display projection."""

import pytest
from commandcore_server.shell_receipt import build_shell_card

FIXTURE = "ghp_" + "fixture" * 5


def card(command, **payload):
    return build_shell_card({"command": command}, {"status": "ok", **payload})


@pytest.mark.parametrize(("field", "limit"), [("stdout", 4096), ("stderr", 2048)])
def test_credential_crossing_output_boundary_is_masked(field, limit):
    text = "x" * (limit - 10) + " " + FIXTURE
    result = card("git status", **{field: text})
    assert "ghp_" not in result[field]
    assert "fixture" not in result[field]
    assert result["truncated"]
    assert len(result[field]) <= limit


def test_private_key_marker_crossing_boundary_withholds_preview():
    text = "x" * 4080 + "\n-----BEGIN RSA PRIVATE KEY-----\nfixture\n"
    result = card("git status", stdout=text)
    assert result["stdout"] == "[sensitive output withheld]"
    assert result["truncated"]


def test_long_source_preview_redacts_before_clipping():
    command = "echo " + "x" * 2385 + " " + FIXTURE + "\n" + "# line\n" * 500
    result = card(command, stdout="output")
    assert result["command_visibility"] == "shortened"
    assert "ghp_" not in result["command"]
    assert "fixture" not in result["command"]
    assert result["stdout"] == ""


def test_oversized_output_is_not_partially_scanned():
    result = card("git status", stdout="x" * 262145)
    assert result["stdout"] == "[output preview limit exceeded]"
    assert result["truncated"]


def test_oversized_command_does_not_return_unscanned_prefix():
    result = card("echo " + "x" * 262145, stdout="output")
    assert result["command_visibility"] == "withheld"
    assert not result["command"]
    assert not result["stdout"]


def test_plain_output_remains_visible_and_bounded():
    result = card("git status", stdout="clean", stderr="x" * 2050)
    assert result["stdout"] == "clean"
    assert result["stderr"] == "x" * 2048
    assert result["truncated"]
