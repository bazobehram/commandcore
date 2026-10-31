"""Tag-release image metadata identity gate characterization tests."""

import pytest

from scripts.verify_image_identity import SOURCE, verify

COMMIT = "a" * 40
IMAGE = "sha256:" + "b" * 64


def test_verified_image_identity_is_report_only():
    report = verify(
        expected_commit=COMMIT,
        image_id=IMAGE,
        revision=COMMIT,
        source=SOURCE,
    )
    assert report["gate"] == "PASS"
    assert report["image_id"] == IMAGE
    assert "not independent artifact" in report["note"]


@pytest.mark.parametrize(
    "args",
    [
        {"expected_commit": ""},
        {"expected_commit": "A" * 40},
        {"expected_commit": COMMIT + "a"},
        {"image_id": "commandcore:latest"},
        {"image_id": "sha256:abc"},
        {"revision": "c" * 40},
        {"revision": ""},
        {"source": "<no value>"},
        {"source": "https://example.org/not-commandcore"},
    ],
)
def test_missing_or_untrusted_metadata_fails_closed(args):
    kwargs = dict(
        expected_commit=COMMIT, image_id=IMAGE, revision=COMMIT, source=SOURCE
    )
    kwargs.update(args)
    with pytest.raises(ValueError):
        verify(**kwargs)
