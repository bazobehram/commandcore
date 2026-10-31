"""Validate published OCI image identity metadata without authorizing deployment."""

from __future__ import annotations

import argparse
import json
import re
import sys

REVISION = re.compile(r"^[0-9a-f]{40}$")
IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
SOURCE = "https://github.com/bazobehram/commandcore"


def verify(*, expected_commit: str, image_id: str, revision: str, source: str) -> dict:
    if type(expected_commit) is not str or not REVISION.fullmatch(expected_commit):
        raise ValueError("invalid trusted source commit")
    if type(image_id) is not str or not IMAGE_ID.fullmatch(image_id):
        raise ValueError("invalid immutable local image ID")
    if revision != expected_commit:
        raise ValueError("missing or incorrect image revision label")
    if source != SOURCE:
        raise ValueError("missing or incorrect image source label")
    return {
        "gate": "PASS",
        "source_commit": expected_commit,
        "image_id": image_id,
        "note": (
            "Published image identity consistency only, not independent artifact "
            "attestation, production deployment approval, or runtime parity."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--source", required=True)
    args = parser.parse_args()
    try:
        report = verify(
            expected_commit=args.expected_commit,
            image_id=args.image_id,
            revision=args.revision,
            source=args.source,
        )
    except ValueError:
        print(json.dumps({"gate": "BLOCKED", "reason": "OCI image identity mismatch"}))
        return 2
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
