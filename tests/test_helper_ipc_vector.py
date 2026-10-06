from __future__ import annotations

import base64
import hashlib
import hmac
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_helper_ipc_vector_matches_python_reference_canonicalization():
    v = json.loads((ROOT / "packages/protocol/helper-ipc-v1-vector.json").read_text())
    canonical = json.dumps(
        v["payload"], sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    assert canonical.decode() == v["canonical_utf8"]
    secret = base64.b64decode(v["secret_b64"], validate=True)
    assert (
        hmac.new(secret, canonical, hashlib.sha256).hexdigest() == v["hmac_sha256_hex"]
    )


def test_rust_helper_unit_test_consumes_same_vector():
    source = (ROOT / "agent/rust/src/helper.rs").read_text()
    assert "helper-ipc-v1-vector.json" in source
    assert "helper_hmac_vector_matches_python_reference" in source
