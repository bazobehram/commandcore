import base64, json
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


def test_agent_protocol_v1_crypto_vectors_are_stable():
    root = Path(__file__).resolve().parents[1]
    v = json.loads(
        (root / "packages/protocol/agent-protocol-v1-vectors.json").read_text()
    )
    assert v["protocol_version"] == "1"
    old = Ed25519PrivateKey.from_private_bytes(
        base64.b64decode(v["keys"]["old_private_seed_b64"])
    )
    new = Ed25519PrivateKey.from_private_bytes(
        base64.b64decode(v["keys"]["new_private_seed_b64"])
    )
    old_pub = base64.b64encode(
        old.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    ).decode()
    new_pub = base64.b64encode(
        new.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    ).decode()
    assert old_pub == v["keys"]["old_public_key_b64"]
    assert new_pub == v["keys"]["new_public_key_b64"]
    assert (
        base64.b64encode(old.sign(v["auth"]["message_utf8"].encode())).decode()
        == v["auth"]["signature_b64"]
    )
    assert (
        base64.b64encode(
            old.sign(v["key_rotation_prepare"]["message_utf8"].encode())
        ).decode()
        == v["key_rotation_prepare"]["old_signature_b64"]
    )
    assert (
        base64.b64encode(
            new.sign(v["key_rotation_prepare"]["message_utf8"].encode())
        ).decode()
        == v["key_rotation_prepare"]["new_signature_b64"]
    )
    assert (
        base64.b64encode(
            new.sign(v["key_rotation_confirm"]["message_utf8"].encode())
        ).decode()
        == v["key_rotation_confirm"]["new_signature_b64"]
    )
