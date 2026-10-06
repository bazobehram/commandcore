use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

pub const PROTOCOL_VERSION: &str = "1";

pub fn auth_message(device_id: &str, nonce: &str) -> Vec<u8> {
    format!("commandcore-agent-auth-v1\n{device_id}\n{nonce}").into_bytes()
}

pub fn rotation_prepare_message(device_id: &str, nonce: &str, new_public_key_b64: &str) -> Vec<u8> {
    format!("commandcore-key-rotation-prepare-v1\n{device_id}\n{nonce}\n{new_public_key_b64}")
        .into_bytes()
}

pub fn rotation_confirm_message(device_id: &str, rotation_id: &str) -> Vec<u8> {
    format!("commandcore-key-rotation-confirm-v1\n{device_id}\n{rotation_id}").into_bytes()
}

pub fn signing_key_from_seed_b64(seed_b64: &str) -> Result<SigningKey, String> {
    let raw = B64.decode(seed_b64).map_err(|e| e.to_string())?;
    let seed: [u8; 32] = raw
        .try_into()
        .map_err(|_| "Ed25519 seed must be 32 bytes".to_string())?;
    Ok(SigningKey::from_bytes(&seed))
}

pub fn private_seed_b64(key: &SigningKey) -> String {
    B64.encode(key.to_bytes())
}

pub fn public_key_b64(key: &SigningKey) -> String {
    B64.encode(VerifyingKey::from(key).to_bytes())
}

pub fn sign_b64(key: &SigningKey, message: &[u8]) -> String {
    B64.encode(key.sign(message).to_bytes())
}
