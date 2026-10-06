//! CommandCore native Rust Agent candidate.
//!
//! Implements the Agent Protocol v1 network path and native executor for
//! supported CommandCore targets. Release readiness is determined by the
//! platform matrix and CI/runtime acceptance gates, not by compilation alone.

pub mod activity;
pub mod client;
pub mod enrollment;
pub mod executor;
pub mod health;
pub mod helper;
#[cfg(target_os = "linux")]
pub mod jobs;
pub mod local_ui;
pub mod network;
pub mod output;
pub mod policy;
pub mod protocol;
pub mod release;
pub mod state;

pub use protocol::{
    auth_message, public_key_b64, rotation_confirm_message, rotation_prepare_message, sign_b64,
    signing_key_from_seed_b64, PROTOCOL_VERSION,
};

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn vectors() -> Value {
        serde_json::from_str(include_str!(
            "../../../packages/protocol/agent-protocol-v1-vectors.json"
        ))
        .expect("valid protocol vectors")
    }

    #[test]
    fn protocol_vectors_match_python_reference() {
        let v = vectors();
        assert_eq!(v["protocol_version"], PROTOCOL_VERSION);
        let device = v["device_id"].as_str().unwrap();
        let old =
            signing_key_from_seed_b64(v["keys"]["old_private_seed_b64"].as_str().unwrap()).unwrap();
        let new =
            signing_key_from_seed_b64(v["keys"]["new_private_seed_b64"].as_str().unwrap()).unwrap();
        assert_eq!(
            public_key_b64(&old),
            v["keys"]["old_public_key_b64"].as_str().unwrap()
        );
        assert_eq!(
            public_key_b64(&new),
            v["keys"]["new_public_key_b64"].as_str().unwrap()
        );
        let auth = auth_message(device, v["auth"]["nonce"].as_str().unwrap());
        assert_eq!(
            String::from_utf8(auth.clone()).unwrap(),
            v["auth"]["message_utf8"].as_str().unwrap()
        );
        assert_eq!(
            sign_b64(&old, &auth),
            v["auth"]["signature_b64"].as_str().unwrap()
        );
        let prep = rotation_prepare_message(
            device,
            v["key_rotation_prepare"]["nonce"].as_str().unwrap(),
            v["keys"]["new_public_key_b64"].as_str().unwrap(),
        );
        assert_eq!(
            sign_b64(&old, &prep),
            v["key_rotation_prepare"]["old_signature_b64"]
                .as_str()
                .unwrap()
        );
        assert_eq!(
            sign_b64(&new, &prep),
            v["key_rotation_prepare"]["new_signature_b64"]
                .as_str()
                .unwrap()
        );
        let confirm = rotation_confirm_message(
            device,
            v["key_rotation_confirm"]["rotation_id"].as_str().unwrap(),
        );
        assert_eq!(
            sign_b64(&new, &confirm),
            v["key_rotation_confirm"]["new_signature_b64"]
                .as_str()
                .unwrap()
        );
    }
}
