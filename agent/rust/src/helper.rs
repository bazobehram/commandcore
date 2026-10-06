use crate::{
    output::OutputSink,
    policy::{load_local_policy, PermissionProfile},
};
#[cfg(unix)]
use anyhow::Context;
use anyhow::{anyhow, Result};
#[cfg(any(unix, test))]
use hmac::{Hmac, Mac};
#[cfg(unix)]
use rand::{distributions::Alphanumeric, Rng};
#[cfg(any(unix, test))]
use serde_json::Map;
use serde_json::{json, Value};
#[cfg(any(unix, test))]
use sha2::Sha256;
#[cfg(unix)]
use std::time::{SystemTime, UNIX_EPOCH};
use std::{env, fs, path::PathBuf};

#[derive(Clone, Debug)]
pub struct HelperClient {
    pub socket_path: PathBuf,
    pub secret_path: PathBuf,
}

impl Default for HelperClient {
    fn default() -> Self {
        Self {
            socket_path: env::var("COMMANDCORE_HELPER_SOCKET")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("/run/commandcore/helper.sock")),
            secret_path: env::var("COMMANDCORE_HELPER_SECRET")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("/etc/commandcore/helper.key")),
        }
    }
}

#[cfg(any(unix, test))]
fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = Map::new();
            for key in keys {
                out.insert(key.clone(), canonicalize(&map[key]));
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(canonicalize).collect()),
        other => other.clone(),
    }
}

#[cfg(any(unix, test))]
fn canonical_bytes(payload: &Value) -> Result<Vec<u8>> {
    let mut body = payload.clone();
    if let Some(obj) = body.as_object_mut() {
        obj.remove("mac");
    }
    Ok(serde_json::to_vec(&canonicalize(&body))?)
}

impl HelperClient {
    #[cfg(unix)]
    fn signed(&self, mut payload: Value) -> Result<Value> {
        let mut secret = fs::read(&self.secret_path)
            .with_context(|| format!("read helper secret {}", self.secret_path.display()))?;
        while secret.last().is_some_and(|b| b.is_ascii_whitespace()) {
            secret.pop();
        }
        if secret.len() < 32 {
            return Err(anyhow!("helper secret must contain at least 32 bytes"));
        }
        let obj = payload
            .as_object_mut()
            .context("helper payload must be object")?;
        obj.entry("request_id")
            .or_insert_with(|| Value::String(uuid::Uuid::new_v4().to_string()));
        obj.entry("timestamp").or_insert_with(|| {
            Value::from(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            )
        });
        obj.entry("nonce").or_insert_with(|| {
            let nonce: String = rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(32)
                .map(char::from)
                .collect();
            Value::String(nonce)
        });
        let bytes = canonical_bytes(&payload)?;
        let mut mac = Hmac::<Sha256>::new_from_slice(&secret)
            .map_err(|_| anyhow!("invalid helper HMAC key"))?;
        mac.update(&bytes);
        payload.as_object_mut().unwrap().insert(
            "mac".into(),
            Value::String(hex::encode(mac.finalize().into_bytes())),
        );
        Ok(payload)
    }

    #[cfg(unix)]
    async fn request(&self, payload: Value, output: Option<&OutputSink>) -> Result<Value> {
        use tokio::{
            io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
            net::UnixStream,
            time::{timeout, Duration},
        };
        let stream = timeout(
            Duration::from_secs(5),
            UnixStream::connect(&self.socket_path),
        )
        .await??;
        let (read_half, mut write_half) = stream.into_split();
        let signed = self.signed(payload)?;
        let mut encoded = serde_json::to_vec(&signed)?;
        encoded.push(b'\n');
        write_half.write_all(&encoded).await?;
        write_half.flush().await?;
        let mut reader = BufReader::new(read_half);
        let mut line = String::new();
        loop {
            line.clear();
            let n = timeout(Duration::from_secs(3605), reader.read_line(&mut line)).await??;
            if n == 0 {
                return Err(anyhow!("privileged helper closed without final result"));
            }
            if line.len() > 32 * 1024 * 1024 {
                return Err(anyhow!("helper response exceeded max frame"));
            }
            let msg: Value = serde_json::from_str(&line)?;
            match msg.get("type").and_then(Value::as_str).unwrap_or("") {
                "output" => {
                    if let Some(sink) = output {
                        sink.send(
                            msg.get("stream")
                                .and_then(Value::as_str)
                                .unwrap_or("stdout"),
                            msg.get("data").and_then(Value::as_str).unwrap_or(""),
                        )
                        .await;
                    }
                }
                "result" => {
                    return Ok(msg.get("outcome").cloned().unwrap_or_else(
                        || json!({"status":"error","error":"invalid_helper_result"}),
                    ))
                }
                "probe" => return Ok(msg),
                "error" => {
                    return Ok(
                        json!({"status":"error","error":msg.get("error").and_then(Value::as_str).unwrap_or("helper_error")}),
                    )
                }
                _ => {}
            }
        }
    }

    #[cfg(not(unix))]
    async fn request(&self, _payload: Value, _output: Option<&OutputSink>) -> Result<Value> {
        Err(anyhow!(
            "privileged helper IPC is not implemented on this platform"
        ))
    }

    pub async fn probe(&self) -> Value {
        self.request(json!({"action":"probe"}), None)
            .await
            .unwrap_or_else(|_| json!({"available":false,"max_permission_profile":"STANDARD"}))
    }

    pub async fn execute(
        &self,
        execution_id: &str,
        tool: &str,
        arguments: Value,
        output: &OutputSink,
    ) -> Result<Value> {
        self.request(
            json!({
                "action":"execute",
                "execution_id":execution_id,
                "permission_profile":"FULL_CONTROL",
                "tool":tool,
                "arguments":arguments,
            }),
            Some(output),
        )
        .await
    }

    pub async fn cancel(&self, execution_id: &str) -> Result<Value> {
        self.request(json!({"action":"cancel","execution_id":execution_id}), None)
            .await
    }
}

pub async fn runtime_capabilities(version: &str) -> Value {
    let policy = load_local_policy();
    let helper = HelperClient::default();
    let probe = if policy.configured_max == PermissionProfile::FullControl {
        helper.probe().await
    } else {
        json!({"available":false})
    };
    let helper_ok = policy.configured_max == PermissionProfile::FullControl
        && probe
            .get("available")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        && probe.get("max_permission_profile").and_then(Value::as_str) == Some("FULL_CONTROL");
    let effective = match policy.configured_max {
        PermissionProfile::ReadOnly => PermissionProfile::ReadOnly,
        PermissionProfile::FullControl if helper_ok => PermissionProfile::FullControl,
        _ => PermissionProfile::Standard,
    };
    let rollout_path = env::var("COMMANDCORE_AGENT_ROLLOUT_STATE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/opt/commandcore-agent/rollout.json"));
    let rollout: Value = fs::read(&rollout_path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or(Value::Null);
    let command_exists = |name: &str| -> bool {
        env::var_os("PATH")
            .map(|paths| env::split_paths(&paths).any(|p| p.join(name).is_file()))
            .unwrap_or(false)
    };
    let update_trust =
        !policy.update_public_key_b64.is_empty() && !policy.update_manifest_origins.is_empty();
    let mut capabilities = json!({
        "agent_implementation":"rust",
        "filesystem":true,"shell":true,"process":true,"system":true,"transfer":true,
        "git":command_exists("git"),"docker":helper_ok && command_exists("docker"),
        "services":helper_ok,"packages":helper_ok,"system_power":helper_ok,
        "browser":false,"desktop":false,"screen":false,"keyboard":false,"mouse":false,"clipboard":false,
        "privileged_helper":helper_ok,
        "agent_update":true,"agent_update_version":"1",
        "configured_max_permission_profile":policy.configured_max.as_str(),
        "policy_error":policy.policy_error,
        "local_max_permission_profile":effective.as_str(),
        "privileged_helper_version":probe.get("helper_version").cloned().unwrap_or(Value::Null),
        "filesystem_version":"1","shell_version":"1","process_version":"1","system_version":"1","transfer_version":"1",
        "git_version":"1","docker_version":"1","services_version":"1","packages_version":"1","system_power_version":"1",
        "update_rollout_status":rollout.get("status").cloned().unwrap_or(Value::Null),
        "update_candidate_version":rollout.get("candidate_version").cloned().unwrap_or(Value::Null),
        "agent_update_trust_configured":update_trust,
        "native_agent_version":version,
    });
    capabilities["structured_process_filters"] = json!(cfg!(target_os = "linux"));
    capabilities["search_exclusions"] = json!(true);
    capabilities["host_health"] = json!(cfg!(target_os = "linux"));
    capabilities["persistent_output_metadata"] = json!(cfg!(target_os = "linux"));
    #[cfg(target_os = "linux")]
    {
        capabilities["agent_process_id"] = json!(std::process::id());
        capabilities["agent_process_start"] = json!(crate::jobs::identity(std::process::id()).ok());
        capabilities["agent_boot_id"] =
            json!(fs::read_to_string("/proc/sys/kernel/random/boot_id")
                .ok()
                .map(|s| s.trim().to_string()));
    }
    capabilities
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

    #[test]
    fn helper_hmac_vector_matches_python_reference() {
        let v: Value = serde_json::from_str(include_str!(
            "../../../packages/protocol/helper-ipc-v1-vector.json"
        ))
        .unwrap();
        let secret = B64.decode(v["secret_b64"].as_str().unwrap()).unwrap();
        let payload = v["payload"].clone();
        let canonical = canonical_bytes(&payload).unwrap();
        assert_eq!(
            String::from_utf8(canonical.clone()).unwrap(),
            v["canonical_utf8"].as_str().unwrap()
        );
        let mut mac = Hmac::<Sha256>::new_from_slice(&secret).unwrap();
        mac.update(&canonical);
        assert_eq!(
            hex::encode(mac.finalize().into_bytes()),
            v["hmac_sha256_hex"].as_str().unwrap()
        );
    }
}
