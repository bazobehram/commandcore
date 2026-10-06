//! Agent-initiated enrollment: locally generated identity, explicit browser approval.
use crate::{
    client, helper,
    protocol::{private_seed_b64, public_key_b64, sign_b64, signing_key_from_seed_b64},
    state::{self, AgentState},
};
use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::RngCore;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Write,
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use url::Url;

fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}
fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .context("Invalid enrollment response")
}

pub async fn enroll_url(
    origin: String,
    name: Option<String>,
    path: Option<PathBuf>,
    no_connect: bool,
    insecure: bool,
) -> Result<()> {
    let base = Url::parse(&origin)?;
    let loopback = matches!(base.host_str(), Some("127.0.0.1" | "localhost" | "::1"));
    if base.scheme() != "https" && !(insecure && loopback && base.scheme() == "http") {
        return Err(anyhow!(
            "HTTPS required; HTTP allowed only for explicit loopback development"
        ));
    }
    if !base.username().is_empty()
        || base.password().is_some()
        || base.query().is_some()
        || base.fragment().is_some()
        || base.path() != "/"
    {
        return Err(anyhow!(
            "Use a server origin without credentials, path or query"
        ));
    }
    let path = path.unwrap_or_else(state::default_state_path);
    if path.exists() {
        return Err(anyhow!("Identity already exists; use status or rotate-key"));
    }
    let pending = path.with_file_name("enrollment.pending.json");
    let hostname = hostname::get()?.to_string_lossy().to_string();
    let origin = base.as_str().trim_end_matches('/').to_string();
    let mut identity = if pending.exists() {
        state::load(&pending)?
    } else {
        let key = client::new_signing_key();
        let mut credential = [0u8; 40];
        rand::rngs::OsRng.fill_bytes(&mut credential);
        let mut websocket = base.clone();
        websocket
            .set_scheme(if base.scheme() == "https" {
                "wss"
            } else {
                "ws"
            })
            .map_err(|()| anyhow!("Invalid Agent URL"))?;
        websocket.set_path("/agent");
        let identity = AgentState {
            device_id: uuid::Uuid::new_v4().to_string(),
            device_token: URL_SAFE_NO_PAD.encode(credential),
            private_key_b64: private_seed_b64(&key),
            public_key_b64: public_key_b64(&key),
            control_url: origin.clone(),
            agent_url: websocket.to_string(),
            display_name: name.unwrap_or_else(|| hostname.clone()),
            key_generation: 1,
            pending_private_key_b64: None,
            pending_public_key_b64: None,
            pending_rotation_id: None,
            state_version: 2,
        };
        state::save(&identity, &pending)?;
        identity
    };
    if identity.control_url != origin {
        return Err(anyhow!("Pending enrollment belongs to another server"));
    }
    let mut saved: Value = serde_json::from_slice(&fs::read(&pending)?)?;
    if !identity.device_id.is_empty()
        && !identity.device_token.is_empty()
        && saved.get("enrollment_id").and_then(Value::as_str).is_some()
    {
        if let Ok((mut ws, _)) =
            client::connect_authenticated(&identity, &identity.private_key_b64).await
        {
            ws.close(None).await?;
            state::save(&identity, &path)?;
            fs::remove_file(&pending)?;
            println!("[OK] Approved device identity recovered securely.");
            if no_connect {
                return Ok(());
            }
            let code = client::run_agent(path, false).await;
            return if code == 0 {
                Ok(())
            } else {
                Err(anyhow!("Agent exited with code {code}"))
            };
        }
    }
    let key = signing_key_from_seed_b64(&identity.private_key_b64).map_err(anyhow::Error::msg)?;
    let caps = helper::runtime_capabilities(client::VERSION).await;
    let ceiling = if caps["local_max_permission_profile"] == "READ_ONLY" {
        "READ_ONLY"
    } else {
        "STANDARD"
    };
    let mut metadata = json!({"display_name":identity.display_name,"hostname":hostname,"platform":if cfg!(target_os="linux") {"Linux"} else if cfg!(windows) {"Windows"} else {std::env::consts::OS},"architecture":std::env::consts::ARCH,"agent_version":client::VERSION,"protocol_version":"1","public_key_b64":identity.public_key_b64,"capabilities":caps,"local_ceiling":ceiling});
    if !identity.device_id.is_empty() && !identity.device_token.is_empty() {
        metadata["device_id"] = json!(identity.device_id);
        metadata["device_token_hash"] = json!(hex::encode(Sha256::digest(
            identity.device_token.as_bytes()
        )));
    }
    let client = reqwest::Client::builder()
        .user_agent(format!("CommandCore-Agent/{}", client::VERSION))
        .timeout(Duration::from_secs(20))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    if saved
        .get("enrollment_expires_at")
        .and_then(Value::as_f64)
        .unwrap_or(0.0)
        <= now()
    {
        let proof = sign_b64(
            &key,
            format!(
                "commandcore-enroll-init-v1\n{}",
                serde_json::to_string(&metadata)?
            )
            .as_bytes(),
        );
        let mut body = metadata.clone();
        body["proof"] = json!(proof);
        let response = client
            .post(format!("{origin}/api/enrollment/start"))
            .json(&body)
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(anyhow!("Enrollment start rejected ({})", response.status()));
        }
        let data: Value = response.json().await?;
        saved["enrollment_id"] = data["id"].clone();
        saved["enrollment_poll_token"] = data["poll_token"].clone();
        saved["enrollment_uri"] = data["verification_uri"].clone();
        saved["enrollment_code"] = data["verification_code"].clone();
        saved["enrollment_expires_at"] = data["expires_at"].clone();
        state::save(&saved, &pending)?;
    }
    let id = text(&saved, "enrollment_id")?;
    let poll = text(&saved, "enrollment_poll_token")?;
    println!("CommandCore\n\nDevice: {}\nOS: {}\nArchitecture: {}\nRequested local ceiling: {ceiling}\n\nOpen:\n{}\n\nVerification code: {}\n\nWaiting for approval...",identity.display_name,metadata["platform"].as_str().unwrap_or("unknown"),std::env::consts::ARCH,text(&saved,"enrollment_uri")?,text(&saved,"enrollment_code")?);
    std::io::stdout().flush()?;
    let proof = sign_b64(
        &key,
        format!("commandcore-enroll-claim-v1\n{id}\n{poll}").as_bytes(),
    );
    while now() < saved["enrollment_expires_at"].as_f64().unwrap_or(0.0) {
        let response = client
            .post(format!("{origin}/api/enrollment/poll"))
            .json(&json!({"poll_token":poll,"proof":proof}))
            .send()
            .await?;
        if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            tokio::time::sleep(Duration::from_secs(5)).await;
            continue;
        }
        if !response.status().is_success() {
            return Err(anyhow!(
                "Enrollment expired or consumed; no credentials logged"
            ));
        }
        let data: Value = response.json().await?;
        match text(&data, "status")? {
            "rejected" => return Err(anyhow!("Enrollment rejected")),
            "approved" => {
                if data.get("credential_source").and_then(Value::as_str) == Some("agent") {
                    if text(&data, "device_id")? != identity.device_id {
                        return Err(anyhow!("Device identity mismatch"));
                    }
                } else {
                    identity.device_token = text(&data, "device_token")?.to_string();
                }
                identity.device_id = text(&data, "device_id")?.to_string();
                state::save(&identity, &path)?;
                fs::remove_file(&pending)?;
                println!("[OK] Device approved\n[OK] Device identity established\n[OK] Permission ceiling: {ceiling}");
                if no_connect {
                    return Ok(());
                }
                let code = client::run_agent(path, false).await;
                return if code == 0 {
                    Ok(())
                } else {
                    Err(anyhow!("Agent exited with code {code}"))
                };
            }
            "pending" => tokio::time::sleep(Duration::from_secs(3)).await,
            _ => return Err(anyhow!("Unexpected enrollment status")),
        }
    }
    Err(anyhow!("Enrollment expired; run enrollment again"))
}
