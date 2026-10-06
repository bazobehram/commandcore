use crate::{
    executor::{capabilities, Executor},
    output::OutputSink,
    protocol::{
        auth_message, public_key_b64, sign_b64, signing_key_from_seed_b64, PROTOCOL_VERSION,
    },
    state::{self, AgentState},
};
use anyhow::{anyhow, Context, Result};
use ed25519_dalek::SigningKey;
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::{
    env, fs,
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{net::TcpStream, sync::mpsc, task::JoinSet, time::sleep};
use tokio_tungstenite::{
    tungstenite::{
        client::IntoClientRequest,
        http::{header::AUTHORIZATION, HeaderValue},
        Message,
    },
    MaybeTlsStream, WebSocketStream,
};
use tokio_util::sync::CancellationToken;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

pub async fn connect_authenticated(
    state: &AgentState,
    private_key_b64: &str,
) -> Result<(Ws, Value)> {
    let key = signing_key_from_seed_b64(private_key_b64).map_err(|e| anyhow!(e))?;
    let mut request = state.agent_url.clone().into_client_request()?;
    request.headers_mut().insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!(
            "Device {}:{}",
            state.device_id, state.device_token
        ))?,
    );
    let mut ws = crate::network::connect(request).await?;
    let challenge = tokio::time::timeout(Duration::from_secs(10), ws.next())
        .await
        .context("stage=authentication: challenge timeout")?
        .context("stage=authentication: connection closed before challenge")??;
    if let Message::Close(Some(frame)) = &challenge {
        if matches!(u16::from(frame.code), 4401 | 4403) {
            return Err(anyhow!("Agent authorization rejected"));
        }
    }
    let challenge: Value = serde_json::from_str(challenge.to_text()?)?;
    if challenge.get("type").and_then(Value::as_str) != Some("challenge")
        || challenge.get("protocol_version").and_then(Value::as_str) != Some(PROTOCOL_VERSION)
    {
        return Err(anyhow!("invalid server challenge or protocol mismatch"));
    }
    let nonce = challenge
        .get("nonce")
        .and_then(Value::as_str)
        .context("challenge nonce missing")?;
    let signature = sign_b64(&key, &auth_message(&state.device_id, nonce));
    let hello = json!({
        "type":"hello","device_id":state.device_id,"protocol_version":PROTOCOL_VERSION,
        "agent_version":VERSION,"capabilities":capabilities().await,"signature":signature,
    });
    tokio::time::timeout(
        Duration::from_secs(15),
        ws.send(Message::Text(serde_json::to_string(&hello)?)),
    )
    .await
    .context("stage=authentication: Agent hello send timeout")??;
    let ack = tokio::time::timeout(Duration::from_secs(10), ws.next())
        .await
        .context("stage=authentication: hello ack timeout")?
        .context("stage=authentication: connection closed before hello ack")??;
    let ack: Value = serde_json::from_str(ack.to_text()?)?;
    if ack.get("type").and_then(Value::as_str) != Some("hello.ack") {
        return Err(anyhow!(
            "Agent authorization rejected: stage=authentication"
        ));
    }
    Ok((ws, ack))
}

pub async fn run_agent(state_path: PathBuf, once: bool) -> i32 {
    // Keep managed job handles and output across transport reconnects.
    let initial = match state::load(&state_path) {
        Ok(state) => state,
        Err(_) => {
            eprintln!("No valid Agent state");
            return 1;
        }
    };
    crate::activity::register_secrets([
        initial.device_token.clone(),
        initial.private_key_b64.clone(),
        initial.pending_private_key_b64.clone().unwrap_or_default(),
    ]);
    crate::activity::register_secrets(
        std::env::vars()
            .filter(|(k, _)| {
                ["SECRET", "TOKEN", "PASSWORD", "KEY", "CREDENTIAL", "COOKIE"]
                    .iter()
                    .any(|part| k.to_uppercase().contains(part))
            })
            .map(|(_, v)| v),
    );
    let executor = match Executor::for_state(
        env::var("COMMANDCORE_AGENT_MAX_TRANSFER_BYTES")
            .ok()
            .and_then(|x| x.parse().ok())
            .unwrap_or(10 * 1024 * 1024),
        &state_path,
        &initial.device_id,
    ) {
        Ok(executor) => executor,
        Err(_) => {
            eprintln!("Unsafe managed-job state directory");
            return 1;
        }
    };
    let mut backoff = 1u64;
    let mut prefer_pending = false;
    loop {
        let mut current = match state::load(&state_path) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("No valid Agent state: {e}");
                return 1;
            }
        };
        if current.pending_private_key_b64.is_some() && !prefer_pending {
            prefer_pending = true;
        }
        let used_pending = prefer_pending && current.pending_private_key_b64.is_some();
        let selected = if used_pending {
            current.pending_private_key_b64.clone().unwrap()
        } else {
            current.private_key_b64.clone()
        };
        match connect_authenticated(&current, &selected).await {
            Ok((ws, ack)) => {
                if used_pending {
                    let generation = ack
                        .get("key_generation")
                        .and_then(Value::as_u64)
                        .unwrap_or(current.key_generation + 1);
                    if let Err(e) = state::promote_pending(&mut current, generation)
                        .and_then(|_| state::save(&current, &state_path))
                    {
                        eprintln!("failed to persist promoted key: {e}");
                        return 1;
                    }
                }
                prefer_pending = false;
                backoff = 1;
                if let Err(e) = write_health(&health_path(&state_path), &current, true, None) {
                    eprintln!("health marker warning: {e}");
                }
                println!(
                    "CommandCore Rust Agent connected: {} ({})",
                    current.display_name, current.device_id
                );
                crate::activity::emit(
                    "CONNECTION",
                    json!({"status":"connected", "device_id":current.device_id}),
                );
                let result = run_connection(ws, current.clone(), executor.clone()).await;
                let _ = write_health(
                    &health_path(&state_path),
                    &current,
                    false,
                    Some("disconnected"),
                );
                crate::activity::emit(
                    "CONNECTION",
                    json!({"status":"reconnecting", "reason":"disconnected", "retry_in_seconds":backoff}),
                );
                eprintln!("CommandCore Agent disconnected; reconnecting in {backoff}s");
                if let Err(e) = result {
                    eprintln!("Agent connection error: stage=established: {e}");
                }
            }
            Err(e) => {
                let http_denied = e.chain().any(|cause| {
                    matches!(cause.downcast_ref::<tokio_tungstenite::tungstenite::Error>(),
                        Some(tokio_tungstenite::tungstenite::Error::Http(response))
                        if matches!(response.status().as_u16(), 401 | 403))
                });
                if http_denied || e.to_string().starts_with("Agent authorization rejected") {
                    executor.authorization_revoked().await;
                }
                if current.pending_private_key_b64.is_some() {
                    prefer_pending = !prefer_pending;
                }
                crate::activity::emit(
                    "CONNECTION",
                    json!({"status":"reconnecting", "reason":"connection failed", "retry_in_seconds":backoff}),
                );
                eprintln!("Agent connection error: {e}; reconnecting in {backoff}s");
            }
        }
        if once {
            executor.cancel_all().await;
            return 1;
        }
        sleep(Duration::from_secs(backoff)).await;
        backoff = (backoff * 2).min(30);
    }
}

async fn run_connection(ws: Ws, state: AgentState, executor: Executor) -> Result<()> {
    let (mut sink, mut stream) = ws.split();
    let (tx, mut rx) = mpsc::channel::<Value>(64);
    let transport_failed = CancellationToken::new();
    let writer_failed = transport_failed.clone();
    let writer = tokio::spawn(async move {
        while let Some(value) = rx.recv().await {
            if !matches!(
                tokio::time::timeout(
                    Duration::from_secs(15),
                    sink.send(Message::Text(
                        serde_json::to_string(&value).unwrap_or_else(|_| "{}".into()),
                    ))
                )
                .await,
                Ok(Ok(()))
            ) {
                break;
            }
        }
        writer_failed.cancel();
    });
    let hb_tx = tx.clone();
    let heartbeat = tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(15)).await;
            if hb_tx
                .send(json!({"type":"heartbeat","capabilities":capabilities().await}))
                .await
                .is_err()
            {
                break;
            }
        }
    });
    let mut authorization_ended = false;
    let mut jobs = JoinSet::new();
    let receive_result: Result<()> = async {
        loop {
            // Authenticated servers acknowledge heartbeats every 15 seconds.
            // Older Uvicorn servers also send WebSocket pings. A silent socket
            // must not strand the Agent after a blackholed network connection.
            let message = tokio::select! {
                _ = transport_failed.cancelled() => return Err(anyhow!("Agent WebSocket writer stopped")),
                message = tokio::time::timeout(Duration::from_secs(45), stream.next()) =>
                    message.context("Agent WebSocket idle timeout")?,
            };
            let Some(message) = message else { break };
            let message = message?;
            if let Message::Close(frame) = &message {
                authorization_ended = frame
                    .as_ref()
                    .is_some_and(|f| matches!(u16::from(f.code), 4001 | 4002 | 4401 | 4403));
                break;
            }
            if !message.is_text() {
                continue;
            }
            let msg: Value = serde_json::from_str(message.to_text()?)?;
            match msg.get("type").and_then(Value::as_str).unwrap_or("") {
                "job.request" => {
                    let eid = msg
                        .get("execution_id")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    if eid.is_empty() {
                        continue;
                    }
                    let tool = msg
                        .get("tool")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    let args = msg
                        .get("arguments")
                        .cloned()
                        .filter(Value::is_object)
                        .unwrap_or_else(|| json!({}));
                    let profile = msg
                        .get("permission_profile")
                        .and_then(Value::as_str)
                        .unwrap_or("READ_ONLY")
                        .to_string();
                    let exec = executor.clone();
                    let out_tx = tx.clone();
                    jobs.spawn(async move {
                        let started = std::time::Instant::now();
                        crate::activity::emit("REQUEST", crate::activity::request(&msg));
                        let mut span = crate::activity::Span::new(&msg);
                        let output = OutputSink::new(eid.clone(), out_tx.clone());
                        let capture = output.clone();
                        let outcome = exec.execute(&eid, &profile, &tool, args, output).await;
                        crate::activity::emit("RESULT", crate::activity::result(&msg, &outcome, started.elapsed().as_millis(), capture.preview().await));
                        span.complete();
                        let mut payload = serde_json::Map::new();
                        payload.insert("type".into(), Value::String("job.result".into()));
                        payload.insert("execution_id".into(), Value::String(eid));
                        if let Some(obj) = outcome.as_object() {
                            for (k, v) in obj {
                                payload.insert(k.clone(), v.clone());
                            }
                        }
                        if !payload.contains_key("exit_code") {
                            if let Some(code) = payload
                                .get("result")
                                .and_then(Value::as_object)
                                .and_then(|r| r.get("exit_code"))
                                .cloned()
                            {
                                payload.insert("exit_code".into(), code);
                            }
                        }
                        let _ = out_tx.send(Value::Object(payload)).await;
                    });
                }
                "job.cancel" => {
                    if let Some(id) = msg.get("execution_id").and_then(Value::as_str) {
                        executor.cancel(id).await;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }
    .await;
    // Cleanup must also run on transport/JSON errors, not only a clean EOF.
    if authorization_ended {
        executor.authorization_revoked().await;
    } else {
        executor.cancel_requests().await;
    }
    jobs.abort_all();
    while jobs.join_next().await.is_some() {}
    heartbeat.abort();
    let _ = heartbeat.await;
    drop(tx);
    // Never wait for a queued output frame or stalled socket during reconnect.
    writer.abort();
    let _ = writer.await;
    let _ = state;
    receive_result
}

pub fn health_path(state_path: &Path) -> PathBuf {
    if let Ok(v) = env::var("COMMANDCORE_AGENT_HEALTH_FILE") {
        if !v.trim().is_empty() {
            return PathBuf::from(v);
        }
    }
    state_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("health.json")
}

pub fn write_health(
    path: &Path,
    state: &AgentState,
    connected: bool,
    detail: Option<&str>,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut payload = json!({
        "schema_version":1,"version":VERSION,"implementation":"rust","device_id":state.device_id,
        "protocol_version":PROTOCOL_VERSION,"key_generation":state.key_generation,"connected":connected,
        "observed_at_unix":SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64(),
        "pid":std::process::id(),
    });
    if let Some(detail) = detail {
        payload
            .as_object_mut()
            .unwrap()
            .insert("detail".into(), Value::String(detail.into()));
    }
    #[cfg(target_os = "linux")]
    {
        payload["process_start"] = json!(crate::jobs::identity(std::process::id()).ok());
        payload["boot_id"] = json!(fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .ok()
            .map(|s| s.trim().to_string()));
    }
    let parent = path.parent().context("health path parent")?;
    let tmp = parent.join(format!(".health.{}.tmp", uuid::Uuid::new_v4()));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o644);
    }
    let mut file = options.open(&tmp)?;
    serde_json::to_writer(&mut file, &payload)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    fs::rename(tmp, path)?;
    Ok(())
}

pub fn new_signing_key() -> SigningKey {
    use rand_core::OsRng;
    SigningKey::generate(&mut OsRng)
}
pub fn key_public_b64(key: &SigningKey) -> String {
    public_key_b64(key)
}
