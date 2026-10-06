use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use commandcore_agent_rust::{
    client::{self, VERSION},
    enrollment, helper,
    protocol::{
        private_seed_b64, public_key_b64, rotation_confirm_message, rotation_prepare_message,
        sign_b64, signing_key_from_seed_b64,
    },
    state::{self, AgentState},
};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use tokio_tungstenite::tungstenite::Message;
use url::Url;
use uuid::Uuid;

#[derive(Parser)]
#[command(name="commandcore-agent-rust", version=VERSION, about="CommandCore native Rust Agent")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    #[cfg(target_os = "linux")]
    #[command(hide = true)]
    JobWorker {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        device: String,
        #[arg(long)]
        job: String,
    },
    VerifyRelease {
        manifest: PathBuf,
        #[arg(long)]
        public_key: String,
        #[arg(long)]
        platform: String,
        #[arg(long)]
        architecture: String,
        #[arg(long)]
        artifact: Option<PathBuf>,
        #[arg(long)]
        newer_than: Option<String>,
    },
    Enroll {
        token: String,
        #[arg(long)]
        control_url: Option<String>,
        #[arg(long)]
        agent_url: Option<String>,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        state: Option<PathBuf>,
        #[arg(long)]
        force: bool,
        #[arg(long)]
        insecure: bool,
        #[arg(long)]
        no_connect: bool,
    },
    Run {
        #[arg(long)]
        state: Option<PathBuf>,
        #[arg(long)]
        once: bool,
    },
    Status {
        #[arg(long)]
        state: Option<PathBuf>,
        /// Machine-readable status, preserving the existing JSON fields.
        #[arg(long)]
        json: bool,
        #[arg(long, default_value = "commandcore-agent.service")]
        service: String,
    },
    Activity {
        /// Emit redacted structured JSON objects, one per line.
        #[arg(long)]
        json: bool,
        /// Print recent entries and exit; omit to watch live activity.
        #[arg(long)]
        last: Option<u32>,
        #[arg(long)]
        errors: bool,
        #[arg(long)]
        service: Option<String>,
    },
    RotateKey {
        #[arg(long)]
        state: Option<PathBuf>,
    },
    Capabilities,
    EnableFullControl {
        #[arg(long, default_value = "commandcore")]
        agent_user: String,
        #[arg(long)]
        acknowledge_root_access: bool,
    },
    DisableFullControl,
}

#[tokio::main]
async fn main() {
    if let Err(e) = real_main().await {
        eprintln!("{e:#}");
        std::process::exit(1);
    }
}

async fn real_main() -> Result<()> {
    match Cli::parse().command {
        #[cfg(target_os = "linux")]
        Commands::JobWorker { root, device, job } => {
            commandcore_agent_rust::jobs::worker(root, device, job).await
        }
        Commands::VerifyRelease {
            manifest,
            public_key,
            platform,
            architecture,
            artifact,
            newer_than,
        } => {
            let metadata = commandcore_agent_rust::release::verify(
                &manifest,
                &public_key,
                &platform,
                &architecture,
                artifact.as_deref(),
            )?;
            if let Some(installed) = newer_than {
                commandcore_agent_rust::release::require_newer(
                    metadata["version"]
                        .as_str()
                        .context("missing verified release version")?,
                    &installed,
                )?;
            }
            println!("{}", serde_json::to_string(&metadata)?);
            Ok(())
        }
        Commands::EnableFullControl {
            agent_user,
            acknowledge_root_access,
        } => {
            let mut arguments = vec![
                "enable-full-control".to_string(),
                "--agent-user".to_string(),
                agent_user,
            ];
            if acknowledge_root_access {
                arguments.push("--acknowledge-root-access".to_string());
            }
            configure_local_helper(arguments)
        }
        Commands::DisableFullControl => {
            configure_local_helper(vec!["disable-full-control".to_string()])
        }
        Commands::Enroll {
            token,
            control_url,
            agent_url,
            name,
            state: state_path,
            force,
            insecure,
            no_connect,
        } => {
            if token.starts_with("https://") || token.starts_with("http://") {
                return enrollment::enroll_url(token, name, state_path, no_connect, insecure).await;
            }
            enroll(
                token,
                control_url.context("legacy enrollment requires --control-url")?,
                agent_url.context("legacy enrollment requires --agent-url")?,
                name,
                state_path,
                force,
                insecure,
            )
            .await
        }
        Commands::Run {
            state: state_path,
            once,
        } => {
            let code =
                client::run_agent(state_path.unwrap_or_else(state::default_state_path), once).await;
            if code == 0 {
                Ok(())
            } else {
                Err(anyhow!("Agent exited with code {code}"))
            }
        }
        Commands::Status {
            state: state_path,
            json,
            service,
        } => {
            show_status(
                state_path.unwrap_or_else(state::default_state_path),
                json,
                service,
            )
            .await
        }
        Commands::Activity {
            json,
            last,
            errors,
            service,
        } => commandcore_agent_rust::local_ui::activity(last, errors, service, json).await,
        Commands::RotateKey { state: state_path } => {
            rotate_key(state_path.unwrap_or_else(state::default_state_path)).await
        }
        Commands::Capabilities => {
            println!(
                "{}",
                serde_json::to_string_pretty(&helper::runtime_capabilities(VERSION).await)?
            );
            Ok(())
        }
    }
}

fn configure_local_helper(arguments: Vec<String>) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        let path = Path::new("/opt/commandcore-agent/helper/venv/bin/commandcore-agent");
        let metadata = std::fs::symlink_metadata(path)
            .context("Install the separately reviewed root helper runtime first")?;
        if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(anyhow!("Refusing an untrusted root helper launcher"));
        }
        for parent in path.ancestors().skip(1) {
            let metadata = std::fs::symlink_metadata(parent)?;
            if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                return Err(anyhow!("Root helper launcher directory is not protected"));
            }
        }
        let status = std::process::Command::new(path).args(arguments).status()?;
        if !status.success() {
            return Err(anyhow!("Local privileged helper configuration failed"));
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = arguments;
        Err(anyhow!(
            "Local privileged helper configuration is supported only on Linux"
        ))
    }
}

async fn show_status(path: PathBuf, machine_readable: bool, service: String) -> Result<()> {
    if !path.exists() && !machine_readable {
        println!("CommandCore Agent {VERSION}\nNot enrolled. Open the panel's Add a device flow to enroll this machine.");
        return Ok(());
    }
    let st = state::load(&path)?;
    let caps = helper::runtime_capabilities(VERSION).await;
    let connection = commandcore_agent_rust::local_ui::connection(&path, &st.device_id).await;
    let service_status = commandcore_agent_rust::local_ui::service_status(&service).await;
    if !machine_readable {
        println!("CommandCore Agent {VERSION}\nDevice: {} ({})\nConnection: {}\nService: {} / {}\nLocal permission ceiling: {}\nConnection was last observed at Unix time {}. The panel confirms live reachability.\nWatch activity: commandcore-agent activity",
            st.display_name, st.device_id, connection["state"].as_str().unwrap_or("unknown"),
            service_status["ActiveState"].as_str().unwrap_or("unavailable"), service_status["SubState"].as_str().unwrap_or("unknown"),
            caps["local_max_permission_profile"].as_str().unwrap_or("unknown"), connection["observed_at_unix"]);
        return Ok(());
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "device_id":st.device_id,"display_name":st.display_name,"control_url":st.control_url,"agent_url":st.agent_url,
            "state_file":path,"agent_version":VERSION,"agent_implementation":"rust","protocol_version":"1",
            "key_generation":st.key_generation,"key_rotation_pending":st.pending_private_key_b64.is_some(),
            "local_max_permission_profile":caps.get("local_max_permission_profile"),
            "configured_max_permission_profile":caps.get("configured_max_permission_profile"),
            "privileged_helper":caps.get("privileged_helper").cloned().unwrap_or(Value::Bool(false)),
            "privileged_helper_version":caps.get("privileged_helper_version"),
            "connection":connection,"service":service_status,
        }))?
    );
    Ok(())
}

fn loopback_host(host: &str) -> bool {
    matches!(host, "127.0.0.1" | "localhost" | "::1")
}

fn validate_endpoints(control_url: &str, agent_url: &str, insecure: bool) -> Result<()> {
    let control = Url::parse(control_url).context("invalid control URL")?;
    let control_host = control.host_str().context("control URL host missing")?;
    if !matches!(control.scheme(), "http" | "https") {
        return Err(anyhow!("control URL must use http/https"));
    }
    if control.scheme() == "http" && !loopback_host(control_host) {
        return Err(anyhow!("remote control URL must use HTTPS"));
    }
    if insecure && !loopback_host(control_host) {
        return Err(anyhow!(
            "--insecure is allowed only for loopback development"
        ));
    }
    let agent = Url::parse(agent_url).context("invalid Agent URL")?;
    let agent_host = agent.host_str().context("Agent URL host missing")?;
    if !matches!(agent.scheme(), "ws" | "wss") {
        return Err(anyhow!("Agent URL must use ws/wss"));
    }
    if agent.scheme() == "ws" && !loopback_host(agent_host) {
        return Err(anyhow!("remote Agent URL must use WSS"));
    }
    Ok(())
}

async fn enroll(
    token: String,
    control_url: String,
    agent_url: String,
    name: Option<String>,
    state_path: Option<PathBuf>,
    force: bool,
    insecure: bool,
) -> Result<()> {
    validate_endpoints(&control_url, &agent_url, insecure)?;
    let path = state_path.unwrap_or_else(state::default_state_path);
    if path.exists() && !force {
        return Err(anyhow!(
            "Refusing to overwrite existing Agent identity: {}",
            path.display()
        ));
    }
    let key = client::new_signing_key();
    let public = public_key_b64(&key);
    let private = private_seed_b64(&key);
    let hostname = hostname::get()?.to_string_lossy().to_string();
    let display = name.unwrap_or_else(|| hostname.clone());
    let platform = match std::env::consts::OS {
        "linux" => "Linux",
        "windows" => "Windows",
        "macos" => "macOS",
        x => x,
    };
    let payload = json!({"token":token,"display_name":display,"hostname":hostname,"platform":platform,"architecture":std::env::consts::ARCH,"agent_version":VERSION,"protocol_version":"1","public_key_b64":public,"capabilities":helper::runtime_capabilities(VERSION).await});
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(insecure)
        .timeout(Duration::from_secs(20))
        .build()?;
    let url = format!("{}/api/agent/enroll", control_url.trim_end_matches('/'));
    let response = client.post(url).json(&payload).send().await?;
    let status = response.status();
    let data: Value = response.json().await?;
    if !status.is_success() {
        return Err(anyhow!("Enrollment failed ({status}): {data}"));
    }
    let st = AgentState {
        device_id: data
            .get("device_id")
            .and_then(Value::as_str)
            .context("missing device_id")?
            .into(),
        device_token: data
            .get("device_token")
            .and_then(Value::as_str)
            .context("missing device_token")?
            .into(),
        private_key_b64: private,
        public_key_b64: public,
        control_url: control_url.trim_end_matches('/').into(),
        agent_url,
        display_name: payload["display_name"].as_str().unwrap_or("device").into(),
        key_generation: 1,
        pending_private_key_b64: None,
        pending_public_key_b64: None,
        pending_rotation_id: None,
        state_version: 2,
    };
    state::save(&st, &path)?;
    println!(
        "{}",
        serde_json::to_string_pretty(
            &json!({"device_id":st.device_id,"status":data.get("status"),"state_file":path})
        )?
    );
    Ok(())
}

async fn rotate_key(path: PathBuf) -> Result<()> {
    let mut st = state::load(&path)?;
    if let Some(pending) = st.pending_private_key_b64.clone() {
        if let Ok((mut ws, ack)) = client::connect_authenticated(&st, &pending).await {
            let _ = ws.close(None).await;
            let generation = ack
                .get("key_generation")
                .and_then(Value::as_u64)
                .unwrap_or(st.key_generation + 1);
            state::promote_pending(&mut st, generation)?;
            state::save(&st, &path)?;
            println!(
                "{}",
                json!({"ok":true,"device_id":st.device_id,"key_generation":st.key_generation,"recovered":true})
            );
            return Ok(());
        }
    }
    let (mut ws, ack) = client::connect_authenticated(&st, &st.private_key_b64).await?;
    if st.pending_private_key_b64.is_some()
        && st.pending_public_key_b64.is_some()
        && st.pending_rotation_id.is_some()
    {
        confirm_pending(&mut ws, &mut st, &path).await?;
        return Ok(());
    }
    let nonce = ack
        .get("key_rotation_nonce")
        .and_then(Value::as_str)
        .context("server_does_not_support_key_rotation")?;
    let new = client::new_signing_key();
    let new_private = private_seed_b64(&new);
    let new_public = public_key_b64(&new);
    let old = signing_key_from_seed_b64(&st.private_key_b64).map_err(|e| anyhow!(e))?;
    let proof = rotation_prepare_message(&st.device_id, nonce, &new_public);
    let request_id = Uuid::new_v4().to_string();
    ws.send(Message::Text(serde_json::to_string(&json!({"type":"device.key.rotate.prepare","request_id":request_id,"new_public_key_b64":new_public.clone(),"old_signature":sign_b64(&old,&proof),"new_signature":sign_b64(&new,&proof)}))?)).await?;
    let prepared = next_json(&mut ws).await?;
    if prepared.get("type").and_then(Value::as_str) != (Some("device.key.rotate.prepared")) {
        return Err(anyhow!("rotation prepare failed: {prepared}"));
    }
    let rotation_id = prepared
        .get("rotation_id")
        .and_then(Value::as_str)
        .context("rotation_id missing")?
        .to_string();
    state::begin_rotation(&mut st, new_private, new_public, rotation_id);
    state::save(&st, &path)?;
    confirm_pending(&mut ws, &mut st, &path).await
}

async fn confirm_pending(ws: &mut client::Ws, st: &mut AgentState, path: &Path) -> Result<()> {
    let rotation_id = st
        .pending_rotation_id
        .clone()
        .context("pending rotation id missing")?;
    let key = signing_key_from_seed_b64(
        st.pending_private_key_b64
            .as_deref()
            .context("pending private key missing")?,
    )
    .map_err(|e| anyhow!(e))?;
    let request_id = Uuid::new_v4().to_string();
    let proof = rotation_confirm_message(&st.device_id, &rotation_id);
    ws.send(Message::Text(serde_json::to_string(&json!({"type":"device.key.rotate.confirm","request_id":request_id,"rotation_id":rotation_id,"new_signature":sign_b64(&key,&proof)}))?)).await?;
    let ack = next_json(ws).await?;
    if ack.get("type").and_then(Value::as_str) == Some("device.key.rotate.error")
        && ack.get("error").and_then(Value::as_str) == Some("key_rotation_not_pending")
    {
        state::clear_pending(st);
        state::save(st, path)?;
        return Err(anyhow!(
            "rotation expired; pending state cleared, rerun rotate-key"
        ));
    }
    if ack.get("type").and_then(Value::as_str) != Some("device.key.rotate.ack") {
        return Err(anyhow!("rotation confirm failed: {ack}"));
    }
    let generation = ack
        .get("key_generation")
        .and_then(Value::as_u64)
        .unwrap_or(st.key_generation + 1);
    state::promote_pending(st, generation)?;
    state::save(st, path)?;
    println!(
        "{}",
        json!({"ok":true,"device_id":st.device_id,"key_generation":st.key_generation})
    );
    Ok(())
}

async fn next_json(ws: &mut client::Ws) -> Result<Value> {
    let item = tokio::time::timeout(Duration::from_secs(10), ws.next())
        .await
        .context("rotation response timeout")?;
    let message = item.context("connection closed")??;
    Ok(serde_json::from_str(message.to_text()?)?)
}
