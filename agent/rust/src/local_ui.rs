//! Local operator commands. Only allowlisted health fields are displayed.
#[cfg(target_os = "linux")]
use anyhow::Context;
use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use std::path::Path;
#[cfg(target_os = "linux")]
use std::{process::Stdio, time::Duration};

pub async fn connection(state: &Path, device: &str) -> Value {
    let path = crate::client::health_path(state);
    let health = std::fs::metadata(&path)
        .ok()
        .filter(|m| m.is_file() && m.len() <= 65536)
        .and_then(|_| std::fs::read(&path).ok())
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok());
    let Some(health) = health.filter(|h| h["device_id"] == device) else {
        return json!({"state":"unknown","reason":"no matching connection observation"});
    };
    #[cfg(target_os = "linux")]
    let live = health["pid"]
        .as_u64()
        .zip(health["process_start"].as_str())
        .is_some_and(|(pid, start)| crate::jobs::matches(pid as u32, start))
        && health["boot_id"].as_str()
            == std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
                .ok()
                .as_deref()
                .map(str::trim);
    #[cfg(not(target_os = "linux"))]
    let live = false;
    json!({"state":if !live {"unconfirmed"} else if health["connected"] == true {"connected"} else {"reconnecting"},
        "observed_at_unix":health["observed_at_unix"],"process_identity_verified":live,
        "note":"Local connection observation; panel is authoritative for server reachability."})
}

pub async fn activity(
    last: Option<u32>,
    errors: bool,
    service: Option<String>,
    as_json: bool,
) -> Result<()> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (last, errors, service, as_json);
        Err(anyhow!("Local activity is currently supported on Linux"))
    }
    #[cfg(target_os = "linux")]
    {
        let service = service.unwrap_or_else(|| "commandcore-agent.service".into());
        if !service.starts_with("commandcore-agent")
            || !service.ends_with(".service")
            || !service
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
        {
            return Err(anyhow!("Invalid CommandCore service name"));
        }
        let mut command = tokio::process::Command::new("journalctl");
        command
            .args(["--user", "--unit", &service, "--no-pager", "--output=json"])
            .arg("--lines")
            .arg(last.unwrap_or(20).clamp(1, 5000).to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .kill_on_drop(true);
        if last.is_none() {
            command.arg("--follow");
        }
        use tokio::io::{AsyncBufReadExt, BufReader};
        let mut child = command
            .spawn()
            .context("Cannot read local CommandCore activity")?;
        let mut lines =
            BufReader::new(child.stdout.take().context("Missing activity reader")?).lines();
        while let Some(line) = lines.next_line().await? {
            if let Ok(record) = serde_json::from_str::<Value>(&line) {
                if let Some(display) = record["MESSAGE"]
                    .as_str()
                    .and_then(|m| crate::activity::render(m, as_json, errors))
                {
                    println!("{display}");
                }
            }
        }
        let status = child.wait().await?;
        if !status.success() {
            return Err(anyhow!(
                "CommandCore activity unavailable (journal access or service name)"
            ));
        }
        Ok(())
    }
}

pub async fn service_status(service: &str) -> Value {
    #[cfg(target_os = "linux")]
    {
        let mut command = tokio::process::Command::new("systemctl");
        command
            .args([
                "--user",
                "show",
                "--property=ActiveState,SubState,Result",
                service,
            ])
            .stdin(Stdio::null())
            .kill_on_drop(true);
        if let Ok(Ok(output)) = tokio::time::timeout(Duration::from_secs(2), command.output()).await
        {
            if output.status.success() {
                let mut result = serde_json::Map::new();
                for line in String::from_utf8_lossy(&output.stdout).lines() {
                    if let Some((key, value)) = line.split_once('=') {
                        if ["ActiveState", "SubState", "Result"].contains(&key) {
                            result.insert(key.into(), json!(value));
                        }
                    }
                }
                return Value::Object(result);
            }
        }
    }
    let _ = service;
    json!({"available":false})
}
