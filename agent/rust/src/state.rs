use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    env, fs,
    io::Write,
    path::{Path, PathBuf},
};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentState {
    pub device_id: String,
    pub device_token: String,
    pub private_key_b64: String,
    pub public_key_b64: String,
    pub control_url: String,
    pub agent_url: String,
    pub display_name: String,
    #[serde(default = "one")]
    pub key_generation: u64,
    #[serde(default)]
    pub pending_private_key_b64: Option<String>,
    #[serde(default)]
    pub pending_public_key_b64: Option<String>,
    #[serde(default)]
    pub pending_rotation_id: Option<String>,
    #[serde(default = "state_version")]
    pub state_version: u32,
}

fn one() -> u64 {
    1
}
fn state_version() -> u32 {
    2
}

pub fn default_state_path() -> PathBuf {
    if let Ok(value) = env::var("COMMANDCORE_AGENT_STATE") {
        if !value.trim().is_empty() {
            return PathBuf::from(value);
        }
    }
    #[cfg(windows)]
    {
        let base = env::var("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("."));
        base.join("CommandCore").join("agent.json")
    }
    #[cfg(not(windows))]
    {
        let home = env::var("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("."));
        let legacy = home.join(".config").join("commandcore").join("agent.json");
        if let Ok(config) = env::var("XDG_CONFIG_HOME") {
            if !config.is_empty() {
                let configured = PathBuf::from(config).join("commandcore").join("agent.json");
                // Keep an existing legacy identity until the configured path
                // actually contains one; never silently re-enroll or move keys.
                if configured.exists() || !legacy.exists() {
                    return configured;
                }
            }
        }
        legacy
    }
}

pub fn load(path: &Path) -> Result<AgentState> {
    let bytes = fs::read(path).with_context(|| format!("read Agent state {}", path.display()))?;
    serde_json::from_slice(&bytes).context("parse Agent state")
}

pub fn save<T: Serialize>(state: &T, path: &Path) -> Result<()> {
    let parent = path.parent().context("state path has no parent")?;
    fs::create_dir_all(parent)?;
    let temp = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|x| x.to_str())
            .unwrap_or("agent.json"),
        Uuid::new_v4()
    ));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temp)?;
    serde_json::to_writer_pretty(&mut file, state)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    fs::rename(&temp, path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        if let Ok(dir) = fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

pub fn begin_rotation(
    state: &mut AgentState,
    private_key_b64: String,
    public_key_b64: String,
    rotation_id: String,
) {
    state.pending_private_key_b64 = Some(private_key_b64);
    state.pending_public_key_b64 = Some(public_key_b64);
    state.pending_rotation_id = Some(rotation_id);
}

pub fn promote_pending(state: &mut AgentState, generation: u64) -> Result<()> {
    let private = state
        .pending_private_key_b64
        .take()
        .context("no pending private key")?;
    let public = state
        .pending_public_key_b64
        .take()
        .context("no pending public key")?;
    state.private_key_b64 = private;
    state.public_key_b64 = public;
    state.key_generation = generation.max(state.key_generation + 1);
    state.pending_rotation_id = None;
    Ok(())
}

pub fn clear_pending(state: &mut AgentState) {
    state.pending_private_key_b64 = None;
    state.pending_public_key_b64 = None;
    state.pending_rotation_id = None;
}
