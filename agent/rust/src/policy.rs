use serde_json::Value;
use std::{
    collections::BTreeSet,
    env, fs,
    io::Read,
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum PermissionProfile {
    ReadOnly,
    Standard,
    FullControl,
}

impl PermissionProfile {
    pub fn parse(value: &str) -> Self {
        match value.trim().to_ascii_uppercase().as_str() {
            "FULL_CONTROL" => Self::FullControl,
            "STANDARD" => Self::Standard,
            _ => Self::ReadOnly,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "READ_ONLY",
            Self::Standard => "STANDARD",
            Self::FullControl => "FULL_CONTROL",
        }
    }
}

#[derive(Clone, Debug)]
pub struct LocalPolicy {
    pub configured_max: PermissionProfile,
    pub update_public_key_b64: String,
    pub update_manifest_origins: BTreeSet<String>,
    pub policy_error: Option<String>,
    pub stop_managed_jobs_on_revocation: bool,
}

impl Default for LocalPolicy {
    fn default() -> Self {
        Self {
            configured_max: PermissionProfile::Standard,
            update_public_key_b64: String::new(),
            update_manifest_origins: BTreeSet::new(),
            policy_error: None,
            stop_managed_jobs_on_revocation: false,
        }
    }
}

pub fn policy_path() -> PathBuf {
    env::var("COMMANDCORE_AGENT_POLICY")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/etc/commandcore/agent-policy.json"))
}

pub fn load_local_policy() -> LocalPolicy {
    load_policy_at(&policy_path())
}

pub fn load_policy_at(path: &Path) -> LocalPolicy {
    let mut out = LocalPolicy::default();
    let loaded = read_policy(path);
    let v = match loaded {
        Ok(Some(v)) => v,
        Ok(None) => return constrain_environment(out),
        Err(_) => {
            out.configured_max = PermissionProfile::ReadOnly;
            out.policy_error = Some("invalid_or_unreadable_or_untrusted".into());
            return constrain_environment(out);
        }
    };
    out.stop_managed_jobs_on_revocation = v
        .get("stop_managed_jobs_on_revocation")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if let Some(profile) = v
        .get("configured_max_permission_profile")
        .and_then(Value::as_str)
    {
        out.configured_max = match profile {
            "READ_ONLY" => PermissionProfile::ReadOnly,
            "STANDARD" => PermissionProfile::Standard,
            "FULL_CONTROL" => PermissionProfile::FullControl,
            _ => unreachable!(),
        };
    }
    out.update_public_key_b64 = v
        .get("update_public_key_b64")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    if let Some(items) = v.get("update_manifest_origins").and_then(Value::as_array) {
        for item in items {
            if let Some(s) = item.as_str() {
                let clean = s.trim().trim_end_matches('/').to_ascii_lowercase();
                if !clean.is_empty() {
                    out.update_manifest_origins.insert(clean);
                }
            }
        }
    }
    constrain_environment(out)
}

fn read_policy(path: &Path) -> Result<Option<Value>, Box<dyn std::error::Error>> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        other => {
            let meta = other?;
            if !meta.is_file() || meta.file_type().is_symlink() {
                return Err("invalid file".into());
            }
        }
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.len() > 1_048_576 {
        return Err("invalid size".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if ![0, nix::unistd::geteuid().as_raw()].contains(&meta.uid()) || meta.mode() & 0o022 != 0 {
            return Err("untrusted file".into());
        }
    }
    let mut bytes = Vec::new();
    file.take(1_048_577).read_to_end(&mut bytes)?;
    let value: Value = serde_json::from_slice(&bytes)?;
    let profile = value
        .get("configured_max_permission_profile")
        .and_then(Value::as_str)
        .ok_or("missing profile")?;
    if !["READ_ONLY", "STANDARD", "FULL_CONTROL"].contains(&profile) {
        return Err("invalid profile".into());
    }
    if path == Path::new("/etc/commandcore/agent-policy.json") || profile == "FULL_CONTROL" {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if meta.uid() != 0 {
                return Err("root policy required".into());
            }
            let absolute = if path.is_absolute() {
                path.to_path_buf()
            } else {
                env::current_dir()?.join(path)
            };
            for parent in absolute.parent().ok_or("no parent")?.ancestors() {
                let m = fs::symlink_metadata(parent)?;
                if !m.is_dir()
                    || m.file_type().is_symlink()
                    || m.uid() != 0
                    || (m.mode() & 0o022 != 0 && m.mode() & 0o1000 == 0)
                {
                    return Err("untrusted directory".into());
                }
            }
        }
        #[cfg(not(unix))]
        {
            return Err("root trust unavailable".into());
        }
    }
    Ok(Some(value))
}

fn constrain_environment(mut policy: LocalPolicy) -> LocalPolicy {
    if let Ok(ceiling) = env::var("COMMANDCORE_AGENT_MAX_PERMISSION_PROFILE") {
        policy.configured_max = policy
            .configured_max
            .min(PermissionProfile::parse(&ceiling));
    }
    policy
}

pub fn is_allowed(profile: PermissionProfile, tool: &str) -> bool {
    const READ: &[&str] = &[
        "fs.list",
        "fs.stat",
        "fs.read",
        "fs.search",
        "process.list",
        "process.status",
        "process.output",
        "system.info",
        "system.metrics",
        "transfer.download",
        "git.status",
        "git.diff",
        "git.log",
        "agent.update.status",
    ];
    const STANDARD: &[&str] = &[
        "fs.write",
        "fs.patch",
        "fs.copy",
        "fs.move",
        "fs.delete",
        "shell.exec",
        "process.start",
        "process.stop",
        "transfer.upload",
        "git.run",
    ];
    const FULL: &[&str] = &[
        "services.manage",
        "package.install",
        "system.reboot",
        "system.shutdown",
        "docker.ps",
        "docker.inspect",
        "docker.logs",
        "docker.exec",
        "docker.run",
        "agent.update.stage",
        "agent.update.activate",
        "agent.update.rollback",
    ];
    READ.contains(&tool)
        || profile >= PermissionProfile::Standard && STANDARD.contains(&tool)
        || profile >= PermissionProfile::FullControl && FULL.contains(&tool)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn present_invalid_policy_fails_closed() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("policy.json");
        for text in [
            "{",
            "[]",
            "{}",
            r#"{"configured_max_permission_profile":"invalid"}"#,
        ] {
            fs::write(&path, text).unwrap();
            let policy = load_policy_at(&path);
            assert_eq!(policy.configured_max, PermissionProfile::ReadOnly);
            assert!(policy.policy_error.is_some());
        }
        fs::remove_file(&path).unwrap();
        let policy = load_policy_at(&path);
        assert!(policy.configured_max <= PermissionProfile::Standard);
        assert!(policy.policy_error.is_none());
    }

    #[test]
    fn valid_read_only_and_standard() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("policy.json");
        for expected in [PermissionProfile::ReadOnly, PermissionProfile::Standard] {
            fs::write(
                &path,
                format!(
                    r#"{{"configured_max_permission_profile":"{}"}}"#,
                    expected.as_str()
                ),
            )
            .unwrap();
            let policy = load_policy_at(&path);
            assert!(policy.configured_max <= expected);
            assert!(policy.policy_error.is_none());
        }
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_permissions_and_links_fail_closed() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("policy.json");
        fs::write(&path, r#"{"configured_max_permission_profile":"STANDARD"}"#).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(load_policy_at(&path).policy_error.is_some());
        let link = root.path().join("link");
        symlink(&path, &link).unwrap();
        assert!(load_policy_at(&link).policy_error.is_some());
        fs::remove_file(path).unwrap();
        assert!(load_policy_at(&link).policy_error.is_some());
    }

    #[test]
    fn full_control_requires_trusted_root() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("policy.json");
        fs::write(
            &path,
            r#"{"configured_max_permission_profile":"FULL_CONTROL"}"#,
        )
        .unwrap();
        let policy = load_policy_at(&path);
        #[cfg(unix)]
        if nix::unistd::geteuid().is_root() {
            assert!(policy.policy_error.is_none());
            return;
        }
        assert_eq!(policy.configured_max, PermissionProfile::ReadOnly);
        assert!(policy.policy_error.is_some());
    }
}
