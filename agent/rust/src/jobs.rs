//! Linux jobs run in an independent, unprivileged local supervisor.
//! No command/environment contents are persisted in the job metadata.
use anyhow::{anyhow, Context, Result};
use nix::{
    sys::signal::{killpg, Signal},
    unistd::Pid,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::Command,
    time::sleep,
};
use uuid::Uuid;

const OUTPUT_LIMIT: usize = 1_048_576;
const STATE_LIMIT: u64 = 65_536;

#[derive(Clone)]
pub struct JobStore {
    root: PathBuf,
    device: String,
}

#[derive(Serialize, Deserialize)]
struct Job {
    process_id: String,
    device_id: String,
    worker_pid: u32,
    worker_start: String,
    pid: u32,
    pid_start: String,
    boot_id: String,
    started_at: f64,
    completed_at: Option<f64>,
    running: bool,
    exit_code: Option<i32>,
    signal: Option<String>,
    termination_reason: Option<String>,
    #[serde(default)]
    systemd_unit: Option<String>,
    #[serde(default)]
    invocation_id: Option<String>,
    #[serde(default)]
    reconciled_at: Option<f64>,
    #[serde(default)]
    manager_pid: Option<u32>,
    #[serde(default)]
    manager_start: Option<String>,
}

fn unit_properties(unit: &str) -> Result<Value> {
    // Names are constructed from canonical device/job UUIDs, never caller input.
    let mut child = std::process::Command::new("systemctl")
        .args([
            "--user",
            "show",
            "--property=ActiveState,Result,InvocationID",
            unit,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while child.try_wait()?.is_none() {
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(anyhow!("managed unit state query timed out"));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(anyhow!("managed unit state unavailable"));
    }
    let mut value = json!({});
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        if let Some((key, val)) = line.split_once('=') {
            value[key] = json!(val);
        }
    }
    Ok(value)
}

fn user_manager_available() -> bool {
    std::env::var_os("XDG_RUNTIME_DIR").is_some_and(|p| Path::new(&p).join("bus").exists())
}

fn resources(job: &Job) -> Value {
    let Some(unit) = &job.systemd_unit else {
        return json!({"available":false,"reason":"legacy_shared_cgroup"});
    };
    if job.boot_id != boot().unwrap_or_default() || !matches(job.worker_pid, &job.worker_start) {
        return json!({"available":false,"reason":"supervisor_not_running"});
    }
    let text = fs::read_to_string(format!("/proc/{}/cgroup", job.worker_pid)).unwrap_or_default();
    let Some(path) = text.lines().find_map(|line| line.strip_prefix("0::")) else {
        return json!({"available":false});
    };
    if !path.starts_with('/')
        || path.split('/').any(|p| p == "..")
        || !path.ends_with(&format!("/{unit}"))
    {
        return json!({"available":false,"reason":"unit_identity_mismatch"});
    }
    let root = Path::new("/sys/fs/cgroup").join(path.trim_start_matches('/'));
    let number = |name: &str| {
        fs::read_to_string(root.join(name))
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
    };
    let current = number("memory.current");
    let maximum = number("memory.max");
    let mut events = json!({});
    for line in fs::read_to_string(root.join("memory.events"))
        .unwrap_or_default()
        .lines()
    {
        if let Some((key, val)) = line.split_once(' ') {
            if ["low", "high", "max", "oom", "oom_kill", "oom_group_kill"].contains(&key) {
                events[key] = json!(val.parse::<u64>().ok());
            }
        }
    }
    let near_limit = current
        .zip(maximum)
        .is_some_and(|(c, m)| m > 0 && c as f64 / m as f64 >= 0.9);
    json!({"available":current.is_some(),"memory_current_bytes":current,"memory_max_bytes":maximum,"memory_events":events,
        "memory_headroom_bytes":current.zip(maximum).map(|(c,m)| m.saturating_sub(c)),"near_memory_limit":near_limit,
        "accounting":"Job cgroup includes reclaimable cache; driver/unified allocations may not all be charged here."})
}

fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}
fn boot() -> Result<String> {
    Ok(fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .into())
}
pub(crate) fn identity(pid: u32) -> Result<String> {
    let text = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let fields: Vec<_> = text
        .rsplit_once(')')
        .context("invalid process stat")?
        .1
        .split_whitespace()
        .collect();
    Ok(fields
        .get(19)
        .context("missing process start identity")?
        .to_string())
}
pub(crate) fn matches(pid: u32, start: &str) -> bool {
    let alive = fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .is_some_and(|text| {
            text.rsplit_once(')')
                .is_some_and(|(_, fields)| fields.split_whitespace().next() != Some("Z"))
        });
    pid > 0 && alive && identity(pid).is_ok_and(|v| v == start)
}

fn trusted_dir(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_dir() || meta.uid() != nix::unistd::geteuid().as_raw() || meta.mode() & 0o077 != 0 {
        return Err(anyhow!("unsafe job directory"));
    }
    Ok(())
}
fn create_dir(path: &Path) -> Result<()> {
    if !path.exists() {
        let mut builder = fs::DirBuilder::new();
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700).create(path)?;
    }
    trusted_dir(path)
}
fn read_protected(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.uid() != nix::unistd::geteuid().as_raw()
        || meta.mode() & 0o077 != 0
        || meta.len() > limit
    {
        return Err(anyhow!("unsafe job file"));
    }
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(anyhow!("oversize job file"));
    }
    Ok(bytes)
}
fn write_atomic(path: &Path, value: &impl Serialize) -> Result<()> {
    let parent = path.parent().context("missing job directory")?;
    trusted_dir(parent)?;
    let temp = parent.join(format!(".{}.tmp", Uuid::new_v4()));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)?;
    let bytes = serde_json::to_vec(value)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::rename(&temp, path)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

impl JobStore {
    pub fn new(parent: &Path, device: &str) -> Result<Self> {
        Uuid::parse_str(device)?;
        // Parents may be root-owned, but never symlinks or writable by others
        // (root-owned sticky /tmp is allowed for isolated test fixtures).
        for ancestor in parent.ancestors() {
            let m = fs::symlink_metadata(ancestor)?;
            if !m.is_dir()
                || ![0, nix::unistd::geteuid().as_raw()].contains(&m.uid())
                || (m.mode() & 0o022 != 0 && !(m.uid() == 0 && m.mode() & 0o1000 != 0))
            {
                return Err(anyhow!("untrusted job parent"));
            }
        }
        let base = parent.join("managed-jobs");
        create_dir(&base)?;
        let root = base.join(device);
        create_dir(&root)?;
        Ok(Self {
            root,
            device: device.into(),
        })
    }
    fn directory(&self, id: &str) -> Result<PathBuf> {
        let parsed = Uuid::parse_str(id)?;
        if parsed.to_string() != id {
            return Err(anyhow!("noncanonical job id"));
        }
        trusted_dir(&self.root)?;
        let dir = self.root.join(id);
        trusted_dir(&dir)?;
        Ok(dir)
    }
    fn read(&self, id: &str) -> Result<Job> {
        let dir = self.directory(id)?;
        let job: Job =
            serde_json::from_slice(&read_protected(&dir.join("job.json"), STATE_LIMIT)?)?;
        if job.process_id != id || job.device_id != self.device {
            return Err(anyhow!("job device identity mismatch"));
        }
        if let Some(unit) = &job.systemd_unit {
            if unit != &format!("commandcore-job-{}-{}.service", self.device, id) {
                return Err(anyhow!("managed unit identity mismatch"));
            }
        }
        Ok(job)
    }
    fn reconcile(&self, mut job: Job) -> Result<Job> {
        if job.running {
            if job.boot_id != boot()? {
                job.running = false;
                job.termination_reason = Some("host_rebooted".into());
                job.reconciled_at = Some(now());
            } else if !matches(job.worker_pid, &job.worker_start) {
                if job.worker_pid == 0 && now() - job.started_at < 15.0 {
                    return Ok(job); // systemd worker has not claimed its identity yet
                }
                // Never signal a reused PID. An orphaned surviving child is
                // explicitly reported; remote stop cannot pretend it succeeded.
                job.running = matches(job.pid, &job.pid_start);
                job.termination_reason = Some("worker_lost".into());
                job.reconciled_at = Some(now());
                if let Some(unit) = &job.systemd_unit {
                    let properties = unit_properties(unit)?;
                    if properties["InvocationID"].as_str() == job.invocation_id.as_deref()
                        && properties["Result"] == "oom-kill"
                    {
                        job.termination_reason = Some("workload_oom".into());
                    } else if job
                        .manager_pid
                        .zip(job.manager_start.as_deref())
                        .is_some_and(|(pid, start)| !matches(pid, start))
                    {
                        job.termination_reason = Some("user_manager_lost".into());
                    }
                }
                if !job.running {
                    // Completion instant is unknown after supervisor loss.
                    job.completed_at = None;
                }
            }
            if job.termination_reason.is_some() {
                write_atomic(&self.directory(&job.process_id)?.join("job.json"), &job)?;
            }
        }
        Ok(job)
    }
    pub fn status(&self, id: &str) -> Result<Value> {
        Uuid::parse_str(id)?;
        if !self.root.join(id).exists() {
            return Ok(
                json!({"process_id":id,"found":false,"managed":false,"running":false,"reason":"unknown_process"}),
            );
        }
        let job = self.reconcile(self.read(id)?)?;
        let resource_snapshot = resources(&job);
        let mut value = serde_json::to_value(job)?;
        value["found"] = json!(true);
        value["managed"] = json!(true);
        value["elapsed_seconds"] = json!(
            value["completed_at"]
                .as_f64()
                .or_else(|| value["reconciled_at"].as_f64())
                .unwrap_or_else(now)
                - value["started_at"].as_f64().unwrap_or_else(now)
        );
        value["elapsed_is_reconciled_upper_bound"] =
            json!(value["completed_at"].is_null() && value["reconciled_at"].is_number());
        value["resources"] = resource_snapshot;
        value["failure_domain"] = json!(if value["systemd_unit"].is_string() {
            "separate_user_unit"
        } else {
            "shared_parent_cgroup"
        });
        Ok(value)
    }
    pub fn list(&self) -> Result<Vec<Value>> {
        trusted_dir(&self.root)?;
        let mut jobs = Vec::new();
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let id = entry.file_name().to_string_lossy().into_owned();
            if Uuid::parse_str(&id).is_err() {
                continue;
            }
            jobs.push(self.status(&id)?);
        }
        jobs.sort_by(|a, b| {
            b["started_at"]
                .as_f64()
                .unwrap_or_default()
                .total_cmp(&a["started_at"].as_f64().unwrap_or_default())
        });
        Ok(jobs)
    }
    fn cleanup(&self) -> Result<()> {
        let mut retained = 0;
        for job in self.list()? {
            if job["running"] == true {
                continue;
            }
            retained += 1;
            if retained > 100
                || job["completed_at"]
                    .as_f64()
                    .or_else(|| job["reconciled_at"].as_f64())
                    .is_some_and(|v| now() - v > 7.0 * 86400.0)
            {
                let id = job["process_id"].as_str().context("missing id")?;
                let dir = self.directory(id)?;
                let metadata = self.read(id)?;
                if let Some(unit) = &metadata.systemd_unit {
                    let properties = unit_properties(unit)?;
                    if properties["InvocationID"].as_str() == metadata.invocation_id.as_deref() {
                        let status = std::process::Command::new("systemctl")
                            .args(["--user", "stop", unit])
                            .stdin(Stdio::null())
                            .stdout(Stdio::null())
                            .stderr(Stdio::null())
                            .status()?;
                        if !status.success() {
                            return Err(anyhow!("managed unit cleanup failed"));
                        }
                    }
                }
                // Remove only this store's validated immediate job directory.
                fs::remove_dir_all(dir)?;
            }
        }
        Ok(())
    }
    pub async fn start(&self, spec: &Value) -> Result<Value> {
        let serialized = serde_json::to_vec(spec)?;
        if serialized.len() > 2_097_152 {
            return Err(anyhow!("worker input limit"));
        }
        let command = spec["command"].as_str().context("command required")?;
        if command.len() > 1_048_576 {
            return Err(anyhow!("command too large"));
        }
        self.cleanup()?;
        if self.list()?.iter().filter(|j| j["running"] == true).count() >= 32 {
            return Err(anyhow!("managed job limit reached"));
        }
        let id = Uuid::new_v4().to_string();
        let dir = self.root.join(&id);
        let systemd_unit = user_manager_available()
            .then(|| format!("commandcore-job-{}-{}.service", self.device, id));
        let mut child = if let Some(unit) = &systemd_unit {
            let mut cmd = Command::new("systemd-run");
            cmd.args([
                "--user",
                "--quiet",
                "--pipe",
                "--service-type=exec",
                "--unit",
                unit,
                "--property=RemainAfterExit=no",
                "--property=Restart=no",
                "--property=KillMode=control-group",
                "--property=OOMPolicy=kill",
                "--property=NoNewPrivileges=yes",
                "--property=OOMScoreAdjust=500",
                "--property=TimeoutStopSec=5s",
            ]);
            // Optional local owner policy; remote process arguments cannot set it.
            let policy = self
                .root
                .parent()
                .and_then(Path::parent)
                .context("job policy parent")?
                .join("job-resources.json");
            if policy.exists() {
                let policy: Value = serde_json::from_slice(&read_protected(&policy, STATE_LIMIT)?)?;
                let limit = policy["memory_max_bytes"]
                    .as_u64()
                    .filter(|v| *v >= 64 * 1024 * 1024)
                    .context("invalid local job memory limit (minimum 64 MiB)")?;
                cmd.arg(format!("--property=MemoryMax={limit}"));
                cmd.arg("--property=MemorySwapMax=0");
            }
            cmd.arg("--").arg(std::env::current_exe()?);
            cmd
        } else {
            // Development/non-systemd environments retain the RC4 supervisor.
            // A real installed user service must never silently share its cgroup.
            let cgroup = fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
            if cgroup.contains("commandcore-agent") && cgroup.contains(".service") {
                return Err(anyhow!(
                    "user manager unavailable: refusing shared-cgroup workload"
                ));
            }
            Command::new(std::env::current_exe()?)
        };
        child
            .arg("job-worker")
            .arg("--root")
            .arg(&self.root)
            .arg("--device")
            .arg(&self.device)
            .arg("--job")
            .arg(&id)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(false);
        child.process_group(0);
        create_dir(&dir)?;
        let mut child = match child.spawn() {
            Ok(child) => child,
            Err(e) => {
                fs::remove_dir(&dir)?;
                return Err(e.into());
            }
        };
        let worker_pid = if systemd_unit.is_some() {
            0
        } else {
            child.id().context("missing worker pid")?
        };
        let worker_start = if worker_pid == 0 {
            String::new()
        } else {
            identity(worker_pid)?
        };
        let meta = Job {
            process_id: id.clone(),
            device_id: self.device.clone(),
            worker_pid,
            worker_start,
            pid: 0,
            pid_start: String::new(),
            boot_id: boot()?,
            started_at: now(),
            completed_at: None,
            running: true,
            exit_code: None,
            signal: None,
            termination_reason: None,
            systemd_unit,
            invocation_id: None,
            reconciled_at: None,
            manager_pid: None,
            manager_start: None,
        };
        write_atomic(&dir.join("job.json"), &meta)?;
        let mut input = child.stdin.take().context("worker input")?;
        input.write_all(&serialized).await?;
        input.shutdown().await?;
        drop(input);
        // Reap locally while this Agent exists. Restart reparents the independent
        // supervisor to init; dropping this handle never kills its workload.
        tokio::spawn(async move {
            let _ = child.wait().await;
        });
        for _ in 0..100 {
            let state = self.status(&id)?;
            if state["pid"].as_u64().unwrap_or(0) > 0 {
                return Ok(state);
            }
            if state["running"] == false {
                return Err(anyhow!("managed worker failed to start"));
            }
            sleep(Duration::from_millis(20)).await;
        }
        Err(anyhow!("managed worker startup timed out"))
    }
    pub fn output(&self, id: &str, offset: usize, limit: usize) -> Result<Value> {
        let state = self.status(id)?;
        if state["found"] == false {
            return Ok(json!({"process_id":id,"available":false,"reason":"unknown_process"}));
        }
        let dir = self.directory(id)?;
        let read_output = |name: &str| -> Result<Vec<u8>> {
            let path = dir.join(name);
            if !path.exists() {
                return Ok(Vec::new());
            }
            read_protected(&path, OUTPUT_LIMIT as u64)
        };
        let stdout = read_output("stdout")?;
        let stderr = read_output("stderr")?;
        let stats = |name: &str, retained: usize| -> Result<Value> {
            let path = dir.join(format!("{name}.stats.json"));
            if !path.exists() {
                return Ok(
                    json!({"retained_bytes":retained,"truncated":null,"complete":false,"reason":"legacy_or_capture_not_started"}),
                );
            }
            Ok(serde_json::from_slice(&read_protected(
                &path,
                STATE_LIMIT,
            )?)?)
        };
        let stdout_stats = stats("stdout", stdout.len())?;
        let stderr_stats = stats("stderr", stderr.len())?;
        let slice = |b: Vec<u8>| {
            let start = offset.min(b.len());
            String::from_utf8_lossy(
                &b[start..start.saturating_add(limit.min(OUTPUT_LIMIT)).min(b.len())],
            )
            .into_owned()
        };
        Ok(
            json!({"process_id":id,"available":true,"running":state["running"],"stdout":slice(stdout),"stderr":slice(stderr),"stdout_capture":stdout_stats,"stderr_capture":stderr_stats,"output_limit_bytes":OUTPUT_LIMIT,"exit_code":state["exit_code"],"signal":state["signal"],"termination_reason":state["termination_reason"]}),
        )
    }
    pub async fn stop(&self, id: &str, force: bool) -> Result<Value> {
        let state = self.status(id)?;
        if state["found"] == false {
            return Ok(json!({"process_id":id,"stopped":false,"reason":"unknown_process"}));
        }
        if state["running"] == false {
            return Ok(
                json!({"process_id":id,"stopped":true,"already_exited":true,"termination_reason":state["termination_reason"],"signal":state["signal"]}),
            );
        }
        if state["termination_reason"] == "worker_lost"
            || state["termination_reason"] == "user_manager_lost"
        {
            return Ok(
                json!({"process_id":id,"stopped":false,"reason":"worker_lost","requires_local_reconciliation":true}),
            );
        }
        write_atomic(
            &self.directory(id)?.join("stop.json"),
            &json!({"force":force}),
        )?;
        for _ in 0..150 {
            let state = self.status(id)?;
            if state["running"] == false {
                return Ok(
                    json!({"process_id":id,"stopped":true,"already_exited":false,"exit_code":state["exit_code"],"termination_reason":state["termination_reason"],"signal":state["signal"]}),
                );
            }
            sleep(Duration::from_millis(50)).await;
        }
        Err(anyhow!("managed termination timeout"))
    }
}

async fn capture(mut stream: impl AsyncRead + Unpin, path: PathBuf) -> Result<()> {
    let stats_path = path.with_file_name(format!(
        "{}.stats.json",
        path.file_name().context("output file")?.to_string_lossy()
    ));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    let mut retained = 0;
    let mut observed = 0u64;
    let mut last_output_at: Option<f64> = None;
    let mut published = 0u64;
    let mut last_publish = std::time::Instant::now();
    write_atomic(
        &stats_path,
        &json!({"observed_bytes":0,"retained_bytes":0,"truncated":false,"complete":false,"last_output_at":null}),
    )?;
    let mut buf = [0u8; 8192];
    loop {
        let size = stream.read(&mut buf).await?;
        if size == 0 {
            break;
        }
        let amount = size.min(OUTPUT_LIMIT - retained);
        file.write_all(&buf[..amount])?;
        retained += amount;
        observed = observed.saturating_add(size as u64);
        last_output_at = Some(now());
        // Discard excess while draining the pipe, so output limits never block jobs.
        file.flush()?;
        if published == 0
            || observed - published >= 65536
            || last_publish.elapsed() >= Duration::from_secs(1)
        {
            write_atomic(
                &stats_path,
                &json!({"observed_bytes":observed,"retained_bytes":retained,"truncated":observed > retained as u64,"complete":false,"last_output_at":last_output_at}),
            )?;
            published = observed;
            last_publish = std::time::Instant::now();
        }
    }
    file.sync_all()?;
    write_atomic(
        &stats_path,
        &json!({"observed_bytes":observed,"retained_bytes":retained,"truncated":observed > retained as u64,"complete":true,"last_output_at":last_output_at}),
    )?;
    Ok(())
}

pub async fn worker(root: PathBuf, device: String, id: String) -> Result<()> {
    let store = JobStore { root, device };
    let dir = store.directory(&id)?;
    let mut input = Vec::new();
    std::io::stdin().take(2_097_153).read_to_end(&mut input)?;
    if input.len() > 2_097_152 {
        return Err(anyhow!("worker input limit"));
    }
    let mut meta = store.read(&id)?;
    if meta.worker_pid == 0 {
        let unit = meta.systemd_unit.as_ref().context("missing managed unit")?;
        let cgroup = fs::read_to_string("/proc/self/cgroup")?;
        if meta.boot_id != boot()?
            || !cgroup
                .lines()
                .any(|line| line.ends_with(&format!("/{unit}")))
        {
            return Err(anyhow!("worker unit identity mismatch"));
        }
        let properties = unit_properties(unit)?;
        meta.invocation_id = Some(
            properties["InvocationID"]
                .as_str()
                .filter(|s| !s.is_empty())
                .context("missing invocation identity")?
                .into(),
        );
        meta.worker_pid = std::process::id();
        meta.worker_start = identity(meta.worker_pid)?;
        let parent = nix::unistd::getppid().as_raw() as u32;
        meta.manager_pid = Some(parent);
        meta.manager_start = Some(identity(parent)?);
        write_atomic(&dir.join("job.json"), &meta)?;
    }
    if meta.worker_pid != std::process::id() || !matches(meta.worker_pid, &meta.worker_start) {
        return Err(anyhow!("worker identity mismatch"));
    }
    let spec: Value = serde_json::from_slice(&input)?;
    let mut command = Command::new("/bin/sh");
    command
        .arg("-c")
        .arg(spec["command"].as_str().context("command required")?);
    if let Some(cwd) = spec["cwd"].as_str() {
        command.current_dir(cwd);
    }
    if let Some(env) = spec["env"].as_object() {
        for (k, v) in env {
            if let Some(v) = v.as_str() {
                command.env(k, v);
            }
        }
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .kill_on_drop(true);
    let mut child = command.spawn()?;
    meta.pid = child.id().context("missing job pid")?;
    meta.pid_start = identity(meta.pid)?;
    write_atomic(&dir.join("job.json"), &meta)?;
    let stdout = tokio::spawn(capture(
        child.stdout.take().context("stdout")?,
        dir.join("stdout"),
    ));
    let stderr = tokio::spawn(capture(
        child.stderr.take().context("stderr")?,
        dir.join("stderr"),
    ));
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if dir.join("stop.json").exists() {
            let request: Value =
                serde_json::from_slice(&read_protected(&dir.join("stop.json"), STATE_LIMIT)?)?;
            let force = request["force"] == true;
            let sig = if force {
                Signal::SIGKILL
            } else {
                Signal::SIGTERM
            };
            if !matches(meta.pid, &meta.pid_start) {
                return Err(anyhow!("job PID changed before stop"));
            }
            killpg(Pid::from_raw(meta.pid as i32), sig)?;
            meta.termination_reason = Some("stopped_by_request".into());
            meta.signal = Some(format!("{sig:?}"));
            match tokio::time::timeout(Duration::from_secs(3), child.wait()).await {
                Ok(status) => break status?,
                Err(_) => {
                    // Child remains unreaped here; its PID cannot have been reused.
                    killpg(Pid::from_raw(meta.pid as i32), Signal::SIGKILL)?;
                    meta.signal = Some("SIGKILL".into());
                    break child.wait().await?;
                }
            }
        }
        sleep(Duration::from_millis(50)).await;
    };
    for mut drain in [stdout, stderr] {
        if tokio::time::timeout(Duration::from_secs(2), &mut drain)
            .await
            .is_err()
        {
            drain.abort();
        }
    }
    use std::os::unix::process::ExitStatusExt;
    meta.running = false;
    meta.completed_at = Some(now());
    meta.exit_code = status.code();
    if meta.termination_reason.is_none() {
        meta.termination_reason = Some(
            if status.signal().is_some() {
                "terminated_by_signal"
            } else {
                "exited"
            }
            .into(),
        );
        meta.signal = status
            .signal()
            .and_then(|n| Signal::try_from(n).ok())
            .map(|s| format!("{s:?}"));
    }
    write_atomic(&dir.join("job.json"), &meta)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn cross_device_and_unsafe_state_rejected() {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let device = Uuid::new_v4().to_string();
        let store = JobStore::new(temp.path(), &device).unwrap();
        assert!(store.status("../escape").is_err());
        let id = Uuid::new_v4().to_string();
        create_dir(&store.root.join(&id)).unwrap();
        let meta = Job {
            process_id: id.clone(),
            device_id: Uuid::new_v4().to_string(),
            worker_pid: 1,
            worker_start: "wrong".into(),
            pid: 1,
            pid_start: "wrong".into(),
            boot_id: boot().unwrap(),
            started_at: now(),
            completed_at: None,
            running: true,
            exit_code: None,
            signal: None,
            termination_reason: None,
            systemd_unit: None,
            invocation_id: None,
            reconciled_at: None,
            manager_pid: None,
            manager_start: None,
        };
        write_atomic(&store.root.join(&id).join("job.json"), &meta).unwrap();
        assert!(store.status(&id).is_err());
    }
    #[test]
    fn reused_pid_never_appears_running() {
        let temp = tempfile::tempdir().unwrap();
        let device = Uuid::new_v4().to_string();
        let store = JobStore::new(temp.path(), &device).unwrap();
        let id = Uuid::new_v4().to_string();
        create_dir(&store.root.join(&id)).unwrap();
        let meta = Job {
            process_id: id.clone(),
            device_id: device,
            worker_pid: std::process::id(),
            worker_start: "impossible".into(),
            pid: std::process::id(),
            pid_start: "impossible".into(),
            boot_id: boot().unwrap(),
            started_at: now(),
            completed_at: None,
            running: true,
            exit_code: None,
            signal: None,
            termination_reason: None,
            systemd_unit: None,
            invocation_id: None,
            reconciled_at: None,
            manager_pid: None,
            manager_start: None,
        };
        write_atomic(&store.root.join(&id).join("job.json"), &meta).unwrap();
        let state = store.status(&id).unwrap();
        assert_eq!(state["running"], false);
        assert_eq!(state["termination_reason"], "worker_lost");
        assert!(state["completed_at"].is_null());
        assert!(state["reconciled_at"].is_number());
    }

    #[tokio::test]
    async fn bounded_capture_exposes_overflow_and_last_output() {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let (mut writer, reader) = tokio::io::duplex(8192);
        let producer = tokio::spawn(async move {
            let block = [b'x'; 8192];
            for _ in 0..140 {
                writer.write_all(&block).await.unwrap();
            }
        });
        capture(reader, temp.path().join("stdout")).await.unwrap();
        producer.await.unwrap();
        assert_eq!(
            fs::metadata(temp.path().join("stdout")).unwrap().len(),
            OUTPUT_LIMIT as u64
        );
        let stats: Value = serde_json::from_slice(
            &read_protected(&temp.path().join("stdout.stats.json"), STATE_LIMIT).unwrap(),
        )
        .unwrap();
        assert_eq!(stats["observed_bytes"], 140 * 8192);
        assert_eq!(stats["truncated"], true);
        assert_eq!(stats["complete"], true);
        assert!(stats["last_output_at"].is_number());
    }

    #[tokio::test]
    async fn unknown_job_is_a_domain_result() {
        let temp = tempfile::tempdir().unwrap();
        let store = JobStore::new(temp.path(), &Uuid::new_v4().to_string()).unwrap();
        let id = Uuid::new_v4().to_string();
        assert_eq!(store.status(&id).unwrap()["found"], false);
        assert_eq!(store.output(&id, 0, 100).unwrap()["available"], false);
        assert_eq!(
            store.stop(&id, true).await.unwrap()["reason"],
            "unknown_process"
        );
    }
}
