use crate::{
    helper::{runtime_capabilities, HelperClient},
    output::OutputSink,
    policy::{is_allowed, load_local_policy, PermissionProfile},
};
use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use regex::Regex;
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    env, fs,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::AsyncReadExt,
    process::{Child, Command},
    sync::Mutex,
    time::{sleep, timeout},
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use walkdir::WalkDir;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone)]
pub struct Executor {
    inner: Arc<Inner>,
}

struct Inner {
    running: Mutex<HashMap<String, CancellationToken>>,
    managed: Mutex<HashMap<String, Arc<ManagedProcess>>>,
    helper: HelperClient,
    max_transfer_bytes: usize,
    #[cfg(target_os = "linux")]
    job_store: Option<crate::jobs::JobStore>,
}

struct ManagedProcess {
    pid: u32,
    command: String,
    cwd: Option<String>,
    started_at: f64,
    stdout: Mutex<Vec<u8>>,
    stderr: Mutex<Vec<u8>>,
    running: AtomicBool,
    force_stop: AtomicBool,
    exit_code: Mutex<Option<i32>>,
    cancel: CancellationToken,
}

impl Executor {
    pub fn new(max_transfer_bytes: usize) -> Self {
        Self {
            inner: Arc::new(Inner {
                running: Mutex::new(HashMap::new()),
                managed: Mutex::new(HashMap::new()),
                helper: HelperClient::default(),
                max_transfer_bytes,
                #[cfg(target_os = "linux")]
                job_store: None,
            }),
        }
    }

    pub fn for_state(
        max_transfer_bytes: usize,
        state_path: &Path,
        device_id: &str,
    ) -> Result<Self> {
        let mut executor = Self::new(max_transfer_bytes);
        #[cfg(target_os = "linux")]
        {
            let store = crate::jobs::JobStore::new(
                state_path.parent().context("state parent required")?,
                device_id,
            )?;
            Arc::get_mut(&mut executor.inner)
                .context("executor already shared")?
                .job_store = Some(store);
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (state_path, device_id, &mut executor);
        }
        Ok(executor)
    }

    pub async fn authorization_revoked(&self) {
        self.cancel_requests().await;
        if load_local_policy().stop_managed_jobs_on_revocation {
            #[cfg(target_os = "linux")]
            if let Some(store) = &self.inner.job_store {
                if let Ok(jobs) = store.list() {
                    for job in jobs {
                        if let Some(id) = job["process_id"].as_str() {
                            let _ = store.stop(id, false).await;
                        }
                    }
                }
            }
            self.cancel_all().await;
        }
    }

    pub async fn cancel(&self, execution_id: &str) {
        let _ = self.inner.helper.cancel(execution_id).await;
        if let Some(token) = self.inner.running.lock().await.get(execution_id).cloned() {
            token.cancel();
        }
    }

    pub async fn cancel_all(&self) {
        self.cancel_requests().await;
        let processes: Vec<Arc<ManagedProcess>> =
            self.inner.managed.lock().await.values().cloned().collect();
        for process in &processes {
            process.cancel.cancel();
        }
        let _ = timeout(Duration::from_secs(5), async {
            while processes.iter().any(|p| p.running.load(Ordering::Acquire)) {
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
    }

    pub async fn cancel_requests(&self) {
        let tokens: Vec<CancellationToken> =
            self.inner.running.lock().await.values().cloned().collect();
        for token in tokens {
            token.cancel();
        }
    }

    pub async fn execute(
        &self,
        execution_id: &str,
        profile_raw: &str,
        tool: &str,
        args: Value,
        output: OutputSink,
    ) -> Value {
        let requested = PermissionProfile::parse(profile_raw);
        let configured = load_local_policy().configured_max;
        let profile = std::cmp::min(requested, configured);
        if !is_allowed(profile, tool) {
            if requested > configured {
                return json!({"status":"error","error":format!("local_permission_ceiling:{}", configured.as_str())});
            }
            return json!({"status":"error","error":format!("permission_denied: {tool} under {}", profile.as_str())});
        }
        if profile == PermissionProfile::FullControl {
            let probe = self.inner.helper.probe().await;
            if probe.get("available").and_then(Value::as_bool) != Some(true)
                || probe.get("max_permission_profile").and_then(Value::as_str)
                    != Some("FULL_CONTROL")
            {
                return json!({"status":"error","error":"privileged_helper_unavailable_or_not_authorized"});
            }
            return self
                .inner
                .helper
                .execute(execution_id, tool, args, &output)
                .await
                .unwrap_or_else(
                    |e| json!({"status":"error","error":format!("helper_error: {e}")}),
                );
        }
        let result = self.execute_local(execution_id, tool, &args, output).await;
        match result {
            Ok(v) => {
                if v.get("status")
                    .and_then(Value::as_str)
                    .is_some_and(|s| s == "error" || s == "timeout")
                {
                    v
                } else {
                    json!({"status":"ok","result":v})
                }
            }
            Err(e) => json!({"status":"error","error":format!("{}", e)}),
        }
    }

    async fn execute_local(
        &self,
        execution_id: &str,
        tool: &str,
        args: &Value,
        output: OutputSink,
    ) -> Result<Value> {
        match tool {
            "fs.list" => self.fs_list(args).await,
            "fs.stat" => self.fs_stat(args).await,
            "fs.read" => self.fs_read(args).await,
            "fs.write" => self.fs_write(args).await,
            "fs.patch" => self.fs_patch(args).await,
            "fs.search" => self.fs_search(args).await,
            "fs.copy" => self.fs_copy(args).await,
            "fs.move" => self.fs_move(args).await,
            "fs.delete" => self.fs_delete(args).await,
            "shell.exec" => self.shell_exec(execution_id, args, output).await,
            "process.start" => self.process_start(args).await,
            "process.list" => self.process_list(args).await,
            "process.status" => self.process_status(args).await,
            "process.output" => self.process_output(args).await,
            "process.stop" => self.process_stop(args).await,
            "system.info" => self.system_info().await,
            "system.metrics" => self.system_metrics(true).await,
            "transfer.upload" => self.transfer_upload(args).await,
            "transfer.download" => self.transfer_download(args).await,
            "git.status" => self.git_status(args).await,
            "git.diff" => self.git_diff(args).await,
            "git.log" => self.git_log(args).await,
            "git.run" => self.git_run(execution_id, args, output).await,
            "agent.update.status" => self.agent_update_status().await,
            _ => Err(anyhow!("unsupported_tool: {tool}")),
        }
    }

    async fn fs_list(&self, args: &Value) -> Result<Value> {
        let path = req_str(args, "path")?;
        let limit = args
            .get("limit")
            .and_then(Value::as_u64)
            .unwrap_or(1000)
            .clamp(1, 5000) as usize;
        let mut entries = Vec::new();
        for entry in fs::read_dir(&path)?.take(limit) {
            let entry = entry?;
            let meta = fs::symlink_metadata(entry.path())?;
            entries.push(json!({
                "name":entry.file_name().to_string_lossy(),
                "path":entry.path().to_string_lossy(),
                "is_file":meta.is_file(),"is_dir":meta.is_dir(),"is_symlink":meta.file_type().is_symlink(),
                "size":meta.len(),
            }));
        }
        Ok(json!({"path":path,"entries":entries}))
    }

    async fn fs_stat(&self, args: &Value) -> Result<Value> {
        let path = req_str(args, "path")?;
        let meta = match fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(json!({"path":path,"found":false,"reason":"file_not_found"}))
            }
            Err(e) => return Err(e.into()),
        };
        Ok(json!({
            "path":path,"found":true,"size":meta.len(),"is_file":meta.is_file(),"is_dir":meta.is_dir(),"is_symlink":meta.file_type().is_symlink(),
            "modified":meta.modified().ok().and_then(system_time_secs),"created":meta.created().ok().and_then(system_time_secs),
            "readonly":meta.permissions().readonly(),
        }))
    }

    async fn fs_read(&self, args: &Value) -> Result<Value> {
        let path = req_str(args, "path")?;
        let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0);
        let length = args
            .get("length")
            .and_then(Value::as_u64)
            .unwrap_or(65536)
            .clamp(1, 1_048_576) as usize;
        let encoding = args
            .get("encoding")
            .and_then(Value::as_str)
            .unwrap_or("text");
        let mut file = match fs::File::open(&path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(json!({"path":path,"found":false,"reason":"file_not_found"}))
            }
            Err(e) => return Err(e.into()),
        };
        file.seek(SeekFrom::Start(offset))?;
        let mut buf = vec![0u8; length];
        let n = file.read(&mut buf)?;
        buf.truncate(n);
        let data = if encoding == "base64" {
            B64.encode(&buf)
        } else {
            String::from_utf8_lossy(&buf).to_string()
        };
        Ok(
            json!({"path":path,"found":true,"offset":offset,"bytes":n,"encoding":encoding,"data":data,"eof":n < length}),
        )
    }

    async fn fs_write(&self, args: &Value) -> Result<Value> {
        let path = PathBuf::from(req_str(args, "path")?);
        let data = req_str(args, "data")?;
        let mode = args
            .get("mode")
            .and_then(Value::as_str)
            .unwrap_or("rewrite");
        let encoding = args
            .get("encoding")
            .and_then(Value::as_str)
            .unwrap_or("text");
        if args
            .get("create_parents")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
        }
        let bytes = if encoding == "base64" {
            B64.decode(data)?
        } else {
            data.into_bytes()
        };
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true);
        if mode == "append" {
            opts.append(true);
        } else {
            opts.truncate(true);
        }
        let mut f = opts.open(&path)?;
        f.write_all(&bytes)?;
        f.flush()?;
        Ok(json!({"path":path.to_string_lossy(),"bytes_written":bytes.len(),"mode":mode}))
    }

    async fn fs_patch(&self, args: &Value) -> Result<Value> {
        let requested = PathBuf::from(req_str(args, "path")?);
        let follow = args
            .get("follow_symlinks")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let link_meta = fs::symlink_metadata(&requested)?;
        if link_meta.file_type().is_symlink() && !follow {
            return Err(anyhow!("symlink_refused"));
        }
        let path = if link_meta.file_type().is_symlink() {
            fs::canonicalize(&requested)?
        } else {
            requested.clone()
        };
        let meta = fs::metadata(&path)?;
        if !meta.is_file() {
            return Err(anyhow!("path_not_regular_file"));
        }
        let mut text = fs::read_to_string(&path).context("fs.patch requires UTF-8 text")?;
        let patches = args
            .get("patches")
            .and_then(Value::as_array)
            .context("patches must be an array")?;
        let mut applied = 0usize;
        for patch in patches {
            let search = req_str(patch, "search")?;
            let replace = req_str(patch, "replace")?;
            let replace_all = patch
                .get("replace_all")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let count = text.matches(&search).count();
            if count == 0 {
                return Err(anyhow!("patch_search_missing"));
            }
            if count > 1 && !replace_all {
                return Err(anyhow!("patch_search_ambiguous"));
            }
            text = if replace_all {
                text.replace(&search, &replace)
            } else {
                text.replacen(&search, &replace, 1)
            };
            applied += if replace_all { count } else { 1 };
        }
        let parent = path.parent().context("patch path has no parent")?;
        let temp = parent.join(format!(
            ".{}.{}.tmp",
            path.file_name().and_then(|x| x.to_str()).unwrap_or("patch"),
            Uuid::new_v4()
        ));
        {
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp)?;
            f.write_all(text.as_bytes())?;
            f.sync_all()?;
        }
        fs::set_permissions(&temp, meta.permissions())?;
        fs::rename(&temp, &path)?;
        Ok(
            json!({"path":requested.to_string_lossy(),"resolved_path":path.to_string_lossy(),"patches_applied":patches.len(),"replacements":applied}),
        )
    }

    async fn fs_search(&self, args: &Value) -> Result<Value> {
        let root = PathBuf::from(req_str(args, "root")?);
        let query = req_str(args, "query")?;
        let content = args
            .get("content")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let regex_mode = args.get("regex").and_then(Value::as_bool).unwrap_or(false);
        let max_results = args
            .get("max_results")
            .and_then(Value::as_u64)
            .unwrap_or(100)
            .clamp(1, 1000) as usize;
        let re = if regex_mode {
            Some(Regex::new(&query)?)
        } else {
            None
        };
        let matches = |text: &str| -> bool {
            re.as_ref()
                .map(|r| r.is_match(text))
                .unwrap_or_else(|| text.contains(&query))
        };
        let mut results = Vec::new();
        let exclude_dirs: Vec<&str> = args["exclude_dirs"]
            .as_array()
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let max_file_bytes = args["max_file_bytes"]
            .as_u64()
            .unwrap_or(2 * 1024 * 1024)
            .clamp(1, 2 * 1024 * 1024);
        for item in WalkDir::new(&root)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| {
                e.depth() == 0
                    || !e.file_type().is_dir()
                    || !exclude_dirs.contains(&e.file_name().to_str().unwrap_or(""))
            })
            .filter_map(Result::ok)
        {
            if results.len() >= max_results {
                break;
            }
            let path = item.path();
            let name = path.file_name().and_then(|x| x.to_str()).unwrap_or("");
            if matches(name) {
                results.push(json!({"path":path.to_string_lossy(),"match":"name"}));
                if results.len() >= max_results {
                    break;
                }
            }
            if content && item.file_type().is_file() {
                if let Ok(meta) = item.metadata() {
                    if meta.len() <= max_file_bytes {
                        if let Ok(text) = fs::read_to_string(path) {
                            if !text.contains('\0') && matches(&text) {
                                results
                                    .push(json!({"path":path.to_string_lossy(),"match":"content"}));
                            }
                        }
                    }
                }
            }
        }
        let truncated = results.len() >= max_results;
        Ok(
            json!({"root":root.to_string_lossy(),"query":query,"results":results,"truncated":truncated,"exclude_dirs":exclude_dirs,"max_file_bytes":max_file_bytes,"binary_skipping":true}),
        )
    }

    async fn fs_copy(&self, args: &Value) -> Result<Value> {
        let src = PathBuf::from(req_str(args, "source")?);
        let dst = PathBuf::from(req_str(args, "destination")?);
        let overwrite = args
            .get("overwrite")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if dst.exists() {
            if !overwrite {
                return Err(anyhow!("destination_exists"));
            }
            remove_path(&dst, true)?;
        }
        copy_recursive(&src, &dst)?;
        Ok(json!({"source":src.to_string_lossy(),"destination":dst.to_string_lossy()}))
    }

    async fn fs_move(&self, args: &Value) -> Result<Value> {
        let src = PathBuf::from(req_str(args, "source")?);
        let dst = PathBuf::from(req_str(args, "destination")?);
        let overwrite = args
            .get("overwrite")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if dst.exists() {
            if !overwrite {
                return Err(anyhow!("destination_exists"));
            }
            remove_path(&dst, true)?;
        }
        fs::rename(&src, &dst)?;
        Ok(json!({"source":src.to_string_lossy(),"destination":dst.to_string_lossy()}))
    }

    async fn fs_delete(&self, args: &Value) -> Result<Value> {
        let path = PathBuf::from(req_str(args, "path")?);
        let recursive = args
            .get("recursive")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        remove_path(&path, recursive)?;
        Ok(json!({"path":path.to_string_lossy(),"deleted":true}))
    }

    async fn shell_exec(
        &self,
        execution_id: &str,
        args: &Value,
        output: OutputSink,
    ) -> Result<Value> {
        let command = req_str(args, "command")?;
        let cwd = args
            .get("cwd")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let timeout_ms = args
            .get("timeout_ms")
            .and_then(Value::as_u64)
            .unwrap_or(30000)
            .clamp(100, 3_600_000);
        let envs = json_string_map(args.get("env"));
        self.run_command(
            execution_id,
            shell_command(&command),
            cwd,
            envs,
            Duration::from_millis(timeout_ms),
            output,
        )
        .await
    }

    async fn run_command(
        &self,
        execution_id: &str,
        argv: Vec<String>,
        cwd: Option<String>,
        envs: HashMap<String, String>,
        duration: Duration,
        output: OutputSink,
    ) -> Result<Value> {
        let mut cmd = command_with_args(&argv)?;
        if let Some(cwd) = cwd.as_deref() {
            cmd.current_dir(cwd);
        }
        cmd.envs(envs);
        cmd.stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        #[cfg(unix)]
        {
            cmd.process_group(0);
        }
        let mut child = cmd.spawn()?;
        let pid = child.id().unwrap_or(0);
        let token = CancellationToken::new();
        self.inner
            .running
            .lock()
            .await
            .insert(execution_id.to_string(), token.clone());
        let out_task = child.stdout.take().map(|mut stream| {
            let sink = output.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            sink.send("stdout", String::from_utf8_lossy(&buf[..n]).to_string())
                                .await
                        }
                    }
                }
            })
        });
        let err_task = child.stderr.take().map(|mut stream| {
            let sink = output.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            sink.send("stderr", String::from_utf8_lossy(&buf[..n]).to_string())
                                .await
                        }
                    }
                }
            })
        });
        let outcome = tokio::select! {
            result = timeout(duration, child.wait()) => match result {
                Ok(status) => json!({"exit_code":status?.code(),"pid":pid,"argv":argv}),
                Err(_) => { terminate_child(&mut child, pid, false).await; json!({"status":"timeout","exit_code":child.try_wait()?.and_then(|s|s.code()),"error":"command timeout"}) }
            },
            _ = token.cancelled() => {
                terminate_child(&mut child, pid, false).await;
                json!({"status":"error","error":"cancelled","exit_code":child.try_wait()?.and_then(|s|s.code())})
            }
        };
        if let Some(t) = out_task {
            let _ = t.await;
        }
        if let Some(t) = err_task {
            let _ = t.await;
        }
        self.inner.running.lock().await.remove(execution_id);
        Ok(outcome)
    }

    async fn process_start(&self, args: &Value) -> Result<Value> {
        #[cfg(target_os = "linux")]
        if let Some(store) = &self.inner.job_store {
            let metrics = self.system_metrics(false).await?;
            let mut started = store.start(args).await?;
            started["health_at_start"] = metrics["health"].clone();
            return Ok(started);
        }
        let command = req_str(args, "command")?;
        let cwd = args
            .get("cwd")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let envs = json_string_map(args.get("env"));
        let argv = shell_command(&command);
        let mut cmd = command_with_args(&argv)?;
        if let Some(cwd) = cwd.as_deref() {
            cmd.current_dir(cwd);
        }
        cmd.envs(envs);
        cmd.stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        #[cfg(unix)]
        {
            cmd.process_group(0);
        }
        let mut child = cmd.spawn()?;
        let pid = child.id().unwrap_or(0);
        let process_id = Uuid::new_v4().to_string();
        let managed = Arc::new(ManagedProcess {
            pid,
            command: command.clone(),
            cwd: cwd.clone(),
            started_at: now_secs(),
            stdout: Mutex::new(Vec::new()),
            stderr: Mutex::new(Vec::new()),
            running: AtomicBool::new(true),
            force_stop: AtomicBool::new(false),
            exit_code: Mutex::new(None),
            cancel: CancellationToken::new(),
        });
        self.inner
            .managed
            .lock()
            .await
            .insert(process_id.clone(), managed.clone());
        if let Some(mut stdout) = child.stdout.take() {
            let m = managed.clone();
            tokio::spawn(async move {
                let mut b = vec![0; 8192];
                loop {
                    match stdout.read(&mut b).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => append_bounded(&m.stdout, &b[..n]).await,
                    }
                }
            });
        }
        if let Some(mut stderr) = child.stderr.take() {
            let m = managed.clone();
            tokio::spawn(async move {
                let mut b = vec![0; 8192];
                loop {
                    match stderr.read(&mut b).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => append_bounded(&m.stderr, &b[..n]).await,
                    }
                }
            });
        }
        let monitor = managed.clone();
        tokio::spawn(async move {
            let status = tokio::select! {
                status = child.wait() => status.ok(),
                _ = monitor.cancel.cancelled() => { terminate_child(&mut child, pid, monitor.force_stop.load(Ordering::Acquire)).await; child.wait().await.ok() }
            };
            *monitor.exit_code.lock().await = status.and_then(|s| s.code());
            monitor.running.store(false, Ordering::Release);
        });
        Ok(
            json!({"process_id":process_id,"pid":pid,"command":command,"started_at":managed.started_at}),
        )
    }

    async fn process_list(&self, args: &Value) -> Result<Value> {
        #[cfg(target_os = "linux")]
        {
            let limit = args
                .get("limit")
                .and_then(Value::as_u64)
                .unwrap_or(500)
                .clamp(1, 2000) as usize;
            let needle = args
                .get("filter")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_ascii_lowercase();
            let alternatives: Vec<String> = args["contains_any"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_ascii_lowercase)
                        .collect()
                })
                .unwrap_or_default();
            let mut rows = Vec::new();
            for entry in fs::read_dir("/proc")? {
                let entry = entry?;
                let name = entry.file_name();
                let Some(pid_text) = name.to_str() else {
                    continue;
                };
                let Ok(pid) = pid_text.parse::<u32>() else {
                    continue;
                };
                let base = entry.path();
                let comm = fs::read_to_string(base.join("comm"))
                    .unwrap_or_default()
                    .trim()
                    .to_string();
                let cmdline = fs::read(base.join("cmdline"))
                    .ok()
                    .map(|b| {
                        String::from_utf8_lossy(&b)
                            .replace('\0', " ")
                            .trim()
                            .to_string()
                    })
                    .unwrap_or_default();
                let hay = format!("{comm} {cmdline}").to_ascii_lowercase();
                if !needle.is_empty() && !hay.contains(&needle) {
                    continue;
                }
                if !alternatives.is_empty() && !alternatives.iter().any(|s| hay.contains(s)) {
                    continue;
                }
                if args["pid"].as_u64().is_some_and(|p| p != pid as u64) {
                    continue;
                }
                let stat = fs::read_to_string(base.join("stat")).unwrap_or_default();
                let fields: Vec<_> = stat
                    .rsplit_once(')')
                    .map(|(_, s)| s.split_whitespace().collect())
                    .unwrap_or_default();
                let ppid = fields.get(1).and_then(|s| s.parse::<u32>().ok());
                let state = fields.first().copied();
                if args["parent_pid"]
                    .as_u64()
                    .is_some_and(|p| Some(p) != ppid.map(u64::from))
                {
                    continue;
                }
                if args["state"].as_str().is_some_and(|s| Some(s) != state) {
                    continue;
                }
                use std::os::unix::fs::MetadataExt;
                let uid = fs::metadata(&base).ok().map(|m| m.uid());
                if args["uid"]
                    .as_u64()
                    .is_some_and(|u| Some(u) != uid.map(u64::from))
                {
                    continue;
                }
                let pages = fields.get(21).and_then(|s| s.parse::<u64>().ok());
                let page_size = unsafe { nix::libc::sysconf(nix::libc::_SC_PAGESIZE) };
                let ticks = unsafe { nix::libc::sysconf(nix::libc::_SC_CLK_TCK) };
                let cpu_ticks = fields
                    .get(11)
                    .and_then(|s| s.parse::<u64>().ok())
                    .zip(fields.get(12).and_then(|s| s.parse::<u64>().ok()))
                    .map(|(a, b)| a.saturating_add(b));
                rows.push(json!({"pid":pid,"name":comm,"cmdline":cmdline,"parent_pid":ppid,"state":state,"uid":uid,
                    "rss_bytes":pages.and_then(|p| p.checked_mul(page_size.max(0) as u64)),
                    "cpu_time_seconds":cpu_ticks.filter(|_| ticks > 0).map(|n| n as f64 / ticks as f64)}));
            }
            rows.sort_by_key(|row| row["pid"].as_u64().unwrap_or(0));
            let truncated = rows.len() > limit;
            rows.truncate(limit);
            let managed_jobs = if let Some(store) = &self.inner.job_store {
                store.list()?
            } else {
                Vec::new()
            };
            Ok(
                json!({"processes":rows,"managed_jobs":managed_jobs,"truncated":truncated,"filter_semantics":"case-insensitive literal; contains_any is OR, other filters are AND"}),
            )
        }
        #[cfg(windows)]
        {
            let script = "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); @(Get-Process | Select-Object @{n='pid';e={$_.Id}},@{n='name';e={$_.ProcessName}}) | ConvertTo-Json -Compress";
            let (code, text, error) = capture_command(
                vec![
                    "powershell.exe".into(),
                    "-NoProfile".into(),
                    "-NonInteractive".into(),
                    "-Command".into(),
                    script.into(),
                ],
                Duration::from_secs(20),
                1_048_576,
            )
            .await?;
            if code != 0 {
                return Err(anyhow!("Windows process enumeration failed: {error}"));
            }
            let mut rows: Vec<Value> = serde_json::from_str(text.trim())?;
            let needle = args
                .get("filter")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_ascii_lowercase();
            rows.retain(|row| {
                row["name"]
                    .as_str()
                    .unwrap_or("")
                    .to_ascii_lowercase()
                    .contains(&needle)
            });
            rows.truncate(
                args.get("limit")
                    .and_then(Value::as_u64)
                    .unwrap_or(500)
                    .clamp(1, 2000) as usize,
            );
            Ok(json!({"processes":rows}))
        }
        #[cfg(not(any(target_os = "linux", windows)))]
        {
            let _ = args;
            Err(anyhow!("process.list unsupported on this platform"))
        }
    }

    async fn process_status(&self, args: &Value) -> Result<Value> {
        #[cfg(target_os = "linux")]
        if let (Some(store), Some(id)) = (&self.inner.job_store, args["process_id"].as_str()) {
            return store.status(id);
        }
        if let Some(process_id) = args.get("process_id").and_then(Value::as_str) {
            let managed = self.inner.managed.lock().await.get(process_id).cloned();
            let Some(m) = managed else {
                return Ok(json!({"found":false,"process_id":process_id}));
            };
            return Ok(
                json!({"found":true,"managed":true,"process_id":process_id,"pid":m.pid,"running":m.running.load(Ordering::Acquire),"exit_code":*m.exit_code.lock().await,"command":m.command,"cwd":m.cwd,"started_at":m.started_at}),
            );
        }
        let pid = args
            .get("pid")
            .and_then(Value::as_u64)
            .context("process_id or pid required")? as u32;
        #[cfg(target_os = "linux")]
        {
            Ok(
                json!({"found":PathBuf::from(format!("/proc/{pid}")).exists(),"managed":false,"pid":pid}),
            )
        }
        #[cfg(not(target_os = "linux"))]
        Ok(json!({"found":false,"managed":false,"pid":pid}))
    }

    async fn process_output(&self, args: &Value) -> Result<Value> {
        #[cfg(target_os = "linux")]
        if let Some(store) = &self.inner.job_store {
            return store.output(
                &req_str(args, "process_id")?,
                args["offset"].as_u64().unwrap_or(0) as usize,
                args["limit"].as_u64().unwrap_or(65536) as usize,
            );
        }
        let id = req_str(args, "process_id")?;
        let m = self.inner.managed.lock().await.get(&id).cloned();
        let Some(m) = m else {
            return Ok(
                json!({"available":false,"reason":"output_unavailable_for_external_or_unknown_process","process_id":id}),
            );
        };
        let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0) as usize;
        let limit = args
            .get("limit")
            .and_then(Value::as_u64)
            .unwrap_or(65536)
            .clamp(1, 1_048_576) as usize;
        let out = m.stdout.lock().await;
        let err = m.stderr.lock().await;
        let stdout = slice_lossy(&out, offset, limit);
        let stderr = slice_lossy(&err, offset, limit);
        Ok(
            json!({"available":true,"process_id":id,"stdout":stdout,"stderr":stderr,"offset":offset,"running":m.running.load(Ordering::Acquire),"exit_code":*m.exit_code.lock().await}),
        )
    }

    async fn process_stop(&self, args: &Value) -> Result<Value> {
        #[cfg(target_os = "linux")]
        if let (Some(store), Some(id)) = (&self.inner.job_store, args["process_id"].as_str()) {
            return store
                .stop(id, args["force"].as_bool().unwrap_or(false))
                .await;
        }
        if let Some(id) = args.get("process_id").and_then(Value::as_str) {
            let m = self.inner.managed.lock().await.get(id).cloned();
            let Some(m) = m else {
                return Ok(json!({"process_id":id,"stopped":false,"reason":"not_found"}));
            };
            let already_exited = !m.running.load(Ordering::Acquire);
            if args.get("force").and_then(Value::as_bool).unwrap_or(false) {
                m.force_stop.store(true, Ordering::Release);
            }
            m.cancel.cancel();
            timeout(Duration::from_secs(5), async {
                while m.running.load(Ordering::Acquire) {
                    sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .context("managed process termination timed out")?;
            return Ok(
                json!({"process_id":id,"pid":m.pid,"stopped":true,"already_exited":already_exited,"exit_code":*m.exit_code.lock().await}),
            );
        }
        let pid = args
            .get("pid")
            .and_then(Value::as_i64)
            .context("process_id or pid required")?;
        if pid <= 0 || pid > i32::MAX as i64 {
            return Err(anyhow!("pid must be a positive process identifier"));
        }
        #[cfg(unix)]
        {
            let pid = pid as i32;
            use nix::{
                sys::signal::{kill, Signal},
                unistd::Pid,
            };
            let sig = if args.get("force").and_then(Value::as_bool).unwrap_or(false) {
                Signal::SIGKILL
            } else {
                Signal::SIGTERM
            };
            kill(Pid::from_raw(pid), sig)?;
            Ok(json!({"pid":pid,"signal":format!("{sig:?}")}))
        }
        #[cfg(not(unix))]
        {
            let _ = pid;
            Err(anyhow!(
                "external process.stop currently targets Unix; use managed process_id on Windows"
            ))
        }
    }

    #[cfg(windows)]
    async fn system_info(&self) -> Result<Value> {
        let mut info = windows_system_snapshot().await?;
        info["hostname"] = json!(hostname::get()?.to_string_lossy());
        info["platform"] = json!("Windows");
        info["architecture"] = json!(std::env::consts::ARCH);
        info["agent_version"] = json!(VERSION);
        info["agent_implementation"] = json!("rust");
        info["protocol_version"] = json!("1");
        Ok(info)
    }

    #[cfg(windows)]
    async fn system_metrics(&self, include_accelerators: bool) -> Result<Value> {
        let _ = include_accelerators;
        windows_system_snapshot().await
    }

    #[cfg(not(windows))]
    async fn system_info(&self) -> Result<Value> {
        let hostname = hostname::get()?.to_string_lossy().to_string();
        let os_release = parse_os_release();
        let mem = parse_meminfo();
        let boot = fs::read_to_string("/proc/uptime")
            .ok()
            .and_then(|s| s.split_whitespace().next()?.parse::<f64>().ok())
            .map(|up| now_secs() - up);
        Ok(json!({
            "hostname":hostname,"platform":std::env::consts::OS,"architecture":std::env::consts::ARCH,
            "os_release":os_release,"agent_version":VERSION,"agent_implementation":"rust","protocol_version":"1",
            "boot_time":boot,"cpu_count":std::thread::available_parallelism().map(|x|x.get()).unwrap_or(1),
            "memory_total":mem.get("MemTotal").copied().unwrap_or(0)*1024,
        }))
    }

    #[cfg(not(windows))]
    async fn system_metrics(&self, include_accelerators: bool) -> Result<Value> {
        let first = read_cpu_totals();
        sleep(Duration::from_millis(100)).await;
        let second = read_cpu_totals();
        let cpu_percent = match (first, second) {
            (Some((i1, t1)), Some((i2, t2))) if t2 > t1 => {
                100.0 * (1.0 - (i2 - i1) as f64 / (t2 - t1) as f64)
            }
            _ => 0.0,
        };
        let mem = parse_meminfo();
        let total = mem.get("MemTotal").copied().unwrap_or(0) * 1024;
        let available = mem.get("MemAvailable").copied().unwrap_or(0) * 1024;
        let load = fs::read_to_string("/proc/loadavg").unwrap_or_default();
        let loads: Vec<f64> = load
            .split_whitespace()
            .take(3)
            .filter_map(|x| x.parse().ok())
            .collect();
        #[cfg(unix)]
        let disk = nix::sys::statvfs::statvfs(Path::new("/")).ok().map(|s| {
            let total = s.blocks() * s.fragment_size();
            let used = total.saturating_sub(s.blocks_free() * s.fragment_size());
            let free = s.blocks_available() * s.fragment_size();
            let percent = if used + free > 0 { 100.0 * used as f64 / (used + free) as f64 } else { 0.0 };
            json!({"path":"/","total":total,"used":used,"free":free,"available":free,"percent":percent})
        });
        #[cfg(not(unix))]
        let disk: Option<Value> = None;
        let memory_used = total.saturating_sub(available);
        let memory_percent = if total > 0 {
            100.0 * memory_used as f64 / total as f64
        } else {
            0.0
        };
        let swap_total = mem.get("SwapTotal").copied().unwrap_or(0) * 1024;
        let swap_used = swap_total.saturating_sub(mem.get("SwapFree").copied().unwrap_or(0) * 1024);
        let swap_percent = if swap_total > 0 {
            100.0 * swap_used as f64 / swap_total as f64
        } else {
            0.0
        };
        // Preserve legacy flat fields while matching the Python MCP result contract.
        let mut metrics = json!({"cpu_percent":cpu_percent.clamp(0.0,100.0),"memory_total":total,"memory_available":available,
            "memory_used":memory_used,"load":loads,"loadavg":loads,"disk":disk,
            "memory":{"total":total,"available":available,"percent":memory_percent},
            "swap":{"total":swap_total,"used":swap_used,"percent":swap_percent}});
        metrics["health"] = crate::health::host(&metrics);
        if include_accelerators {
            metrics["health"]["accelerators"] = crate::health::accelerators().await;
        }
        Ok(metrics)
    }

    async fn transfer_upload(&self, args: &Value) -> Result<Value> {
        let path = PathBuf::from(req_str(args, "path")?);
        let data = B64.decode(req_str(args, "data_base64")?)?;
        if data.len() > self.inner.max_transfer_bytes {
            return Err(anyhow!("transfer exceeds configured maximum"));
        }
        if path.exists()
            && !args
                .get("overwrite")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        {
            return Err(anyhow!("destination_exists"));
        }
        if let Some(p) = path.parent() {
            fs::create_dir_all(p)?;
        }
        fs::write(&path, &data)?;
        Ok(json!({"path":path.to_string_lossy(),"bytes_written":data.len()}))
    }

    async fn transfer_download(&self, args: &Value) -> Result<Value> {
        let path = PathBuf::from(req_str(args, "path")?);
        let data = fs::read(&path)?;
        if data.len() > self.inner.max_transfer_bytes {
            return Err(anyhow!("transfer exceeds configured maximum"));
        }
        Ok(json!({"path":path.to_string_lossy(),"bytes":data.len(),"data_base64":B64.encode(data)}))
    }

    async fn git_status(&self, args: &Value) -> Result<Value> {
        let repo = req_str(args, "repo")?;
        let out = capture_command(
            vec![
                "git".into(),
                "-c".into(),
                format!("safe.directory={repo}"),
                "-C".into(),
                repo.clone(),
                "status".into(),
                "--porcelain=v2".into(),
                "--branch".into(),
            ],
            Duration::from_secs(30),
            1_048_576,
        )
        .await?;
        if out.0 != 0 {
            return Err(anyhow!(out.2));
        }
        let clean = !out.1.lines().any(|l| !l.is_empty() && !l.starts_with('#'));
        Ok(json!({"repo":repo,"porcelain_v2":out.1,"clean":clean}))
    }

    async fn git_diff(&self, args: &Value) -> Result<Value> {
        let repo = req_str(args, "repo")?;
        let mut argv = vec![
            "git".into(),
            "-c".into(),
            format!("safe.directory={repo}"),
            "-C".into(),
            repo.clone(),
            "diff".into(),
            "--no-ext-diff".into(),
            "--no-color".into(),
        ];
        if args.get("staged").and_then(Value::as_bool).unwrap_or(false) {
            argv.push("--cached".into());
        }
        if let Some(paths) = args.get("paths").and_then(Value::as_array) {
            if !paths.is_empty() {
                argv.push("--".into());
                for p in paths {
                    argv.push(p.as_str().unwrap_or("").into());
                }
            }
        }
        let max = args
            .get("max_bytes")
            .and_then(Value::as_u64)
            .unwrap_or(262144)
            .clamp(1024, 1_048_576) as usize;
        let out = capture_command(argv, Duration::from_secs(60), max).await?;
        if out.0 != 0 {
            return Err(anyhow!(out.2));
        }
        let truncated = out.1.len() >= max;
        Ok(json!({"repo":repo,"diff":out.1,"truncated":truncated}))
    }

    async fn git_log(&self, args: &Value) -> Result<Value> {
        let repo = req_str(args, "repo")?;
        let limit = args
            .get("limit")
            .and_then(Value::as_u64)
            .unwrap_or(20)
            .clamp(1, 200);
        let sep = "\u{1f}";
        let fmt = format!("%H{sep}%h{sep}%an{sep}%ae{sep}%aI{sep}%s");
        let out = capture_command(
            vec![
                "git".into(),
                "-c".into(),
                format!("safe.directory={repo}"),
                "-C".into(),
                repo.clone(),
                "log".into(),
                format!("-{limit}"),
                format!("--pretty=format:{fmt}"),
            ],
            Duration::from_secs(30),
            1_048_576,
        )
        .await?;
        if out.0 != 0 {
            return Err(anyhow!(out.2));
        }
        let commits:Vec<Value>=out.1.lines().filter_map(|line|{let p:Vec<&str>=line.splitn(6,sep).collect(); if p.len()==6{Some(json!({"sha":p[0],"short_sha":p[1],"author":p[2],"email":p[3],"date":p[4],"subject":p[5]}))}else{None}}).collect();
        Ok(json!({"repo":repo,"commits":commits}))
    }

    async fn git_run(&self, execution_id: &str, args: &Value, output: OutputSink) -> Result<Value> {
        let repo = req_str(args, "repo")?;
        let raw = args
            .get("args")
            .and_then(Value::as_array)
            .context("args must be array")?;
        if raw.is_empty() {
            return Err(anyhow!("args must be non-empty"));
        }
        let clean: Vec<String> = raw
            .iter()
            .map(|x| x.as_str().unwrap_or("").to_string())
            .collect();
        if clean.iter().any(|x| x.contains('\0')) {
            return Err(anyhow!("git args contain NUL"));
        }
        let mut argv = vec![
            "git".into(),
            "-c".into(),
            format!("safe.directory={repo}"),
            "-C".into(),
            repo.clone(),
        ];
        argv.extend(clean.clone());
        let ms = args
            .get("timeout_ms")
            .and_then(Value::as_u64)
            .unwrap_or(120000)
            .clamp(100, 600000);
        let mut result = self
            .run_command(
                execution_id,
                argv,
                None,
                HashMap::new(),
                Duration::from_millis(ms),
                output,
            )
            .await?;
        if let Some(o) = result.as_object_mut() {
            o.insert("repo".into(), Value::String(repo));
            o.insert("git_args".into(), json!(clean));
        }
        Ok(result)
    }

    async fn agent_update_status(&self) -> Result<Value> {
        let path = env::var("COMMANDCORE_AGENT_ROLLOUT_STATE")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/opt/commandcore-agent/rollout.json"));
        let rollout: Value = fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or(Value::Null);
        let policy = load_local_policy();
        Ok(
            json!({"current_version":VERSION,"implementation":"rust","rollout":rollout,"trusted_release_key_configured":!policy.update_public_key_b64.is_empty()}),
        )
    }
}

fn req_str(v: &Value, key: &str) -> Result<String> {
    v.get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .with_context(|| format!("{key} is required"))
}
fn json_string_map(v: Option<&Value>) -> HashMap<String, String> {
    v.and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default()
}
fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}
fn system_time_secs(v: SystemTime) -> Option<f64> {
    v.duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs_f64())
}
fn shell_command(command: &str) -> Vec<String> {
    #[cfg(windows)]
    {
        vec![
            env::var("COMSPEC").unwrap_or_else(|_| "cmd.exe".into()),
            "/D".into(),
            "/S".into(),
            "/C".into(),
            command.into(),
        ]
    }
    #[cfg(not(windows))]
    {
        vec![
            env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into()),
            "-c".into(),
            command.into(),
        ]
    }
}
async fn append_bounded(target: &Mutex<Vec<u8>>, data: &[u8]) {
    let mut b = target.lock().await;
    let left = (4usize * 1024 * 1024).saturating_sub(b.len());
    b.extend_from_slice(&data[..data.len().min(left)]);
}
fn slice_lossy(data: &[u8], offset: usize, limit: usize) -> String {
    if offset >= data.len() {
        String::new()
    } else {
        String::from_utf8_lossy(&data[offset..(offset + limit).min(data.len())]).to_string()
    }
}
fn remove_path(path: &Path, recursive: bool) -> Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if meta.is_dir() && !meta.file_type().is_symlink() {
        if recursive {
            fs::remove_dir_all(path)?
        } else {
            fs::remove_dir(path)?
        }
    } else {
        fs::remove_file(path)?
    }
    Ok(())
}
fn copy_recursive(src: &Path, dst: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(src)?;
    if meta.is_dir() {
        fs::create_dir_all(dst)?;
        for e in fs::read_dir(src)? {
            let e = e?;
            copy_recursive(&e.path(), &dst.join(e.file_name()))?;
        }
    } else if meta.file_type().is_symlink() {
        return Err(anyhow!("copying symlinks is refused by native Agent"));
    } else {
        if let Some(p) = dst.parent() {
            fs::create_dir_all(p)?;
        }
        fs::copy(src, dst)?;
    }
    Ok(())
}
#[cfg(not(windows))]
fn parse_os_release() -> HashMap<String, String> {
    let mut m = HashMap::new();
    if let Ok(s) = fs::read_to_string("/etc/os-release") {
        for line in s.lines() {
            if let Some((k, v)) = line.split_once('=') {
                m.insert(k.into(), v.trim_matches('"').into());
            }
        }
    }
    m
}
#[cfg(not(windows))]
fn parse_meminfo() -> HashMap<String, u64> {
    let mut m = HashMap::new();
    if let Ok(s) = fs::read_to_string("/proc/meminfo") {
        for l in s.lines() {
            if let Some((k, r)) = l.split_once(':') {
                if let Some(v) = r.split_whitespace().next().and_then(|x| x.parse().ok()) {
                    m.insert(k.into(), v);
                }
            }
        }
    }
    m
}
#[cfg(not(windows))]
fn read_cpu_totals() -> Option<(u64, u64)> {
    let s = fs::read_to_string("/proc/stat").ok()?;
    let l = s.lines().next()?;
    let nums: Vec<u64> = l
        .split_whitespace()
        .skip(1)
        .filter_map(|x| x.parse().ok())
        .collect();
    if nums.len() < 4 {
        return None;
    }
    Some((
        nums[3] + nums.get(4).copied().unwrap_or(0),
        nums.iter().sum(),
    ))
}
#[cfg(windows)]
async fn windows_system_snapshot() -> Result<Value> {
    let script = r#"$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$os=Get-CimInstance Win32_OperatingSystem
$cpu=@(Get-CimInstance Win32_Processor)
$total=[uint64]$os.TotalVisibleMemorySize*1024; $free=[uint64]$os.FreePhysicalMemory*1024
$used=$total-$free; $pct=if($total -gt 0){100.0*$used/$total}else{0}
$disk=Get-CimInstance Win32_LogicalDisk -Filter ('DeviceID="'+$env:SystemDrive+'"')
$dt=[uint64]$disk.Size; $df=[uint64]$disk.FreeSpace; $du=$dt-$df
$dp=if($dt -gt 0){100.0*$du/$dt}else{0}
$swap=@(Get-CimInstance Win32_PageFileUsage); $st=[uint64](($swap|Measure-Object AllocatedBaseSize -Sum).Sum)*1048576
$su=[uint64](($swap|Measure-Object CurrentUsage -Sum).Sum)*1048576
$sp=if($st -gt 0){100.0*$su/$st}else{0}
@{os_release=@{name=$os.Caption;version=$os.Version};boot_time=([DateTimeOffset]$os.LastBootUpTime).ToUnixTimeSeconds();cpu_count=[Environment]::ProcessorCount
cpu_percent=($cpu|Measure-Object LoadPercentage -Average).Average;memory_total=$total;memory_available=$free;memory_used=$used
memory=@{total=$total;available=$free;percent=$pct};swap=@{total=$st;used=$su;percent=$sp}
disk=@{path=$env:SystemDrive;total=$dt;used=$du;free=$df;available=$df;percent=$dp};load=@();loadavg=@()}|ConvertTo-Json -Depth 5 -Compress"#;
    let (code, text, error) = capture_command(
        vec![
            "powershell.exe".into(),
            "-NoProfile".into(),
            "-NonInteractive".into(),
            "-Command".into(),
            script.into(),
        ],
        Duration::from_secs(20),
        1_048_576,
    )
    .await?;
    if code != 0 {
        return Err(anyhow!("Windows system query failed: {error}"));
    }
    Ok(serde_json::from_str(text.trim())?)
}

async fn capture_command(
    argv: Vec<String>,
    duration: Duration,
    max: usize,
) -> Result<(i32, String, String)> {
    let mut cmd = Command::new(argv.first().context("empty argv")?);
    cmd.args(&argv[1..])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    let output = timeout(duration, cmd.output())
        .await
        .map_err(|_| anyhow!("command timeout"))??;
    let out = String::from_utf8_lossy(&output.stdout[..output.stdout.len().min(max)]).to_string();
    let err = String::from_utf8_lossy(&output.stderr[..output.stderr.len().min(max)]).to_string();
    Ok((output.status.code().unwrap_or(-1), out, err))
}

fn command_with_args(argv: &[String]) -> Result<Command> {
    let mut command = Command::new(argv.first().context("empty argv")?);
    #[cfg(windows)]
    if argv.len() == 5 && argv[1..4] == ["/D", "/S", "/C"] {
        // cmd does not use the normal Windows C runtime escaping rules.
        // The final value is an explicitly authorized shell program, not a
        // data argument. /D disables registry AutoRun commands.
        command.args(&argv[1..4]);
        command.raw_arg(format!("\"{}\"", argv[4]));
        return Ok(command);
    }
    command.args(&argv[1..]);
    Ok(command)
}

#[cfg(unix)]
async fn terminate_child(child: &mut Child, pid: u32, force: bool) {
    use nix::{
        sys::signal::{killpg, Signal},
        unistd::Pid,
    };
    let _ = killpg(
        Pid::from_raw(pid as i32),
        if force {
            Signal::SIGKILL
        } else {
            Signal::SIGTERM
        },
    );
    if timeout(Duration::from_secs(3), child.wait()).await.is_err() {
        let _ = killpg(Pid::from_raw(pid as i32), Signal::SIGKILL);
        let _ = child.wait().await;
    }
}
#[cfg(windows)]
async fn terminate_child(child: &mut Child, pid: u32, _force: bool) {
    // End the managed shell tree, including descendants with inherited pipes.
    // The retained child handle prevents the shell PID from being reused here.
    if pid != 0 {
        let mut killer = Command::new("taskkill.exe");
        killer
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true);
        let _ = timeout(Duration::from_secs(3), killer.status()).await;
    }
    let _ = child.kill().await;
    let _ = child.wait().await;
}

#[cfg(not(any(unix, windows)))]
async fn terminate_child(child: &mut Child, _pid: u32, _force: bool) {
    let _ = child.kill().await;
    let _ = child.wait().await;
}

pub async fn capabilities() -> Value {
    runtime_capabilities(VERSION).await
}
