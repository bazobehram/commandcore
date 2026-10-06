//! Local AI work timeline: sanitize before emitting, never replay raw journal messages.
use regex::Regex;
use serde_json::{json, Map, Value};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

pub const PREFIX: &str = "COMMANDCORE_ACTIVITY ";
const LIMIT: usize = 2048;
fn policy() -> &'static Value {
    static POLICY: OnceLock<Value> = OnceLock::new();
    POLICY.get_or_init(|| {
        serde_json::from_str(include_str!("../../commandcore_agent/activity_policy.json")).unwrap()
    })
}
fn patterns() -> &'static Vec<(Regex, String)> {
    static PATTERNS: OnceLock<Vec<(Regex, String)>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        policy()["patterns"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| {
                (
                    Regex::new(p[0].as_str().unwrap()).unwrap(),
                    p[1].as_str().unwrap().into(),
                )
            })
            .collect()
    })
}
fn secrets() -> &'static Mutex<Vec<String>> {
    static SECRETS: OnceLock<Mutex<Vec<String>>> = OnceLock::new();
    SECRETS.get_or_init(|| Mutex::new(Vec::new()))
}
pub fn register_secrets(values: impl IntoIterator<Item = String>) {
    let mut known = secrets().lock().unwrap();
    for value in values {
        if !value.is_empty() && !known.contains(&value) {
            known.push(value);
        }
    }
    known.sort_by_key(|s| std::cmp::Reverse(s.len()));
}
fn text(value: &str) -> String {
    let mut input = value.to_owned();
    for secret in secrets().lock().unwrap().iter() {
        input = input.replace(secret, "[REDACTED]");
    }
    for (pattern, _) in &patterns()[3..6] {
        register_secrets(
            pattern
                .captures_iter(&input)
                .filter_map(|c| c.get(2))
                .map(|m| m.as_str().trim_matches(['\'', '"']).to_owned())
                .filter(|s| !s.starts_with("[REDACTED")),
        );
    }
    let mut safe = input;
    for secret in secrets().lock().unwrap().iter() {
        safe = safe.replace(secret, "[REDACTED]");
    }
    for (pattern, replacement) in patterns() {
        safe = pattern
            .replace_all(&safe, replacement.as_str())
            .into_owned();
    }
    safe.chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .collect()
}
pub fn sanitize(value: &Value) -> Value {
    let mut input = value.clone();
    if input.get("tool").is_some()
        && !policy()["tools"]
            .as_array()
            .unwrap()
            .contains(&input["tool"])
    {
        input.as_object_mut().unwrap().retain(|k, _| {
            [
                "tool",
                "event",
                "request_id",
                "execution_id",
                "timestamp_unix",
                "duration_ms",
                "status",
            ]
            .contains(&k.as_str())
        });
        input["reason"] = json!("unreviewed tool payload suppressed");
        if !input["status"].is_null()
            && !["ok", "error", "timeout", "cancelled"]
                .contains(&input["status"].as_str().unwrap_or(""))
        {
            input["status"] = json!("unknown");
        }
    }
    let mut safe = sanitize_at(&input, 0);
    if safe.is_object() {
        while safe.to_string().len() > 16384 {
            let key = safe
                .as_object()
                .unwrap()
                .iter()
                .filter(|(k, v)| {
                    ![
                        "event",
                        "tool",
                        "request_id",
                        "execution_id",
                        "timestamp_unix",
                        "status",
                    ]
                    .contains(&k.as_str())
                        && **v != json!("[BOUNDED FIELD]")
                })
                .max_by_key(|(_, v)| v.to_string().len())
                .map(|(k, _)| k.clone());
            let Some(key) = key else { break };
            safe[key] = json!("[BOUNDED FIELD]");
            safe["truncated"] = json!(true);
        }
    }
    safe
}
fn sanitize_at(value: &Value, depth: usize) -> Value {
    if depth > 6 {
        return json!("[BOUNDED]");
    }
    match value {
        Value::Object(o) => Value::Object(
            o.iter()
                .filter(|(k, _)| {
                    policy()["fields"]
                        .as_str()
                        .unwrap()
                        .split_whitespace()
                        .any(|f| f == *k)
                })
                .take(64)
                .map(|(k, v)| (k.clone(), sanitize_at(v, depth + 1)))
                .collect(),
        ),
        Value::Array(a) => Value::Array(
            a.iter()
                .take(32)
                .map(|v| sanitize_at(v, depth + 1))
                .collect(),
        ),
        Value::String(s) => {
            let safe = text(s);
            let mut preview: String = safe.chars().take(LIMIT).collect();
            if safe.chars().count() > LIMIT {
                preview.push_str("… [truncated]");
            }
            json!(preview)
        }
        _ => value.clone(),
    }
}
fn sensitive_path(path: &str) -> bool {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| Regex::new(r"(?i)(^|[/\\])(?:\.env(?:\..*)?|\.ssh|\.aws|\.kube|credentials[^/\\]*|.*(?:private|secret|token).*|agent-state\.json|state\.json|id_rsa|id_ed25519)(?:$|[/\\])|\.(?:pem|key|p12|pfx)$").unwrap()).is_match(path)
}
pub fn context(msg: &Value) -> Value {
    if let Some(env) = msg["arguments"]["env"].as_object() {
        register_secrets(env.values().filter_map(Value::as_str).map(str::to_owned));
    }
    if let Some(argv) = msg["arguments"]["argv"].as_array() {
        for pair in argv.windows(2) {
            let flag = pair[0].as_str().unwrap_or("").to_lowercase();
            if [
                "--password",
                "--token",
                "--secret",
                "--api-key",
                "--user",
                "--cookie",
            ]
            .contains(&flag.as_str())
                || (["-u", "-b"].contains(&flag.as_str())
                    && argv.first().and_then(Value::as_str).is_some_and(|s| {
                        std::path::Path::new(s)
                            .file_name()
                            .is_some_and(|n| n == "curl")
                    }))
            {
                register_secrets(pair[1].as_str().map(str::to_owned));
            }
        }
    }
    let mut value = json!({"tool":msg["tool"], "request_id":msg.get("request_id").unwrap_or(&msg["execution_id"]), "execution_id":msg["execution_id"]});
    if !msg["activity"]["source"].is_null() {
        value["source"] = msg["activity"]["source"].clone();
    }
    value
}
pub fn request(msg: &Value) -> Value {
    let mut value = context(msg);
    let args = &msg["arguments"];
    if let Some(o) = sanitize(args).as_object() {
        let sensitive = msg["tool"] == "keyboard.type"
            || msg["tool"]
                .as_str()
                .is_some_and(|t| t.starts_with("clipboard.") || t.starts_with("transfer."));
        value.as_object_mut().unwrap().extend(
            o.iter()
                .filter(|(k, _)| {
                    ![
                        "tool",
                        "request_id",
                        "execution_id",
                        "source",
                        "event",
                        "timestamp_unix",
                    ]
                    .contains(&k.as_str())
                        && (!sensitive
                            || [
                                "path",
                                "source_path",
                                "destination_path",
                                "destination",
                                "src",
                                "dst",
                                "length",
                                "offset",
                                "encoding",
                            ]
                            .contains(&k.as_str()))
                })
                .map(|(k, v)| (k.clone(), v.clone())),
        );
    }
    if value.get("timeout_ms").is_none() {
        value["timeout_ms"] = msg["timeout_ms"].clone();
    }
    if ["shell.exec", "process.start"].contains(&msg["tool"].as_str().unwrap_or(""))
        && value["cwd"].is_null()
    {
        value["cwd"] = json!(std::env::current_dir()
            .ok()
            .map(|p| p.to_string_lossy().to_string()));
    }
    if msg["tool"] == "fs.write" {
        let raw = args["data"].as_str().unwrap_or("");
        let n = if args["encoding"] == "base64" {
            (raw.len() * 3 / 4).saturating_sub(raw.len() - raw.trim_end_matches('=').len())
        } else {
            raw.len()
        };
        value["bytes"] = json!(n);
    }
    if msg["tool"] == "fs.patch" {
        value["patch_count"] = json!(args["patches"].as_array().map_or(0, Vec::len));
    }
    value
}
pub fn result(msg: &Value, outcome: &Value, duration: u128, streams: Value) -> Value {
    let mut value = context(msg);
    for part in [outcome, &outcome["result"]] {
        if let Some(o) = sanitize(part).as_object() {
            value.as_object_mut().unwrap().extend(o.clone());
        }
    }
    value["duration_ms"] = json!(duration);
    if outcome["result"]["health"]["state"] == "warning"
        || outcome["result"]["health_at_start"]["state"] == "warning"
    {
        value["resource_warning"] = json!(true);
    }
    let tool = msg["tool"].as_str().unwrap_or("");
    let args = &msg["arguments"];
    if tool.starts_with("fs.") && args.get("path").is_some() && value.get("path").is_none() {
        value["path"] = args["path"].clone();
    }
    if tool == "fs.read" {
        let raw = &outcome["result"];
        value["bytes_returned"] = raw.get("bytes").cloned().unwrap_or(json!(0));
        if raw["encoding"] != "base64"
            && args["encoding"] != "base64"
            && !sensitive_path(args["path"].as_str().unwrap_or(""))
            && !raw["data"]
                .as_str()
                .unwrap_or("")
                .contains(['\0', '\u{fffd}'])
        {
            value["preview"] = raw["data"].clone();
        }
    }
    if ["fs.write", "fs.patch"].contains(&tool) && outcome["status"] == "ok" {
        value["changed"] =
            json!(tool == "fs.write" || value["replacements"].as_u64().unwrap_or(0) > 0);
    }
    if tool == "keyboard.type" || tool.starts_with("clipboard.") || tool.starts_with("transfer.") {
        for key in ["preview", "stdout", "stderr", "command", "argv", "error"] {
            value.as_object_mut().unwrap().remove(key);
        }
    } else if let Some(o) = streams.as_object() {
        value.as_object_mut().unwrap().extend(o.clone());
    }
    value
}
pub fn emit(event: &str, mut data: Value) {
    data["event"] = json!(event);
    data["timestamp_unix"] = json!(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64());
    println!("{PREFIX}{}", sanitize(&data));
}
pub fn render(message: &str, as_json: bool, errors: bool) -> Option<String> {
    let raw: Value = serde_json::from_str(message.strip_prefix(PREFIX)?).ok()?;
    if !raw.is_object() {
        return None;
    }
    let value = sanitize(&raw);
    let event = value["event"].as_str()?;
    if !["REQUEST", "RESULT", "CONNECTION"].contains(&event) {
        return None;
    }
    if errors
        && value["exit_code"].as_i64().is_none_or(|code| code == 0)
        && value["resource_warning"] != true
        && (value["status"].is_null()
            || ["ok", "connected"].contains(&value["status"].as_str().unwrap_or("")))
    {
        return None;
    }
    if as_json {
        return Some(value.to_string());
    }
    let seconds = value["timestamp_unix"].as_f64().unwrap_or(0.0) as u64 % 86400;
    Some(format!(
        "{:02}:{:02}:{:02} UTC {event}\n{}",
        seconds / 3600,
        seconds / 60 % 60,
        seconds % 60,
        serde_json::to_string_pretty(&value).ok()?
    ))
}

/// A disconnected/aborted job still closes its observable lifecycle.
pub struct Span {
    context: Value,
    started: std::time::Instant,
    completed: bool,
}
impl Span {
    pub fn new(msg: &Value) -> Self {
        Self {
            context: sanitize(&context(msg)),
            started: std::time::Instant::now(),
            completed: false,
        }
    }
    pub fn complete(&mut self) {
        self.completed = true;
    }
}
impl Drop for Span {
    fn drop(&mut self) {
        if !self.completed {
            let mut data = self.context.clone();
            data["status"] = json!("cancelled");
            data["reason"] = json!("execution interrupted");
            data["duration_ms"] = json!(self.started.elapsed().as_millis());
            emit("RESULT", data);
        }
    }
}

#[derive(Default)]
pub struct Capture {
    streams: Map<String, Value>,
    counts: Map<String, Value>,
}
impl Capture {
    pub fn append(&mut self, stream: &str, data: &str) {
        if !["stdout", "stderr"].contains(&stream) {
            return;
        }
        let count =
            self.counts.get(stream).and_then(Value::as_u64).unwrap_or(0) + data.len() as u64;
        self.counts.insert(stream.into(), json!(count));
        let value = self.streams.entry(stream.to_string()).or_insert(json!(""));
        let mut raw = value.as_str().unwrap().to_owned();
        if raw.len() < 16384 {
            raw.extend(data.chars().take(16384 - raw.len()));
        }
        *value = json!(raw);
    }
    pub fn value(&self) -> Value {
        if self.streams.is_empty() {
            return Value::Null;
        }
        let mut value = Value::Object(self.streams.clone());
        for (stream, count) in &self.counts {
            value[format!("{stream}_bytes")] = count.clone();
        }
        value["truncated"] = json!(self
            .counts
            .values()
            .any(|n| n.as_u64().unwrap_or(0) > LIMIT as u64));
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn msg(tool: &str, args: Value) -> Value {
        json!({"tool":tool,"request_id":"request-fixture","execution_id":"execution-fixture","arguments":args,"activity":{"source":{"channel":"mcp","client_id":"fixture-client"}}})
    }
    #[test]
    fn unknown_tool_is_metadata_only() {
        let mut value = msg(
            "future.unreviewed",
            json!({"command":"opaque-dummy-payload", "preview":"opaque-dummy-payload"}),
        );
        value["event"] = json!("REQUEST");
        value["command"] = json!("opaque-dummy-payload");
        let safe = sanitize(&value);
        assert!(!safe.to_string().contains("opaque-dummy-payload"));
        assert_eq!(safe["request_id"], "request-fixture");
        assert!(render(&format!("{PREFIX}{value}"), true, false)
            .unwrap()
            .contains("unreviewed tool payload suppressed"));
    }
    #[test]
    fn commands_and_redaction() {
        for command in [
            "python train.py",
            "python scripts/migrate.py",
            "pytest tests/test_api.py",
            "npm test",
            "cargo test",
            "git diff",
            "docker compose ps",
        ] {
            let mut v = sanitize(&request(&msg(
                "shell.exec",
                json!({"command":command,"cwd":"/home/user/project"}),
            )));
            assert_eq!(v["command"], command);
            assert_eq!(v["source"]["client_id"], "fixture-client");
            v["event"] = json!("REQUEST");
            v["timestamp_unix"] = json!(1000);
            for json in [true, false] {
                assert!(render(&format!("{PREFIX}{v}"), json, false)
                    .unwrap()
                    .contains(command));
            }
        }
        for (raw, secret) in [
            (
                "TOKEN=rustfixturesecret python check.py",
                "rustfixturesecret",
            ),
            (
                "python check.py --password \"rust fixture spaces\"",
                "rust fixture spaces",
            ),
            (
                "curl -u user:rustbasicfixture https://example.org",
                "rustbasicfixture",
            ),
            (
                "Authorization: Bearer rustheaderfixture",
                "rustheaderfixture",
            ),
            ("Cookie: session=rustcookiefixture", "rustcookiefixture"),
            ("{\"api_key\":\"rustjsonfixture\"}", "rustjsonfixture"),
            ("https://user:rusturlfixture@example.org", "rusturlfixture"),
            (
                concat!(
                    "-----BEGIN ",
                    "RSA PRIVATE KEY-----\nrustpemfixture\n-----END RSA PRIVATE KEY-----"
                ),
                "rustpemfixture",
            ),
        ] {
            assert!(
                !sanitize(&json!({"stdout":raw}))
                    .to_string()
                    .contains(secret),
                "fixture: {secret}"
            );
        }
        assert!(!text("\u{1b}[31mhello").contains('\u{1b}'));
        let value = sanitize(&request(&msg(
            "shell.exec",
            json!({"argv":["curl","--password","rustargvfixture"],"env":{"TOKEN":"rustenvfixture"}}),
        )));
        assert!(!value.to_string().contains("rustargvfixture"));
        assert!(!text("rustenvfixture").contains("rustenvfixture"));
    }
    #[test]
    fn payloads_previews_and_split_capture() {
        for tool in [
            "fs.write",
            "fs.patch",
            "keyboard.type",
            "clipboard.read",
            "clipboard.write",
            "transfer.upload",
        ] {
            let v = request(&msg(
                tool,
                json!({"path":"/tmp/config.py", "data":"rustpayloadfixture", "text":"rustpayloadfixture","patches":[{"search":"rustpayloadfixture"}]}),
            ));
            assert!(!sanitize(&v).to_string().contains("rustpayloadfixture"));
            if tool == "fs.write" {
                assert_eq!(v["bytes"], 18);
            }
            if tool == "fs.patch" {
                assert_eq!(v["patch_count"], 1);
            }
        }
        for (path, encoding, data) in [
            ("/tmp/.env", "text", "hiddenfixture"),
            ("/tmp/state.json", "text", "hiddenfixture"),
            ("/tmp/binary", "base64", "hiddenfixture"),
            ("/tmp/binary", "text", "binary\0fixture"),
        ] {
            let v = result(
                &msg("fs.read", json!({"path":path,"encoding":encoding})),
                &json!({"status":"ok","result":{"data":data,"bytes":13,"encoding":encoding}}),
                1,
                Value::Null,
            );
            assert!(v.get("preview").is_none());
            assert_eq!(v["bytes_returned"], 13);
        }
        let mut capture = Capture::default();
        capture.append("stdout", "TOKEN=rustsplit");
        capture.append("stdout", "fixture\n");
        capture.append("stderr", &"line\n".repeat(5000));
        let v = sanitize(&capture.value());
        assert!(!v.to_string().contains("rustsplitfixture"));
        assert!(v["stderr"].as_str().unwrap().len() < 2100);
        assert_eq!(v["stderr_bytes"], 25000);
        assert_eq!(v["truncated"], true);
        assert!(render("raw untrusted journal", true, false).is_none());
        assert!(render(&format!("{PREFIX}[]"), true, false).is_none());
    }
    #[tokio::test]
    async fn real_executor_pipeline() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("config.py");
        std::fs::write(&path, "value = 1\n").unwrap();
        let executor = crate::executor::Executor::new(1024);
        let jobs = [
            msg("fs.read", json!({"path":path})),
            msg(
                "fs.patch",
                json!({"path":path,"patches":[{"search":"value = 1","replace":"value = 2"}]}),
            ),
            msg("fs.read", json!({"path":path})),
            msg(
                "shell.exec",
                json!({"command":"echo tests pass","cwd":temp.path(),"timeout_ms":5000}),
            ),
        ];
        let mut results = Vec::new();
        for msg in jobs {
            let (tx, mut rx) = tokio::sync::mpsc::channel(32);
            let sink = crate::output::OutputSink::new("fixture", tx);
            let capture = sink.clone();
            let drain = tokio::spawn(async move { while rx.recv().await.is_some() {} });
            let outcome = executor
                .execute(
                    "fixture",
                    "STANDARD",
                    msg["tool"].as_str().unwrap(),
                    msg["arguments"].clone(),
                    sink,
                )
                .await;
            assert_eq!(outcome["status"], "ok", "fixture outcome: {outcome}");
            results.push(sanitize(&result(
                &msg,
                &outcome,
                1,
                capture.preview().await,
            )));
            drop(capture);
            drain.await.unwrap();
        }
        assert_eq!(results[0]["preview"], "value = 1\n");
        assert_eq!(results[1]["changed"], true);
        assert_eq!(results[2]["preview"], "value = 2\n");
        assert_eq!(results[3]["exit_code"], 0);
        assert!(results[3]["stdout"]
            .as_str()
            .unwrap()
            .contains("tests pass"));
    }
}
