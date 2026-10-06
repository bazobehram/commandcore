//! Small platform-neutral health summary; GPU metrics are optional and bounded.
use serde_json::{json, Value};
use std::{fs, time::Duration};

pub fn host(metrics: &Value) -> Value {
    let mut conditions = Vec::new();
    let free = metrics["disk"]["available"].as_u64();
    let percent = metrics["disk"]["percent"].as_f64();
    if free.is_some_and(|n| n < 5 * 1024 * 1024 * 1024) && percent.is_some_and(|p| p >= 95.0) {
        conditions.push(json!({"code":"disk_capacity_low","severity":"warning","available_bytes":free,"used_percent":percent,
            "context":"Root filesystem is at least 95% used with less than 5 GiB available; check workload/checkpoint requirements."}));
    }
    let pressure = ["memory", "cpu", "io"]
        .into_iter()
        .map(|resource| {
            let text = fs::read_to_string(format!("/proc/pressure/{resource}")).ok();
            let mut rows = json!({});
            if let Some(text) = text {
                for line in text.lines() {
                    let mut fields = line.split_whitespace();
                    let kind = fields.next().unwrap_or_default();
                    let mut row = json!({});
                    for field in fields {
                        if let Some((key, value)) = field.split_once('=') {
                            if let Ok(number) = value.parse::<f64>() {
                                row[key] = json!(number);
                            }
                        }
                    }
                    rows[kind] = row;
                }
            }
            (resource.to_string(), rows)
        })
        .collect::<serde_json::Map<String, Value>>();
    let memory_stall = pressure
        .get("memory")
        .and_then(|v| v["some"]["avg10"].as_f64());
    let available = metrics["memory_available"].as_u64();
    let total = metrics["memory_total"].as_u64();
    if memory_stall.is_some_and(|n| n >= 10.0)
        && available
            .zip(total)
            .is_some_and(|(a, t)| t > 0 && a as f64 / (t as f64) < 0.05)
    {
        conditions.push(json!({"code":"memory_pressure","severity":"warning","available_bytes":available,"stall_percent_10s":memory_stall,
            "context":"Available host RAM below 5% and memory stalls at least 10% over ten seconds."}));
    }
    json!({"state":if !conditions.is_empty() {"warning"} else if metrics["memory_total"].as_u64().is_some_and(|n| n > 0) {"ok"} else {"unknown"},"conditions":conditions,"pressure":pressure,
        "automatic_actions":false,"accelerators":{"available":false,"reason":"not_queried"}})
}

fn device_rows(text: &str) -> Vec<Value> {
    text.lines().take(64).filter_map(|line| {
        let fields: Vec<_> = line.split(',').map(str::trim).collect();
        if fields.len() != 6 { return None; }
        let mib = |s: &str| s.parse::<u64>().ok().and_then(|n| n.checked_mul(1024*1024));
        Some(json!({"index":fields[0].parse::<u32>().ok(),"accelerator_id":fields[1],"name":fields[2],"utilization_percent":fields[3].parse::<f64>().ok(),
            "memory_used_bytes":mib(fields[4]),"memory_total_bytes":mib(fields[5])}))
    }).collect()
}

pub async fn accelerators() -> Value {
    let mut command = tokio::process::Command::new("nvidia-smi");
    command
        .args([
            "--query-gpu=index,uuid,name,utilization.gpu,memory.used,memory.total",
            "--format=csv,noheader,nounits",
        ])
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true);
    let output = match tokio::time::timeout(Duration::from_secs(2), command.output()).await {
        Ok(Ok(o)) if o.status.success() && o.stdout.len() <= 65536 => o,
        _ => return json!({"available":false,"reason":"unsupported_or_unavailable"}),
    };
    let devices = device_rows(&String::from_utf8_lossy(&output.stdout));
    let mut command = tokio::process::Command::new("nvidia-smi");
    command
        .args([
            "--query-compute-apps=pid,gpu_uuid,used_gpu_memory",
            "--format=csv,noheader,nounits",
        ])
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true);
    let mut processes = Vec::new();
    if let Ok(Ok(output)) = tokio::time::timeout(Duration::from_secs(2), command.output()).await {
        if output.status.success() && output.stdout.len() <= 65536 {
            for line in String::from_utf8_lossy(&output.stdout).lines().take(256) {
                let fields: Vec<_> = line.split(',').map(str::trim).collect();
                if fields.len() == 3 {
                    if let Ok(pid) = fields[0].parse::<u32>() {
                        processes.push(json!({"pid":pid,"accelerator_id":fields[1],"memory_bytes":fields[2].parse::<u64>().ok().and_then(|n| n.checked_mul(1024*1024))}));
                    }
                }
            }
        }
    }
    json!({"available":true,"provider":"nvidia","devices":devices,"processes":processes,
        "memory_accounting":"Driver-reported; shared/unified memory may overlap host RAM. Do not add these values to host usage."})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn disk_warning_requires_both_capacity_conditions() {
        assert_eq!(
            host(&json!({"disk":{"available":2_000_000_000u64,"percent":99.8}}))["state"],
            "warning"
        );
        assert_eq!(
            host(
                &json!({"memory_total":16_000_000_000u64,"disk":{"available":2_000_000_000u64,"percent":50.0}})
            )["state"],
            "ok"
        );
        assert_eq!(host(&json!({}))["state"], "unknown");
    }

    #[test]
    fn driver_unknown_memory_is_not_reported_as_zero() {
        let rows = device_rows("0, GPU-example, NVIDIA GB10, 78, [N/A], [N/A]\n1, GPU-other, NVIDIA Example, 4, 512, 16384");
        assert_eq!(rows[0]["accelerator_id"], "GPU-example");
        assert!(rows[0]["memory_total_bytes"].is_null());
        assert_eq!(rows[1]["memory_used_bytes"], 512 * 1024 * 1024);
        assert_eq!(rows[0]["utilization_percent"], 78.0);
    }
}
