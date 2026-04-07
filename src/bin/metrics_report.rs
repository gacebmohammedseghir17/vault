use std::collections::BTreeMap;
use std::env;

use erdps_agent::config::agent_config::AgentConfig;
use erdps_agent::observability::prometheus_metrics::EnterpriseMetricsRegistry;
use erdps_agent::logger::init_logger;

#[derive(Debug, Clone)]
struct Options {
    format: String,          // json | table | summary
    types: Option<String>,   // actions,policy,quarantine,threat,system,validation (comma)
    component: Option<String>,
    since: Option<String>,   // RFC3339
    until: Option<String>,   // RFC3339
    bind: Option<String>,    // host:port (overrides config)
}

impl Default for Options {
    fn default() -> Self {
        Self {
            format: "summary".to_string(),
            types: None,
            component: None,
            since: None,
            until: None,
            bind: None,
        }
    }
}

fn print_usage() {
    println!(
        "Metrics Reporter\n\
         \nUsage:\n\
         \tmetrics_report [--format <json|table|summary>] [--types <list>] [--component <key>] [--since <RFC3339>] [--until <RFC3339>] [--bind <host:port>]\n\
         \nExamples:\n\
         \tmetrics_report --format summary\n\
         \tmetrics_report --format json --types actions,policy --component threat_detected\n\
         \tmetrics_report --format table --since 2025-01-01T00:00:00Z --until 2025-01-02T00:00:00Z\n\
         \tmetrics_report --bind 127.0.0.1:19091 --types threat,system --format summary\n"
    );
}

fn parse_args() -> Options {
    let mut opts = Options::default();
    let mut args = env::args().skip(1).peekable();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            "--format" => {
                if let Some(v) = args.next() {
                    opts.format = v;
                }
            }
            "--types" => {
                if let Some(v) = args.next() {
                    opts.types = Some(v);
                }
            }
            "--component" => {
                if let Some(v) = args.next() {
                    opts.component = Some(v);
                }
            }
            "--since" => {
                if let Some(v) = args.next() {
                    opts.since = Some(v);
                }
            }
            "--until" => {
                if let Some(v) = args.next() {
                    opts.until = Some(v);
                }
            }
            "--bind" => {
                if let Some(v) = args.next() {
                    opts.bind = Some(v);
                }
            }
            unknown => {
                eprintln!("Unknown argument: {}", unknown);
                print_usage();
                std::process::exit(2);
            }
        }
    }

    opts
}

fn resolve_bind(opts: &Options) -> String {
    if let Some(b) = &opts.bind {
        return b.clone();
    }

    // Try to load from config.toml
    if let Ok(content) = std::fs::read_to_string("config.toml") {
        if let Ok(cfg) = toml::from_str::<AgentConfig>(&content) {
            return cfg.observability.metrics_bind;
        }
    }

    // Fallback default
    "127.0.0.1:19091".to_string()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logger for better CLI diagnostics
    let _ = init_logger();
    let opts = parse_args();
    let bind = resolve_bind(&opts);

    let mut qs: Vec<(String, String)> = Vec::new();
    if let Some(t) = &opts.types {
        qs.push(("type".to_string(), t.clone()));
    }
    if let Some(c) = &opts.component {
        qs.push(("component".to_string(), c.clone()));
    }
    if let Some(s) = &opts.since {
        qs.push(("since".to_string(), s.clone()));
    }
    if let Some(u) = &opts.until {
        qs.push(("until".to_string(), u.clone()));
    }

    let qstr = if qs.is_empty() {
        String::new()
    } else {
        let pairs = qs
            .into_iter()
            .map(|(k, v)| format!("{}={}", urlencoding::encode(&k), urlencoding::encode(&v)))
            .collect::<Vec<_>>()
            .join("&");
        format!("?{}", pairs)
    };

    let url = format!("http://{}/metrics.json{}", bind, qstr);

    let client = reqwest::Client::new();
    let resp = client.get(&url).send().await?;
    if !resp.status().is_success() {
        eprintln!("Failed to fetch metrics: {}", resp.status());
        std::process::exit(1);
    }

    let registry: EnterpriseMetricsRegistry = resp.json().await?;

    match opts.format.as_str() {
        "json" => {
            let s = serde_json::to_string_pretty(&registry)?;
            println!("{}", s);
        }
        "table" => {
            print_table(&registry);
        }
        _ => {
            print_summary(&registry);
        }
    }

    Ok(())
}

fn print_table(registry: &EnterpriseMetricsRegistry) {
    println!("== ERDPS Actions Total ==");
    let mut actions: BTreeMap<String, u64> = BTreeMap::new();
    for (k, v) in &registry.erdps_actions_total {
        actions.insert(k.clone(), *v);
    }
    let max_key = actions.keys().map(|k| k.len()).max().unwrap_or(5);
    println!("{:<width$} | {}", "action", "count", width = max_key.max(6));
    println!("{:-<width$}-+-------", "", width = max_key.max(6));
    for (k, v) in actions {
        println!("{:<width$} | {}", k, v, width = max_key.max(6));
    }

    println!("\n== Policy Decision Latency (ms) ==");
    let latencies: Vec<f64> = registry
        .policy_decision_latency_ms
        .iter()
        .map(|l| l.latency_ms)
        .collect();
    if latencies.is_empty() {
        println!("No data");
    } else {
        let (min, avg, p90, p99) = stats(&latencies);
        println!("min: {:.2}\tavg: {:.2}\tp90: {:.2}\tp99: {:.2}", min, avg, p90, p99);
    }

    println!("\n== Quarantine Metrics ==");
    println!(
        "files: {}\tprocesses: {}\tnetwork: {}\tactive: {}\tavg_time_ms: {:.2}",
        registry.quarantine_metrics.files_quarantined_total,
        registry.quarantine_metrics.processes_quarantined_total,
        registry.quarantine_metrics.network_quarantined_total,
        registry.quarantine_metrics.active_quarantine_items,
        registry.quarantine_metrics.avg_quarantine_time_ms
    );

    println!("\n== Threat Detection Metrics ==");
    println!(
        "detected_total: {}\taccuracy: {:.4}\tfalse_positive_rate: {:.4}\tmttd_seconds: {:.2}",
        registry.threat_detection_metrics.threats_detected_total,
        registry.threat_detection_metrics.detection_accuracy,
        registry.threat_detection_metrics.false_positive_rate,
        registry.threat_detection_metrics.mttd_seconds
    );

    println!("\n== System Performance Metrics ==");
    println!(
        "cpu_percent: {:.2}\tmemory_mb: {:.2}\tuptime_seconds: {}",
        registry.system_performance_metrics.cpu_usage_percent,
        registry.system_performance_metrics.memory_usage_mb,
        registry.system_performance_metrics.uptime_seconds
    );

    println!("\n== Validation Metrics ==");
    println!(
        "executed_total: {}\tsuccessful_total: {}\tzero_fp_compliance: {}\tperformance_compliance: {}",
        registry.validation_metrics.validations_executed_total,
        registry.validation_metrics.validations_successful_total,
        registry.validation_metrics.zero_fp_compliance,
        registry.validation_metrics.performance_compliance
    );
}

fn print_summary(registry: &EnterpriseMetricsRegistry) {
    println!("Metrics Summary (last_update: {})", registry.last_update);
    let total_actions: u64 = registry.erdps_actions_total.values().sum();
    println!("- ERDPS actions executed: {}", total_actions);

    let latencies: Vec<f64> = registry
        .policy_decision_latency_ms
        .iter()
        .map(|l| l.latency_ms)
        .collect();
    if !latencies.is_empty() {
        let (_, avg, p90, _) = stats(&latencies);
        println!("- Policy decision latency avg: {:.2} ms (p90: {:.2})", avg, p90);
    } else {
        println!("- Policy decision latency: no data");
    }

    println!(
        "- Quarantine active: {} (files: {}, processes: {}, network: {})",
        registry.quarantine_metrics.active_quarantine_items,
        registry.quarantine_metrics.files_quarantined_total,
        registry.quarantine_metrics.processes_quarantined_total,
        registry.quarantine_metrics.network_quarantined_total
    );

    println!(
        "- Threats detected: {} (accuracy: {:.2}, FPR: {:.2})",
        registry.threat_detection_metrics.threats_detected_total,
        registry.threat_detection_metrics.detection_accuracy,
        registry.threat_detection_metrics.false_positive_rate
    );

    println!(
        "- System: CPU {:.2}% | Memory {:.2} MB | Uptime {} s",
        registry.system_performance_metrics.cpu_usage_percent,
        registry.system_performance_metrics.memory_usage_mb,
        registry.system_performance_metrics.uptime_seconds
    );

    println!(
        "- Validation: executed {} | successful {} | zero-fp {} | perf {}",
        registry.validation_metrics.validations_executed_total,
        registry.validation_metrics.validations_successful_total,
        registry.validation_metrics.zero_fp_compliance,
        registry.validation_metrics.performance_compliance
    );
}

fn stats(values: &[f64]) -> (f64, f64, f64, f64) {
    // Robust percentile calculation with NaN-safe handling and nearest-rank indexing.
    // - Filters out non-finite values to avoid panics on partial_cmp
    // - Uses nearest-rank definition: ceil(p * N) - 1 (bounded)
    // - Returns zeros if no valid values are present
    let mut v: Vec<f64> = values.iter().copied().filter(|x| x.is_finite()).collect();
    if v.is_empty() {
        return (0.0, 0.0, 0.0, 0.0);
    }

    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let len = v.len();
    let min = v[0];
    let sum: f64 = v.iter().sum();
    let avg: f64 = sum / len as f64;

    // nearest-rank percentile index helper
    let pr_idx = |p: f64| -> usize {
        if len == 0 { return 0; }
        let idx = (p * len as f64).ceil() as usize;
        idx.saturating_sub(1).min(len - 1)
    };

    let p90 = v[pr_idx(0.90)];
    let p99 = v[pr_idx(0.99)];
    (min, avg, p90, p99)
}