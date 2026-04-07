use std::fs;
use toml;
use serde::{Deserialize, Serialize};

// Simplified config structure to test parsing
#[derive(Debug, Serialize, Deserialize)]
struct TestConfig {
    service: ServiceConfig,
    observability: ObservabilityConfig,
    performance: PerformanceConfig,
    detection: DetectionConfig,
    agent_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ServiceConfig {
    mode: String,
    scan_paths: Vec<String>,
    exclude_paths: Vec<String>,
    ipc_bind: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ObservabilityConfig {
    metrics_bind: String,
    dashboard_bind: String,
    log_level: String,
    log_filters: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct PerformanceConfig {
    cpu_limit_percent: f64,
    memory_limit_mb: u64,
    enable_enforcement: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct DetectionConfig {
    mttd_target_seconds: u64,
    false_positive_threshold: f64,
    enable_yara_fs_monitor: bool,
    yara_rules_path: String,
}

fn main() {
    let content = fs::read_to_string("config.toml").expect("Failed to read config.toml");
    println!("Config content:");
    println!("{}", content);
    println!("\n--- Attempting to parse ---");
    
    match toml::from_str::<TestConfig>(&content) {
        Ok(config) => {
            println!("✓ Successfully parsed config!");
            println!("Agent ID: {}", config.agent_id);
            println!("IPC Bind: {}", config.service.ipc_bind);
        }
        Err(e) => {
            println!("❌ Failed to parse config: {}", e);
            println!("Error details: {:?}", e);
        }
    }
}