//! Scanning Configuration Module
//!
//! This module defines configuration structures for the scanning subsystem.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// Main scanning configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanningConfig {
    pub enabled: bool,
    pub default_scanner: String,
    pub scanners: HashMap<String, ScannerConfig>,
    pub global: GlobalScanConfig,
    pub monitored_directories: Vec<MonitoredDirectory>,
    pub scheduled_scans: Vec<ScheduledScan>,
}

/// Configuration for individual scanners
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerConfig {
    pub enabled: bool,
    pub scanner_type: String,
    pub settings: HashMap<String, serde_json::Value>,
}

/// Global scanning configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalScanConfig {
    pub max_file_size: u64,
    pub scan_timeout: Duration,
    pub concurrent_scans: usize,
    pub include_extensions: Vec<String>,
    pub exclude_extensions: Vec<String>,
}

/// Directory monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoredDirectory {
    pub enabled: bool,
    pub path: String,
    pub scanner: Option<String>,
    pub file_patterns: Vec<String>,
    pub recursive: bool,
}

/// Scheduled scan configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledScan {
    pub enabled: bool,
    pub name: String,
    pub scanner: String,
    pub paths: Vec<String>,
    pub schedule: String, // Cron-like schedule
    pub priority: ScanPriority,
}

/// Scan priority levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanPriority {
    Low,
    Normal,
    High,
    Critical,
}

impl Default for ScanningConfig {
    fn default() -> Self {
        let mut scanners = HashMap::new();
        scanners.insert(
            "yara".to_string(),
            ScannerConfig {
                enabled: true,
                scanner_type: "yara".to_string(),
                settings: HashMap::new(),
            },
        );

        Self {
            enabled: true,
            default_scanner: "yara".to_string(),
            scanners,
            global: GlobalScanConfig::default(),
            monitored_directories: Vec::new(),
            scheduled_scans: Vec::new(),
        }
    }
}

impl Default for GlobalScanConfig {
    fn default() -> Self {
        Self {
            max_file_size: 100 * 1024 * 1024, // 100MB
            scan_timeout: Duration::from_secs(30),
            concurrent_scans: 4,
            include_extensions: vec![
                "exe".to_string(),
                "dll".to_string(),
                "bat".to_string(),
                "cmd".to_string(),
                "ps1".to_string(),
                "vbs".to_string(),
                "js".to_string(),
                "jar".to_string(),
                "zip".to_string(),
                "rar".to_string(),
            ],
            exclude_extensions: vec![
                "txt".to_string(),
                "log".to_string(),
                "jpg".to_string(),
                "png".to_string(),
                "gif".to_string(),
                "mp3".to_string(),
                "mp4".to_string(),
                "avi".to_string(),
            ],
        }
    }
}

/// Get scanning configuration from agent config
pub fn get_scanning_config(_config: &crate::config::AgentConfig) -> ScanningConfig {
    // For now, return default config
    // In a real implementation, this would extract scanning config from AgentConfig
    ScanningConfig::default()
}

/// Validate scanning configuration
pub fn validate_scanning_config(_config: &mut crate::config::AgentConfig) -> anyhow::Result<()> {
    // Validation logic for scanning configuration
    // For now, just return Ok
    Ok(())
}

/// Get default YARA rules path
pub fn get_default_yara_rules_path() -> String {
    "./rules".to_string()
}
