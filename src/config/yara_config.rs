//! YARA Configuration Module
//!
//! This module handles loading and managing YARA scanning configuration
//! from JSON configuration files with validation and error handling.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// YARA scanning configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraConfig {
    pub enabled: bool,
    pub rules_path: String,
    /// Additional rule directories to scan (for comprehensive rule loading)
    pub additional_rules_paths: Vec<String>,
    pub scan_directories: Vec<String>,
    pub excluded_directories: Vec<String>,
    pub file_extensions: Vec<String>,
    pub max_file_size_mb: u64,
    pub scan_timeout_seconds: u64,
    pub max_concurrent_scans: usize,
    pub memory_chunk_size: usize,
    pub real_time_monitoring: RealTimeMonitoringConfig,
    pub periodic_scan: PeriodicScanConfig,
    pub performance: PerformanceConfig,
    pub alerts: AlertConfig,
}

/// Real-time file system monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealTimeMonitoringConfig {
    pub enabled: bool,
    pub watch_directories: Vec<String>,
    pub scan_on_write: bool,
    pub scan_on_create: bool,
    pub scan_on_modify: bool,
    pub debounce_ms: u64,
    /// Maximum number of pending events in the channel before applying backpressure
    pub max_pending_events: Option<usize>,
}

/// Periodic scanning configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeriodicScanConfig {
    pub enabled: bool,
    pub interval_minutes: u64,
    pub full_system_scan_hours: u64,
}

/// Performance and resource limits configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    pub memory_limit_mb: u64,
    pub cpu_limit_percent: u8,
    pub io_priority: String,
}

/// Alert configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertConfig {
    pub send_to_dashboard: bool,
    pub log_to_file: bool,
    pub severity_threshold: String,
}

/// IPC communication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcConfig {
    pub enabled: bool,
    pub protocol: String,
    pub address: String,
    pub port: u16,
    pub retry_attempts: u32,
    pub retry_delay_ms: u64,
    pub connection_timeout_ms: u64,
    pub heartbeat_interval_ms: u64,
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub file_path: String,
    pub max_file_size_mb: u64,
    pub max_files: u32,
    pub console_output: bool,
}

/// Complete configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub yara: YaraConfig,
    pub ipc: IpcConfig,
    pub logging: LoggingConfig,
}

impl Default for YaraConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rules_path: "rules/".to_string(),
            additional_rules_paths: vec![
                "rules/signature-base/".to_string(),
                "rules/eset-malware-iocs/".to_string(),
                "rules/yara-forge-full/".to_string(),
                "rules/elastic-security/".to_string(),
                "rules/reversinglabs-yara/".to_string(),
                "rules/yara-forge-core/".to_string(),
                "rules/kaggle-yara-rules/".to_string(),
                "rules/awesome-yara/".to_string(),
            ],
            scan_directories: vec![
                "C:\\Users".to_string(),
                "C:\\Downloads".to_string(),
                "C:\\Documents".to_string(),
                "C:\\Desktop".to_string(),
                "C:\\Temp".to_string(),
            ],
            excluded_directories: vec![
                "C:\\Windows\\System32".to_string(),
                "C:\\Windows\\SysWOW64".to_string(),
                "C:\\Program Files".to_string(),
                "C:\\Program Files (x86)".to_string(),
            ],
            file_extensions: vec![
                ".exe".to_string(),
                ".dll".to_string(),
                ".bat".to_string(),
                ".cmd".to_string(),
                ".ps1".to_string(),
                ".vbs".to_string(),
                ".js".to_string(),
                ".jar".to_string(),
                ".scr".to_string(),
                ".com".to_string(),
                ".pif".to_string(),
                // Enable scanning of ransom simulation artifacts
                ".txt".to_string(),
                ".ransom_test".to_string(),
                ".enc".to_string(),
            ],
            max_file_size_mb: 100,
            scan_timeout_seconds: 30,
            max_concurrent_scans: 4,
            memory_chunk_size: 1024 * 1024, // 1MB chunks
            real_time_monitoring: RealTimeMonitoringConfig::default(),
            periodic_scan: PeriodicScanConfig::default(),
            performance: PerformanceConfig::default(),
            alerts: AlertConfig::default(),
        }
    }
}

impl Default for RealTimeMonitoringConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            watch_directories: vec![
                "C:\\Users".to_string(),
                "C:\\Downloads".to_string(),
                "C:\\Documents".to_string(),
                "C:\\Desktop".to_string(),
            ],
            scan_on_write: true,
            scan_on_create: true,
            scan_on_modify: false,
            debounce_ms: 1000,
            max_pending_events: Some(1000), // Default to 1000 pending events
        }
    }
}

impl Default for PeriodicScanConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_minutes: 60,
            full_system_scan_hours: 24,
        }
    }
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            memory_limit_mb: 512,
            cpu_limit_percent: 25,
            io_priority: "low".to_string(),
        }
    }
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            send_to_dashboard: true,
            log_to_file: true,
            severity_threshold: "medium".to_string(),
        }
    }
}

impl Default for IpcConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            protocol: "tcp".to_string(),
            address: "127.0.0.1".to_string(),
            port: 7777,
            retry_attempts: 3,
            retry_delay_ms: 1000,
            connection_timeout_ms: 5000,
            heartbeat_interval_ms: 30000,
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            file_path: "logs/yara_scanner.log".to_string(),
            max_file_size_mb: 10,
            max_files: 5,
            console_output: true,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            yara: YaraConfig::default(),
            ipc: IpcConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}

impl Config {
    /// Load configuration from JSON file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read config file: {:?}", path.as_ref()))?;

        let config: Config = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse config file: {:?}", path.as_ref()))?;

        config
            .validate()
            .with_context(|| "Configuration validation failed")?;

        Ok(config)
    }

    /// Load configuration with fallback to default
    pub fn load_or_default<P: AsRef<Path>>(path: P) -> Self {
        match Self::load_from_file(&path) {
            Ok(config) => {
                log::info!("Loaded YARA configuration from: {:?}", path.as_ref());
                config
            }
            Err(e) => {
                log::warn!(
                    "Failed to load YARA config from {:?}: {}. Using defaults.",
                    path.as_ref(),
                    e
                );
                Self::default()
            }
        }
    }

    /// Save configuration to JSON file
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content =
            serde_json::to_string_pretty(self).context("Failed to serialize configuration")?;

        // Create parent directory if it doesn't exist
        if let Some(parent) = path.as_ref().parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create config directory: {:?}", parent))?;
        }

        fs::write(&path, content)
            .with_context(|| format!("Failed to write config file: {:?}", path.as_ref()))?;

        Ok(())
    }

    /// Validate configuration values
    pub fn validate(&self) -> Result<()> {
        // Validate YARA configuration
        if self.yara.enabled {
            if self.yara.rules_path.is_empty() {
                return Err(anyhow::anyhow!(
                    "YARA rules path cannot be empty when YARA is enabled"
                ));
            }

            if self.yara.scan_directories.is_empty() {
                return Err(anyhow::anyhow!(
                    "At least one scan directory must be specified"
                ));
            }

            if self.yara.max_file_size_mb == 0 {
                return Err(anyhow::anyhow!("Max file size must be greater than 0"));
            }

            if self.yara.scan_timeout_seconds == 0 {
                return Err(anyhow::anyhow!("Scan timeout must be greater than 0"));
            }

            if self.yara.max_concurrent_scans == 0 {
                return Err(anyhow::anyhow!(
                    "Max concurrent scans must be greater than 0"
                ));
            }
        }

        // Validate IPC configuration
        if self.ipc.enabled {
            if self.ipc.address.is_empty() {
                return Err(anyhow::anyhow!(
                    "IPC address cannot be empty when IPC is enabled"
                ));
            }

            if self.ipc.port == 0 {
                return Err(anyhow::anyhow!("IPC port must be greater than 0"));
            }
        }

        Ok(())
    }

    /// Get scan timeout as Duration
    pub fn scan_timeout(&self) -> Duration {
        Duration::from_secs(self.yara.scan_timeout_seconds)
    }

    /// Get debounce duration as Duration
    pub fn debounce_duration(&self) -> Duration {
        Duration::from_millis(self.yara.real_time_monitoring.debounce_ms)
    }

    /// Get retry delay as Duration
    pub fn retry_delay(&self) -> Duration {
        Duration::from_millis(self.ipc.retry_delay_ms)
    }

    /// Get connection timeout as Duration
    pub fn connection_timeout(&self) -> Duration {
        Duration::from_millis(self.ipc.connection_timeout_ms)
    }

    /// Get heartbeat interval as Duration
    pub fn heartbeat_interval(&self) -> Duration {
        Duration::from_millis(self.ipc.heartbeat_interval_ms)
    }

    /// Check if a directory should be excluded from scanning
    pub fn is_directory_excluded(&self, path: &str) -> bool {
        self.yara
            .excluded_directories
            .iter()
            .any(|excluded| path.starts_with(excluded))
    }

    /// Check if a file extension should be scanned
    pub fn should_scan_extension(&self, extension: &str) -> bool {
        if self.yara.file_extensions.is_empty() {
            return true; // Scan all extensions if none specified
        }

        self.yara
            .file_extensions
            .iter()
            .any(|ext| ext.eq_ignore_ascii_case(extension))
    }

    /// Get maximum file size in bytes
    pub fn max_file_size_bytes(&self) -> u64 {
        self.yara.max_file_size_mb * 1024 * 1024
    }

    /// Get memory limit in bytes
    pub fn memory_limit_bytes(&self) -> u64 {
        self.yara.performance.memory_limit_mb * 1024 * 1024
    }
}

/// Load YARA configuration from the default location
pub fn load_yara_config() -> Config {
    let config_path = PathBuf::from("config/yara_config.json");
    Config::load_or_default(config_path)
}

/// Create default configuration file if it doesn't exist
pub fn ensure_default_config() -> Result<()> {
    let config_path = PathBuf::from("config/yara_config.json");

    if !config_path.exists() {
        let default_config = Config::default();
        default_config
            .save_to_file(&config_path)
            .context("Failed to create default YARA configuration")?;
        log::info!("Created default YARA configuration at: {:?}", config_path);
    }

    Ok(())
}
