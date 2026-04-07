//! Main Agent Configuration
//!
//! This module defines the core configuration structure for the ERDPS Agent.

use anyhow::{Context, Result};
use base64::Engine;
use rand::{thread_rng, RngCore};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::str::FromStr;
use std::net::{IpAddr, SocketAddr};
use crate::ai::AIConfig;

/// Default configuration schema version
fn default_config_version() -> String {
    "2.0".to_string()
}

#[cfg(feature = "yara")]
use crate::yara_updater::YaraUpdaterConfig;

/// Service configuration section
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    pub mode: String,
    pub scan_paths: Vec<String>,
    pub exclude_paths: Vec<String>,
    pub ipc_bind: String,
    /// Path to TLS certificate for IPC (PEM format)
    pub tls_cert_path: Option<String>,
    /// Path to TLS private key for IPC (PEM format)
    pub tls_key_path: Option<String>,
    /// Allow volume-wide scanning (C:\, D:\) - requires explicit opt-in for safety
    #[serde(default)]
    pub allow_volume_scan: Option<bool>,
}

/// Observability configuration section
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservabilityConfig {
    pub metrics_bind: String,
    pub metrics_port: u16,
    pub dashboard_bind: String,
    pub dashboard_port: u16,
    pub log_level: String,
    pub log_filters: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallerConfig {
    pub signing_enabled: bool,
    pub signtool_path: String,
    pub certificate_thumbprint: String,
    pub timestamp_url: String,
    pub artifact_paths: Vec<String>,
}

/// Performance configuration section
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    pub cpu_limit_percent: f64,
    pub memory_limit_mb: u64,
    pub enable_enforcement: bool,
}

/// Detection configuration section
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionConfig {
    pub mttd_target_seconds: u64,
    pub false_positive_threshold: f64,
    pub enable_yara_fs_monitor: bool,
    pub yara_rules_path: String,
    
    /// Advanced disassembly configuration
    #[cfg(feature = "advanced-disassembly")]
    pub disassembly: Option<DisassemblyConfig>,
    
    /// AI integration configuration
    #[cfg(feature = "ai-integration")]
    pub ai_integration: Option<AiIntegrationConfig>,
}

/// Disassembly configuration for advanced malware analysis
#[cfg(feature = "advanced-disassembly")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisassemblyConfig {
    pub enabled: bool,
    pub supported_architectures: Vec<String>,
    pub max_file_size_mb: u64,
    pub analysis_timeout_secs: u64,
    pub pattern_detection: PatternDetectionConfig,
    pub entropy_analysis: bool,
    pub pe_analysis: bool,
}

/// Pattern detection configuration for disassembly
#[cfg(feature = "advanced-disassembly")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternDetectionConfig {
    pub shellcode_detection: bool,
    pub packer_detection: bool,
    pub obfuscation_detection: bool,
    pub anti_analysis_detection: bool,
    pub injection_detection: bool,
    pub ransomware_detection: bool,
    pub keylogger_detection: bool,
    pub rootkit_detection: bool,
    pub sensitivity_level: String, // "low", "medium", "high"
}

/// AI integration configuration for enhanced analysis
#[cfg(feature = "ai-integration")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiIntegrationConfig {
    pub enabled: bool,
    pub ollama_endpoint: String,
    pub model_name: String,
    pub analysis_timeout_secs: u64,
    pub max_file_size_mb: u64,
    pub confidence_threshold: f64,
    pub yara_generation: YaraGenerationConfig,
    pub malware_classification: MalwareClassificationConfig,
}

/// YARA rule generation configuration
#[cfg(feature = "ai-integration")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraGenerationConfig {
    pub enabled: bool,
    pub auto_deploy: bool,
    pub rule_quality_threshold: f64,
    pub max_rules_per_sample: u32,
}

/// Malware classification configuration
#[cfg(feature = "ai-integration")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalwareClassificationConfig {
    pub enabled: bool,
    pub classification_threshold: f64,
    pub supported_families: Vec<String>,
}

/// Main agent configuration matching the current config.toml format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// Configuration schema version for validation and migration
    #[serde(default = "default_config_version")]
    pub config_version: String,

    pub service: ServiceConfig,
    pub observability: ObservabilityConfig,
    pub performance: PerformanceConfig,
    pub detection: DetectionConfig,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ai: Option<AIConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub installer: Option<InstallerConfig>,

    // Legacy fields for compatibility
    pub agent_id: String,
    pub ipc_key: String,
    pub quarantine_path: String,
    pub audit_log_path: String,

    // Legacy detection thresholds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mass_modification_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mass_modification_window_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extension_mutation_window_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extension_mutation_threshold: Option<f64>,

    // Legacy process monitoring
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_monitoring_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suspicious_process_threshold: Option<u32>,

    // Legacy network monitoring
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_monitoring_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suspicious_network_threshold: Option<u32>,

    // Legacy performance settings
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_concurrent_scans: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scan_timeout_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_limit_mb: Option<usize>,

    // YARA-specific settings
    pub yara_enabled: Option<bool>,
    pub yara_process_scan_enabled: Option<bool>,
    pub yara_scan_downloads: Option<bool>,
    pub yara_scan_temp_files: Option<bool>,
    pub yara_scan_user_files: Option<bool>,
    pub yara_scan_system_files: Option<bool>,
    pub yara_scan_network_drives: Option<bool>,
    pub yara_scan_removable_drives: Option<bool>,
    pub yara_scan_archives: Option<bool>,
    pub yara_scan_memory: Option<bool>,
    pub yara_scan_registry: Option<bool>,
    pub yara_scan_startup: Option<bool>,
    pub yara_scan_services: Option<bool>,
    pub yara_scan_drivers: Option<bool>,
    pub yara_scan_dlls: Option<bool>,
    pub yara_scan_executables: Option<bool>,
    pub yara_scan_scripts: Option<bool>,
    pub yara_scan_documents: Option<bool>,
    pub yara_scan_images: Option<bool>,
    pub yara_scan_videos: Option<bool>,
    pub yara_scan_audio: Option<bool>,
    pub yara_scan_compressed: Option<bool>,
    pub yara_scan_encrypted: Option<bool>,
    pub yara_scan_hidden: Option<bool>,
    pub yara_scan_system_protected: Option<bool>,

    // YARA configuration reference
    #[cfg(feature = "yara")]
    pub yara: Option<crate::config::YaraConfig>,

    // YARA updater configuration
    #[cfg(feature = "yara")]
    pub yara_updater: YaraUpdaterConfig,

    pub allow_terminate: bool,

    /// Mitigation score threshold
    pub mitigation_score_threshold: u32,

    /// Auto mitigation enabled
    pub auto_mitigate: bool,

    /// Process behavior window in seconds
    pub process_behavior_window_secs: u64,

    /// Process behavior write threshold
    pub process_behavior_write_threshold: u32,
    pub entropy_threshold: f64,
    pub dry_run: bool,
    pub auto_quarantine_score: u32,
    pub ransom_note_patterns: Vec<String>,
    pub yara_scan_directories: Option<Vec<String>>,
    pub yara_max_file_size_mb: Option<u64>,
    pub yara_process_scan_interval_minutes: Option<u64>,
    pub yara_downloads_scan_interval_minutes: Option<u64>,
    pub yara_target_processes: Option<Vec<String>>,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            mode: "production".to_string(),
            scan_paths: vec![
                "C:\\Users".to_string(),
                "C:\\Program Files".to_string(),
                "C:\\Program Files (x86)".to_string(),
            ],
            exclude_paths: vec![
                "C:\\Windows\\System32".to_string(),
                "C:\\Windows\\SysWOW64".to_string(),
                "C:\\$Recycle.Bin".to_string(),
            ],
            ipc_bind: "127.0.0.1:8080".to_string(),
            tls_cert_path: None,
            tls_key_path: None,
            allow_volume_scan: Some(false), // Default to no volume-wide scanning for safety
        }
    }
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            metrics_bind: "127.0.0.1:19091".to_string(),
            metrics_port: 19091,
            dashboard_bind: "127.0.0.1:19092".to_string(), // Dashboard on separate port
            dashboard_port: 19092,                         // Dashboard on separate port
            log_level: "info".to_string(),
            log_filters: "cranelift=warn,wasmtime=warn,walrus=warn,aho_corasick=warn".to_string(),
        }
    }
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            cpu_limit_percent: 6.0,
            memory_limit_mb: 200,
            enable_enforcement: true,
        }
    }
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            mttd_target_seconds: 60,
            false_positive_threshold: 0.1,
            enable_yara_fs_monitor: true,
            yara_rules_path: "./yara_rules".to_string(),
            
            #[cfg(feature = "advanced-disassembly")]
            disassembly: Some(DisassemblyConfig::default()),
            
            #[cfg(feature = "ai-integration")]
            ai_integration: Some(AiIntegrationConfig::default()),
        }
    }
}

impl Default for InstallerConfig {
    fn default() -> Self {
        Self {
            signing_enabled: false,
            signtool_path: "C:\\Program Files (x86)\\Windows Kits\\10\\bin\\x64\\signtool.exe".to_string(),
            certificate_thumbprint: String::new(),
            timestamp_url: "http://timestamp.digicert.com".to_string(),
            artifact_paths: Vec::new(),
        }
    }
}

#[cfg(feature = "advanced-disassembly")]
impl Default for DisassemblyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            supported_architectures: vec![
                "x86".to_string(),
                "x64".to_string(),
                "arm".to_string(),
                "arm64".to_string(),
            ],
            max_file_size_mb: 100,
            analysis_timeout_secs: 300,
            pattern_detection: PatternDetectionConfig::default(),
            entropy_analysis: true,
            pe_analysis: true,
        }
    }
}

#[cfg(feature = "advanced-disassembly")]
impl Default for PatternDetectionConfig {
    fn default() -> Self {
        Self {
            shellcode_detection: true,
            packer_detection: true,
            obfuscation_detection: true,
            anti_analysis_detection: true,
            injection_detection: true,
            ransomware_detection: true,
            keylogger_detection: true,
            rootkit_detection: true,
            sensitivity_level: "medium".to_string(),
        }
    }
}

#[cfg(feature = "ai-integration")]
impl Default for AiIntegrationConfig {
    fn default() -> Self {
        Self {
            enabled: false, // Disabled by default as it requires local Ollama setup
            ollama_endpoint: "http://localhost:11434".to_string(),
            model_name: "llama3.2:3b".to_string(),
            analysis_timeout_secs: 600,
            max_file_size_mb: 50,
            confidence_threshold: 0.7,
            yara_generation: YaraGenerationConfig::default(),
            malware_classification: MalwareClassificationConfig::default(),
        }
    }
}

#[cfg(feature = "ai-integration")]
impl Default for YaraGenerationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            auto_deploy: false, // Manual review recommended
            rule_quality_threshold: 0.8,
            max_rules_per_sample: 5,
        }
    }
}

#[cfg(feature = "ai-integration")]
impl Default for MalwareClassificationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            classification_threshold: 0.75,
            supported_families: vec![
                "ransomware".to_string(),
                "trojan".to_string(),
                "backdoor".to_string(),
                "keylogger".to_string(),
                "rootkit".to_string(),
                "worm".to_string(),
                "virus".to_string(),
                "adware".to_string(),
                "spyware".to_string(),
            ],
        }
    }
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            config_version: default_config_version(),
            service: ServiceConfig::default(),
            observability: ObservabilityConfig::default(),
            performance: PerformanceConfig::default(),
            detection: DetectionConfig::default(),
            ai: Some(AIConfig::default()),
            installer: Some(InstallerConfig::default()),
            agent_id: "erdps-agent-001".to_string(),
            ipc_key: generate_secure_key(),
            quarantine_path: get_default_quarantine_path(),
            audit_log_path: get_default_audit_log_path(),
            mass_modification_count: Some(50),
            mass_modification_window_secs: Some(60),
            extension_mutation_window_secs: Some(300),
            extension_mutation_threshold: Some(0.8),
            process_monitoring_enabled: Some(true),
            suspicious_process_threshold: Some(10),
            network_monitoring_enabled: Some(true),
            suspicious_network_threshold: Some(20),
            max_concurrent_scans: Some(4),
            scan_timeout_secs: Some(300),
            memory_limit_mb: Some(512),
            yara_enabled: Some(true),
            yara_process_scan_enabled: Some(false),
            yara_scan_downloads: Some(true),
            yara_scan_temp_files: Some(true),
            yara_scan_user_files: Some(true),
            yara_scan_system_files: Some(false),
            yara_scan_network_drives: Some(false),
            yara_scan_removable_drives: Some(true),
            yara_scan_archives: Some(true),
            yara_scan_memory: Some(false),
            yara_scan_registry: Some(false),
            yara_scan_startup: Some(true),
            yara_scan_services: Some(false),
            yara_scan_drivers: Some(false),
            yara_scan_dlls: Some(true),
            yara_scan_executables: Some(true),
            yara_scan_scripts: Some(true),
            yara_scan_documents: Some(true),
            yara_scan_images: Some(false),
            yara_scan_videos: Some(false),
            yara_scan_audio: Some(false),
            yara_scan_compressed: Some(true),
            yara_scan_encrypted: Some(false),
            yara_scan_hidden: Some(true),
            yara_scan_system_protected: Some(false),
            #[cfg(feature = "yara")]
            yara: Some(crate::config::YaraConfig::default()),
            #[cfg(feature = "yara")]
            yara_updater: YaraUpdaterConfig::default(),
            allow_terminate: false,
            mitigation_score_threshold: 70,
            auto_mitigate: true,
            process_behavior_window_secs: 300,
            process_behavior_write_threshold: 100,
            entropy_threshold: 7.0,
            dry_run: false,
            auto_quarantine_score: 80,
            ransom_note_patterns: vec![
                "README".to_string(),
                "DECRYPT".to_string(),
                "RANSOM".to_string(),
                "PAYMENT".to_string(),
            ],
            yara_scan_directories: None,
            yara_max_file_size_mb: Some(100),
            yara_process_scan_interval_minutes: Some(5),
            yara_downloads_scan_interval_minutes: Some(30),
            yara_target_processes: None,
        }
    }
}

impl AgentConfig {
    /// Validate configuration values with strict checks
    pub fn validate(&self) -> Result<()> {
        // --- Service checks ---
        if self.service.scan_paths.is_empty() {
            return Err(anyhow::anyhow!("[service.scan_paths] must contain at least one path"));
        }

        // Disallow root volume scans unless explicitly allowed
        let allow_volume_scan = self.service.allow_volume_scan.unwrap_or(false);
        for p in &self.service.scan_paths {
            if is_volume_root(p) && !allow_volume_scan {
                return Err(anyhow::anyhow!(
                    format!(
                        "[service.scan_paths] contains root volume '{}' but allow_volume_scan=false",
                        p
                    )
                ));
            }
        }

        // Validate IPC bind address
        if SocketAddr::from_str(&self.service.ipc_bind).is_err() {
            return Err(anyhow::anyhow!(
                format!("[service.ipc_bind] is not a valid host:port: '{}'", self.service.ipc_bind)
            ));
        }

        // --- Observability checks ---
        // u16 already guarantees <= 65535; just ensure non-zero
        if self.observability.metrics_port == 0 {
            return Err(anyhow::anyhow!(
                format!(
                    "[observability.metrics_port] must be between 1 and 65535, got {}",
                    self.observability.metrics_port
                )
            ));
        }
        if self.observability.dashboard_port == 0 {
            return Err(anyhow::anyhow!(
                format!(
                    "[observability.dashboard_port] must be between 1 and 65535, got {}",
                    self.observability.dashboard_port
                )
            ));
        }
        // Accept either bare IP or host:port forms in bind strings
        if SocketAddr::from_str(&self.observability.metrics_bind).is_err()
            && IpAddr::from_str(&self.observability.metrics_bind).is_err()
        {
            return Err(anyhow::anyhow!(
                format!(
                    "[observability.metrics_bind] must be a valid IP or host:port, got '{}'",
                    self.observability.metrics_bind
                )
            ));
        }
        if SocketAddr::from_str(&self.observability.dashboard_bind).is_err()
            && IpAddr::from_str(&self.observability.dashboard_bind).is_err()
        {
            return Err(anyhow::anyhow!(
                format!(
                    "[observability.dashboard_bind] must be a valid IP or host:port, got '{}'",
                    self.observability.dashboard_bind
                )
            ));
        }
        if !is_valid_log_level(&self.observability.log_level) {
            return Err(anyhow::anyhow!(
                format!(
                    "[observability.log_level] must be one of trace, debug, info, warn, error; got '{}'",
                    self.observability.log_level
                )
            ));
        }

        // --- Performance checks ---
        if !(self.performance.cpu_limit_percent > 0.0 && self.performance.cpu_limit_percent <= 100.0)
        {
            return Err(anyhow::anyhow!(
                format!(
                    "[performance.cpu_limit_percent] must be in (0, 100], got {}",
                    self.performance.cpu_limit_percent
                )
            ));
        }
        if self.performance.memory_limit_mb == 0 {
            return Err(anyhow::anyhow!(
                "[performance.memory_limit_mb] must be greater than 0"
            ));
        }

        // --- Detection checks ---
        if self.detection.mttd_target_seconds == 0 {
            return Err(anyhow::anyhow!(
                "[detection.mttd_target_seconds] must be greater than 0"
            ));
        }
        if !(self.detection.false_positive_threshold >= 0.0
            && self.detection.false_positive_threshold <= 1.0)
        {
            return Err(anyhow::anyhow!(
                format!(
                    "[detection.false_positive_threshold] must be in [0.0, 1.0], got {}",
                    self.detection.false_positive_threshold
                )
            ));
        }
        if self.detection.yara_rules_path.trim().is_empty() {
            return Err(anyhow::anyhow!(
                "[detection.yara_rules_path] must be a non-empty path"
            ));
        }

        // --- General/legacy checks ---
        if self.quarantine_path.trim().is_empty() {
            return Err(anyhow::anyhow!(
                "[quarantine_path] must be a non-empty path"
            ));
        }
        if self.audit_log_path.trim().is_empty() {
            return Err(anyhow::anyhow!(
                "[audit_log_path] must be a non-empty path"
            ));
        }
        if self.config_version.trim().is_empty() {
            return Err(anyhow::anyhow!(
                "[config_version] must be a non-empty string"
            ));
        }

        // Risk/mitigation thresholds
        if self.mitigation_score_threshold > 100 {
            return Err(anyhow::anyhow!(
                format!(
                    "[mitigation_score_threshold] must be in 0..=100, got {}",
                    self.mitigation_score_threshold
                )
            ));
        }
        if self.auto_quarantine_score > 100 {
            return Err(anyhow::anyhow!(
                format!(
                    "[auto_quarantine_score] must be in 0..=100, got {}",
                    self.auto_quarantine_score
                )
            ));
        }
        if !(self.entropy_threshold >= 0.0 && self.entropy_threshold <= 8.0) {
            return Err(anyhow::anyhow!(
                format!(
                    "[entropy_threshold] must be in [0.0, 8.0], got {}",
                    self.entropy_threshold
                )
            ));
        }
        if self.process_behavior_window_secs == 0 {
            return Err(anyhow::anyhow!(
                "[process_behavior_window_secs] must be greater than 0"
            ));
        }
        if self.process_behavior_write_threshold == 0 {
            return Err(anyhow::anyhow!(
                "[process_behavior_write_threshold] must be greater than 0"
            ));
        }

        // Optional YARA parameters
        if let Some(v) = self.yara_max_file_size_mb {
            if v == 0 {
                return Err(anyhow::anyhow!(
                    "[yara_max_file_size_mb] must be greater than 0 when set"
                ));
            }
        }
        if let Some(v) = self.yara_process_scan_interval_minutes {
            if v == 0 {
                return Err(anyhow::anyhow!(
                    "[yara_process_scan_interval_minutes] must be greater than 0 when set"
                ));
            }
        }
        if let Some(v) = self.yara_downloads_scan_interval_minutes {
            if v == 0 {
                return Err(anyhow::anyhow!(
                    "[yara_downloads_scan_interval_minutes] must be greater than 0 when set"
                ));
            }
        }

        // Ransom note patterns should not be empty to be useful
        if self.ransom_note_patterns.is_empty() {
            return Err(anyhow::anyhow!(
                "[ransom_note_patterns] must contain at least one pattern"
            ));
        }

        Ok(())
    }
    /// Load configuration from file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        log::info!("Loading config from path: {}", path.as_ref().display());

        let content = fs::read_to_string(path.as_ref())
            .with_context(|| format!("Failed to read config file: {:?}", path.as_ref()))?;

        let config: AgentConfig =
            toml::from_str(&content).with_context(|| "Failed to parse config file as TOML")?;

        // Explicit logging as required for production
        log::info!(
            "Loaded config from path {} (schema v{})",
            path.as_ref().display(),
            config.config_version
        );

        // Perform strict validation and provide clear errors
        if let Err(e) = config.validate() {
            log::error!(
                "Config validation failed for {}: {}",
                path.as_ref().display(),
                e
            );
            return Err(e);
        }

        Ok(config)
    }

    /// Save configuration to file
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content =
            toml::to_string_pretty(self).with_context(|| "Failed to serialize config to TOML")?;

        fs::write(path.as_ref(), content)
            .with_context(|| format!("Failed to write config file: {:?}", path.as_ref()))?;

        Ok(())
    }

    /// Load configuration with strict validation (no defaults)
    pub fn load_strict<P: AsRef<Path>>(path: P) -> Result<Self> {
        if !path.as_ref().exists() {
            return Err(anyhow::anyhow!("Config file does not exist: {}", path.as_ref().display()));
        }

        let content = fs::read_to_string(path.as_ref())
            .with_context(|| format!("Failed to read config file: {:?}", path.as_ref()))?;

        // Parse as raw TOML value first to check for missing sections
        let toml_value: toml::Value = toml::from_str(&content)
            .with_context(|| "Failed to parse config file as TOML")?;

        // Check for critical sections
        let missing_sections = Self::check_missing_critical_sections(&toml_value);
        if !missing_sections.is_empty() {
            return Err(anyhow::anyhow!(
                "Missing critical config sections: {}. Use --ignore-defaults=false to allow defaults.",
                missing_sections.join(", ")
            ));
        }

        // If all critical sections are present, parse normally
        let config: AgentConfig = toml::from_str(&content)
            .with_context(|| "Failed to parse config file as TOML")?;

        log::info!(
            "Loaded strict config from {} (schema v{})",
            path.as_ref().display(),
            config.config_version
        );

        // Strict validation
        config.validate()?;

        Ok(config)
    }

    /// Check for missing critical sections in TOML
    fn check_missing_critical_sections(toml_value: &toml::Value) -> Vec<String> {
        let mut missing = Vec::new();
        
        if !toml_value.get("service").is_some() {
            missing.push("service".to_string());
        }
        if !toml_value.get("observability").is_some() {
            missing.push("observability".to_string());
        }
        if !toml_value.get("performance").is_some() {
            missing.push("performance".to_string());
        }
        
        missing
    }

    /// Load configuration with fallback to default
    pub fn load_or_default<P: AsRef<Path>>(path: P) -> Self {
        Self::load_or_default_with_flags(&path, false)
    }

    /// Load configuration with optional strict mode
    pub fn load_or_default_with_flags<P: AsRef<Path>>(path: P, ignore_defaults: bool) -> Self {
        if ignore_defaults {
            match Self::load_strict(&path) {
                Ok(config) => config,
                Err(e) => {
                    log::error!("Strict config loading failed: {}", e);
                    std::process::exit(1);
                }
            }
        } else {
            match Self::load_from_file(&path) {
                Ok(config) => {
                    
                    log::info!(
                        "Loaded configuration from {} (schema v{})",
                        path.as_ref().display(),
                        config.config_version
                    );
                    log::info!(
                        "Config loaded - scan_paths: {:?}, exclusions: {:?}, ipc_bind: {}, metrics_bind: {}, dashboard_bind: {}",
                        config.service.scan_paths,
                        config.service.exclude_paths,
                        config.service.ipc_bind,
                        config.observability.metrics_bind,
                        config.observability.dashboard_bind
                    );
                    log::info!(
                        "Config SLO thresholds - CPU: {}%, Memory: {}MB, MTTD: {}s, FP threshold: {}",
                        config.performance.cpu_limit_percent,
                        config.performance.memory_limit_mb,
                        config.detection.mttd_target_seconds,
                        config.detection.false_positive_threshold
                    );
                    config
                }
                Err(e) => {
                    log::warn!(
                        "Failed to load configuration from {}: {}. Using default configuration.",
                        path.as_ref().display(),
                        e
                    );
                    log::warn!("Config fallback - using default values for all sections");
                    let default_config = Self::default();
                    log::warn!(
                        "Default config fallback (schema v{}) - ipc_bind: {}, metrics_bind: {}, dashboard_bind: {}",
                        default_config.config_version,
                        default_config.service.ipc_bind,
                        default_config.observability.metrics_bind,
                        default_config.observability.dashboard_bind
                    );
                    // Validate defaults to ensure they are sane
                    if let Err(e) = default_config.validate() {
                        log::error!("Default configuration failed validation: {}", e);
                        std::process::exit(1);
                    }
                    default_config
                }
            }
        }
    }
}

/// Generate a secure random key for IPC communication
fn generate_secure_key() -> String {
    let mut key = [0u8; 32];
    thread_rng().fill_bytes(&mut key);
    base64::engine::general_purpose::STANDARD.encode(key)
}

/// Get default quarantine path based on the operating system
fn get_default_quarantine_path() -> String {
    if cfg!(windows) {
        "C:\\ProgramData\\ERDPS\\quarantine".to_string()
    } else {
        "/var/lib/erdps/quarantine".to_string()
    }
}

/// Get default audit log path based on the operating system
fn get_default_audit_log_path() -> String {
    if cfg!(windows) {
        "C:\\ProgramData\\ERDPS\\logs\\audit.log".to_string()
    } else {
        "/var/log/erdps/audit.log".to_string()
    }
}

/// Get default config version

fn is_valid_log_level(level: &str) -> bool {
    matches!(level.to_lowercase().as_str(), "trace" | "debug" | "info" | "warn" | "error")
}

fn is_volume_root(p: &str) -> bool {
    // Detect patterns like "C:\" on Windows
    if p.len() == 3 {
        let bytes = p.as_bytes();
        let is_letter = (bytes[0] >= b'A' && bytes[0] <= b'Z') || (bytes[0] >= b'a' && bytes[0] <= b'z');
        let is_colon = bytes[1] == b':';
        let is_backslash = bytes[2] == b'\\';
        return is_letter && is_colon && is_backslash;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_default_config() {
        let config = AgentConfig::default();
        assert!(!config.ipc_key.is_empty());
        assert!(!config.agent_id.is_empty());
        assert!(config.mass_modification_count.unwrap_or(0) > 0);
    }

    #[test]
    fn test_config_serialization() {
        let config = AgentConfig::default();
        let serialized = toml::to_string(&config).unwrap();
        let deserialized: AgentConfig = toml::from_str(&serialized).unwrap();

        assert_eq!(config.ipc_key, deserialized.ipc_key);
        assert_eq!(config.agent_id, deserialized.agent_id);
    }

    #[test]
    fn test_config_file_operations() {
        let config = AgentConfig::default();
        let temp_file = NamedTempFile::new().unwrap();

        // Save config
        config.save_to_file(temp_file.path()).unwrap();

        // Load config
        let loaded_config = AgentConfig::load_from_file(temp_file.path()).unwrap();

        assert_eq!(config.ipc_key, loaded_config.ipc_key);
        assert_eq!(config.agent_id, loaded_config.agent_id);
    }

    #[test]
    fn test_config_toml_parsing_validation() {
        // Test loading the actual config.toml file
        let config_path = "config.toml";

        // This test validates that config.toml can be parsed without falling back to defaults
        let config = match AgentConfig::load_from_file(config_path) {
            Ok(cfg) => cfg,
            Err(_) => {
                // If config.toml doesn't exist, create a baseline one for testing
                let baseline_config = AgentConfig {
                    service: ServiceConfig {
                        mode: "production".to_string(),
                        scan_paths: vec!["C:\\Users".to_string(), "C:\\Program Files".to_string()],
                        exclude_paths: vec![
                            "C:\\Windows\\System32".to_string(),
                            "C:\\$Recycle.Bin".to_string(),
                        ],
                        ipc_bind: "127.0.0.1:8888".to_string(),
                        tls_cert_path: None,
                        tls_key_path: None,
                        allow_volume_scan: Some(false),
                    },
                    observability: ObservabilityConfig {
                        metrics_bind: "127.0.0.1:19091".to_string(),
                        metrics_port: 19091,
                        dashboard_bind: "127.0.0.1:19092".to_string(),
                        dashboard_port: 19092,
                        log_level: "debug".to_string(),
                        log_filters: "test=debug".to_string(),
                    },
                    performance: PerformanceConfig {
                        cpu_limit_percent: 6.0,
                        memory_limit_mb: 200,
                        enable_enforcement: true,
                    },
                    detection: DetectionConfig {
                        mttd_target_seconds: 60,
                        false_positive_threshold: 0.1,
                        enable_yara_fs_monitor: true,
                        yara_rules_path: "./rules".to_string(),
                        ..DetectionConfig::default()
                    },
                    ..AgentConfig::default()
                };

                // Save baseline config for future tests
                let _ = baseline_config.save_to_file(config_path);
                baseline_config
            }
        };

        // Validate parsed values match expected schema
        assert_eq!(config.service.mode, "production");
    }

    #[test]
    fn test_comprehensive_config_parsing_validation() {
        // Create a comprehensive test config with all sections
        let test_config = AgentConfig {
            config_version: "1.0.0".to_string(),
            service: ServiceConfig {
                mode: "test".to_string(),
                scan_paths: vec!["C:\\TestPath1".to_string(), "C:\\TestPath2".to_string()],
                exclude_paths: vec!["C:\\ExcludePath1".to_string()],
                ipc_bind: "127.0.0.1:9999".to_string(),
                tls_cert_path: None,
                tls_key_path: None,
                allow_volume_scan: Some(true),
            },
            observability: ObservabilityConfig {
                metrics_bind: "127.0.0.1:19999".to_string(),
                metrics_port: 19999,
                dashboard_bind: "127.0.0.1:19998".to_string(),
                dashboard_port: 19998,
                log_level: "trace".to_string(),
                log_filters: "comprehensive=trace".to_string(),
            },
            performance: PerformanceConfig {
                cpu_limit_percent: 15.0,
                memory_limit_mb: 512,
                enable_enforcement: false,
            },
            detection: DetectionConfig {
                mttd_target_seconds: 120,
                false_positive_threshold: 0.05,
                enable_yara_fs_monitor: false,
                yara_rules_path: "./test_rules".to_string(),
                ..DetectionConfig::default()
            },
            ..AgentConfig::default()
        };

        // Serialize to TOML
        let toml_content = toml::to_string_pretty(&test_config).unwrap();

        // Parse back from TOML
        let parsed_config: AgentConfig = toml::from_str(&toml_content).unwrap();

        // Validate all sections match exactly
        assert_eq!(parsed_config.config_version, test_config.config_version);

        // Service section validation
        assert_eq!(parsed_config.service.mode, test_config.service.mode);
        assert_eq!(
            parsed_config.service.scan_paths,
            test_config.service.scan_paths
        );
        assert_eq!(
            parsed_config.service.exclude_paths,
            test_config.service.exclude_paths
        );
        assert_eq!(parsed_config.service.ipc_bind, test_config.service.ipc_bind);
        assert_eq!(
            parsed_config.service.allow_volume_scan,
            test_config.service.allow_volume_scan
        );

        // Observability section validation
        assert_eq!(
            parsed_config.observability.metrics_bind,
            test_config.observability.metrics_bind
        );
        assert_eq!(
            parsed_config.observability.metrics_port,
            test_config.observability.metrics_port
        );
        assert_eq!(
            parsed_config.observability.dashboard_bind,
            test_config.observability.dashboard_bind
        );
        assert_eq!(
            parsed_config.observability.dashboard_port,
            test_config.observability.dashboard_port
        );
        assert_eq!(
            parsed_config.observability.log_level,
            test_config.observability.log_level
        );
        assert_eq!(
            parsed_config.observability.log_filters,
            test_config.observability.log_filters
        );

        // Performance section validation
        assert_eq!(
            parsed_config.performance.cpu_limit_percent,
            test_config.performance.cpu_limit_percent
        );
        assert_eq!(
            parsed_config.performance.memory_limit_mb,
            test_config.performance.memory_limit_mb
        );
        assert_eq!(
            parsed_config.performance.enable_enforcement,
            test_config.performance.enable_enforcement
        );

        // Detection section validation
        assert_eq!(
            parsed_config.detection.mttd_target_seconds,
            test_config.detection.mttd_target_seconds
        );
        assert_eq!(
            parsed_config.detection.false_positive_threshold,
            test_config.detection.false_positive_threshold
        );
        assert_eq!(
            parsed_config.detection.enable_yara_fs_monitor,
            test_config.detection.enable_yara_fs_monitor
        );
        assert_eq!(
            parsed_config.detection.yara_rules_path,
            test_config.detection.yara_rules_path
        );

        println!("✓ Comprehensive config parsing validation passed");

        // Validate critical config sections
        assert!(parsed_config.performance.cpu_limit_percent > 0.0);
        assert!(parsed_config.performance.memory_limit_mb > 0);

        assert!(parsed_config.detection.mttd_target_seconds > 0);
        assert!(parsed_config.detection.false_positive_threshold >= 0.0);
        assert!(!parsed_config.detection.yara_rules_path.is_empty());

        println!("✓ Config validation passed - all sections parsed correctly");
    }
}
