//! Alert System Module
//!
//! This module provides structured JSON alert generation and management
//! for the RANSolution agent detection system.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
#[cfg(feature = "yara")]
use std::path::PathBuf;
use std::sync::Arc;
#[cfg(feature = "yara")]
use std::time::SystemTime;
#[cfg(feature = "yara")]
use std::time::UNIX_EPOCH;
use tokio::sync::{mpsc, RwLock};
#[cfg(feature = "yara")]
use uuid::Uuid;

#[cfg(feature = "yara")]
use crate::filesystem::FileSystemEvent;
#[cfg(feature = "yara")]
use crate::yara::file_scanner::YaraMatch;
#[cfg(feature = "yara")]
use crate::yara::ScanResult;

/// Alert severity levels
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Alert status
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertStatus {
    New,
    Acknowledged,
    InProgress,
    Resolved,
    FalsePositive,
}

/// Process information associated with an alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub executable_path: Option<String>,
    pub command_line: Option<String>,
    pub parent_pid: Option<u32>,
    pub user: Option<String>,
    pub start_time: Option<u64>,
}

/// File information associated with an alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    pub path: String,
    pub size: Option<u64>,
    pub hash_md5: Option<String>,
    pub hash_sha1: Option<String>,
    pub hash_sha256: Option<String>,
    pub created_time: Option<u64>,
    pub modified_time: Option<u64>,
    pub accessed_time: Option<u64>,
    pub file_type: Option<String>,
}

/// YARA rule match information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMatchInfo {
    pub rule_name: String,
    pub rule_namespace: Option<String>,
    pub rule_tags: Vec<String>,
    pub rule_metadata: HashMap<String, String>,
    pub match_count: u32,
    pub match_strings: Vec<String>,
    pub match_offsets: Vec<u64>,
}

/// System information at the time of alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    pub hostname: String,
    pub os_version: String,
    pub agent_version: String,
    pub cpu_usage: Option<f32>,
    pub memory_usage: Option<f32>,
    pub disk_usage: Option<f32>,
}

/// Main alert structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    /// Unique alert identifier
    pub id: String,

    /// Alert timestamp (Unix timestamp in milliseconds)
    pub timestamp: u64,

    /// Alert severity level
    pub severity: AlertSeverity,

    /// Alert status
    pub status: AlertStatus,

    /// Alert title/summary
    pub title: String,

    /// Detailed alert description
    pub description: String,

    /// Process information
    pub process: ProcessInfo,

    /// File information
    pub file: FileInfo,

    /// YARA match information
    pub yara_matches: Vec<YaraMatchInfo>,

    /// System information
    pub system: SystemInfo,

    /// Additional metadata
    pub metadata: HashMap<String, String>,

    /// Alert source (e.g., "file_monitor", "periodic_scan")
    pub source: String,

    /// Detection confidence score (0.0 to 1.0)
    pub confidence: f32,

    /// Recommended actions
    pub recommended_actions: Vec<String>,
}

/// Alert generation statistics
#[derive(Debug, Clone, Default)]
pub struct AlertStats {
    pub total_alerts: u64,
    pub alerts_by_severity: HashMap<AlertSeverity, u64>,
    pub alerts_by_status: HashMap<AlertStatus, u64>,
    pub alerts_sent: u64,
    pub alerts_failed: u64,
    pub average_generation_time_ms: f64,
}

/// Alert generator and manager
#[derive(Debug, Clone)]
pub struct AlertManager {
    #[cfg(feature = "yara")]
    alert_sender: mpsc::UnboundedSender<Alert>,
    statistics: Arc<RwLock<AlertStats>>,
    #[cfg(feature = "yara")]
    system_info: SystemInfo,
}

impl AlertManager {
    /// Create a new alert manager
    pub fn new() -> (Self, mpsc::UnboundedReceiver<Alert>) {
        let (_alert_tx, alert_rx) = mpsc::unbounded_channel();

        #[cfg(feature = "yara")]
        let alert_tx = _alert_tx;

        #[cfg(feature = "yara")]
        let system_info = SystemInfo {
            hostname: Self::get_hostname(),
            os_version: Self::get_os_version(),
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            cpu_usage: None,
            memory_usage: None,
            disk_usage: None,
        };

        let manager = Self {
            #[cfg(feature = "yara")]
            alert_sender: alert_tx,
            statistics: Arc::new(RwLock::new(AlertStats::default())),
            #[cfg(feature = "yara")]
            system_info,
        };

        (manager, alert_rx)
    }

    /// Generate an alert from a YARA scan result and file system event
    #[cfg(feature = "yara")]
    pub async fn generate_alert(
        &self,
        scan_result: &ScanResult,
        fs_event: &FileSystemEvent,
        source: &str,
    ) -> Result<Alert> {
        let start_time = std::time::Instant::now();

        // Generate unique alert ID
        let alert_id = Uuid::new_v4().to_string();

        // Get current timestamp
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("Failed to get current timestamp")?
            .as_millis() as u64;

        // Determine severity based on YARA matches
        let severity = self.determine_severity(&scan_result.matches);

        // Get process information
        let process = self.get_process_info(fs_event).await;

        // Get file information
        let file = self.get_file_info(&fs_event.file_path).await?;

        // Convert YARA matches
        let yara_matches = self.convert_yara_matches(&scan_result.matches);

        // Generate title and description
        let (title, description) = self.generate_alert_content(&yara_matches, &file);

        // Calculate confidence score
        let confidence = self.calculate_confidence(&scan_result.matches);

        // Generate recommended actions
        let recommended_actions = self.generate_recommended_actions(&severity, &yara_matches);

        // Create metadata
        let mut metadata = HashMap::new();
        metadata.insert(
            "scan_duration_ms".to_string(),
            scan_result.duration.as_millis().to_string(),
        );
        metadata.insert(
            "file_size_bytes".to_string(),
            scan_result.file_size.to_string(),
        );
        metadata.insert(
            "matches_count".to_string(),
            scan_result.matches.len().to_string(),
        );

        let alert = Alert {
            id: alert_id,
            timestamp,
            severity: severity.clone(),
            status: AlertStatus::New,
            title,
            description,
            process,
            file,
            yara_matches,
            system: self.system_info.clone(),
            metadata,
            source: source.to_string(),
            confidence,
            recommended_actions,
        };

        // Send alert
        self.alert_sender
            .send(alert.clone())
            .context("Failed to send alert")?;

        // Update statistics
        self.update_statistics(&alert, start_time.elapsed()).await;

        Ok(alert)
    }

    /// Determine alert severity based on YARA matches
    #[cfg(feature = "yara")]
    fn determine_severity(&self, matches: &[YaraMatch]) -> AlertSeverity {
        let mut max_severity = AlertSeverity::Low;

        for rule_match in matches {
            for tag in &rule_match.tags {
                match tag.to_lowercase().as_str() {
                    "critical" | "high" => {
                        if matches!(max_severity, AlertSeverity::Low | AlertSeverity::Medium) {
                            max_severity = AlertSeverity::High;
                        }
                    }
                    "ransomware" | "trojan" | "backdoor" => {
                        max_severity = AlertSeverity::Critical;
                        break;
                    }
                    _ => {}
                }
            }

            // Check metadata for severity indicators
            for (key, value) in &rule_match.metadata {
                match key.to_lowercase().as_str() {
                    "severity" => match value.to_lowercase().as_str() {
                        "critical" => max_severity = AlertSeverity::Critical,
                        "high" => {
                            if matches!(max_severity, AlertSeverity::Low | AlertSeverity::Medium) {
                                max_severity = AlertSeverity::High;
                            }
                        }
                        _ => {}
                    },
                    _ => {}
                }
            }
        }

        max_severity
    }

    /// Get process information from filesystem event
    #[cfg(feature = "yara")]
    async fn get_process_info(&self, fs_event: &FileSystemEvent) -> ProcessInfo {
        // TODO: Implement actual process information retrieval
        // For now, use placeholder data from the event
        ProcessInfo {
            pid: fs_event.process_id.unwrap_or(0),
            name: fs_event
                .process_name
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
            executable_path: None,
            command_line: None,
            parent_pid: None,
            user: None,
            start_time: None,
        }
    }

    /// Get file information
    #[cfg(feature = "yara")]
    async fn get_file_info(&self, file_path: &PathBuf) -> Result<FileInfo> {
        let path_str = file_path.to_string_lossy().to_string();

        // Get file metadata if file exists
        let (size, created_time, modified_time, accessed_time) = if file_path.exists() {
            match std::fs::metadata(file_path) {
                Ok(metadata) => {
                    let size = Some(metadata.len());
                    let created = metadata
                        .created()
                        .ok()
                        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                        .map(|d| d.as_secs());
                    let modified = metadata
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                        .map(|d| d.as_secs());
                    let accessed = metadata
                        .accessed()
                        .ok()
                        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                        .map(|d| d.as_secs());
                    (size, created, modified, accessed)
                }
                Err(_) => (None, None, None, None),
            }
        } else {
            (None, None, None, None)
        };

        // Determine file type from extension
        let file_type = file_path
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.to_lowercase());

        Ok(FileInfo {
            path: path_str,
            size,
            hash_md5: None, // TODO: Calculate file hashes
            hash_sha1: None,
            hash_sha256: None,
            created_time,
            modified_time,
            accessed_time,
            file_type,
        })
    }

    /// Convert YARA matches to alert format
    #[cfg(feature = "yara")]
    fn convert_yara_matches(&self, matches: &[YaraMatch]) -> Vec<YaraMatchInfo> {
        matches
            .iter()
            .map(|rule_match| YaraMatchInfo {
                rule_name: rule_match.rule_name.clone(),
                rule_namespace: rule_match.namespace.clone(),
                rule_tags: rule_match.tags.clone(),
                rule_metadata: rule_match.metadata.clone(),
                match_count: rule_match.strings.len() as u32,
                match_strings: rule_match
                    .strings
                    .iter()
                    .map(|s| s.identifier.clone())
                    .collect(),
                match_offsets: rule_match.strings.iter().map(|s| s.offset).collect(),
            })
            .collect()
    }

    /// Generate alert title and description
    #[cfg(feature = "yara")]
    fn generate_alert_content(
        &self,
        yara_matches: &[YaraMatchInfo],
        file: &FileInfo,
    ) -> (String, String) {
        let rule_names: Vec<&str> = yara_matches.iter().map(|m| m.rule_name.as_str()).collect();

        let title = if rule_names.len() == 1 {
            format!("YARA Detection: {} in {}", rule_names[0], file.path)
        } else {
            format!(
                "YARA Detection: {} rules matched in {}",
                rule_names.len(),
                file.path
            )
        };

        let description = format!(
            "Suspicious file detected by YARA engine. File: {} ({}). Matched rules: {}. \
            This file exhibits behavior patterns consistent with malicious software.",
            file.path,
            file.size
                .map(|s| format!("{} bytes", s))
                .unwrap_or_else(|| "unknown size".to_string()),
            rule_names.join(", ")
        );

        (title, description)
    }

    /// Calculate confidence score based on matches
    #[cfg(feature = "yara")]
    fn calculate_confidence(&self, matches: &[YaraMatch]) -> f32 {
        if matches.is_empty() {
            return 0.0;
        }

        let mut total_confidence = 0.0;
        let mut weight_sum = 0.0;

        for rule_match in matches {
            let mut rule_confidence = 0.5; // Base confidence
            let weight = 1.0;

            // Increase confidence based on rule tags
            for tag in &rule_match.tags {
                match tag.to_lowercase().as_str() {
                    "high_confidence" | "verified" => rule_confidence += 0.3,
                    "medium_confidence" => rule_confidence += 0.2,
                    "experimental" | "low_confidence" => rule_confidence -= 0.2,
                    _ => {}
                }
            }

            // Increase confidence based on number of string matches
            let string_bonus = (rule_match.strings.len() as f32 * 0.1).min(0.3);
            rule_confidence += string_bonus;

            total_confidence += rule_confidence * weight;
            weight_sum += weight;
        }

        let result: f32 = total_confidence / weight_sum;
        result.min(1.0).max(0.0)
    }

    /// Generate recommended actions based on severity and matches
    #[cfg(feature = "yara")]
    fn generate_recommended_actions(
        &self,
        severity: &AlertSeverity,
        matches: &[YaraMatchInfo],
    ) -> Vec<String> {
        let mut actions = Vec::new();

        match severity {
            AlertSeverity::Critical => {
                actions.push("Immediately isolate the affected system".to_string());
                actions.push("Quarantine the suspicious file".to_string());
                actions.push("Terminate associated processes".to_string());
                actions.push("Perform full system scan".to_string());
                actions.push("Contact security team immediately".to_string());
            }
            AlertSeverity::High => {
                actions.push("Quarantine the suspicious file".to_string());
                actions.push("Monitor system for additional suspicious activity".to_string());
                actions.push("Perform targeted scan of related directories".to_string());
                actions.push("Review process activity".to_string());
            }
            AlertSeverity::Medium => {
                actions.push("Monitor the file for changes".to_string());
                actions.push("Perform additional analysis".to_string());
                actions.push("Review file origin and purpose".to_string());
            }
            AlertSeverity::Low => {
                actions.push("Log the detection for analysis".to_string());
                actions.push("Monitor for pattern repetition".to_string());
            }
        }

        // Add specific actions based on rule types
        for yara_match in matches {
            for tag in &yara_match.rule_tags {
                match tag.to_lowercase().as_str() {
                    "ransomware" => {
                        actions.push("Check for encrypted files".to_string());
                        actions.push("Verify backup integrity".to_string());
                    }
                    "trojan" | "backdoor" => {
                        actions.push("Check network connections".to_string());
                        actions.push("Monitor outbound traffic".to_string());
                    }
                    "packer" | "obfuscated" => {
                        actions.push("Perform static analysis".to_string());
                        actions.push("Submit to sandbox for dynamic analysis".to_string());
                    }
                    _ => {}
                }
            }
        }

        actions.sort();
        actions.dedup();
        actions
    }

    /// Update alert statistics
    #[cfg(feature = "yara")]
    async fn update_statistics(&self, alert: &Alert, generation_time: std::time::Duration) {
        let mut stats = self.statistics.write().await;

        stats.total_alerts += 1;
        *stats
            .alerts_by_severity
            .entry(alert.severity.clone())
            .or_insert(0) += 1;
        *stats
            .alerts_by_status
            .entry(alert.status.clone())
            .or_insert(0) += 1;

        // Update average generation time
        let new_time_ms = generation_time.as_millis() as f64;
        if stats.total_alerts == 1 {
            stats.average_generation_time_ms = new_time_ms;
        } else {
            stats.average_generation_time_ms =
                (stats.average_generation_time_ms * (stats.total_alerts - 1) as f64 + new_time_ms)
                    / stats.total_alerts as f64;
        }
    }

    /// Get current alert statistics
    pub async fn get_statistics(&self) -> AlertStats {
        let stats = self.statistics.read().await;
        stats.clone()
    }

    /// Reset alert statistics
    pub async fn reset_statistics(&self) {
        let mut stats = self.statistics.write().await;
        *stats = AlertStats::default();
    }

    /// Get hostname
    #[cfg(feature = "yara")]
    fn get_hostname() -> String {
        std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "unknown".to_string())
    }

    /// Get OS version
    #[cfg(feature = "yara")]
    fn get_os_version() -> String {
        format!("{} {}", std::env::consts::OS, std::env::consts::ARCH)
    }
}

/// Serialize alert to JSON string
pub fn serialize_alert(alert: &Alert) -> Result<String> {
    serde_json::to_string_pretty(alert).context("Failed to serialize alert to JSON")
}

/// Deserialize alert from JSON string
pub fn deserialize_alert(json: &str) -> Result<Alert> {
    serde_json::from_str(json).context("Failed to deserialize alert from JSON")
}

/// Create a new alert manager instance
pub fn create_alert_manager() -> (AlertManager, mpsc::UnboundedReceiver<Alert>) {
    AlertManager::new()
}
