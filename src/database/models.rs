//! Database models for production metrics and validation tracking

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Detection scan record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionScan {
    pub scan_id: String,
    pub target_path: String,
    pub scan_type: String, // BEHAVIORAL, MEMORY, NETWORK, YARA, COMPREHENSIVE
    pub status: String,    // QUEUED, RUNNING, COMPLETED, FAILED, TIMEOUT
    pub priority: String,  // HIGH, MEDIUM, LOW
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub duration_ms: Option<i64>,
    pub cpu_usage_percent: Option<f64>,
    pub memory_usage_mb: Option<i64>,
    pub files_scanned: Option<i64>,
}

impl DetectionScan {
    pub fn new(target_path: String, scan_type: String) -> Self {
        Self {
            scan_id: Uuid::new_v4().to_string(),
            target_path,
            scan_type,
            status: "QUEUED".to_string(),
            priority: "MEDIUM".to_string(),
            created_at: Utc::now(),
            completed_at: None,
            duration_ms: None,
            cpu_usage_percent: None,
            memory_usage_mb: None,
            files_scanned: None,
        }
    }
}

/// Detection result record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionResult {
    pub result_id: String,
    pub scan_id: String,
    pub threat_family_id: String,
    pub confidence_score: f64,
    pub detection_engine: String,
    pub indicators: Vec<String>,
    pub recommended_actions: Vec<String>,
    pub created_at: DateTime<Utc>,
}

/// Malware sample metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalwareSample {
    pub sample_id: String,
    pub sha256_hash: String,
    pub family_name: String,
    pub file_size: i64,
    pub file_path: String,
    pub threat_level: String,      // LOW, MEDIUM, HIGH, CRITICAL
    pub validation_status: String, // PENDING, VALIDATED, FAILED
    pub added_at: DateTime<Utc>,
    pub last_validated: Option<DateTime<Utc>>,
}

impl MalwareSample {
    pub fn new(
        sha256_hash: String,
        family_name: String,
        file_path: String,
        file_size: i64,
        threat_level: String,
    ) -> Self {
        Self {
            sample_id: Uuid::new_v4().to_string(),
            sha256_hash,
            family_name,
            file_size,
            file_path,
            threat_level,
            validation_status: "PENDING".to_string(),
            added_at: Utc::now(),
            last_validated: None,
        }
    }
}

/// Validation run record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationRun {
    pub validation_id: String,
    pub sample_id: String,
    pub scan_id: String,
    pub mttd_seconds: Option<f64>,
    pub accuracy_score: Option<f64>,
    pub detected: bool,
    pub false_positive: bool,
    pub isolation_config: Option<String>, // JSON
    pub run_at: DateTime<Utc>,
}

impl ValidationRun {
    pub fn new(sample_id: String, scan_id: String, detected: bool) -> Self {
        Self {
            validation_id: Uuid::new_v4().to_string(),
            sample_id,
            scan_id,
            mttd_seconds: None,
            accuracy_score: None,
            detected,
            false_positive: false,
            isolation_config: None,
            run_at: Utc::now(),
        }
    }
}

/// System metrics record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMetrics {
    pub metric_id: String,
    pub cpu_usage_percent: f64,
    pub memory_usage_mb: i64,
    pub disk_io_mbps: f64,
    pub network_io_mbps: f64,
    pub active_scans: i64,
    pub queue_depth: i64,
    pub recorded_at: DateTime<Utc>,
}

impl SystemMetrics {
    pub fn new(
        cpu_usage: f64,
        memory_mb: i64,
        disk_io: f64,
        network_io: f64,
        active_scans: i64,
        queue_depth: i64,
    ) -> Self {
        Self {
            metric_id: Uuid::new_v4().to_string(),
            cpu_usage_percent: cpu_usage,
            memory_usage_mb: memory_mb,
            disk_io_mbps: disk_io,
            network_io_mbps: network_io,
            active_scans,
            queue_depth,
            recorded_at: Utc::now(),
        }
    }
}

/// Performance gate configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceGate {
    pub gate_id: String,
    pub metric_type: String, // CPU, MEMORY, DISK_IO, NETWORK_IO, MTTD, FP_RATE
    pub threshold_value: f64,
    pub enforcement_action: String, // ALERT, THROTTLE, BLOCK, DEGRADE
    pub enabled: bool,
}

/// Validation statistics summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationStats {
    pub total_runs: i64,
    pub detection_rate: f64,
    pub false_positive_rate: f64,
    pub avg_mttd: f64,
    pub avg_accuracy: f64,
}

impl ValidationStats {
    /// Check if validation stats meet production KPIs
    pub fn meets_production_kpis(&self) -> bool {
        self.detection_rate >= 0.995 &&  // ≥ 99.5%
        self.false_positive_rate < 0.001 && // < 0.1%
        self.avg_mttd < 60.0 // < 60 seconds
    }

    /// Get KPI compliance report
    pub fn get_kpi_report(&self) -> KpiReport {
        KpiReport {
            detection_rate_compliant: self.detection_rate >= 0.995,
            false_positive_rate_compliant: self.false_positive_rate < 0.001,
            mttd_compliant: self.avg_mttd < 60.0,
            overall_compliant: self.meets_production_kpis(),
        }
    }
}

/// KPI compliance report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KpiReport {
    pub detection_rate_compliant: bool,
    pub false_positive_rate_compliant: bool,
    pub mttd_compliant: bool,
    pub overall_compliant: bool,
}

/// Threat family definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatFamily {
    pub family_id: String,
    pub family_name: String,
    pub description: String,
    pub mitigation_strategies: Vec<String>,
}

/// YARA rule metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraRule {
    pub rule_id: String,
    pub rule_name: String,
    pub family_id: String,
    pub rule_content: String,
    pub version: String,
    pub compiled_at: DateTime<Utc>,
    pub enabled: bool,
    pub performance_score: Option<f64>,
    pub accuracy_score: Option<f64>,
}

/// Isolation configuration for malware analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolationConfig {
    pub network_isolation: bool,
    pub filesystem_isolation: bool,
    pub registry_isolation: bool,
    pub process_isolation: bool,
    pub timeout_seconds: u64,
    pub resource_limits: ResourceLimits,
    pub max_concurrent_sessions: usize,
    pub max_memory_per_session_mb: u64,
    pub max_cpu_per_session_percent: f64,
    pub sandbox_directory: String,
}

impl Default for IsolationConfig {
    fn default() -> Self {
        Self {
            network_isolation: true,
            filesystem_isolation: true,
            registry_isolation: true,
            process_isolation: true,
            timeout_seconds: 300, // 5 minutes
            resource_limits: ResourceLimits::default(),
            max_concurrent_sessions: 5,
            max_memory_per_session_mb: 512,
            max_cpu_per_session_percent: 80.0,
            sandbox_directory: "./isolation_workspace".to_string(),
        }
    }
}

/// Resource limits for isolated execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub max_cpu_percent: f64,
    pub max_memory_mb: i64,
    pub max_disk_io_mbps: f64,
    pub max_network_io_mbps: f64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_cpu_percent: 10.0,
            max_memory_mb: 100,
            max_disk_io_mbps: 5.0,
            max_network_io_mbps: 1.0,
        }
    }
}
