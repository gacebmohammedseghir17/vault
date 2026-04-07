//! Core types and data structures for the Enhanced ERDPS Agent

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::SystemTime;
use uuid::Uuid;
// Removed unused imports: AlertConfig, EscalationConfig

// ML imports removed for production

/// Unique identifier for threats
pub type ThreatId = Uuid;

/// Unique identifier for agents
pub type AgentId = Uuid;

/// Unique identifier for quarantine entries
pub type QuarantineId = Uuid;

/// Detection confidence score (0.0 to 1.0)
pub type ConfidenceScore = f64;

/// Threat severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub enum ThreatSeverity {
    Low,
    #[default]
    Medium,
    High,
    Critical,
}

/// Detection methods used by various engines
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectionMethod {
    Signature(String),
    Behavioral(String),
    MachineLearning(String),
    Heuristic(String),
    Network(String),
    Hybrid(Vec<DetectionMethod>),
}

/// Threat types that can be detected
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThreatType {
    Ransomware,
    Cryptominer,
    Trojan,
    Worm,
    Rootkit,
    Spyware,
    Adware,
    Backdoor,
    Botnet,
    Virus,
    Unknown,
    SystemModification,
    FileEncryption,
    ProcessInjection,
    NetworkIntrusion,
    DataExfiltration,
}

/// Threat classification
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatClassification {
    Malicious,
    Suspicious,
    Benign,
    Unknown,
}

/// Metadata associated with a quarantined file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineMetadata {
    pub detection_engine: String,
    pub detection_rule: Option<String>,
    pub confidence_score: f64,
    pub threat_classification: ThreatClassification,
    pub threat_type: ThreatType,
    pub severity: ThreatSeverity,
    pub original_path: PathBuf,
    pub timestamp: DateTime<Utc>,
}


/// Digital signature information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigitalSignature {
    pub signer: String,
    pub issuer: String,
    pub serial_number: String,
    pub algorithm: String,
    pub valid_from: DateTime<Utc>,
    pub valid_to: DateTime<Utc>,
    pub is_valid: bool,
}

/// Indicator of Compromise match
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocMatch {
    pub ioc_type: String,
    pub value: String,
    pub confidence: f64,
    pub source: String,
}

/// Encryption key for quarantine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionKey {
    pub key: Vec<u8>,
    pub algorithm: String,
    pub key_id: String,
}

/// Process context for quarantine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessContext {
    pub pid: u32,
    pub name: String,
    pub user: String,
    pub command_line: String,
    pub start_time: DateTime<Utc>,
}

/// Network context for quarantine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkContext {
    pub connections: Vec<NetworkPattern>,
    pub dns_requests: Vec<String>,
}

/// Machine Learning features
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlFeatures {
    pub vector: Vec<f64>,
    pub model_version: String,
    pub classification: String,
    pub confidence: f64,
}

/// File metadata (size, timestamps, permissions)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    pub size: u64,
    pub creation_time: SystemTime,
    pub modification_time: SystemTime,
    pub access_time: SystemTime,
    pub permissions: u32,
    pub owner: Option<String>,
    pub group: Option<String>,
    pub extended_attributes: HashMap<String, String>,
    pub alternate_data_streams: Vec<AlternateDataStream>,
}

/// File attributes
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileAttributes {
    pub readonly: bool,
    pub hidden: bool,
    pub system: bool,
    pub directory: bool,
    pub archive: bool,
    pub device: bool,
    pub normal: bool,
    pub temporary: bool,
    pub sparse_file: bool,
    pub reparse_point: bool,
    pub compressed: bool,
    pub offline: bool,
    pub not_content_indexed: bool,
    pub encrypted: bool,
}

impl Default for FileAttributes {
    fn default() -> Self {
        Self {
            readonly: false,
            hidden: false,
            system: false,
            directory: false,
            archive: false,
            device: false,
            normal: true,
            temporary: false,
            sparse_file: false,
            reparse_point: false,
            compressed: false,
            offline: false,
            not_content_indexed: false,
            encrypted: false,
        }
    }
}

/// Alternate Data Stream information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlternateDataStream {
    pub name: String,
    pub size: u64,
    pub hash: String,
}

/// File permissions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilePermissions {
    pub owner: String,
    pub group: String,
    pub mode: u32,
    pub acls: Vec<String>,
}

/// Delta information for incremental backups
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaInfo {
    pub base_snapshot_id: String,
    pub patch_file: String,
    pub original_size: u64,
    pub patch_size: u64,
}

/// Actions that can be taken in response to threats
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResponseAction {
    Block,
    Quarantine,
    Terminate,
    Alert,
    Rollback,
    Isolate,
    Monitor,
    QuarantineFile,
    TerminateProcess,
    BlockNetwork,
    SystemModification,
    LogOnly,
    ProtectFiles,
}

/// Detection result from any detection engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionResult {
    pub threat_id: ThreatId,
    pub threat_type: ThreatType,
    pub severity: ThreatSeverity,
    pub confidence: ConfidenceScore,
    pub detection_method: DetectionMethod,
    pub file_path: Option<PathBuf>,
    pub process_info: Option<ProcessInfo>,
    pub network_info: Option<NetworkInfo>,
    pub metadata: HashMap<String, String>,
    pub detected_at: DateTime<Utc>,
    pub recommended_actions: Vec<ResponseAction>,
    pub details: String,
    pub timestamp: DateTime<Utc>,
    pub source: String,
}

/// Process information for behavioral analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub name: String,
    pub command_line: Option<String>,
    pub executable_path: Option<PathBuf>,
    pub user: Option<String>,
    pub start_time: DateTime<Utc>,
    pub cpu_usage: Option<f64>,
    pub memory_usage: Option<u64>,
}

/// Network information for network-based detections
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    pub source_ip: Option<String>,
    pub destination_ip: Option<String>,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub protocol: Option<String>,
    pub domain: Option<String>,
    pub url: Option<String>,
    pub user_agent: Option<String>,
}

/// File operation types for behavioral analysis
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileOperation {
    Create,
    Read,
    Write,
    Delete,
    Rename,
    Move,
    Copy,
    Encrypt,
    Decrypt,
}

/// File operation event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileOperationEvent {
    pub operation: FileOperation,
    pub file_path: PathBuf,
    pub process_info: ProcessInfo,
    pub timestamp: DateTime<Utc>,
    pub file_size: Option<u64>,
    pub file_hash: Option<String>,
    pub entropy: Option<f64>,
}

/// Registry operation types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegistryOperation {
    CreateKey,
    DeleteKey,
    SetValue,
    DeleteValue,
    QueryKey,
    QueryValue,
}

/// Registry operation event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryOperationEvent {
    pub operation: RegistryOperation,
    pub key_path: String,
    pub value_name: Option<String>,
    pub value_data: Option<String>,
    pub process_info: ProcessInfo,
    pub timestamp: DateTime<Utc>,
}

/// API call sequence for heuristic analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiCallSequence {
    pub api_calls: Vec<String>,
    pub process_info: ProcessInfo,
    pub timestamp: DateTime<Utc>,
    pub sequence_hash: String,
}

/// Network pattern for network monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPattern {
    pub pattern_type: String,
    pub source: String,
    pub destination: String,
    pub protocol: String,
    pub payload_hash: Option<String>,
    pub timestamp: DateTime<Utc>,
}

/// Behavioral metrics for analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorMetric {
    pub metric_name: String,
    pub value: f64,
    pub threshold: f64,
    pub is_suspicious: bool,
    pub timestamp: DateTime<Utc>,
}

use crate::prevention::quarantine::RestorationInfo;

/// Quarantine entry information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    pub quarantine_id: QuarantineId,
    pub threat_id: ThreatId,
    pub threat_type: ThreatType,
    pub severity: ThreatSeverity,
    pub original_path: PathBuf,
    pub quarantine_path: PathBuf,
    pub file_hash: String,
    pub file_size: u64,
    pub quarantined_at: DateTime<Utc>,
    pub metadata: HashMap<String, String>,
    pub restore_info: Option<RestoreInfo>,
    pub restoration_info: Option<RestorationInfo>,
}

/// Information needed to restore a quarantined file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreInfo {
    pub original_permissions: u32,
    pub original_owner: Option<String>,
    pub original_timestamps: FileTimestamps,
    pub backup_location: Option<PathBuf>,
}

/// File timestamp information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileTimestamps {
    pub created: Option<DateTime<Utc>>,
    pub modified: Option<DateTime<Utc>>,
    pub accessed: Option<DateTime<Utc>>,
}

/// Agent status information
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentStatus {
    Starting,
    Running,
    Paused,
    Stopping,
    Stopped,
    Error(String),
}

/// Agent health information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentHealth {
    pub status: AgentStatus,
    pub uptime: std::time::Duration,
    pub cpu_usage: f64,
    pub memory_usage: u64,
    pub disk_usage: u64,
    pub active_scans: u32,
    pub threats_detected: u64,
    pub last_update: DateTime<Utc>,
}

/// Scan context for detection engines
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanContext {
    pub scan_id: Uuid,
    pub priority: ScanPriority,
    pub timeout: Option<std::time::Duration>,
    pub max_file_size: Option<u64>,
    pub include_archives: bool,
    pub deep_scan: bool,
    pub metadata: HashMap<String, String>,
}

/// Scan priority levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ScanPriority {
    Low,
    #[default]
    Normal,
    High,
    Critical,
}

/// Machine learning analysis result
// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct MLAnalysisResult {
//     pub threat_probability: f64,
//     pub threat_type: Option<ThreatType>,
//     pub confidence: ConfidenceScore,
//     pub features_used: Vec<String>,
//     pub model_version: String,
//     pub analysis_timestamp: DateTime<Utc>,
// } // Commented out - ML engine not implemented

/// Machine learning features for threat detection
// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct MLFeatures {
//     // Static analysis features
//     pub file_entropy: f64,
//     pub file_size: u64,
//     pub file_extension: Option<String>,
//     pub pe_characteristics: Option<PEFeatures>,
//     pub string_features: StringFeatures,
//     pub import_features: ImportFeatures,
//     #[cfg(feature = "ml-engine")]
//     pub entropy_features: Option<EntropyFeatures>,
//
//     // Dynamic analysis features
//     pub api_call_patterns: Vec<ApiCallSequence>,
//     pub file_operations: Vec<FileOperationEvent>,
//     pub network_patterns: Vec<NetworkPattern>,
//     pub registry_operations: Vec<RegistryOperationEvent>,
//
//     // Behavioral features
//     pub behavior_metrics: Vec<BehaviorMetric>,
// } // Commented out - ML engine not implemented

// impl Default for MLFeatures {
//     fn default() -> Self {
//         Self {
//             file_entropy: 0.0,
//             file_size: 0,
//             file_extension: None,
//             pe_characteristics: None,
//             string_features: StringFeatures {
//                 total_strings: 0,
//                 printable_strings: 0,
//                 suspicious_strings: Vec::new(),
//                 entropy_of_strings: 0.0,
//                 average_string_length: 0.0,
//             },
//             import_features: ImportFeatures {
//                 imported_dlls: Vec::new(),
//                 imported_functions: Vec::new(),
//                 suspicious_imports: Vec::new(),
//                 import_entropy: 0.0,
//             },
//             #[cfg(feature = "ml-engine")]
//             entropy_features: Some(EntropyFeatures {
//                 overall_entropy: 0.0,
//                 section_entropies: Vec::new(),
//                 entropy_variance: 0.0,
//                 high_entropy_sections: 0,
//                 entropy_distribution: Vec::new(),
//             }),
//             api_call_patterns: Vec::new(),
//             file_operations: Vec::new(),
//             network_patterns: Vec::new(),
//             registry_operations: Vec::new(),
//             behavior_metrics: Vec::new(),
//         }
//     }
// } // Commented out - ML engine not implemented

/// PE (Portable Executable) file characteristics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PEFeatures {
    pub machine_type: u16,
    pub number_of_sections: u16,
    pub timestamp: u32,
    pub characteristics: u16,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub entry_point: u32,
    pub image_base: u64,
}

/// String-based features extracted from files
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StringFeatures {
    pub total_strings: u32,
    pub printable_strings: u32,
    pub suspicious_strings: Vec<String>,
    pub entropy_of_strings: f64,
    pub average_string_length: f64,
}

/// Import table features from PE files
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ImportFeatures {
    pub imported_dlls: Vec<String>,
    pub imported_functions: Vec<String>,
    pub suspicious_imports: Vec<String>,
    pub import_entropy: f64,
}

/// Threat intelligence indicator of compromise
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IOC {
    pub ioc_type: IOCType,
    pub value: String,
    pub source: String,
    pub confidence: ConfidenceScore,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub tags: Vec<String>,
    pub metadata: HashMap<String, String>,
}

/// Types of indicators of compromise
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IOCType {
    FileHash,
    IPAddress,
    Domain,
    URL,
    Email,
    Mutex,
    Registry,
    Certificate,
    UserAgent,
}

/// Behavioral metrics for the behavioral analysis engine
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BehavioralMetrics {
    pub file_operations_per_second: f64,
    pub registry_operations_per_second: f64,
    pub process_creations_per_second: f64,
    pub network_connections_per_second: f64,
    pub entropy_changes_detected: u64,
    pub suspicious_api_calls: u64,
    pub file_encryption_attempts: u64,
    pub system_modifications: u64,
}

/// Pattern types for behavioral analysis
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PatternType {
    FileEncryption,
    MassFileModification,
    RegistryModification,
    ProcessInjection,
    NetworkCommunication,
    SystemModification,
    ApiSequence,
}

/// Pattern condition for behavioral analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternCondition {
    pub condition_type: String,
    pub operator: String,
    pub value: String,
    pub weight: f64,
}

/// Pattern match result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternMatch {
    pub pattern_id: String,
    pub confidence: f64,
    pub matched_conditions: Vec<String>,
    pub timestamp: DateTime<Utc>,
}

/// Behavioral event for correlation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralEvent {
    pub event_id: Uuid,
    pub event_type: String,
    pub process_info: Option<ProcessInfo>,
    pub file_path: Option<PathBuf>,
    pub registry_key: Option<String>,
    pub network_info: Option<NetworkInfo>,
    pub timestamp: DateTime<Utc>,
    pub metadata: HashMap<String, String>,
}

/// Correlation rule for event correlation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationRule {
    pub rule_id: String,
    pub name: String,
    pub description: String,
    pub event_types: Vec<String>,
    pub time_window: std::time::Duration,
    pub minimum_events: usize,
    pub confidence_threshold: f64,
}

/// Correlation context for tracking related events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationContext {
    pub context_id: String,
    pub rule_id: String,
    pub events: Vec<BehavioralEvent>,
    pub start_time: DateTime<Utc>,
    pub last_update: DateTime<Utc>,
    pub confidence: f64,
}

/// Suspicious pattern detected by behavioral analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousPattern {
    pub pattern_type: PatternType,
    pub first_occurrence: std::time::SystemTime,
    pub last_occurrence: std::time::SystemTime,
    pub occurrence_count: u32,
    pub severity_score: f64,
    pub associated_processes: std::collections::HashSet<u32>,
    pub metadata: HashMap<String, String>,
}

impl std::fmt::Display for ThreatSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ThreatSeverity::Low => write!(f, "Low"),
            ThreatSeverity::Medium => write!(f, "Medium"),
            ThreatSeverity::High => write!(f, "High"),
            ThreatSeverity::Critical => write!(f, "Critical"),
        }
    }
}

impl std::fmt::Display for ThreatType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ThreatType::Ransomware => write!(f, "Ransomware"),
            ThreatType::Cryptominer => write!(f, "Cryptominer"),
            ThreatType::Trojan => write!(f, "Trojan"),
            ThreatType::Worm => write!(f, "Worm"),
            ThreatType::Rootkit => write!(f, "Rootkit"),
            ThreatType::Spyware => write!(f, "Spyware"),
            ThreatType::Adware => write!(f, "Adware"),
            ThreatType::Backdoor => write!(f, "Backdoor"),
            ThreatType::Botnet => write!(f, "Botnet"),
            ThreatType::Virus => write!(f, "Virus"),
            ThreatType::Unknown => write!(f, "Unknown"),
            ThreatType::SystemModification => write!(f, "System Modification"),
            ThreatType::FileEncryption => write!(f, "File Encryption"),
            ThreatType::ProcessInjection => write!(f, "Process Injection"),
            ThreatType::NetworkIntrusion => write!(f, "Network Intrusion"),
            ThreatType::DataExfiltration => write!(f, "Data Exfiltration"),
        }
    }
}
