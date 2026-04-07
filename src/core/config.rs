//! Configuration management for the Enhanced ERDPS Agent

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

/// Main configuration structure for the Enhanced ERDPS Agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedAgentConfig {
    /// Agent identification and basic settings
    pub agent: AgentConfig,

    /// Detection engines configuration
    pub detection: DetectionConfig,

    /// Prevention engines configuration
    pub prevention: PreventionConfig,

    /// Quarantine system configuration
    pub quarantine: QuarantineConfig,

    /// Rollback engine configuration
    pub rollback: RollbackConfig,

    /// Threat intelligence configuration
    pub threat_intelligence: ThreatIntelligenceConfig,

    /// Multi-agent coordination configuration
    pub coordination: CoordinationConfig,

    /// Telemetry and monitoring configuration
    pub telemetry: TelemetryConfig,

    /// Windows service configuration
    pub windows_service: WindowsServiceConfig,

    /// Security hardening configuration
    pub security: SecurityConfig,

    /// Performance tuning configuration
    pub performance: PerformanceConfig,

    /// Behavioral analysis configuration with thresholds
    #[serde(default)]
    pub behavioral_analysis: BehavioralAnalysisConfig,

    /// Machine learning configuration with model settings
    // pub machine_learning: MachineLearningConfig, // Commented out - ML engine not implemented

    /// Automated response configuration with action policies
    #[serde(default)]
    pub automated_response: AutomatedResponseConfig,

    /// Enterprise validation configuration for real-world testing
    #[serde(default)]
    pub enterprise_validation: EnterpriseValidationConfig,
}

/// Basic agent configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub agent_id: Option<String>,
    pub name: String,
    pub version: String,
    pub log_level: String,
    pub log_file: Option<PathBuf>,
    pub config_file: PathBuf,
    pub data_directory: PathBuf,
    pub temp_directory: PathBuf,
    pub update_interval: Duration,
    pub heartbeat_interval: Duration,
}

/// Detection engines configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionConfig {
    pub signature: SignatureEngineConfig,
    pub behavioral: BehavioralEngineConfig,
    pub heuristic: HeuristicEngineConfig,
    #[cfg(feature = "network-monitoring")]
    pub network: NetworkEngineConfig,
    pub enabled_engines: Vec<String>,
    pub scan_timeout: Duration,
    pub max_concurrent_scans: usize,
}

/// YARA-X signature engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureEngineConfig {
    pub enabled: bool,
    pub rules_directory: PathBuf,
    pub compiled_rules_cache: PathBuf,
    pub rule_sources: Vec<RuleSource>,
    pub update_interval: Duration,
    pub max_rule_size: usize,
    pub compilation_timeout: Duration,
    pub scan_timeout: Duration,
    pub max_matches: usize,
    pub max_file_size: u64,
    pub parallel_scans: bool,
    pub custom_variables: std::collections::HashMap<String, String>,
}

impl Default for SignatureEngineConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rules_directory: PathBuf::from("rules"),
            compiled_rules_cache: PathBuf::from("compiled_rules"),
            rule_sources: Vec::new(),
            update_interval: Duration::from_secs(3600), // 1 hour
            max_rule_size: 10 * 1024 * 1024,            // 10MB
            compilation_timeout: Duration::from_secs(60),
            scan_timeout: Duration::from_secs(30),
            max_matches: 1000,
            max_file_size: 100 * 1024 * 1024, // 100MB
            parallel_scans: true,
            custom_variables: std::collections::HashMap::new(),
        }
    }
}

/// Rule source configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSource {
    pub name: String,
    pub source_type: RuleSourceType,
    pub url: Option<String>,
    pub path: Option<PathBuf>,
    pub api_key: Option<String>,
    pub update_interval: Duration,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleSourceType {
    Local,
    Http,
    Git,
    Api,
}

/// Behavioral analysis engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralEngineConfig {
    pub enabled: bool,
    pub process_monitoring: ProcessMonitoringConfig,
    pub file_monitoring: FileMonitoringConfig,
    pub registry_monitoring: RegistryMonitoringConfig,
    pub entropy_analysis: EntropyAnalysisConfig,
    pub behavior_database: PathBuf,
    pub analysis_window: Duration,
    pub suspicious_threshold: f64,
    pub max_file_size_for_entropy: u64,
    pub enable_process_monitoring: bool,
    pub monitoring_interval: Duration,
    pub enable_fs_monitoring: bool,
    pub protected_directories: Vec<PathBuf>,
    pub high_entropy_threshold: f64,
}

impl Default for BehavioralEngineConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            process_monitoring: ProcessMonitoringConfig::default(),
            file_monitoring: FileMonitoringConfig::default(),
            registry_monitoring: RegistryMonitoringConfig::default(),
            entropy_analysis: EntropyAnalysisConfig::default(),
            behavior_database: PathBuf::from("behavior.db"),
            analysis_window: Duration::from_secs(300),
            suspicious_threshold: 0.7,
            max_file_size_for_entropy: 50 * 1024 * 1024, // 50MB
            enable_process_monitoring: true,
            monitoring_interval: Duration::from_secs(5),
            enable_fs_monitoring: true,
            protected_directories: vec![
                PathBuf::from("C:\\Users"),
                PathBuf::from("C:\\Documents and Settings"),
                PathBuf::from("C:\\ProgramData"),
            ],
            high_entropy_threshold: 7.5,
        }
    }
}

/// Process monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessMonitoringConfig {
    pub enabled: bool,
    pub monitor_creation: bool,
    pub monitor_termination: bool,
    pub monitor_injection: bool,
    pub monitor_hollowing: bool,
    pub excluded_processes: Vec<String>,
    pub api_hooking: bool,
}

impl Default for ProcessMonitoringConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            monitor_creation: true,
            monitor_termination: true,
            monitor_injection: true,
            monitor_hollowing: true,
            excluded_processes: Vec::new(),
            api_hooking: true,
        }
    }
}

/// File system monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMonitoringConfig {
    pub enabled: bool,
    pub monitored_paths: Vec<PathBuf>,
    pub excluded_paths: Vec<PathBuf>,
    pub monitor_creates: bool,
    pub monitor_writes: bool,
    pub monitor_deletes: bool,
    pub monitor_renames: bool,
    pub rapid_encryption_threshold: usize,
    pub entropy_threshold: f64,
}

impl Default for FileMonitoringConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            monitored_paths: Vec::new(),
            excluded_paths: Vec::new(),
            monitor_creates: true,
            monitor_writes: true,
            monitor_deletes: true,
            monitor_renames: true,
            rapid_encryption_threshold: 100,
            entropy_threshold: 7.5,
        }
    }
}

/// Registry monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryMonitoringConfig {
    pub enabled: bool,
    pub monitored_keys: Vec<String>,
    pub excluded_keys: Vec<String>,
    pub monitor_creates: bool,
    pub monitor_deletes: bool,
    pub monitor_modifications: bool,
}

impl Default for RegistryMonitoringConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            monitored_keys: Vec::new(),
            excluded_keys: Vec::new(),
            monitor_creates: true,
            monitor_deletes: true,
            monitor_modifications: true,
        }
    }
}

/// Entropy analysis configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyAnalysisConfig {
    pub enabled: bool,
    pub chunk_size: usize,
    pub high_entropy_threshold: f64,
    pub low_entropy_threshold: f64,
    pub analysis_depth: usize,
}

impl Default for EntropyAnalysisConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            chunk_size: 1024,
            high_entropy_threshold: 7.5,
            low_entropy_threshold: 3.0,
            analysis_depth: 10,
        }
    }
}

// ML configuration structs removed - ML engine not implemented in production

/// Heuristic analysis engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeuristicEngineConfig {
    pub enabled: bool,
    pub api_sequence_analysis: ApiSequenceConfig,
    pub packer_detection: PackerDetectionConfig,
    pub obfuscation_detection: ObfuscationDetectionConfig,
    pub pattern_database: PathBuf,
    pub suspicious_threshold: f64,
    pub max_file_size: u64,
    pub analysis_timeout: Duration,
    pub packer_detection_enabled: bool,
    pub behavior_analysis_enabled: bool,
    pub code_analysis_enabled: bool,
    pub obfuscation_detection_enabled: bool,
    pub anomaly_detection_enabled: bool,
}

/// API sequence analysis configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiSequenceConfig {
    pub enabled: bool,
    pub sequence_length: usize,
    pub suspicious_patterns: Vec<String>,
    pub api_categories: HashMap<String, Vec<String>>,
}

/// Packer detection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackerDetectionConfig {
    pub enabled: bool,
    pub known_packers: Vec<String>,
    pub entropy_threshold: f64,
    pub section_analysis: bool,
}

/// Obfuscation detection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObfuscationDetectionConfig {
    pub enabled: bool,
    pub string_obfuscation: bool,
    pub control_flow_obfuscation: bool,
    pub anti_debug_detection: bool,
    pub anti_vm_detection: bool,
}

/// Network monitoring engine configuration
#[cfg(feature = "network-monitoring")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEngineConfig {
    pub enabled: bool,
    pub interfaces: Vec<String>,
    pub packet_capture: PacketCaptureConfig,
    pub c2_detection: C2DetectionConfig,
    pub dns_monitoring: DnsMonitoringConfig,
    pub traffic_analysis: TrafficAnalysisConfig,
}

#[cfg(feature = "network-monitoring")]
impl Default for NetworkEngineConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interfaces: vec!["any".to_string()],
            packet_capture: PacketCaptureConfig::default(),
            c2_detection: C2DetectionConfig::default(),
            dns_monitoring: DnsMonitoringConfig::default(),
            traffic_analysis: TrafficAnalysisConfig::default(),
        }
    }
}

impl Default for ApiSequenceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            sequence_length: 10,
            suspicious_patterns: Vec::new(),
            api_categories: HashMap::new(),
        }
    }
}

impl Default for PackerDetectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            known_packers: vec![
                "UPX".to_string(),
                "ASPack".to_string(),
                "PECompact".to_string(),
            ],
            entropy_threshold: 7.0,
            section_analysis: true,
        }
    }
}

impl Default for ObfuscationDetectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            string_obfuscation: true,
            control_flow_obfuscation: true,
            anti_debug_detection: true,
            anti_vm_detection: true,
        }
    }
}

impl Default for HeuristicEngineConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            api_sequence_analysis: ApiSequenceConfig::default(),
            packer_detection: PackerDetectionConfig::default(),
            obfuscation_detection: ObfuscationDetectionConfig::default(),
            pattern_database: PathBuf::from("patterns.db"),
            suspicious_threshold: 0.7,
            max_file_size: 100 * 1024 * 1024,           // 100MB
            analysis_timeout: Duration::from_secs(300), // 5 minutes
            packer_detection_enabled: true,
            behavior_analysis_enabled: true,
            code_analysis_enabled: true,
            obfuscation_detection_enabled: true,
            anomaly_detection_enabled: true,
        }
    }
}

/// Packet capture configuration
#[cfg(feature = "network-monitoring")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketCaptureConfig {
    pub enabled: bool,
    pub buffer_size: usize,
    pub capture_filter: Option<String>,
    pub max_packet_size: usize,
    pub promiscuous_mode: bool,
}

#[cfg(feature = "network-monitoring")]
impl Default for PacketCaptureConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            buffer_size: 65536,
            capture_filter: None,
            max_packet_size: 1500,
            promiscuous_mode: false,
        }
    }
}

/// C2 detection configuration
#[cfg(feature = "network-monitoring")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct C2DetectionConfig {
    pub enabled: bool,
    pub known_c2_domains: Vec<String>,
    pub known_c2_ips: Vec<String>,
    pub beacon_detection: bool,
    pub dga_detection: bool,
    pub suspicious_tls: bool,
}

#[cfg(feature = "network-monitoring")]
impl Default for C2DetectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            known_c2_domains: Vec::new(),
            known_c2_ips: Vec::new(),
            beacon_detection: true,
            dga_detection: true,
            suspicious_tls: true,
        }
    }
}

/// DNS monitoring configuration
#[cfg(feature = "network-monitoring")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsMonitoringConfig {
    pub enabled: bool,
    pub monitor_queries: bool,
    pub monitor_responses: bool,
    pub suspicious_domains: Vec<String>,
    pub dga_threshold: f64,
}

#[cfg(feature = "network-monitoring")]
impl Default for DnsMonitoringConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            monitor_queries: true,
            monitor_responses: true,
            suspicious_domains: Vec::new(),
            dga_threshold: 0.7,
        }
    }
}

/// Traffic analysis configuration
#[cfg(feature = "network-monitoring")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficAnalysisConfig {
    pub enabled: bool,
    pub flow_timeout: Duration,
    pub suspicious_ports: Vec<u16>,
    pub protocol_analysis: bool,
    pub payload_analysis: bool,
}

#[cfg(feature = "network-monitoring")]
impl Default for TrafficAnalysisConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            flow_timeout: Duration::from_secs(300),
            suspicious_ports: vec![22, 23, 135, 139, 445, 1433, 3389],
            protocol_analysis: true,
            payload_analysis: false,
        }
    }
}

/// Prevention engines configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreventionConfig {
    pub active_prevention: ActivePreventionConfig,
    pub response_actions: Vec<String>,
    pub auto_response: bool,
    pub confirmation_required: bool,
}

/// Active prevention configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivePreventionConfig {
    pub enabled: bool,
    pub process_termination: bool,
    pub file_protection: bool,
    pub network_blocking: bool,
    pub registry_protection: bool,
    pub user_notification: bool,
}

/// Quarantine system configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineConfig {
    pub enabled: bool,
    pub quarantine_directory: PathBuf,
    pub encryption_enabled: bool,
    pub compression_enabled: bool,
    pub metadata_preservation: bool,
    pub max_quarantine_size: u64,
    pub retention_period: Duration,
    pub auto_cleanup: bool,
}

/// Rollback engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackConfig {
    pub enabled: bool,
    pub shadow_copy_integration: bool,
    pub backup_directory: PathBuf,
    pub max_backup_size: u64,
    pub backup_retention: Duration,
    pub auto_backup: bool,
    pub backup_interval: Duration,
    pub max_restore_points: usize,
}

/// Threat intelligence configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelligenceConfig {
    pub enabled: bool,
    pub feeds: Vec<ThreatFeedConfig>,
    pub ioc_database: PathBuf,
    pub update_interval: Duration,
    pub attribution_analysis: bool,
    pub confidence_threshold: f64,
}

/// Threat feed configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatFeedConfig {
    pub name: String,
    pub feed_type: ThreatFeedType,
    pub url: Option<String>,
    pub api_key: Option<String>,
    pub update_interval: Duration,
    pub enabled: bool,
    pub weight: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatFeedType {
    Stix,
    Misp,
    OpenIOC,
    Custom,
}

/// Multi-agent coordination configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CoordinationConfig {
    pub enabled: bool,
    pub discovery: DiscoveryConfig,
    pub communication: CommunicationConfig,
    pub load_balancing: LoadBalancingConfig,
    pub consensus: ConsensusConfig,
}

/// Agent discovery configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    pub enabled: bool,
    pub discovery_method: DiscoveryMethod,
    pub multicast_address: Option<String>,
    pub discovery_port: u16,
    pub discovery_interval: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DiscoveryMethod {
    Multicast,
    Broadcast,
    Registry,
    Static,
}

/// Secure communication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommunicationConfig {
    pub encryption_enabled: bool,
    pub certificate_path: Option<PathBuf>,
    pub private_key_path: Option<PathBuf>,
    pub ca_certificate_path: Option<PathBuf>,
    pub communication_port: u16,
    pub timeout: Duration,
}

/// Load balancing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadBalancingConfig {
    pub enabled: bool,
    pub strategy: LoadBalancingStrategy,
    pub health_check_interval: Duration,
    pub max_load_threshold: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LoadBalancingStrategy {
    RoundRobin,
    LeastLoaded,
    Random,
    Weighted,
}

/// Consensus configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusConfig {
    pub enabled: bool,
    pub consensus_threshold: f64,
    pub voting_timeout: Duration,
    pub quorum_size: usize,
}

/// Telemetry and monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryConfig {
    pub enabled: bool,
    pub metrics: MetricsConfig,
    pub tracing: TracingConfig,
    pub health_monitoring: HealthMonitoringConfig,
    pub performance_monitoring: PerformanceMonitoringConfig,
}

/// Path validation configuration for /scan endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathValidationConfig {
    /// Allowed root directories for scanning
    pub allowed_roots: Vec<PathBuf>,
    /// Allowed file extensions (empty means all allowed)
    pub allowed_extensions: Vec<String>,
    /// Maximum file size in bytes for scanning
    pub max_file_size: u64,
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Enable rate limiting
    pub enabled: bool,
    /// Maximum requests per second
    pub requests_per_second: u64,
    /// Request body size limit in bytes (8KB to 32KB)
    pub max_body_size: usize,
}

/// Metrics configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    pub enabled: bool,
    pub prometheus_endpoint: String,
    pub collection_interval: Duration,
    pub retention_period: Duration,
    pub custom_metrics: Vec<String>,
    /// HTTP server bind address (default: 127.0.0.1)
    pub bind_address: String,
    /// HTTP server port
    pub port: u16,
    /// Optional shared secret for /scan endpoint authentication
    pub shared_secret: Option<String>,
    /// Path validation configuration
    pub path_validation: PathValidationConfig,
    /// Rate limiting configuration
    pub rate_limit: RateLimitConfig,
}

/// Tracing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracingConfig {
    pub enabled: bool,
    pub jaeger_endpoint: Option<String>,
    pub sampling_rate: f64,
    pub max_spans: usize,
}

/// Health monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthMonitoringConfig {
    pub enabled: bool,
    pub check_interval: Duration,
    pub cpu_threshold: f64,
    pub memory_threshold: f64,
    pub disk_threshold: f64,
}

/// Performance monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMonitoringConfig {
    pub enabled: bool,
    pub profiling_enabled: bool,
    pub benchmark_interval: Duration,
    pub performance_alerts: bool,
}

/// Windows service configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowsServiceConfig {
    pub service_name: String,
    pub display_name: String,
    pub description: String,
    pub start_type: ServiceStartType,
    pub dependencies: Vec<String>,
    pub recovery_actions: Vec<ServiceRecoveryAction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServiceStartType {
    Auto,
    Manual,
    Disabled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServiceRecoveryAction {
    Restart,
    Reboot,
    RunCommand(String),
    None,
}

/// Security hardening configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub code_signing: CodeSigningConfig,
    pub privilege_separation: PrivilegeSeparationConfig,
    pub tamper_protection: TamperProtectionConfig,
    pub secure_communication: bool,
    pub audit_logging: bool,
}

/// Code signing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeSigningConfig {
    pub enabled: bool,
    pub certificate_path: Option<PathBuf>,
    pub verify_signatures: bool,
    pub trusted_publishers: Vec<String>,
}

/// Privilege separation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivilegeSeparationConfig {
    pub enabled: bool,
    pub service_account: Option<String>,
    pub minimum_privileges: bool,
    pub sandbox_enabled: bool,
}

/// Tamper protection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TamperProtectionConfig {
    pub enabled: bool,
    pub self_protection: bool,
    pub config_protection: bool,
    pub process_protection: bool,
}

/// Performance tuning configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    pub thread_pool_size: usize,
    pub max_memory_usage: u64,
    pub cache_size: usize,
    pub io_buffer_size: usize,
    pub batch_processing: bool,
    pub async_processing: bool,
}

/// Behavioral analysis configuration with thresholds
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralAnalysisConfig {
    pub enabled: bool,
    pub behavior_score_threshold: f64,
    pub file_modification_threshold: u32,
    pub process_spawn_threshold: u32,
    pub registry_modification_threshold: u32,
    pub entropy_change_threshold: f64,
    pub suspicious_process_chain_threshold: u32,
    pub analysis_window_seconds: u64,
    pub cooldown_period_seconds: u64,
}

/// Machine learning configuration with model settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineLearningConfig {
    pub enabled: bool,
    pub model_path: PathBuf,
    pub feature_cache_size: usize,
    pub anomaly_threshold: f64,
    pub model_accuracy_threshold: f64,
    pub false_positive_rate_threshold: f64,
    pub batch_size: usize,
    pub inference_timeout_ms: u64,
    pub model_update_interval_hours: u64,
    pub enable_online_learning: bool,
}

/// Automated response configuration with action policies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutomatedResponseConfig {
    pub enabled: bool,
    pub enable_process_termination: bool,
    pub enable_file_quarantine: bool,
    pub enable_network_isolation: bool,
    pub enable_system_snapshot: bool,
    pub response_timeout_seconds: u64,
    pub escalation_levels: Vec<ResponseEscalationLevel>,
    pub cooldown_period_seconds: u64,
    pub max_actions_per_hour: u32,
}

/// Response escalation level configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseEscalationLevel {
    pub severity_threshold: f64,
    pub actions: Vec<ResponseAction>,
    pub require_confirmation: bool,
}

/// Response action types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResponseAction {
    Alert,
    ProcessTermination,
    FileQuarantine,
    NetworkIsolation,
    SystemSnapshot,
    UserNotification,
}

/// Enterprise validation configuration for real-world testing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnterpriseValidationConfig {
    /// Enable enterprise validation features
    pub enabled: bool,

    /// Directory containing real ransomware samples
    pub samples_dir: PathBuf,

    /// Real file system snapshot for benchmarking
    pub real_fs_snapshot: PathBuf,

    /// C2 endpoint for network exfiltration testing
    pub c2_endpoint: Option<String>,

    /// Maximum time to detect threats (MTTD) in seconds
    pub max_detection_time_seconds: u64,

    /// Maximum CPU overhead percentage during testing
    pub max_cpu_overhead_percent: f64,

    /// Maximum memory increase in bytes during testing
    pub max_memory_increase_bytes: u64,

    /// Enable air-gapped testing environment
    pub air_gapped_testing: bool,

    /// Enable Windows Event Log integration for audit
    pub enable_event_logging: bool,

    /// Service account for least-privilege testing
    pub service_account: Option<String>,

    /// Real application testing configuration
    pub real_app_testing: RealApplicationTestingConfig,

    /// Performance benchmarking configuration
    pub performance_benchmarking: PerformanceBenchmarkingConfig,

    /// Network monitoring configuration for C2 detection
    pub network_monitoring: NetworkMonitoringConfig,
}

/// Real application testing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealApplicationTestingConfig {
    /// Enable testing with real applications
    pub enabled: bool,

    /// Applications to test (Office, Chrome, Visual Studio, etc.)
    pub test_applications: Vec<String>,

    /// Installation directories for test applications
    pub application_paths: HashMap<String, PathBuf>,

    /// Test scenarios to run
    pub test_scenarios: Vec<String>,
}

/// Performance benchmarking configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceBenchmarkingConfig {
    /// Enable performance benchmarking
    pub enabled: bool,

    /// Number of files to use in filesystem benchmark
    pub benchmark_file_count: usize,

    /// Size range for benchmark files (min, max) in bytes
    pub file_size_range: (u64, u64),

    /// Workload simulation tools to use
    pub workload_tools: Vec<String>,

    /// Benchmark duration in seconds
    pub benchmark_duration_seconds: u64,
}

/// Network monitoring configuration for enterprise validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMonitoringConfig {
    /// Enable network monitoring for C2 detection
    pub enabled: bool,

    /// Ports to monitor for suspicious traffic
    pub monitored_ports: Vec<u16>,

    /// HTTP/HTTPS beacon detection patterns
    pub beacon_patterns: Vec<String>,

    /// Data exfiltration thresholds
    pub exfiltration_threshold_bytes: u64,
}

/// Default configuration implementation
impl Default for EnhancedAgentConfig {
    fn default() -> Self {
        Self {
            agent: AgentConfig::default(),
            detection: DetectionConfig::default(),
            prevention: PreventionConfig::default(),
            quarantine: QuarantineConfig::default(),
            rollback: RollbackConfig::default(),
            threat_intelligence: ThreatIntelligenceConfig::default(),
            coordination: CoordinationConfig::default(),
            telemetry: TelemetryConfig::default(),
            windows_service: WindowsServiceConfig::default(),
            security: SecurityConfig::default(),
            performance: PerformanceConfig::default(),
            behavioral_analysis: BehavioralAnalysisConfig::default(),
            // machine_learning: MachineLearningConfig::default(), // Commented out - ML engine not implemented
            automated_response: AutomatedResponseConfig::default(),
            enterprise_validation: EnterpriseValidationConfig::default(),
        }
    }
}

// Default implementations for all config structs would go here...
// For brevity, I'll implement a few key ones

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            agent_id: None,
            name: "Enhanced ERDPS Agent".to_string(),
            version: "2.0.0".to_string(),
            log_level: "info".to_string(),
            log_file: None,
            config_file: PathBuf::from("config/agent.toml"),
            data_directory: PathBuf::from("data"),
            temp_directory: PathBuf::from("temp"),
            update_interval: Duration::from_secs(3600), // 1 hour
            heartbeat_interval: Duration::from_secs(30),
        }
    }
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            signature: SignatureEngineConfig::default(),
            behavioral: BehavioralEngineConfig::default(),
            // machine_learning: MLEngineConfig::default(), // Commented out - ML engine not implemented
            heuristic: HeuristicEngineConfig::default(),
            #[cfg(feature = "network-monitoring")]
            network: NetworkEngineConfig::default(),
            enabled_engines: vec![
                "signature".to_string(),
                "behavioral".to_string(),
                "heuristic".to_string(),
            ],
            scan_timeout: Duration::from_secs(300), // 5 minutes
            max_concurrent_scans: 4,
        }
    }
}

impl Default for PreventionConfig {
    fn default() -> Self {
        Self {
            active_prevention: ActivePreventionConfig::default(),
            response_actions: vec!["quarantine".to_string(), "notify".to_string()],
            auto_response: false,
            confirmation_required: true,
        }
    }
}

impl Default for ActivePreventionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            process_termination: false,
            file_protection: true,
            network_blocking: false,
            registry_protection: true,
            user_notification: true,
        }
    }
}

impl Default for QuarantineConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            quarantine_directory: PathBuf::from("quarantine"),
            encryption_enabled: true,
            compression_enabled: true,
            metadata_preservation: true,
            max_quarantine_size: 1024 * 1024 * 1024, // 1GB
            retention_period: Duration::from_secs(30 * 24 * 3600), // 30 days
            auto_cleanup: true,
        }
    }
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            thread_pool_size: 4,
            max_memory_usage: 512 * 1024 * 1024, // 512MB
            cache_size: 1000,
            io_buffer_size: 8192,
            batch_processing: true,
            async_processing: true,
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            code_signing: CodeSigningConfig::default(),
            privilege_separation: PrivilegeSeparationConfig::default(),
            tamper_protection: TamperProtectionConfig::default(),
            secure_communication: true,
            audit_logging: true,
        }
    }
}

impl Default for CodeSigningConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            certificate_path: None,
            verify_signatures: true,
            trusted_publishers: vec![],
        }
    }
}

impl Default for PrivilegeSeparationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            service_account: None,
            minimum_privileges: true,
            sandbox_enabled: false,
        }
    }
}

impl Default for TamperProtectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            self_protection: true,
            config_protection: true,
            process_protection: true,
        }
    }
}

impl Default for WindowsServiceConfig {
    fn default() -> Self {
        Self {
            service_name: "ERDPSAgent".to_string(),
            display_name: "Enhanced ERDPS Agent".to_string(),
            description: "Enhanced Endpoint Detection and Response Protection System".to_string(),
            start_type: ServiceStartType::Auto,
            dependencies: vec![],
            recovery_actions: vec![ServiceRecoveryAction::Restart],
        }
    }
}

impl Default for RollbackConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            shadow_copy_integration: true,
            backup_directory: PathBuf::from("backup"),
            max_backup_size: 2 * 1024 * 1024 * 1024, // 2GB
            backup_retention: Duration::from_secs(7 * 24 * 3600), // 7 days
            auto_backup: true,
            backup_interval: Duration::from_secs(24 * 3600), // 24 hours
            max_restore_points: 10,
        }
    }
}

impl Default for ThreatIntelligenceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            feeds: vec![],
            ioc_database: PathBuf::from("ioc.db"),
            update_interval: Duration::from_secs(3600), // 1 hour
            attribution_analysis: false,
            confidence_threshold: 0.7,
        }
    }
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            discovery_method: DiscoveryMethod::Multicast,
            multicast_address: Some("224.0.0.1".to_string()),
            discovery_port: 8080,
            discovery_interval: Duration::from_secs(30),
        }
    }
}

impl Default for CommunicationConfig {
    fn default() -> Self {
        Self {
            encryption_enabled: true,
            certificate_path: None,
            private_key_path: None,
            ca_certificate_path: None,
            communication_port: 8443,
            timeout: Duration::from_secs(30),
        }
    }
}

impl Default for LoadBalancingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            strategy: LoadBalancingStrategy::RoundRobin,
            health_check_interval: Duration::from_secs(30),
            max_load_threshold: 0.8,
        }
    }
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            consensus_threshold: 0.6,
            voting_timeout: Duration::from_secs(10),
            quorum_size: 3,
        }
    }
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            metrics: MetricsConfig::default(),
            tracing: TracingConfig::default(),
            health_monitoring: HealthMonitoringConfig::default(),
            performance_monitoring: PerformanceMonitoringConfig::default(),
        }
    }
}

impl Default for PathValidationConfig {
    fn default() -> Self {
        Self {
            allowed_roots: vec![
                PathBuf::from("C:\\Users"),
                PathBuf::from("C:\\Temp"),
                PathBuf::from("C:\\Downloads"),
            ],
            allowed_extensions: vec![
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
                "7z".to_string(),
            ],
            max_file_size: 100 * 1024 * 1024, // 100MB
        }
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            requests_per_second: 10,  // 10 requests per second
            max_body_size: 32 * 1024, // 32KB
        }
    }
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            prometheus_endpoint: "http://localhost:19091".to_string(),
            collection_interval: Duration::from_secs(60),
            retention_period: Duration::from_secs(7 * 24 * 3600), // 7 days
            custom_metrics: vec![],
            bind_address: "0.0.0.0".to_string(),
            port: 19091,
            shared_secret: None,
            path_validation: PathValidationConfig::default(),
            rate_limit: RateLimitConfig::default(),
        }
    }
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            jaeger_endpoint: None,
            sampling_rate: 0.1,
            max_spans: 1000,
        }
    }
}

impl Default for HealthMonitoringConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            check_interval: Duration::from_secs(60),
            cpu_threshold: 80.0,
            memory_threshold: 80.0,
            disk_threshold: 90.0,
        }
    }
}

impl Default for PerformanceMonitoringConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            profiling_enabled: false,
            benchmark_interval: Duration::from_secs(300), // 5 minutes
            performance_alerts: true,
        }
    }
}

impl Default for BehavioralAnalysisConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            behavior_score_threshold: 0.7,
            file_modification_threshold: 100,
            process_spawn_threshold: 50,
            registry_modification_threshold: 20,
            entropy_change_threshold: 0.5,
            suspicious_process_chain_threshold: 5,
            analysis_window_seconds: 300, // 5 minutes
            cooldown_period_seconds: 60,  // 1 minute
        }
    }
}

impl Default for MachineLearningConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            model_path: PathBuf::from("models/ransomware_detector.model"),
            feature_cache_size: 10000,
            anomaly_threshold: 0.8,
            model_accuracy_threshold: 0.95,
            false_positive_rate_threshold: 0.01,
            batch_size: 32,
            inference_timeout_ms: 5000, // 5 seconds
            model_update_interval_hours: 24,
            enable_online_learning: false,
        }
    }
}

impl Default for AutomatedResponseConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            enable_process_termination: false, // Disabled by default for safety
            enable_file_quarantine: true,
            enable_network_isolation: false, // Disabled by default for safety
            enable_system_snapshot: true,
            response_timeout_seconds: 30,
            escalation_levels: vec![
                ResponseEscalationLevel {
                    severity_threshold: 0.3,
                    actions: vec![ResponseAction::Alert, ResponseAction::UserNotification],
                    require_confirmation: false,
                },
                ResponseEscalationLevel {
                    severity_threshold: 0.7,
                    actions: vec![
                        ResponseAction::Alert,
                        ResponseAction::FileQuarantine,
                        ResponseAction::SystemSnapshot,
                    ],
                    require_confirmation: true,
                },
                ResponseEscalationLevel {
                    severity_threshold: 0.9,
                    actions: vec![
                        ResponseAction::Alert,
                        ResponseAction::ProcessTermination,
                        ResponseAction::FileQuarantine,
                        ResponseAction::NetworkIsolation,
                        ResponseAction::SystemSnapshot,
                    ],
                    require_confirmation: true,
                },
            ],
            cooldown_period_seconds: 300, // 5 minutes
            max_actions_per_hour: 10,
        }
    }
}

impl Default for EnterpriseValidationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            samples_dir: PathBuf::from("/samples/ransom"),
            real_fs_snapshot: PathBuf::from("/mnt/fs_snapshot"),
            c2_endpoint: Some("http://lab-c2.local".to_string()),
            max_detection_time_seconds: 60,
            max_cpu_overhead_percent: 6.0,
            max_memory_increase_bytes: 100 * 1024 * 1024, // 100MB
            air_gapped_testing: true,
            enable_event_logging: true,
            service_account: None,
            real_app_testing: RealApplicationTestingConfig::default(),
            performance_benchmarking: PerformanceBenchmarkingConfig::default(),
            network_monitoring: NetworkMonitoringConfig::default(),
        }
    }
}

impl Default for RealApplicationTestingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            test_applications: vec![
                "Microsoft Office".to_string(),
                "Google Chrome".to_string(),
                "Visual Studio".to_string(),
                "Adobe Acrobat".to_string(),
            ],
            application_paths: HashMap::new(),
            test_scenarios: vec![
                "installation".to_string(),
                "update".to_string(),
                "uninstallation".to_string(),
                "normal_operation".to_string(),
            ],
        }
    }
}

impl Default for PerformanceBenchmarkingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            benchmark_file_count: 100000,
            file_size_range: (1024, 10 * 1024 * 1024), // 1KB to 10MB
            workload_tools: vec![
                "xcopy".to_string(),
                "robocopy".to_string(),
                "7zip".to_string(),
            ],
            benchmark_duration_seconds: 3600, // 1 hour
        }
    }
}

impl Default for NetworkMonitoringConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            monitored_ports: vec![80, 443, 8080, 8443, 53, 22, 3389],
            beacon_patterns: vec![
                "GET /beacon".to_string(),
                "POST /data".to_string(),
                "User-Agent: Mozilla/5.0".to_string(),
            ],
            exfiltration_threshold_bytes: 10 * 1024 * 1024, // 10MB
        }
    }
}

// Additional default implementations would continue here...
// This is a comprehensive configuration system that allows fine-tuning
// of all aspects of the Enhanced ERDPS Agent
