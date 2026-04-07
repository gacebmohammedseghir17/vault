//! AI-YARA correlation engine for enhanced threat detection
//! Combines AI analysis with YARA rule matching for comprehensive malware detection

use crate::ai::{AnalysisRequest, AnalysisResult, ThreatClassification, Severity};


use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::error;

pub mod correlation_engine;
pub mod rule_generator;
pub mod threat_scorer;

// AI-YARA correlator for super-enhanced detection
#[cfg(feature = "ai-integration")]
pub mod ai_yara_correlator;
#[cfg(feature = "ai-integration")]
pub use ai_yara_correlator::*;

/// Correlation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationConfig {
    /// Enable AI-enhanced correlation
    pub enable_ai_correlation: bool,
    /// Minimum confidence threshold for AI analysis
    pub ai_confidence_threshold: f32,
    /// Minimum YARA rule score threshold
    pub yara_score_threshold: f32,
    /// Weight for AI analysis in final score (0.0 to 1.0)
    pub ai_weight: f32,
    /// Weight for YARA analysis in final score (0.0 to 1.0)
    pub yara_weight: f32,
    /// Enable dynamic rule generation
    pub enable_dynamic_rules: bool,
    /// Maximum number of dynamic rules to maintain
    pub max_dynamic_rules: usize,
    /// Rule generation confidence threshold
    pub rule_generation_threshold: f32,
    /// Cache TTL for correlation results in seconds
    pub cache_ttl_seconds: u64,
    /// Enable behavioral correlation
    pub enable_behavioral_correlation: bool,
    /// Behavioral analysis window in seconds
    pub behavioral_window_seconds: u64,
}

impl Default for CorrelationConfig {
    fn default() -> Self {
        Self {
            enable_ai_correlation: true,
            ai_confidence_threshold: 0.7,
            yara_score_threshold: 0.6,
            ai_weight: 0.6,
            yara_weight: 0.4,
            enable_dynamic_rules: true,
            max_dynamic_rules: 1000,
            rule_generation_threshold: 0.8,
            cache_ttl_seconds: 3600, // 1 hour
            enable_behavioral_correlation: true,
            behavioral_window_seconds: 300, // 5 minutes
        }
    }
}

/// Correlation input data
#[derive(Debug, Clone)]
pub struct CorrelationInput {
    /// File path being analyzed
    pub file_path: String,
    /// File content (if available)
    pub file_content: Option<Vec<u8>>,
    /// File metadata
    pub metadata: FileMetadata,
    /// Behavioral indicators
    pub behavioral_indicators: Vec<BehavioralIndicator>,
    /// Network indicators
    pub network_indicators: Vec<NetworkIndicator>,
    /// Process information
    pub process_info: Option<ProcessInfo>,
}

/// File metadata for correlation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    /// File size in bytes
    pub size: u64,
    /// File hash (SHA256)
    pub hash: String,
    /// File type/extension
    pub file_type: String,
    /// Creation timestamp
    pub created_at: Option<SystemTime>,
    /// Last modified timestamp
    pub modified_at: Option<SystemTime>,
    /// File entropy
    pub entropy: Option<f64>,
    /// PE/ELF specific metadata
    pub binary_metadata: Option<BinaryMetadata>,
}

/// Binary-specific metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryMetadata {
    /// Architecture (x86, x64, ARM, etc.)
    pub architecture: String,
    /// Entry point address
    pub entry_point: Option<u64>,
    /// Imported functions
    pub imports: Vec<String>,
    /// Exported functions
    pub exports: Vec<String>,
    /// Sections information
    pub sections: Vec<SectionInfo>,
    /// Compiler/packer information
    pub compiler_info: Option<String>,
}

/// Section information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionInfo {
    /// Section name
    pub name: String,
    /// Virtual address
    pub virtual_address: u64,
    /// Virtual size
    pub virtual_size: u64,
    /// Raw size
    pub raw_size: u64,
    /// Section characteristics/permissions
    pub characteristics: u32,
    /// Section entropy
    pub entropy: Option<f64>,
}

/// Behavioral indicator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralIndicator {
    /// Indicator type
    pub indicator_type: BehavioralType,
    /// Indicator description
    pub description: String,
    /// Severity level
    pub severity: Severity,
    /// Confidence score (0.0 to 1.0)
    pub confidence: f32,
    /// Timestamp when observed
    pub timestamp: SystemTime,
    /// Additional context data
    pub context: HashMap<String, String>,
}

/// Types of behavioral indicators
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum BehavioralType {
    /// File system operations
    FileSystem,
    /// Registry operations
    Registry,
    /// Network activity
    Network,
    /// Process operations
    Process,
    /// Memory operations
    Memory,
    /// Cryptographic operations
    Cryptographic,
    /// Anti-analysis techniques
    AntiAnalysis,
    /// Persistence mechanisms
    Persistence,
    /// Privilege escalation
    PrivilegeEscalation,
    /// Data exfiltration
    DataExfiltration,
}

/// Network indicator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkIndicator {
    /// Indicator type
    pub indicator_type: NetworkType,
    /// Network address/domain
    pub address: String,
    /// Port number (if applicable)
    pub port: Option<u16>,
    /// Protocol
    pub protocol: String,
    /// Direction (inbound/outbound)
    pub direction: String,
    /// Data transferred (bytes)
    pub bytes_transferred: u64,
    /// Timestamp
    pub timestamp: SystemTime,
    /// Geolocation info
    pub geolocation: Option<GeolocationInfo>,
}

/// Types of network indicators
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum NetworkType {
    /// Command and control communication
    CommandAndControl,
    /// Data exfiltration
    DataExfiltration,
    /// Malware download
    MalwareDownload,
    /// DNS queries
    DnsQuery,
    /// Suspicious connections
    SuspiciousConnection,
    /// Botnet communication
    BotnetCommunication,
}

/// Geolocation information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeolocationInfo {
    /// Country code
    pub country: String,
    /// Region/state
    pub region: Option<String>,
    /// City
    pub city: Option<String>,
    /// ISP/Organization
    pub organization: Option<String>,
    /// Threat intelligence reputation
    pub reputation: Option<String>,
}

/// Process information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    /// Process ID
    pub pid: u32,
    /// Parent process ID
    pub ppid: Option<u32>,
    /// Process name
    pub name: String,
    /// Command line arguments
    pub command_line: Option<String>,
    /// Process start time
    pub start_time: SystemTime,
    /// User context
    pub user: Option<String>,
    /// Process privileges
    pub privileges: Vec<String>,
    /// Memory usage
    pub memory_usage: Option<u64>,
    /// CPU usage percentage
    pub cpu_usage: Option<f32>,
}

/// Correlation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationResult {
    /// Overall threat score (0.0 to 1.0)
    pub threat_score: f32,
    /// Threat classification
    pub classification: ThreatClassification,
    /// Severity level
    pub severity: Severity,
    /// AI analysis results
    pub ai_results: Vec<AnalysisResult>,
    /// YARA rule matches
    pub yara_matches: Vec<YaraMatch>,
    /// Generated dynamic rules
    pub dynamic_rules: Vec<DynamicRule>,
    /// Correlation findings
    pub findings: Vec<CorrelationFinding>,
    /// Behavioral analysis summary
    pub behavioral_summary: BehavioralSummary,
    /// Network analysis summary
    pub network_summary: NetworkSummary,
    /// Recommended actions
    pub recommended_actions: Vec<String>,
    /// Analysis timestamp
    pub timestamp: SystemTime,
    /// Processing time in milliseconds
    pub processing_time_ms: u64,
}

/// YARA rule match result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMatch {
    /// Rule name
    pub rule_name: String,
    /// Rule namespace
    pub namespace: Option<String>,
    /// Match score (0.0 to 1.0)
    pub score: f32,
    /// Matched strings/patterns
    pub matched_strings: Vec<MatchedString>,
    /// Rule metadata
    pub metadata: HashMap<String, String>,
    /// Match timestamp
    pub timestamp: SystemTime,
}

/// Matched string in YARA rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchedString {
    /// String identifier
    pub identifier: String,
    /// Matched content
    pub content: String,
    /// Offset in file
    pub offset: u64,
    /// Length of match
    pub length: u32,
}

/// Dynamic rule generated by AI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicRule {
    /// Rule name
    pub name: String,
    /// Rule content (YARA syntax)
    pub content: String,
    /// Generation confidence
    pub confidence: f32,
    /// Rule description
    pub description: String,
    /// Target threat types
    pub target_threats: Vec<String>,
    /// Generation timestamp
    pub created_at: SystemTime,
    /// Rule effectiveness score
    pub effectiveness_score: Option<f32>,
    /// Usage statistics
    pub usage_stats: RuleUsageStats,
}

/// Rule usage statistics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuleUsageStats {
    /// Total times rule was applied
    pub total_applications: u64,
    /// True positive matches
    pub true_positives: u64,
    /// False positive matches
    pub false_positives: u64,
    /// Last used timestamp
    pub last_used: Option<SystemTime>,
    /// Average processing time
    pub avg_processing_time_ms: f64,
}

/// Correlation finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationFinding {
    /// Finding type
    pub finding_type: FindingType,
    /// Finding description
    pub description: String,
    /// Confidence score
    pub confidence: f32,
    /// Severity level
    pub severity: Severity,
    /// Supporting evidence
    pub evidence: Vec<Evidence>,
    /// Related indicators
    pub related_indicators: Vec<String>,
    /// Mitigation suggestions
    pub mitigations: Vec<String>,
}

/// Types of correlation findings
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FindingType {
    /// Malware family identification
    MalwareFamilyIdentification,
    /// Attack technique detection
    AttackTechniqueDetection,
    /// Behavioral pattern correlation
    BehavioralPatternCorrelation,
    /// Network pattern correlation
    NetworkPatternCorrelation,
    /// Code similarity detection
    CodeSimilarityDetection,
    /// Threat actor attribution
    ThreatActorAttribution,
    /// Campaign correlation
    CampaignCorrelation,
    /// Anomaly detection
    AnomalyDetection,
}

/// Evidence supporting a finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    /// Evidence type
    pub evidence_type: EvidenceType,
    /// Evidence description
    pub description: String,
    /// Evidence data/content
    pub data: String,
    /// Confidence in evidence
    pub confidence: f32,
    /// Source of evidence
    pub source: String,
}

/// Types of evidence
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EvidenceType {
    /// File hash match
    FileHash,
    /// String pattern match
    StringPattern,
    /// Behavioral indicator
    BehavioralIndicator,
    /// Network indicator
    NetworkIndicator,
    /// Code pattern
    CodePattern,
    /// Metadata correlation
    MetadataCorrelation,
    /// Temporal correlation
    TemporalCorrelation,
}

/// Behavioral analysis summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralSummary {
    /// Total behavioral indicators
    pub total_indicators: usize,
    /// High severity indicators
    pub high_severity_count: usize,
    /// Most common behavior types
    pub common_behaviors: Vec<(BehavioralType, usize)>,
    /// Behavioral risk score
    pub risk_score: f32,
    /// Timeline of behaviors
    pub behavior_timeline: Vec<BehaviorTimelineEntry>,
}

/// Behavior timeline entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorTimelineEntry {
    /// Timestamp
    pub timestamp: SystemTime,
    /// Behavior type
    pub behavior_type: BehavioralType,
    /// Description
    pub description: String,
    /// Severity
    pub severity: Severity,
}

/// Network analysis summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSummary {
    /// Total network indicators
    pub total_indicators: usize,
    /// Unique destinations
    pub unique_destinations: usize,
    /// Total bytes transferred
    pub total_bytes: u64,
    /// Suspicious connections count
    pub suspicious_connections: usize,
    /// Geographic distribution
    pub geographic_distribution: HashMap<String, usize>,
    /// Protocol distribution
    pub protocol_distribution: HashMap<String, usize>,
    /// Network risk score
    pub risk_score: f32,
}

/// Correlation error types
#[derive(Debug, thiserror::Error)]
pub enum CorrelationError {
    #[error("AI analysis error: {0}")]
    AIAnalysisError(String),
    
    #[error("YARA engine error: {0}")]
    YaraEngineError(String),
    
    #[error("Rule generation error: {0}")]
    RuleGenerationError(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Configuration error: {0}")]
    ConfigurationError(String),
    
    #[error("Cache error: {0}")]
    CacheError(String),
    
    #[error("Timeout error: {0}")]
    TimeoutError(String),
}

/// Correlation result type
pub type CorrelationResultType = Result<CorrelationResult, CorrelationError>;

/// Correlation statistics
#[derive(Debug, Clone, Default)]
pub struct CorrelationStats {
    /// Total correlations performed
    pub total_correlations: u64,
    /// Successful correlations
    pub successful_correlations: u64,
    /// Failed correlations
    pub failed_correlations: u64,
    /// Average processing time
    pub avg_processing_time_ms: f64,
    /// Cache hit rate
    pub cache_hit_rate: f32,
    /// AI analysis success rate
    pub ai_success_rate: f32,
    /// YARA analysis success rate
    pub yara_success_rate: f32,
    /// Dynamic rules generated
    pub dynamic_rules_generated: u64,
    /// Dynamic rules effectiveness
    pub dynamic_rules_effectiveness: f32,
}

/// Main correlation engine trait
#[async_trait::async_trait]
pub trait CorrelationEngine: Send + Sync {
    /// Perform correlation analysis
    async fn correlate(&self, input: CorrelationInput) -> CorrelationResultType;
    
    /// Get correlation statistics
    async fn get_stats(&self) -> CorrelationStats;
    
    /// Update configuration
    async fn update_config(&self, config: CorrelationConfig) -> Result<(), CorrelationError>;
    
    /// Clear correlation cache
    async fn clear_cache(&self) -> Result<(), CorrelationError>;
    
    /// Get dynamic rules
    async fn get_dynamic_rules(&self) -> Result<Vec<DynamicRule>, CorrelationError>;
    
    /// Add custom rule
    async fn add_custom_rule(&self, rule: DynamicRule) -> Result<(), CorrelationError>;
    
    /// Remove dynamic rule
    async fn remove_dynamic_rule(&self, rule_name: &str) -> Result<(), CorrelationError>;
}

/// Utility functions for correlation
pub mod utils {
    use super::*;
    
    /// Calculate file entropy
    pub fn calculate_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        
        let mut counts = [0u32; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }
        
        let len = data.len() as f64;
        let mut entropy = 0.0;
        
        for &count in &counts {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }
        
        entropy
    }
    
    /// Extract file type from path
    pub fn extract_file_type(path: &str) -> String {
        Path::new(path)
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("unknown")
            .to_lowercase()
    }
    
    /// Calculate behavioral risk score
    pub fn calculate_behavioral_risk(indicators: &[BehavioralIndicator]) -> f32 {
        if indicators.is_empty() {
            return 0.0;
        }
        
        let mut total_score = 0.0;
        let mut weight_sum = 0.0;
        
        for indicator in indicators {
            let severity_weight = match indicator.severity {
                Severity::Critical => 1.0,
                Severity::High => 0.8,
                Severity::Medium => 0.6,
                Severity::Low => 0.4,
                Severity::Info => 0.2,
            };
            
            total_score += indicator.confidence * severity_weight;
            weight_sum += severity_weight;
        }
        
        if weight_sum > 0.0 {
            total_score / weight_sum
        } else {
            0.0
        }
    }
    
    /// Calculate network risk score
    pub fn calculate_network_risk(indicators: &[NetworkIndicator]) -> f32 {
        if indicators.is_empty() {
            return 0.0;
        }
        
        let mut risk_score = 0.0;
        let suspicious_types = [
            NetworkType::CommandAndControl,
            NetworkType::DataExfiltration,
            NetworkType::MalwareDownload,
            NetworkType::BotnetCommunication,
        ];
        
        for indicator in indicators {
            let type_risk = if suspicious_types.contains(&indicator.indicator_type) {
                0.8
            } else {
                0.3
            };
            
            let reputation_risk = indicator.geolocation
                .as_ref()
                .and_then(|geo| geo.reputation.as_ref())
                .map(|rep| match rep.as_str() {
                    "malicious" => 1.0,
                    "suspicious" => 0.7,
                    "unknown" => 0.5,
                    _ => 0.2,
                })
                .unwrap_or(0.5);
            
            risk_score += type_risk * reputation_risk;
        }
        
        (risk_score / indicators.len() as f32).min(1.0)
    }
    
    /// Get current timestamp
    pub fn current_timestamp() -> SystemTime {
        SystemTime::now()
    }
    
    /// Convert SystemTime to Unix timestamp
    pub fn systemtime_to_unix(time: SystemTime) -> u64 {
        time.duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::utils::*;

    #[test]
    fn test_entropy_calculation() {
        let data = b"AAAA";
        let entropy = calculate_entropy(data);
        assert_eq!(entropy, 0.0); // All same bytes = 0 entropy
        
        let data = b"ABCD";
        let entropy = calculate_entropy(data);
        assert_eq!(entropy, 2.0); // Perfect distribution = max entropy for 4 bytes
    }

    #[test]
    fn test_file_type_extraction() {
        assert_eq!(extract_file_type("test.exe"), "exe");
        assert_eq!(extract_file_type("malware.dll"), "dll");
        assert_eq!(extract_file_type("script.ps1"), "ps1");
        assert_eq!(extract_file_type("noextension"), "unknown");
    }

    #[test]
    fn test_behavioral_risk_calculation() {
        let indicators = vec![
            BehavioralIndicator {
                indicator_type: BehavioralType::FileSystem,
                description: "Test".to_string(),
                severity: Severity::High,
                confidence: 0.9,
                timestamp: SystemTime::now(),
                context: HashMap::new(),
            },
            BehavioralIndicator {
                indicator_type: BehavioralType::Network,
                description: "Test".to_string(),
                severity: Severity::Medium,
                confidence: 0.7,
                timestamp: SystemTime::now(),
                context: HashMap::new(),
            },
        ];
        
        let risk = calculate_behavioral_risk(&indicators);
        assert!(risk > 0.0 && risk <= 1.0);
    }

    #[test]
    fn test_network_risk_calculation() {
        let indicators = vec![
            NetworkIndicator {
                indicator_type: NetworkType::CommandAndControl,
                address: "192.168.1.1".to_string(),
                port: Some(443),
                protocol: "TCP".to_string(),
                direction: "outbound".to_string(),
                bytes_transferred: 1024,
                timestamp: SystemTime::now(),
                geolocation: Some(GeolocationInfo {
                    country: "US".to_string(),
                    region: None,
                    city: None,
                    organization: None,
                    reputation: Some("malicious".to_string()),
                }),
            },
        ];
        
        let risk = calculate_network_risk(&indicators);
        assert!(risk > 0.0 && risk <= 1.0);
    }

    #[test]
    fn test_correlation_config_default() {
        let config = CorrelationConfig::default();
        assert!(config.enable_ai_correlation);
        assert_eq!(config.ai_confidence_threshold, 0.7);
        assert_eq!(config.yara_score_threshold, 0.6);
    }
}
