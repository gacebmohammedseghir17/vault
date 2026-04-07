//! AI integration module for ERDPS
//! Provides local Ollama AI integration for malware analysis

pub mod ollama_client;
pub mod analysis_pipeline;
pub mod model_manager;


use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// AI analysis configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIConfig {
    /// Ollama server URL
    pub ollama_url: String,
    /// Default model for analysis
    pub default_model: String,
    /// Request timeout in seconds
    pub timeout_seconds: u64,
    /// Maximum retries for failed requests
    pub max_retries: u32,
    /// Enable caching of analysis results
    pub enable_cache: bool,
    /// Cache TTL in seconds
    pub cache_ttl: u64,
}

impl Default for AIConfig {
    fn default() -> Self {
        Self {
            ollama_url: "http://localhost:11434".to_string(),
            default_model: "deepseek-r1:1.5b".to_string(),
            timeout_seconds: 30,
            max_retries: 3,
            enable_cache: true,
            cache_ttl: 3600, // 1 hour
        }
    }
}

/// AI analysis request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisRequest {
    /// Type of analysis to perform
    pub analysis_type: AnalysisType,
    /// Input data for analysis
    pub input_data: AnalysisInput,
    /// Model to use (optional, uses default if not specified)
    pub model: Option<String>,
    /// Additional context for analysis
    pub context: HashMap<String, String>,
}

/// Type of AI analysis
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AnalysisType {
    /// Malware classification
    MalwareClassification,
    /// YARA rule generation
    YaraRuleGeneration,
    /// Behavioral analysis
    BehavioralAnalysis,
    /// Code similarity analysis
    SimilarityAnalysis,
    /// Threat intelligence correlation
    ThreatCorrelation,
    /// Custom analysis
    Custom(String),
}

impl std::fmt::Display for AnalysisType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnalysisType::MalwareClassification => write!(f, "Malware Classification"),
            AnalysisType::YaraRuleGeneration => write!(f, "YARA Rule Generation"),
            AnalysisType::BehavioralAnalysis => write!(f, "Behavioral Analysis"),
            AnalysisType::SimilarityAnalysis => write!(f, "Code Similarity Analysis"),
            AnalysisType::ThreatCorrelation => write!(f, "Threat Intelligence Correlation"),
            AnalysisType::Custom(s) => write!(f, "Custom: {}", s),
        }
    }
}

/// Input data for AI analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnalysisInput {
    /// Binary file data
    BinaryData {
        data: Vec<u8>,
        filename: String,
        file_type: String,
    },
    /// Disassembly code
    DisassemblyCode {
        instructions: Vec<String>,
        architecture: String,
        entry_point: u64,
    },
    /// Network traffic data
    NetworkTraffic {
        packets: Vec<String>,
        protocol: String,
        flow_info: HashMap<String, String>,
    },
    /// Behavioral indicators
    BehavioralData {
        indicators: Vec<String>,
        timeline: Vec<String>,
        process_info: HashMap<String, String>,
    },
    /// Text data for analysis
    TextData {
        content: String,
        data_type: String,
    },
}

/// AI analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    /// Analysis type that was performed
    pub analysis_type: AnalysisType,
    /// Confidence score (0.0 to 1.0)
    pub confidence: f32,
    /// Analysis findings
    pub findings: Vec<Finding>,
    /// Generated YARA rules (if applicable)
    pub yara_rules: Option<Vec<String>>,
    /// Threat classification
    pub threat_classification: Option<ThreatClassification>,
    /// Processing time in milliseconds
    pub processing_time_ms: u64,
    /// Model used for analysis
    pub model_used: String,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Analysis finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Finding category
    pub category: String,
    /// Severity level
    pub severity: Severity,
    /// Description of the finding
    pub description: String,
    /// Confidence score for this finding
    pub confidence: f32,
    /// Evidence supporting the finding
    pub evidence: Vec<String>,
    /// Recommended actions
    pub recommendations: Vec<String>,
}

/// Threat classification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatClassification {
    /// Primary threat family
    pub family: String,
    /// Threat variant
    pub variant: Option<String>,
    /// Malware type
    pub malware_type: Vec<String>,
    /// Attack techniques (MITRE ATT&CK)
    pub attack_techniques: Vec<String>,
    /// Confidence score
    pub confidence: f32,
}

/// Severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// Informational
    Info,
    /// Low severity
    Low,
    /// Medium severity
    Medium,
    /// High severity
    High,
    /// Critical severity
    Critical,
}

/// AI analysis error types
#[derive(Debug, thiserror::Error)]
pub enum AIError {
    #[error("Ollama server connection failed: {0}")]
    ConnectionError(String),
    
    #[error("Model not available: {0}")]
    ModelNotAvailable(String),
    
    #[error("Analysis request failed: {0}")]
    AnalysisError(String),
    
    #[error("Invalid input data: {0}")]
    InvalidInput(String),
    
    #[error("Timeout occurred during analysis")]
    Timeout,
    
    #[error("Rate limit exceeded")]
    RateLimit,
    
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    
    #[error("HTTP error: {0}")]
    HttpError(String),
    
    #[error("Cache error: {0}")]
    CacheError(String),
}

/// Result type for AI operations
pub type AIResult<T> = Result<T, AIError>;

/// AI analysis statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisStats {
    /// Total analyses performed
    pub total_analyses: u64,
    /// Successful analyses
    pub successful_analyses: u64,
    /// Failed analyses
    pub failed_analyses: u64,
    /// Average processing time in milliseconds
    pub avg_processing_time_ms: f64,
    /// Cache hit rate
    pub cache_hit_rate: f32,
    /// Model usage statistics
    pub model_usage: HashMap<String, u64>,
    /// Analysis type statistics
    pub analysis_type_stats: HashMap<String, u64>,
}

impl Default for AnalysisStats {
    fn default() -> Self {
        Self {
            total_analyses: 0,
            successful_analyses: 0,
            failed_analyses: 0,
            avg_processing_time_ms: 0.0,
            cache_hit_rate: 0.0,
            model_usage: HashMap::new(),
            analysis_type_stats: HashMap::new(),
        }
    }
}

/// Trait for AI analysis providers
#[async_trait::async_trait]
pub trait AIAnalyzer: Send + Sync {
    /// Perform analysis on the given request
    async fn analyze(&self, request: AnalysisRequest) -> AIResult<AnalysisResult>;
    
    /// Check if the analyzer is available
    async fn is_available(&self) -> bool;
    
    /// Get available models
    async fn get_available_models(&self) -> AIResult<Vec<String>>;
    
    /// Get analysis statistics
    fn get_statistics(&self) -> AnalysisStats;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ai_config_default() {
        let config = AIConfig::default();
        assert_eq!(config.ollama_url, "http://localhost:11434");
        assert_eq!(config.default_model, "llama3.2:3b");
        assert_eq!(config.timeout_seconds, 30);
    }

    #[test]
    fn test_analysis_request_serialization() {
        let request = AnalysisRequest {
            analysis_type: AnalysisType::MalwareClassification,
            input_data: AnalysisInput::TextData {
                content: "test content".to_string(),
                data_type: "text".to_string(),
            },
            model: Some("test-model".to_string()),
            context: HashMap::new(),
        };

        let serialized = serde_json::to_string(&request).unwrap();
        let deserialized: AnalysisRequest = serde_json::from_str(&serialized).unwrap();
        
        assert_eq!(request.analysis_type, deserialized.analysis_type);
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }
}
