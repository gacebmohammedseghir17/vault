//! Error handling for the Enhanced ERDPS Agent

use std::fmt;
use std::io;
use thiserror::Error;

/// Main error type for the Enhanced ERDPS Agent
#[derive(Error, Debug, Clone)]
pub enum EnhancedAgentError {
    #[error("Configuration error: {0}")]
    Configuration(String),

    #[error("Detection engine error: {0}")]
    DetectionEngine(String),

    #[error("Detection error: {0}")]
    Detection(String),

    #[error("Signature engine error: {0}")]
    SignatureEngine(#[from] SignatureEngineError),

    #[error("Behavioral engine error: {0}")]
    BehavioralEngine(BehavioralEngineError),

    #[error("Prevention engine error: {0}")]
    PreventionEngine(String),

    #[error("Quarantine system error: {0}")]
    Quarantine(String),

    #[error("Rollback engine error: {0}")]
    Rollback(String),

    #[error("Threat intelligence error: {0}")]
    ThreatIntelligence(String),

    #[error("Agent coordination error: {0}")]
    AgentCoordination(String),

    #[error("Telemetry error: {0}")]
    Telemetry(String),

    #[error("Windows service error: {0}")]
    WindowsService(String),

    #[error("Security error: {0}")]
    Security(String),

    #[error("I/O error: {0}")]
    Io(String),

    #[error("File system error: {0}")]
    FileSystem(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Binary serialization error: {0}")]
    BinarySerialization(String),

    #[error("Database error: {0}")]
    Database(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Timeout error: {0}")]
    Timeout(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Resource exhausted: {0}")]
    ResourceExhausted(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Anyhow error: {0}")]
    Anyhow(String),

    // Deployment-specific errors
    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Load balancer error: {0}")]
    LoadBalancerError(String),

    #[error("Service discovery error: {0}")]
    ServiceDiscoveryError(String),

    #[error("Circuit breaker open: {0}")]
    CircuitBreakerOpen(String),

    #[error("Service not found: {0}")]
    ServiceNotFound(String),

    #[error("Blue-green deployment error: {0}")]
    BlueGreenDeployment(#[from] crate::deployment::blue_green::BlueGreenError),

    #[error("System error: {0}")]
    System(String),
}

impl From<io::Error> for EnhancedAgentError {
    fn from(err: io::Error) -> Self {
        EnhancedAgentError::Io(err.to_string())
    }
}

impl From<serde_json::Error> for EnhancedAgentError {
    fn from(err: serde_json::Error) -> Self {
        EnhancedAgentError::Serialization(err.to_string())
    }
}

impl From<anyhow::Error> for EnhancedAgentError {
    fn from(err: anyhow::Error) -> Self {
        EnhancedAgentError::Anyhow(err.to_string())
    }
}

// Implementation of From trait for Box<dyn std::error::Error + Send + Sync>
impl From<Box<dyn std::error::Error + Send + Sync>> for EnhancedAgentError {
    fn from(err: Box<dyn std::error::Error + Send + Sync>) -> Self {
        EnhancedAgentError::System(err.to_string())
    }
}

/// Specialized error types for different components

#[derive(Error, Debug, Clone)]
pub enum SignatureEngineError {
    #[error("YARA compilation error: {0}")]
    YaraCompilation(String),

    #[error("Rule compilation error: {0}")]
    RuleCompilation(String),

    #[error("YARA scanning error: {0}")]
    YaraScanning(String),

    #[error("Scan error: {0}")]
    ScanError(String),

    #[error("Scan timeout")]
    ScanTimeout,

    #[error("Rule loading error: {0}")]
    RuleLoading(String),

    #[error("Rule update error: {0}")]
    RuleUpdate(String),

    #[error("Invalid rule format: {0}")]
    InvalidRuleFormat(String),

    #[error("Configuration error: {0}")]
    Configuration(String),

    #[error("File access error: {0}")]
    FileAccess(String),

    #[error("System error: {0}")]
    SystemError(String),

    #[error("File too large: {0} bytes")]
    FileTooLarge(u64),

    #[error("Rules not loaded")]
    RulesNotLoaded,
}

#[derive(Error, Debug, Clone)]
pub enum BehavioralEngineError {
    #[error("Process monitoring error: {0}")]
    ProcessMonitoring(String),

    #[error("File system monitoring error: {0}")]
    FileSystemMonitoring(String),

    #[error("Registry monitoring error: {0}")]
    RegistryMonitoring(String),

    #[error("Entropy calculation error: {0}")]
    EntropyCalculation(String),

    #[error("Behavior analysis error: {0}")]
    BehaviorAnalysis(String),

    #[error("File access error: {0}")]
    FileAccess(String),
}

// Commented out - ML engine not implemented
// #[derive(Error, Debug)]
// pub enum MLEngineError {
//     #[error("Model loading error: {0}")]
//     ModelLoading(String),
// 
//     #[error("Feature extraction error: {0}")]
//     FeatureExtraction(String),
// 
//     #[error("Inference error: {0}")]
//     Inference(String),
// 
//     #[error("Model training error: {0}")]
//     ModelTraining(String),
// 
//     #[error("Invalid model format: {0}")]
//     InvalidModelFormat(String),
// 
//     #[error("Feature extraction timeout")]
//     FeatureExtractionTimeout,
// 
//     #[error("No models loaded")]
//     NoModelsLoaded,
// 
//     #[error("All models failed")]
//     AllModelsFailed,
// 
//     #[error("File too large for analysis: {0} bytes")]
//     FileTooLarge(u64),
// }

#[derive(Error, Debug)]
pub enum HeuristicEngineError {
    #[error("API sequence analysis error: {0}")]
    ApiSequenceAnalysis(String),

    #[error("Packer detection error: {0}")]
    PackerDetection(String),

    #[error("Obfuscation detection error: {0}")]
    ObfuscationDetection(String),

    #[error("Pattern matching error: {0}")]
    PatternMatching(String),

    #[error("File access error: {0}")]
    FileAccess(String),

    #[error("File too large: {0} bytes")]
    FileTooLarge(u64),

    #[error("Analysis timeout")]
    AnalysisTimeout,

    #[error("Behavior analysis error: {0}")]
    BehaviorAnalysis(String),
}

#[cfg(feature = "network-monitoring")]
#[derive(Error, Debug)]
pub enum NetworkEngineError {
    #[error("Packet capture error: {0}")]
    PacketCapture(String),

    #[error("Traffic analysis error: {0}")]
    TrafficAnalysis(String),

    #[error("C2 detection error: {0}")]
    C2Detection(String),

    #[error("DNS monitoring error: {0}")]
    DnsMonitoring(String),

    #[error("Network interface error: {0}")]
    NetworkInterface(String),

    #[error("Capture error: {0}")]
    CaptureError(String),

    #[error("No default interface available")]
    NoDefaultInterface,

    #[error("Interface not found: {0}")]
    InterfaceNotFound(String),
}

#[derive(Error, Debug)]
pub enum PreventionEngineError {
    #[error("Process termination error: {0}")]
    ProcessTermination(String),

    #[error("File protection error: {0}")]
    FileProtection(String),

    #[error("Network blocking error: {0}")]
    NetworkBlocking(String),

    #[error("Registry protection error: {0}")]
    RegistryProtection(String),

    #[error("Access control error: {0}")]
    AccessControl(String),
}

#[derive(Error, Debug)]
pub enum QuarantineError {
    #[error("File quarantine error: {0}")]
    FileQuarantine(String),

    #[error("Quarantine storage error: {0}")]
    QuarantineStorage(String),

    #[error("Metadata preservation error: {0}")]
    MetadataPreservation(String),

    #[error("Quarantine restoration error: {0}")]
    QuarantineRestoration(String),

    #[error("Encryption error: {0}")]
    Encryption(String),
}

#[derive(Error, Debug)]
pub enum RollbackEngineError {
    #[error("Shadow copy error: {0}")]
    ShadowCopy(String),

    #[error("File restoration error: {0}")]
    FileRestoration(String),

    #[error("Backup creation error: {0}")]
    BackupCreation(String),

    #[error("Snapshot management error: {0}")]
    SnapshotManagement(String),

    #[error("Volume management error: {0}")]
    VolumeManagement(String),
}

#[derive(Error, Debug)]
pub enum ThreatIntelligenceError {
    #[error("Feed update error: {0}")]
    FeedUpdate(String),

    #[error("IOC processing error: {0}")]
    IocProcessing(String),

    #[error("Attribution analysis error: {0}")]
    AttributionAnalysis(String),

    #[error("Feed parsing error: {0}")]
    FeedParsing(String),

    #[error("API communication error: {0}")]
    ApiCommunication(String),
}

#[derive(Error, Debug)]
pub enum CoordinationError {
    #[error("Agent discovery error: {0}")]
    AgentDiscovery(String),

    #[error("Secure communication error: {0}")]
    SecureCommunication(String),

    #[error("Load balancing error: {0}")]
    LoadBalancing(String),

    #[error("Consensus error: {0}")]
    Consensus(String),

    #[error("Message routing error: {0}")]
    MessageRouting(String),
}

#[derive(Error, Debug)]
pub enum TelemetryError {
    #[error("Metrics collection error: {0}")]
    MetricsCollection(String),

    #[error("Metrics export error: {0}")]
    MetricsExport(String),

    #[error("Tracing error: {0}")]
    Tracing(String),

    #[error("Log aggregation error: {0}")]
    LogAggregation(String),

    #[error("Performance monitoring error: {0}")]
    PerformanceMonitoring(String),
}

/// Result type alias for convenience
pub type Result<T> = std::result::Result<T, EnhancedAgentError>;

/// Error type alias for backward compatibility
pub type Error = EnhancedAgentError;

/// Convert specialized errors to main error type
impl From<BehavioralEngineError> for EnhancedAgentError {
    fn from(err: BehavioralEngineError) -> Self {
        EnhancedAgentError::BehavioralEngine(err)
    }
}

// Commented out - ML engine not implemented
// impl From<MLEngineError> for EnhancedAgentError {
//     fn from(err: MLEngineError) -> Self {
//         EnhancedAgentError::DetectionEngine(err.to_string())
//     }
// }

impl From<HeuristicEngineError> for EnhancedAgentError {
    fn from(err: HeuristicEngineError) -> Self {
        EnhancedAgentError::DetectionEngine(err.to_string())
    }
}

#[cfg(feature = "network-monitoring")]
impl From<NetworkEngineError> for EnhancedAgentError {
    fn from(err: NetworkEngineError) -> Self {
        EnhancedAgentError::DetectionEngine(err.to_string())
    }
}

impl From<PreventionEngineError> for EnhancedAgentError {
    fn from(err: PreventionEngineError) -> Self {
        EnhancedAgentError::PreventionEngine(err.to_string())
    }
}

impl From<QuarantineError> for EnhancedAgentError {
    fn from(err: QuarantineError) -> Self {
        EnhancedAgentError::Quarantine(err.to_string())
    }
}

impl From<RollbackEngineError> for EnhancedAgentError {
    fn from(err: RollbackEngineError) -> Self {
        EnhancedAgentError::Rollback(err.to_string())
    }
}

impl From<ThreatIntelligenceError> for EnhancedAgentError {
    fn from(err: ThreatIntelligenceError) -> Self {
        EnhancedAgentError::ThreatIntelligence(err.to_string())
    }
}

impl From<CoordinationError> for EnhancedAgentError {
    fn from(err: CoordinationError) -> Self {
        EnhancedAgentError::AgentCoordination(err.to_string())
    }
}

impl From<TelemetryError> for EnhancedAgentError {
    fn from(err: TelemetryError) -> Self {
        EnhancedAgentError::Telemetry(err.to_string())
    }
}

// Import deployment error types

use crate::deployment::rollback::RollbackError;


impl From<RollbackError> for EnhancedAgentError {
    fn from(err: RollbackError) -> Self {
        EnhancedAgentError::Rollback(err.to_string())
    }
}

/// Error context for better debugging
#[derive(Debug, Clone)]
pub struct ErrorContext {
    pub component: String,
    pub operation: String,
    pub details: std::collections::HashMap<String, String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl ErrorContext {
    pub fn new(component: &str, operation: &str) -> Self {
        Self {
            component: component.to_string(),
            operation: operation.to_string(),
            details: std::collections::HashMap::new(),
            timestamp: chrono::Utc::now(),
        }
    }

    pub fn with_detail(mut self, key: &str, value: &str) -> Self {
        self.details.insert(key.to_string(), value.to_string());
        self
    }
}

/// Enhanced error with context
#[derive(Debug)]
pub struct ContextualError {
    pub error: EnhancedAgentError,
    pub context: ErrorContext,
}

impl fmt::Display for ContextualError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}:{}] {} (at {})",
            self.context.component,
            self.context.operation,
            self.error,
            self.context.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
        )
    }
}

impl std::error::Error for ContextualError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}
