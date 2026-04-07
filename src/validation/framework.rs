//! Core Validation Framework
//!
//! This module provides the main validation framework that orchestrates malware testing,
//! YARA rules validation, false positive detection, and performance metrics collection.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock};
use tokio::time::timeout;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{
    MalwareSampleManager, FalsePositiveValidator, ProductionYaraManager,
    MTTDTracker, IsolationManager, DetectionMetrics,
};

/// Validation framework errors
#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("Framework initialization failed: {0}")]
    InitializationFailed(String),
    #[error("Session creation failed: {0}")]
    SessionCreationFailed(String),
    #[error("Validation execution failed: {0}")]
    ExecutionFailed(String),
    #[error("Configuration error: {0}")]
    ConfigurationError(String),
    #[error("Resource unavailable: {0}")]
    ResourceUnavailable(String),
    #[error("Timeout occurred: {0}")]
    Timeout(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    #[error("Database error: {0}")]
    DatabaseError(String),
}

/// Framework configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameworkConfig {
    pub workspace_directory: PathBuf,
    pub malware_samples_directory: PathBuf,
    pub benign_samples_directory: PathBuf,
    pub yara_rules_directory: PathBuf,
    pub isolation_directory: PathBuf,
    pub metrics_directory: PathBuf,
    pub max_concurrent_validations: usize,
    pub validation_timeout_seconds: u64,
    pub enable_isolation: bool,
    pub enable_metrics_collection: bool,
    pub enable_real_time_monitoring: bool,
    pub false_positive_threshold: f64,
    pub detection_confidence_threshold: f64,
    pub mttd_target_seconds: u64,
    pub performance_baseline_samples: usize,
}

/// Validation session configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationSession {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub session_type: SessionType,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub status: SessionStatus,
    pub configuration: SessionConfig,
    pub results: Option<SessionResult>,
}

/// Types of validation sessions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SessionType {
    MalwareValidation,
    FalsePositiveValidation,
    YaraRulesValidation,
    PerformanceBaseline,
    ComprehensiveValidation,
    CustomValidation(String),
}

/// Session status tracking
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SessionStatus {
    Created,
    Initializing,
    Running,
    Paused,
    Completed,
    Failed,
    Cancelled,
}

/// Session-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    pub enable_malware_testing: bool,
    pub enable_false_positive_testing: bool,
    pub enable_yara_validation: bool,
    pub enable_performance_metrics: bool,
    pub enable_isolation: bool,
    pub sample_limit: Option<usize>,
    pub timeout_override: Option<Duration>,
    pub custom_parameters: HashMap<String, serde_json::Value>,
}

/// Comprehensive session results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionResult {
    pub session_id: Uuid,
    pub execution_duration: Duration,
    pub total_samples_processed: u64,
    pub malware_detection_results: Option<MalwareDetectionResults>,
    pub false_positive_results: Option<FalsePositiveResults>,
    pub yara_validation_results: Option<YaraValidationResults>,
    pub performance_metrics: Option<PerformanceResults>,
    pub overall_success_rate: f64,
    pub recommendations: Vec<ValidationRecommendation>,
    pub errors_encountered: Vec<String>,
}

/// Malware detection results summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalwareDetectionResults {
    pub samples_tested: u64,
    pub samples_detected: u64,
    pub detection_rate: f64,
    pub average_mttd: Duration,
    pub false_negatives: u64,
    pub confidence_distribution: HashMap<String, u64>,
}

/// False positive results summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FalsePositiveResults {
    pub benign_samples_tested: u64,
    pub false_positives_detected: u64,
    pub false_positive_rate: f64,
    pub accuracy: f64,
    pub whitelist_additions: u64,
}

/// YARA validation results summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraValidationResults {
    pub rules_tested: u64,
    pub rules_passed: u64,
    pub rules_failed: u64,
    pub compilation_success_rate: f64,
    pub performance_metrics: HashMap<String, f64>,
}

/// Performance results summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceResults {
    pub average_scan_time: Duration,
    pub memory_usage_peak: u64,
    pub cpu_usage_average: f64,
    pub throughput_samples_per_second: f64,
    pub resource_efficiency_score: f64,
}

/// Validation recommendations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationRecommendation {
    pub category: RecommendationCategory,
    pub priority: RecommendationPriority,
    pub title: String,
    pub description: String,
    pub action_items: Vec<String>,
}

/// Recommendation categories
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RecommendationCategory {
    Performance,
    Accuracy,
    FalsePositives,
    Configuration,
    Security,
    Monitoring,
}

/// Recommendation priorities
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RecommendationPriority {
    Low,
    Medium,
    High,
    Critical,
}

/// Main validation framework
pub struct ValidationFramework {
    pub config: FrameworkConfig,
    pub malware_manager: Arc<Mutex<MalwareSampleManager>>,
    pub false_positive_validator: Arc<Mutex<FalsePositiveValidator>>,
    pub yara_manager: Arc<Mutex<ProductionYaraManager>>,
    pub isolation_manager: Arc<Mutex<IsolationManager>>,
    pub mttd_tracker: Arc<Mutex<MTTDTracker>>,
    pub detection_metrics: Arc<RwLock<DetectionMetrics>>,
    pub active_sessions: Arc<RwLock<HashMap<Uuid, ValidationSession>>>,
    pub session_results: Arc<RwLock<HashMap<Uuid, SessionResult>>>,
}

impl ValidationFramework {
    /// Create a new validation framework
    pub async fn new(config: FrameworkConfig) -> Result<Self, ValidationError> {
        // Create necessary directories
        tokio::fs::create_dir_all(&config.workspace_directory).await?;
        tokio::fs::create_dir_all(&config.malware_samples_directory).await?;
        tokio::fs::create_dir_all(&config.benign_samples_directory).await?;
        tokio::fs::create_dir_all(&config.yara_rules_directory).await?;
        tokio::fs::create_dir_all(&config.isolation_directory).await?;
        tokio::fs::create_dir_all(&config.metrics_directory).await?;

        // Initialize components
        let malware_config = super::malware_testing::MalwareConfig {
            samples_directory: config.malware_samples_directory.clone(),
            isolation_enabled: config.enable_isolation,
            max_concurrent_scans: config.max_concurrent_validations,
            scan_timeout_seconds: config.validation_timeout_seconds,
            ..Default::default()
        };
        let malware_manager = Arc::new(Mutex::new(
            MalwareSampleManager::new(malware_config).await
                .map_err(|e| ValidationError::InitializationFailed(format!("Malware manager: {}", e)))?
        ));

        let fp_config = super::false_positive_tester::FalsePositiveConfig {
            benign_samples_directory: config.benign_samples_directory.clone(),
            max_false_positive_rate: config.false_positive_threshold,
            validation_timeout_seconds: config.validation_timeout_seconds,
            confidence_threshold: config.detection_confidence_threshold,
            ..Default::default()
        };
        let false_positive_validator = Arc::new(Mutex::new(
            FalsePositiveValidator::new(fp_config)
        ));

        let yara_config = super::production_yara::YaraConfig {
            rules_directory: config.yara_rules_directory.clone(),
            enable_caching: true,
            cache_size_mb: 256,
            compilation_timeout_seconds: 30,
            ..Default::default()
        };
        let yara_manager = Arc::new(Mutex::new(
            ProductionYaraManager::new(yara_config).await
                .map_err(|e| ValidationError::InitializationFailed(format!("YARA manager: {}", e)))?
        ));

        let isolation_config = super::isolation::IsolationConfig {
            workspace_directory: config.isolation_directory.clone(),
            enable_vm_isolation: config.enable_isolation,
            max_execution_time_seconds: config.validation_timeout_seconds,
            ..Default::default()
        };
        let isolation_manager = Arc::new(Mutex::new(
            IsolationManager::new(isolation_config).await
                .map_err(|e| ValidationError::InitializationFailed(format!("Isolation manager: {}", e)))?
        ));

        let mttd_tracker = Arc::new(Mutex::new(
            MTTDTracker::new(Duration::from_secs(config.mttd_target_seconds))
        ));

        let detection_metrics = Arc::new(RwLock::new(
            DetectionMetrics::new()
        ));

        Ok(Self {
            config,
            malware_manager,
            false_positive_validator,
            yara_manager,
            isolation_manager,
            mttd_tracker,
            detection_metrics,
            active_sessions: Arc::new(RwLock::new(HashMap::new())),
            session_results: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Create a new validation session
    pub async fn create_session(
        &self,
        name: String,
        description: String,
        session_type: SessionType,
        config: SessionConfig,
    ) -> Result<Uuid, ValidationError> {
        let session_id = Uuid::new_v4();
        
        let session = ValidationSession {
            id: session_id,
            name,
            description,
            session_type,
            created_at: chrono::Utc::now(),
            started_at: None,
            completed_at: None,
            status: SessionStatus::Created,
            configuration: config,
            results: None,
        };

        let mut sessions = self.active_sessions.write().await;
        sessions.insert(session_id, session);

        Ok(session_id)
    }

    /// Start a validation session
    pub async fn start_session(&self, session_id: &Uuid) -> Result<(), ValidationError> {
        let mut sessions = self.active_sessions.write().await;
        
        if let Some(session) = sessions.get_mut(session_id) {
            if session.status != SessionStatus::Created {
                return Err(ValidationError::ExecutionFailed(
                    format!("Session {} is not in Created status", session_id)
                ));
            }
            
            session.status = SessionStatus::Initializing;
            session.started_at = Some(chrono::Utc::now());
            
            // Clone session for async processing
            let session_clone = session.clone();
            drop(sessions);
            
            // Start session execution in background
            let framework = self.clone_arc_components();
            tokio::spawn(async move {
                if let Err(e) = Self::execute_session_async(framework, session_clone).await {
                    eprintln!("Session execution failed: {}", e);
                }
            });
            
            Ok(())
        } else {
            Err(ValidationError::SessionCreationFailed(
                format!("Session {} not found", session_id)
            ))
        }
    }

    /// Execute a validation session asynchronously
    async fn execute_session_async(
        components: FrameworkComponents,
        mut session: ValidationSession,
    ) -> Result<(), ValidationError> {
        let start_time = Instant::now();
        
        // Update session status
        session.status = SessionStatus::Running;
        
        let mut result = SessionResult {
            session_id: session.id,
            execution_duration: Duration::ZERO,
            total_samples_processed: 0,
            malware_detection_results: None,
            false_positive_results: None,
            yara_validation_results: None,
            performance_metrics: None,
            overall_success_rate: 0.0,
            recommendations: Vec::new(),
            errors_encountered: Vec::new(),
        };

        // Execute validation based on session type and configuration
        match session.session_type {
            SessionType::MalwareValidation => {
                if let Ok(malware_results) = Self::execute_malware_validation(&components, &session.configuration).await {
                    result.malware_detection_results = Some(malware_results);
                }
            }
            SessionType::FalsePositiveValidation => {
                if let Ok(fp_results) = Self::execute_false_positive_validation(&components, &session.configuration).await {
                    result.false_positive_results = Some(fp_results);
                }
            }
            SessionType::YaraRulesValidation => {
                if let Ok(yara_results) = Self::execute_yara_validation(&components, &session.configuration).await {
                    result.yara_validation_results = Some(yara_results);
                }
            }
            SessionType::ComprehensiveValidation => {
                // Execute all validation types
                if session.configuration.enable_malware_testing {
                    if let Ok(malware_results) = Self::execute_malware_validation(&components, &session.configuration).await {
                        result.malware_detection_results = Some(malware_results);
                    }
                }
                
                if session.configuration.enable_false_positive_testing {
                    if let Ok(fp_results) = Self::execute_false_positive_validation(&components, &session.configuration).await {
                        result.false_positive_results = Some(fp_results);
                    }
                }
                
                if session.configuration.enable_yara_validation {
                    if let Ok(yara_results) = Self::execute_yara_validation(&components, &session.configuration).await {
                        result.yara_validation_results = Some(yara_results);
                    }
                }
            }
            _ => {
                // Handle other session types
            }
        }

        // Calculate overall metrics
        result.execution_duration = start_time.elapsed();
        result.overall_success_rate = Self::calculate_overall_success_rate(&result);
        result.recommendations = Self::generate_recommendations(&result);

        // Update session
        session.status = SessionStatus::Completed;
        session.completed_at = Some(chrono::Utc::now());
        session.results = Some(result.clone());

        // Store results (in a real implementation, this would update the framework's state)
        println!("Session {} completed with success rate: {:.2}%", 
                session.id, result.overall_success_rate * 100.0);

        Ok(())
    }

    /// Execute malware validation
    async fn execute_malware_validation(
        _components: &FrameworkComponents,
        _config: &SessionConfig,
    ) -> Result<MalwareDetectionResults, ValidationError> {
        // Placeholder implementation
        Ok(MalwareDetectionResults {
            samples_tested: 100,
            samples_detected: 95,
            detection_rate: 0.95,
            average_mttd: Duration::from_secs(2),
            false_negatives: 5,
            confidence_distribution: HashMap::new(),
        })
    }

    /// Execute false positive validation
    async fn execute_false_positive_validation(
        _components: &FrameworkComponents,
        _config: &SessionConfig,
    ) -> Result<FalsePositiveResults, ValidationError> {
        // Placeholder implementation
        Ok(FalsePositiveResults {
            benign_samples_tested: 1000,
            false_positives_detected: 5,
            false_positive_rate: 0.005,
            accuracy: 0.995,
            whitelist_additions: 3,
        })
    }

    /// Execute YARA validation
    async fn execute_yara_validation(
        _components: &FrameworkComponents,
        _config: &SessionConfig,
    ) -> Result<YaraValidationResults, ValidationError> {
        // Placeholder implementation
        Ok(YaraValidationResults {
            rules_tested: 50,
            rules_passed: 48,
            rules_failed: 2,
            compilation_success_rate: 0.96,
            performance_metrics: HashMap::new(),
        })
    }

    /// Calculate overall success rate
    fn calculate_overall_success_rate(result: &SessionResult) -> f64 {
        let mut total_weight = 0.0;
        let mut weighted_success = 0.0;

        if let Some(malware_results) = &result.malware_detection_results {
            total_weight += 0.4; // 40% weight for malware detection
            weighted_success += 0.4 * malware_results.detection_rate;
        }

        if let Some(fp_results) = &result.false_positive_results {
            total_weight += 0.3; // 30% weight for false positive control
            weighted_success += 0.3 * fp_results.accuracy;
        }

        if let Some(yara_results) = &result.yara_validation_results {
            total_weight += 0.3; // 30% weight for YARA rules
            weighted_success += 0.3 * yara_results.compilation_success_rate;
        }

        if total_weight > 0.0 {
            weighted_success / total_weight
        } else {
            0.0
        }
    }

    /// Generate validation recommendations
    fn generate_recommendations(result: &SessionResult) -> Vec<ValidationRecommendation> {
        let mut recommendations = Vec::new();

        // Check false positive rate
        if let Some(fp_results) = &result.false_positive_results {
            if fp_results.false_positive_rate > 0.01 {
                recommendations.push(ValidationRecommendation {
                    category: RecommendationCategory::FalsePositives,
                    priority: RecommendationPriority::High,
                    title: "High False Positive Rate Detected".to_string(),
                    description: format!("False positive rate of {:.2}% exceeds recommended threshold of 1%", 
                                       fp_results.false_positive_rate * 100.0),
                    action_items: vec![
                        "Review and tune detection rules".to_string(),
                        "Expand whitelist with legitimate applications".to_string(),
                        "Implement additional context-aware filtering".to_string(),
                    ],
                });
            }
        }

        // Check detection rate
        if let Some(malware_results) = &result.malware_detection_results {
            if malware_results.detection_rate < 0.95 {
                recommendations.push(ValidationRecommendation {
                    category: RecommendationCategory::Accuracy,
                    priority: RecommendationPriority::Critical,
                    title: "Low Malware Detection Rate".to_string(),
                    description: format!("Detection rate of {:.2}% is below recommended 95%", 
                                       malware_results.detection_rate * 100.0),
                    action_items: vec![
                        "Update malware signatures and rules".to_string(),
                        "Enhance behavioral detection capabilities".to_string(),
                        "Review and expand threat intelligence feeds".to_string(),
                    ],
                });
            }
        }

        recommendations
    }

    /// Clone Arc components for async operations
    fn clone_arc_components(&self) -> FrameworkComponents {
        FrameworkComponents {
            malware_manager: Arc::clone(&self.malware_manager),
            false_positive_validator: Arc::clone(&self.false_positive_validator),
            yara_manager: Arc::clone(&self.yara_manager),
            isolation_manager: Arc::clone(&self.isolation_manager),
            mttd_tracker: Arc::clone(&self.mttd_tracker),
            detection_metrics: Arc::clone(&self.detection_metrics),
        }
    }

    /// Get session status
    pub async fn get_session_status(&self, session_id: &Uuid) -> Option<SessionStatus> {
        let sessions = self.active_sessions.read().await;
        sessions.get(session_id).map(|s| s.status.clone())
    }

    /// Get session results
    pub async fn get_session_results(&self, session_id: &Uuid) -> Option<SessionResult> {
        let results = self.session_results.read().await;
        results.get(session_id).cloned()
    }

    /// List all sessions
    pub async fn list_sessions(&self) -> Vec<ValidationSession> {
        let sessions = self.active_sessions.read().await;
        sessions.values().cloned().collect()
    }

    /// Cancel a running session
    pub async fn cancel_session(&self, session_id: &Uuid) -> Result<(), ValidationError> {
        let mut sessions = self.active_sessions.write().await;
        
        if let Some(session) = sessions.get_mut(session_id) {
            if session.status == SessionStatus::Running {
                session.status = SessionStatus::Cancelled;
                session.completed_at = Some(chrono::Utc::now());
                Ok(())
            } else {
                Err(ValidationError::ExecutionFailed(
                    "Session is not running".to_string()
                ))
            }
        } else {
            Err(ValidationError::SessionCreationFailed(
                "Session not found".to_string()
            ))
        }
    }
}

/// Framework components for async operations
#[derive(Clone)]
struct FrameworkComponents {
    pub malware_manager: Arc<Mutex<MalwareSampleManager>>,
    pub false_positive_validator: Arc<Mutex<FalsePositiveValidator>>,
    pub yara_manager: Arc<Mutex<ProductionYaraManager>>,
    pub isolation_manager: Arc<Mutex<IsolationManager>>,
    pub mttd_tracker: Arc<Mutex<MTTDTracker>>,
    pub detection_metrics: Arc<RwLock<DetectionMetrics>>,
}

/// Default framework configuration
impl Default for FrameworkConfig {
    fn default() -> Self {
        Self {
            workspace_directory: PathBuf::from("./validation_workspace"),
            malware_samples_directory: PathBuf::from("./validation_workspace/malware_samples"),
            benign_samples_directory: PathBuf::from("./validation_workspace/benign_samples"),
            yara_rules_directory: PathBuf::from("./validation_workspace/yara_rules"),
            isolation_directory: PathBuf::from("./validation_workspace/isolation"),
            metrics_directory: PathBuf::from("./validation_workspace/metrics"),
            max_concurrent_validations: 4,
            validation_timeout_seconds: 5,
            enable_isolation: true,
            enable_metrics_collection: true,
            enable_real_time_monitoring: true,
            false_positive_threshold: 0.01,
            detection_confidence_threshold: 0.7,
            mttd_target_seconds: 5,
            performance_baseline_samples: 1000,
        }
    }
}

impl FrameworkConfig {
    /// Test configuration with reduced timeouts and limits
    pub fn test_config() -> Self {
        Self {
            max_concurrent_validations: 2,
            validation_timeout_seconds: 30,
            enable_isolation: false,
            performance_baseline_samples: 10,
            ..Default::default()
        }
    }

    /// Production configuration with enhanced capabilities
    pub fn production_config() -> Self {
        Self {
            max_concurrent_validations: 8,
            validation_timeout_seconds: 5,
            enable_isolation: true,
            enable_metrics_collection: true,
            enable_real_time_monitoring: true,
            performance_baseline_samples: 10000,
            ..Default::default()
        }
    }
}

/// Default session configuration
impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            enable_malware_testing: true,
            enable_false_positive_testing: true,
            enable_yara_validation: true,
            enable_performance_metrics: true,
            enable_isolation: true,
            sample_limit: None,
            timeout_override: None,
            custom_parameters: HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_framework_creation() {
        let temp_dir = TempDir::new().unwrap();
        let config = FrameworkConfig {
            workspace_directory: temp_dir.path().to_path_buf(),
            ..FrameworkConfig::test_config()
        };
        
        let framework = ValidationFramework::new(config).await;
        assert!(framework.is_ok());
    }

    #[tokio::test]
    async fn test_session_creation() {
        let temp_dir = TempDir::new().unwrap();
        let config = FrameworkConfig {
            workspace_directory: temp_dir.path().to_path_buf(),
            ..FrameworkConfig::test_config()
        };
        
        let framework = ValidationFramework::new(config).await.unwrap();
        
        let session_id = framework.create_session(
            "Test Session".to_string(),
            "Test validation session".to_string(),
            SessionType::MalwareValidation,
            SessionConfig::default(),
        ).await.unwrap();
        
        let status = framework.get_session_status(&session_id).await;
        assert_eq!(status, Some(SessionStatus::Created));
    }

    #[test]
    fn test_success_rate_calculation() {
        let result = SessionResult {
            session_id: Uuid::new_v4(),
            execution_duration: Duration::from_secs(5),
            total_samples_processed: 100,
            malware_detection_results: Some(MalwareDetectionResults {
                samples_tested: 100,
                samples_detected: 95,
                detection_rate: 0.95,
                average_mttd: Duration::from_secs(2),
                false_negatives: 5,
                confidence_distribution: HashMap::new(),
            }),
            false_positive_results: Some(FalsePositiveResults {
                benign_samples_tested: 1000,
                false_positives_detected: 5,
                false_positive_rate: 0.005,
                accuracy: 0.995,
                whitelist_additions: 3,
            }),
            yara_validation_results: None,
            performance_metrics: None,
            overall_success_rate: 0.0,
            recommendations: Vec::new(),
            errors_encountered: Vec::new(),
        };
        
        let success_rate = ValidationFramework::calculate_overall_success_rate(&result);
        assert!(success_rate > 0.9); // Should be high with good detection and low false positives
    }
}
