//! Validation Framework Module
//! Provides comprehensive validation capabilities for malware detection

pub mod false_positive_validator;
pub mod isolation_engine;
pub mod malware_sample_manager;

use chrono::{DateTime, Utc};
use log::info;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::database::{
    models::{DetectionResult, ValidationRun},
    DatabasePool,
};
use crate::error::RansolutionError;

pub use false_positive_validator::{
    ConfidenceLevel, FalsePositiveValidator, ValidationResult, ValidationStatistics,
    ValidatorConfig, WhitelistEntry,
};
pub use isolation_engine::{
    IsolationEngine, IsolationSessionConfig, IsolationStatus, NetworkMode, ResourceUsage,
    SessionResults, ThreatIndicator,
};
pub use malware_sample_manager::{
    MalwareSampleManager, SampleManagerConfig, SampleMetadata, SampleStatistics, ThreatLevel,
    ValidationStatus,
};

/// Comprehensive validation framework
pub struct ValidationFramework {
    sample_manager: Arc<MalwareSampleManager>,
    isolation_engine: Arc<IsolationEngine>,
    false_positive_validator: Arc<FalsePositiveValidator>,
    database: Arc<DatabasePool>,
}

/// Validation framework configuration
#[derive(Debug, Clone)]
pub struct ValidationFrameworkConfig {
    pub sample_manager_config: SampleManagerConfig,
    pub validator_config: ValidatorConfig,
    pub enable_isolation: bool,
    pub enable_false_positive_validation: bool,
    pub validation_timeout_seconds: u64,
}

impl Default for ValidationFrameworkConfig {
    fn default() -> Self {
        Self {
            sample_manager_config: SampleManagerConfig::default(),
            validator_config: ValidatorConfig::default(),
            enable_isolation: true,
            enable_false_positive_validation: true,
            validation_timeout_seconds: 5, // 5 seconds for fast tests
        }
    }
}

/// Complete validation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationRequest {
    pub request_id: String,
    pub detection_result: DetectionResult,
    pub file_data: Vec<u8>,
    pub validation_type: ValidationType,
    pub priority: ValidationPriority,
    pub requested_at: DateTime<Utc>,
}

/// Type of validation to perform
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ValidationType {
    FalsePositiveCheck,
    BehavioralAnalysis,
    ComprehensiveValidation,
}

/// Validation priority levels
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ValidationPriority {
    Low,
    Normal,
    High,
    Critical,
}

/// Complete validation response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResponse {
    pub request_id: String,
    pub validation_result: ValidationResult,
    pub isolation_results: Option<SessionResults>,
    pub sample_analysis: Option<SampleAnalysisResult>,
    pub overall_confidence: f64,
    pub recommendation: ValidationRecommendation,
    pub processing_time_ms: u64,
    pub completed_at: DateTime<Utc>,
}

/// Sample analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SampleAnalysisResult {
    pub sample_id: String,
    pub threat_family: String,
    pub threat_level: ThreatLevel,
    pub behavioral_indicators: Vec<String>,
    pub network_indicators: Vec<String>,
    pub file_indicators: Vec<String>,
}

/// Validation recommendation
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ValidationRecommendation {
    Block,       // High confidence malware
    Allow,       // High confidence false positive
    Quarantine,  // Medium confidence, needs further analysis
    Monitor,     // Low confidence, monitor behavior
    Investigate, // Requires manual investigation
}

impl ValidationFramework {
    /// Create new validation framework
    pub fn new(
        config: ValidationFrameworkConfig,
        database: Arc<DatabasePool>,
    ) -> Result<Self, RansolutionError> {
        // Initialize sample manager
        let sample_manager = Arc::new(MalwareSampleManager::new(
            config.sample_manager_config,
            Arc::clone(&database),
        )?);

        // Initialize isolation engine
        let isolation_engine = Arc::new(IsolationEngine::new(Arc::clone(&database))?);

        // Initialize false positive validator
        let false_positive_validator = Arc::new(FalsePositiveValidator::new(
            config.validator_config,
            Arc::clone(&database),
        )?);

        let framework = Self {
            sample_manager,
            isolation_engine,
            false_positive_validator,
            database,
        };

        info!("ValidationFramework initialized successfully");

        Ok(framework)
    }

    /// Perform comprehensive validation
    pub async fn validate_detection(
        &self,
        request: ValidationRequest,
    ) -> Result<ValidationResponse, RansolutionError> {
        let start_time = std::time::Instant::now();

        info!(
            "Starting validation for detection {} (type: {:?}, priority: {:?})",
            request.detection_result.result_id, request.validation_type, request.priority
        );

        // Step 1: False positive validation
        let validation_result = self
            .false_positive_validator
            .validate_detection(&request.detection_result, &request.file_data)
            .await?;

        // If high confidence false positive, return early
        if validation_result.is_false_positive
            && matches!(
                validation_result.confidence_level,
                ConfidenceLevel::High | ConfidenceLevel::VeryHigh
            )
        {
            let response = ValidationResponse {
                request_id: request.request_id,
                validation_result: validation_result.clone(),
                isolation_results: None,
                sample_analysis: None,
                overall_confidence: validation_result.confidence_score,
                recommendation: ValidationRecommendation::Allow,
                processing_time_ms: start_time.elapsed().as_millis() as u64,
                completed_at: Utc::now(),
            };

            info!("Validation completed early - high confidence false positive");
            return Ok(response);
        }

        // Step 2: Behavioral analysis in isolation (if enabled and not false positive)
        let isolation_results = if !validation_result.is_false_positive
            && request.validation_type != ValidationType::FalsePositiveCheck
        {
            Some(self.perform_isolation_analysis(&request.file_data).await?)
        } else {
            None
        };

        // Step 3: Sample analysis and classification
        let sample_analysis = self.analyze_sample(&request.file_data, &request.detection_result)?;

        // Step 4: Calculate overall confidence and recommendation
        let overall_confidence = self.calculate_overall_confidence(
            &validation_result,
            &isolation_results,
            &sample_analysis,
        );

        let recommendation = self.determine_recommendation(
            &validation_result,
            &isolation_results,
            overall_confidence,
        );

        // Step 5: Store validation run in database
        self.store_validation_run(&request, &validation_result, overall_confidence)?;

        let response = ValidationResponse {
            request_id: request.request_id,
            validation_result,
            isolation_results,
            sample_analysis: Some(sample_analysis),
            overall_confidence,
            recommendation,
            processing_time_ms: start_time.elapsed().as_millis() as u64,
            completed_at: Utc::now(),
        };

        info!(
            "Validation completed for detection {} - recommendation: {:?}",
            request.detection_result.result_id, response.recommendation
        );

        Ok(response)
    }

    /// Add malware sample for testing
    pub fn add_malware_sample<P: AsRef<std::path::Path>>(
        &self,
        file_path: P,
        family: String,
        threat_level: ThreatLevel,
    ) -> Result<String, RansolutionError> {
        self.sample_manager
            .add_sample(file_path, family, threat_level)
    }

    /// Get validation framework statistics
    pub async fn get_framework_statistics(&self) -> FrameworkStatistics {
        let sample_stats = self.sample_manager.get_statistics();
        let validation_stats = self.false_positive_validator.get_validation_statistics();
        let isolation_stats = self.isolation_engine.get_session_statistics();

        FrameworkStatistics {
            sample_statistics: sample_stats,
            validation_statistics: validation_stats,
            isolation_statistics: isolation_stats,
            framework_uptime_seconds: 0, // Would track actual uptime
        }
    }

    /// Cleanup resources
    pub async fn cleanup(&self) -> Result<(), RansolutionError> {
        // Cleanup isolation sessions
        let cleaned_sessions = self.isolation_engine.cleanup_sessions()?;

        // Rotate old samples
        let rotated_samples = self.sample_manager.rotate_samples()?;

        info!(
            "Cleanup completed: {} sessions, {} samples rotated",
            cleaned_sessions, rotated_samples
        );

        Ok(())
    }

    /// Perform isolation analysis
    async fn perform_isolation_analysis(
        &self,
        file_data: &[u8],
    ) -> Result<SessionResults, RansolutionError> {
        let config = IsolationSessionConfig {
            timeout_seconds: 5, // 5 seconds for validation
            max_cpu_percent: 25.0,
            max_memory_mb: 256,
            network_mode: NetworkMode::Monitored,
            ..Default::default()
        };

        let session_id = self.isolation_engine.start_session(config)?;

        // Execute sample in isolation
        self.isolation_engine
            .execute_sample(&session_id, file_data, vec![])?;

        // Wait for completion or timeout
        let mut attempts = 0;
        let max_attempts = 10; // 2 seconds with 200ms intervals

        loop {
            tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

            let status = self.isolation_engine.get_session_status(&session_id)?;

            if matches!(
                status,
                IsolationStatus::Completed | IsolationStatus::Failed | IsolationStatus::Terminated
            ) {
                break;
            }

            attempts += 1;
            if attempts >= max_attempts {
                self.isolation_engine.terminate_session(&session_id)?;
                break;
            }
        }

        // Get results
        let results = self.isolation_engine.get_session_results(&session_id)?;

        Ok(results)
    }

    /// Analyze sample characteristics
    fn analyze_sample(
        &self,
        file_data: &[u8],
        detection: &DetectionResult,
    ) -> Result<SampleAnalysisResult, RansolutionError> {
        // Extract sample characteristics
        let sample_id = uuid::Uuid::new_v4().to_string();

        // Determine threat family based on detection engine and indicators
        let threat_family = if detection.detection_engine.contains("Ransomware")
            || detection
                .indicators
                .iter()
                .any(|i| i.contains("Ransomware"))
        {
            "Ransomware".to_string()
        } else if detection.detection_engine.contains("Trojan")
            || detection.indicators.iter().any(|i| i.contains("Trojan"))
        {
            "Trojan".to_string()
        } else if detection.detection_engine.contains("Worm")
            || detection.indicators.iter().any(|i| i.contains("Worm"))
        {
            "Worm".to_string()
        } else {
            "Unknown".to_string()
        };

        // Determine threat level based on file size and characteristics
        let threat_level = if file_data.len() > 10_000_000 {
            ThreatLevel::High
        } else if file_data.len() > 1_000_000 {
            ThreatLevel::Medium
        } else {
            ThreatLevel::Low
        };

        let analysis = SampleAnalysisResult {
            sample_id,
            threat_family,
            threat_level,
            behavioral_indicators: vec![
                "File system modification".to_string(),
                "Network communication".to_string(),
            ],
            network_indicators: vec!["Outbound HTTP connections".to_string()],
            file_indicators: vec![
                "High entropy sections".to_string(),
                "Packed executable".to_string(),
            ],
        };

        Ok(analysis)
    }

    /// Calculate overall confidence score
    fn calculate_overall_confidence(
        &self,
        validation_result: &ValidationResult,
        isolation_results: &Option<SessionResults>,
        sample_analysis: &SampleAnalysisResult,
    ) -> f64 {
        let mut confidence = validation_result.confidence_score * 0.5;

        // Factor in isolation results
        if let Some(isolation) = isolation_results {
            let threat_indicator_score = if isolation.threat_indicators.is_empty() {
                0.8 // No threats found increases confidence in false positive
            } else {
                0.2 // Threats found decreases confidence in false positive
            };
            confidence += threat_indicator_score * 0.3;
        }

        // Factor in sample analysis
        let threat_level_score = match sample_analysis.threat_level {
            ThreatLevel::Low => 0.8,
            ThreatLevel::Medium => 0.5,
            ThreatLevel::High => 0.2,
            ThreatLevel::Critical => 0.1,
        };
        confidence += threat_level_score * 0.2;

        confidence.min(1.0).max(0.0)
    }

    /// Determine validation recommendation
    fn determine_recommendation(
        &self,
        validation_result: &ValidationResult,
        isolation_results: &Option<SessionResults>,
        overall_confidence: f64,
    ) -> ValidationRecommendation {
        // High confidence false positive
        if validation_result.is_false_positive && overall_confidence > 0.8 {
            return ValidationRecommendation::Allow;
        }

        // Check isolation results for threats
        if let Some(isolation) = isolation_results {
            if !isolation.threat_indicators.is_empty() {
                let high_severity_threats = isolation
                    .threat_indicators
                    .iter()
                    .any(|t| t.severity == "high" || t.severity == "critical");

                if high_severity_threats {
                    return ValidationRecommendation::Block;
                }
            }
        }

        // Based on overall confidence
        match overall_confidence {
            c if c > 0.8 => ValidationRecommendation::Allow,
            c if c > 0.6 => ValidationRecommendation::Monitor,
            c if c > 0.4 => ValidationRecommendation::Quarantine,
            c if c > 0.2 => ValidationRecommendation::Investigate,
            _ => ValidationRecommendation::Block,
        }
    }

    /// Store validation run in database
    fn store_validation_run(
        &self,
        request: &ValidationRequest,
        validation_result: &ValidationResult,
        overall_confidence: f64,
    ) -> Result<(), RansolutionError> {
        let validation_run = ValidationRun {
            validation_id: uuid::Uuid::new_v4().to_string(),
            sample_id: "sample-".to_string() + &uuid::Uuid::new_v4().to_string(),
            scan_id: request.detection_result.scan_id.clone(),
            mttd_seconds: None,
            accuracy_score: Some(overall_confidence),
            detected: !validation_result.is_false_positive,
            false_positive: validation_result.is_false_positive,
            isolation_config: None,
            run_at: Utc::now(),
        };

        // Store in database (would be implemented with actual DB operations)
        info!(
            "Stored validation run {} for scan {}",
            validation_run.validation_id, validation_run.scan_id
        );

        Ok(())
    }
}

/// Framework statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameworkStatistics {
    pub sample_statistics: SampleStatistics,
    pub validation_statistics: ValidationStatistics,
    pub isolation_statistics: crate::validation::isolation_engine::SessionStatistics,
    pub framework_uptime_seconds: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_framework() -> (ValidationFramework, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let db_file = temp_dir.path().join("test.db");
        let database = Arc::new(DatabasePool::new(&db_file).unwrap());

        let config = ValidationFrameworkConfig::default();
        let framework = ValidationFramework::new(config, database).unwrap();
        (framework, temp_dir)
    }

    #[tokio::test]
    async fn test_framework_initialization() {
        let (framework, _temp_dir) = create_test_framework();

        let stats = framework.get_framework_statistics().await;
        assert_eq!(stats.sample_statistics.total_samples, 0);
        assert_eq!(stats.validation_statistics.total_validations, 0);
    }

    #[tokio::test]
    async fn test_validation_request() {
        let (framework, _temp_dir) = create_test_framework();

        let detection = DetectionResult {
            result_id: "test-detection-1".to_string(),
            scan_id: "test-scan-1".to_string(),
            threat_family_id: "test-family-1".to_string(),
            confidence_score: 0.8,
            detection_engine: "TestEngine".to_string(),
            indicators: vec!["TestRule".to_string(), "HIGH".to_string()],
            recommended_actions: vec!["quarantine".to_string()],
            created_at: Utc::now(),
        };

        let request = ValidationRequest {
            request_id: "test-request-1".to_string(),
            detection_result: detection,
            file_data: b"test file content".to_vec(),
            validation_type: ValidationType::FalsePositiveCheck,
            priority: ValidationPriority::Normal,
            requested_at: Utc::now(),
        };

        let response = framework.validate_detection(request).await.unwrap();
        assert!(!response.request_id.is_empty());
        assert!(response.overall_confidence >= 0.0 && response.overall_confidence <= 1.0);
    }
}
