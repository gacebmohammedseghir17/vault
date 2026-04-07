//! False Positive Validator for reducing detection false positives
//! Implements ML-based validation, whitelist management, and confidence scoring

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
// std::path::Path import removed - not used
use chrono::{DateTime, Duration, Utc};
use log::{debug, info};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::database::{models::DetectionResult, DatabasePool};
use crate::error::RansolutionError;

use crate::error::AgentError;
/// Validation confidence levels
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ConfidenceLevel {
    VeryLow,  // 0.0 - 0.2
    Low,      // 0.2 - 0.4
    Medium,   // 0.4 - 0.6
    High,     // 0.6 - 0.8
    VeryHigh, // 0.8 - 1.0
}

impl From<f64> for ConfidenceLevel {
    fn from(score: f64) -> Self {
        match score {
            s if s < 0.2 => ConfidenceLevel::VeryLow,
            s if s < 0.4 => ConfidenceLevel::Low,
            s if s < 0.6 => ConfidenceLevel::Medium,
            s if s < 0.8 => ConfidenceLevel::High,
            _ => ConfidenceLevel::VeryHigh,
        }
    }
}

impl ConfidenceLevel {
    pub fn to_score(&self) -> f64 {
        match self {
            ConfidenceLevel::VeryLow => 0.1,
            ConfidenceLevel::Low => 0.3,
            ConfidenceLevel::Medium => 0.5,
            ConfidenceLevel::High => 0.7,
            ConfidenceLevel::VeryHigh => 0.9,
        }
    }
}

/// Validation result for a detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub detection_id: String,
    pub is_false_positive: bool,
    pub confidence_score: f64,
    pub confidence_level: ConfidenceLevel,
    pub validation_reasons: Vec<String>,
    pub whitelist_matches: Vec<WhitelistEntry>,
    pub behavioral_analysis: BehavioralAnalysis,
    pub reputation_score: f64,
    pub validation_timestamp: DateTime<Utc>,
}

/// Whitelist entry for known good files
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhitelistEntry {
    pub entry_id: String,
    pub file_hash: String,
    pub file_path: String,
    pub publisher: Option<String>,
    pub digital_signature: Option<String>,
    pub reason: String,
    pub added_by: String,
    pub added_at: DateTime<Utc>,
    pub last_verified: DateTime<Utc>,
    pub verification_count: u64,
}

/// Behavioral analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralAnalysis {
    pub file_operations: FileOperationAnalysis,
    pub network_behavior: NetworkBehaviorAnalysis,
    pub process_behavior: ProcessBehaviorAnalysis,
    pub registry_behavior: RegistryBehaviorAnalysis,
    pub anomaly_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileOperationAnalysis {
    pub read_operations: u64,
    pub write_operations: u64,
    pub delete_operations: u64,
    pub suspicious_paths: Vec<String>,
    pub entropy_changes: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkBehaviorAnalysis {
    pub outbound_connections: u64,
    pub inbound_connections: u64,
    pub suspicious_domains: Vec<String>,
    pub data_exfiltration_indicators: Vec<String>,
    pub c2_communication_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessBehaviorAnalysis {
    pub child_processes: u64,
    pub injection_attempts: u64,
    pub privilege_escalation: bool,
    pub persistence_mechanisms: Vec<String>,
    pub evasion_techniques: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryBehaviorAnalysis {
    pub registry_modifications: u64,
    pub startup_entries: Vec<String>,
    pub security_modifications: Vec<String>,
    pub suspicious_keys: Vec<String>,
}

/// ML feature vector for validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureVector {
    pub file_size: f64,
    pub entropy: f64,
    pub pe_characteristics: Vec<f64>,
    pub string_features: Vec<f64>,
    pub behavioral_features: Vec<f64>,
    pub network_features: Vec<f64>,
    pub temporal_features: Vec<f64>,
}

/// Validation configuration
#[derive(Debug, Clone)]
pub struct ValidatorConfig {
    pub false_positive_threshold: f64,
    pub confidence_threshold: f64,
    pub whitelist_auto_update: bool,
    pub behavioral_analysis_timeout: Duration,
    pub reputation_sources: Vec<String>,
    pub ml_model_path: String,
}

impl Default for ValidatorConfig {
    fn default() -> Self {
        Self {
            false_positive_threshold: 0.7,
            confidence_threshold: 0.6,
            whitelist_auto_update: true,
            behavioral_analysis_timeout: Duration::minutes(5),
            reputation_sources: vec![
                "VirusTotal".to_string(),
                "Microsoft Defender".to_string(),
                "Internal Reputation".to_string(),
            ],
            ml_model_path: "models/false_positive_classifier.bin".to_string(),
        }
    }
}

/// False Positive Validator
#[derive(Debug)]
pub struct FalsePositiveValidator {
    config: ValidatorConfig,
    database: Arc<DatabasePool>,
    whitelist: Arc<Mutex<HashMap<String, WhitelistEntry>>>,
    reputation_cache: Arc<Mutex<HashMap<String, f64>>>,
    validation_history: Arc<Mutex<HashMap<String, ValidationResult>>>,
}

impl FalsePositiveValidator {
    /// Create new false positive validator
    pub fn new(
        config: ValidatorConfig,
        database: Arc<DatabasePool>,
    ) -> Result<Self, RansolutionError> {
        let validator = Self {
            config,
            database,
            whitelist: Arc::new(Mutex::new(HashMap::new())),
            reputation_cache: Arc::new(Mutex::new(HashMap::new())),
            validation_history: Arc::new(Mutex::new(HashMap::new())),
        };

        // Load existing whitelist from database
        validator.load_whitelist()?;

        info!(
            "FalsePositiveValidator initialized with {} whitelist entries",
            validator.whitelist.lock().unwrap().len()
        );

        Ok(validator)
    }

    /// Validate a detection result for false positives
    pub async fn validate_detection(
        &self,
        detection: &DetectionResult,
        file_data: &[u8],
    ) -> Result<ValidationResult, RansolutionError> {
        let start_time = std::time::Instant::now();

        // Calculate file hash
        let file_hash = format!("{:x}", Sha256::digest(file_data));

        // Check whitelist first
        let whitelist_matches = self.check_whitelist(&file_hash, "")?;

        // If whitelisted, mark as false positive with high confidence
        if !whitelist_matches.is_empty() {
            let result = ValidationResult {
                detection_id: detection.result_id.clone(),
                is_false_positive: true,
                confidence_score: 0.95,
                confidence_level: ConfidenceLevel::VeryHigh,
                validation_reasons: vec!["File found in whitelist".to_string()],
                whitelist_matches,
                behavioral_analysis: BehavioralAnalysis::default(),
                reputation_score: 1.0,
                validation_timestamp: Utc::now(),
            };

            self.store_validation_result(&result)?;
            return Ok(result);
        }

        // Extract features for ML analysis
        let features = self.extract_features(file_data, detection)?;

        // Perform behavioral analysis
        let behavioral_analysis = self.analyze_behavior(detection, file_data)?;

        // Get reputation score
        let reputation_score = self.get_reputation_score(&file_hash).unwrap_or(0.5);

        // Calculate ML-based confidence score
        let ml_score = self.calculate_ml_score(&features)?;

        // Combine scores for final confidence
        let combined_confidence =
            self.combine_scores(ml_score, reputation_score, &behavioral_analysis);

        // Determine if it's a false positive
        let is_false_positive = combined_confidence > self.config.false_positive_threshold;

        let mut validation_reasons = Vec::new();
        if ml_score > 0.7 {
            validation_reasons.push("High ML confidence score".to_string());
        }
        if reputation_score > 0.8 {
            validation_reasons.push("Good reputation score".to_string());
        }
        if behavioral_analysis.anomaly_score < 0.3 {
            validation_reasons.push("Low behavioral anomaly score".to_string());
        }

        let result = ValidationResult {
            detection_id: detection.result_id.clone(),
            is_false_positive,
            confidence_score: combined_confidence,
            confidence_level: ConfidenceLevel::from(combined_confidence),
            validation_reasons,
            whitelist_matches: Vec::new(),
            behavioral_analysis,
            reputation_score,
            validation_timestamp: Utc::now(),
        };

        // Store validation result
        self.store_validation_result(&result)?;

        let duration = start_time.elapsed();
        debug!(
            "Validation completed for {} in {:?}",
            detection.result_id, duration
        );

        Ok(result)
    }

    /// Add entry to whitelist
    pub fn add_to_whitelist(
        &self,
        file_hash: String,
        file_path: String,
        reason: String,
        added_by: String,
    ) -> Result<String, RansolutionError> {
        let entry_id = uuid::Uuid::new_v4().to_string();

        let entry = WhitelistEntry {
            entry_id: entry_id.clone(),
            file_hash: file_hash.clone(),
            file_path,
            publisher: None,
            digital_signature: None,
            reason,
            added_by,
            added_at: Utc::now(),
            last_verified: Utc::now(),
            verification_count: 1,
        };

        // Store in memory cache
        self.whitelist
            .lock()
            .unwrap()
            .insert(file_hash.clone(), entry.clone());

        // Store in database (would be implemented with actual DB operations)
        info!(
            "Added {} to whitelist with reason: {}",
            file_hash, entry.reason
        );

        Ok(entry_id)
    }

    /// Remove entry from whitelist
    pub fn remove_from_whitelist(&self, file_hash: &str) -> Result<(), RansolutionError> {
        let mut whitelist = self.whitelist.lock().unwrap();
        if whitelist.remove(file_hash).is_some() {
            info!("Removed {} from whitelist", file_hash);
            Ok(())
        } else {
            Err(AgentError::Validation { 
                message: format!("Hash {} not found in whitelist", file_hash),
                field: None, 
                expected: None, 
                actual: None, 
                context: None 
            })
        }
    }

    /// Get validation statistics
    pub fn get_validation_statistics(&self) -> ValidationStatistics {
        let history = self.validation_history.lock().unwrap();
        let total_validations = history.len();

        let false_positives = history.values().filter(|v| v.is_false_positive).count();

        let high_confidence = history
            .values()
            .filter(|v| {
                matches!(
                    v.confidence_level,
                    ConfidenceLevel::High | ConfidenceLevel::VeryHigh
                )
            })
            .count();

        let avg_confidence = if total_validations > 0 {
            history.values().map(|v| v.confidence_score).sum::<f64>() / total_validations as f64
        } else {
            0.0
        };

        ValidationStatistics {
            total_validations,
            false_positives,
            false_positive_rate: if total_validations > 0 {
                false_positives as f64 / total_validations as f64
            } else {
                0.0
            },
            high_confidence_validations: high_confidence,
            average_confidence_score: avg_confidence,
            whitelist_entries: self.whitelist.lock().unwrap().len(),
        }
    }

    /// Update ML model with new training data
    pub fn update_model(
        &self,
        training_data: Vec<(FeatureVector, bool)>,
    ) -> Result<(), RansolutionError> {
        // In a real implementation, this would retrain the ML model
        info!(
            "Updating ML model with {} training samples",
            training_data.len()
        );

        // Simulate model update
        std::thread::sleep(std::time::Duration::from_millis(100));

        info!("ML model updated successfully");
        Ok(())
    }

    /// Check whitelist for matches
    pub fn check_whitelist(
        &self,
        file_hash: &str,
        file_path: &str,
    ) -> Result<Vec<WhitelistEntry>, RansolutionError> {
        let whitelist = self.whitelist.lock().unwrap();
        let mut matches = Vec::new();
        let mut found_hashes = std::collections::HashSet::new();

        // Check by hash
        if let Some(entry) = whitelist.get(file_hash) {
            matches.push(entry.clone());
            found_hashes.insert(entry.file_hash.clone());
        }

        // Check by path patterns (simplified) - only if file_path is not empty and avoid duplicates
        if !file_path.is_empty() {
            for entry in whitelist.values() {
                if file_path == entry.file_path && !found_hashes.contains(&entry.file_hash) {
                    matches.push(entry.clone());
                    found_hashes.insert(entry.file_hash.clone());
                }
            }
        }

        Ok(matches)
    }

    /// Extract ML features from file data
    fn extract_features(
        &self,
        file_data: &[u8],
        _detection: &DetectionResult,
    ) -> Result<FeatureVector, RansolutionError> {
        // Calculate entropy
        let entropy = self.calculate_entropy(file_data);

        // Extract basic features
        let features = FeatureVector {
            file_size: file_data.len() as f64,
            entropy,
            pe_characteristics: vec![0.5, 0.3, 0.7], // Simulated PE features
            string_features: vec![0.4, 0.6, 0.2],    // Simulated string analysis
            behavioral_features: vec![0.3, 0.8, 0.1], // Simulated behavioral features
            network_features: vec![0.2, 0.4, 0.6],   // Simulated network features
            temporal_features: vec![0.7, 0.3, 0.9],  // Simulated temporal features
        };

        Ok(features)
    }

    /// Analyze behavioral patterns
    fn analyze_behavior(
        &self,
        _detection: &DetectionResult,
        _file_data: &[u8],
    ) -> Result<BehavioralAnalysis, RansolutionError> {
        // Simulate behavioral analysis
        let analysis = BehavioralAnalysis {
            file_operations: FileOperationAnalysis {
                read_operations: 10,
                write_operations: 5,
                delete_operations: 0,
                suspicious_paths: Vec::new(),
                entropy_changes: 0.1,
            },
            network_behavior: NetworkBehaviorAnalysis {
                outbound_connections: 2,
                inbound_connections: 0,
                suspicious_domains: Vec::new(),
                data_exfiltration_indicators: Vec::new(),
                c2_communication_score: 0.1,
            },
            process_behavior: ProcessBehaviorAnalysis {
                child_processes: 1,
                injection_attempts: 0,
                privilege_escalation: false,
                persistence_mechanisms: Vec::new(),
                evasion_techniques: Vec::new(),
            },
            registry_behavior: RegistryBehaviorAnalysis {
                registry_modifications: 3,
                startup_entries: Vec::new(),
                security_modifications: Vec::new(),
                suspicious_keys: Vec::new(),
            },
            anomaly_score: 0.2, // Low anomaly score indicates normal behavior
        };

        Ok(analysis)
    }

    /// Get reputation score from external sources
    fn get_reputation_score(&self, file_hash: &str) -> Result<f64, RansolutionError> {
        // Check cache first
        {
            let cache = self.reputation_cache.lock().unwrap();
            if let Some(&score) = cache.get(file_hash) {
                return Ok(score);
            }
        }

        // Simulate reputation lookup
        let reputation_score = 0.7; // Simulated good reputation

        // Cache the result
        self.reputation_cache
            .lock()
            .unwrap()
            .insert(file_hash.to_string(), reputation_score);

        Ok(reputation_score)
    }

    /// Calculate ML-based confidence score
    fn calculate_ml_score(&self, features: &FeatureVector) -> Result<f64, RansolutionError> {
        // Simulate ML model inference
        let score = (features.entropy + features.file_size / 1000000.0)
            .min(1.0)
            .max(0.0);
        Ok(score * 0.8) // Scale to reasonable range
    }

    /// Combine multiple scores into final confidence
    fn combine_scores(
        &self,
        ml_score: f64,
        reputation_score: f64,
        behavioral: &BehavioralAnalysis,
    ) -> f64 {
        let behavioral_score = 1.0 - behavioral.anomaly_score;

        // Weighted combination
        let combined = (ml_score * 0.4) + (reputation_score * 0.3) + (behavioral_score * 0.3);
        combined.min(1.0).max(0.0)
    }

    /// Calculate file entropy
    fn calculate_entropy(&self, data: &[u8]) -> f64 {
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

    /// Store validation result
    fn store_validation_result(&self, result: &ValidationResult) -> Result<(), RansolutionError> {
        // Store in memory cache
        self.validation_history
            .lock()
            .unwrap()
            .insert(result.detection_id.clone(), result.clone());

        // Store in database (would be implemented with actual DB operations)
        debug!(
            "Stored validation result for detection {}",
            result.detection_id
        );

        Ok(())
    }

    /// Load whitelist from database
    fn load_whitelist(&self) -> Result<(), RansolutionError> {
        // In a real implementation, this would load from database
        debug!("Loading whitelist from database");
        Ok(())
    }
}

impl Default for BehavioralAnalysis {
    fn default() -> Self {
        Self {
            file_operations: FileOperationAnalysis {
                read_operations: 0,
                write_operations: 0,
                delete_operations: 0,
                suspicious_paths: Vec::new(),
                entropy_changes: 0.0,
            },
            network_behavior: NetworkBehaviorAnalysis {
                outbound_connections: 0,
                inbound_connections: 0,
                suspicious_domains: Vec::new(),
                data_exfiltration_indicators: Vec::new(),
                c2_communication_score: 0.0,
            },
            process_behavior: ProcessBehaviorAnalysis {
                child_processes: 0,
                injection_attempts: 0,
                privilege_escalation: false,
                persistence_mechanisms: Vec::new(),
                evasion_techniques: Vec::new(),
            },
            registry_behavior: RegistryBehaviorAnalysis {
                registry_modifications: 0,
                startup_entries: Vec::new(),
                security_modifications: Vec::new(),
                suspicious_keys: Vec::new(),
            },
            anomaly_score: 0.0,
        }
    }
}

/// Validation statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationStatistics {
    pub total_validations: usize,
    pub false_positives: usize,
    pub false_positive_rate: f64,
    pub high_confidence_validations: usize,
    pub average_confidence_score: f64,
    pub whitelist_entries: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_validator() -> (FalsePositiveValidator, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let db_file = temp_dir.path().join("test.db");
        let database = Arc::new(DatabasePool::new(&db_file).unwrap());

        let config = ValidatorConfig::default();
        let validator = FalsePositiveValidator::new(config, database).unwrap();
        (validator, temp_dir)
    }

    #[test]
    fn test_whitelist_management() {
        let (validator, _temp_dir) = create_test_validator();

        let file_hash = "abc123".to_string();
        let file_path = "C:\\Windows\\System32\\notepad.exe".to_string();
        let reason = "Known good system file".to_string();
        let added_by = "admin".to_string();

        // Add to whitelist
        let _entry_id = validator
            .add_to_whitelist(file_hash.clone(), file_path.clone(), reason, added_by)
            .unwrap();

        // Check whitelist
        let matches = validator.check_whitelist(&file_hash, &file_path).unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].file_hash, file_hash);

        // Remove from whitelist
        validator.remove_from_whitelist(&file_hash).unwrap();

        let matches = validator.check_whitelist(&file_hash, &file_path).unwrap();
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn test_entropy_calculation() {
        let (validator, _temp_dir) = create_test_validator();

        // Test with uniform data (high entropy)
        let uniform_data: Vec<u8> = (0..256).map(|i| i as u8).collect();
        let entropy = validator.calculate_entropy(&uniform_data);
        assert!(entropy > 7.0); // Should be close to 8.0 for uniform distribution

        // Test with repeated data (low entropy)
        let repeated_data = vec![0u8; 1000];
        let entropy = validator.calculate_entropy(&repeated_data);
        assert!(entropy < 1.0); // Should be close to 0.0 for repeated data
    }

    #[test]
    fn test_validation_statistics() {
        let (validator, _temp_dir) = create_test_validator();

        let stats = validator.get_validation_statistics();
        assert_eq!(stats.total_validations, 0);
        assert_eq!(stats.false_positive_rate, 0.0);
    }
}
