//! Automated Response Module
//!
//! This module implements automated response capabilities for the ERDPS agent.
//! It provides policy-based response actions for malware detections, including
//! quarantine, alerting, and blocking functionality.
//!
//! Key components:
//! - AutoResponder: Main response coordinator with policy evaluation
//! - ResponseAction: Enumeration of available response actions
//! - ResponsePolicy: TOML-based policy configuration
//! - QuarantineManager: File quarantine and restoration functionality

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Datelike, Timelike, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::fs;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::yara::ember_detector::MalwareScore;

/// Available response actions for malware detections
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ResponseAction {
    /// Quarantine the file by moving it to a secure location
    Quarantine {
        /// Target quarantine directory
        quarantine_dir: PathBuf,
        /// Whether to encrypt the quarantined file
        encrypt: bool,
    },
    /// Generate an alert without taking action on the file
    Alert {
        /// Alert severity level
        severity: AlertSeverity,
        /// Additional alert metadata
        metadata: HashMap<String, String>,
    },
    /// Block file access by setting restrictive permissions
    Block {
        /// Whether to make the block permanent
        permanent: bool,
        /// Backup original permissions for restoration
        _backup_permissions: bool,
    },
    /// Delete the file permanently
    Delete {
        /// Whether to perform secure deletion
        secure: bool,
    },
    /// No action - log only
    LogOnly,
}

/// Alert severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AlertSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Response policy configuration loaded from TOML
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponsePolicy {
    /// Policy name
    pub name: String,
    /// Policy description
    pub description: String,
    /// Policy version
    pub version: String,
    /// Default action for unmatched detections
    pub default_action: ResponseAction,
    /// Rules for specific conditions
    pub rules: Vec<PolicyRule>,
    /// Global settings
    pub settings: PolicySettings,
}

/// Individual policy rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Rule name
    pub name: String,
    /// Rule conditions
    pub conditions: RuleConditions,
    /// Action to take when conditions are met
    pub action: ResponseAction,
    /// Rule priority (higher numbers take precedence)
    pub priority: u32,
    /// Whether the rule is enabled
    pub enabled: bool,
}

/// Conditions for policy rule evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleConditions {
    /// Minimum malware probability threshold
    pub min_probability: Option<f32>,
    /// Maximum malware probability threshold
    pub max_probability: Option<f32>,
    /// File extension patterns
    pub file_extensions: Option<Vec<String>>,
    /// File path patterns
    pub path_patterns: Option<Vec<String>>,
    /// File size constraints
    pub file_size: Option<FileSizeConstraint>,
    /// Suspicious API patterns
    pub suspicious_apis: Option<Vec<String>>,
    /// Time-based constraints
    pub time_constraints: Option<TimeConstraint>,
}

/// File size constraint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSizeConstraint {
    /// Minimum file size in bytes
    pub min_size: Option<u64>,
    /// Maximum file size in bytes
    pub max_size: Option<u64>,
}

/// Time-based constraint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeConstraint {
    /// Allowed hours (0-23)
    pub allowed_hours: Option<Vec<u8>>,
    /// Allowed days of week (0=Sunday, 6=Saturday)
    pub allowed_days: Option<Vec<u8>>,
}

/// Global policy settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySettings {
    /// Default quarantine directory
    pub quarantine_dir: PathBuf,
    /// Maximum quarantine retention days
    pub quarantine_retention_days: u32,
    /// Enable automatic cleanup of quarantine
    pub auto_cleanup: bool,
    /// Log all actions to database
    pub log_actions: bool,
    /// Notification settings
    pub notifications: NotificationSettings,
}

/// Notification configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationSettings {
    /// Enable email notifications
    pub email_enabled: bool,
    /// Email recipients
    pub email_recipients: Vec<String>,
    /// Enable webhook notifications
    pub webhook_enabled: bool,
    /// Webhook URL
    pub webhook_url: Option<String>,
}

/// Response execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseResult {
    /// Unique response ID
    pub id: Uuid,
    /// File path that was processed
    pub file_path: PathBuf,
    /// Action that was taken
    pub action: ResponseAction,
    /// Execution status
    pub status: ResponseStatus,
    /// Timestamp of response
    pub timestamp: DateTime<Utc>,
    /// Error message if failed
    pub error_message: Option<String>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Response execution status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ResponseStatus {
    Success,
    Failed,
    Partial,
    Skipped,
}

/// Quarantined file information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantinedFile {
    /// Unique quarantine ID
    pub id: Uuid,
    /// Original file path
    pub original_path: PathBuf,
    /// Quarantine file path
    pub quarantine_path: PathBuf,
    /// Quarantine timestamp
    pub quarantined_at: DateTime<Utc>,
    /// Original file hash
    pub file_hash: String,
    /// Original file size
    pub file_size: u64,
    /// Malware score that triggered quarantine
    pub malware_score: f32,
    /// Whether file is encrypted in quarantine
    pub encrypted: bool,
}

/// Main automated response coordinator
pub struct AutoResponder {
    /// Current response policy
    policy: ResponsePolicy,
    /// Quarantine manager
    quarantine_manager: QuarantineManager,
    /// Response history
    response_history: Vec<ResponseResult>,
}

/// Quarantine file manager
pub struct QuarantineManager {
    /// Base quarantine directory
    quarantine_dir: PathBuf,
    /// Quarantined files registry
    quarantined_files: HashMap<Uuid, QuarantinedFile>,
    /// Encryption key for quarantined files
    encryption_key: Option<Vec<u8>>,
}

impl AutoResponder {
    /// Create a new AutoResponder with the given policy
    pub fn new(policy: ResponsePolicy) -> Result<Self> {
        let quarantine_manager = QuarantineManager::new(policy.settings.quarantine_dir.clone())?;

        Ok(Self {
            policy,
            quarantine_manager,
            response_history: Vec::new(),
        })
    }

    /// Load response policy from TOML file
    pub async fn load_policy(policy_path: &Path) -> Result<ResponsePolicy> {
        info!("Loading response policy from: {:?}", policy_path);

        let policy_content = fs::read_to_string(policy_path)
            .await
            .context("Failed to read policy file")?;

        let policy: ResponsePolicy =
            toml::from_str(&policy_content).context("Failed to parse policy TOML")?;

        info!("Loaded policy '{}' version {}", policy.name, policy.version);
        Ok(policy)
    }

    /// Evaluate malware detection and execute appropriate response
    pub async fn respond_to_detection(
        &mut self,
        malware_score: &MalwareScore,
    ) -> Result<ResponseResult> {
        debug!(
            "Evaluating response for file: {:?}",
            malware_score.file_info.path
        );

        // Find matching policy rule
        let action = self.evaluate_policy(malware_score)?;

        // Execute the determined action
        let result = self.execute_action(&action, malware_score).await?;

        // Store result in history
        self.response_history.push(result.clone());

        // Log action if enabled
        if self.policy.settings.log_actions {
            self.log_response(&result).await?;
        }

        // Send notifications if configured
        self.send_notifications(&result).await?;

        Ok(result)
    }

    /// Evaluate policy rules to determine appropriate action
    fn evaluate_policy(&self, malware_score: &MalwareScore) -> Result<ResponseAction> {
        debug!(
            "Evaluating policy rules for malware score: {:.4}",
            malware_score.probability
        );

        // Sort rules by priority (highest first)
        let mut sorted_rules = self.policy.rules.clone();
        sorted_rules.sort_by(|a, b| b.priority.cmp(&a.priority));

        // Evaluate rules in priority order
        for rule in &sorted_rules {
            if !rule.enabled {
                continue;
            }

            if self.evaluate_rule_conditions(&rule.conditions, malware_score)? {
                info!(
                    "Policy rule '{}' matched, action: {:?}",
                    rule.name, rule.action
                );
                return Ok(rule.action.clone());
            }
        }

        // No rules matched, use default action
        info!(
            "No policy rules matched, using default action: {:?}",
            self.policy.default_action
        );
        Ok(self.policy.default_action.clone())
    }

    /// Evaluate individual rule conditions
    fn evaluate_rule_conditions(
        &self,
        conditions: &RuleConditions,
        malware_score: &MalwareScore,
    ) -> Result<bool> {
        // Check probability thresholds
        if let Some(min_prob) = conditions.min_probability {
            if malware_score.probability < min_prob {
                return Ok(false);
            }
        }

        if let Some(max_prob) = conditions.max_probability {
            if malware_score.probability > max_prob {
                return Ok(false);
            }
        }

        // Check file extension
        if let Some(ref extensions) = conditions.file_extensions {
            if let Some(ref ext) = malware_score.file_info.extension {
                if !extensions.iter().any(|e| e.eq_ignore_ascii_case(ext)) {
                    return Ok(false);
                }
            } else {
                return Ok(false);
            }
        }

        // Check path patterns
        if let Some(ref patterns) = conditions.path_patterns {
            let path_str = malware_score.file_info.path.to_string_lossy();
            if !patterns.iter().any(|pattern| path_str.contains(pattern)) {
                return Ok(false);
            }
        }

        // Check file size constraints
        if let Some(ref size_constraint) = conditions.file_size {
            if let Some(min_size) = size_constraint.min_size {
                if malware_score.file_info.size < min_size {
                    return Ok(false);
                }
            }

            if let Some(max_size) = size_constraint.max_size {
                if malware_score.file_info.size > max_size {
                    return Ok(false);
                }
            }
        }

        // Check suspicious APIs
        if let Some(ref api_patterns) = conditions.suspicious_apis {
            if let Some(ref pe_features) = malware_score.pe_features {
                let has_suspicious_api = api_patterns.iter().any(|pattern| {
                    pe_features
                        .imports
                        .suspicious_apis
                        .iter()
                        .any(|api| api.contains(pattern))
                });

                if !has_suspicious_api {
                    return Ok(false);
                }
            } else {
                return Ok(false);
            }
        }

        // Check time constraints
        if let Some(ref time_constraint) = conditions.time_constraints {
            let now = Utc::now();

            if let Some(ref allowed_hours) = time_constraint.allowed_hours {
                let current_hour = now.hour() as u8;
                if !allowed_hours.contains(&current_hour) {
                    return Ok(false);
                }
            }

            if let Some(ref allowed_days) = time_constraint.allowed_days {
                let current_day = now.weekday().num_days_from_sunday() as u8;
                if !allowed_days.contains(&current_day) {
                    return Ok(false);
                }
            }
        }

        Ok(true)
    }

    /// Execute the determined response action
    async fn execute_action(
        &mut self,
        action: &ResponseAction,
        malware_score: &MalwareScore,
    ) -> Result<ResponseResult> {
        let response_id = Uuid::new_v4();
        let timestamp = Utc::now();
        let file_path = malware_score.file_info.path.clone();

        info!("Executing action {:?} for file: {:?}", action, file_path);

        let (status, error_message) = match action {
            ResponseAction::Quarantine {
                quarantine_dir,
                encrypt,
            } => {
                match self
                    .quarantine_manager
                    .quarantine_file(&file_path, Some(quarantine_dir), *encrypt, malware_score)
                    .await
                {
                    Ok(_) => (ResponseStatus::Success, None),
                    Err(e) => {
                        error!("Quarantine failed: {}", e);
                        (ResponseStatus::Failed, Some(e.to_string()))
                    }
                }
            }

            ResponseAction::Alert { severity, metadata } => {
                match self.generate_alert(severity, metadata, malware_score).await {
                    Ok(_) => (ResponseStatus::Success, None),
                    Err(e) => {
                        error!("Alert generation failed: {}", e);
                        (ResponseStatus::Failed, Some(e.to_string()))
                    }
                }
            }

            ResponseAction::Block {
                permanent,
                _backup_permissions,
            } => {
                match self
                    .block_file(&file_path, *permanent, *_backup_permissions)
                    .await
                {
                    Ok(_) => (ResponseStatus::Success, None),
                    Err(e) => {
                        error!("File blocking failed: {}", e);
                        (ResponseStatus::Failed, Some(e.to_string()))
                    }
                }
            }

            ResponseAction::Delete { secure } => {
                match self.delete_file(&file_path, *secure).await {
                    Ok(_) => (ResponseStatus::Success, None),
                    Err(e) => {
                        error!("File deletion failed: {}", e);
                        (ResponseStatus::Failed, Some(e.to_string()))
                    }
                }
            }

            ResponseAction::LogOnly => {
                info!("Log-only action for file: {:?}", file_path);
                (ResponseStatus::Success, None)
            }
        };

        Ok(ResponseResult {
            id: response_id,
            file_path,
            action: action.clone(),
            status,
            timestamp,
            error_message,
            metadata: HashMap::new(),
        })
    }

    /// Generate alert for malware detection
    async fn generate_alert(
        &self,
        severity: &AlertSeverity,
        _metadata: &HashMap<String, String>,
        malware_score: &MalwareScore,
    ) -> Result<()> {
        info!(
            "Generating {:?} severity alert for file: {:?}",
            severity, malware_score.file_info.path
        );

        // TODO: Implement actual alerting mechanism
        // This could integrate with SIEM, email, webhooks, etc.

        Ok(())
    }

    /// Block file access by modifying permissions
    async fn block_file(
        &self,
        file_path: &Path,
        permanent: bool,
        _backup_permissions: bool,
    ) -> Result<()> {
        info!(
            "Blocking file access: {:?} (permanent: {})",
            file_path, permanent
        );

        // TODO: Implement file blocking logic
        // This would modify file permissions to prevent access

        Ok(())
    }

    /// Delete file securely or normally
    async fn delete_file(&self, file_path: &Path, secure: bool) -> Result<()> {
        info!("Deleting file: {:?} (secure: {})", file_path, secure);

        if secure {
            // TODO: Implement secure deletion (overwrite with random data)
            warn!("Secure deletion not yet implemented, using normal deletion");
        }

        fs::remove_file(file_path)
            .await
            .context("Failed to delete file")?;

        Ok(())
    }

    /// Log response action to database
    async fn log_response(&self, result: &ResponseResult) -> Result<()> {
        debug!("Logging response action: {:?}", result.id);

        // TODO: Implement database logging
        // This would store the response result in the database

        Ok(())
    }

    /// Send notifications based on configuration
    async fn send_notifications(&self, result: &ResponseResult) -> Result<()> {
        let notifications = &self.policy.settings.notifications;

        if notifications.email_enabled && !notifications.email_recipients.is_empty() {
            // TODO: Implement email notifications
            debug!(
                "Would send email notification for response: {:?}",
                result.id
            );
        }

        if notifications.webhook_enabled {
            if let Some(ref webhook_url) = notifications.webhook_url {
                // TODO: Implement webhook notifications
                debug!("Would send webhook notification to: {}", webhook_url);
            }
        }

        Ok(())
    }

    /// Get response history
    pub fn get_response_history(&self) -> &[ResponseResult] {
        &self.response_history
    }

    /// Get quarantine manager
    pub fn get_quarantine_manager(&self) -> &QuarantineManager {
        &self.quarantine_manager
    }
}

impl QuarantineManager {
    /// Create a new quarantine manager
    pub fn new(quarantine_dir: PathBuf) -> Result<Self> {
        // Ensure quarantine directory exists
        std::fs::create_dir_all(&quarantine_dir)
            .context("Failed to create quarantine directory")?;

        Ok(Self {
            quarantine_dir,
            quarantined_files: HashMap::new(),
            encryption_key: None, // TODO: Generate or load encryption key
        })
    }

    /// Quarantine a file
    pub async fn quarantine_file(
        &mut self,
        file_path: &Path,
        custom_quarantine_dir: Option<&PathBuf>,
        encrypt: bool,
        malware_score: &MalwareScore,
    ) -> Result<Uuid> {
        let quarantine_id = Uuid::new_v4();
        let quarantine_dir = custom_quarantine_dir.unwrap_or(&self.quarantine_dir);

        // Create quarantine subdirectory with timestamp
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
        let quarantine_subdir = quarantine_dir.join(format!("quarantine_{}", timestamp));
        fs::create_dir_all(&quarantine_subdir)
            .await
            .context("Failed to create quarantine subdirectory")?;

        // Generate quarantine filename
        let original_filename = file_path
            .file_name()
            .ok_or_else(|| anyhow!("Invalid file path"))?;
        let quarantine_filename =
            format!("{}_{}", quarantine_id, original_filename.to_string_lossy());
        let quarantine_path = quarantine_subdir.join(quarantine_filename);

        // Move file to quarantine
        fs::rename(file_path, &quarantine_path)
            .await
            .context("Failed to move file to quarantine")?;

        // Encrypt if requested
        if encrypt {
            // TODO: Implement file encryption
            warn!("File encryption in quarantine not yet implemented");
        }

        // Calculate file hash
        let file_data = fs::read(&quarantine_path)
            .await
            .context("Failed to read quarantined file for hashing")?;
        let file_hash = format!("{:x}", md5::compute(&file_data));

        // Create quarantine record
        let quarantined_file = QuarantinedFile {
            id: quarantine_id,
            original_path: file_path.to_path_buf(),
            quarantine_path,
            quarantined_at: Utc::now(),
            file_hash,
            file_size: malware_score.file_info.size,
            malware_score: malware_score.probability,
            encrypted: encrypt,
        };

        self.quarantined_files
            .insert(quarantine_id, quarantined_file);

        info!(
            "File quarantined successfully: {:?} -> {:?}",
            file_path, quarantine_id
        );

        Ok(quarantine_id)
    }

    /// Restore a quarantined file
    pub async fn restore_file(&mut self, quarantine_id: Uuid) -> Result<PathBuf> {
        let quarantined_file = self
            .quarantined_files
            .get(&quarantine_id)
            .ok_or_else(|| anyhow!("Quarantined file not found: {}", quarantine_id))?;

        let original_path = quarantined_file.original_path.clone();
        let quarantine_path = quarantined_file.quarantine_path.clone();

        // Decrypt if necessary
        if quarantined_file.encrypted {
            // TODO: Implement file decryption
            warn!("File decryption not yet implemented");
        }

        // Restore file to original location
        fs::rename(&quarantine_path, &original_path)
            .await
            .context("Failed to restore file from quarantine")?;

        // Remove from quarantine registry
        self.quarantined_files.remove(&quarantine_id);

        info!(
            "File restored successfully: {:?} -> {:?}",
            quarantine_id, original_path
        );

        Ok(original_path)
    }

    /// List all quarantined files
    pub fn list_quarantined_files(&self) -> Vec<&QuarantinedFile> {
        self.quarantined_files.values().collect()
    }

    /// Clean up old quarantined files
    pub async fn cleanup_old_files(&mut self, retention_days: u32) -> Result<usize> {
        let cutoff_date = Utc::now() - chrono::Duration::days(retention_days as i64);
        let mut removed_count = 0;

        let mut to_remove = Vec::new();

        for (id, file) in &self.quarantined_files {
            if file.quarantined_at < cutoff_date {
                to_remove.push(*id);
            }
        }

        for id in to_remove {
            if let Some(file) = self.quarantined_files.remove(&id) {
                if let Err(e) = fs::remove_file(&file.quarantine_path).await {
                    warn!(
                        "Failed to remove old quarantined file {:?}: {}",
                        file.quarantine_path, e
                    );
                } else {
                    removed_count += 1;
                }
            }
        }

        info!("Cleaned up {} old quarantined files", removed_count);
        Ok(removed_count)
    }
}

/// Default response policy for testing and initial setup
pub fn create_default_policy(quarantine_dir: PathBuf) -> ResponsePolicy {
    ResponsePolicy {
        name: "Default ERDPS Policy".to_string(),
        description: "Default automated response policy for ERDPS".to_string(),
        version: "1.0.0".to_string(),
        default_action: ResponseAction::Alert {
            severity: AlertSeverity::Medium,
            metadata: HashMap::new(),
        },
        rules: vec![
            PolicyRule {
                name: "High Confidence Malware".to_string(),
                conditions: RuleConditions {
                    min_probability: Some(0.8),
                    max_probability: None,
                    file_extensions: None,
                    path_patterns: None,
                    file_size: None,
                    suspicious_apis: None,
                    time_constraints: None,
                },
                action: ResponseAction::Quarantine {
                    quarantine_dir: quarantine_dir.clone(),
                    encrypt: true,
                },
                priority: 100,
                enabled: true,
            },
            PolicyRule {
                name: "Executable Files Medium Risk".to_string(),
                conditions: RuleConditions {
                    min_probability: Some(0.5),
                    max_probability: Some(0.8),
                    file_extensions: Some(vec![
                        "exe".to_string(),
                        "dll".to_string(),
                        "scr".to_string(),
                    ]),
                    path_patterns: None,
                    file_size: None,
                    suspicious_apis: None,
                    time_constraints: None,
                },
                action: ResponseAction::Block {
                    permanent: false,
                    _backup_permissions: true,
                },
                priority: 50,
                enabled: true,
            },
        ],
        settings: PolicySettings {
            quarantine_dir,
            quarantine_retention_days: 30,
            auto_cleanup: true,
            log_actions: true,
            notifications: NotificationSettings {
                email_enabled: false,
                email_recipients: vec![],
                webhook_enabled: false,
                webhook_url: None,
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::yara::ember_detector::{FileInfo, ModelInfo};
    use tempfile::TempDir;

    fn create_test_malware_score(probability: f32, file_path: PathBuf) -> MalwareScore {
        MalwareScore {
            probability,
            is_malware: probability > 0.5,
            features: vec![0.0; 2381],
            pe_features: None,
            file_info: FileInfo {
                size: 1024,
                path: file_path,
                hash: None,
                extension: Some("exe".to_string()),
                created: None,
                modified: None,
            },
            model_info: ModelInfo {
                version: "1.0.0".to_string(),
                path: PathBuf::from("test_model.onnx"),
                threshold: 0.5,
                feature_count: 2381,
                model_type: crate::yara::ember_detector::ModelType::Heuristic,
                performance: crate::yara::ember_detector::ModelPerformance {
                    accuracy: 0.95,
                    false_positive_rate: 0.01,
                    true_positive_rate: 0.94,
                    precision: 0.96,
                    f1_score: 0.95,
                },
            },
            confidence: 0.8,
            timestamp: chrono::Utc::now(),
        }
    }

    #[tokio::test]
    async fn test_policy_evaluation() {
        let temp_dir = TempDir::new().unwrap();
        let policy = create_default_policy(temp_dir.path().to_path_buf());
        let mut responder = AutoResponder::new(policy).unwrap();

        // Create a test file to quarantine
        let test_file_path = temp_dir.path().join("test.exe");
        fs::write(&test_file_path, b"test malware content")
            .await
            .unwrap();

        // Test high confidence detection
        let high_score = create_test_malware_score(0.9, test_file_path);
        let result = responder.respond_to_detection(&high_score).await.unwrap();

        match result.action {
            ResponseAction::Quarantine { .. } => {}
            _ => panic!("Expected quarantine action for high confidence detection"),
        }

        assert_eq!(result.status, ResponseStatus::Success);
    }

    #[tokio::test]
    async fn test_quarantine_manager() {
        let temp_dir = TempDir::new().unwrap();
        let mut manager = QuarantineManager::new(temp_dir.path().to_path_buf()).unwrap();

        // Create a test file
        let test_file_path = temp_dir.path().join("test_malware.exe");
        fs::write(&test_file_path, b"test malware content")
            .await
            .unwrap();

        let malware_score = create_test_malware_score(0.9, test_file_path.clone());

        // Quarantine the file
        let quarantine_id = manager
            .quarantine_file(&test_file_path, None, false, &malware_score)
            .await
            .unwrap();

        // Verify file was moved
        assert!(!test_file_path.exists());
        assert_eq!(manager.list_quarantined_files().len(), 1);

        // Restore the file
        let restored_path = manager.restore_file(quarantine_id).await.unwrap();
        assert_eq!(restored_path, test_file_path);
        assert!(test_file_path.exists());
        assert_eq!(manager.list_quarantined_files().len(), 0);
    }

    #[test]
    fn test_rule_condition_evaluation() {
        let temp_dir = TempDir::new().unwrap();
        let policy = create_default_policy(temp_dir.path().to_path_buf());
        let responder = AutoResponder::new(policy).unwrap();

        let conditions = RuleConditions {
            min_probability: Some(0.7),
            max_probability: Some(0.9),
            file_extensions: Some(vec!["exe".to_string()]),
            path_patterns: None,
            file_size: Some(FileSizeConstraint {
                min_size: Some(100),
                max_size: Some(10000),
            }),
            suspicious_apis: None,
            time_constraints: None,
        };

        // Test matching conditions
        let matching_score = create_test_malware_score(0.8, PathBuf::from("test.exe"));
        assert!(responder
            .evaluate_rule_conditions(&conditions, &matching_score)
            .unwrap());

        // Test non-matching probability
        let low_prob_score = create_test_malware_score(0.5, PathBuf::from("test.exe"));
        assert!(!responder
            .evaluate_rule_conditions(&conditions, &low_prob_score)
            .unwrap());
    }
}
