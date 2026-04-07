//! False Positive Validation Framework
//!
//! This module provides comprehensive false positive testing and validation for ERDPS production deployment.
//! It includes benign sample testing, whitelist management, and detection accuracy measurement.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};
use tokio::fs;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use sqlite::{Connection, State};
use log::{info, warn, error, debug};
use chrono::Utc;
use sha2::Digest;
use crate::validation::metrics::{DetectionMetrics, MemoryUsageSample, CpuUsageSample};
use crate::validation::malware_testing::MalwareSampleManager;

/// Errors that can occur during false positive validation
#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("Sample validation failed: {0}")]
    ValidationFailed(String),
    #[error("Whitelist operation failed: {0}")]
    WhitelistError(String),
    #[error("Baseline creation failed: {0}")]
    BaselineError(String),
    #[error("Threshold exceeded: {0}")]
    ThresholdExceeded(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    #[error("Database error: {0}")]
    DatabaseError(String),
}

/// Benign sample for false positive testing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenignSample {
    pub id: Uuid,
    pub name: String,
    pub file_path: PathBuf,
    pub hash_sha256: String,
    pub file_size: u64,
    pub file_type: FileType,
    pub source: String,
    pub category: SampleCategory,
    pub expected_clean: bool,
    pub validation_history: Vec<ValidationResult>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// File types for categorization
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum FileType {
    Executable,
    Document,
    Archive,
    Script,
    Image,
    Video,
    Audio,
    System,
    Library,
    Other(String),
}

/// Sample categories for testing
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SampleCategory {
    SystemFiles,
    LegitimateApplications,
    DevelopmentTools,
    SecurityTools,
    CompressedFiles,
    EncryptedFiles,
    UserDocuments,
    MediaFiles,
    CustomCategory(String),
}

/// Validation result for a sample
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub sample_id: Uuid,
    pub validation_time: chrono::DateTime<chrono::Utc>,
    pub detected_as_malicious: bool,
    pub detection_confidence: f64,
    pub detection_methods: Vec<String>,
    pub false_positive: bool,
    pub validation_duration: Duration,
    pub notes: Option<String>,
}

/// Whitelist entry for known good files
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhitelistEntry {
    pub id: Uuid,
    pub hash_sha256: String,
    pub file_path: Option<PathBuf>,
    pub description: String,
    pub category: WhitelistCategory,
    pub added_by: String,
    pub added_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub validation_count: u64,
}

/// Whitelist categories
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum WhitelistCategory {
    SystemBinary,
    TrustedApplication,
    DevelopmentTool,
    SecurityTool,
    UserApplication,
    CustomTrusted(String),
}

/// False positive testing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FalsePositiveConfig {
    pub benign_samples_directory: PathBuf,
    pub whitelist_file: PathBuf,
    pub baseline_directory: PathBuf,
    pub max_false_positive_rate: f64,
    pub validation_timeout_seconds: u64,
    pub enable_automatic_whitelisting: bool,
    pub confidence_threshold: f64,
    pub sample_sources: Vec<SampleSource>,
}

/// External sample sources for benign files
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SampleSource {
    pub name: String,
    pub source_type: SourceType,
    pub path_or_url: String,
    pub enabled: bool,
    pub update_interval_hours: u64,
}

/// SLO monitoring thresholds
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SloThresholds {
    /// Maximum acceptable false positive rate (0.001 = 0.1%)
    pub max_false_positive_rate: f64,
    /// Maximum mean time to detection in seconds (60s)
    pub max_mttd_seconds: u64,
    /// Minimum detection accuracy (0.999 = 99.9%)
    pub min_accuracy: f64,
    /// Maximum validation time per sample in milliseconds
    pub max_validation_time_ms: u64,
}

/// Current SLO compliance status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SloStatus {
    /// Current false positive rate
    pub current_false_positive_rate: f64,
    /// Current mean time to detection
    pub current_mttd_seconds: u64,
    /// Current detection accuracy
    pub current_accuracy: f64,
    /// Average validation time
    pub avg_validation_time_ms: u64,
    /// SLO compliance status
    pub is_compliant: bool,
    /// Last compliance check timestamp
    pub last_check: chrono::DateTime<chrono::Utc>,
    /// Violations in the last 24 hours
    pub violations_24h: u32,
}

/// SLO violation details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SloViolation {
    pub violation_id: Uuid,
    pub violation_type: SloViolationType,
    pub threshold_value: f64,
    pub actual_value: f64,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub severity: ViolationSeverity,
    pub description: String,
}

/// Types of SLO violations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SloViolationType {
    FalsePositiveRate,
    MeanTimeToDetection,
    DetectionAccuracy,
    ValidationTime,
}

impl std::fmt::Display for SloViolationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SloViolationType::FalsePositiveRate => write!(f, "false_positive_rate"),
            SloViolationType::MeanTimeToDetection => write!(f, "mean_time_to_detection"),
            SloViolationType::DetectionAccuracy => write!(f, "detection_accuracy"),
            SloViolationType::ValidationTime => write!(f, "validation_time"),
        }
    }
}

/// Severity levels for SLO violations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ViolationSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Types of sample sources
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SourceType {
    LocalDirectory,
    NetworkShare,
    HttpDownload,
    SystemScan,
}

/// Validation statistics and metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationStatistics {
    pub total_samples_tested: u64,
    pub false_positives_detected: u64,
    pub true_negatives: u64,
    pub false_positive_rate: f64,
    pub accuracy: f64,
    pub average_validation_time: Duration,
    pub by_file_type: HashMap<FileType, TypeStatistics>,
    pub by_category: HashMap<SampleCategory, CategoryStatistics>,
    pub validation_history: Vec<ValidationBatch>,
}

/// Statistics by file type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeStatistics {
    pub total_samples: u64,
    pub false_positives: u64,
    pub false_positive_rate: f64,
}

/// Statistics by sample category
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryStatistics {
    pub total_samples: u64,
    pub false_positives: u64,
    pub false_positive_rate: f64,
}

/// Batch validation results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationBatch {
    pub batch_id: Uuid,
    pub start_time: chrono::DateTime<chrono::Utc>,
    pub end_time: chrono::DateTime<chrono::Utc>,
    pub samples_tested: u64,
    pub false_positives: u64,
    pub batch_false_positive_rate: f64,
}

/// Main false positive validator
#[derive(Debug)]
pub struct FalsePositiveValidator {
    pub config: FalsePositiveConfig,
    pub benign_samples: HashMap<Uuid, BenignSample>,
    pub whitelist: HashMap<String, WhitelistEntry>, // SHA256 -> Entry
    pub statistics: ValidationStatistics,
    /// Database connection for metrics storage
    pub db_connection: Option<Connection>,
    /// Sample manager for database operations
    pub sample_manager: Option<MalwareSampleManager>,
    /// SLO monitoring thresholds
    pub slo_thresholds: SloThresholds,
    /// Current SLO compliance status
    pub slo_status: SloStatus,
}

impl FalsePositiveValidator {
    /// Create a new false positive validator
    pub fn new(config: FalsePositiveConfig) -> Self {
        let slo_thresholds = SloThresholds {
            max_false_positive_rate: 0.001, // 0.1%
            max_mttd_seconds: 60,
            min_accuracy: 0.999, // 99.9%
            max_validation_time_ms: 5000, // 5 seconds
        };
        
        let slo_status = SloStatus {
            current_false_positive_rate: 0.0,
            current_mttd_seconds: 0,
            current_accuracy: 1.0,
            avg_validation_time_ms: 0,
            is_compliant: true,
            last_check: Utc::now(),
            violations_24h: 0,
        };
        
        Self {
            config,
            benign_samples: HashMap::new(),
            whitelist: HashMap::new(),
            statistics: ValidationStatistics::new(),
            db_connection: None,
            sample_manager: None,
            slo_thresholds,
            slo_status,
        }
    }
    
    /// Create a new validator with database connection
    pub fn new_with_database(config: FalsePositiveConfig, db_path: &str) -> Result<Self, ValidationError> {
        let mut validator = Self::new(config);
        
        // Initialize database connection
        let connection = Connection::open(db_path)
            .map_err(|e| ValidationError::DatabaseError(format!("Failed to open database: {}", e)))?;
        
        // Initialize sample manager
        let sample_manager = MalwareSampleManager::new(db_path.to_string())
            .map_err(|e| ValidationError::DatabaseError(format!("Failed to create sample manager: {}", e)))?;
        
        validator.db_connection = Some(connection);
        validator.sample_manager = Some(sample_manager);
        
        Ok(validator)
    }

    /// Initialize the validator with sample loading and baseline creation
    pub async fn initialize(&mut self) -> Result<(), ValidationError> {
        // Create necessary directories
        fs::create_dir_all(&self.config.benign_samples_directory).await?;
        fs::create_dir_all(&self.config.baseline_directory).await?;

        // Load existing whitelist
        self.load_whitelist().await?;

        // Load benign samples
        self.load_benign_samples().await?;

        // Update samples from sources
        self.update_samples_from_sources().await?;

        // Create baseline if needed
        self.create_baseline().await?;

        Ok(())
    }

    /// Load whitelist from file
    pub async fn load_whitelist(&mut self) -> Result<(), ValidationError> {
        if self.config.whitelist_file.exists() {
            let content = fs::read_to_string(&self.config.whitelist_file).await?;
            let whitelist_entries: Vec<WhitelistEntry> = serde_json::from_str(&content)?;
            
            for entry in whitelist_entries {
                self.whitelist.insert(entry.hash_sha256.clone(), entry);
            }
        }
        Ok(())
    }

    /// Save whitelist to file
    pub async fn save_whitelist(&self) -> Result<(), ValidationError> {
        let entries: Vec<&WhitelistEntry> = self.whitelist.values().collect();
        let content = serde_json::to_string_pretty(&entries)?;
        fs::write(&self.config.whitelist_file, content).await?;
        Ok(())
    }

    /// Load benign samples from directory
    pub async fn load_benign_samples(&mut self) -> Result<(), ValidationError> {
        let mut entries = fs::read_dir(&self.config.benign_samples_directory).await?;
        
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            
            if path.is_file() {
                if let Ok(sample) = self.create_benign_sample_from_file(&path).await {
                    self.benign_samples.insert(sample.id, sample);
                }
            }
        }
        
        Ok(())
    }

    /// Create a benign sample from file
    async fn create_benign_sample_from_file(&self, file_path: &Path) -> Result<BenignSample, ValidationError> {
        let metadata = fs::metadata(file_path).await?;
        let file_data = fs::read(file_path).await?;
        
        // Calculate SHA256 hash
        let sha256_hash = format!("{:x}", sha2::Sha256::digest(&file_data));
        
        // Determine file type
        let file_type = self.determine_file_type(file_path);
        
        // Determine category
        let category = self.determine_sample_category(file_path, &file_type);
        
        let sample = BenignSample {
            id: Uuid::new_v4(),
            name: file_path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown")
                .to_string(),
            file_path: file_path.to_path_buf(),
            hash_sha256: sha256_hash,
            file_size: metadata.len(),
            file_type,
            source: "local".to_string(),
            category,
            expected_clean: true,
            validation_history: Vec::new(),
            created_at: chrono::Utc::now(),
        };
        
        Ok(sample)
    }

    /// Determine file type from path and content
    fn determine_file_type(&self, file_path: &Path) -> FileType {
        if let Some(extension) = file_path.extension().and_then(|e| e.to_str()) {
            match extension.to_lowercase().as_str() {
                "exe" | "msi" | "com" | "scr" | "bat" | "cmd" => FileType::Executable,
                "doc" | "docx" | "pdf" | "txt" | "rtf" | "xls" | "xlsx" | "ppt" | "pptx" => FileType::Document,
                "zip" | "rar" | "7z" | "tar" | "gz" | "bz2" => FileType::Archive,
                "js" | "vbs" | "ps1" | "py" | "pl" | "sh" => FileType::Script,
                "jpg" | "jpeg" | "png" | "gif" | "bmp" | "tiff" => FileType::Image,
                "mp4" | "avi" | "mkv" | "mov" | "wmv" | "flv" => FileType::Video,
                "mp3" | "wav" | "flac" | "aac" | "ogg" => FileType::Audio,
                "sys" | "dll" | "drv" => FileType::System,
                "lib" | "a" | "so" | "dylib" => FileType::Library,
                _ => FileType::Other(extension.to_string()),
            }
        } else {
            FileType::Other("no_extension".to_string())
        }
    }

    /// Determine sample category
    fn determine_sample_category(&self, file_path: &Path, file_type: &FileType) -> SampleCategory {
        let path_str = file_path.to_string_lossy().to_lowercase();
        
        if path_str.contains("system32") || path_str.contains("windows") {
            return SampleCategory::SystemFiles;
        }
        
        if path_str.contains("program files") {
            return SampleCategory::LegitimateApplications;
        }
        
        if path_str.contains("visual studio") || path_str.contains("git") || path_str.contains("node_modules") {
            return SampleCategory::DevelopmentTools;
        }
        
        if path_str.contains("antivirus") || path_str.contains("security") {
            return SampleCategory::SecurityTools;
        }
        
        match file_type {
            FileType::Archive => SampleCategory::CompressedFiles,
            FileType::Document => SampleCategory::UserDocuments,
            FileType::Image | FileType::Video | FileType::Audio => SampleCategory::MediaFiles,
            _ => SampleCategory::LegitimateApplications,
        }
    }

    /// Update samples from external sources
    pub async fn update_samples_from_sources(&mut self) -> Result<(), ValidationError> {
        for source in &self.config.sample_sources {
            if source.enabled {
                if let Err(e) = self.update_from_source(source).await {
                    eprintln!("Failed to update from source {}: {}", source.name, e);
                }
            }
        }
        Ok(())
    }

    /// Update samples from a specific source
    async fn update_from_source(&mut self, source: &SampleSource) -> Result<(), ValidationError> {
        match source.source_type {
            SourceType::LocalDirectory => {
                self.scan_local_directory(&PathBuf::from(&source.path_or_url)).await?
            }
            SourceType::SystemScan => {
                self.perform_system_scan().await?
            }
            _ => {
                // Placeholder for network sources
                println!("Updating from source: {} ({})", source.name, source.path_or_url);
            }
        }
        Ok(())
    }

    /// Scan local directory for benign samples
    async fn scan_local_directory(&mut self, directory: &Path) -> Result<(), ValidationError> {
        if !directory.exists() {
            return Ok(());
        }
        
        let mut entries = fs::read_dir(directory).await?;
        
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            
            if path.is_file() {
                if let Ok(sample) = self.create_benign_sample_from_file(&path).await {
                    // Check if already exists
                    if !self.benign_samples.values().any(|s| s.hash_sha256 == sample.hash_sha256) {
                        self.benign_samples.insert(sample.id, sample);
                    }
                }
            } else if path.is_dir() {
                // Recursively scan subdirectories
                self.scan_local_directory(&path).await?;
            }
        }
        
        Ok(())
    }

    /// Perform system scan for common benign files
    async fn perform_system_scan(&mut self) -> Result<(), ValidationError> {
        let system_paths = vec![
            PathBuf::from("C:\\Windows\\System32"),
            PathBuf::from("C:\\Program Files"),
            PathBuf::from("C:\\Program Files (x86)"),
        ];
        
        for path in system_paths {
            if path.exists() {
                // Scan only top-level files to avoid overwhelming the system
                if let Ok(mut entries) = fs::read_dir(&path).await {
                    let mut count = 0;
                    while let Some(entry) = entries.next_entry().await? {
                        if count >= 100 { // Limit to prevent excessive scanning
                            break;
                        }
                        
                        let file_path = entry.path();
                        if file_path.is_file() {
                            if let Ok(sample) = self.create_benign_sample_from_file(&file_path).await {
                                if !self.benign_samples.values().any(|s| s.hash_sha256 == sample.hash_sha256) {
                                    self.benign_samples.insert(sample.id, sample);
                                }
                            }
                            count += 1;
                        }
                    }
                }
            }
        }
        
        Ok(())
    }

    /// Create baseline of known good files
    pub async fn create_baseline(&mut self) -> Result<(), ValidationError> {
        let baseline_file = self.config.baseline_directory.join("baseline.json");
        
        // Create baseline from current benign samples
        let baseline_data = serde_json::json!({
            "created_at": chrono::Utc::now(),
            "sample_count": self.benign_samples.len(),
            "samples": self.benign_samples.values().collect::<Vec<_>>(),
        });
        
        let baseline_json = serde_json::to_string_pretty(&baseline_data)?;
        fs::write(baseline_file, baseline_json).await?;
        
        Ok(())
    }

    /// Validate a single sample against detection engine
    pub async fn validate_sample(&mut self, sample_id: &Uuid) -> Result<ValidationResult, ValidationError> {
        let sample = self.benign_samples.get(sample_id)
            .ok_or_else(|| ValidationError::ValidationFailed("Sample not found".to_string()))?
            .clone();
        
        let start_time = Instant::now();
        
        // Check whitelist first
        if self.is_whitelisted(&sample.hash_sha256) {
            let result = ValidationResult {
                sample_id: sample.id,
                validation_time: chrono::Utc::now(),
                detected_as_malicious: false,
                detection_confidence: 0.0,
                detection_methods: vec!["whitelist".to_string()],
                false_positive: false,
                validation_duration: start_time.elapsed(),
                notes: Some("Whitelisted file".to_string()),
            };
            
            return Ok(result);
        }
        
        // Simulate detection engine validation
        let (detected, confidence, methods) = self.simulate_detection_scan(&sample).await?;
        
        let validation_duration = start_time.elapsed();
        
        // Determine if this is a false positive
        let false_positive = detected && sample.expected_clean;
        
        let result = ValidationResult {
            sample_id: sample.id,
            validation_time: chrono::Utc::now(),
            detected_as_malicious: detected,
            detection_confidence: confidence,
            detection_methods: methods,
            false_positive,
            validation_duration,
            notes: None,
        };
        
        // Update sample history
        if let Some(sample) = self.benign_samples.get_mut(sample_id) {
            sample.validation_history.push(result.clone());
        }
        
        // Update statistics
        self.update_statistics(&result, &sample);
        
        // Store validation result in database if available
        if let Some(ref mut sample_manager) = self.sample_manager {
            if let Err(e) = self.store_validation_result(sample_manager, &result, &sample).await {
                warn!("Failed to store validation result in database: {}", e);
            }
        }
        
        // Auto-whitelist if configured and meets criteria
        if self.config.enable_automatic_whitelisting && 
           !detected && 
           confidence < self.config.confidence_threshold {
            self.add_to_whitelist(&sample, "auto_validation").await?;
        }
        
        // Check for SLO violations after each validation
        if let Err(e) = self.check_slo_compliance().await {
            warn!("SLO compliance check failed: {}", e);
        }
        
        Ok(result)
    }
    
    /// Store validation result in database
    async fn store_validation_result(&self, sample_manager: &mut MalwareSampleManager, 
                                   result: &ValidationResult, sample: &BenignSample) -> Result<(), ValidationError> {
        // Store false positive tracking if it's a false positive
        if result.false_positive {
            sample_manager.store_false_positive_tracking(
                &sample.hash_sha256,
                &sample.file_type.to_string(),
                result.detection_confidence,
                &result.detection_methods.join(","),
                &format!("False positive detected for benign sample: {}", sample.name)
            ).await.map_err(|e| ValidationError::DatabaseError(e.to_string()))?;
        }
        
        // Store performance metrics
        sample_manager.store_performance_metrics(
            result.validation_duration.as_millis() as f64,
            0.0, // CPU usage - would need actual measurement
            0.0, // Memory usage - would need actual measurement
            if result.detected_as_malicious { "detected" } else { "clean" },
            &format!("Validation of sample: {}", sample.name)
        ).await.map_err(|e| ValidationError::DatabaseError(e.to_string()))?;
        
        Ok(())
    }

    /// Simulate detection engine scan
    async fn simulate_detection_scan(&self, sample: &BenignSample) -> Result<(bool, f64, Vec<String>), ValidationError> {
        // Simulate scanning delay
        tokio::time::sleep(Duration::from_millis(50)).await;
        
        // Mock detection logic (in production, integrate with actual ERDPS engine)
        let detected = match sample.file_type {
            FileType::Executable => {
                // Higher chance of false positive for executables
                sample.file_size > 1_000_000 && sample.name.contains("setup")
            }
            FileType::Script => {
                // Scripts might trigger behavioral detection
                sample.name.contains("install") || sample.name.contains("update")
            }
            _ => false, // Most other file types should be clean
        };
        
        let confidence = if detected { 0.7 } else { 0.1 };
        let methods = if detected {
            vec!["heuristic_analysis".to_string(), "behavioral_detection".to_string()]
        } else {
            vec![]
        };
        
        Ok((detected, confidence, methods))
    }

    /// Check if a file hash is whitelisted
    pub fn is_whitelisted(&self, hash: &str) -> bool {
        if let Some(entry) = self.whitelist.get(hash) {
            // Check if whitelist entry has expired
            if let Some(expires_at) = entry.expires_at {
                chrono::Utc::now() < expires_at
            } else {
                true // No expiration
            }
        } else {
            false
        }
    }

    /// Add file to whitelist
    pub async fn add_to_whitelist(&mut self, sample: &BenignSample, added_by: &str) -> Result<(), ValidationError> {
        let entry = WhitelistEntry {
            id: Uuid::new_v4(),
            hash_sha256: sample.hash_sha256.clone(),
            file_path: Some(sample.file_path.clone()),
            description: format!("Auto-whitelisted: {}", sample.name),
            category: self.determine_whitelist_category(&sample.category),
            added_by: added_by.to_string(),
            added_at: chrono::Utc::now(),
            expires_at: None,
            validation_count: 1,
        };
        
        self.whitelist.insert(sample.hash_sha256.clone(), entry);
        self.save_whitelist().await?;
        
        Ok(())
    }

    /// Determine whitelist category from sample category
    fn determine_whitelist_category(&self, sample_category: &SampleCategory) -> WhitelistCategory {
        match sample_category {
            SampleCategory::SystemFiles => WhitelistCategory::SystemBinary,
            SampleCategory::LegitimateApplications => WhitelistCategory::TrustedApplication,
            SampleCategory::DevelopmentTools => WhitelistCategory::DevelopmentTool,
            SampleCategory::SecurityTools => WhitelistCategory::SecurityTool,
            SampleCategory::UserDocuments | SampleCategory::MediaFiles => WhitelistCategory::UserApplication,
            SampleCategory::CustomCategory(name) => WhitelistCategory::CustomTrusted(name.clone()),
            _ => WhitelistCategory::UserApplication,
        }
    }

    /// Update validation statistics
    fn update_statistics(&mut self, result: &ValidationResult, sample: &BenignSample) {
        self.statistics.total_samples_tested += 1;
        
        if result.false_positive {
            self.statistics.false_positives_detected += 1;
        } else {
            self.statistics.true_negatives += 1;
        }
        
        // Update rates
        self.statistics.false_positive_rate = 
            self.statistics.false_positives_detected as f64 / self.statistics.total_samples_tested as f64;
        
        self.statistics.accuracy = 
            self.statistics.true_negatives as f64 / self.statistics.total_samples_tested as f64;
        
        // Update average validation time
        let total_time = self.statistics.average_validation_time * (self.statistics.total_samples_tested - 1) as u32 + result.validation_duration;
        self.statistics.average_validation_time = total_time / self.statistics.total_samples_tested as u32;
        
        // Update by file type
        let type_stats = self.statistics.by_file_type.entry(sample.file_type.clone()).or_insert_with(|| {
            TypeStatistics {
                total_samples: 0,
                false_positives: 0,
                false_positive_rate: 0.0,
            }
        });
        
        type_stats.total_samples += 1;
        if result.false_positive {
            type_stats.false_positives += 1;
        }
        type_stats.false_positive_rate = type_stats.false_positives as f64 / type_stats.total_samples as f64;
        
        // Update by category
        let category_stats = self.statistics.by_category.entry(sample.category.clone()).or_insert_with(|| {
            CategoryStatistics {
                total_samples: 0,
                false_positives: 0,
                false_positive_rate: 0.0,
            }
        });
        
        category_stats.total_samples += 1;
        if result.false_positive {
            category_stats.false_positives += 1;
        }
        category_stats.false_positive_rate = category_stats.false_positives as f64 / category_stats.total_samples as f64;
    }

    /// Run batch validation on all samples
    pub async fn run_batch_validation(&mut self) -> Result<ValidationBatch, ValidationError> {
        let batch_id = Uuid::new_v4();
        let start_time = chrono::Utc::now();
        
        let sample_ids: Vec<Uuid> = self.benign_samples.keys().cloned().collect();
        let mut false_positives = 0;
        
        for sample_id in &sample_ids {
            match self.validate_sample(sample_id).await {
                Ok(result) => {
                    if result.false_positive {
                        false_positives += 1;
                    }
                }
                Err(e) => {
                    eprintln!("Validation failed for sample {}: {}", sample_id, e);
                }
            }
        }
        
        let end_time = chrono::Utc::now();
        let samples_tested = sample_ids.len() as u64;
        let batch_false_positive_rate = false_positives as f64 / samples_tested as f64;
        
        let batch = ValidationBatch {
            batch_id,
            start_time,
            end_time,
            samples_tested,
            false_positives,
            batch_false_positive_rate,
        };
        
        self.statistics.validation_history.push(batch.clone());
        
        // Check if false positive rate exceeds threshold
        if batch_false_positive_rate > self.config.max_false_positive_rate {
            return Err(ValidationError::ThresholdExceeded(
                format!("False positive rate {:.2}% exceeds threshold {:.2}%", 
                    batch_false_positive_rate * 100.0, 
                    self.config.max_false_positive_rate * 100.0)
            ));
        }
        
        Ok(batch)
    }

    /// Get validation statistics
    pub fn get_statistics(&self) -> &ValidationStatistics {
        &self.statistics
    }

    /// Export validation report
    pub async fn export_validation_report(&self, output_path: &Path) -> Result<(), ValidationError> {
        let report = serde_json::json!({
            "statistics": self.statistics,
            "whitelist_entries": self.whitelist.len(),
            "benign_samples": self.benign_samples.len(),
            "slo_status": self.slo_status,
            "slo_thresholds": self.slo_thresholds,
            "export_timestamp": chrono::Utc::now(),
        });
        
        let report_json = serde_json::to_string_pretty(&report)?;
        fs::write(output_path, report_json).await?;
        
        Ok(())
    }
    
    /// Check SLO compliance and update status
    pub async fn check_slo_compliance(&mut self) -> Result<bool, ValidationError> {
        let now = Utc::now();
        
        // Update current metrics
        self.slo_status.current_false_positive_rate = self.statistics.false_positive_rate;
        self.slo_status.current_accuracy = self.statistics.accuracy;
        self.slo_status.avg_validation_time_ms = self.statistics.average_validation_time.as_millis() as u64;
        
        // Calculate MTTD from recent validation history
        if !self.statistics.validation_history.is_empty() {
            let recent_batches: Vec<_> = self.statistics.validation_history
                .iter()
                .filter(|batch| (now - batch.start_time).num_hours() <= 24)
                .collect();
            
            if !recent_batches.is_empty() {
                let total_duration: i64 = recent_batches
                    .iter()
                    .map(|batch| (batch.end_time - batch.start_time).num_seconds())
                    .sum();
                self.slo_status.current_mttd_seconds = (total_duration / recent_batches.len() as i64) as u64;
            }
        }
        
        // Check compliance
        let mut violations = Vec::new();
        
        // Check false positive rate
        if self.slo_status.current_false_positive_rate > self.slo_thresholds.max_false_positive_rate {
            violations.push(SloViolation {
                violation_id: Uuid::new_v4(),
                violation_type: SloViolationType::FalsePositiveRate,
                threshold_value: self.slo_thresholds.max_false_positive_rate,
                actual_value: self.slo_status.current_false_positive_rate,
                timestamp: now,
                severity: self.determine_violation_severity(SloViolationType::FalsePositiveRate, 
                    self.slo_status.current_false_positive_rate, self.slo_thresholds.max_false_positive_rate),
                description: format!("False positive rate {:.4}% exceeds threshold {:.4}%", 
                    self.slo_status.current_false_positive_rate * 100.0, 
                    self.slo_thresholds.max_false_positive_rate * 100.0),
            });
        }
        
        // Check MTTD
        if self.slo_status.current_mttd_seconds > self.slo_thresholds.max_mttd_seconds {
            violations.push(SloViolation {
                violation_id: Uuid::new_v4(),
                violation_type: SloViolationType::MeanTimeToDetection,
                threshold_value: self.slo_thresholds.max_mttd_seconds as f64,
                actual_value: self.slo_status.current_mttd_seconds as f64,
                timestamp: now,
                severity: self.determine_violation_severity(SloViolationType::MeanTimeToDetection, 
                    self.slo_status.current_mttd_seconds as f64, self.slo_thresholds.max_mttd_seconds as f64),
                description: format!("MTTD {}s exceeds threshold {}s", 
                    self.slo_status.current_mttd_seconds, self.slo_thresholds.max_mttd_seconds),
            });
        }
        
        // Check accuracy
        if self.slo_status.current_accuracy < self.slo_thresholds.min_accuracy {
            violations.push(SloViolation {
                violation_id: Uuid::new_v4(),
                violation_type: SloViolationType::DetectionAccuracy,
                threshold_value: self.slo_thresholds.min_accuracy,
                actual_value: self.slo_status.current_accuracy,
                timestamp: now,
                severity: self.determine_violation_severity(SloViolationType::DetectionAccuracy, 
                    self.slo_status.current_accuracy, self.slo_thresholds.min_accuracy),
                description: format!("Detection accuracy {:.4}% below threshold {:.4}%", 
                    self.slo_status.current_accuracy * 100.0, 
                    self.slo_thresholds.min_accuracy * 100.0),
            });
        }
        
        // Check validation time
        if self.slo_status.avg_validation_time_ms > self.slo_thresholds.max_validation_time_ms {
            violations.push(SloViolation {
                violation_id: Uuid::new_v4(),
                violation_type: SloViolationType::ValidationTime,
                threshold_value: self.slo_thresholds.max_validation_time_ms as f64,
                actual_value: self.slo_status.avg_validation_time_ms as f64,
                timestamp: now,
                severity: self.determine_violation_severity(SloViolationType::ValidationTime, 
                    self.slo_status.avg_validation_time_ms as f64, self.slo_thresholds.max_validation_time_ms as f64),
                description: format!("Validation time {}ms exceeds threshold {}ms", 
                    self.slo_status.avg_validation_time_ms, self.slo_thresholds.max_validation_time_ms),
            });
        }
        
        // Update compliance status
        self.slo_status.is_compliant = violations.is_empty();
        self.slo_status.last_check = now;
        
        // Store violations in database if available
        if let Some(ref mut sample_manager) = self.sample_manager {
            for violation in &violations {
                if let Err(e) = self.store_slo_violation(sample_manager, violation).await {
                    warn!("Failed to store SLO violation: {}", e);
                }
            }
        }
        
        // Log violations
        for violation in &violations {
            match violation.severity {
                ViolationSeverity::Critical => error!("Critical SLO violation: {}", violation.description),
                ViolationSeverity::High => error!("High SLO violation: {}", violation.description),
                ViolationSeverity::Medium => warn!("Medium SLO violation: {}", violation.description),
                ViolationSeverity::Low => info!("Low SLO violation: {}", violation.description),
            }
        }
        
        Ok(self.slo_status.is_compliant)
    }
    
    /// Determine violation severity based on how much the threshold is exceeded
    fn determine_violation_severity(&self, violation_type: SloViolationType, actual: f64, threshold: f64) -> ViolationSeverity {
        let ratio = match violation_type {
            SloViolationType::FalsePositiveRate | SloViolationType::MeanTimeToDetection | SloViolationType::ValidationTime => {
                actual / threshold
            },
            SloViolationType::DetectionAccuracy => {
                threshold / actual
            },
        };
        
        if ratio >= 3.0 {
            ViolationSeverity::Critical
        } else if ratio >= 2.0 {
            ViolationSeverity::High
        } else if ratio >= 1.5 {
            ViolationSeverity::Medium
        } else {
            ViolationSeverity::Low
        }
    }
    
    /// Store SLO violation in database
    async fn store_slo_violation(&self, sample_manager: &mut MalwareSampleManager, violation: &SloViolation) -> Result<(), ValidationError> {
        let violation_json = serde_json::to_string(violation)
            .map_err(|e| ValidationError::SerializationError(e.to_string()))?;
        
        sample_manager.store_slo_monitoring(
            &violation.violation_type.to_string(),
            violation.actual_value,
            violation.threshold_value,
            !matches!(violation.severity, ViolationSeverity::Low),
            &violation_json
        ).await.map_err(|e| ValidationError::DatabaseError(e.to_string()))?;
        
        Ok(())
    }
    
    /// Get current SLO status
    pub fn get_slo_status(&self) -> &SloStatus {
        &self.slo_status
    }
    
    /// Get SLO compliance rate over the last N days
    pub async fn get_slo_compliance_rate(&self, days: u32) -> Result<f64, ValidationError> {
        if let Some(ref sample_manager) = self.sample_manager {
            sample_manager.get_slo_compliance_rate(days).await
                .map_err(|e| ValidationError::DatabaseError(e.to_string()))
        } else {
            // Fallback calculation from validation history
            let cutoff = Utc::now() - chrono::Duration::days(days as i64);
            let recent_batches: Vec<_> = self.statistics.validation_history
                .iter()
                .filter(|batch| batch.start_time >= cutoff)
                .collect();
            
            if recent_batches.is_empty() {
                return Ok(1.0); // No data means compliant
            }
            
            let compliant_batches = recent_batches
                .iter()
                .filter(|batch| batch.batch_false_positive_rate <= self.slo_thresholds.max_false_positive_rate)
                .count();
            
            Ok(compliant_batches as f64 / recent_batches.len() as f64)
        }
    }
}

/// Default validation statistics
impl ValidationStatistics {
    pub fn new() -> Self {
        Self {
            total_samples_tested: 0,
            false_positives_detected: 0,
            true_negatives: 0,
            false_positive_rate: 0.0,
            accuracy: 0.0,
            average_validation_time: Duration::ZERO,
            by_file_type: HashMap::new(),
            by_category: HashMap::new(),
            validation_history: Vec::new(),
        }
    }
}

/// Default false positive configuration
impl Default for FalsePositiveConfig {
    fn default() -> Self {
        Self {
            benign_samples_directory: PathBuf::from("./benign_samples"),
            whitelist_file: PathBuf::from("./whitelist.json"),
            baseline_directory: PathBuf::from("./baseline"),
            max_false_positive_rate: 0.01, // 1%
            validation_timeout_seconds: 30,
            enable_automatic_whitelisting: true,
            confidence_threshold: 0.3,
            sample_sources: vec![
                SampleSource {
                    name: "System Files".to_string(),
                    source_type: SourceType::SystemScan,
                    path_or_url: "system".to_string(),
                    enabled: true,
                    update_interval_hours: 168, // Weekly
                },
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_validator_creation() {
        let temp_dir = TempDir::new().unwrap();
        let config = FalsePositiveConfig {
            benign_samples_directory: temp_dir.path().to_path_buf(),
            ..Default::default()
        };
        
        let validator = FalsePositiveValidator::new(config);
        assert_eq!(validator.benign_samples.len(), 0);
        assert_eq!(validator.whitelist.len(), 0);
    }

    #[test]
    fn test_file_type_determination() {
        let temp_dir = TempDir::new().unwrap();
        let config = FalsePositiveConfig::default();
        let validator = FalsePositiveValidator::new(config);
        
        assert_eq!(validator.determine_file_type(&PathBuf::from("test.exe")), FileType::Executable);
        assert_eq!(validator.determine_file_type(&PathBuf::from("document.pdf")), FileType::Document);
        assert_eq!(validator.determine_file_type(&PathBuf::from("archive.zip")), FileType::Archive);
        assert_eq!(validator.determine_file_type(&PathBuf::from("script.js")), FileType::Script);
    }

    #[test]
    fn test_whitelist_category_determination() {
        let config = FalsePositiveConfig::default();
        let validator = FalsePositiveValidator::new(config);
        
        assert_eq!(validator.determine_whitelist_category(&SampleCategory::SystemFiles), WhitelistCategory::SystemBinary);
        assert_eq!(validator.determine_whitelist_category(&SampleCategory::DevelopmentTools), WhitelistCategory::DevelopmentTool);
        assert_eq!(validator.determine_whitelist_category(&SampleCategory::SecurityTools), WhitelistCategory::SecurityTool);
    }

    #[tokio::test]
    async fn test_statistics_update() {
        let config = FalsePositiveConfig::default();
        let mut validator = FalsePositiveValidator::new(config);
        
        let sample = BenignSample {
            id: Uuid::new_v4(),
            name: "test.exe".to_string(),
            file_path: PathBuf::from("test.exe"),
            hash_sha256: "abc123".to_string(),
            file_size: 1000,
            file_type: FileType::Executable,
            source: "test".to_string(),
            category: SampleCategory::LegitimateApplications,
            expected_clean: true,
            validation_history: Vec::new(),
            created_at: chrono::Utc::now(),
        };
        
        let result = ValidationResult {
            sample_id: sample.id,
            validation_time: chrono::Utc::now(),
            detected_as_malicious: true,
            detection_confidence: 0.8,
            detection_methods: vec!["test".to_string()],
            false_positive: true,
            validation_duration: Duration::from_millis(100),
            notes: None,
        };
        
        validator.update_statistics(&result, &sample);
        
        assert_eq!(validator.statistics.total_samples_tested, 1);
        assert_eq!(validator.statistics.false_positives_detected, 1);
        assert_eq!(validator.statistics.false_positive_rate, 1.0);
    }
}
