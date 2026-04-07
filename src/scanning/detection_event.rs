//! Detection event structures for malware scanning results
//!
//! This module defines the data structures used to represent scan results,
//! detection events, and related metadata from malware scanning operations.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[cfg(feature = "api-hooking")]
use uuid::Uuid;

/// Severity levels for detections
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    /// Low severity - suspicious but not necessarily malicious
    Low = 1,
    /// Medium severity - likely malicious activity
    Medium = 2,
    /// High severity - confirmed malicious activity
    High = 3,
    /// Critical severity - immediate threat requiring action
    Critical = 4,
}

impl Severity {
    /// Convert severity to numeric score
    pub fn to_score(&self) -> u8 {
        *self as u8
    }

    /// Create severity from numeric score
    pub fn from_score(score: u8) -> Self {
        match score {
            1 => Severity::Low,
            2 => Severity::Medium,
            3 => Severity::High,
            4.. => Severity::Critical,
            _ => Severity::Low,
        }
    }

    /// Get severity as string
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Low => "Low",
            Severity::Medium => "Medium",
            Severity::High => "High",
            Severity::Critical => "Critical",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Types of malware detection
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectionType {
    /// YARA rule match
    YaraRule,
    /// Signature-based detection
    Signature,
    /// Heuristic analysis detection
    Heuristic,
    /// Behavioral analysis detection
    Behavioral,
    /// Machine learning detection
    MachineLearning,
    /// Custom detection logic
    Custom(String),
}

impl std::fmt::Display for DetectionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DetectionType::YaraRule => write!(f, "YARA Rule"),
            DetectionType::Signature => write!(f, "Signature"),
            DetectionType::Heuristic => write!(f, "Heuristic"),
            DetectionType::Behavioral => write!(f, "Behavioral"),
            DetectionType::MachineLearning => write!(f, "Machine Learning"),
            DetectionType::Custom(name) => write!(f, "Custom: {}", name),
        }
    }
}

/// Information about a matched rule or signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMatch {
    /// Name of the matched rule
    pub rule_name: String,

    /// Description of what the rule detects
    pub description: Option<String>,

    /// Tags associated with the rule (e.g., "ransomware", "trojan")
    pub tags: Vec<String>,

    /// Author of the rule
    pub author: Option<String>,

    /// Rule version or date
    pub version: Option<String>,

    /// Confidence score (0.0 to 1.0)
    pub confidence: f32,

    /// Specific strings or patterns that matched
    pub matched_strings: Vec<MatchedString>,

    /// Additional metadata from the rule
    pub metadata: HashMap<String, String>,
}

/// Information about a specific string match within a rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchedString {
    /// Identifier of the matched string (e.g., "$string1")
    pub identifier: String,

    /// The actual matched content (truncated if too long)
    pub content: String,

    /// Offset where the match was found
    pub offset: u64,

    /// Length of the match
    pub length: u32,
}

/// A single detection event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionEvent {
    /// Unique identifier for this detection
    pub id: String,

    /// Path to the file where detection occurred
    pub file_path: PathBuf,

    /// Type of detection
    pub detection_type: DetectionType,

    /// Severity of the detection
    pub severity: Severity,

    /// Timestamp when detection occurred
    pub timestamp: DateTime<Utc>,

    /// Information about matched rules
    pub rule_matches: Vec<RuleMatch>,

    /// Scanner engine that made the detection
    pub scanner_engine: String,

    /// Engine version
    pub engine_version: String,

    /// File size in bytes
    pub file_size: Option<u64>,

    /// File hash (SHA256)
    pub file_hash: Option<String>,

    /// MIME type of the file
    pub mime_type: Option<String>,

    /// Additional context information
    pub context: HashMap<String, String>,

    /// Whether this detection has been quarantined
    pub quarantined: bool,

    /// Action taken in response to this detection
    pub action_taken: Option<String>,
}

impl DetectionEvent {
    /// Create a new detection event
    pub fn new(
        file_path: PathBuf,
        detection_type: DetectionType,
        severity: Severity,
        scanner_engine: String,
        engine_version: String,
    ) -> Self {
        Self {
            #[cfg(feature = "api-hooking")]
            id: Uuid::new_v4().to_string(),
            #[cfg(not(feature = "api-hooking"))]
            id: format!(
                "det_{}",
                chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
            ),
            file_path,
            detection_type,
            severity,
            timestamp: Utc::now(),
            rule_matches: Vec::new(),
            scanner_engine,
            engine_version,
            file_size: None,
            file_hash: None,
            mime_type: None,
            context: HashMap::new(),
            quarantined: false,
            action_taken: None,
        }
    }

    /// Add a rule match to this detection
    pub fn add_rule_match(&mut self, rule_match: RuleMatch) {
        self.rule_matches.push(rule_match);
    }

    /// Set file metadata
    pub fn set_file_metadata(
        &mut self,
        size: Option<u64>,
        hash: Option<String>,
        mime_type: Option<String>,
    ) {
        self.file_size = size;
        self.file_hash = hash;
        self.mime_type = mime_type;
    }

    /// Add context information
    pub fn add_context<K: Into<String>, V: Into<String>>(&mut self, key: K, value: V) {
        self.context.insert(key.into(), value.into());
    }

    /// Mark as quarantined
    pub fn set_quarantined(&mut self, action: Option<String>) {
        self.quarantined = true;
        self.action_taken = action;
    }

    /// Get the highest confidence score from all rule matches
    pub fn max_confidence(&self) -> f32 {
        self.rule_matches
            .iter()
            .map(|m| m.confidence)
            .fold(0.0, f32::max)
    }

    /// Get all rule names that matched
    pub fn rule_names(&self) -> Vec<&str> {
        self.rule_matches
            .iter()
            .map(|m| m.rule_name.as_str())
            .collect()
    }

    /// Get all tags from matched rules
    pub fn all_tags(&self) -> Vec<&str> {
        self.rule_matches
            .iter()
            .flat_map(|m| m.tags.iter().map(|t| t.as_str()))
            .collect()
    }
}

/// Result of scanning a single file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// Path to the scanned file
    pub file_path: PathBuf,

    /// Whether the scan completed successfully
    pub scan_successful: bool,

    /// Error message if scan failed
    pub error_message: Option<String>,

    /// Time taken to scan in milliseconds
    pub scan_time_ms: u64,

    /// Timestamp when scan was performed
    pub scan_timestamp: DateTime<Utc>,

    /// Scanner engine used
    pub scanner_engine: String,

    /// Detection events found (empty if clean)
    pub detections: Vec<DetectionEvent>,

    /// File size in bytes
    pub file_size: Option<u64>,

    /// Whether file was skipped (due to size, type, etc.)
    pub skipped: bool,

    /// Reason for skipping if applicable
    pub skip_reason: Option<String>,
}

impl ScanResult {
    /// Create a new successful scan result
    pub fn success(
        file_path: PathBuf,
        scanner_engine: String,
        scan_time_ms: u64,
        detections: Vec<DetectionEvent>,
    ) -> Self {
        Self {
            file_path,
            scan_successful: true,
            error_message: None,
            scan_time_ms,
            scan_timestamp: Utc::now(),
            scanner_engine,
            detections,
            file_size: None,
            skipped: false,
            skip_reason: None,
        }
    }

    /// Create a new failed scan result
    pub fn error(
        file_path: PathBuf,
        scanner_engine: String,
        scan_time_ms: u64,
        error_message: String,
    ) -> Self {
        Self {
            file_path,
            scan_successful: false,
            error_message: Some(error_message),
            scan_time_ms,
            scan_timestamp: Utc::now(),
            scanner_engine,
            detections: Vec::new(),
            file_size: None,
            skipped: false,
            skip_reason: None,
        }
    }

    /// Create a new skipped scan result
    pub fn skipped(file_path: PathBuf, scanner_engine: String, skip_reason: String) -> Self {
        Self {
            file_path,
            scan_successful: true,
            error_message: None,
            scan_time_ms: 0,
            scan_timestamp: Utc::now(),
            scanner_engine,
            detections: Vec::new(),
            file_size: None,
            skipped: true,
            skip_reason: Some(skip_reason),
        }
    }

    /// Check if any malware was detected
    pub fn has_detections(&self) -> bool {
        !self.detections.is_empty()
    }

    /// Get the highest severity detection
    pub fn max_severity(&self) -> Option<Severity> {
        self.detections.iter().map(|d| d.severity).max()
    }

    /// Set file size
    pub fn set_file_size(&mut self, size: u64) {
        self.file_size = Some(size);
    }

    /// Get total number of rule matches across all detections
    pub fn total_rule_matches(&self) -> usize {
        self.detections.iter().map(|d| d.rule_matches.len()).sum()
    }
}

/// Summary statistics for a batch scan operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchScanSummary {
    /// Total files processed
    pub total_files: usize,

    /// Files successfully scanned
    pub successful_scans: usize,

    /// Files that failed to scan
    pub failed_scans: usize,

    /// Files skipped
    pub skipped_files: usize,

    /// Total detections found
    pub total_detections: usize,

    /// Files with detections
    pub infected_files: usize,

    /// Total scan time in milliseconds
    pub total_scan_time_ms: u64,

    /// Average scan time per file in milliseconds
    pub avg_scan_time_ms: f64,

    /// Timestamp when batch scan started
    pub start_time: DateTime<Utc>,

    /// Timestamp when batch scan completed
    pub end_time: DateTime<Utc>,

    /// Scanner engine used
    pub scanner_engine: String,
}

impl BatchScanSummary {
    /// Create a new batch scan summary from scan results
    pub fn from_results(
        results: &[ScanResult],
        scanner_engine: String,
        start_time: DateTime<Utc>,
    ) -> Self {
        let total_files = results.len();
        let successful_scans = results
            .iter()
            .filter(|r| r.scan_successful && !r.skipped)
            .count();
        let failed_scans = results.iter().filter(|r| !r.scan_successful).count();
        let skipped_files = results.iter().filter(|r| r.skipped).count();
        let total_detections = results.iter().map(|r| r.detections.len()).sum();
        let infected_files = results.iter().filter(|r| r.has_detections()).count();
        let total_scan_time_ms = results.iter().map(|r| r.scan_time_ms).sum();
        let avg_scan_time_ms = if successful_scans > 0 {
            total_scan_time_ms as f64 / successful_scans as f64
        } else {
            0.0
        };

        Self {
            total_files,
            successful_scans,
            failed_scans,
            skipped_files,
            total_detections,
            infected_files,
            total_scan_time_ms,
            avg_scan_time_ms,
            start_time,
            end_time: Utc::now(),
            scanner_engine,
        }
    }
}
