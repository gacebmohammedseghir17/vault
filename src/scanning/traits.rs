//! Traits for malware scanning engines
//!
//! This module defines the core traits that enable extensible malware detection
//! capabilities. The MalwareScanner trait provides a common interface that can
//! be implemented by different scanning engines (YARA, ClamAV, custom heuristics, etc.).

use async_trait::async_trait;
use std::path::Path;
use thiserror::Error;

use super::detection_event::{DetectionEvent, ScanResult};

/// Errors that can occur during malware scanning operations
#[derive(Error, Debug)]
pub enum ScanError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Scanner not initialized: {0}")]
    NotInitialized(String),

    #[error("Rules compilation failed: {0}")]
    RulesCompilation(String),

    #[error("Scan timeout: operation took longer than {timeout_secs} seconds")]
    Timeout { timeout_secs: u64 },

    #[error("File too large: {size_mb}MB exceeds limit of {limit_mb}MB")]
    FileTooLarge { size_mb: u64, limit_mb: u64 },

    #[error("Permission denied: {path}")]
    PermissionDenied { path: String },

    #[error("Unsupported file type: {extension}")]
    UnsupportedFileType { extension: String },

    #[error("Scanner engine error: {0}")]
    EngineError(String),

    #[error("Configuration error: {0}")]
    Configuration(String),
}

/// Configuration for scanning operations
#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// Maximum file size to scan in MB
    pub max_file_size_mb: u64,

    /// Scan timeout in seconds
    pub timeout_secs: u64,

    /// Whether to scan compressed files
    pub scan_compressed: bool,

    /// Whether to follow symbolic links
    pub follow_symlinks: bool,

    /// Maximum recursion depth for directory scanning
    pub max_recursion_depth: u32,

    /// File extensions to exclude from scanning
    pub excluded_extensions: Vec<String>,

    /// Directories to exclude from scanning
    pub excluded_directories: Vec<String>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            max_file_size_mb: 100,
            timeout_secs: 60,
            scan_compressed: false,
            follow_symlinks: false,
            max_recursion_depth: 10,
            excluded_extensions: vec!["tmp".to_string(), "log".to_string(), "cache".to_string()],
            excluded_directories: vec![
                "node_modules".to_string(),
                ".git".to_string(),
                "target".to_string(),
            ],
        }
    }
}

/// Statistics for scanning operations
#[derive(Debug, Clone, Default)]
pub struct ScanStats {
    /// Total number of files scanned
    pub files_scanned: u64,

    /// Total number of directories processed
    pub directories_processed: u64,

    /// Number of files skipped (due to size, type, etc.)
    pub files_skipped: u64,

    /// Number of scan errors encountered
    pub scan_errors: u64,

    /// Total scanning time in milliseconds
    pub total_scan_time_ms: u64,

    /// Number of detections found
    pub detections_found: u64,

    /// Average scan time per file in milliseconds
    pub avg_scan_time_ms: f64,
}

/// Core trait for malware scanning engines
///
/// This trait provides a common interface for different malware detection engines.
/// Implementations should handle their own initialization, rule management, and
/// scanning logic while providing consistent results through this interface.
#[async_trait]
pub trait MalwareScanner: Send + Sync {
    /// Initialize the scanner with rules from the specified path
    ///
    /// # Arguments
    /// * `rules_path` - Path to the rules directory or file
    ///
    /// # Returns
    /// * `Ok(())` if initialization succeeded
    /// * `Err(ScanError)` if initialization failed
    async fn initialize(&mut self, rules_path: &Path) -> Result<(), ScanError>;

    /// Check if the scanner is properly initialized and ready to scan
    fn is_initialized(&self) -> bool;

    /// Scan a single file for malware
    ///
    /// # Arguments
    /// * `file_path` - Path to the file to scan
    ///
    /// # Returns
    /// * `Ok(ScanResult)` containing scan results and any detections
    /// * `Err(ScanError)` if scanning failed
    async fn scan_file(&self, file_path: &Path) -> Result<ScanResult, ScanError>;

    /// Scan a directory for malware, optionally recursively
    ///
    /// # Arguments
    /// * `dir_path` - Path to the directory to scan
    /// * `recursive` - Whether to scan subdirectories recursively
    ///
    /// # Returns
    /// * `Ok(Vec<ScanResult>)` containing results for all scanned files
    /// * `Err(ScanError)` if directory scanning failed
    async fn scan_directory(
        &self,
        dir_path: &Path,
        recursive: bool,
    ) -> Result<Vec<ScanResult>, ScanError>;

    /// Scan a memory buffer for malware
    ///
    /// # Arguments
    /// * `data` - Byte buffer to scan
    /// * `context` - Optional context information (e.g., "process_memory", "network_data")
    ///
    /// # Returns
    /// * `Ok(Vec<DetectionEvent>)` containing any detections found
    /// * `Err(ScanError)` if scanning failed
    async fn scan_memory(
        &self,
        data: &[u8],
        context: Option<&str>,
    ) -> Result<Vec<DetectionEvent>, ScanError>;

    /// Get information about loaded rules
    ///
    /// # Returns
    /// * Map of rule names to their descriptions or metadata
    async fn get_rules_info(&self) -> std::collections::HashMap<String, String>;

    /// Get the number of loaded rules
    async fn get_rules_count(&self) -> usize;

    /// Get scanning statistics
    fn get_stats(&self) -> ScanStats;

    /// Reset scanning statistics
    fn reset_stats(&mut self);

    /// Update scanner configuration
    fn set_config(&mut self, config: ScanConfig);

    /// Get current scanner configuration
    fn get_config(&self) -> &ScanConfig;

    /// Get the scanner engine name (e.g., "YARA", "ClamAV", "Custom")
    fn get_engine_name(&self) -> &'static str;

    /// Get the scanner engine version
    fn get_engine_version(&self) -> String;

    /// Perform any cleanup operations
    async fn cleanup(&mut self) -> Result<(), ScanError> {
        // Default implementation does nothing
        Ok(())
    }

    /// Reload rules from the configured path
    ///
    /// This is useful for updating rules without reinitializing the entire scanner
    async fn reload_rules(&mut self) -> Result<(), ScanError> {
        // Default implementation returns an error
        Err(ScanError::EngineError(
            "Rule reloading not supported by this scanner".to_string(),
        ))
    }

    /// Validate that the scanner is in a healthy state
    ///
    /// # Returns
    /// * `Ok(())` if the scanner is healthy
    /// * `Err(ScanError)` if there are health issues
    async fn health_check(&self) -> Result<(), ScanError> {
        if self.is_initialized() {
            Ok(())
        } else {
            Err(ScanError::NotInitialized(
                "Scanner not properly initialized".to_string(),
            ))
        }
    }
}

/// Trait for scanners that support batch operations
#[async_trait]
pub trait BatchScanner: MalwareScanner {
    /// Scan multiple files concurrently
    ///
    /// # Arguments
    /// * `file_paths` - Vector of file paths to scan
    /// * `max_concurrent` - Maximum number of concurrent scans (None for default)
    ///
    /// # Returns
    /// * `Ok(Vec<ScanResult>)` containing results for all files
    /// * `Err(ScanError)` if batch scanning failed
    async fn batch_scan_files(
        &self,
        file_paths: &[&Path],
        max_concurrent: Option<usize>,
    ) -> Result<Vec<ScanResult>, ScanError>;
}

/// Trait for scanners that support real-time monitoring
#[async_trait]
pub trait RealtimeScanner: MalwareScanner {
    /// Start real-time monitoring of specified directories
    ///
    /// # Arguments
    /// * `watch_paths` - Directories to monitor
    /// * `callback` - Function to call when files are detected as malware
    async fn start_monitoring(
        &mut self,
        watch_paths: &[&Path],
        callback: Box<dyn Fn(DetectionEvent) + Send + Sync>,
    ) -> Result<(), ScanError>;

    /// Stop real-time monitoring
    async fn stop_monitoring(&mut self) -> Result<(), ScanError>;

    /// Check if real-time monitoring is active
    fn is_monitoring(&self) -> bool;
}
