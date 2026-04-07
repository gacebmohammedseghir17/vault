//!
//! Comprehensive error handling for YARA integration
//!
//! This module provides detailed error categorization, logging, and recovery mechanisms
//! for production-ready YARA scanning operations.

use std::io;
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, error, info, warn};

/// Comprehensive error types for YARA operations
#[derive(Error, Debug, Serialize, Deserialize)]
pub enum YaraError {
    /// YARA library initialization errors
    #[error("YARA initialization failed: {message}")]
    InitializationError {
        message: String,
        #[serde(skip)]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Rule compilation and loading errors
    #[error("YARA rule error in {file_path}: {message}")]
    RuleError {
        file_path: PathBuf,
        message: String,
        line_number: Option<u32>,
        column: Option<u32>,
    },

    /// File system access errors
    #[error("File system error for {path}: {kind}")]
    FileSystemError {
        path: PathBuf,
        kind: FileSystemErrorKind,
        #[serde(skip)]
        source: Option<io::Error>,
    },

    /// Scanning operation errors
    #[error("Scan error for {target}: {kind}")]
    ScanError {
        target: PathBuf,
        kind: ScanErrorKind,
        duration: Option<Duration>,
    },

    /// Resource exhaustion errors
    #[error("Resource exhaustion: {kind}")]
    ResourceError {
        kind: ResourceErrorKind,
        current_usage: u64,
        limit: u64,
    },

    /// Network and update errors
    #[error("Network error during {operation}: {message}")]
    NetworkError {
        operation: String,
        message: String,
        retry_count: u32,
        #[serde(skip)]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Configuration errors
    #[error("Configuration error: {message}")]
    ConfigurationError {
        message: String,
        field: Option<String>,
    },

    /// Permission and security errors
    #[error("Security error: {kind}")]
    SecurityError {
        kind: SecurityErrorKind,
        context: String,
    },

    /// Timeout errors
    #[error("Operation timed out after {duration:?}: {operation}")]
    TimeoutError {
        operation: String,
        duration: Duration,
    },

    /// Recovery and rollback errors
    #[error("Recovery failed: {message}")]
    RecoveryError {
        message: String,
        original_error: String,
    },
}

/// File system error categories
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FileSystemErrorKind {
    /// File not found
    NotFound,
    /// Permission denied
    PermissionDenied,
    /// File is locked by another process
    FileLocked,
    /// File is too large to process
    FileTooLarge { size: u64, limit: u64 },
    /// Invalid file format or corruption
    InvalidFormat,
    /// Disk space exhausted
    DiskFull,
    /// Path too long
    PathTooLong,
    /// Invalid characters in path
    InvalidPath,
    /// Network path unavailable
    NetworkUnavailable,
    /// Other I/O error
    Other(String),
}

impl std::fmt::Display for FileSystemErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileSystemErrorKind::NotFound => write!(f, "file not found"),
            FileSystemErrorKind::PermissionDenied => write!(f, "permission denied"),
            FileSystemErrorKind::FileLocked => write!(f, "file is locked"),
            FileSystemErrorKind::FileTooLarge { size, limit } => {
                write!(f, "file too large ({} bytes, limit {} bytes)", size, limit)
            }
            FileSystemErrorKind::InvalidFormat => write!(f, "invalid file format"),
            FileSystemErrorKind::DiskFull => write!(f, "disk space exhausted"),
            FileSystemErrorKind::PathTooLong => write!(f, "path too long"),
            FileSystemErrorKind::InvalidPath => write!(f, "invalid path"),
            FileSystemErrorKind::NetworkUnavailable => write!(f, "network path unavailable"),
            FileSystemErrorKind::Other(msg) => write!(f, "I/O error: {}", msg),
        }
    }
}

/// Scan operation error categories
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScanErrorKind {
    /// File could not be read
    ReadError,
    /// File format not supported
    UnsupportedFormat,
    /// Scan was interrupted
    Interrupted,
    /// Memory mapping failed
    MemoryMapFailed,
    /// YARA engine error
    EngineError(String),
    /// Scan timeout
    Timeout,
    /// File changed during scan
    FileModified,
    /// Insufficient permissions
    InsufficientPermissions,
    /// Permission denied for process access
    PermissionDenied,
    /// Platform not supported for this operation
    UnsupportedPlatform,
}

/// Resource exhaustion error categories
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResourceErrorKind {
    /// Memory limit exceeded
    MemoryExhausted,
    /// Too many open files
    FileHandleExhausted,
    /// CPU usage too high
    CpuExhausted,
    /// Disk space exhausted
    DiskSpaceExhausted,
    /// Network bandwidth exhausted
    BandwidthExhausted,
    /// Thread pool exhausted
    ThreadPoolExhausted,
}

/// Security error categories
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityErrorKind {
    /// Attempting to access system files
    SystemFileAccess,
    /// Path traversal attempt
    PathTraversal,
    /// Suspicious file characteristics
    SuspiciousFile,
    /// Integrity check failed
    IntegrityCheckFailed,
    /// Unauthorized access attempt
    UnauthorizedAccess,
}

impl std::fmt::Display for ScanErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanErrorKind::ReadError => write!(f, "file could not be read"),
            ScanErrorKind::UnsupportedFormat => write!(f, "file format not supported"),
            ScanErrorKind::Interrupted => write!(f, "scan was interrupted"),
            ScanErrorKind::MemoryMapFailed => write!(f, "memory mapping failed"),
            ScanErrorKind::EngineError(msg) => write!(f, "YARA engine error: {}", msg),
            ScanErrorKind::Timeout => write!(f, "scan timeout"),
            ScanErrorKind::FileModified => write!(f, "file changed during scan"),
            ScanErrorKind::InsufficientPermissions => write!(f, "insufficient permissions"),
            ScanErrorKind::PermissionDenied => write!(f, "permission denied for process access"),
            ScanErrorKind::UnsupportedPlatform => {
                write!(f, "platform not supported for this operation")
            }
        }
    }
}

impl std::fmt::Display for ResourceErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResourceErrorKind::MemoryExhausted => write!(f, "memory limit exceeded"),
            ResourceErrorKind::FileHandleExhausted => write!(f, "too many open files"),
            ResourceErrorKind::CpuExhausted => write!(f, "CPU usage too high"),
            ResourceErrorKind::DiskSpaceExhausted => write!(f, "disk space exhausted"),
            ResourceErrorKind::BandwidthExhausted => write!(f, "network bandwidth exhausted"),
            ResourceErrorKind::ThreadPoolExhausted => write!(f, "thread pool exhausted"),
        }
    }
}

impl std::fmt::Display for SecurityErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecurityErrorKind::SystemFileAccess => write!(f, "attempting to access system files"),
            SecurityErrorKind::PathTraversal => write!(f, "path traversal attempt detected"),
            SecurityErrorKind::SuspiciousFile => write!(f, "suspicious file characteristics"),
            SecurityErrorKind::IntegrityCheckFailed => write!(f, "integrity check failed"),
            SecurityErrorKind::UnauthorizedAccess => write!(f, "unauthorized access attempt"),
        }
    }
}

/// Error severity levels for logging and alerting
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ErrorSeverity {
    /// Informational - operation completed with minor issues
    Info,
    /// Warning - operation completed but with concerns
    Warning,
    /// Error - operation failed but system remains stable
    Error,
    /// Critical - system stability may be compromised
    Critical,
    /// Fatal - immediate intervention required
    Fatal,
}

/// Error context for enhanced debugging and monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorContext {
    /// Timestamp when error occurred
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Thread ID where error occurred
    pub thread_id: String,
    /// Process ID
    pub process_id: u32,
    /// System information
    pub system_info: SystemInfo,
    /// Operation context
    pub operation: String,
    /// Additional metadata
    pub metadata: std::collections::HashMap<String, String>,
}

/// System information for error context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    /// Operating system
    pub os: String,
    /// Architecture
    pub arch: String,
    /// Available memory (bytes)
    pub available_memory: u64,
    /// CPU usage percentage
    pub cpu_usage: f32,
    /// Disk usage percentage
    pub disk_usage: f32,
}

/// Error recovery strategy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecoveryStrategy {
    /// Retry the operation
    Retry {
        max_attempts: u32,
        delay: Duration,
        backoff_multiplier: f32,
    },
    /// Skip the current item and continue
    Skip,
    /// Fallback to alternative method
    Fallback(String),
    /// Abort the operation
    Abort,
    /// Manual intervention required
    Manual(String),
}

/// Comprehensive error handler for YARA operations
pub struct YaraErrorHandler {
    /// Error statistics
    error_stats: std::sync::Arc<std::sync::Mutex<ErrorStatistics>>,
    /// Recovery strategies by error type
    recovery_strategies: std::collections::HashMap<String, RecoveryStrategy>,
    /// Maximum error rate before triggering alerts
    max_error_rate: f32,
    /// Time window for error rate calculation
    error_rate_window: Duration,
}

/// Simplified error representation for statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimpleError {
    pub category: String,
    pub severity: ErrorSeverity,
    pub message: String,
}

/// Error statistics for monitoring
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ErrorStatistics {
    /// Total error count
    pub total_errors: u64,
    /// Errors by category
    pub errors_by_category: std::collections::HashMap<String, u64>,
    /// Errors by severity
    pub errors_by_severity: std::collections::HashMap<ErrorSeverity, u64>,
    /// Recent errors (last 1000)
    pub recent_errors: std::collections::VecDeque<(chrono::DateTime<chrono::Utc>, SimpleError)>,
    /// Recovery success rate
    pub recovery_success_rate: f32,
    /// Average error resolution time
    pub avg_resolution_time: Duration,
}

impl YaraError {
    /// Get the severity level of this error
    pub fn severity(&self) -> ErrorSeverity {
        match self {
            YaraError::InitializationError { .. } => ErrorSeverity::Fatal,
            YaraError::RuleError { .. } => ErrorSeverity::Error,
            YaraError::FileSystemError { kind, .. } => match kind {
                FileSystemErrorKind::NotFound => ErrorSeverity::Warning,
                FileSystemErrorKind::PermissionDenied => ErrorSeverity::Error,
                FileSystemErrorKind::FileLocked => ErrorSeverity::Warning,
                FileSystemErrorKind::FileTooLarge { .. } => ErrorSeverity::Warning,
                FileSystemErrorKind::DiskFull => ErrorSeverity::Critical,
                _ => ErrorSeverity::Error,
            },
            YaraError::ScanError { kind, .. } => match kind {
                ScanErrorKind::Timeout => ErrorSeverity::Warning,
                ScanErrorKind::InsufficientPermissions => ErrorSeverity::Warning,
                ScanErrorKind::EngineError(_) => ErrorSeverity::Error,
                _ => ErrorSeverity::Warning,
            },
            YaraError::ResourceError { .. } => ErrorSeverity::Critical,
            YaraError::NetworkError { .. } => ErrorSeverity::Warning,
            YaraError::ConfigurationError { .. } => ErrorSeverity::Error,
            YaraError::SecurityError { .. } => ErrorSeverity::Critical,
            YaraError::TimeoutError { .. } => ErrorSeverity::Warning,
            YaraError::RecoveryError { .. } => ErrorSeverity::Error,
        }
    }

    /// Get the error category for statistics
    pub fn category(&self) -> &'static str {
        match self {
            YaraError::InitializationError { .. } => "initialization",
            YaraError::RuleError { .. } => "rule",
            YaraError::FileSystemError { .. } => "filesystem",
            YaraError::ScanError { .. } => "scan",
            YaraError::ResourceError { .. } => "resource",
            YaraError::NetworkError { .. } => "network",
            YaraError::ConfigurationError { .. } => "configuration",
            YaraError::SecurityError { .. } => "security",
            YaraError::TimeoutError { .. } => "timeout",
            YaraError::RecoveryError { .. } => "recovery",
        }
    }

    /// Check if this error is recoverable
    pub fn is_recoverable(&self) -> bool {
        match self {
            YaraError::InitializationError { .. } => false,
            YaraError::RuleError { .. } => false,
            YaraError::FileSystemError { kind, .. } => matches!(
                kind,
                FileSystemErrorKind::FileLocked
                    | FileSystemErrorKind::NetworkUnavailable
                    | FileSystemErrorKind::Other(_)
            ),
            YaraError::ScanError { kind, .. } => matches!(
                kind,
                ScanErrorKind::Timeout | ScanErrorKind::Interrupted | ScanErrorKind::FileModified
            ),
            YaraError::ResourceError { .. } => true,
            YaraError::NetworkError { .. } => true,
            YaraError::ConfigurationError { .. } => false,
            YaraError::SecurityError { .. } => false,
            YaraError::TimeoutError { .. } => true,
            YaraError::RecoveryError { .. } => false,
        }
    }

    /// Get suggested recovery strategy
    pub fn recovery_strategy(&self) -> RecoveryStrategy {
        match self {
            YaraError::FileSystemError { kind, .. } => match kind {
                FileSystemErrorKind::FileLocked => RecoveryStrategy::Retry {
                    max_attempts: 3,
                    delay: Duration::from_millis(500),
                    backoff_multiplier: 2.0,
                },
                FileSystemErrorKind::NetworkUnavailable => RecoveryStrategy::Retry {
                    max_attempts: 5,
                    delay: Duration::from_secs(1),
                    backoff_multiplier: 1.5,
                },
                FileSystemErrorKind::PermissionDenied => RecoveryStrategy::Skip,
                _ => RecoveryStrategy::Skip,
            },
            YaraError::ScanError { kind, .. } => match kind {
                ScanErrorKind::Timeout => RecoveryStrategy::Retry {
                    max_attempts: 2,
                    delay: Duration::from_millis(100),
                    backoff_multiplier: 1.0,
                },
                ScanErrorKind::FileModified => RecoveryStrategy::Retry {
                    max_attempts: 1,
                    delay: Duration::from_millis(50),
                    backoff_multiplier: 1.0,
                },
                _ => RecoveryStrategy::Skip,
            },
            YaraError::NetworkError { .. } => RecoveryStrategy::Retry {
                max_attempts: 3,
                delay: Duration::from_secs(2),
                backoff_multiplier: 2.0,
            },
            YaraError::ResourceError { .. } => RecoveryStrategy::Retry {
                max_attempts: 2,
                delay: Duration::from_secs(5),
                backoff_multiplier: 1.0,
            },
            _ => RecoveryStrategy::Abort,
        }
    }
}

impl Default for YaraErrorHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl YaraErrorHandler {
    /// Create a new error handler
    pub fn new() -> Self {
        Self {
            error_stats: std::sync::Arc::new(std::sync::Mutex::new(ErrorStatistics::default())),
            recovery_strategies: std::collections::HashMap::new(),
            max_error_rate: 0.1, // 10% error rate threshold
            error_rate_window: Duration::from_secs(5 * 60), // 5 minutes
        }
    }

    /// Handle an error with comprehensive logging and recovery
    pub async fn handle_error(
        &self,
        error: &YaraError,
        context: ErrorContext,
    ) -> Result<RecoveryStrategy, YaraError> {
        let severity = error.severity();
        let category = error.category();

        // Log the error with appropriate level
        match severity {
            ErrorSeverity::Info => info!(
                error = %error,
                category = category,
                context = ?context,
                "YARA operation completed with info"
            ),
            ErrorSeverity::Warning => warn!(
                error = %error,
                category = category,
                context = ?context,
                "YARA operation warning"
            ),
            ErrorSeverity::Error => error!(
                error = %error,
                category = category,
                context = ?context,
                "YARA operation error"
            ),
            ErrorSeverity::Critical => error!(
                error = %error,
                category = category,
                context = ?context,
                "CRITICAL YARA error - immediate attention required"
            ),
            ErrorSeverity::Fatal => error!(
                error = %error,
                category = category,
                context = ?context,
                "FATAL YARA error - system stability compromised"
            ),
        }

        // Update statistics
        self.update_statistics(error).await;

        // Check error rate and trigger alerts if necessary
        if self.check_error_rate().await {
            self.trigger_alert(severity, error, &context).await;
        }

        // Determine recovery strategy
        let strategy = self.get_recovery_strategy(error);

        debug!(
            strategy = ?strategy,
            error_category = category,
            "Determined recovery strategy for error"
        );

        Ok(strategy)
    }

    /// Update error statistics
    async fn update_statistics(&self, error: &YaraError) {
        if let Ok(mut stats) = self.error_stats.lock() {
            stats.total_errors += 1;

            // Update category statistics
            *stats
                .errors_by_category
                .entry(error.category().to_string())
                .or_insert(0) += 1;

            // Update severity statistics
            *stats
                .errors_by_severity
                .entry(error.severity())
                .or_insert(0) += 1;

            // Add to recent errors (keep last 1000)
            let simple_error = SimpleError {
                category: error.category().to_string(),
                severity: error.severity(),
                message: error.to_string(),
            };
            stats
                .recent_errors
                .push_back((chrono::Utc::now(), simple_error));
            if stats.recent_errors.len() > 1000 {
                stats.recent_errors.pop_front();
            }
        }
    }

    /// Check if error rate exceeds threshold
    async fn check_error_rate(&self) -> bool {
        if let Ok(stats) = self.error_stats.lock() {
            let now = chrono::Utc::now();
            let window_start =
                now - chrono::Duration::from_std(self.error_rate_window).unwrap_or_default();

            let recent_error_count = stats
                .recent_errors
                .iter()
                .filter(|(timestamp, _)| *timestamp > window_start)
                .count();

            let error_rate = recent_error_count as f32 / self.error_rate_window.as_secs() as f32;
            error_rate > self.max_error_rate
        } else {
            false
        }
    }

    /// Trigger alert for high error rates or critical errors
    async fn trigger_alert(
        &self,
        severity: ErrorSeverity,
        error: &YaraError,
        context: &ErrorContext,
    ) {
        warn!(
            severity = ?severity,
            error = %error,
            context = ?context,
            "ALERT: High error rate or critical error detected"
        );

        // Here you could integrate with alerting systems:
        // - Send email notifications
        // - Post to Slack/Teams
        // - Create incident tickets
        // - Trigger monitoring alerts
    }

    /// Get recovery strategy for an error
    fn get_recovery_strategy(&self, error: &YaraError) -> RecoveryStrategy {
        // Check for custom strategy first
        if let Some(strategy) = self.recovery_strategies.get(error.category()) {
            strategy.clone()
        } else {
            // Use default strategy based on error type
            error.recovery_strategy()
        }
    }

    /// Get current error statistics
    pub async fn get_statistics(&self) -> ErrorStatistics {
        self.error_stats
            .lock()
            .map(|stats| stats.clone())
            .unwrap_or_else(|_| ErrorStatistics::default())
    }

    /// Reset error statistics
    pub async fn reset_statistics(&self) {
        if let Ok(mut stats) = self.error_stats.lock() {
            *stats = ErrorStatistics::default();
        }
    }
}

/// Helper function to create error context
pub fn create_error_context(operation: &str) -> ErrorContext {
    ErrorContext {
        timestamp: chrono::Utc::now(),
        thread_id: format!("{:?}", std::thread::current().id()),
        process_id: std::process::id(),
        system_info: SystemInfo {
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            available_memory: get_available_memory(),
            cpu_usage: get_cpu_usage(),
            disk_usage: get_disk_usage(),
        },
        operation: operation.to_string(),
        metadata: std::collections::HashMap::new(),
    }
}

/// Get available system memory (placeholder implementation)
fn get_available_memory() -> u64 {
    // This would use system-specific APIs to get actual memory info
    // For now, return a placeholder value
    8 * 1024 * 1024 * 1024 // 8GB placeholder
}

/// Get current CPU usage (placeholder implementation)
fn get_cpu_usage() -> f32 {
    // This would use system-specific APIs to get actual CPU usage
    // For now, return a placeholder value
    25.0 // 25% placeholder
}

/// Get current disk usage (placeholder implementation)
fn get_disk_usage() -> f32 {
    // This would use system-specific APIs to get actual disk usage
    // For now, return a placeholder value
    45.0 // 45% placeholder
}

/// Convert standard I/O errors to YARA errors
impl From<io::Error> for YaraError {
    fn from(error: io::Error) -> Self {
        let kind = match error.kind() {
            io::ErrorKind::NotFound => FileSystemErrorKind::NotFound,
            io::ErrorKind::PermissionDenied => FileSystemErrorKind::PermissionDenied,
            io::ErrorKind::InvalidInput => FileSystemErrorKind::InvalidPath,
            _ => FileSystemErrorKind::Other(error.to_string()),
        };

        YaraError::FileSystemError {
            path: PathBuf::new(), // Would be filled in by caller
            kind,
            source: Some(error),
        }
    }
}

#[cfg(all(test, feature = "yara"))]
mod tests {
    use super::*;

    #[test]
    fn test_error_severity() {
        let error = YaraError::InitializationError {
            message: "Test error".to_string(),
            source: None,
        };
        assert_eq!(error.severity(), ErrorSeverity::Fatal);
    }

    #[test]
    fn test_error_category() {
        let error = YaraError::ScanError {
            target: PathBuf::from("/test/file"),
            kind: ScanErrorKind::Timeout,
            duration: Some(Duration::from_secs(30)),
        };
        assert_eq!(error.category(), "scan");
    }

    #[test]
    fn test_recoverable_errors() {
        let recoverable = YaraError::NetworkError {
            operation: "download".to_string(),
            message: "Connection timeout".to_string(),
            retry_count: 1,
            source: None,
        };
        assert!(recoverable.is_recoverable());

        let non_recoverable = YaraError::InitializationError {
            message: "Library not found".to_string(),
            source: None,
        };
        assert!(!non_recoverable.is_recoverable());
    }

    #[tokio::test]
    async fn test_error_handler() {
        let handler = YaraErrorHandler::new();
        let error = YaraError::ScanError {
            target: PathBuf::from("/test/file"),
            kind: ScanErrorKind::Timeout,
            duration: Some(Duration::from_secs(30)),
        };
        let context = create_error_context("test_scan");

        let strategy = handler.handle_error(&error, context).await.unwrap();
        assert!(matches!(strategy, RecoveryStrategy::Retry { .. }));
    }
}
