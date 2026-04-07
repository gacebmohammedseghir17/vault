//!
//! Enhanced Error handling module for ERDPS Agent
//!
//! This module provides comprehensive error handling, logging, and recovery
//! mechanisms for all agent operations, with special focus on YARA integration.

pub mod yara_errors;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{error, warn, info, debug};
use chrono::{DateTime, Utc};
use uuid::Uuid;

// Removed circular import - AgentError is defined in this module
// Re-export YARA-specific errors
pub use yara_errors::{
    ErrorSeverity, FileSystemErrorKind, ResourceErrorKind, ScanErrorKind, SecurityErrorKind,
    YaraError,
};

/// Enhanced error context for better debugging and recovery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorContext {
    pub operation: String,
    pub component: String,
    pub timestamp: DateTime<Utc>,
    pub correlation_id: Uuid,
    pub metadata: HashMap<String, String>,
    pub recovery_suggestions: Vec<String>,
}

impl ErrorContext {
    pub fn new(operation: &str, component: &str) -> Self {
        Self {
            operation: operation.to_string(),
            component: component.to_string(),
            timestamp: Utc::now(),
            correlation_id: Uuid::new_v4(),
            metadata: HashMap::new(),
            recovery_suggestions: Vec::new(),
        }
    }

    pub fn with_metadata(mut self, key: &str, value: &str) -> Self {
        self.metadata.insert(key.to_string(), value.to_string());
        self
    }

    pub fn with_recovery_suggestion(mut self, suggestion: &str) -> Self {
        self.recovery_suggestions.push(suggestion.to_string());
        self
    }
}

/// General agent error types with enhanced context
#[derive(Error, Debug, Serialize, Deserialize)]
pub enum AgentError {
    /// YARA-related errors
    #[error("YARA error: {0}")]
    Yara(#[from] YaraError),

    /// Configuration errors with context
    #[error("Configuration error: {message}")]
    Configuration {
        message: String,
        field: Option<String>,
        context: Option<ErrorContext>,
    },

    /// Network communication errors with retry information
    #[error("Network error: {message}")]
    Network {
        message: String,
        endpoint: Option<String>,
        retry_count: u32,
        context: Option<ErrorContext>,
    },

    /// Database operation errors with transaction info
    #[error("Database error: {message}")]
    Database {
        message: String,
        operation: Option<String>,
        transaction_id: Option<String>,
        context: Option<ErrorContext>,
    },

    /// Authentication and authorization errors
    #[error("Authentication error: {message}")]
    Authentication { 
        message: String,
        user_id: Option<String>,
        context: Option<ErrorContext>,
    },

    /// Service lifecycle errors
    #[error("Service error: {message}")]
    Service { 
        message: String, 
        service: String,
        context: Option<ErrorContext>,
    },

    /// General I/O errors with path information
    #[error("I/O error: {message}")]
    Io {
        message: String,
        path: Option<std::path::PathBuf>,
        operation: Option<String>,
        context: Option<ErrorContext>,
    },

    /// System-level errors
    #[error("System error: {0}")]
    SystemError(String),

    /// Validation errors with field information
    #[error("Validation error: {message}")]
    Validation {
        message: String,
        field: Option<String>,
        expected: Option<String>,
        actual: Option<String>,
        context: Option<ErrorContext>,
    },

    /// Execution errors with process information
    #[error("Execution error: {message}")]
    Execution {
        message: String,
        command: Option<String>,
        exit_code: Option<i32>,
        context: Option<ErrorContext>,
    },

    /// Resource management errors with usage information
    #[error("Resource error: {message}")]
    Resource {
        message: String,
        resource_type: String,
        current_usage: Option<u64>,
        limit: Option<u64>,
        context: Option<ErrorContext>,
    },

    /// Cryptographic operation errors
    #[error("Crypto error: {message}")]
    Crypto {
        message: String,
        algorithm: Option<String>,
        context: Option<ErrorContext>,
    },

    /// Parse errors with position information
    #[error("Parse error: {message}")]
    Parse {
        message: String,
        input: Option<String>,
        position: Option<usize>,
        context: Option<ErrorContext>,
    },

    /// Security errors with threat information
    #[error("Security error: {message}")]
    Security {
        message: String,
        threat_level: Option<String>,
        source_description: Option<String>,
        context: Option<ErrorContext>,
    },

    /// Performance errors with metrics
    #[error("Performance error: {message}")]
    Performance {
        message: String,
        metric: String,
        threshold: f64,
        actual: f64,
        context: Option<ErrorContext>,
    },

    /// Timeout errors with duration information
    #[error("Timeout error: {message}")]
    Timeout {
        message: String,
        operation: String,
        duration: std::time::Duration,
        context: Option<ErrorContext>,
    },
}

impl AgentError {
    /// Add context to an error
    pub fn with_context(mut self, context: ErrorContext) -> Self {
        match &mut self {
            AgentError::Configuration { context: ctx, .. } => *ctx = Some(context),
            AgentError::Network { context: ctx, .. } => *ctx = Some(context),
            AgentError::Database { context: ctx, transaction_id: None, .. } => *ctx = Some(context),
            AgentError::Authentication { context: ctx, .. } => *ctx = Some(context),
            AgentError::Service { context: ctx, .. } => *ctx = Some(context),
            AgentError::Io { context: ctx, .. } => *ctx = Some(context),
            AgentError::Validation { context: ctx, .. } => *ctx = Some(context),
            AgentError::Execution { context: ctx, .. } => *ctx = Some(context),
            AgentError::Resource { context: ctx, .. } => *ctx = Some(context),
            AgentError::Crypto { context: ctx, .. } => *ctx = Some(context),
            AgentError::Parse { context: ctx, .. } => *ctx = Some(context),
            AgentError::Security { context: ctx, .. } => *ctx = Some(context),
            AgentError::Performance { context: ctx, .. } => *ctx = Some(context),
            AgentError::Timeout { context: ctx, .. } => *ctx = Some(context),
            _ => {} // For variants without context
        }
        self
    }

    /// Get the error context if available
    pub fn get_context(&self) -> Option<&ErrorContext> {
        match self {
            AgentError::Configuration { context, .. } => context.as_ref(),
            AgentError::Network { context, .. } => context.as_ref(),
            AgentError::Database { context, .. } => context.as_ref(),
            AgentError::Authentication { context, .. } => context.as_ref(),
            AgentError::Service { context, .. } => context.as_ref(),
            AgentError::Io { context, .. } => context.as_ref(),
            AgentError::Validation { context, .. } => context.as_ref(),
            AgentError::Execution { context, .. } => context.as_ref(),
            AgentError::Resource { context, .. } => context.as_ref(),
            AgentError::Crypto { context, .. } => context.as_ref(),
            AgentError::Parse { context, .. } => context.as_ref(),
            AgentError::Security { context, .. } => context.as_ref(),
            AgentError::Performance { context, .. } => context.as_ref(),
            AgentError::Timeout { context, .. } => context.as_ref(),
            _ => None,
        }
    }

    /// Check if error is recoverable
    pub fn is_recoverable(&self) -> bool {
        match self {
            AgentError::Network { .. } => true,
            AgentError::Database { context: None , transaction_id: None, .. } => true,
            AgentError::Timeout { .. } => true,
            AgentError::Resource { .. } => true,
            AgentError::Performance { context: None, .. } => true,
            AgentError::Configuration { context: None, .. } => false,
            AgentError::Security { .. } => false,
            AgentError::Authentication { .. } => false,
            _ => false,
        }
    }

    /// Get recovery suggestions
    pub fn get_recovery_suggestions(&self) -> Vec<String> {
        let mut suggestions = Vec::new();
        
        if let Some(context) = self.get_context() {
            suggestions.extend(context.recovery_suggestions.clone());
        }

        match self {
            AgentError::Network { .. } => {
                suggestions.push("Check network connectivity".to_string());
                suggestions.push("Verify endpoint configuration".to_string());
                suggestions.push("Retry with exponential backoff".to_string());
            },
            AgentError::Database { .. } => {
                suggestions.push("Check database connection".to_string());
                suggestions.push("Verify transaction state".to_string());
                suggestions.push("Consider connection pooling".to_string());
            },
            AgentError::Resource { .. } => {
                suggestions.push("Free up system resources".to_string());
                suggestions.push("Increase resource limits".to_string());
                suggestions.push("Implement resource cleanup".to_string());
            },
            AgentError::Performance { .. } => {
                suggestions.push("Optimize algorithm performance".to_string());
                suggestions.push("Increase timeout values".to_string());
                suggestions.push("Scale system resources".to_string());
            },
            _ => {}
        }

        suggestions
    }
}

/// Result type alias for agent operations
pub type AgentResult<T> = Result<T, AgentError>;
pub type RansolutionError = AgentError;

/// Implement From for boxed errors
impl From<std::io::Error> for AgentError {
    fn from(error: std::io::Error) -> Self {
        AgentError::Io {
            message: error.to_string(),
            path: None,
            operation: None,
            context: None,
        }
    }
}

impl From<Box<dyn std::error::Error + Send + Sync>> for AgentError {
    fn from(error: Box<dyn std::error::Error + Send + Sync>) -> Self {
        AgentError::SystemError(error.to_string())
    }
}

/// Enhanced error report with structured data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorReport {
    pub id: Uuid,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub error_type: String,
    pub message: String,
    pub severity: ErrorSeverity,
    pub context: std::collections::HashMap<String, String>,
    pub stack_trace: Option<String>,
    pub recovery_action: Option<String>,
    pub correlation_id: Option<Uuid>,
    pub component: Option<String>,
    pub operation: Option<String>,
    pub is_recoverable: bool,
    pub recovery_suggestions: Vec<String>,
}

/// Enhanced error reporter with structured logging
pub struct ErrorReporter {
    reports: std::sync::Arc<std::sync::Mutex<Vec<ErrorReport>>>,
    max_buffer_size: usize,
    endpoint: Option<String>,
    logger: Arc<dyn ErrorLogger + Send + Sync>,
}

/// Trait for error logging implementations
pub trait ErrorLogger {
    fn log_error(&self, report: &ErrorReport);
    fn log_recovery_attempt(&self, error_id: Uuid, action: &str);
    fn log_recovery_success(&self, error_id: Uuid);
    fn log_recovery_failure(&self, error_id: Uuid, reason: &str);
}

/// Default structured logger implementation
pub struct StructuredLogger;

impl ErrorLogger for StructuredLogger {
    fn log_error(&self, report: &ErrorReport) {
        match report.severity {
            ErrorSeverity::Critical => {
                error!(
                    error_id = %report.id,
                    correlation_id = ?report.correlation_id,
                    component = ?report.component,
                    operation = ?report.operation,
                    recoverable = report.is_recoverable,
                    "Critical error: {}",
                    report.message
                );
            },
            ErrorSeverity::Error => {
                error!(
                    error_id = %report.id,
                    correlation_id = ?report.correlation_id,
                    component = ?report.component,
                    operation = ?report.operation,
                    recoverable = report.is_recoverable,
                    "Error: {}",
                    report.message
                );
            },
            ErrorSeverity::Fatal => {
                error!(
                    error_id = %report.id,
                    correlation_id = ?report.correlation_id,
                    component = ?report.component,
                    operation = ?report.operation,
                    recoverable = report.is_recoverable,
                    "Fatal error: {}",
                    report.message
                );
            },
            ErrorSeverity::Warning => {
                warn!(
                    error_id = %report.id,
                    correlation_id = ?report.correlation_id,
                    component = ?report.component,
                    operation = ?report.operation,
                    recoverable = report.is_recoverable,
                    "Warning: {}",
                    report.message
                );
            },
            ErrorSeverity::Info => {
                info!(
                    error_id = %report.id,
                    correlation_id = ?report.correlation_id,
                    component = ?report.component,
                    operation = ?report.operation,
                    recoverable = report.is_recoverable,
                    "Info: {}",
                    report.message
                );
            },
        }
    }

    fn log_recovery_attempt(&self, error_id: Uuid, action: &str) {
        info!(error_id = %error_id, action = action, "Attempting error recovery");
    }

    fn log_recovery_success(&self, error_id: Uuid) {
        info!(error_id = %error_id, "Error recovery successful");
    }

    fn log_recovery_failure(&self, error_id: Uuid, reason: &str) {
        warn!(error_id = %error_id, reason = reason, "Error recovery failed");
    }
}

impl ErrorReporter {
    pub fn new(max_buffer_size: usize, endpoint: Option<String>) -> Self {
        Self {
            reports: Arc::new(std::sync::Mutex::new(Vec::new())),
            max_buffer_size,
            endpoint,
            logger: Arc::new(StructuredLogger),
        }
    }

    pub fn with_logger(mut self, logger: Arc<dyn ErrorLogger + Send + Sync>) -> Self {
        self.logger = logger;
        self
    }

    pub fn report_error(
        &self,
        error: &AgentError,
        context: std::collections::HashMap<String, String>,
    ) {
        let report = ErrorReport {
            id: Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            error_type: self.get_error_type(error),
            message: error.to_string(),
            severity: self.get_error_severity(error),
            context,
            stack_trace: std::backtrace::Backtrace::capture().to_string().into(),
            recovery_action: None,
            correlation_id: error.get_context().map(|ctx| ctx.correlation_id),
            component: error.get_context().map(|ctx| ctx.component.clone()),
            operation: error.get_context().map(|ctx| ctx.operation.clone()),
            is_recoverable: error.is_recoverable(),
            recovery_suggestions: error.get_recovery_suggestions(),
        };

        // Log the error using structured logging
        self.logger.log_error(&report);

        // Store in buffer
        if let Ok(mut reports) = self.reports.lock() {
            reports.push(report);
            if reports.len() > self.max_buffer_size {
                reports.remove(0);
            }
        }
    }

    pub fn attempt_recovery(&self, error_id: Uuid, action: &str) {
        self.logger.log_recovery_attempt(error_id, action);
    }

    pub fn report_recovery_success(&self, error_id: Uuid) {
        self.logger.log_recovery_success(error_id);
    }

    pub fn report_recovery_failure(&self, error_id: Uuid, reason: &str) {
        self.logger.log_recovery_failure(error_id, reason);
    }

    fn get_error_type(&self, error: &AgentError) -> String {
        match error {
            AgentError::Yara(_) => "YARA".to_string(),
            AgentError::Configuration { .. } => "configuration".to_string(),
            AgentError::Network { .. } => "Network".to_string(),
            AgentError::Database { .. } => "Database".to_string(),
            AgentError::Authentication { .. } => "Authentication".to_string(),
            AgentError::Service { .. } => "Service".to_string(),
            AgentError::Io { .. } => "IO".to_string(),
            AgentError::SystemError(_) => "System".to_string(),
            AgentError::Validation { .. } => "Validation".to_string(),
            AgentError::Execution { .. } => "Execution".to_string(),
            AgentError::Resource { .. } => "Resource".to_string(),
            AgentError::Crypto { .. } => "Crypto".to_string(),
            AgentError::Parse { .. } => "Parse".to_string(),
            AgentError::Security { .. } => "Security".to_string(),
            AgentError::Performance { .. } => "Performance".to_string(),
            AgentError::Timeout { .. } => "Timeout".to_string(),
        }
    }

    fn get_error_severity(&self, error: &AgentError) -> ErrorSeverity {
        match error {
            AgentError::Security { .. } => ErrorSeverity::Critical,
            AgentError::Authentication { .. } => ErrorSeverity::Critical,
            AgentError::SystemError(_) => ErrorSeverity::Critical,
            AgentError::Database { .. } => ErrorSeverity::Critical,
            AgentError::Configuration { .. } => ErrorSeverity::Critical,
            AgentError::Network { .. } => ErrorSeverity::Warning,
            AgentError::Performance { .. } => ErrorSeverity::Warning,
            AgentError::Timeout { .. } => ErrorSeverity::Warning,
            AgentError::Resource { .. } => ErrorSeverity::Warning,
            AgentError::Validation { .. } => ErrorSeverity::Info,
            AgentError::Parse { .. } => ErrorSeverity::Info,
            _ => ErrorSeverity::Warning,
        }
    }

    pub fn get_reports(&self) -> Vec<ErrorReport> {
        self.reports.lock().unwrap().clone()
    }

    pub fn clear_reports(&self) {
        if let Ok(mut reports) = self.reports.lock() {
            reports.clear();
        }
    }

    pub async fn flush_reports(&self) -> Result<(), AgentError> {
        if let Some(_endpoint) = &self.endpoint {
            // TODO: Implement remote reporting
            debug!("Flushing error reports to remote endpoint");
        }
        Ok(())
    }
}

/// Enhanced error reporting macro with context
#[macro_export]
macro_rules! report_error_with_context {
    ($reporter:expr, $error:expr, $operation:expr, $component:expr) => {
        {
            let context = $crate::error::ErrorContext::new($operation, $component);
            let error_with_context = $error.with_context(context);
            $reporter.report_error(&error_with_context, std::collections::HashMap::new())
        }
    };
    ($reporter:expr, $error:expr, $operation:expr, $component:expr, $($key:expr => $value:expr),*) => {
        {
            let context = $crate::error::ErrorContext::new($operation, $component);
            let error_with_context = $error.with_context(context);
            let mut metadata = std::collections::HashMap::new();
            $(
                metadata.insert($key.to_string(), $value.to_string());
            )*
            $reporter.report_error(&error_with_context, metadata)
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_reporter() {
        let reporter = ErrorReporter::new(100, None);
        let error = AgentError::Configuration {
            message: "Test error".to_string(),
            field: Some("test_field".to_string()),
            context: None };

        let mut context = std::collections::HashMap::new();
        context.insert("component".to_string(), "test".to_string());

        reporter.report_error(&error, context);

        let reports = reporter.get_reports();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].error_type, "configuration");
    }

    // #[test]
    // fn test_yara_error_macro() {
    //     let error = yara_error!(init, "Test initialization error");
    //     assert!(matches!(error, YaraError::InitializationError { .. }));

    //     let error = yara_error!(fs, "/test/path", FileSystemErrorKind::NotFound);
    //     assert!(matches!(error, YaraError::FileSystemError { .. }));
    // }

    // #[test]
    // fn test_agent_error_conversion() {
    //     let yara_error = yara_error!(init, "Test error");
    //     let agent_error: AgentError = yara_error.into();
    //     assert!(matches!(agent_error, AgentError::Yara(_)));
    // }
}
