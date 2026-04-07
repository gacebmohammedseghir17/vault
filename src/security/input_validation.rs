//! Input Validation and Sanitization Module
//!
//! This module provides comprehensive input validation and sanitization capabilities
//! to prevent injection attacks, buffer overflows, and other security vulnerabilities.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;
use regex::Regex;
use serde::{Deserialize, Serialize};
use tracing::warn;
use uuid::Uuid;
use crate::error::{AgentError, AgentResult, ErrorContext};

/// Input validation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationConfig {
    /// Maximum string length for various input types
    pub max_string_lengths: HashMap<String, usize>,
    /// Allowed file extensions
    pub allowed_file_extensions: Vec<String>,
    /// Blocked file extensions
    pub blocked_file_extensions: Vec<String>,
    /// Maximum file size in bytes
    pub max_file_size: u64,
    /// Enable strict path validation
    pub strict_path_validation: bool,
    /// Enable SQL injection detection
    pub enable_sql_injection_detection: bool,
    /// Enable XSS detection
    pub enable_xss_detection: bool,
    /// Enable command injection detection
    pub enable_command_injection_detection: bool,
    /// Custom validation patterns
    pub custom_patterns: HashMap<String, String>,
}

/// Validation result
#[derive(Debug, Clone, PartialEq)]
pub enum ValidationResult {
    Valid,
    Invalid(ValidationError),
    Sanitized(String),
}

/// Validation error types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ValidationError {
    TooLong { max_length: usize, actual_length: usize },
    TooShort { min_length: usize, actual_length: usize },
    InvalidFormat { expected: String, actual: String },
    ContainsForbiddenCharacters { forbidden_chars: Vec<char> },
    PathTraversal,
    SqlInjection,
    XssAttempt,
    CommandInjection,
    InvalidFileExtension { extension: String },
    FileTooLarge { max_size: u64, actual_size: u64 },
    InvalidIpAddress,
    InvalidUuid,
    InvalidEmail,
    InvalidUrl,
    CustomPatternMismatch { pattern_name: String },
}

/// Input validator
pub struct InputValidator {
    config: ValidationConfig,
    sql_injection_patterns: Vec<Regex>,
    xss_patterns: Vec<Regex>,
    command_injection_patterns: Vec<Regex>,
    path_traversal_patterns: Vec<Regex>,
    email_regex: Regex,
    url_regex: Regex,
    custom_regexes: HashMap<String, Regex>,
}

impl InputValidator {
    /// Create a new input validator
    pub fn new(config: ValidationConfig) -> AgentResult<Self> {
        let sql_injection_patterns = Self::compile_sql_injection_patterns()?;
        let xss_patterns = Self::compile_xss_patterns()?;
        let command_injection_patterns = Self::compile_command_injection_patterns()?;
        let path_traversal_patterns = Self::compile_path_traversal_patterns()?;
        
        let email_regex = Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
            .map_err(|e| AgentError::Parse {
                message: format!("Failed to compile email regex: {}", e),
                input: None,
                position: None,
                context: Some(ErrorContext::new("new", "input_validator")),
            })?;

        let url_regex = Regex::new(r"^https?://[a-zA-Z0-9.-]+(?:\.[a-zA-Z]{2,})?(?:/[^\s]*)?$")
            .map_err(|e| AgentError::Parse {
                message: format!("Failed to compile URL regex: {}", e),
                input: None,
                position: None,
                context: Some(ErrorContext::new("new", "input_validator")),
            })?;

        let mut custom_regexes = HashMap::new();
        for (name, pattern) in &config.custom_patterns {
            let regex = Regex::new(pattern).map_err(|e| AgentError::Parse {
                message: format!("Failed to compile custom regex '{}': {}", name, e),
                input: Some(pattern.clone()),
                position: None,
                context: Some(ErrorContext::new("new", "input_validator")),
            })?;
            custom_regexes.insert(name.clone(), regex);
        }

        Ok(Self {
            config,
            sql_injection_patterns,
            xss_patterns,
            command_injection_patterns,
            path_traversal_patterns,
            email_regex,
            url_regex,
            custom_regexes,
        })
    }

    /// Validate a string input
    pub fn validate_string(&self, input: &str, input_type: &str) -> ValidationResult {
        // Check length constraints
        if let Some(&max_length) = self.config.max_string_lengths.get(input_type) {
            if input.len() > max_length {
                return ValidationResult::Invalid(ValidationError::TooLong {
                    max_length,
                    actual_length: input.len(),
                });
            }
        }

        // Check for SQL injection
        if self.config.enable_sql_injection_detection {
            if let Some(error) = self.check_sql_injection(input) {
                return ValidationResult::Invalid(error);
            }
        }

        // Check for XSS
        if self.config.enable_xss_detection {
            if let Some(error) = self.check_xss(input) {
                return ValidationResult::Invalid(error);
            }
        }

        // Check for command injection
        if self.config.enable_command_injection_detection {
            if let Some(error) = self.check_command_injection(input) {
                return ValidationResult::Invalid(error);
            }
        }

        ValidationResult::Valid
    }

    /// Validate and sanitize a string input
    pub fn sanitize_string(&self, input: &str, input_type: &str) -> ValidationResult {
        let mut sanitized = input.to_string();
        let mut was_sanitized = false;

        // Remove potentially dangerous characters
        let dangerous_chars = ['<', '>', '"', '\'', '&', '\0', '\r', '\n'];
        for &ch in &dangerous_chars {
            if sanitized.contains(ch) {
                sanitized = sanitized.replace(ch, "");
                was_sanitized = true;
            }
        }

        // Check length after sanitization
        if let Some(&max_length) = self.config.max_string_lengths.get(input_type) {
            if sanitized.len() > max_length {
                sanitized.truncate(max_length);
                was_sanitized = true;
            }
        }

        if was_sanitized {
            ValidationResult::Sanitized(sanitized)
        } else {
            ValidationResult::Valid
        }
    }

    /// Validate a file path
    pub fn validate_path(&self, path: &Path) -> ValidationResult {
        let path_str = path.to_string_lossy();

        // Check for path traversal attempts
        for pattern in &self.path_traversal_patterns {
            if pattern.is_match(&path_str) {
                warn!("Path traversal attempt detected: {}", path_str);
                return ValidationResult::Invalid(ValidationError::PathTraversal);
            }
        }

        // Check file extension if specified
        if let Some(extension) = path.extension() {
            let ext_str = extension.to_string_lossy().to_lowercase();
            
            // Check blocked extensions
            if self.config.blocked_file_extensions.contains(&ext_str) {
                return ValidationResult::Invalid(ValidationError::InvalidFileExtension {
                    extension: ext_str,
                });
            }

            // Check allowed extensions (if specified)
            if !self.config.allowed_file_extensions.is_empty() 
                && !self.config.allowed_file_extensions.contains(&ext_str) {
                return ValidationResult::Invalid(ValidationError::InvalidFileExtension {
                    extension: ext_str,
                });
            }
        }

        ValidationResult::Valid
    }

    /// Validate file size
    pub fn validate_file_size(&self, size: u64) -> ValidationResult {
        if size > self.config.max_file_size {
            ValidationResult::Invalid(ValidationError::FileTooLarge {
                max_size: self.config.max_file_size,
                actual_size: size,
            })
        } else {
            ValidationResult::Valid
        }
    }

    /// Validate an IP address
    pub fn validate_ip_address(&self, ip_str: &str) -> ValidationResult {
        match IpAddr::from_str(ip_str) {
            Ok(_) => ValidationResult::Valid,
            Err(_) => ValidationResult::Invalid(ValidationError::InvalidIpAddress),
        }
    }

    /// Validate a UUID
    pub fn validate_uuid(&self, uuid_str: &str) -> ValidationResult {
        match Uuid::from_str(uuid_str) {
            Ok(_) => ValidationResult::Valid,
            Err(_) => ValidationResult::Invalid(ValidationError::InvalidUuid),
        }
    }

    /// Validate an email address
    pub fn validate_email(&self, email: &str) -> ValidationResult {
        if self.email_regex.is_match(email) {
            ValidationResult::Valid
        } else {
            ValidationResult::Invalid(ValidationError::InvalidEmail)
        }
    }

    /// Validate a URL
    pub fn validate_url(&self, url: &str) -> ValidationResult {
        if self.url_regex.is_match(url) {
            ValidationResult::Valid
        } else {
            ValidationResult::Invalid(ValidationError::InvalidUrl)
        }
    }

    /// Validate against a custom pattern
    pub fn validate_custom_pattern(&self, input: &str, pattern_name: &str) -> ValidationResult {
        if let Some(regex) = self.custom_regexes.get(pattern_name) {
            if regex.is_match(input) {
                ValidationResult::Valid
            } else {
                ValidationResult::Invalid(ValidationError::CustomPatternMismatch {
                    pattern_name: pattern_name.to_string(),
                })
            }
        } else {
            ValidationResult::Invalid(ValidationError::CustomPatternMismatch {
                pattern_name: pattern_name.to_string(),
            })
        }
    }

    /// Check for SQL injection patterns
    fn check_sql_injection(&self, input: &str) -> Option<ValidationError> {
        for pattern in &self.sql_injection_patterns {
            if pattern.is_match(input) {
                warn!("SQL injection attempt detected: {}", input);
                return Some(ValidationError::SqlInjection);
            }
        }
        None
    }

    /// Check for XSS patterns
    fn check_xss(&self, input: &str) -> Option<ValidationError> {
        for pattern in &self.xss_patterns {
            if pattern.is_match(input) {
                warn!("XSS attempt detected: {}", input);
                return Some(ValidationError::XssAttempt);
            }
        }
        None
    }

    /// Check for command injection patterns
    fn check_command_injection(&self, input: &str) -> Option<ValidationError> {
        for pattern in &self.command_injection_patterns {
            if pattern.is_match(input) {
                warn!("Command injection attempt detected: {}", input);
                return Some(ValidationError::CommandInjection);
            }
        }
        None
    }

    /// Compile SQL injection detection patterns
    fn compile_sql_injection_patterns() -> AgentResult<Vec<Regex>> {
        let patterns = vec![
            r"(?i)(union\s+select)",
            r"(?i)(select\s+.*\s+from)",
            r"(?i)(insert\s+into)",
            r"(?i)(delete\s+from)",
            r"(?i)(update\s+.*\s+set)",
            r"(?i)(drop\s+table)",
            r"(?i)(create\s+table)",
            r"(?i)(alter\s+table)",
            r"(?i)(\'\s*or\s*\'\s*=\s*\')",
            r"(?i)(\'\s*or\s*1\s*=\s*1)",
            r"(?i)(--\s*$)",
            r"(?i)(/\*.*\*/)",
            r"(?i)(exec\s*\()",
            r"(?i)(sp_executesql)",
        ];

        let mut compiled_patterns = Vec::new();
        for pattern in patterns {
            let regex = Regex::new(pattern).map_err(|e| AgentError::Parse {
                message: format!("Failed to compile SQL injection pattern: {}", e),
                input: Some(pattern.to_string()),
                position: None,
                context: Some(ErrorContext::new("compile_sql_injection_patterns", "input_validator")),
            })?;
            compiled_patterns.push(regex);
        }

        Ok(compiled_patterns)
    }

    /// Compile XSS detection patterns
    fn compile_xss_patterns() -> AgentResult<Vec<Regex>> {
        let patterns = vec![
            r"(?i)<script[^>]*>",
            r"(?i)</script>",
            r"(?i)<iframe[^>]*>",
            r"(?i)<object[^>]*>",
            r"(?i)<embed[^>]*>",
            r"(?i)<link[^>]*>",
            r"(?i)<meta[^>]*>",
            r"(?i)javascript:",
            r"(?i)vbscript:",
            r"(?i)onload\s*=",
            r"(?i)onerror\s*=",
            r"(?i)onclick\s*=",
            r"(?i)onmouseover\s*=",
            r"(?i)onfocus\s*=",
            r"(?i)onblur\s*=",
            r"(?i)eval\s*\(",
            r"(?i)expression\s*\(",
        ];

        let mut compiled_patterns = Vec::new();
        for pattern in patterns {
            let regex = Regex::new(pattern).map_err(|e| AgentError::Parse {
                message: format!("Failed to compile XSS pattern: {}", e),
                input: Some(pattern.to_string()),
                position: None,
                context: Some(ErrorContext::new("compile_xss_patterns", "input_validator")),
            })?;
            compiled_patterns.push(regex);
        }

        Ok(compiled_patterns)
    }

    /// Compile command injection detection patterns
    fn compile_command_injection_patterns() -> AgentResult<Vec<Regex>> {
        let patterns = vec![
            r"(?i)(\|\s*[a-z])",
            r"(?i)(&&\s*[a-z])",
            r"(?i)(\|\|\s*[a-z])",
            r"(?i)(;\s*[a-z])",
            r"(?i)(`[^`]*`)",
            r"(?i)(\$\([^)]*\))",
            r"(?i)(>\s*/)",
            r"(?i)(<\s*/)",
            r"(?i)(>>\s*/)",
            r"(?i)(nc\s+-)",
            r"(?i)(wget\s+)",
            r"(?i)(curl\s+)",
            r"(?i)(chmod\s+)",
            r"(?i)(rm\s+-)",
            r"(?i)(cat\s+/)",
        ];

        let mut compiled_patterns = Vec::new();
        for pattern in patterns {
            let regex = Regex::new(pattern).map_err(|e| AgentError::Parse {
                message: format!("Failed to compile command injection pattern: {}", e),
                input: Some(pattern.to_string()),
                position: None,
                context: Some(ErrorContext::new("compile_command_injection_patterns", "input_validator")),
            })?;
            compiled_patterns.push(regex);
        }

        Ok(compiled_patterns)
    }

    /// Compile path traversal detection patterns
    fn compile_path_traversal_patterns() -> AgentResult<Vec<Regex>> {
        let patterns = vec![
            r"\.\.[\\/]",
            r"[\\/]\.\.[\\/]",
            r"\.\.[\\/]\.\.[\\/]",
            r"%2e%2e[\\/]",
            r"[\\/]%2e%2e[\\/]",
            r"%2e%2e%2f",
            r"%2e%2e%5c",
            r"\.\.%2f",
            r"\.\.%5c",
            r"%c0%ae%c0%ae[\\/]",
            r"%c1%9c",
        ];

        let mut compiled_patterns = Vec::new();
        for pattern in patterns {
            let regex = Regex::new(pattern).map_err(|e| AgentError::Parse {
                message: format!("Failed to compile path traversal pattern: {}", e),
                input: Some(pattern.to_string()),
                position: None,
                context: Some(ErrorContext::new("compile_path_traversal_patterns", "input_validator")),
            })?;
            compiled_patterns.push(regex);
        }

        Ok(compiled_patterns)
    }
}

impl Default for ValidationConfig {
    fn default() -> Self {
        let mut max_string_lengths = HashMap::new();
        max_string_lengths.insert("general".to_string(), 1000);
        max_string_lengths.insert("filename".to_string(), 255);
        max_string_lengths.insert("path".to_string(), 4096);
        max_string_lengths.insert("email".to_string(), 254);
        max_string_lengths.insert("url".to_string(), 2048);
        max_string_lengths.insert("description".to_string(), 5000);

        Self {
            max_string_lengths,
            allowed_file_extensions: vec![
                "txt".to_string(),
                "log".to_string(),
                "json".to_string(),
                "xml".to_string(),
                "csv".to_string(),
                "pdf".to_string(),
                "doc".to_string(),
                "docx".to_string(),
                "xls".to_string(),
                "xlsx".to_string(),
            ],
            blocked_file_extensions: vec![
                "exe".to_string(),
                "bat".to_string(),
                "cmd".to_string(),
                "com".to_string(),
                "pif".to_string(),
                "scr".to_string(),
                "vbs".to_string(),
                "js".to_string(),
                "jar".to_string(),
                "ps1".to_string(),
            ],
            max_file_size: 100 * 1024 * 1024, // 100MB
            strict_path_validation: true,
            enable_sql_injection_detection: true,
            enable_xss_detection: true,
            enable_command_injection_detection: true,
            custom_patterns: HashMap::new(),
        }
    }
}
