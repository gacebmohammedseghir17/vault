//! YARA Rule Manager for thread-safe rule compilation and scanning
//!
//! This module provides a comprehensive YARA rule management system with:
//! - Thread-safe rule caching using Arc<RwLock<Rules>>
//! - Hot-reloading capabilities with atomic rule swapping
//! - File and memory scanning APIs
//! - Comprehensive error handling and logging

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use log::{debug, error, info, warn};
use thiserror::Error;
use yara_x::{Compiler, MetaValue, Rules, Scanner};

// Removed unused import: use crate::metrics::get_metrics;

/// Errors that can occur during YARA rule management operations
#[derive(Error, Debug)]
pub enum YaraRuleError {
    #[error("YARA compilation error: {0}")]
    CompilationError(String),

    #[error("File access error for {path}: {source}")]
    FileAccess {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("YARA scanning error: {0}")]
    ScanError(String),

    #[error("Rules not loaded - call load_from_dir first")]
    RulesNotLoaded,

    #[error("Invalid rule directory: {0}")]
    InvalidDirectory(String),

    #[error("YARA library error: {0}")]
    YaraLibraryError(#[from] yara_x::errors::CompileError),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Represents a YARA rule match with detailed information
#[derive(Debug, Clone)]
pub struct YaraMatch {
    /// Name of the matched YARA rule
    pub rule_name: String,
    /// Namespace of the rule (if any)
    pub namespace: String,
    /// Tags associated with the rule
    pub tags: Vec<String>,
    /// Rule metadata
    pub metadata: HashMap<String, String>,
    /// Matched strings information
    pub strings: Vec<MatchedString>,
    /// Timestamp when match was found
    pub timestamp: u64,
}

/// Information about a matched string within a YARA rule
#[derive(Debug, Clone)]
pub struct MatchedString {
    /// String identifier from the rule
    pub identifier: String,
    /// Offset in the scanned data
    pub offset: u64,
    /// Length of the match
    pub length: usize,
    /// Matched data (hex representation, truncated to 64 bytes)
    pub data: String,
}

/// Statistics about rule compilation and loading
#[derive(Debug, Clone)]
pub struct RuleStats {
    /// Number of rule files loaded
    pub files_loaded: usize,
    /// Total number of rules compiled
    pub rules_count: usize,
    /// Time taken for compilation
    pub compilation_time: Duration,
    /// Timestamp of last successful load
    pub last_loaded: SystemTime,
    /// Directory path of loaded rules
    pub rules_directory: PathBuf,
    /// Number of files with compilation errors
    pub compile_errors: usize,
    /// Files that had compilation errors (filename -> error message)
    pub error_files: HashMap<String, String>,
}

/// Thread-safe YARA rule manager with hot-reloading capabilities
pub struct YaraRuleManager {
    /// Thread-safe cache of compiled YARA rules
    rules: Arc<RwLock<Option<Rules>>>,
    /// Statistics about loaded rules
    stats: Arc<RwLock<Option<RuleStats>>>,
    /// File modification times for hot-reload detection
    file_mtimes: Arc<RwLock<HashMap<PathBuf, SystemTime>>>,
    /// Rules directory path
    rules_directory: Arc<RwLock<Option<PathBuf>>>,
}

impl Default for YaraRuleManager {
    fn default() -> Self {
        Self::new()
    }
}

impl YaraRuleManager {
    /// Create a new YARA rule manager
    pub fn new() -> Self {
        info!("Initializing YARA rule manager");
        Self {
            rules: Arc::new(RwLock::new(None)),
            stats: Arc::new(RwLock::new(None)),
            file_mtimes: Arc::new(RwLock::new(HashMap::new())),
            rules_directory: Arc::new(RwLock::new(None)),
        }
    }

    /// Normalize YARA rule content by stripping BOM, removing leading blank lines,
    /// and validating that the file is not empty
    fn normalize_rule_content(&self, content: &str, file_path: &Path) -> Result<String, String> {
        // Strip BOM if present (UTF-8 BOM is 0xEF 0xBB 0xBF)
        let content = if content.starts_with('\u{FEFF}') {
            debug!("Stripped BOM from rule file: {}", file_path.display());
            &content[1..]
        } else {
            content
        };

        // Remove leading blank lines
        let lines: Vec<&str> = content.lines().collect();
        let mut start_idx = 0;

        for (idx, line) in lines.iter().enumerate() {
            if !line.trim().is_empty() {
                start_idx = idx;
                break;
            }
        }

        if start_idx > 0 {
            debug!(
                "Removed {} leading blank lines from rule file: {}",
                start_idx,
                file_path.display()
            );
        }

        // Reconstruct content without leading blank lines
        let normalized_content = if start_idx < lines.len() {
            lines[start_idx..].join("\n")
        } else {
            String::new()
        };

        // Validate that the file is not empty after normalization
        if normalized_content.trim().is_empty() {
            return Err(format!(
                "Rule file is empty after normalization: {}",
                file_path.display()
            ));
        }

        // Basic validation - check if it looks like a YARA rule
        if !normalized_content.contains("rule ") {
            return Err(format!(
                "Rule file does not contain any YARA rules: {}",
                file_path.display()
            ));
        }

        Ok(normalized_content)
    }

    /// Load and compile YARA rules from a directory
    ///
    /// # Arguments
    /// * `path` - Directory path containing .yar/.yara files
    ///
    /// # Returns
    /// Number of rule files successfully loaded
    pub async fn load_from_dir(&self, path: &str) -> Result<usize, YaraRuleError> {
        let start_time = Instant::now();
        let rules_path = Path::new(path);

        info!("Loading YARA rules from directory: {}", path);

        if !rules_path.exists() {
            return Err(YaraRuleError::InvalidDirectory(format!(
                "Directory does not exist: {}",
                path
            )));
        }

        if !rules_path.is_dir() {
            return Err(YaraRuleError::InvalidDirectory(format!(
                "Path is not a directory: {}",
                path
            )));
        }

        // Find all YARA rule files
        let rule_files = self.find_rule_files(rules_path)?;

        if rule_files.is_empty() {
            warn!("No YARA rule files found in directory: {}", path);
            return Ok(0);
        }

        info!("Found {} YARA rule files", rule_files.len());

        // Compile rules
        let (compiled_rules, file_mtimes, rules_count, error_count, error_files) =
            self.compile_rules(&rule_files).await?;
        let compilation_time = start_time.elapsed();

        // Update internal state atomically
        {
            let mut rules_guard = self.rules.write().unwrap();
            *rules_guard = Some(compiled_rules);
        }

        {
            let mut stats_guard = self.stats.write().unwrap();
            *stats_guard = Some(RuleStats {
                files_loaded: rule_files.len(),
                rules_count,
                compilation_time,
                last_loaded: SystemTime::now(),
                rules_directory: rules_path.to_path_buf(),
                compile_errors: error_count,
                error_files,
            });
        }

        {
            let mut mtimes_guard = self.file_mtimes.write().unwrap();
            *mtimes_guard = file_mtimes;
        }

        {
            let mut dir_guard = self.rules_directory.write().unwrap();
            *dir_guard = Some(rules_path.to_path_buf());
        }

        info!(
            "Successfully loaded {} rules from {} files in {:.2}ms",
            rules_count,
            rule_files.len(),
            compilation_time.as_millis()
        );

        Ok(rule_files.len())
    }

    /// Check if rules have been loaded
    pub fn is_loaded(&self) -> bool {
        self.rules.read().unwrap().is_some()
    }

    /// Get the number of loaded rules
    pub fn rules_count(&self) -> usize {
        self.stats
            .read()
            .unwrap()
            .as_ref()
            .map(|s| s.rules_count)
            .unwrap_or(0)
    }

    /// Get statistics about loaded rules
    pub fn get_stats(&self) -> Option<RuleStats> {
        self.stats.read().unwrap().clone()
    }

    /// Find all YARA rule files in a directory (recursive)
    fn find_rule_files(&self, dir: &Path) -> Result<Vec<PathBuf>, YaraRuleError> {
        let mut rule_files = Vec::new();

        fn visit_dir(dir: &Path, files: &mut Vec<PathBuf>) -> Result<(), std::io::Error> {
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();

                if path.is_dir() {
                    visit_dir(&path, files)?;
                } else if let Some(ext) = path.extension() {
                    if ext == "yar" || ext == "yara" {
                        files.push(path);
                    }
                }
            }
            Ok(())
        }

        visit_dir(dir, &mut rule_files).map_err(|e| YaraRuleError::FileAccess {
            path: dir.to_string_lossy().to_string(),
            source: e,
        })?;

        rule_files.sort();
        Ok(rule_files)
    }

    /// Compile YARA rules from file paths
    async fn compile_rules(
        &self,
        rule_files: &[PathBuf],
    ) -> Result<
        (
            Rules,
            HashMap<PathBuf, SystemTime>,
            usize,
            usize,
            HashMap<String, String>,
        ),
        YaraRuleError,
    > {
        let mut compiler = Compiler::new();

        // Define external variables at compile time
        // These must be defined at compile time for YARA-X compatibility
        if let Err(e) = compiler.define_global("filename", "") {
            warn!(
                "Failed to define filename external variable at compile time: {}",
                e
            );
        }
        if let Err(e) = compiler.define_global("filepath", "") {
            warn!(
                "Failed to define filepath external variable at compile time: {}",
                e
            );
        }
        if let Err(e) = compiler.define_global("extension", "") {
            warn!(
                "Failed to define extension external variable at compile time: {}",
                e
            );
        }

        let mut file_mtimes = HashMap::new();
        let mut compiled_count = 0;
        let mut total_rules = 0;
        let mut error_count = 0;
        let mut error_files = HashMap::new();

        for rule_file in rule_files {
            debug!("Compiling rule file: {}", rule_file.display());

            // Get file modification time
            let metadata = match fs::metadata(rule_file) {
                Ok(metadata) => metadata,
                Err(e) => {
                    let error_msg = format!("Failed to read metadata: {}", e);
                    error!("Error processing {}: {}", rule_file.display(), error_msg);
                    error_files.insert(
                        rule_file
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .to_string(),
                        error_msg,
                    );
                    error_count += 1;
                    continue;
                }
            };

            let mtime = match metadata.modified() {
                Ok(mtime) => mtime,
                Err(e) => {
                    let error_msg = format!("Failed to get modification time: {}", e);
                    error!("Error processing {}: {}", rule_file.display(), error_msg);
                    error_files.insert(
                        rule_file
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .to_string(),
                        error_msg,
                    );
                    error_count += 1;
                    continue;
                }
            };

            file_mtimes.insert(rule_file.clone(), mtime);

            // Read rule file
            let rule_content = match fs::read_to_string(rule_file) {
                Ok(content) => content,
                Err(e) => {
                    let error_msg = format!("Failed to read file: {}", e);
                    error!("Error processing {}: {}", rule_file.display(), error_msg);
                    error_files.insert(
                        rule_file
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .to_string(),
                        error_msg,
                    );
                    error_count += 1;
                    continue;
                }
            };

            // Normalize rule content
            let normalized_content = match self.normalize_rule_content(&rule_content, rule_file) {
                Ok(content) => content,
                Err(error_msg) => {
                    error!("Error normalizing {}: {}", rule_file.display(), error_msg);
                    let filename = rule_file
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string();
                    error_files.insert(filename.clone(), error_msg);

                    // Update metrics for compilation error
                    if let Some(metrics) = crate::metrics::get_metrics().await {
                        metrics.inc_compile_error_for(&filename);
                    }

                    error_count += 1;
                    continue;
                }
            };

            // Count rules in this file by counting "rule " occurrences
            let rules_in_file = normalized_content.matches("rule ").count();
            total_rules += rules_in_file;
            debug!("Found {} rules in {}", rules_in_file, rule_file.display());

            // Add normalized content to compiler
            if let Err(e) = compiler.add_source(normalized_content.as_str()) {
                let error_msg = format!("Compilation failed: {}", e);
                error!("Error compiling {}: {}", rule_file.display(), error_msg);
                let filename = rule_file
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                error_files.insert(filename.clone(), error_msg);

                // Update metrics for compilation error
                if let Some(metrics) = crate::metrics::get_metrics().await {
                    metrics.inc_compile_error_for(&filename);
                }

                error_count += 1;
                continue;
            }

            compiled_count += 1;
        }

        if compiled_count == 0 {
            return Err(YaraRuleError::CompilationError(
                "No rule files could be compiled successfully".to_string(),
            ));
        }

        debug!(
            "Finalizing compilation of {} rule files with {} total rules ({} errors)",
            compiled_count, total_rules, error_count
        );

        if error_count > 0 {
            warn!(
                "Compilation completed with {} errors out of {} files",
                error_count,
                rule_files.len()
            );
        }

        let rules = compiler.build();

        // Update metrics for successfully loaded rules
        if let Some(metrics) = crate::metrics::get_metrics().await {
            metrics.set_rules_loaded(total_rules as i64);
        }

        Ok((rules, file_mtimes, total_rules, error_count, error_files))
    }

    /// Hot-reload rules if any files have been updated
    ///
    /// This method safely reloads rules by:
    /// 1. Checking file modification times
    /// 2. Compiling new ruleset into temporary object
    /// 3. Atomically swapping only if compilation succeeds
    /// 4. Logging errors without crashing on invalid rules
    pub async fn reload_if_updated(&self) -> Result<bool, YaraRuleError> {
        let rules_dir = {
            let dir_guard = self.rules_directory.read().unwrap();
            match dir_guard.as_ref() {
                Some(dir) => dir.clone(),
                None => {
                    debug!("No rules directory set, skipping reload check");
                    return Ok(false);
                }
            }
        };

        debug!("Checking for rule file updates in: {}", rules_dir.display());

        // Check if any files have been modified
        let current_files = self.find_rule_files(&rules_dir)?;
        let mut needs_reload = false;

        {
            let mtimes_guard = self.file_mtimes.read().unwrap();

            // Check for new files
            for file in &current_files {
                if !mtimes_guard.contains_key(file) {
                    info!("New rule file detected: {}", file.display());
                    needs_reload = true;
                    break;
                }
            }

            // Check for modified files
            if !needs_reload {
                for file in &current_files {
                    if let Ok(metadata) = fs::metadata(file) {
                        if let Ok(mtime) = metadata.modified() {
                            if let Some(cached_mtime) = mtimes_guard.get(file) {
                                if mtime > *cached_mtime {
                                    info!("Modified rule file detected: {}", file.display());
                                    needs_reload = true;
                                    break;
                                }
                            }
                        }
                    }
                }
            }

            // Check for deleted files
            if !needs_reload {
                for cached_file in mtimes_guard.keys() {
                    if !current_files.contains(cached_file) {
                        info!("Deleted rule file detected: {}", cached_file.display());
                        needs_reload = true;
                        break;
                    }
                }
            }
        }

        if !needs_reload {
            debug!("No rule file changes detected");
            return Ok(false);
        }

        info!("Rule file changes detected, initiating hot-reload");
        let start_time = Instant::now();

        // Attempt to compile new ruleset
        match self.compile_rules(&current_files).await {
            Ok((new_rules, new_mtimes, rules_count, error_count, error_files)) => {
                let compilation_time = start_time.elapsed();

                // Atomic swap of rules
                {
                    let mut rules_guard = self.rules.write().unwrap();
                    *rules_guard = Some(new_rules);
                }

                // Update statistics
                {
                    let mut stats_guard = self.stats.write().unwrap();
                    *stats_guard = Some(RuleStats {
                        files_loaded: current_files.len(),
                        rules_count,
                        compilation_time,
                        last_loaded: SystemTime::now(),
                        rules_directory: rules_dir,
                        compile_errors: error_count,
                        error_files,
                    });
                }

                // Update file modification times
                {
                    let mut mtimes_guard = self.file_mtimes.write().unwrap();
                    *mtimes_guard = new_mtimes;
                }

                info!(
                    "Hot-reload completed successfully: {} rules from {} files in {:.2}ms",
                    rules_count,
                    current_files.len(),
                    compilation_time.as_millis()
                );

                Ok(true)
            }
            Err(e) => {
                error!("Hot-reload failed due to compilation error: {}", e);
                warn!("Keeping existing rules loaded to maintain service availability");

                // Don't propagate the error - log it but keep existing rules
                // This ensures the service remains operational even with invalid new rules
                Ok(false)
            }
        }
    }

    /// Scan a file for YARA rule matches
    ///
    /// # Arguments
    /// * `path` - Path to the file to scan
    ///
    /// # Returns
    /// Vector of YARA matches found in the file
    pub fn matches_file(&self, path: &Path) -> Result<Vec<YaraMatch>, YaraRuleError> {
        debug!("Scanning file: {}", path.display());

        // Read file content
        let file_data = fs::read(path).map_err(|e| YaraRuleError::FileAccess {
            path: path.to_string_lossy().to_string(),
            source: e,
        })?;

        // Perform scan while holding the lock
        let rules_guard = self.rules.read().unwrap();
        match rules_guard.as_ref() {
            Some(rules) => self.scan_data_with_externals(rules, &file_data, Some(path)),
            None => Err(YaraRuleError::RulesNotLoaded),
        }
    }

    /// Scan byte data for YARA rule matches
    ///
    /// # Arguments
    /// * `data` - Byte data to scan
    ///
    /// # Returns
    /// Vector of YARA matches found in the data
    pub fn matches_bytes(&self, data: &[u8]) -> Result<Vec<YaraMatch>, YaraRuleError> {
        debug!("Scanning {} bytes of data", data.len());

        // Perform scan while holding the lock
        let rules_guard = self.rules.read().unwrap();
        match rules_guard.as_ref() {
            Some(rules) => self.scan_data_with_externals(rules, data, None),
            None => Err(YaraRuleError::RulesNotLoaded),
        }
    }

    /// Internal method to scan data with compiled rules and external variables
    fn scan_data_with_externals(
        &self,
        rules: &Rules,
        data: &[u8],
        file_path: Option<&Path>,
    ) -> Result<Vec<YaraMatch>, YaraRuleError> {
        let mut scanner = Scanner::new(rules);
        scanner.set_timeout(std::time::Duration::from_secs(30));

        // Set external variables if file path is provided
        if let Some(path) = file_path {
            // Set filename external variable
            if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
                if let Err(e) = scanner.set_global("filename", filename) {
                    warn!("Failed to set filename external variable: {}", e);
                }
            }

            // Set filepath external variable
            let filepath = path.to_string_lossy();
            if let Err(e) = scanner.set_global("filepath", filepath.as_ref()) {
                warn!("Failed to set filepath external variable: {}", e);
            }

            // Set extension external variable
            if let Some(extension) = path.extension().and_then(|e| e.to_str()) {
                if let Err(e) = scanner.set_global("extension", extension) {
                    warn!("Failed to set extension external variable: {}", e);
                }
            }
        }

        let scan_results = scanner
            .scan(data)
            .map_err(|e| YaraRuleError::ScanError(format!("YARA scan failed: {}", e)))?;

        let mut matches = Vec::new();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        for rule in scan_results.matching_rules() {
            let mut metadata = HashMap::new();

            // Extract rule metadata
            for (key, value) in rule.metadata() {
                let value_str = match value {
                    MetaValue::Integer(i) => i.to_string(),
                    MetaValue::Float(f) => f.to_string(),
                    MetaValue::Bool(b) => b.to_string(),
                    MetaValue::String(s) => s.to_string(),
                    MetaValue::Bytes(b) => {
                        // Convert bytes to hex string
                        b.iter()
                            .map(|byte| format!("{:02x}", byte))
                            .collect::<String>()
                    }
                };
                metadata.insert(key.to_string(), value_str);
            }

            let mut matched_strings = Vec::new();

            // Extract matched strings
            for pattern in rule.patterns() {
                for m in pattern.matches() {
                    let match_range = m.range();
                    let offset = match_range.start;
                    let length = match_range.len();

                    let match_data = if data.len() > offset {
                        let end_offset = std::cmp::min(offset + length, data.len());
                        &data[offset..end_offset]
                    } else {
                        &[]
                    };

                    // Convert to hex string for binary data
                    let hex_data = if match_data.len() <= 64 {
                        match_data
                            .iter()
                            .map(|byte| format!("{:02x}", byte))
                            .collect::<String>()
                    } else {
                        format!(
                            "{}...",
                            match_data[..64]
                                .iter()
                                .map(|byte| format!("{:02x}", byte))
                                .collect::<String>()
                        )
                    };

                    matched_strings.push(MatchedString {
                        identifier: pattern.identifier().to_string(),
                        offset: offset as u64,
                        length,
                        data: hex_data,
                    });
                }
            }

            let rule_name = rule.identifier().to_string();
            let yara_match = YaraMatch {
                rule_name: rule_name.clone(),
                namespace: rule.namespace().to_string(),
                tags: vec!["malware".to_string(), "detection".to_string()], // Default tags for YARA rules
                metadata: HashMap::new(), // Initialize empty metadata
                strings: matched_strings,
                timestamp,
            };

            matches.push(yara_match);
            debug!("Found match: {}", rule_name);
        }

        if !matches.is_empty() {
            info!("Found {} YARA matches", matches.len());
        }

        Ok(matches)
    }
}

#[cfg(all(test, feature = "yara"))]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use tempfile::TempDir;
    use tokio::time::Duration;

    // Helper function to create a temporary directory with YARA rules
    fn create_test_rules_dir() -> (TempDir, String) {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let rules_path = temp_dir.path().to_str().unwrap().to_string();

        // Create a valid YARA rule based on WannaCry patterns
        let valid_rule = r#"
rule WannaCry_Ransomware {
    meta:
        description = "WannaCry Ransomware Detection"
        family = "ransomware"
        severity = "high"
    strings:
        $wannacry_sig = "WNcry@2ol7"
    condition:
        $wannacry_sig
}
"#;

        let rule_file_path = temp_dir.path().join("wannacry_test.yar");
        let mut file = fs::File::create(&rule_file_path).expect("Failed to create rule file");
        file.write_all(valid_rule.as_bytes())
            .expect("Failed to write rule");

        (temp_dir, rules_path)
    }

    fn create_invalid_rules_dir() -> (TempDir, String) {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let rules_path = temp_dir.path().to_str().unwrap().to_string();

        // Create an invalid YARA rule
        let invalid_rule = r#"
rule InvalidRule {
    strings:
        $test_string = "MALWARE_SIGNATURE"
    condition:
        invalid_syntax_here
}
"#;

        let rule_file_path = temp_dir.path().join("invalid_rule.yar");
        let mut file = fs::File::create(&rule_file_path).expect("Failed to create rule file");
        file.write_all(invalid_rule.as_bytes())
            .expect("Failed to write rule");

        (temp_dir, rules_path)
    }

    fn create_test_file_with_content(content: &[u8]) -> (TempDir, std::path::PathBuf) {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let file_path = temp_dir.path().join("test_file.bin");

        let mut file = fs::File::create(&file_path).expect("Failed to create test file");
        file.write_all(content)
            .expect("Failed to write test content");

        (temp_dir, file_path)
    }

    #[test]
    fn test_new_manager() {
        let manager = YaraRuleManager::new();
        assert!(!manager.is_loaded());
        assert_eq!(manager.rules_count(), 0);
    }

    #[tokio::test]
    async fn test_load_valid_rules() {
        let (_temp_dir, rules_path) = create_test_rules_dir();
        let manager = YaraRuleManager::new();

        let result = manager.load_from_dir(&rules_path).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1); // Should load 1 rule
        assert!(manager.is_loaded());
        assert_eq!(manager.rules_count(), 1);
    }

    #[tokio::test]
    async fn test_load_invalid_rules() {
        let (_temp_dir, rules_path) = create_invalid_rules_dir();
        let manager = YaraRuleManager::new();

        let result = manager.load_from_dir(&rules_path).await;
        assert!(result.is_err());
        assert!(!manager.is_loaded());
        assert_eq!(manager.rules_count(), 0);
    }

    #[tokio::test]
    async fn test_load_nonexistent_directory() {
        let manager = YaraRuleManager::new();

        let result = manager.load_from_dir("/nonexistent/path").await;
        assert!(result.is_err());
        assert!(!manager.is_loaded());
    }

    #[tokio::test]
    async fn test_matches_bytes_with_match() {
        let (_temp_dir, rules_path) = create_test_rules_dir();
        let manager = YaraRuleManager::new();

        // Load rules first
        manager
            .load_from_dir(&rules_path)
            .await
            .expect("Failed to load rules");

        // Test data that should match
        let test_data = b"This contains WNcry@2ol7 in the middle";
        let result = manager.matches_bytes(test_data);

        assert!(result.is_ok());
        let matches = result.unwrap();
        assert!(!matches.is_empty());
        assert_eq!(matches[0].rule_name, "WannaCry_Ransomware");
    }

    #[tokio::test]
    async fn test_matches_bytes_without_match() {
        let (_temp_dir, rules_path) = create_test_rules_dir();
        let manager = YaraRuleManager::new();

        // Load rules first
        manager
            .load_from_dir(&rules_path)
            .await
            .expect("Failed to load rules");

        // Test data that should not match
        let test_data = b"This is clean data without any suspicious content";
        let result = manager.matches_bytes(test_data);

        assert!(result.is_ok());
        let matches = result.unwrap();
        assert!(matches.is_empty());
    }

    #[tokio::test]
    async fn test_matches_file_with_match() {
        let (_temp_dir, rules_path) = create_test_rules_dir();
        let manager = YaraRuleManager::new();

        // Load rules first
        manager
            .load_from_dir(&rules_path)
            .await
            .expect("Failed to load rules");

        // Create test file with matching content
        let test_content = b"This file contains WNcry@2ol7";
        let (_file_temp_dir, file_path) = create_test_file_with_content(test_content);

        let result = manager.matches_file(&file_path);

        assert!(result.is_ok());
        let matches = result.unwrap();
        assert!(!matches.is_empty());
        assert_eq!(matches[0].rule_name, "WannaCry_Ransomware");
    }

    #[test]
    fn test_scan_without_loaded_rules() {
        let manager = YaraRuleManager::new();

        let test_data = b"Some test data";
        let result = manager.matches_bytes(test_data);

        assert!(result.is_err());
        match result.unwrap_err() {
            YaraRuleError::RulesNotLoaded => {} // Expected error
            _ => panic!("Expected RulesNotLoaded error"),
        }
    }

    #[tokio::test]
    async fn test_get_stats() {
        let (_temp_dir, rules_path) = create_test_rules_dir();
        let manager = YaraRuleManager::new();

        // Load rules first
        manager
            .load_from_dir(&rules_path)
            .await
            .expect("Failed to load rules");

        let stats = manager.get_stats().expect("Failed to get stats");
        assert_eq!(stats.rules_count, 1);
        assert!(stats.compilation_time > Duration::from_nanos(0));
    }

    #[tokio::test]
    async fn test_empty_directory() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let rules_path = temp_dir.path().to_str().unwrap().to_string();

        let manager = YaraRuleManager::new();
        let result = manager.load_from_dir(&rules_path).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0); // No rules loaded
        assert!(!manager.is_loaded()); // Should not be considered loaded with 0 rules
    }

    #[tokio::test]
    async fn test_multiple_rule_files() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let rules_path = temp_dir.path().to_str().unwrap().to_string();

        // Create multiple rule files
        let rule1 = r#"
rule Rule1 {
    strings:
        $test1 = "SIGNATURE1"
    condition:
        $test1
}
"#;

        let rule2 = r#"
rule Rule2 {
    strings:
        $test2 = "SIGNATURE2"
    condition:
        $test2
}
"#;

        // Write first rule file
        let rule_file1 = temp_dir.path().join("rule1.yar");
        let mut file1 = fs::File::create(&rule_file1).expect("Failed to create rule file 1");
        file1
            .write_all(rule1.as_bytes())
            .expect("Failed to write rule 1");

        // Write second rule file
        let rule_file2 = temp_dir.path().join("rule2.yara");
        let mut file2 = fs::File::create(&rule_file2).expect("Failed to create rule file 2");
        file2
            .write_all(rule2.as_bytes())
            .expect("Failed to write rule 2");

        let manager = YaraRuleManager::new();
        let result = manager.load_from_dir(&rules_path).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 2); // Should load 2 rules
        assert!(manager.is_loaded());
        assert_eq!(manager.rules_count(), 2);
    }
}
