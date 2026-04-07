//! Production YARA Rules Integration
//!
//! This module provides comprehensive YARA rules management for ERDPS production deployment.
//! It includes rule compilation, caching, performance optimization, and integration with detection engines.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::fs;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Errors that can occur during YARA rules operations
#[derive(Debug, thiserror::Error)]
pub enum YaraError {
    #[error("Rule compilation failed: {0}")]
    CompilationError(String),
    #[error("Rule not found: {0}")]
    RuleNotFound(String),
    #[error("Invalid rule format: {0}")]
    InvalidFormat(String),
    #[error("Performance threshold exceeded: {0}ms")]
    PerformanceThreshold(u64),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
}

/// YARA rule metadata and information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraRule {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub author: String,
    pub version: String,
    pub rule_content: String,
    pub file_path: PathBuf,
    pub tags: Vec<String>,
    pub severity: RuleSeverity,
    pub performance_score: Option<f64>,
    pub last_updated: chrono::DateTime<chrono::Utc>,
    pub compilation_status: CompilationStatus,
}

/// Rule severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RuleSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// Rule compilation status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CompilationStatus {
    Compiled,
    Failed(String),
    Pending,
    Disabled,
}

/// YARA rule match result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMatch {
    pub rule_id: Uuid,
    pub rule_name: String,
    pub file_path: PathBuf,
    pub matches: Vec<MatchInstance>,
    pub scan_time: Duration,
    pub confidence: f64,
    pub metadata: HashMap<String, String>,
}

/// Individual match instance within a file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchInstance {
    pub offset: u64,
    pub length: u64,
    pub matched_string: String,
    pub context: Option<String>,
}

/// Performance metrics for YARA rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulePerformanceMetrics {
    pub rule_id: Uuid,
    pub total_scans: u64,
    pub total_scan_time: Duration,
    pub average_scan_time: Duration,
    pub fastest_scan: Duration,
    pub slowest_scan: Duration,
    pub match_count: u64,
    pub false_positive_count: u64,
}

/// Configuration for YARA rules management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraConfig {
    pub rules_directory: PathBuf,
    pub compiled_rules_cache: PathBuf,
    pub max_scan_time_ms: u64,
    pub enable_performance_monitoring: bool,
    pub auto_update_rules: bool,
    pub rule_sources: Vec<RuleSource>,
    pub compilation_threads: usize,
}

/// External rule sources configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSource {
    pub name: String,
    pub url: String,
    pub update_interval_hours: u64,
    pub enabled: bool,
    pub authentication: Option<SourceAuthentication>,
}

/// Authentication for rule sources
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceAuthentication {
    pub auth_type: AuthType,
    pub credentials: HashMap<String, String>,
}

/// Authentication types for rule sources
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthType {
    ApiKey,
    BasicAuth,
    OAuth2,
    None,
}

/// Main production YARA manager
pub struct ProductionYaraManager {
    pub config: YaraConfig,
    pub rules: Arc<RwLock<HashMap<Uuid, YaraRule>>>,
    pub compiled_rules: Arc<RwLock<HashMap<Uuid, Vec<u8>>>>,
    pub performance_metrics: Arc<RwLock<HashMap<Uuid, RulePerformanceMetrics>>>,
    pub rule_cache: Arc<RwLock<HashMap<String, Vec<Uuid>>>>, // Tag -> Rule IDs
}

impl ProductionYaraManager {
    /// Create a new production YARA manager
    pub fn new(config: YaraConfig) -> Self {
        Self {
            config,
            rules: Arc::new(RwLock::new(HashMap::new())),
            compiled_rules: Arc::new(RwLock::new(HashMap::new())),
            performance_metrics: Arc::new(RwLock::new(HashMap::new())),
            rule_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Initialize the YARA manager with rule loading and compilation
    pub async fn initialize(&mut self) -> Result<(), YaraError> {
        // Create necessary directories
        fs::create_dir_all(&self.config.rules_directory).await?;
        fs::create_dir_all(&self.config.compiled_rules_cache).await?;

        // Load existing rules
        self.load_rules_from_directory().await?;

        // Update rules from external sources if enabled
        if self.config.auto_update_rules {
            self.update_rules_from_sources().await?;
        }

        // Compile all rules
        self.compile_all_rules().await?;

        // Build rule cache
        self.build_rule_cache().await?;

        Ok(())
    }

    /// Load YARA rules from the rules directory
    pub async fn load_rules_from_directory(&mut self) -> Result<Vec<YaraRule>, YaraError> {
        let mut loaded_rules = Vec::new();
        let mut entries = fs::read_dir(&self.config.rules_directory).await?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            
            if path.extension().and_then(|s| s.to_str()) == Some("yar") ||
               path.extension().and_then(|s| s.to_str()) == Some("yara") {
                
                if let Ok(rule) = self.load_rule_from_file(&path).await {
                    loaded_rules.push(rule.clone());
                    
                    let mut rules = self.rules.write().await;
                    rules.insert(rule.id, rule);
                }
            }
        }

        Ok(loaded_rules)
    }

    /// Load a single YARA rule from file
    async fn load_rule_from_file(&self, file_path: &Path) -> Result<YaraRule, YaraError> {
        let content = fs::read_to_string(file_path).await?;
        
        // Parse rule metadata from content
        let (name, description, author, version, tags) = self.parse_rule_metadata(&content)?;
        
        let rule = YaraRule {
            id: Uuid::new_v4(),
            name,
            description,
            author,
            version,
            rule_content: content,
            file_path: file_path.to_path_buf(),
            tags,
            severity: self.determine_rule_severity(&content),
            performance_score: None,
            last_updated: chrono::Utc::now(),
            compilation_status: CompilationStatus::Pending,
        };

        Ok(rule)
    }

    /// Parse metadata from YARA rule content
    fn parse_rule_metadata(&self, content: &str) -> Result<(String, String, String, String, Vec<String>), YaraError> {
        let mut name = "Unknown".to_string();
        let mut description = "No description".to_string();
        let mut author = "Unknown".to_string();
        let mut version = "1.0".to_string();
        let mut tags = Vec::new();

        // Simple metadata parsing (in production, use proper YARA parser)
        for line in content.lines() {
            let line = line.trim();
            
            if line.starts_with("rule ") {
                if let Some(rule_name) = line.split_whitespace().nth(1) {
                    name = rule_name.trim_end_matches('{').to_string();
                }
            }
            
            if line.contains("description = ") {
                if let Some(desc) = line.split('"').nth(1) {
                    description = desc.to_string();
                }
            }
            
            if line.contains("author = ") {
                if let Some(auth) = line.split('"').nth(1) {
                    author = auth.to_string();
                }
            }
            
            if line.contains("version = ") {
                if let Some(ver) = line.split('"').nth(1) {
                    version = ver.to_string();
                }
            }
            
            if line.contains("tags = ") {
                // Parse tags array
                if let Some(tags_str) = line.split('[').nth(1) {
                    if let Some(tags_content) = tags_str.split(']').next() {
                        tags = tags_content
                            .split(',')
                            .map(|t| t.trim().trim_matches('"').to_string())
                            .collect();
                    }
                }
            }
        }

        Ok((name, description, author, version, tags))
    }

    /// Determine rule severity based on content analysis
    fn determine_rule_severity(&self, content: &str) -> RuleSeverity {
        let content_lower = content.to_lowercase();
        
        if content_lower.contains("ransomware") || 
           content_lower.contains("cryptolocker") ||
           content_lower.contains("wannacry") {
            return RuleSeverity::Critical;
        }
        
        if content_lower.contains("trojan") || 
           content_lower.contains("backdoor") ||
           content_lower.contains("rootkit") {
            return RuleSeverity::High;
        }
        
        if content_lower.contains("suspicious") || 
           content_lower.contains("malware") {
            return RuleSeverity::Medium;
        }
        
        if content_lower.contains("pua") || 
           content_lower.contains("adware") {
            return RuleSeverity::Low;
        }
        
        RuleSeverity::Info
    }

    /// Update rules from external sources
    pub async fn update_rules_from_sources(&mut self) -> Result<(), YaraError> {
        for source in &self.config.rule_sources {
            if source.enabled {
                if let Err(e) = self.update_from_source(source).await {
                    eprintln!("Failed to update from source {}: {}", source.name, e);
                }
            }
        }
        Ok(())
    }

    /// Update rules from a specific source
    async fn update_from_source(&self, source: &RuleSource) -> Result<(), YaraError> {
        // Placeholder for external source integration
        // In production, this would implement:
        // - HTTP client for downloading rules
        // - Authentication handling
        // - Rule validation and parsing
        // - Incremental updates
        
        println!("Updating rules from source: {}", source.name);
        Ok(())
    }

    /// Compile all loaded YARA rules
    pub async fn compile_all_rules(&mut self) -> Result<(), YaraError> {
        let rules = self.rules.read().await;
        let rule_ids: Vec<Uuid> = rules.keys().cloned().collect();
        drop(rules);

        // Compile rules in parallel batches
        let chunk_size = self.config.compilation_threads;
        
        for chunk in rule_ids.chunks(chunk_size) {
            let mut handles = Vec::new();
            
            for &rule_id in chunk {
                let rules_clone = Arc::clone(&self.rules);
                let compiled_rules_clone = Arc::clone(&self.compiled_rules);
                
                let handle = tokio::spawn(async move {
                    Self::compile_single_rule(rule_id, rules_clone, compiled_rules_clone).await
                });
                
                handles.push(handle);
            }
            
            // Wait for all compilations in this batch
            for handle in handles {
                if let Err(e) = handle.await {
                    eprintln!("Rule compilation task failed: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Compile a single YARA rule
    async fn compile_single_rule(
        rule_id: Uuid,
        rules: Arc<RwLock<HashMap<Uuid, YaraRule>>>,
        compiled_rules: Arc<RwLock<HashMap<Uuid, Vec<u8>>>>,
    ) -> Result<(), YaraError> {
        let rule_content = {
            let rules_guard = rules.read().await;
            rules_guard.get(&rule_id)
                .map(|r| r.rule_content.clone())
                .ok_or_else(|| YaraError::RuleNotFound(rule_id.to_string()))?
        };

        // Simulate rule compilation (in production, use actual YARA library)
        let compilation_result = Self::simulate_yara_compilation(&rule_content).await;
        
        match compilation_result {
            Ok(compiled_bytes) => {
                // Store compiled rule
                let mut compiled_guard = compiled_rules.write().await;
                compiled_guard.insert(rule_id, compiled_bytes);
                
                // Update rule status
                let mut rules_guard = rules.write().await;
                if let Some(rule) = rules_guard.get_mut(&rule_id) {
                    rule.compilation_status = CompilationStatus::Compiled;
                }
            }
            Err(error) => {
                // Update rule status with error
                let mut rules_guard = rules.write().await;
                if let Some(rule) = rules_guard.get_mut(&rule_id) {
                    rule.compilation_status = CompilationStatus::Failed(error.to_string());
                }
            }
        }

        Ok(())
    }

    /// Simulate YARA rule compilation
    async fn simulate_yara_compilation(rule_content: &str) -> Result<Vec<u8>, YaraError> {
        // Basic validation
        if !rule_content.contains("rule ") {
            return Err(YaraError::InvalidFormat("Missing rule declaration".to_string()));
        }
        
        if !rule_content.contains("condition:") {
            return Err(YaraError::InvalidFormat("Missing condition section".to_string()));
        }
        
        // Simulate compilation delay
        tokio::time::sleep(Duration::from_millis(10)).await;
        
        // Return mock compiled bytes
        Ok(rule_content.as_bytes().to_vec())
    }

    /// Build rule cache for fast lookups
    async fn build_rule_cache(&mut self) -> Result<(), YaraError> {
        let mut cache = self.rule_cache.write().await;
        cache.clear();
        
        let rules = self.rules.read().await;
        
        for (rule_id, rule) in rules.iter() {
            // Cache by tags
            for tag in &rule.tags {
                cache.entry(tag.clone())
                    .or_insert_with(Vec::new)
                    .push(*rule_id);
            }
            
            // Cache by severity
            let severity_key = format!("severity:{:?}", rule.severity);
            cache.entry(severity_key)
                .or_insert_with(Vec::new)
                .push(*rule_id);
        }
        
        Ok(())
    }

    /// Scan a file with YARA rules
    pub async fn scan_file(&self, file_path: &Path, rule_filter: Option<Vec<String>>) -> Result<Vec<YaraMatch>, YaraError> {
        let start_time = Instant::now();
        let mut matches = Vec::new();
        
        // Get rules to scan with
        let rule_ids = if let Some(filter) = rule_filter {
            self.get_rules_by_tags(&filter).await?
        } else {
            let rules = self.rules.read().await;
            rules.keys().cloned().collect()
        };
        
        // Read file content
        let file_content = fs::read(file_path).await?;
        
        // Scan with each rule
        for rule_id in rule_ids {
            if let Some(rule_match) = self.scan_with_rule(rule_id, file_path, &file_content).await? {
                matches.push(rule_match);
            }
        }
        
        let scan_duration = start_time.elapsed();
        
        // Check performance threshold
        if scan_duration.as_millis() > self.config.max_scan_time_ms as u128 {
            return Err(YaraError::PerformanceThreshold(scan_duration.as_millis() as u64));
        }
        
        Ok(matches)
    }

    /// Get rules by tags
    async fn get_rules_by_tags(&self, tags: &[String]) -> Result<Vec<Uuid>, YaraError> {
        let cache = self.rule_cache.read().await;
        let mut rule_ids = Vec::new();
        
        for tag in tags {
            if let Some(ids) = cache.get(tag) {
                rule_ids.extend(ids);
            }
        }
        
        // Remove duplicates
        rule_ids.sort();
        rule_ids.dedup();
        
        Ok(rule_ids)
    }

    /// Scan file content with a specific rule
    async fn scan_with_rule(
        &self,
        rule_id: Uuid,
        file_path: &Path,
        file_content: &[u8],
    ) -> Result<Option<YaraMatch>, YaraError> {
        let start_time = Instant::now();
        
        // Get rule information
        let rule_name = {
            let rules = self.rules.read().await;
            rules.get(&rule_id)
                .map(|r| r.name.clone())
                .ok_or_else(|| YaraError::RuleNotFound(rule_id.to_string()))?
        };
        
        // Check if rule is compiled
        let compiled_rules = self.compiled_rules.read().await;
        if !compiled_rules.contains_key(&rule_id) {
            return Ok(None);
        }
        
        // Simulate YARA scanning (in production, use actual YARA library)
        let match_instances = self.simulate_yara_scan(rule_id, file_content).await?;
        
        let scan_time = start_time.elapsed();
        
        // Update performance metrics
        self.update_rule_performance_metrics(rule_id, scan_time, !match_instances.is_empty()).await;
        
        if !match_instances.is_empty() {
            Ok(Some(YaraMatch {
                rule_id,
                rule_name,
                file_path: file_path.to_path_buf(),
                matches: match_instances,
                scan_time,
                confidence: 0.95, // Mock confidence
                metadata: HashMap::new(),
            }))
        } else {
            Ok(None)
        }
    }

    /// Simulate YARA scanning
    async fn simulate_yara_scan(&self, _rule_id: Uuid, file_content: &[u8]) -> Result<Vec<MatchInstance>, YaraError> {
        // Simulate scanning delay
        tokio::time::sleep(Duration::from_micros(100)).await;
        
        // Mock match detection (in production, use actual YARA library)
        if file_content.len() > 1000 && file_content.windows(4).any(|w| w == b"test") {
            Ok(vec![MatchInstance {
                offset: 0,
                length: 4,
                matched_string: "test".to_string(),
                context: Some("Mock match context".to_string()),
            }])
        } else {
            Ok(Vec::new())
        }
    }

    /// Update performance metrics for a rule
    async fn update_rule_performance_metrics(&self, rule_id: Uuid, scan_time: Duration, had_match: bool) {
        if !self.config.enable_performance_monitoring {
            return;
        }
        
        let mut metrics = self.performance_metrics.write().await;
        
        let rule_metrics = metrics.entry(rule_id).or_insert_with(|| {
            RulePerformanceMetrics {
                rule_id,
                total_scans: 0,
                total_scan_time: Duration::ZERO,
                average_scan_time: Duration::ZERO,
                fastest_scan: scan_time,
                slowest_scan: scan_time,
                match_count: 0,
                false_positive_count: 0,
            }
        });
        
        rule_metrics.total_scans += 1;
        rule_metrics.total_scan_time += scan_time;
        rule_metrics.average_scan_time = rule_metrics.total_scan_time / rule_metrics.total_scans as u32;
        
        if scan_time < rule_metrics.fastest_scan {
            rule_metrics.fastest_scan = scan_time;
        }
        
        if scan_time > rule_metrics.slowest_scan {
            rule_metrics.slowest_scan = scan_time;
        }
        
        if had_match {
            rule_metrics.match_count += 1;
        }
    }

    /// Get performance metrics for all rules
    pub async fn get_performance_metrics(&self) -> HashMap<Uuid, RulePerformanceMetrics> {
        self.performance_metrics.read().await.clone()
    }

    /// Get rules by severity level
    pub async fn get_rules_by_severity(&self, severity: RuleSeverity) -> Vec<YaraRule> {
        let rules = self.rules.read().await;
        rules.values()
            .filter(|rule| rule.severity == severity)
            .cloned()
            .collect()
    }

    /// Export rules and metrics for reporting
    pub async fn export_rules_report(&self, output_path: &Path) -> Result<(), YaraError> {
        let rules = self.rules.read().await;
        let metrics = self.performance_metrics.read().await;
        
        let report = serde_json::json!({
            "rules": *rules,
            "performance_metrics": *metrics,
            "export_timestamp": chrono::Utc::now(),
        });
        
        let report_json = serde_json::to_string_pretty(&report)?;
        fs::write(output_path, report_json).await?;
        
        Ok(())
    }
}

/// Default YARA configuration
impl Default for YaraConfig {
    fn default() -> Self {
        Self {
            rules_directory: PathBuf::from("./yara_rules"),
            compiled_rules_cache: PathBuf::from("./compiled_rules"),
            max_scan_time_ms: 5000, // 5 seconds
            enable_performance_monitoring: true,
            auto_update_rules: true,
            rule_sources: vec![
                RuleSource {
                    name: "YARA-Rules".to_string(),
                    url: "https://github.com/Yara-Rules/rules".to_string(),
                    update_interval_hours: 24,
                    enabled: true,
                    authentication: None,
                },
            ],
            compilation_threads: 4,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_yara_manager_creation() {
        let temp_dir = TempDir::new().unwrap();
        let config = YaraConfig {
            rules_directory: temp_dir.path().to_path_buf(),
            ..Default::default()
        };
        
        let manager = ProductionYaraManager::new(config);
        assert_eq!(manager.rules.read().await.len(), 0);
    }

    #[tokio::test]
    async fn test_rule_severity_determination() {
        let temp_dir = TempDir::new().unwrap();
        let config = YaraConfig {
            rules_directory: temp_dir.path().to_path_buf(),
            ..Default::default()
        };
        
        let manager = ProductionYaraManager::new(config);
        
        assert_eq!(manager.determine_rule_severity("ransomware detection"), RuleSeverity::Critical);
        assert_eq!(manager.determine_rule_severity("trojan behavior"), RuleSeverity::High);
        assert_eq!(manager.determine_rule_severity("suspicious activity"), RuleSeverity::Medium);
        assert_eq!(manager.determine_rule_severity("pua detection"), RuleSeverity::Low);
        assert_eq!(manager.determine_rule_severity("generic info"), RuleSeverity::Info);
    }

    #[tokio::test]
    async fn test_metadata_parsing() {
        let temp_dir = TempDir::new().unwrap();
        let config = YaraConfig {
            rules_directory: temp_dir.path().to_path_buf(),
            ..Default::default()
        };
        
        let manager = ProductionYaraManager::new(config);
        
        let rule_content = r#"
            rule TestRule {
                meta:
                    description = "Test rule for validation"
                    author = "ERDPS Team"
                    version = "1.0"
                strings:
                    $test = "malware"
                condition:
                    $test
            }
        "#;
        
        let (name, description, author, version, _tags) = manager.parse_rule_metadata(rule_content).unwrap();
        
        assert_eq!(name, "TestRule");
        assert_eq!(description, "Test rule for validation");
        assert_eq!(author, "ERDPS Team");
        assert_eq!(version, "1.0");
    }
}
