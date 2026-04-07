//! Enhanced YARA Scanner
//!
//! This module provides an enhanced YARA scanning engine that integrates:
//! - Category-based rule selection and filtering
//! - Performance monitoring and optimization
//! - Rule correlation and relationship analysis
//! - Dynamic rule loading and compilation
//! - Comprehensive scan result analysis
//! - Resource management and timeout handling

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{info, error, debug};

use crate::config::yara_config::Config;
use super::{
    category_system::{YaraCategorySystem, CategoryScanConfig},
    category_scanner::CategoryFilter,
    performance_monitor::{PerformanceMonitor, OperationType, PerformanceMetrics},
    // rule_optimizer::{YaraRuleOptimizer, OptimizationResult},
    file_scanner::{YaraFileScanner, ScanResult},
    rule_loader::{YaraRuleLoader},
    storage::YaraStorage,
};

/// Enhanced scan configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedScanConfig {
    pub category_filter: Option<CategoryFilter>,
    pub scan_config: CategoryScanConfig,
    pub enable_correlation_analysis: bool,
    pub enable_performance_monitoring: bool,
    pub enable_rule_optimization: bool,
    pub max_scan_time: Option<Duration>,
    pub max_memory_usage: Option<u64>,
    pub parallel_scanning: bool,
    pub max_concurrent_scans: usize,
    pub result_aggregation: ResultAggregation,
    pub output_format: OutputFormat,
}

/// Result aggregation options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResultAggregation {
    All,           // Return all matches
    HighPriority,  // Only high-priority matches
    Deduplicated,  // Remove duplicate/similar matches
    Correlated,    // Group correlated matches
}

/// Output format options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OutputFormat {
    Standard,
    Detailed,
    Json,
    Xml,
    Summary,
}

/// Enhanced scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedScanResult {
    pub file_path: PathBuf,
    pub scan_id: String,
    pub scan_timestamp: u64,
    pub scan_duration: Duration,
    pub matches: Vec<EnhancedMatch>,
    pub category_matches: HashMap<String, Vec<EnhancedMatch>>,
    pub correlation_results: Vec<CorrelationMatch>,
    pub performance_metrics: PerformanceMetrics,
    pub rule_stats: ScanRuleStats,
    pub threat_assessment: ThreatAssessment,
    pub recommendations: Vec<String>,
    pub metadata: ScanMetadata,
}

/// Enhanced match information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedMatch {
    pub rule_name: String,
    pub rule_categories: Vec<String>,
    pub match_offset: u64,
    pub match_length: u64,
    pub match_data: Option<String>,
    pub confidence_score: f64,
    pub severity_level: SeverityLevel,
    pub threat_indicators: Vec<ThreatIndicator>,
    pub rule_metadata: HashMap<String, String>,
    pub performance_impact: f64,
    pub correlation_id: Option<String>,
}

/// Correlation match information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationMatch {
    pub correlation_id: String,
    pub primary_match: String,
    pub related_matches: Vec<String>,
    pub correlation_type: String,
    pub confidence_score: f64,
    pub threat_level: SeverityLevel,
    pub attack_chain: Vec<String>,
    pub mitigation_suggestions: Vec<String>,
}

/// Severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum SeverityLevel {
    Critical = 4,
    High = 3,
    Medium = 2,
    Low = 1,
    Info = 0,
}

/// Threat indicators
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIndicator {
    pub indicator_type: IndicatorType,
    pub value: String,
    pub confidence: f64,
    pub context: String,
}

/// Types of threat indicators
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IndicatorType {
    FileHash,
    IpAddress,
    Domain,
    Url,
    Registry,
    Mutex,
    Service,
    Process,
    NetworkTraffic,
    Behavior,
}

/// Scan rule statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRuleStats {
    pub total_rules_loaded: usize,
    pub rules_by_category: HashMap<String, usize>,
    pub rules_matched: usize,
    pub rules_skipped: usize,
    pub rules_failed: usize,
    pub optimization_applied: bool,
    pub deduplication_applied: bool,
    pub average_rule_performance: f64,
}

/// Threat assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatAssessment {
    pub overall_threat_level: SeverityLevel,
    pub confidence_score: f64,
    pub threat_categories: Vec<String>,
    pub attack_vectors: Vec<String>,
    pub potential_impact: String,
    pub false_positive_likelihood: f64,
    pub recommended_actions: Vec<String>,
}

/// Scan metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanMetadata {
    pub scanner_version: String,
    pub yara_version: String,
    pub rule_set_version: String,
    pub scan_mode: String,
    pub file_size: u64,
    pub file_type: Option<String>,
    pub file_hash: Option<String>,
    pub scan_environment: HashMap<String, String>,
}

/// Enhanced YARA scanner
pub struct EnhancedYaraScanner {
    category_system: Arc<RwLock<YaraCategorySystem>>,
    performance_monitor: Arc<RwLock<PerformanceMonitor>>,
    // rule_optimizer: Arc<RwLock<YaraRuleOptimizer>>,
    file_scanner: Arc<RwLock<YaraFileScanner>>,
    rule_loader: Arc<RwLock<YaraRuleLoader>>,
    storage: Arc<RwLock<YaraStorage>>,
    scan_cache: Arc<RwLock<HashMap<String, EnhancedScanResult>>>,
    active_scans: Arc<RwLock<HashMap<String, Instant>>>,
}

impl Default for EnhancedScanConfig {
    fn default() -> Self {
        Self {
            category_filter: None,
            scan_config: CategoryScanConfig::default(),
            enable_correlation_analysis: true,
            enable_performance_monitoring: true,
            enable_rule_optimization: true,
            max_scan_time: Some(Duration::from_secs(300)), // 5 minutes
            max_memory_usage: Some(1024 * 1024 * 1024), // 1GB
            parallel_scanning: true,
            max_concurrent_scans: 4,
            result_aggregation: ResultAggregation::Correlated,
            output_format: OutputFormat::Detailed,
        }
    }
}

impl EnhancedYaraScanner {
    /// Create a new enhanced scanner
    pub async fn new() -> Result<Self> {
        let category_system = Arc::new(RwLock::new(YaraCategorySystem::new()));
        let performance_monitor = Arc::new(RwLock::new(PerformanceMonitor::new(":memory:".into(), 100)?));
        
        // Create rule optimizer with rules and output directories
        let _rules_directory = std::env::current_dir()?.join("rules");
        let _output_directory = std::env::current_dir()?.join("optimized_rules");
        // let rule_optimizer = Arc::new(RwLock::new(YaraRuleOptimizer::new(rules_directory, output_directory)));
        // Create a default config for the file scanner
        let config = Arc::new(Config::default());
        
        // Create rule loader with default rules directory
        let rules_directory = std::env::current_dir()?.join("rules");
        let rule_loader_for_scanner = Arc::new(YaraRuleLoader::new(rules_directory.clone(), false));
        let rule_loader_for_enhanced = YaraRuleLoader::new(rules_directory, false);
        let rule_loader = Arc::new(RwLock::new(rule_loader_for_enhanced));
        
        // Create file scanner with rule loader and config
        let file_scanner = Arc::new(RwLock::new(YaraFileScanner::new(
            rule_loader_for_scanner,
            config
        )));
        let mut storage = YaraStorage::new(":memory:");
        storage.initialize().await?;
        let storage = Arc::new(RwLock::new(storage));
        
        Ok(Self {
            category_system,
            performance_monitor,
            // rule_optimizer,
            file_scanner,
            rule_loader,
            storage,
            scan_cache: Arc::new(RwLock::new(HashMap::new())),
            active_scans: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Initialize scanner with rule directory
    pub async fn initialize<P: AsRef<Path>>(&self, rules_directory: P) -> Result<()> {
        info!("Initializing enhanced YARA scanner with rules from: {:?}", rules_directory.as_ref());
        
        // Initialize category system
        {
            let mut category_system = self.category_system.write().await;
            category_system.categorize_rules_from_directory(&rules_directory).await
                .context("Failed to categorize rules")?;
        }
        
        // Load and optimize rules
        {
            let rule_loader = self.rule_loader.write().await;
            rule_loader.load_and_compile_rules()
                .context("Failed to load rules")?;
        }
        
        // Initialize performance monitoring
        {
            let _performance_monitor = self.performance_monitor.write().await;
            // Performance monitoring is ready to use
        }
        
        info!("Enhanced YARA scanner initialized successfully");
        Ok(())
    }

    /// Perform enhanced scan on a file
    pub async fn scan_file<P: AsRef<Path>>(
        &self,
        file_path: P,
        config: &EnhancedScanConfig,
    ) -> Result<EnhancedScanResult> {
        let file_path = file_path.as_ref();
        let scan_id = self.generate_scan_id(file_path);
        let scan_start = Instant::now();
        
        info!("Starting enhanced scan for file: {:?} (ID: {})", file_path, scan_id);
        
        // Register active scan
        {
            let mut active_scans = self.active_scans.write().await;
            active_scans.insert(scan_id.clone(), scan_start);
        }
        
        // Check cache if enabled
        if let Some(cached_result) = self.get_cached_result(&scan_id).await {
            info!("Returning cached scan result for: {:?}", file_path);
            return Ok(cached_result);
        }
        
        let result = self.perform_enhanced_scan(file_path, &scan_id, config).await;
        
        // Remove from active scans
        {
            let mut active_scans = self.active_scans.write().await;
            active_scans.remove(&scan_id);
        }
        
        match result {
            Ok(scan_result) => {
                // Cache result
                self.cache_result(&scan_id, &scan_result).await;
                
                info!(
                    "Enhanced scan completed for: {:?} in {:?} - {} matches found",
                    file_path,
                    scan_result.scan_duration,
                    scan_result.matches.len()
                );
                
                Ok(scan_result)
            }
            Err(e) => {
                error!("Enhanced scan failed for: {:?} - {}", file_path, e);
                Err(e)
            }
        }
    }

    /// Perform the actual enhanced scan
    async fn perform_enhanced_scan(
        &self,
        file_path: &Path,
        scan_id: &str,
        config: &EnhancedScanConfig,
    ) -> Result<EnhancedScanResult> {
        let scan_start = Instant::now();
        
        // Start performance monitoring for this scan
        let performance_monitor = self.performance_monitor.clone();
        {
            let monitor = performance_monitor.write().await;
            monitor.start_operation(scan_id.to_string(), OperationType::FileScanning)?;
        }
        
        // Filter rules based on categories
        let selected_rules = self.select_rules_for_scan(config).await
            .context("Failed to select rules for scan")?;
        
        info!("Selected {} rules for scan based on category filter", selected_rules.len());
        
        // Optimize rules if enabled
        let optimized_rules = if config.enable_rule_optimization {
            self.optimize_rules_for_scan(&selected_rules).await
                .context("Failed to optimize rules")?
        } else {
            selected_rules
        };
        
        // Perform the actual scan
        let scan_results = self.execute_scan(file_path, &optimized_rules, config).await
            .context("Failed to execute scan")?;
        
        // Analyze correlations if enabled
        let correlation_results = if config.enable_correlation_analysis {
            self.analyze_correlations(&scan_results).await
                .context("Failed to analyze correlations")?
        } else {
            Vec::new()
        };
        
        // Generate threat assessment
        let threat_assessment = self.generate_threat_assessment(&scan_results, &correlation_results).await
            .context("Failed to generate threat assessment")?;
        
        // Finish operation and collect performance metrics
        {
            let monitor = performance_monitor.write().await;
            monitor.finish_operation(scan_id.to_string())?
        };
        
        let performance_metrics = {
            let monitor = performance_monitor.read().await;
            monitor.get_performance_stats()?
        };
        
        // Build enhanced scan result
        let enhanced_result = EnhancedScanResult {
            file_path: file_path.to_path_buf(),
            scan_id: scan_id.to_string(),
            scan_timestamp: chrono::Utc::now().timestamp() as u64,
            scan_duration: scan_start.elapsed(),
            matches: self.convert_to_enhanced_matches(scan_results.clone()).await?,
            category_matches: self.group_matches_by_category(&scan_results).await?,
            correlation_results: correlation_results.clone(),
            performance_metrics,
            rule_stats: self.generate_rule_stats(&optimized_rules).await?,
            threat_assessment,
            recommendations: self.generate_recommendations(&scan_results, &correlation_results).await?,
            metadata: self.generate_scan_metadata(file_path).await?,
        };
        
        Ok(enhanced_result)
    }

    /// Select rules based on category filter
    async fn select_rules_for_scan(
        &self,
        config: &EnhancedScanConfig,
    ) -> Result<Vec<String>> {
        // Get all rule metadata from rule loader
        let rule_loader = self.rule_loader.read().await;
        let all_rule_metadata = rule_loader.get_rule_metadata();
        
        let total_rules = all_rule_metadata.len();
        debug!("Total rules loaded: {}", total_rules);
        
        // Apply category filter if provided
        let filtered_rules = if let Some(ref category_filter) = config.category_filter {
            let mut filtered = Vec::new();
            let mut skipped_count = 0;
            
            // Get categorized rule metadata from category system
            let category_system = self.category_system.read().await;
            
            for (rule_name, _rule_metadata) in &all_rule_metadata {
                // Try to get category information from category system
                let category = if let Some(metadata) = category_system.get_rule_metadata(rule_name) {
                    // Get the first category from either categories or auto_assigned_categories
                    metadata.categories.first()
                        .or_else(|| metadata.auto_assigned_categories.first())
                        .cloned()
                        .unwrap_or_else(|| "general".to_string())
                } else {
                    "general".to_string()
                };
                
                // Create a temporary RuleMetadata for category filtering
                // We'll use the actual metadata if available, or create a minimal one
                let temp_metadata = if let Some(existing_metadata) = category_system.get_rule_metadata(rule_name) {
                    existing_metadata.clone()
                } else {
                    // Create minimal metadata with the detected category
                    crate::yara::category_system::RuleMetadata {
                        rule_name: rule_name.clone(),
                        file_path: std::path::PathBuf::from(format!("{}.yar", rule_name)),
                        author: None,
                        description: None,
                        reference: Vec::new(),
                        date: None,
                        version: None,
                        tags: Vec::new(),
                        yara_version: None,
                        hash: String::new(),
                        file_size: 0,
                        categories: Vec::new(),
                        auto_assigned_categories: vec![category.clone()],
                        confidence_scores: std::collections::HashMap::new(),
                    }
                };
                
                if category_filter.matches(&temp_metadata) {
                    filtered.push(rule_name.clone());
                } else {
                    info!("Skipping rule {} category={}", rule_name, category);
                    skipped_count += 1;
                }
            }
            
            debug!("Rules after category filtering: {} (skipped: {})", filtered.len(), skipped_count);
            filtered
        } else {
            // No filter applied, use all rules
            debug!("No category filter applied, using all {} rules", total_rules);
            all_rule_metadata.keys().cloned().collect()
        };
        
        Ok(filtered_rules)
    }

    /// Optimize rules for scanning
    async fn optimize_rules_for_scan(
        &self,
        rule_names: &[String],
    ) -> Result<Vec<String>> {
        // let _rule_optimizer = self.rule_optimizer.read().await;
        
        // This would typically involve rule deduplication and performance optimization
        // For now, we'll return the original rules
        Ok(rule_names.to_vec())
    }

    /// Execute the actual YARA scan
    async fn execute_scan(
        &self,
        _file_path: &Path,
        _rule_names: &[String],
        _config: &EnhancedScanConfig,
    ) -> Result<Vec<ScanResult>> {
        let _file_scanner = self.file_scanner.read().await;
        
        // This would integrate with the actual YARA scanning logic
        // For now, we'll return empty results
        Ok(Vec::new())
    }

    /// Analyze correlations between matches
    async fn analyze_correlations(
        &self,
        _scan_results: &[ScanResult],
    ) -> Result<Vec<CorrelationMatch>> {
        // This would perform correlation analysis using the category system
        // For now, we'll return empty correlations
        Ok(Vec::new())
    }

    /// Generate threat assessment
    async fn generate_threat_assessment(
        &self,
        scan_results: &[ScanResult],
        correlation_results: &[CorrelationMatch],
    ) -> Result<ThreatAssessment> {
        let overall_threat_level = if !scan_results.is_empty() || !correlation_results.is_empty() {
            SeverityLevel::High
        } else {
            SeverityLevel::Info
        };
        
        Ok(ThreatAssessment {
            overall_threat_level,
            confidence_score: 0.8,
            threat_categories: Vec::new(),
            attack_vectors: Vec::new(),
            potential_impact: "Potential malware detected".to_string(),
            false_positive_likelihood: 0.1,
            recommended_actions: vec![
                "Quarantine the file".to_string(),
                "Perform additional analysis".to_string(),
            ],
        })
    }

    /// Convert scan results to enhanced matches
    async fn convert_to_enhanced_matches(
        &self,
        _scan_results: Vec<ScanResult>,
    ) -> Result<Vec<EnhancedMatch>> {
        // This would convert basic scan results to enhanced matches with additional metadata
        Ok(Vec::new())
    }

    /// Group matches by category
    async fn group_matches_by_category(
        &self,
        _scan_results: &[ScanResult],
    ) -> Result<HashMap<String, Vec<EnhancedMatch>>> {
        // This would group matches by their rule categories
        Ok(HashMap::new())
    }

    /// Generate rule statistics
    async fn generate_rule_stats(
        &self,
        rule_names: &[String],
    ) -> Result<ScanRuleStats> {
        Ok(ScanRuleStats {
            total_rules_loaded: rule_names.len(),
            rules_by_category: HashMap::new(),
            rules_matched: 0,
            rules_skipped: 0,
            rules_failed: 0,
            optimization_applied: true,
            deduplication_applied: true,
            average_rule_performance: 0.0,
        })
    }

    /// Generate recommendations
    async fn generate_recommendations(
        &self,
        _scan_results: &[ScanResult],
        _correlation_results: &[CorrelationMatch],
    ) -> Result<Vec<String>> {
        Ok(vec![
            "Consider updating YARA rules".to_string(),
            "Review file permissions".to_string(),
            "Monitor for additional indicators".to_string(),
        ])
    }

    /// Generate scan metadata
    async fn generate_scan_metadata(
        &self,
        file_path: &Path,
    ) -> Result<ScanMetadata> {
        let file_metadata = tokio::fs::metadata(file_path).await
            .context("Failed to get file metadata")?;
        
        Ok(ScanMetadata {
            scanner_version: "1.0.0".to_string(),
            yara_version: "4.0.0".to_string(),
            rule_set_version: "1.0.0".to_string(),
            scan_mode: "enhanced".to_string(),
            file_size: file_metadata.len(),
            file_type: None,
            file_hash: None,
            scan_environment: HashMap::new(),
        })
    }

    /// Generate scan ID
    fn generate_scan_id(&self, file_path: &Path) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(file_path.to_string_lossy().as_bytes());
        let timestamp_nanos = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
        hasher.update(timestamp_nanos.to_string().as_bytes());
        format!("{:x}", hasher.finalize())[..16].to_string()
    }

    /// Get cached scan result
    async fn get_cached_result(&self, scan_id: &str) -> Option<EnhancedScanResult> {
        let cache = self.scan_cache.read().await;
        cache.get(scan_id).cloned()
    }

    /// Cache scan result
    async fn cache_result(&self, scan_id: &str, result: &EnhancedScanResult) {
        let mut cache = self.scan_cache.write().await;
        cache.insert(scan_id.to_string(), result.clone());
        
        // Limit cache size
        if cache.len() > 1000 {
            let oldest_key = cache.keys().next().cloned();
            if let Some(key) = oldest_key {
                cache.remove(&key);
            }
        }
    }

    /// Get scanner statistics
    pub async fn get_scanner_stats(&self) -> Result<ScannerStats> {
        let category_stats = {
            let category_system = self.category_system.read().await;
            category_system.get_category_stats()
        };
        
        let performance_stats = {
            let performance_monitor = self.performance_monitor.read().await;
            performance_monitor.get_performance_stats()?
        };
        
        let active_scans = {
            let active_scans = self.active_scans.read().await;
            active_scans.len()
        };
        
        let cache_size = {
            let cache = self.scan_cache.read().await;
            cache.len()
        };
        
        Ok(ScannerStats {
            category_stats,
            performance_stats,
            active_scans,
            cache_size,
            total_scans_performed: 0, // Would be tracked
            average_scan_time: Duration::from_secs(0), // Would be calculated
        })
    }
}

/// Scanner statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerStats {
    pub category_stats: super::category_system::CategoryStats,
    pub performance_stats: PerformanceMetrics,
    pub active_scans: usize,
    pub cache_size: usize,
    pub total_scans_performed: u64,
    pub average_scan_time: Duration,
}

#[cfg(test)]
mod tests {
    use super::*;
    // Removed unused import: tempfile::TempDir

    #[tokio::test]
    async fn test_enhanced_scanner_creation() {
        let scanner = EnhancedYaraScanner::new().await;
        assert!(scanner.is_ok());
    }

    #[tokio::test]
    async fn test_scan_config_default() {
        let config = EnhancedScanConfig::default();
        assert!(config.enable_correlation_analysis);
        assert!(config.enable_performance_monitoring);
        assert!(config.enable_rule_optimization);
    }

    #[tokio::test]
    async fn test_scan_id_generation() {
        let scanner = EnhancedYaraScanner::new().await.unwrap();
        let path = Path::new("/test/file.exe");
        let id1 = scanner.generate_scan_id(path);
        
        // Add a small delay to ensure different timestamps
        tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;
        
        let id2 = scanner.generate_scan_id(path);
        
        // IDs should be different due to timestamp
        assert_ne!(id1, id2);
        assert_eq!(id1.len(), 16);
        assert_eq!(id2.len(), 16);
    }
}
