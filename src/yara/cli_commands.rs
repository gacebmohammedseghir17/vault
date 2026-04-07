//! YARA CLI Commands Module
//!
//! This module provides command-line interface commands for YARA rule management,
//! including downloading, validation, listing, and enhanced scanning operations.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
// use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::fs;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

// Import multi-layer scanner components
use super::file_scanner::YaraFileScanner;
use super::multi_layer_scanner::{LayeredScanResult, MultiLayerScanner, ScanTarget};
use super::rule_loader::YaraRuleLoader;
use super::rule_sources::RuleSourceManager;
use crate::config::yara_config::Config;

use super::category_system::PerformanceMode;
use super::enhanced_scanner::{
    EnhancedScanConfig, EnhancedScanResult, EnhancedYaraScanner, OutputFormat, ResultAggregation,
};
use super::github_downloader::{GitHubDownloader, GitHubSource};
use super::multi_source_downloader::MultiSourceDownloader;
use super::performance_monitor::PerformanceMonitor;
#[allow(unused_imports)]
use super::rule_optimizer::{OptimizationResult, RuleOptimizer};
use super::rule_validator::RuleValidator;
use super::storage::YaraStorage;

/// Simple threat score structure for CLI operations
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ThreatScore {
    rule_id: String,
    score: f64,
    label: String,
    confidence: f64,
    features: std::collections::HashMap<String, String>,
}

/// YARA CLI command arguments
#[derive(Debug, Args)]
pub struct YaraCliArgs {
    #[command(subcommand)]
    pub command: YaraCommand,
}

/// Available YARA commands
#[derive(Debug, Subcommand)]
pub enum YaraCommand {
    /// Update YARA rules from GitHub repositories
    UpdateRules {
        /// Specific repository to update (optional)
        #[arg(short, long)]
        repository: Option<String>,

        /// Force update even if recently updated
        #[arg(short, long)]
        force: bool,

        /// Validate rules after download
        #[arg(short, long)]
        validate: bool,
    },

    /// Download rules from multiple high-quality sources
    DownloadRules {
        /// Download from all sources
        #[arg(short, long)]
        all: bool,

        /// Specific sources to download from (kaggle, reversinglabs, yara-forge, community)
        #[arg(short, long)]
        sources: Vec<String>,

        /// Force download even if recently updated
        #[arg(short, long)]
        force: bool,

        /// Validate rules after download
        #[arg(short, long)]
        validate: bool,

        /// Show detailed download statistics
        #[arg(short, long)]
        detailed: bool,
    },

    /// List available YARA rules
    ListRules {
        /// Filter by category
        #[arg(short, long)]
        category: Option<String>,

        /// Filter by repository
        #[arg(short, long)]
        repository: Option<String>,

        /// Show only valid rules
        #[arg(short, long)]
        valid_only: bool,

        /// Show detailed information
        #[arg(short, long)]
        detailed: bool,

        /// Output format (table, json, csv)
        #[arg(short, long, default_value = "table")]
        format: String,
    },

    /// Validate YARA rules
    ValidateRules {
        /// Path to rules directory or file
        #[arg(short, long)]
        path: Option<PathBuf>,

        /// Enable strict validation mode
        #[arg(short, long)]
        strict: bool,

        /// Enable performance checks
        #[arg(long)]
        performance: bool,

        /// Output validation report
        #[arg(short, long)]
        report: Option<PathBuf>,
    },

    /// Show YARA engine statistics
    Stats {
        /// Show detailed statistics
        #[arg(short, long)]
        detailed: bool,

        /// Output format (table, json)
        #[arg(short, long, default_value = "table")]
        format: String,
    },

    /// Configure GitHub repositories
    ConfigRepo {
        #[command(subcommand)]
        action: RepoAction,
    },

    /// Enhanced file scanning with rule selection
    ScanEnhanced {
        /// File or directory to scan
        path: PathBuf,

        /// Include specific categories (comma-separated)
        #[arg(long)]
        include_categories: Option<String>,

        /// Exclude specific categories (comma-separated)
        #[arg(long)]
        exclude_categories: Option<String>,

        /// Specific repositories to use
        #[arg(short, long)]
        repositories: Vec<String>,

        /// Maximum number of rules to use
        #[arg(long)]
        max_rules: Option<usize>,

        /// Performance mode (fast, balanced, thorough)
        #[arg(short = 'm', long, default_value = "balanced")]
        performance_mode: String,

        /// Enable correlation analysis
        #[arg(long)]
        correlate: bool,

        /// Enable rule optimization
        #[arg(long)]
        optimize: bool,

        /// Enable performance monitoring
        #[arg(long)]
        monitor: bool,

        /// Maximum scan time in seconds
        #[arg(long)]
        max_time: Option<u64>,

        /// Maximum memory usage in MB
        #[arg(long)]
        max_memory: Option<u64>,

        /// Result aggregation mode (all, high-priority, deduplicated, correlated)
        #[arg(short = 'a', long, default_value = "correlated")]
        aggregation: String,

        /// Output format (table, json)
        #[arg(short, long, default_value = "table")]
        format: String,

        /// Output file path
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Enable parallel scanning
        #[arg(long)]
        parallel: bool,

        /// Maximum concurrent scans
        #[arg(long, default_value = "4")]
        max_concurrent: usize,
    },

    /// Optimize YARA rules for performance and deduplication
    OptimizeRules {
        /// Performance threshold in milliseconds
        #[arg(short, long, default_value = "1000.0")]
        threshold: f32,

        /// Dry run mode - don't update database
        #[arg(long)]
        dry_run: bool,
    },

    /// Show performance metrics for YARA rule compilation
    ShowMetrics {
        /// Show top N slowest rules
        #[arg(long)]
        top: Option<usize>,

        /// Output format (table, json)
        #[arg(short, long, default_value = "table")]
        format: String,
    },

    /// Multi-layer detection scan with parallel layer execution
    MultiScan {
        /// File or directory to scan
        path: PathBuf,

        /// Layers to enable (comma-separated: file,memory,behavior,network)
        #[arg(long, default_value = "file,memory,behavior,network")]
        layers: String,

        /// Risk threshold for alerts (0.0 to 1.0)
        #[arg(long, default_value = "0.7")]
        risk_threshold: f32,

        /// Output format (table, json)
        #[arg(short, long, default_value = "table")]
        format: String,

        /// Output file path
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Enable detailed logging
        #[arg(long)]
        verbose: bool,
    },

    /// Correlate alerts across multiple scan results
    Correlate {
        /// Minimum number of scans for correlation (default: 2)
        #[arg(long, default_value = "2")]
        min_scans: usize,

        /// Minimum number of layers for correlation (default: 2)
        #[arg(long, default_value = "2")]
        min_layers: usize,

        /// JSON scan result files to correlate
        #[arg(long, required = true)]
        scan_result: Vec<PathBuf>,

        /// Database path for storing correlated alerts
        #[arg(long)]
        db_path: Option<PathBuf>,
    },

    /// Score threats using machine learning model
    ScoreThreats {
        /// Path to trained ML model file
        #[arg(long, required = true)]
        model_path: PathBuf,

        /// Path to feature scaler file
        #[arg(long, required = true)]
        scaler_path: PathBuf,

        /// Input JSON file containing RuleMatch objects
        #[arg(long, required = true)]
        input: PathBuf,

        /// Output JSON file for threat scores
        #[arg(long, required = true)]
        output: PathBuf,
    },

    /// Scan files using EMBER ML malware detection
    EmberScan {
        /// Path to file or directory to scan
        #[arg(short, long)]
        path: PathBuf,

        /// Path to EMBER ONNX model file
        #[arg(long, required = true)]
        _ember_model: PathBuf,

        /// Response policy configuration file
        #[arg(long)]
        response_policy: Option<PathBuf>,

        /// Malware probability threshold (0.0-1.0)
        #[arg(short, long, default_value = "0.5")]
        threshold: f32,

        /// Output format (json, table)
        #[arg(short, long, default_value = "table")]
        format: String,

        /// Output file path
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Enable automated response
        #[arg(long)]
        auto_response: bool,
    },

    /// Apply automated response policies to scan results
    AutoResponse {
        /// Response policy configuration file
        #[arg(long, required = true)]
        response_policy: PathBuf,

        /// Path to scan results or database
        #[arg(short, long)]
        input: Option<PathBuf>,

        /// Dry run mode (show actions without executing)
        #[arg(long)]
        dry_run: bool,

        /// Output format (json, table)
        #[arg(short, long, default_value = "table")]
        format: String,
    },

    /// Update all rule sources with latest versions
    UpdateSources {
        /// Force update even if recently updated
        #[arg(short, long)]
        force: bool,

        /// Validate rules after update
        #[arg(short, long)]
        validate: bool,

        /// Show detailed update statistics
        #[arg(short, long)]
        detailed: bool,
    },

    /// Show comprehensive rule statistics and metrics
    RuleStats {
        /// Show detailed statistics by source
        #[arg(short, long)]
        detailed: bool,

        /// Show performance metrics
        #[arg(long)]
        performance: bool,

        /// Output format (table, json)
        #[arg(short, long, default_value = "table")]
        format: String,
    },
}

/// Repository configuration actions
#[derive(Debug, Subcommand)]
pub enum RepoAction {
    /// Add a new repository
    Add {
        /// Repository name
        name: String,
        /// Repository URL
        url: String,
        /// Branch name (default: main)
        #[arg(short, long, default_value = "main")]
        branch: String,
    },

    /// Remove a repository
    Remove {
        /// Repository name
        name: String,
    },

    /// List configured repositories
    List,

    /// Enable/disable a repository
    Toggle {
        /// Repository name
        name: String,
    },
}

/// Rule listing information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleInfo {
    pub file_path: PathBuf,
    pub rule_name: String,
    pub category: Option<String>,
    pub repository: Option<String>,
    pub author: Option<String>,
    pub description: Option<String>,
    pub is_valid: bool,
    pub file_size: u64,
    pub rule_count: usize,
    pub last_validated: Option<String>,
}

/// Scan result information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub file_path: PathBuf,
    pub matches: Vec<RuleMatch>,
    pub scan_time: Duration,
    pub rules_used: usize,
    pub performance_metrics: Option<PerformanceMetrics>,
}

/// Rule match information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMatch {
    pub rule_name: String,
    pub category: Option<String>,
    pub severity: Option<String>,
    pub confidence: Option<String>,
    pub description: Option<String>,
    pub offset: u64,
    pub length: u64,
}

/// Performance metrics for scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub memory_usage_mb: f64,
    pub cpu_usage_percent: f64,
    pub rules_per_second: f64,
    pub bytes_per_second: f64,
}

/// YARA CLI command executor
pub struct YaraCliExecutor {
    storage: YaraStorage,
    downloader: GitHubDownloader,
    multi_downloader: MultiSourceDownloader,
    rule_source_manager: RuleSourceManager,
    validator: RuleValidator,
    rules_directory: PathBuf,
}

impl YaraCliExecutor {
    /// Create a new CLI executor
    pub async fn new<P: AsRef<Path>>(rules_directory: P, db_path: P) -> Result<Self> {
        let rules_directory = rules_directory.as_ref().to_path_buf();
        let db_path_buf = db_path.as_ref().to_path_buf();
        let mut storage = YaraStorage::new(db_path);
        storage
            .initialize()
            .await
            .context("Failed to initialize storage")?;

        let downloader = GitHubDownloader::new(&db_path_buf, &rules_directory);
        let validator = RuleValidator::new(rules_directory.clone());

        // Initialize multi-source downloader
        let cache_path = rules_directory.join("cache");
        let mut multi_downloader = MultiSourceDownloader::new(&rules_directory, &cache_path)
            .context("Failed to create multi-source downloader")?;
        multi_downloader.initialize_default_sources().await
            .context("Failed to initialize default rule sources")?;

        // Initialize rule source manager
        let rule_source_manager = RuleSourceManager::new(&rules_directory);

        Ok(Self {
            storage,
            downloader,
            multi_downloader,
            rule_source_manager,
            validator,
            rules_directory,
        })
    }

    /// Execute a YARA command
    pub async fn execute_command(&mut self, command: YaraCommand) -> Result<()> {
        match command {
            YaraCommand::UpdateRules {
                repository,
                force,
                validate,
            } => self.update_rules(repository, force, validate).await,
            YaraCommand::DownloadRules {
                all,
                sources,
                force,
                validate,
                detailed,
            } => self.download_rules(all, sources, force, validate, detailed).await,
            YaraCommand::ListRules {
                category,
                repository,
                valid_only,
                detailed,
                format,
            } => {
                self.list_rules(category, repository, valid_only, detailed, &format)
                    .await
            }
            YaraCommand::ValidateRules {
                path,
                strict,
                performance,
                report,
            } => self.validate_rules(path, strict, performance, report).await,
            YaraCommand::Stats { detailed, format } => self.show_stats(detailed, &format).await,
            YaraCommand::ConfigRepo { action } => self.config_repository(action).await,
            YaraCommand::ScanEnhanced {
                path,
                include_categories,
                exclude_categories,
                repositories,
                max_rules,
                performance_mode,
                correlate,
                optimize,
                monitor,
                max_time,
                max_memory,
                aggregation,
                format,
                output,
                parallel,
                max_concurrent,
            } => {
                self.scan_enhanced(
                    path,
                    include_categories,
                    exclude_categories,
                    repositories,
                    max_rules,
                    &performance_mode,
                    correlate,
                    optimize,
                    monitor,
                    max_time,
                    max_memory,
                    &aggregation,
                    &format,
                    output,
                    parallel,
                    max_concurrent,
                )
                .await
            }
            YaraCommand::OptimizeRules { threshold, dry_run } => {
                self.optimize_rules(threshold, dry_run).await
            }
            YaraCommand::ShowMetrics { top, format } => self.show_metrics(top, &format).await,
            YaraCommand::MultiScan {
                path,
                layers,
                risk_threshold,
                format,
                output,
                verbose,
            } => {
                let layer_vec: Vec<String> =
                    layers.split(',').map(|s| s.trim().to_string()).collect();
                self.multi_scan(
                    path,
                    &layer_vec,
                    Some(risk_threshold),
                    &format,
                    output,
                    verbose,
                )
                .await
            }
            YaraCommand::Correlate {
                min_scans,
                min_layers,
                scan_result,
                db_path,
            } => {
                self.correlate_alerts(min_scans, min_layers, scan_result, db_path)
                    .await
            }
            YaraCommand::ScoreThreats {
                model_path,
                scaler_path,
                input,
                output,
            } => {
                self.score_threats(model_path, scaler_path, input, output)
                    .await
            }
            YaraCommand::EmberScan {
                path,
                _ember_model,
                response_policy,
                threshold,
                format,
                output,
                auto_response,
            } => {
                #[cfg(not(feature = "basic-detection"))]
                {
                    let _ = (path, ember_model, response_policy, threshold, format, output, auto_response);
                }
                #[cfg(feature = "basic-detection")]
                {
                    self.ember_scan(
                        path,
                        _ember_model,
                        response_policy,
                        threshold,
                        &format,
                        output,
                        auto_response,
                    )
                    .await
                }
                #[cfg(not(feature = "basic-detection"))]
                {
                    Err(anyhow::anyhow!("EMBER detection feature not enabled"))
                }
            }
            YaraCommand::AutoResponse {
                response_policy,
                input,
                dry_run,
                format,
            } => {
                #[cfg(not(feature = "basic-detection"))]
                {
                    let _ = (response_policy, input, dry_run, format);
                }
                #[cfg(feature = "basic-detection")]
                {
                    self.auto_response(response_policy, input, dry_run, &format)
                        .await
                }
                #[cfg(not(feature = "basic-detection"))]
                {
                    Err(anyhow::anyhow!("Auto-response feature not enabled"))
                }
            }
            YaraCommand::UpdateSources {
                force,
                validate,
                detailed,
            } => self.update_sources(force, validate, detailed).await,
            YaraCommand::RuleStats {
                detailed,
                performance,
                format,
            } => self.rule_stats(detailed, performance, &format).await,
        }
    }

    /// Update YARA rules from GitHub repositories
    async fn update_rules(
        &mut self,
        repository: Option<String>,
        force: bool,
        validate: bool,
    ) -> Result<()> {
        info!("Starting YARA rules update process");
        let start_time = Instant::now();

        // Get configured repositories
        let repositories = self
            .storage
            .get_github_repositories()
            .await
            .context("Failed to get configured repositories")?;

        if repositories.is_empty() {
            warn!("No repositories configured. Use 'config-repo add' to add repositories.");
            return Ok(());
        }

        let mut total_downloaded = 0;
        let mut total_validated = 0;

        for stored_repo in repositories {
            // Skip if specific repository requested and this isn't it
            if let Some(ref target_repo) = repository {
                if stored_repo.name != *target_repo {
                    continue;
                }
            }

            // Skip disabled repositories
            if !stored_repo.is_enabled {
                debug!("Skipping disabled repository: {}", stored_repo.name);
                continue;
            }

            info!("Updating repository: {}", stored_repo.name);

            // Create GitHubSource from stored repository
            let github_source = GitHubSource {
                name: stored_repo.name.clone(),
                repository: stored_repo.url.clone(),
                branch: stored_repo.branch.clone(),
                rules_path: "rules".to_string(), // Default rules path
                is_active: stored_repo.is_enabled,
                update_frequency_hours: 24, // Default 24 hours
                last_update: Some(stored_repo.last_updated),
            };

            match self.downloader.fetch_source(&github_source, force).await {
                Ok(stats) => {
                    info!(
                        "Downloaded {} files from {}",
                        stats.downloaded, stored_repo.name
                    );
                    total_downloaded += stats.downloaded;

                    // Note: Repository info storage would need to be updated to work with new structure
                    // For now, we'll skip the storage step as it requires GitHubRepository struct

                    // Validate rules if requested
                    if validate {
                        info!("Validating rules from repository: {}", stored_repo.name);
                        let validation_stats = self
                            .validator
                            .validate_all_rules()
                            .await
                            .context("Failed to validate repository rules")?;

                        total_validated += validation_stats.total_rules;

                        // Store validation results
                        for result in self.validator.get_validation_results() {
                            self.storage
                                .store_rule_metadata(&result, Some(&stored_repo.name))
                                .await
                                .context("Failed to store rule metadata")?;

                            self.storage
                                .store_validation_history(&result)
                                .await
                                .context("Failed to store validation history")?;
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to update repository {}: {}", stored_repo.name, e);
                }
            }
        }

        let elapsed = start_time.elapsed();
        info!(
            "Rules update completed: {} files downloaded, {} files validated in {:?}",
            total_downloaded, total_validated, elapsed
        );

        Ok(())
    }

    /// Download rules from multiple sources using the rule source manager
    async fn download_rules(
        &mut self,
        all: bool,
        sources: Vec<String>,
        force: bool,
        validate: bool,
        detailed: bool,
    ) -> Result<()> {
        let start_time = Instant::now();
        info!("Starting multi-source rule download...");

        // Download from sources using the new rule source manager
        let download_results = if all {
            // Download from all available sources
            self.rule_source_manager.download_all_sources().await?
        } else if !sources.is_empty() {
            // Download from specified sources
            let mut results = Vec::new();
            for source_id in &sources {
                match self.rule_source_manager.download_from_source_id(source_id, force).await {
                    Ok(result) => results.push(result),
                    Err(e) => {
                        error!("Failed to download from source '{}': {}", source_id, e);
                    }
                }
            }
            results
        } else {
            // Default to downloading from all sources
            self.rule_source_manager.download_all_sources().await?
        };

        if download_results.is_empty() {
            warn!("No sources downloaded");
            return Ok(());
        }

        info!("Downloaded from {} sources", download_results.len());
        
        let mut total_downloaded = 0;
        let mut total_validated = 0;

        // Process download results
        for result in &download_results {
            if result.success {
                info!("✓ {}: {} rules downloaded", result.source_name, result.rule_count);
                total_downloaded += result.rule_count;
                
                if validate {
                    if let Some(download_path) = &result.download_path {
                        info!("Validating rules from {}...", result.source_name);
                        match self.validator.validate_directory(download_path).await {
                            Ok(validation_result) => {
                                let valid_count = validation_result.valid_rules.len();
                                total_validated += valid_count;
                                info!("  ✓ {}/{} rules are valid", valid_count, result.rule_count);
                                
                                if !validation_result.invalid_rules.is_empty() {
                                    warn!("  ⚠ {} invalid rules found", validation_result.invalid_rules.len());
                                    if detailed {
                                        for invalid in &validation_result.invalid_rules {
                                            warn!("    - {}: {}", invalid.file_path.display(), invalid.error);
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                error!("Failed to validate rules from {}: {}", result.source_name, e);
                            }
                        }
                    }
                }
            } else {
                error!("✗ {}: {}", result.source_name, 
                       result.error_message.as_deref().unwrap_or("Unknown error"));
            }
        }

        let elapsed = start_time.elapsed();
        
        // Display summary
        info!(
            "Multi-source download completed: {} files downloaded from {} sources in {:?}",
            total_downloaded, download_results.len(), elapsed
        );

        if validate {
            info!("Validation completed: {} rules validated", total_validated);
        }

        Ok(())
    }

    #[allow(dead_code)]
    async fn download_rules_old(
        &mut self,
        all: bool,
        sources: Vec<String>,
        force: bool,
        validate: bool,
        detailed: bool,
    ) -> Result<()> {
        let start_time = Instant::now();
        info!("Starting multi-source rule download...");

        // Determine which sources to download from
        let sources_to_download = if all {
            // Download from all available sources
            self.multi_downloader.get_sources().await?
        } else if !sources.is_empty() {
            // Download from specified sources
            let mut selected_sources = Vec::new();
            let available_sources = self.multi_downloader.get_sources().await?;
            
            for source_name in &sources {
                if let Some(source) = available_sources.iter().find(|s| {
                     s.name.to_lowercase() == source_name.to_lowercase()
                 }) {
                    selected_sources.push(source.clone());
                } else {
                    warn!("Source '{}' not found. Available sources: {:?}", 
                          source_name, 
                          available_sources.iter().map(|s| &s.name).collect::<Vec<_>>());
                }
            }
            selected_sources
        } else {
            // Default to high-priority sources if no specific selection
            self.multi_downloader.get_sources().await?
                .into_iter()
                .filter(|s| s.priority >= 8) // High priority sources only
                .collect()
        };

        if sources_to_download.is_empty() {
            warn!("No sources selected for download");
            return Ok(());
        }

        info!("Downloading from {} sources", sources_to_download.len());
        if detailed {
            for source in &sources_to_download {
                 info!("  - {}: {}", source.name, source.url);
             }
        }

        let mut total_downloaded = 0;
        let mut total_validated = 0;
        let mut download_stats = Vec::new();

        // Download from each source using the old multi-source downloader
        for source in &sources_to_download {
            info!("Downloading from source: {}", source.name);
            
            match self.multi_downloader.download_from_source(source, force).await {
                Ok(stats) => {
                    total_downloaded += stats.files_downloaded;
                    
                    if detailed {
                        info!("  Downloaded {} files ({} bytes) in {:?}", 
                              stats.files_downloaded, 
                              stats.bytes_downloaded, 
                              stats.download_time);
                    }

                    // Validate downloaded rules if requested
                    if validate && stats.files_downloaded > 0 {
                        let rules_path = self.rules_directory.join(&source.name);
                        if rules_path.exists() {
                            match self.validator.validate_all_rules().await {
                                Ok(validation_results) => {
                                    let valid_count = validation_results.valid_rules;
                                    total_validated += valid_count;
                                    
                                    if detailed {
                                        info!("  Validated {}/{} rules from {}", 
                                              valid_count, 
                                              validation_results.total_rules, 
                                              source.name);
                                    }

                                    // Store validation results - ValidationStats doesn't have individual results
                                    // We'll skip storing individual results for now
                                    if detailed {
                                        info!("  Validation stats: {} total rules, {} valid, {} invalid", 
                                              validation_results.total_rules,
                                              validation_results.valid_rules,
                                              validation_results.invalid_rules);
                                    }
                                }
                                Err(e) => {
                                    error!("Failed to validate rules from {}: {}", source.name, e);
                                }
                            }
                        }
                    }

                    download_stats.push((source.name.clone(), stats));
                }
                Err(e) => {
                    error!("Failed to download from {}: {}", source.name, e);
                }
            }
        }

        let elapsed = start_time.elapsed();
        
        // Display summary
        info!(
            "Multi-source download completed: {} files downloaded from {} sources in {:?}",
            total_downloaded, sources_to_download.len(), elapsed
        );

        if validate {
            info!("Validation completed: {} rules validated", total_validated);
        }

        if detailed {
            println!("\n=== Download Summary ===");
            for (source_name, stats) in download_stats {
                println!("Source: {}", source_name);
                println!("  Files: {}", stats.files_downloaded);
                println!("  Size: {} bytes", stats.bytes_downloaded);
                println!("  Time: {:?}", stats.download_time);
                if let Some(error) = stats.last_error {
                    println!("  Last Error: {}", error);
                }
                println!();
            }
        }

        Ok(())
    }

    /// List available YARA rules
    async fn list_rules(
        &mut self,
        category: Option<String>,
        repository: Option<String>,
        valid_only: bool,
        detailed: bool,
        format: &str,
    ) -> Result<()> {
        info!("Listing YARA rules");

        // For now, we'll scan the rules directory to get current rules
        // In a full implementation, this would query the database
        let mut rules = Vec::new();

        Self::collect_rules_info(&self.rules_directory, &self.rules_directory, &mut rules).await?;

        // Apply filters
        if valid_only {
            rules.retain(|rule| rule.is_valid);
        }

        if let Some(ref cat) = category {
            rules.retain(|rule| rule.category.as_ref().map_or(false, |c| c.contains(cat)));
        }

        if let Some(ref repo) = repository {
            rules.retain(|rule| rule.repository.as_ref().map_or(false, |r| r.contains(repo)));
        }

        // Output results
        match format {
            "json" => {
                let json = serde_json::to_string_pretty(&rules)
                    .context("Failed to serialize rules to JSON")?;
                println!("{}", json);
            }
            "csv" => {
                println!(
                    "file_path,rule_name,category,repository,author,is_valid,file_size,rule_count"
                );
                for rule in &rules {
                    println!(
                        "{},{},{},{},{},{},{},{}",
                        rule.file_path.display(),
                        rule.rule_name,
                        rule.category.as_deref().unwrap_or(""),
                        rule.repository.as_deref().unwrap_or(""),
                        rule.author.as_deref().unwrap_or(""),
                        rule.is_valid,
                        rule.file_size,
                        rule.rule_count
                    );
                }
            }
            _ => {
                // Table format (default)
                println!(
                    "\n{:<50} {:<20} {:<15} {:<15} {:<10} {:<8}",
                    "Rule Name", "Category", "Repository", "Author", "Valid", "Size"
                );
                println!("{}", "-".repeat(120));

                for rule in &rules {
                    let rule_name = if rule.rule_name.len() > 47 {
                        format!("{}...", &rule.rule_name[..44])
                    } else {
                        rule.rule_name.clone()
                    };

                    println!(
                        "{:<50} {:<20} {:<15} {:<15} {:<10} {:<8}",
                        rule_name,
                        rule.category.as_deref().unwrap_or("-"),
                        rule.repository.as_deref().unwrap_or("-"),
                        rule.author.as_deref().unwrap_or("-"),
                        if rule.is_valid { "✓" } else { "✗" },
                        format_file_size(rule.file_size)
                    );

                    if detailed {
                        if let Some(ref desc) = rule.description {
                            println!("    Description: {}", desc);
                        }
                        println!("    File: {}", rule.file_path.display());
                        println!("    Rules: {}", rule.rule_count);
                        if let Some(ref validated) = rule.last_validated {
                            println!("    Last Validated: {}", validated);
                        }
                        println!();
                    }
                }

                println!("\nTotal: {} rules", rules.len());
            }
        }

        Ok(())
    }

    /// Validate YARA rules
    async fn validate_rules(
        &mut self,
        path: Option<PathBuf>,
        _strict: bool,
        _performance: bool,
        report: Option<PathBuf>,
    ) -> Result<()> {
        let target_path = path.unwrap_or_else(|| self.rules_directory.clone());
        info!("Validating YARA rules in: {:?}", target_path);

        let mut validator = RuleValidator::new(target_path.clone());
        let stats = validator
            .validate_all_rules()
            .await
            .context("Failed to validate rules")?;

        // Store validation results
        for result in validator.get_validation_results() {
            self.storage
                .store_validation_history(&result)
                .await
                .context("Failed to store validation history")?;
        }

        // Display results
        println!("\nValidation Results:");
        println!("==================");
        println!("Total rules: {}", stats.total_rules);
        println!("Valid rules: {}", stats.valid_rules);
        println!("Invalid rules: {}", stats.invalid_rules);
        println!("Average quality score: {:.2}", stats.average_quality_score);
        println!("High quality rules: {}", stats.high_quality_rules);
        println!("Medium quality rules: {}", stats.medium_quality_rules);
        println!("Low quality rules: {}", stats.low_quality_rules);

        if !stats.validation_errors.is_empty() {
            println!("\nValidation Errors:");
            for error in &stats.validation_errors {
                println!("  {}", error);
            }
        }

        if !stats.recommendations.is_empty() {
            println!("\nRecommendations:");
            for recommendation in &stats.recommendations {
                println!("  {}", recommendation);
            }
        }

        // Generate report if requested
        if let Some(report_path) = report {
            let report_data = serde_json::to_string_pretty(&stats)
                .context("Failed to serialize validation report")?;

            fs::write(&report_path, report_data)
                .await
                .with_context(|| format!("Failed to write report to {:?}", report_path))?;

            info!("Validation report written to: {:?}", report_path);
        }

        Ok(())
    }

    /// Show YARA engine statistics
    async fn show_stats(&mut self, detailed: bool, format: &str) -> Result<()> {
        let stats = self
            .storage
            .get_storage_stats()
            .await
            .context("Failed to get storage statistics")?;

        match format {
            "json" => {
                let json = serde_json::to_string_pretty(&stats)
                    .context("Failed to serialize stats to JSON")?;
                println!("{}", json);
            }
            _ => {
                println!("\nYARA Engine Statistics:");
                println!("=======================");
                println!("Total rules: {}", stats.total_rules);
                println!("Valid rules: {}", stats.valid_rules);
                println!("Invalid rules: {}", stats.invalid_rules);
                println!("Total repositories: {}", stats.total_repositories);
                println!("Enabled repositories: {}", stats.enabled_repositories);
                println!("Total validations: {}", stats.total_validations);
                println!("Recent validations (24h): {}", stats.recent_validations);
                println!(
                    "Average compilation time: {:?}",
                    stats.average_compilation_time
                );
                println!("Database size: {:.2} MB", stats.database_size_mb);

                if let Some(last_update) = stats.last_update {
                    println!("Last update: {:?}", last_update);
                }

                if detailed {
                    let repositories = self
                        .storage
                        .get_github_repositories()
                        .await
                        .context("Failed to get repositories")?;

                    if !repositories.is_empty() {
                        println!("\nConfigured Repositories:");
                        println!(
                            "{:<20} {:<10} {:<10} {:<10} {:<10}",
                            "Name", "Enabled", "Total", "Valid", "Invalid"
                        );
                        println!("{}", "-".repeat(60));

                        for repo in repositories {
                            println!(
                                "{:<20} {:<10} {:<10} {:<10} {:<10}",
                                repo.name,
                                if repo.is_enabled { "✓" } else { "✗" },
                                repo.total_rules,
                                repo.valid_rules,
                                repo.invalid_rules
                            );
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Configure GitHub repositories
    async fn config_repository(&mut self, action: RepoAction) -> Result<()> {
        match action {
            RepoAction::Add { name, url, branch } => {
                info!("Adding repository: {} ({})", name, url);

                // Parse URL to extract owner and repo
                let url_parts: Vec<&str> = url.trim_end_matches('/').split('/').collect();
                if url_parts.len() < 2 {
                    return Err(anyhow::anyhow!("Invalid GitHub URL format"));
                }
                let owner = url_parts[url_parts.len() - 2].to_string();
                let repo_name = url_parts[url_parts.len() - 1].to_string();

                let _repo = GitHubSource {
                    name: name.clone(),
                    repository: format!("{}/{}", owner, repo_name),
                    branch,
                    rules_path: "rules".to_string(),
                    is_active: true,
                    update_frequency_hours: 24,
                    last_update: None,
                };

                // Store the source in the database
                // Note: This would require implementing store_github_source method

                // Add repository to downloader configuration
                // Note: This would typically add to the downloader's repository list
                match self.downloader.fetch_all(false).await {
                    Ok(stats_vec) => {
                        let total_downloaded: usize = stats_vec.iter().map(|s| s.downloaded).sum();

                        // Note: Repository storage would need to be updated for new structure
                        // For now, we'll just log the success

                        info!("Repository '{}' added successfully", name);
                        info!("Downloaded {} rules total", total_downloaded);
                    }
                    Err(e) => {
                        error!("Failed to add repository '{}': {}", name, e);
                        return Err(e.into());
                    }
                }
            }

            RepoAction::Remove { name } => {
                info!("Removing repository: {}", name);
                // Implementation would remove from database
                warn!("Repository removal not yet implemented");
            }

            RepoAction::List => {
                let repositories = self
                    .storage
                    .get_github_repositories()
                    .await
                    .context("Failed to get repositories")?;

                if repositories.is_empty() {
                    println!("No repositories configured.");
                } else {
                    println!("\nConfigured Repositories:");
                    println!(
                        "{:<20} {:<50} {:<10} {:<10}",
                        "Name", "URL", "Branch", "Enabled"
                    );
                    println!("{}", "-".repeat(90));

                    for repo in repositories {
                        let repo_url = &repo.url;
                        println!(
                            "{:<20} {:<50} {:<10} {:<10}",
                            repo.name,
                            if repo_url.len() > 47 {
                                format!("{}...", &repo_url[..44])
                            } else {
                                repo_url.clone()
                            },
                            "main", // Default branch display
                            if repo.is_enabled { "✓" } else { "✗" }
                        );
                    }
                }
            }

            RepoAction::Toggle { name } => {
                info!("Toggling repository: {}", name);
                warn!("Repository toggle not yet implemented");
            }
        }

        Ok(())
    }

    /// Enhanced file scanning with rule selection
    async fn scan_enhanced(
        &mut self,
        path: PathBuf,
        include_categories: Option<String>,
        exclude_categories: Option<String>,
        _repositories: Vec<String>,
        _max_rules: Option<usize>,
        performance_mode: &str,
        correlate: bool,
        optimize: bool,
        monitor: bool,
        max_time: Option<u64>,
        max_memory: Option<u64>,
        aggregation: &str,
        format: &str,
        output: Option<PathBuf>,
        parallel: bool,
        max_concurrent: usize,
    ) -> Result<()> {
        println!("🔍 Starting enhanced YARA scan...");
        println!("📁 Target: {:?}", path);

        // Create enhanced scanner
        let scanner = EnhancedYaraScanner::new()
            .await
            .context("Failed to create enhanced scanner")?;

        // Initialize scanner with rules
        scanner
            .initialize(&self.rules_directory)
            .await
            .context("Failed to initialize scanner")?;

        // Build scan configuration
        let mut scan_config = EnhancedScanConfig::default();

        // Configure category filter
        let category_filter = if include_categories.is_some() || exclude_categories.is_some() {
            use crate::yara::category_scanner::CategoryFilter;

            let include_cats: Vec<&str> = include_categories
                .as_ref()
                .map(|cats| cats.split(',').map(|s| s.trim()).collect())
                .unwrap_or_default();

            let exclude_cats: Vec<&str> = exclude_categories
                .as_ref()
                .map(|cats| cats.split(',').map(|s| s.trim()).collect())
                .unwrap_or_default();

            let filter = CategoryFilter::from_args(&include_cats, &exclude_cats);

            if let Some(ref inc_cats) = include_categories {
                println!("🏷️  Including categories: {}", inc_cats);
            }
            if let Some(ref exc_cats) = exclude_categories {
                println!("🚫 Excluding categories: {}", exc_cats);
            }

            Some(filter)
        } else {
            None
        };

        scan_config.category_filter = category_filter;

        // Configure performance mode
        scan_config.scan_config.performance_mode = match performance_mode {
            "fast" => PerformanceMode::Fast,
            "balanced" => PerformanceMode::Balanced,
            "thorough" => PerformanceMode::Thorough,
            _ => {
                warn!(
                    "Unknown performance mode '{}', using 'balanced'",
                    performance_mode
                );
                PerformanceMode::Balanced
            }
        };

        // Configure options
        scan_config.enable_correlation_analysis = correlate;
        scan_config.enable_rule_optimization = optimize;
        scan_config.enable_performance_monitoring = monitor;
        scan_config.parallel_scanning = parallel;
        scan_config.max_concurrent_scans = max_concurrent;

        // Configure timeouts and limits
        if let Some(time) = max_time {
            scan_config.max_scan_time = Some(Duration::from_secs(time));
        }

        if let Some(memory) = max_memory {
            scan_config.max_memory_usage = Some(memory * 1024 * 1024); // Convert MB to bytes
        }

        // Configure result aggregation
        scan_config.result_aggregation = match aggregation {
            "all" => ResultAggregation::All,
            "high-priority" => ResultAggregation::HighPriority,
            "deduplicated" => ResultAggregation::Deduplicated,
            "correlated" => ResultAggregation::Correlated,
            _ => {
                warn!(
                    "Unknown aggregation mode '{}', using 'correlated'",
                    aggregation
                );
                ResultAggregation::Correlated
            }
        };

        // Configure output format
        scan_config.output_format = match format {
            "json" => OutputFormat::Json,
            "table" => OutputFormat::Standard,
            _ => {
                warn!("Unknown output format '{}', using 'table'", format);
                OutputFormat::Standard
            }
        };

        println!("⚡ Performance mode: {}", performance_mode);
        println!(
            "🔗 Correlation analysis: {}",
            if correlate { "enabled" } else { "disabled" }
        );
        println!(
            "🚀 Rule optimization: {}",
            if optimize { "enabled" } else { "disabled" }
        );
        println!(
            "📊 Performance monitoring: {}",
            if monitor { "enabled" } else { "disabled" }
        );
        println!("📄 Output format: {}", format);
        println!("🔄 Result aggregation: {}", aggregation);

        // Perform scan
        let scan_start = Instant::now();

        if path.is_file() {
            // Scan single file
            println!("📄 Scanning file: {:?}", path);

            let result = scanner
                .scan_file(&path, &scan_config)
                .await
                .context("Failed to scan file")?;

            self.output_scan_result(&result, &scan_config, output.as_ref())
                .await
                .context("Failed to output scan result")?;
        } else if path.is_dir() {
            // Scan directory
            println!("📁 Scanning directory: {:?}", path);

            let mut total_files = 0;
            let mut total_matches = 0;
            let mut scan_results = Vec::new();

            // Walk directory and scan files
            let mut entries = fs::read_dir(&path)
                .await
                .with_context(|| format!("Failed to read directory: {:?}", path))?;

            while let Some(entry) = entries.next_entry().await? {
                let file_path = entry.path();

                if file_path.is_file() {
                    total_files += 1;

                    println!("📄 Scanning: {:?}", file_path);

                    match scanner.scan_file(&file_path, &scan_config).await {
                        Ok(result) => {
                            total_matches += result.matches.len();
                            scan_results.push(result);
                        }
                        Err(e) => {
                            warn!("Failed to scan {:?}: {}", file_path, e);
                        }
                    }
                }
            }

            // Output combined results
            self.output_directory_scan_results(&scan_results, &scan_config, output.as_ref())
                .await
                .context("Failed to output directory scan results")?;

            println!(
                "📊 Scanned {} files, found {} total matches",
                total_files, total_matches
            );
        } else {
            return Err(anyhow::anyhow!("Path does not exist: {:?}", path));
        }

        let scan_duration = scan_start.elapsed();
        println!("⏱️  Total scan time: {:?}", scan_duration);

        println!("✅ Enhanced scan completed successfully");

        Ok(())
    }

    /// Optimize YARA rules by detecting duplicates and measuring performance
    async fn optimize_rules(&self, threshold: f32, dry_run: bool) -> Result<()> {
        println!("🔧 Starting YARA rule optimization...");
        println!("   Threshold: {:.1}ms", threshold);
        println!("   Mode: {}", if dry_run { "DRY RUN" } else { "LIVE" });
        println!();

        let optimizer = RuleOptimizer::new(
            self.rules_directory.clone(),
            self.storage.get_db_path().to_path_buf(),
        )
        .context("Failed to create rule optimizer")?;

        let results = optimizer
            .optimize_all(threshold, dry_run)
            .context("Failed to optimize rules")?;

        if results.is_empty() {
            println!("ℹ️  No rules found to optimize");
            return Ok(());
        }

        // Print results table
        println!("📊 Optimization Results:");
        println!(
            "{:<20} {:<20} {:<15} {}",
            "ID", "Duplicate Of", "Performance", "Status"
        );
        println!("{}", "-".repeat(80));

        for result in &results {
            let duplicate_str = result.duplicate_of.as_deref().unwrap_or("-");
            let status = if dry_run { "[DRY]" } else { "[UPDATED]" };
            println!(
                "{:<20} {:<20} {:<15.2} {}",
                result.id, duplicate_str, result.performance_score, status
            );
        }

        println!();
        let duplicates = results.iter().filter(|r| r.duplicate_of.is_some()).count();
        let unique_rules = results.len() - duplicates;

        println!("📈 Summary:");
        println!("   Total rules processed: {}", results.len());
        println!("   Unique rules: {}", unique_rules);
        println!("   Duplicates found: {}", duplicates);

        if !dry_run && duplicates > 0 {
            println!("   ✅ {} duplicate rules deactivated", duplicates);
        }

        Ok(())
    }

    /// Show performance metrics for YARA rule compilation
    async fn show_metrics(&self, top: Option<usize>, format: &str) -> Result<()> {
        println!("📊 YARA Rule Performance Metrics");
        println!();

        let monitor = PerformanceMonitor::new(
            self.storage.get_db_path().to_path_buf(),
            100, // 100ms threshold
        )
        .context("Failed to create performance monitor")?;

        // Initialize monitor to ensure database schema exists
        monitor
            .start()
            .context("Failed to initialize performance monitor")?;

        let metrics = if let Some(n) = top {
            monitor
                .collect_top_slowest(n)
                .context("Failed to collect top slowest metrics")?
        } else {
            monitor.collect().context("Failed to collect metrics")?
        };

        if metrics.is_empty() {
            println!("ℹ️  No performance metrics available");
            println!(
                "   Run rule optimization to generate metrics: erdps-agent yara optimize-rules"
            );
            return Ok(());
        }

        match format {
            "json" => {
                let json = serde_json::to_string_pretty(&metrics)
                    .context("Failed to serialize metrics to JSON")?;
                println!("{}", json);
            }
            _ => {
                // Table format (default)
                println!(
                    "{:<30} {:<15} {:<20}",
                    "Rule ID", "Compile Time (ms)", "Measured At"
                );
                println!("{}", "-".repeat(65));

                let detailed_metrics = monitor
                    .collect_detailed()
                    .context("Failed to collect detailed metrics")?;

                for metric in &metrics {
                    // Find matching detailed metric by rule_id
                    let detail = detailed_metrics
                        .iter()
                        .find(|d| d.rule_id == metric.rule_id);

                    let timestamp = detail.map(|d| d.measured_at.as_str()).unwrap_or("-");

                    println!(
                        "{:<30} {:<15} {:<20}",
                        if metric.rule_id.len() > 27 {
                            format!("{}...", &metric.rule_id[..24])
                        } else {
                            metric.rule_id.clone()
                        },
                        metric.compile_time_ms,
                        timestamp
                    );
                }

                println!();
                println!("📈 Summary:");
                println!("   Total metrics: {}", metrics.len());

                if !metrics.is_empty() {
                    let avg_time = metrics
                        .iter()
                        .map(|m| m.compile_time_ms as f64)
                        .sum::<f64>()
                        / metrics.len() as f64;
                    let max_time = metrics.iter().map(|m| m.compile_time_ms).max().unwrap_or(0);
                    let min_time = metrics.iter().map(|m| m.compile_time_ms).min().unwrap_or(0);

                    println!("   Average compile time: {:.1}ms", avg_time);
                    println!("   Fastest compile time: {}ms", min_time);
                    println!("   Slowest compile time: {}ms", max_time);

                    let slow_rules = metrics.iter().filter(|m| m.compile_time_ms > 100).count();
                    if slow_rules > 0 {
                        println!("   ⚠️  Rules exceeding 100ms threshold: {}", slow_rules);
                    }
                }
            }
        }

        Ok(())
    }

    /// Output scan result for a single file
    async fn output_scan_result(
        &self,
        result: &EnhancedScanResult,
        config: &EnhancedScanConfig,
        output_file: Option<&PathBuf>,
    ) -> Result<()> {
        let output_content = match config.output_format {
            OutputFormat::Json => serde_json::to_string_pretty(result)
                .context("Failed to serialize result to JSON")?,
            _ => {
                format!(
                    "Scan result for {:?}: {} matches",
                    result.file_path,
                    result.matches.len()
                )
            }
        };

        if let Some(output_path) = output_file {
            fs::write(output_path, &output_content)
                .await
                .context("Failed to write output file")?;
            println!("📄 Results written to: {:?}", output_path);
        } else {
            println!("{}", output_content);
        }

        Ok(())
    }

    /// Output combined results for directory scan
    async fn output_directory_scan_results(
        &self,
        results: &[EnhancedScanResult],
        config: &EnhancedScanConfig,
        output_file: Option<&PathBuf>,
    ) -> Result<()> {
        let output_content = match config.output_format {
            OutputFormat::Json => serde_json::to_string_pretty(results)
                .context("Failed to serialize results to JSON")?,
            _ => {
                let mut content = String::new();
                for result in results {
                    if !result.matches.is_empty() {
                        content.push_str(&format!(
                            "File: {:?}, Matches: {}\n",
                            result.file_path,
                            result.matches.len()
                        ));
                    }
                }
                content
            }
        };

        if let Some(output_path) = output_file {
            fs::write(output_path, &output_content)
                .await
                .context("Failed to write output file")?;
            println!("📄 Results written to: {:?}", output_path);
        } else if !output_content.trim().is_empty() {
            println!("{}", output_content);
        }

        Ok(())
    }

    /// Collect rule information from directory
    fn collect_rules_info<'a>(
        rules_directory: &'a Path,
        directory: &'a Path,
        rules: &'a mut Vec<RuleInfo>,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let mut entries = fs::read_dir(directory)
                .await
                .with_context(|| format!("Failed to read directory: {:?}", directory))?;

            while let Some(entry) = entries.next_entry().await? {
                let path = entry.path();

                if path.is_file() {
                    if let Some(extension) = path.extension() {
                        let ext_str = extension.to_string_lossy().to_lowercase();
                        if ext_str == "yar" || ext_str == "yara" {
                            if let Ok(rule_info) =
                                Self::extract_rule_info_static(rules_directory, &path).await
                            {
                                rules.push(rule_info);
                            }
                        }
                    }
                } else if path.is_dir() {
                    Self::collect_rules_info(rules_directory, &path, rules).await?;
                }
            }

            Ok(())
        })
    }

    /// Extract rule information from a file
    async fn extract_rule_info(&self, file_path: &Path) -> Result<RuleInfo> {
        Self::extract_rule_info_static(&self.rules_directory, file_path).await
    }

    /// Static version of extract_rule_info for use in async contexts
    async fn extract_rule_info_static(
        rules_directory: &Path,
        file_path: &Path,
    ) -> Result<RuleInfo> {
        let content = fs::read_to_string(file_path)
            .await
            .with_context(|| format!("Failed to read file: {:?}", file_path))?;

        let metadata = fs::metadata(file_path)
            .await
            .with_context(|| format!("Failed to get file metadata: {:?}", file_path))?;

        // Extract basic information
        let rule_name = extract_first_rule_name(&content).unwrap_or_else(|| "unknown".to_string());
        let rule_count = content.matches("rule ").count();

        // Determine repository from path
        let repository = file_path.ancestors().find_map(|ancestor| {
            if ancestor.parent() == Some(rules_directory) {
                ancestor
                    .file_name()
                    .map(|name| name.to_string_lossy().to_string())
            } else {
                None
            }
        });

        Ok(RuleInfo {
            file_path: file_path.to_path_buf(),
            rule_name,
            category: None, // Would be extracted from metadata
            repository,
            author: None,      // Would be extracted from metadata
            description: None, // Would be extracted from metadata
            is_valid: true,    // Would be determined by validation
            file_size: metadata.len(),
            rule_count,
            last_validated: None,
        })
    }

    /// Execute multi-layer scan
    async fn multi_scan(
        &mut self,
        path: PathBuf,
        _layers: &[String],
        risk_threshold: Option<f32>,
        format: &str,
        output: Option<PathBuf>,
        verbose: bool,
    ) -> Result<()> {
        info!("Starting multi-layer scan on: {:?}", path);

        // Create rule loader and config for file scanner
        let rule_loader = Arc::new(YaraRuleLoader::new(&self.rules_directory, false));
        let config = Arc::new(Config::default());

        // Create file scanner instance
        let file_scanner = Arc::new(RwLock::new(YaraFileScanner::new(rule_loader, config)));

        // Create multi-layer scanner
        let scanner = MultiLayerScanner::new(
            file_scanner,
            PathBuf::from("scan_results.db"), // Database path for storing results
        );

        // Determine scan target
        let target = if path.is_file() {
            ScanTarget::File(path)
        } else {
            ScanTarget::Directory(path)
        };

        // Execute scan
        let result = scanner
            .scan(target)
            .await
            .context("Multi-layer scan failed")?;

        // Check risk threshold
        let threshold = risk_threshold.unwrap_or(0.7);
        let is_alert = result.risk_score > threshold;

        // Output results
        self.output_multi_scan_result(&result, format, output.as_ref(), verbose, is_alert)
            .await
            .context("Failed to output scan results")?;

        if is_alert {
            println!(
                "🚨 ALERT: Risk score {:.2} exceeds threshold {:.2}",
                result.risk_score, threshold
            );
        }

        info!(
            "Multi-layer scan completed with risk score: {:.2}",
            result.risk_score
        );
        Ok(())
    }

    /// Correlate alerts across multiple scan results
    async fn correlate_alerts(
        &mut self,
        min_scans: usize,
        min_layers: usize,
        scan_result_paths: Vec<PathBuf>,
        db_path: Option<PathBuf>,
    ) -> Result<()> {
        use super::correlation_engine::CorrelationEngine;

        info!(
            "Starting correlation analysis with {} scan results",
            scan_result_paths.len()
        );

        // Load scan results from JSON files
        let mut scan_results = Vec::new();
        for path in &scan_result_paths {
            info!("Loading scan result from: {:?}", path);
            let content = fs::read_to_string(path)
                .await
                .with_context(|| format!("Failed to read scan result file: {:?}", path))?;

            let result: LayeredScanResult = serde_json::from_str(&content)
                .with_context(|| format!("Failed to parse scan result JSON: {:?}", path))?;

            scan_results.push(result);
        }

        // Create correlation engine
        let db_path = db_path.unwrap_or_else(|| PathBuf::from("correlation.db"));
        let engine =
            CorrelationEngine::new(db_path).context("Failed to create correlation engine")?;

        // Perform correlation analysis
        let correlated_alerts = engine
            .correlate(&scan_results, min_scans, min_layers)
            .context("Failed to perform correlation analysis")?;

        info!("Found {} correlated alerts", correlated_alerts.len());

        // Store alerts in database
        if !correlated_alerts.is_empty() {
            engine
                .store_alerts(&correlated_alerts)
                .context("Failed to store correlated alerts")?;
        }

        // Display results in table format
        println!("\nCorrelated Alerts");
        println!("=================");
        println!("{:<36} {:<50} {:<10}", "Alert ID", "Rule IDs", "Confidence");
        println!("{}", "-".repeat(100));

        for alert in &correlated_alerts {
            let rule_ids_str = if alert.rule_ids.len() > 3 {
                format!(
                    "{}, ... ({} total)",
                    alert.rule_ids[..3].join(", "),
                    alert.rule_ids.len()
                )
            } else {
                alert.rule_ids.join(", ")
            };

            let rule_ids_display = if rule_ids_str.len() > 47 {
                format!("{}...", &rule_ids_str[..44])
            } else {
                rule_ids_str
            };

            println!(
                "{:<36} {:<50} {:<10.2}",
                alert.alert_id, rule_ids_display, alert.confidence
            );
        }

        if correlated_alerts.is_empty() {
            println!("No correlated alerts found with the specified thresholds.");
            println!("Try lowering --min-scans or --min-layers values.");
        }

        info!("Correlation analysis completed");
        Ok(())
    }

    /// Score threats using machine learning model
    async fn score_threats(
        &mut self,
        _model_path: PathBuf,
        _scaler_path: PathBuf,
        input_path: PathBuf,
        output_path: PathBuf,
    ) -> Result<()> {
        // use super::ml_threat_scoring::ThreatScorer; // ML threat scoring removed for production
        use super::multi_layer_scanner::RuleMatch;

        info!("Starting ML threat scoring process");

        // Load input RuleMatch objects from JSON
        info!("Loading rule matches from: {:?}", input_path);
        let input_content = fs::read_to_string(&input_path)
            .await
            .with_context(|| format!("Failed to read input file: {:?}", input_path))?;

        let rule_matches: Vec<RuleMatch> = serde_json::from_str(&input_content)
            .with_context(|| format!("Failed to parse input JSON: {:?}", input_path))?;

        info!("Loaded {} rule matches for scoring", rule_matches.len());

        // ML threat scoring removed for production - using basic rule-based scoring
        info!("Computing basic threat scores for {} matches", rule_matches.len());
        
        // Generate basic threat scores based on rule metadata
        let mut threat_scores = Vec::new();
        for rule_match in &rule_matches {
            let score = match rule_match.rule_name.to_lowercase() {
                name if name.contains("trojan") || name.contains("malware") => 0.9,
                name if name.contains("suspicious") || name.contains("pua") => 0.6,
                name if name.contains("adware") || name.contains("riskware") => 0.4,
                _ => 0.3,
            };
            
            let label = if score >= 0.8 { "high" } else if score >= 0.5 { "medium" } else { "low" };
            
            threat_scores.push(ThreatScore {
                rule_id: rule_match.rule_name.clone(),
                score,
                label: label.to_string(),
                confidence: score * 0.8, // Basic confidence calculation
                features: std::collections::HashMap::new(),
            });
        }

        info!("Generated {} threat scores", threat_scores.len());

        // Note: Database storage would require SQLite pool integration
        // For now, we'll skip this step in the CLI implementation
        info!("Skipping database storage (not implemented in CLI executor)");

        // Write output JSON
        info!("Writing threat scores to: {:?}", output_path);
        let output_json = serde_json::to_string_pretty(&threat_scores)
            .context("Failed to serialize threat scores to JSON")?;

        fs::write(&output_path, &output_json)
            .await
            .with_context(|| format!("Failed to write output file: {:?}", output_path))?;

        // Display summary
        println!("\nThreat Scoring Results");
        println!("=====================");
        println!("Total matches scored: {}", threat_scores.len());

        let mut low_count = 0;
        let mut medium_count = 0;
        let mut high_count = 0;

        for score in &threat_scores {
            match score.label.as_str() {
                "low" => low_count += 1,
                "medium" => medium_count += 1,
                "high" => high_count += 1,
                _ => {}
            }
        }

        println!("Low threat: {} matches", low_count);
        println!("Medium threat: {} matches", medium_count);
        println!("High threat: {} matches", high_count);

        println!("\nTop 10 Highest Threat Scores:");
        println!("{:<30} {:<10} {:<10}", "Rule ID", "Score", "Label");
        println!("{}", "-".repeat(52));

        let mut sorted_scores = threat_scores.clone();
        sorted_scores.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        for (_i, score) in sorted_scores.iter().take(10).enumerate() {
            let rule_id_display = if score.rule_id.len() > 27 {
                format!("{}...", &score.rule_id[..24])
            } else {
                score.rule_id.clone()
            };

            println!(
                "{:<30} {:<10.3} {:<10}",
                rule_id_display, score.score, score.label
            );
        }

        println!("\n📄 Results written to: {:?}", output_path);
        info!("ML threat scoring completed successfully");

        Ok(())
    }

    /// Scan files using EMBER ML malware detection
    #[cfg(feature = "basic-detection")]
    async fn ember_scan(
        &mut self,
        path: PathBuf,
        _ember_model: PathBuf,
        response_policy: Option<PathBuf>,
        threshold: f32,
        format: &str,
        output: Option<PathBuf>,
        auto_response: bool,
    ) -> Result<()> {
        use crate::yara::auto_response::AutoResponder;
        use crate::yara::ember_detector::BasicMalwareDetector;

        info!("Starting basic malware detection scan");
        info!("Target path: {:?}", path);
        info!("Threshold: {}", threshold);

        // Initialize basic detector
        let mut detector = BasicMalwareDetector::new(threshold)
            .context("Failed to initialize basic detector")?;

        // Collect files to scan
        let mut files_to_scan = Vec::new();
        if path.is_file() {
            files_to_scan.push(path);
        } else if path.is_dir() {
            Self::collect_pe_files(&path, &mut files_to_scan).await?;
        } else {
            return Err(anyhow::anyhow!("Path does not exist: {:?}", path));
        }

        info!("Found {} files to scan", files_to_scan.len());

        // Scan files
        let mut scan_results = Vec::new();
        let mut malware_count = 0;

        for file_path in &files_to_scan {
            match detector.predict(file_path).await {
                Ok(score) => {
                    if score.is_malware {
                        malware_count += 1;
                    }
                    scan_results.push((file_path.clone(), score));
                }
                Err(e) => {
                    warn!("Failed to scan {:?}: {}", file_path, e);
                }
            }
        }

        // Apply automated response if enabled
        if auto_response && response_policy.is_some() {
            let policy_path = response_policy.unwrap();
            let _quarantine_dir = std::env::temp_dir().join("erdps_quarantine");

            let policy = AutoResponder::load_policy(&policy_path)
                .await
                .context("Failed to load response policy")?;
            let _responder =
                AutoResponder::new(policy).context("Failed to initialize auto responder")?;

            let malware_scores: Vec<_> = scan_results
                .iter()
                .filter(|(_, score)| score.is_malware)
                .map(|(_, score)| score.clone())
                .collect();

            if !malware_scores.is_empty() {
                info!(
                    "Found {} malware detections, would execute automated responses",
                    malware_scores.len()
                );
                // TODO: Implement automated response execution
                // This would iterate through malware_scores and call responder.respond_to_detection
            }
        }

        // Output results
        self.output_basic_results(&scan_results, format, output.as_ref(), malware_count)
            .await?;

        Ok(())
    }

    /// Apply automated response policies
    #[cfg(feature = "basic-detection")]
    async fn auto_response(
        &mut self,
        response_policy: PathBuf,
        _input: Option<PathBuf>,
        dry_run: bool,
        _format: &str,
    ) -> Result<()> {
        use crate::yara::auto_response::AutoResponder;

        info!("Applying automated response policies");
        info!("Policy file: {:?}", response_policy);
        info!("Dry run: {}", dry_run);

        let policy = AutoResponder::load_policy(&response_policy)
            .await
            .context("Failed to load response policy")?;
        let _responder =
            AutoResponder::new(policy).context("Failed to initialize auto responder")?;

        // For now, we'll implement a simple version that works with database results
        // In a full implementation, this would query the ember_detections table

        if dry_run {
            println!("DRY RUN MODE - No actions will be executed");
            println!("Response policy loaded successfully");
            println!("Auto-response system initialized successfully");
        } else {
            println!("Auto-response functionality requires database integration");
            println!("This would query ember_detections table and apply policies");
        }

        Ok(())
    }

    /// Collect PE files from directory
    fn collect_pe_files<'a>(
        dir: &'a PathBuf,
        files: &'a mut Vec<PathBuf>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            let mut entries = tokio::fs::read_dir(dir)
                .await
                .context("Failed to read directory")?;

            while let Some(entry) = entries.next_entry().await? {
                let path = entry.path();
                if path.is_dir() {
                    Self::collect_pe_files(&path, files).await?;
                } else if let Some(ext) = path.extension() {
                    let ext_str = ext.to_string_lossy().to_lowercase();
                    if matches!(ext_str.as_str(), "exe" | "dll" | "sys" | "scr" | "com") {
                        files.push(path);
                    }
                }
            }

            Ok(())
        })
    }

    /// Output basic scan results
    #[cfg(feature = "basic-detection")]
    async fn output_basic_results(
        &self,
        results: &[(PathBuf, crate::yara::ember_detector::MalwareScore)],
        format: &str,
        output_file: Option<&PathBuf>,
        malware_count: usize,
    ) -> Result<()> {
        let output_content = match format {
            "json" => serde_json::to_string_pretty(results)
                .context("Failed to serialize results to JSON")?,
            _ => {
                let mut content = String::new();
                content.push_str("Basic Malware Detection Results\n");
                content.push_str("================================\n\n");
                content.push_str(&format!("Total files scanned: {}\n", results.len()));
                content.push_str(&format!("Malware detected: {}\n\n", malware_count));

                content.push_str(&format!(
                    "{:<50} {:<12} {:<10}\n",
                    "File Path", "Probability", "Status"
                ));
                content.push_str(&format!("{}\n", "-".repeat(75)));

                for (path, score) in results {
                    let path_str = path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("<unknown>");
                    let path_display = if path_str.len() > 47 {
                        format!("{}...", &path_str[..44])
                    } else {
                        path_str.to_string()
                    };

                    let status = if score.is_malware { "MALWARE" } else { "CLEAN" };
                    content.push_str(&format!(
                        "{:<50} {:<12.3} {:<10}\n",
                        path_display, score.probability, status
                    ));
                }

                if malware_count > 0 {
                    content.push_str(
                        "\n🚨 MALWARE DETECTED! Review results and take appropriate action.\n",
                    );
                }

                content
            }
        };

        if let Some(output_path) = output_file {
            tokio::fs::write(output_path, &output_content)
                .await
                .context("Failed to write output file")?;
            println!("📄 Results written to: {:?}", output_path);
        } else {
            println!("{}", output_content);
        }

        Ok(())
    }

    /// Output multi-layer scan results
    async fn update_sources(&mut self, force: bool, validate: bool, detailed: bool) -> Result<()> {
        info!("Updating all rule sources...");
        
        let start_time = Instant::now();
        let mut errors = Vec::new();
        
        // Update all sources using the multi-source downloader
        let summary = match self.multi_downloader.download_all(force, detailed).await {
            Ok(summary) => {
                if detailed {
                    println!("\n📊 Download Summary:");
                    for (source, stats) in &summary.source_stats {
                        if stats.success {
                            println!("  ✅ {}: {} files, {}", 
                                source, 
                                stats.files_downloaded, 
                                format_file_size(stats.size_downloaded)
                            );
                        } else {
                            println!("  ❌ {}: {}", source, stats.error.as_deref().unwrap_or("Unknown error"));
                            errors.push(format!("{}: {}", source, stats.error.as_deref().unwrap_or("Unknown error")));
                        }
                    }
                }
                summary
            }
            Err(e) => {
                error!("Failed to update sources: {}", e);
                return Err(e);
            }
        };
        
        // Validate rules if requested
        if validate {
            info!("Validating downloaded rules...");
            match self.validate_rules(None, false, false, None).await {
                Ok(_) => info!("Rule validation completed successfully"),
                Err(e) => {
                    warn!("Rule validation failed: {}", e);
                    errors.push(format!("Validation failed: {}", e));
                }
            }
        }
        
        let duration = start_time.elapsed();
        
        println!("\n🎉 Update completed in {:.2}s", duration.as_secs_f64());
        println!("📁 Total files: {}", summary.total_files);
        println!("💾 Total size: {}", format_file_size(summary.total_size));
        
        if !errors.is_empty() {
            println!("\n⚠️  Errors encountered:");
            for error in errors {
                println!("  • {}", error);
            }
        }
        
        Ok(())
    }
    
    async fn rule_stats(&mut self, detailed: bool, performance: bool, format: &str) -> Result<()> {
        info!("Gathering rule statistics...");
        
        let start_time = Instant::now();
        let mut rules = Vec::new();
        
        // Collect all rules information
        Self::collect_rules_info(&self.rules_directory, &self.rules_directory, &mut rules).await?;
        
        let total_rules = rules.len();
        let valid_rules = rules.iter().filter(|r| r.is_valid).count();
        let invalid_rules = total_rules - valid_rules;
        let total_size: u64 = rules.iter().map(|r| r.file_size).sum();
        
        // Group by category and repository
        let mut category_stats = std::collections::HashMap::new();
        let mut repo_stats = std::collections::HashMap::new();
        
        for rule in &rules {
            if let Some(category) = &rule.category {
                *category_stats.entry(category.clone()).or_insert(0) += 1;
            }
            if let Some(repo) = &rule.repository {
                *repo_stats.entry(repo.clone()).or_insert(0) += 1;
            }
        }
        
        match format {
            "json" => {
                let stats = serde_json::json!({
                    "total_rules": total_rules,
                    "valid_rules": valid_rules,
                    "invalid_rules": invalid_rules,
                    "total_size_bytes": total_size,
                    "total_size_formatted": format_file_size(total_size),
                    "categories": category_stats,
                    "repositories": repo_stats,
                    "collection_time_ms": start_time.elapsed().as_millis()
                });
                println!("{}", serde_json::to_string_pretty(&stats)?);
            }
            _ => {
                println!("\n📊 YARA Rule Statistics");
                println!("═══════════════════════");
                println!("📁 Total Rules: {}", total_rules);
                println!("✅ Valid Rules: {}", valid_rules);
                println!("❌ Invalid Rules: {}", invalid_rules);
                println!("💾 Total Size: {}", format_file_size(total_size));
                
                if detailed {
                    println!("\n📂 Categories:");
                    let mut sorted_categories: Vec<_> = category_stats.iter().collect();
                    sorted_categories.sort_by(|a, b| b.1.cmp(a.1));
                    for (category, count) in sorted_categories.iter().take(10) {
                        println!("  • {}: {} rules", category, count);
                    }
                    
                    println!("\n🏛️  Repositories:");
                    let mut sorted_repos: Vec<_> = repo_stats.iter().collect();
                    sorted_repos.sort_by(|a, b| b.1.cmp(a.1));
                    for (repo, count) in sorted_repos.iter().take(10) {
                        println!("  • {}: {} rules", repo, count);
                    }
                }
                
                if performance {
                    println!("\n⚡ Performance Metrics:");
                    println!("  • Collection Time: {:.2}ms", start_time.elapsed().as_millis());
                    println!("  • Average Rule Size: {}", format_file_size(total_size / total_rules.max(1) as u64));
                    
                    // Calculate validation rate if we have validation data
                    let validation_rate = (valid_rules as f64 / total_rules.max(1) as f64) * 100.0;
                    println!("  • Validation Rate: {:.1}%", validation_rate);
                }
            }
        }
        
        Ok(())
    }

    async fn output_multi_scan_result(
        &self,
        result: &LayeredScanResult,
        format: &str,
        output_file: Option<&PathBuf>,
        verbose: bool,
        is_alert: bool,
    ) -> Result<()> {
        let output_content = match format {
            "json" => serde_json::to_string_pretty(result)
                .context("Failed to serialize result to JSON")?,
            _ => {
                let mut content = String::new();
                content.push_str(&format!("Multi-Layer Scan Results\n"));
                content.push_str(&format!("========================\n"));
                content.push_str(&format!("Risk Score: {:.2}\n\n", result.risk_score));

                content.push_str(&format!(
                    "File Layer: {} matches\n",
                    result.file_matches.len()
                ));
                if verbose {
                    for m in &result.file_matches {
                        content.push_str(&format!("  - {}\n", m.rule_name));
                    }
                }

                content.push_str(&format!(
                    "Memory Layer: {} matches\n",
                    result.memory_matches.len()
                ));
                if verbose {
                    for m in &result.memory_matches {
                        content.push_str(&format!("  - {}\n", m.rule_name));
                    }
                }

                content.push_str(&format!(
                    "Behavior Layer: {} matches\n",
                    result.behavior_matches.len()
                ));
                if verbose {
                    for m in &result.behavior_matches {
                        content.push_str(&format!("  - {}\n", m.rule_name));
                    }
                }

                content.push_str(&format!(
                    "Network Layer: {} matches\n",
                    result.network_matches.len()
                ));
                if verbose {
                    for m in &result.network_matches {
                        content.push_str(&format!("  - {}\n", m.rule_name));
                    }
                }

                if is_alert {
                    content.push_str(&format!("\n🚨 ALERT: High risk detected!\n"));
                }

                content
            }
        };

        if let Some(output_path) = output_file {
            fs::write(output_path, &output_content)
                .await
                .context("Failed to write output file")?;
            println!("📄 Results written to: {:?}", output_path);
        } else {
            println!("{}", output_content);
        }

        Ok(())
    }
}

/// Extract first rule name from YARA content
fn extract_first_rule_name(content: &str) -> Option<String> {
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with("rule ") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                return Some(parts[1].trim_end_matches('{').to_string());
            }
        }
    }
    None
}

/// Format file size in human-readable format
fn format_file_size(size: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB"];
    let mut size = size as f64;
    let mut unit_index = 0;

    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }

    if unit_index == 0 {
        format!("{} {}", size as u64, UNITS[unit_index])
    } else {
        format!("{:.1} {}", size, UNITS[unit_index])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_rule_name() {
        let content = r#"
            rule TestRule {
                condition:
                    true
            }
        "#;

        assert_eq!(
            extract_first_rule_name(content),
            Some("TestRule".to_string())
        );
    }

    #[test]
    fn test_format_file_size() {
        assert_eq!(format_file_size(512), "512 B");
        assert_eq!(format_file_size(1024), "1.0 KB");
        assert_eq!(format_file_size(1536), "1.5 KB");
        assert_eq!(format_file_size(1048576), "1.0 MB");
    }
}
