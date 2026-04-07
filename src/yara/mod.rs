//! YARA Integration Module
//!
//! This module provides comprehensive YARA rule management and scanning capabilities:
//! - Dynamic rule loading and compilation from multiple sources
//! - Asynchronous file scanning with performance monitoring
//! - GitHub rule downloading from popular repositories
//! - Rule validation and compilation testing
//! - Rule optimization and deduplication engine
//! - Enhanced scanning with category-based filtering and correlation
//! - SQLite-based metadata storage and management
//! - Category-based rule organization and filtering
//! - Extended CLI commands for rule management
//!
//! The module integrates with the existing agent architecture while providing
//! enhanced YARA functionality for malware detection and analysis.

use anyhow::Result;
// use std::sync::Arc;
// use tokio::sync::RwLock;
// use tracing::{info, warn};

// Re-export main types for external use
#[cfg(feature = "basic-detection")]
pub use auto_response::{AutoResponder, ResponseAction, ResponsePolicy, ResponseResult};
pub use category_scanner::CategoryFilter;
pub use category_system::{CategoryStats, RuleCategory, RuleCorrelation, YaraCategorySystem};
pub use cli_commands::{YaraCliArgs, YaraCliExecutor, YaraCommand};
pub use correlation_engine::{CorrelatedAlert, CorrelationEngine};
#[cfg(feature = "basic-detection")]
pub use ember_detector::{BasicFeatures, BasicMalwareDetector as EmberMalwareDetector, MalwareScore};
pub use enhanced_scanner::{EnhancedScanConfig, EnhancedScanResult, EnhancedYaraScanner};
pub use file_scanner::{ScanResult, ScanStatistics, YaraFileScanner};
pub use github_downloader::{DownloadStats, GitHubDownloader, GitHubSource};
pub use multi_source_downloader::{MultiSourceDownloader, RuleSource, SourceDownloadStats, SourceType};

pub use multi_layer_scanner::{LayeredScanResult, MultiLayerScanner, ScanTarget};
pub use performance_monitor::{
    OperationMetrics, OperationType, PerformanceMetrics, PerformanceMonitor,
};
pub use rule_loader::{CompilationStats, RuleMetadata as LoaderRuleMetadata, YaraRuleLoader};
pub use rule_cache::{CacheStats, RuleCacheMetadata, YaraRuleCache};
pub use rule_optimizer::{OptimizationResult, RuleOptimizer};
pub use rule_validator::{ValidationResult, QualityAssessment, RuleValidator};
pub use rule_sources::{RuleSourceManager, RuleSourceConfig, DownloadResult};
pub use storage::{StorageStats, YaraStorage};

// Module declarations
pub mod category_scanner;
pub mod category_system;
pub mod cli_commands;
pub mod correlation_engine;

pub mod enhanced_scanner;
pub mod file_scanner;
pub mod github_downloader;

pub mod multi_layer_scanner;
pub mod performance_monitor;
pub mod rule_loader;
pub mod rule_cache;
pub mod rule_optimizer;
pub mod rule_validator;
pub mod storage;
pub mod multi_source_downloader;
pub mod rule_sources;

// EMBER Malware Detection modules
#[cfg(feature = "basic-detection")]
pub mod auto_response;
#[cfg(feature = "basic-detection")]
pub mod ember_detector;

/// Initialize YARA subsystem
/// This should be called once at application startup
pub fn init() -> Result<(), Box<dyn std::error::Error>> {
    log::info!("Initializing YARA subsystem");

    // Initialize YARA library
    #[cfg(feature = "yara")]
    {
        // YARA library initialization is handled by the yara crate
        log::info!("YARA library initialized successfully");
    }

    Ok(())
}

/// Get YARA library version information
pub fn get_version_info() -> String {
    #[cfg(feature = "yara")]
    {
        format!("YARA integration enabled")
    }
    #[cfg(not(feature = "yara"))]
    {
        "YARA integration disabled".to_string()
    }
}
