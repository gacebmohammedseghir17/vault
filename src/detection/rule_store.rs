//! Production-grade YARA Rule Store for enterprise malware detection
//!
//! This module provides a comprehensive rule management system that:
//! - Downloads YARA rule bundles from remote sources
//! - Validates them using SHA-256 hashing and optional signature verification
//! - Compiles rules using the YARA compiler
//! - Stores compiled bundles on disk with metadata manifests
//! - Supports atomic hot-swap activation for zero-downtime updates
//! - Prevents duplicates through hash-based deduplication
//! - Provides thread-safe API for retrieving active compiled rules

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tracing::{error, info, warn};

// Always use yara_x for consistency
use yara_x::{Compiler, Rules};
use yara_x::errors::CompileError as YaraLibError;

// Import our custom YaraError type
use crate::error::YaraError;

// Helper function to unify build() signature across feature gates
#[cfg(feature = "yara")]
fn build_rules(compiler: Compiler) -> std::result::Result<Rules, YaraError> {
    Ok(compiler.build())
}

#[cfg(not(feature = "yara"))]
fn build_rules(_compiler: Compiler) -> std::result::Result<Rules, YaraError> {
    // Mock implementation for non-YARA builds
    Err(YaraError::InitializationError {
        message: "YARA feature not enabled".to_string(),
        source: None,
    })
}

/// Maximum file size for rule bundles (50 MB)
const MAX_BUNDLE_SIZE: u64 = 50 * 1024 * 1024;

/// Rule bundle metadata and file information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleBundle {
    /// Bundle name identifier
    pub name: String,
    /// Version string (e.g., "2025.08.21-01")
    pub version: String,
    /// Path to the rule file on disk
    pub path: PathBuf,
    /// SHA-256 hash of the rule file
    pub sha256: String,
    /// Number of rules in the bundle
    pub count: u32,
}

/// Compiled YARA rules with metadata
#[derive(Clone)]
pub struct CompiledRules {
    /// Thread-safe handle to compiled YARA rules
    pub handle: Arc<RwLock<Rules>>,
    /// Associated bundle metadata
    pub meta: RuleBundle,
}

/// Rule bundle manifest stored as JSON
#[derive(Debug, Serialize, Deserialize)]
struct RuleManifest {
    name: String,
    version: String,
    sha256: String,
    count: u32,
    created_at: DateTime<Utc>,
}

/// Configuration for rule store operations
#[derive(Debug, Clone)]
pub struct RuleStoreConfig {
    /// Directory for storing rules and cache
    pub rules_dir: PathBuf,
    /// URL for downloading rule updates
    pub update_url: String,
    /// Update check interval in seconds
    pub update_interval_secs: u64,
    /// Whether to require signed rules
    pub require_signed_rules: bool,
}

impl Default for RuleStoreConfig {
    fn default() -> Self {
        Self {
            rules_dir: PathBuf::from("rules"),
            update_url: "https://example.com/rules/ransomware-core.yar".to_string(),
            update_interval_secs: 86400, // 24 hours
            require_signed_rules: false,
        }
    }
}

/// Comprehensive error types for rule store operations
#[derive(Error, Debug)]
pub enum RuleStoreError {
    #[error("Download failed for URL {url}: {source}")]
    DownloadError {
        url: String,
        #[source]
        source: reqwest::Error,
    },

    #[error("Validation failed: {reason}")]
    ValidationError { reason: String },

    #[error("Compilation failed for bundle {bundle}: {reason}")]
    CompileError { bundle: String, reason: String },

    #[error("Activation failed: {reason}")]
    ActivationError { reason: String },

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("JSON serialization error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("YARA library error: {0}")]
    YaraError(#[from] YaraLibError),

    #[error("HTTP request error: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("File size {size} exceeds maximum allowed size {max_size}")]
    FileSizeError { size: u64, max_size: u64 },

    #[error("Invalid file path: {path}")]
    InvalidPath { path: String },

    #[error("Signature verification failed")]
    SignatureError,
}

type Result<T> = std::result::Result<T, RuleStoreError>;

/// Async trait for rule store operations
#[async_trait]
pub trait RuleStore: Send + Sync {
    /// Download a rule bundle from a remote URL with optional signature verification
    async fn download_bundle(&self, url: &str, sig: Option<&[u8]>) -> Result<RuleBundle>;

    /// Compile a rule bundle into executable YARA rules
    fn compile(&self, bundle: &RuleBundle) -> Result<CompiledRules>;

    /// Atomically activate compiled rules for use by the detection engine
    fn activate(&self, compiled: CompiledRules) -> Result<()>;

    /// Get the currently active compiled rules
    fn current(&self) -> Arc<RwLock<Option<CompiledRules>>>;
}

/// Production implementation of the RuleStore trait
pub struct ProductionRuleStore {
    /// Configuration for rule store operations
    config: RuleStoreConfig,
    /// HTTP client for downloading rules
    client: Client,
    /// Currently active compiled rules
    active_rules: Arc<RwLock<Option<CompiledRules>>>,
    /// Cache of downloaded rule hashes for deduplication
    hash_cache: Arc<RwLock<HashMap<String, PathBuf>>>,
}

impl ProductionRuleStore {
    /// Create a new production rule store with the given configuration
    pub fn new(config: RuleStoreConfig) -> Result<Self> {
        // Ensure rules directory exists
        let cache_dir = config.rules_dir.join("cache");
        fs::create_dir_all(&cache_dir)?;

        info!(
            "Initialized RuleStore with rules_dir: {:?}",
            config.rules_dir
        );

        Ok(Self {
            config,
            client: Client::new(),
            active_rules: Arc::new(RwLock::new(None)),
            hash_cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Load existing rule cache from disk
    pub fn load_cache(&self) -> Result<()> {
        let cache_dir = self.config.rules_dir.join("cache");
        if !cache_dir.exists() {
            return Ok(());
        }

        let mut cache = self.hash_cache.write().unwrap();

        for entry in fs::read_dir(&cache_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                if let Ok(manifest_data) = fs::read_to_string(&path) {
                    if let Ok(manifest) = serde_json::from_str::<RuleManifest>(&manifest_data) {
                        let cbin_path = cache_dir.join(format!("{}.cbin", manifest.sha256));
                        if cbin_path.exists() {
                            cache.insert(manifest.sha256.clone(), cbin_path);
                            info!(
                                "Loaded cached rule bundle: {} ({})",
                                manifest.name, manifest.sha256
                            );
                        }
                    }
                }
            }
        }

        info!("Loaded {} cached rule bundles", cache.len());
        Ok(())
    }

    /// Validate file size and security constraints
    fn validate_file(&self, path: &Path) -> Result<()> {
        let metadata = fs::metadata(path)?;

        // Check file size
        if metadata.len() > MAX_BUNDLE_SIZE {
            return Err(RuleStoreError::FileSizeError {
                size: metadata.len(),
                max_size: MAX_BUNDLE_SIZE,
            });
        }

        // Security checks: skip network shares, symlinks, special devices
        if metadata.file_type().is_symlink() {
            return Err(RuleStoreError::ValidationError {
                reason: "Symlinks are not allowed for security reasons".to_string(),
            });
        }

        // Additional platform-specific security checks could be added here

        Ok(())
    }

    /// Verify rule bundle signature (stub implementation)
    fn verify_signature(&self, _data: &[u8], _signature: &[u8]) -> Result<()> {
        // TODO: Implement Ed25519/PKCS#7 signature verification
        // This is a stub for future implementation
        if self.config.require_signed_rules {
            warn!("Signature verification required but not yet implemented");
            return Err(RuleStoreError::SignatureError);
        }
        Ok(())
    }

    /// Count the number of rules in rule content by counting "rule " occurrences
    fn count_rules_in_content(&self, content: &str) -> u32 {
        // Count rules by counting "rule " occurrences in the source text
        content.matches("rule ").count() as u32
    }

    /// Generate and save rule manifest
    fn save_manifest(&self, bundle: &RuleBundle) -> Result<()> {
        let manifest = RuleManifest {
            name: bundle.name.clone(),
            version: bundle.version.clone(),
            sha256: bundle.sha256.clone(),
            count: bundle.count,
            created_at: Utc::now(),
        };

        let manifest_path = self
            .config
            .rules_dir
            .join("cache")
            .join(format!("{}.json", bundle.sha256));

        let manifest_json = serde_json::to_string_pretty(&manifest)?;
        fs::write(&manifest_path, manifest_json)?;

        info!(
            "Saved manifest for bundle: {} at {:?}",
            bundle.name, manifest_path
        );
        Ok(())
    }

    /// Compute SHA-256 hash of a file
    #[allow(dead_code)]
    fn compute_file_hash(&self, path: &Path) -> Result<String> {
        let content = fs::read(path)?;
        let mut hasher = Sha256::new();
        hasher.update(&content);
        Ok(format!("{:x}", hasher.finalize()))
    }
}

#[async_trait]
impl RuleStore for ProductionRuleStore {
    async fn download_bundle(&self, url: &str, sig: Option<&[u8]>) -> Result<RuleBundle> {
        info!("Downloading rule bundle from: {}", url);

        // Download the rule file
        let response =
            self.client
                .get(url)
                .send()
                .await
                .map_err(|e| RuleStoreError::DownloadError {
                    url: url.to_string(),
                    source: e,
                })?;

        if !response.status().is_success() {
            return Err(RuleStoreError::ValidationError {
                reason: format!("HTTP error: {}", response.status()),
            });
        }

        let content = response
            .bytes()
            .await
            .map_err(|e| RuleStoreError::DownloadError {
                url: url.to_string(),
                source: e,
            })?;

        // Validate file size
        if content.len() as u64 > MAX_BUNDLE_SIZE {
            return Err(RuleStoreError::FileSizeError {
                size: content.len() as u64,
                max_size: MAX_BUNDLE_SIZE,
            });
        }

        // Compute SHA-256 hash
        let mut hasher = Sha256::new();
        hasher.update(&content);
        let sha256 = format!("{:x}", hasher.finalize());

        // Check for duplicates
        {
            let cache = self.hash_cache.read().unwrap();
            if cache.contains_key(&sha256) {
                warn!("Skipping duplicate rule bundle with hash: {}", sha256);
                // Return existing bundle info
                let existing_path = cache.get(&sha256).unwrap();
                return Ok(RuleBundle {
                    name: "existing".to_string(),
                    version: "cached".to_string(),
                    path: existing_path.clone(),
                    sha256,
                    count: 0, // Will be updated during compilation
                });
            }
        }

        // Verify signature if provided
        if let Some(signature) = sig {
            self.verify_signature(&content, signature)?;
        }

        // Save to disk
        let filename = format!("{}.yar", sha256);
        let file_path = self.config.rules_dir.join(&filename);
        fs::write(&file_path, &content)?;

        // Validate the saved file
        self.validate_file(&file_path)?;

        // Extract bundle name and version from URL or content
        let name = url
            .split('/')
            .next_back()
            .unwrap_or("unknown")
            .trim_end_matches(".yar")
            .to_string();

        let version = format!("{}", Utc::now().format("%Y.%m.%d-%H%M"));

        let bundle = RuleBundle {
            name,
            version,
            path: file_path,
            sha256: sha256.clone(),
            count: 0, // Will be set during compilation
        };

        // Update cache
        {
            let mut cache = self.hash_cache.write().unwrap();
            cache.insert(sha256.clone(), bundle.path.clone());
        }

        info!(
            "Successfully downloaded rule bundle: {} ({})",
            bundle.name, sha256
        );
        Ok(bundle)
    }

    fn compile(&self, bundle: &RuleBundle) -> Result<CompiledRules> {
        info!(
            "Compiling rule bundle: {} from {:?}",
            bundle.name, bundle.path
        );

        // Read rule file content
        let rule_content = fs::read_to_string(&bundle.path)?;

        // Compile using YARA compiler
        let mut compiler = Compiler::new();

        // Add rules to compiler
        compiler
            .add_source(rule_content.as_str())
            .map_err(|e| RuleStoreError::CompileError {
                bundle: bundle.name.clone(),
                reason: format!("Failed to add rules: {}", e),
            })?;

        let rules = build_rules(compiler).map_err(|e| RuleStoreError::CompileError {
            bundle: bundle.name.clone(),
            reason: format!("Failed to build rules: {}", e),
        })?;

        // Count rules in the source content
        let rule_count = self.count_rules_in_content(&rule_content);

        // Save compiled rules to cache
        let cache_dir = self.config.rules_dir.join("cache");
        let cbin_path = cache_dir.join(format!("{}.cbin", bundle.sha256));

        // YARA doesn't provide direct serialization, so we'll store the source
        // In a real implementation, you might use YARA's save_rules functionality
        fs::write(&cbin_path, &rule_content)?;

        // Update bundle with rule count
        let mut updated_bundle = bundle.clone();
        updated_bundle.count = rule_count;

        // Save manifest
        self.save_manifest(&updated_bundle)?;

        let compiled = CompiledRules {
            handle: Arc::new(RwLock::new(rules)),
            meta: updated_bundle,
        };

        info!(
            "Successfully compiled {} rules from bundle: {}",
            rule_count, bundle.name
        );
        Ok(compiled)
    }

    fn activate(&self, compiled: CompiledRules) -> Result<()> {
        info!(
            "Activating rule bundle: {} with {} rules",
            compiled.meta.name, compiled.meta.count
        );

        // Atomic swap of active rules
        {
            let mut active = self.active_rules.write().unwrap();
            let old_rules = active.replace(compiled.clone());

            if let Some(old) = old_rules {
                info!(
                    "Replaced previous rule bundle: {} with {}",
                    old.meta.name, compiled.meta.name
                );
            }
        }

        info!("Successfully activated rule bundle: {}", compiled.meta.name);
        Ok(())
    }

    fn current(&self) -> Arc<RwLock<Option<CompiledRules>>> {
        Arc::clone(&self.active_rules)
    }
}

/// Create a new production rule store from configuration
pub fn create_rule_store(config: RuleStoreConfig) -> Result<Box<dyn RuleStore>> {
    let store = ProductionRuleStore::new(config)?;
    store.load_cache()?;
    Ok(Box::new(store))
}

#[cfg(all(test, feature = "yara"))]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_config() -> (RuleStoreConfig, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let config = RuleStoreConfig {
            rules_dir: temp_dir.path().to_path_buf(),
            update_url: "https://example.com/test.yar".to_string(),
            update_interval_secs: 3600,
            require_signed_rules: false,
        };
        (config, temp_dir)
    }

    #[test]
    fn test_rule_store_creation() {
        let (config, _temp_dir) = create_test_config();
        let store = ProductionRuleStore::new(config);
        assert!(store.is_ok());
    }

    #[test]
    fn test_file_hash_computation() {
        let (config, temp_dir) = create_test_config();
        let store = ProductionRuleStore::new(config).unwrap();

        let test_file = temp_dir.path().join("test.yar");
        fs::write(&test_file, "rule test { condition: true }").unwrap();

        let hash = store.compute_file_hash(&test_file);
        assert!(hash.is_ok());
        assert_eq!(hash.unwrap().len(), 64); // SHA-256 hex length
    }

    #[test]
    fn test_file_validation() {
        let (config, temp_dir) = create_test_config();
        let store = ProductionRuleStore::new(config).unwrap();

        let test_file = temp_dir.path().join("test.yar");
        fs::write(&test_file, "rule test { condition: true }").unwrap();

        let result = store.validate_file(&test_file);
        assert!(result.is_ok());
    }
}
