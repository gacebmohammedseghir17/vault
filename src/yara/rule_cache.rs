//! ELITE GENIUS YARA Rule Compilation Cache System
//!
//! This module provides intelligent caching for YARA rule compilation to dramatically
//! improve performance when loading thousands of rules repeatedly.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use sha2::{Digest, Sha256};

/// Cache entry for a compiled YARA rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedRuleEntry {
    /// SHA256 hash of the rule content
    pub content_hash: String,
    /// File modification time when cached
    pub cached_at: SystemTime,
    /// File size when cached
    pub file_size: u64,
    /// Compilation success status
    pub compilation_success: bool,
    /// Compilation error message (if failed)
    pub error_message: Option<String>,
    /// Compilation time in milliseconds
    pub compilation_time_ms: u64,
    /// Rule metadata
    pub metadata: RuleCacheMetadata,
}

/// Metadata for cached rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleCacheMetadata {
    pub rule_name: String,
    pub file_path: PathBuf,
    pub rule_count: usize,
    pub imports: Vec<String>,
    pub dependencies: Vec<String>,
}

/// ELITE GENIUS Rule Compilation Cache Manager
#[derive(Debug)]
pub struct YaraRuleCache {
    cache_dir: PathBuf,
    cache_file: PathBuf,
    cache_data: HashMap<PathBuf, CachedRuleEntry>,
    max_cache_age: Duration,
    max_cache_size: usize,
}

impl YaraRuleCache {
    /// Create a new rule cache manager
    pub fn new<P: AsRef<Path>>(cache_dir: P) -> Result<Self> {
        let cache_dir = cache_dir.as_ref().to_path_buf();
        let cache_file = cache_dir.join("yara_rule_cache.json");

        // Create cache directory if it doesn't exist
        if !cache_dir.exists() {
            fs::create_dir_all(&cache_dir)
                .with_context(|| format!("Failed to create cache directory: {:?}", cache_dir))?;
        }

        let mut cache = Self {
            cache_dir,
            cache_file,
            cache_data: HashMap::new(),
            max_cache_age: Duration::from_secs(7 * 24 * 3600), // Cache for 1 week
            max_cache_size: 10000, // Max 10k cached rules
        };

        // Load existing cache
        cache.load_cache()?;

        Ok(cache)
    }

    /// Check if a rule file is cached and valid
    pub fn is_cached(&self, rule_path: &Path) -> Result<bool> {
        if let Some(entry) = self.cache_data.get(rule_path) {
            // Check if file still exists and hasn't changed
            if let Ok(metadata) = fs::metadata(rule_path) {
                let current_size = metadata.len();
                let current_modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                
                // Check if cache is still valid
                let cache_age = SystemTime::now().duration_since(entry.cached_at).unwrap_or_default();
                
                return Ok(
                    current_size == entry.file_size &&
                    current_modified <= entry.cached_at &&
                    cache_age <= self.max_cache_age
                );
            }
        }
        Ok(false)
    }

    /// Get cached compilation result
    pub fn get_cached_result(&self, rule_path: &Path) -> Option<&CachedRuleEntry> {
        self.cache_data.get(rule_path)
    }

    /// Cache a compilation result
    pub fn cache_result(
        &mut self,
        rule_path: &Path,
        content: &str,
        compilation_success: bool,
        error_message: Option<String>,
        compilation_time: Duration,
        metadata: RuleCacheMetadata,
    ) -> Result<()> {
        // Calculate content hash
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        let content_hash = format!("{:x}", hasher.finalize());

        // Get file metadata
        let file_metadata = fs::metadata(rule_path)
            .with_context(|| format!("Failed to get metadata for: {:?}", rule_path))?;

        let entry = CachedRuleEntry {
            content_hash,
            cached_at: SystemTime::now(),
            file_size: file_metadata.len(),
            compilation_success,
            error_message,
            compilation_time_ms: compilation_time.as_millis() as u64,
            metadata,
        };

        self.cache_data.insert(rule_path.to_path_buf(), entry);

        // Cleanup old entries if cache is too large
        self.cleanup_cache();

        // Save cache to disk
        self.save_cache()?;

        Ok(())
    }

    /// Load cache from disk
    pub fn load_cache(&mut self) -> Result<()> {
        if self.cache_file.exists() {
            let cache_content = fs::read_to_string(&self.cache_file)
                .with_context(|| format!("Failed to read cache file: {:?}", self.cache_file))?;
            
            self.cache_data = serde_json::from_str(&cache_content)
                .with_context(|| "Failed to parse cache file")?;
            
            log::info!("🚀 Loaded {} cached rule entries", self.cache_data.len());
        }
        Ok(())
    }

    /// Save cache to disk
    pub fn save_cache(&self) -> Result<()> {
        let cache_content = serde_json::to_string_pretty(&self.cache_data)
            .with_context(|| "Failed to serialize cache data")?;
        
        fs::write(&self.cache_file, cache_content)
            .with_context(|| format!("Failed to write cache file: {:?}", self.cache_file))?;
        
        Ok(())
    }

    /// Cleanup old cache entries to maintain size limit
    fn cleanup_cache(&mut self) {
        if self.cache_data.len() <= self.max_cache_size {
            return;
        }

        // Collect paths to remove
        let mut entries: Vec<_> = self.cache_data.iter()
            .map(|(path, entry)| (path.clone(), entry.cached_at))
            .collect();
        entries.sort_by_key(|(_, cached_at)| *cached_at);

        let to_remove = self.cache_data.len() - self.max_cache_size;
        let paths_to_remove: Vec<_> = entries.iter()
            .take(to_remove)
            .map(|(path, _)| path.clone())
            .collect();

        for path in paths_to_remove {
            self.cache_data.remove(&path);
        }

        log::info!("Cleaned up {} old cache entries", to_remove);
    }

    /// Get cache statistics
    pub fn get_stats(&self) -> CacheStats {
        CacheStats {
            cache_hits: 0, // Will be tracked by rule loader
            cache_misses: 0, // Will be tracked by rule loader
            hit_rate: 0.0, // Will be calculated by rule loader
            total_cached_rules: self.cache_data.len(),
            cache_size_bytes: self.get_cache_size_bytes(),
        }
    }

    /// Get the number of cached rules
    pub fn get_cache_size(&self) -> usize {
        self.cache_data.len()
    }

    /// Get the total cache size in bytes (estimated)
    pub fn get_cache_size_bytes(&self) -> usize {
        self.cache_data.values()
            .map(|entry| {
                std::mem::size_of::<CachedRuleEntry>() +
                entry.content_hash.len() +
                entry.metadata.rule_name.len() +
                entry.metadata.file_path.to_string_lossy().len() +
                entry.metadata.imports.iter().map(|s| s.len()).sum::<usize>() +
                entry.metadata.dependencies.iter().map(|s| s.len()).sum::<usize>() +
                entry.error_message.as_ref().map_or(0, |s| s.len())
            })
            .sum()
    }

    /// Clean up old cache entries
    pub fn cleanup_old_entries(&mut self, max_age_hours: u64) -> Result<usize> {
        let cutoff_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_secs() - (max_age_hours * 3600);

        let mut to_remove = Vec::new();
        
        for (key, entry) in &self.cache_data {
            if let Ok(duration) = entry.cached_at.duration_since(SystemTime::UNIX_EPOCH) {
                if duration.as_secs() < cutoff_time {
                    to_remove.push(key.clone());
                }
            }
        }

        let removed_count = to_remove.len();
        for key in to_remove {
            self.cache_data.remove(&key);
        }

        Ok(removed_count)
    }

    /// Clear all cache entries
    pub fn clear_cache(&mut self) -> Result<()> {
        self.cache_data.clear();
        self.save_cache()?;
        log::info!("🗑️  Cleared all cache entries");
        Ok(())
    }
}

/// Cache performance statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub cache_hits: usize,
    pub cache_misses: usize,
    pub hit_rate: f64,
    pub total_cached_rules: usize,
    pub cache_size_bytes: usize,
}

impl std::fmt::Display for CacheStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Cache Stats: {} rules cached, {:.1}% hit rate ({} hits, {} misses), {} bytes",
            self.total_cached_rules,
            self.hit_rate,
            self.cache_hits,
            self.cache_misses,
            self.cache_size_bytes
        )
    }
}