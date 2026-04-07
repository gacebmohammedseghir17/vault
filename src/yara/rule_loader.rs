//! YARA Rule Loader Module
//!
//! This module handles dynamic loading, compilation, and management of YARA rules
//! with comprehensive error handling and performance monitoring.

use anyhow::{Context, Result};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use yara_x::{Compiler, Rules};
use rayon::prelude::*;
use sha2::{Digest, Sha256};

// Import our elite cache system
use super::rule_cache::{YaraRuleCache, RuleCacheMetadata, CacheStats};

/// YARA rule metadata
#[derive(Debug, Clone)]
pub struct RuleMetadata {
    pub name: String,
    pub file_path: PathBuf,
    pub last_modified: std::time::SystemTime,
    pub size: u64,
    pub compilation_time: Duration,
    pub load_count: u64,
}

/// YARA rule compilation statistics
#[derive(Debug, Clone, Default)]
pub struct CompilationStats {
    pub total_rules: usize,
    pub successful_compilations: usize,
    pub failed_compilations: usize,
    pub total_compilation_time: Duration,
    pub last_compilation: Option<Instant>,
    pub broken_files: usize,
    pub duplicate_files: usize,
}

/// ELITE GENIUS YARA rule loader with dynamic compilation, hot-reloading, and intelligent caching
pub struct YaraRuleLoader {
    /// Primary rules directory
    rules_directory: PathBuf,
    /// Additional rule directories for comprehensive coverage
    additional_rules_directories: Vec<PathBuf>,
    /// Compiled YARA rules (thread-safe)
    compiled_rules: Arc<RwLock<Option<Rules>>>,
    /// Rule metadata cache
    rule_metadata: Arc<RwLock<HashMap<String, RuleMetadata>>>,
    /// Compilation statistics
    compilation_stats: Arc<RwLock<CompilationStats>>,
    /// Auto-reload enabled
    auto_reload: bool,
    /// Last check time for auto-reload
    last_check: Arc<RwLock<Instant>>,
    /// Check interval for auto-reload
    check_interval: Duration,
    /// ELITE GENIUS: Rule compilation cache for massive performance improvement
    rule_cache: Arc<RwLock<YaraRuleCache>>,
    /// Cache hit statistics
    cache_hits: Arc<RwLock<usize>>,
    /// Cache miss statistics
    cache_misses: Arc<RwLock<usize>>,
    /// Suppress per-file broken rule warnings (aggregate summary only)
    suppress_broken_rule_warnings: bool,
    /// Aggregate broken rule errors for a single summary log
    aggregate_broken_rule_errors: bool,
    /// Suppress per-file duplicate rule warnings
    suppress_duplicate_rule_warnings: bool,
    /// Aggregate duplicate rule warnings for a single summary log
    aggregate_duplicate_rule_warnings: bool,
}

/// Manual Debug implementation for YaraRuleLoader
/// (Rules type doesn't implement Debug)
impl std::fmt::Debug for YaraRuleLoader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("YaraRuleLoader")
            .field("rules_directory", &self.rules_directory)
            .field("additional_rules_directories", &self.additional_rules_directories)
            .field("auto_reload", &self.auto_reload)
            .field("check_interval", &self.check_interval)
            .field("compiled_rules", &"<Rules>")
            .field("rule_metadata", &self.rule_metadata)
            .field("compilation_stats", &self.compilation_stats)
            .finish()
    }
}

impl YaraRuleLoader {
    /// Create a new ELITE GENIUS YARA rule loader with intelligent caching
    pub fn new<P: AsRef<Path>>(rules_directory: P, auto_reload: bool) -> Self {
        let cache_dir = rules_directory.as_ref().join(".yara_cache");
        Self {
            rules_directory: rules_directory.as_ref().to_path_buf(),
            additional_rules_directories: Vec::new(),
            compiled_rules: Arc::new(RwLock::new(None)),
            rule_metadata: Arc::new(RwLock::new(HashMap::new())),
            compilation_stats: Arc::new(RwLock::new(CompilationStats::default())),
            auto_reload,
            last_check: Arc::new(RwLock::new(Instant::now())),
            check_interval: Duration::from_secs(30), // Check for changes every 30 seconds
            rule_cache: Arc::new(RwLock::new(YaraRuleCache::new(cache_dir).unwrap_or_else(|e| {
                log::warn!("Failed to create cache: {}, using dummy cache", e);
                // Create a dummy cache that won't work but won't crash
                YaraRuleCache::new(std::env::temp_dir().join("dummy_cache")).unwrap()
            }))),
            cache_hits: Arc::new(RwLock::new(0)),
            cache_misses: Arc::new(RwLock::new(0)),
            suppress_broken_rule_warnings: true,
            aggregate_broken_rule_errors: true,
            suppress_duplicate_rule_warnings: true,
            aggregate_duplicate_rule_warnings: true,
        }
    }

    /// Create a new ELITE GENIUS YARA rule loader with multiple rule directories for comprehensive coverage
    pub fn new_with_multiple_dirs<P: AsRef<Path>>(
        primary_rules_directory: P, 
        additional_directories: Vec<P>, 
        auto_reload: bool
    ) -> Self {
        let additional_paths: Vec<PathBuf> = additional_directories
            .into_iter()
            .map(|p| p.as_ref().to_path_buf())
            .collect();

        let cache_dir = primary_rules_directory.as_ref().join(".yara_cache");
        Self {
            rules_directory: primary_rules_directory.as_ref().to_path_buf(),
            additional_rules_directories: additional_paths,
            compiled_rules: Arc::new(RwLock::new(None)),
            rule_metadata: Arc::new(RwLock::new(HashMap::new())),
            compilation_stats: Arc::new(RwLock::new(CompilationStats::default())),
            auto_reload,
            last_check: Arc::new(RwLock::new(Instant::now())),
            check_interval: Duration::from_secs(30), // Check for changes every 30 seconds
            rule_cache: Arc::new(RwLock::new(YaraRuleCache::new(cache_dir).unwrap_or_else(|e| {
                log::warn!("Failed to create cache: {}, using dummy cache", e);
                YaraRuleCache::new(std::env::temp_dir().join("dummy_cache")).unwrap()
            }))),
            cache_hits: Arc::new(RwLock::new(0)),
            cache_misses: Arc::new(RwLock::new(0)),
            suppress_broken_rule_warnings: true,
            aggregate_broken_rule_errors: true,
            suppress_duplicate_rule_warnings: true,
            aggregate_duplicate_rule_warnings: true,
        }
    }

    /// Initialize the rule loader and perform initial compilation
    pub fn initialize(&self) -> Result<()> {
        log::info!(
            "Initializing YARA rule loader from directory: {:?}",
            self.rules_directory
        );

        // Ensure rules directory exists
        if !self.rules_directory.exists() {
            fs::create_dir_all(&self.rules_directory).with_context(|| {
                format!(
                    "Failed to create rules directory: {:?}",
                    self.rules_directory
                )
            })?;
            log::warn!(
                "Created missing rules directory: {:?}",
                self.rules_directory
            );
        }

        // Perform initial rule compilation
        self.load_and_compile_rules()
            .context("Failed to perform initial rule compilation")?;

        log::info!("YARA rule loader initialized successfully");
        Ok(())
    }

    /// 🚀 ELITE GENIUS YARA rule compilation with intelligent caching and parallel processing
    pub fn load_and_compile_rules(&self) -> Result<()> {
        let start_time = Instant::now();
        log::info!("🚀 Starting ELITE GENIUS YARA rule compilation with intelligent caching...");

        // Find all .yar and .yara files in the rules directory
        let rule_files = self
            .find_rule_files()
            .context("Failed to find YARA rule files")?;

        if rule_files.is_empty() {
            log::warn!(
                "No YARA rule files found in directory: {:?}",
                self.rules_directory
            );
            return Ok(());
        }

        log::info!("🔍 Found {} YARA rule files for processing", rule_files.len());

        // Initialize cache system
        {
            let mut cache = self.rule_cache.write().unwrap();
            if let Err(e) = cache.load_cache() {
                log::warn!("Failed to load rule cache: {}, starting fresh", e);
            }
        }

        let mut stats = CompilationStats {
            total_rules: rule_files.len(),
            ..Default::default()
        };

        // 🧠 GENIUS PARALLEL PROCESSING: Process rules in parallel batches
        let cpu_count = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
        let batch_size = std::cmp::max(1, rule_files.len() / cpu_count);
        log::info!("⚡ Using parallel processing with {} CPU cores, batch size: {}", cpu_count, batch_size);

        // Collect broken rule errors for optional aggregated summary
        let broken_errors: Arc<RwLock<Vec<(PathBuf, String)>>> = Arc::new(RwLock::new(Vec::new()));

        let successful_rules: Vec<(String, RuleMetadata)> = rule_files
            .par_chunks(batch_size)
            .flat_map(|chunk| {
                chunk.par_iter().filter_map(|rule_file| {
                    // Check cache first for MASSIVE performance boost
                    if let Ok(cache) = self.rule_cache.read() {
                        if let Ok(is_cached) = cache.is_cached(rule_file) {
                            if is_cached {
                                if let Some(cached_entry) = cache.get_cached_result(rule_file) {
                                    if cached_entry.compilation_success {
                                        // CACHE HIT! 🎯
                                        {
                                            let mut hits = self.cache_hits.write().unwrap();
                                            *hits += 1;
                                        }
                                        log::debug!("💾 Cache HIT for rule: {:?}", rule_file);
                                        
                                        // Convert cached metadata to RuleMetadata
                                        let metadata = RuleMetadata {
                                            name: cached_entry.metadata.rule_name.clone(),
                                            file_path: cached_entry.metadata.file_path.clone(),
                                            last_modified: cached_entry.cached_at,
                                            size: cached_entry.file_size,
                                            compilation_time: Duration::from_millis(cached_entry.compilation_time_ms),
                                            load_count: 1,
                                        };
                                        
                                        // For cached entries, we need to read the content again
                                        if let Ok(content) = fs::read_to_string(rule_file) {
                                            return Some((content, metadata));
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Prevalidate before expensive compilation
                    match Self::prevalidate_rule_file(rule_file) {
                        Ok(true) => { /* proceed */ }
                        Ok(false) => {
                            // Prevalidation skip: record and optionally suppress logs
                            if self.aggregate_broken_rule_errors {
                                let mut errs = broken_errors.write().unwrap();
                                errs.push((rule_file.to_path_buf(), "Prevalidation failed".to_string()));
                            }
                            if !self.suppress_broken_rule_warnings {
                                log::warn!("⚠️  Skipping prevalidation-failed rule {:?}", rule_file);
                            } else {
                                log::debug!("Skipping prevalidation-failed rule {:?}", rule_file);
                            }
                            return None;
                        }
                        Err(e) => {
                            if self.aggregate_broken_rule_errors {
                                let mut errs = broken_errors.write().unwrap();
                                errs.push((rule_file.to_path_buf(), format!("Prevalidation error: {}", e)));
                            }
                            if !self.suppress_broken_rule_warnings {
                                log::warn!("⚠️  Skipping rule {:?}: {}", rule_file, e);
                            } else {
                                log::debug!("Skipping rule {:?}: {}", rule_file, e);
                            }
                            // Always emit a detailed debug record with file path and reason
                            log::debug!("Rule prevalidation failed for {:?}: {}", rule_file, e);
                            {
                                let mut cs = self.compilation_stats.write().unwrap();
                                cs.broken_files += 1;
                            }
                            return None;
                        }
                    }

                    // Cache miss - compile the rule
                    {
                        let mut misses = self.cache_misses.write().unwrap();
                        *misses += 1;
                    }

                    match self.compile_single_rule_isolated(rule_file) {
                        Ok((content, metadata)) => {
                            // Cache the successful compilation
                            if let Ok(mut cache) = self.rule_cache.write() {
                                let cache_metadata = RuleCacheMetadata {
                                    rule_name: metadata.name.clone(),
                                    file_path: metadata.file_path.clone(),
                                    rule_count: 1,
                                    imports: Vec::new(),
                                    dependencies: Vec::new(),
                                };
                                
                                if let Err(e) = cache.cache_result(
                                    rule_file,
                                    &content,
                                    true,
                                    None,
                                    metadata.compilation_time,
                                    cache_metadata
                                ) {
                                    log::warn!("Failed to cache rule {:?}: {}", rule_file, e);
                                }
                            }

                            log::debug!("✅ Successfully compiled rule: {:?}", rule_file);
                            Some((content, metadata))
                        }
                        Err(e) => {
                            // Cache the failed compilation too
                            if let Ok(mut cache) = self.rule_cache.write() {
                                let cache_metadata = RuleCacheMetadata {
                                    rule_name: rule_file.file_stem()
                                        .and_then(|s| s.to_str())
                                        .unwrap_or("unknown")
                                        .to_string(),
                                    file_path: rule_file.to_path_buf(),
                                    rule_count: 0,
                                    imports: Vec::new(),
                                    dependencies: Vec::new(),
                                };
                                
                                let _ = cache.cache_result(
                                    rule_file,
                                    "",
                                    false,
                                    Some(e.to_string()),
                                    Duration::from_millis(0),
                                    cache_metadata
                                );
                            }
                            
                            if self.aggregate_broken_rule_errors {
                                let mut errs = broken_errors.write().unwrap();
                                errs.push((rule_file.to_path_buf(), e.to_string()));
                            }
                            if !self.suppress_broken_rule_warnings {
                                log::warn!("⚠️  Skipping broken rule {:?}: {}", rule_file, e);
                            } else {
                                log::debug!("Skipping broken rule {:?}: {}", rule_file, e);
                            }
                            None
                        }
                    }
                })
            })
            .collect();

        stats.successful_compilations = successful_rules.len();
        stats.failed_compilations = rule_files.len() - successful_rules.len();

        log::info!("🎯 Parallel compilation results: {} successful, {} failed", 
                  stats.successful_compilations, stats.failed_compilations);

        // Create final compiler with only successful and de-duplicated rules
        let mut final_compiler = Compiler::new();
        let mut metadata_map = HashMap::new();
        let mut seen_rule_names: HashSet<String> = HashSet::new();
        let mut seen_content_hashes: HashSet<String> = HashSet::new();
        let duplicate_warnings: Arc<RwLock<Vec<(PathBuf, Vec<String>)>>> = Arc::new(RwLock::new(Vec::new()));

        // Lightweight YARA rule name extraction
        fn extract_rule_names(content: &str) -> Vec<String> {
            let mut names = Vec::new();
            for line in content.lines() {
                let l = line.trim();
                // Quickly filter lines that can declare rules
                if !(l.starts_with("rule ") || l.starts_with("private rule ") || l.starts_with("global rule ")) {
                    continue;
                }
                // Tokenize and find the token immediately after 'rule'
                let mut tokens = l.split_whitespace();
                let first = tokens.next();
                let second = tokens.next();
                let after_rule = if let Some(f) = first {
                    if f == "rule" {
                        // pattern: rule <name> ...
                        second
                    } else if f == "private" || f == "global" {
                        // pattern: private rule <name> ... OR global rule <name> ...
                        let maybe_rule = second;
                        if let Some(mr) = maybe_rule {
                            if mr == "rule" {
                                tokens.next()
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else { None };

                if let Some(raw_name) = after_rule {
                    // Extract identifier characters (letters, digits, underscore)
                    let mut ident = String::new();
                    for ch in raw_name.chars() {
                        if ch.is_ascii_alphanumeric() || ch == '_' { ident.push(ch); } else { break; }
                    }
                    if !ident.is_empty() { names.push(ident); }
                }
            }
            names
        }

        for (content, metadata) in successful_rules {
            let names = extract_rule_names(&content);
            let mut conflicts: Vec<String> = Vec::new();
            for n in &names {
                if seen_rule_names.contains(n) {
                    conflicts.push(n.clone());
                }
            }

                if !conflicts.is_empty() {
                    // Skip adding this file to avoid duplicate declaration errors
                    if self.aggregate_duplicate_rule_warnings {
                        let mut dups = duplicate_warnings.write().unwrap();
                        dups.push((metadata.file_path.clone(), conflicts.clone()));
                    }
                if !self.suppress_duplicate_rule_warnings {
                    log::warn!(
                        "Skipping rule file {:?} due to duplicate rule names: {:?}",
                        &metadata.file_path,
                        conflicts
                    );
                } else {
                    log::debug!(
                        "Skipping rule file {:?} due to duplicate rule names: {:?}",
                        &metadata.file_path,
                        conflicts
                    );
                }
                stats.failed_compilations += 1;
                stats.duplicate_files += 1;
                stats.successful_compilations -= 1;
                continue;
            }

            // Deduplicate by content hash first
            let mut hasher = Sha256::new();
            hasher.update(content.as_bytes());
            let content_hash = format!("{:x}", hasher.finalize());

            if seen_content_hashes.contains(&content_hash) {
                log::debug!(
                    "Skipping duplicate rule file by content hash: {:?}",
                    &metadata.file_path
                );
                stats.failed_compilations += 0; // do not count as failure
                continue;
            }
            seen_content_hashes.insert(content_hash);

            // Add successful rule content to final compiler
            if let Err(e) = final_compiler.add_source(content.as_str()) {
                log::error!("Failed to add validated rule to final compiler (file {:?}): {}", &metadata.file_path, e);
                log::debug!("Rule file {:?} failed to add to final compiler: {}", &metadata.file_path, e);
                stats.failed_compilations += 1;
                stats.successful_compilations -= 1;
            } else {
                // Track rule names to prevent future duplicates
                for n in names { seen_rule_names.insert(n); }
                metadata_map.insert(metadata.name.clone(), metadata);
            }
        }

        // Build final rules with only working rules
        let rules = final_compiler.build();

        let compilation_time = start_time.elapsed();
        stats.total_compilation_time = compilation_time;
        stats.last_compilation = Some(Instant::now());

        // Save cache for future use
        {
            let cache = self.rule_cache.read().unwrap();
            if let Err(e) = cache.save_cache() {
                log::warn!("Failed to save rule cache: {}", e);
            }
        }

        // Clone stats for logging before moving
        let successful_compilations = stats.successful_compilations;
        let failed_compilations = stats.failed_compilations;

        // Update shared state
        {
            let mut compiled_rules = self.compiled_rules.write().unwrap();
            *compiled_rules = Some(rules);
        }

        {
            let mut rule_metadata = self.rule_metadata.write().unwrap();
            *rule_metadata = metadata_map;
        }

        {
            let mut compilation_stats = self.compilation_stats.write().unwrap();
            *compilation_stats = stats;
        }

        // Report cache performance
        let cache_hits = *self.cache_hits.read().unwrap();
        let cache_misses = *self.cache_misses.read().unwrap();
        let cache_hit_rate = if cache_hits + cache_misses > 0 {
            (cache_hits as f64 / (cache_hits + cache_misses) as f64) * 100.0
        } else {
            0.0
        };

        log::info!(
            "🚀 ELITE GENIUS YARA compilation completed! {} successful, {} failed, took {:?}",
            successful_compilations,
            failed_compilations,
            compilation_time
        );

        // Optional aggregated summary for broken rules
        if self.aggregate_broken_rule_errors {
            let errs = broken_errors.read().unwrap();
            if !errs.is_empty() {
                if self.suppress_broken_rule_warnings {
                    // Only a single summary line to keep logs clean
                    log::info!(
                        "Skipped {} broken/prevalidated rules (warnings suppressed)",
                        errs.len()
                    );
                } else {
                    // Detailed summary
                    log::warn!("Broken rule summary ({} items):", errs.len());
                    for (path, msg) in errs.iter().take(25) { // limit volume
                        log::warn!(" - {:?}: {}", path, msg);
                    }
                    if errs.len() > 25 {
                        log::warn!(" ... and {} more", errs.len() - 25);
                    }
                }
                // Provide a debug-level detailed list of offending files and reasons (limited)
                for (path, msg) in errs.iter().take(25) {
                    log::debug!("Broken rule detail: {:?} => {}", path, msg);
                }
                if errs.len() > 25 {
                    log::debug!("Broken rule details truncated: {} more items", errs.len() - 25);
                }
            }
        }

        // Optional aggregated summary for duplicate warnings
        if self.aggregate_duplicate_rule_warnings {
            let dups = duplicate_warnings.read().unwrap();
            if !dups.is_empty() {
                if self.suppress_duplicate_rule_warnings {
                    log::info!(
                        "Skipped {} duplicate rule files (warnings suppressed)",
                        dups.len()
                    );
                } else {
                    log::warn!("Duplicate rule summary ({} items):", dups.len());
                    for (path, names) in dups.iter().take(25) { // limit volume
                        log::warn!(" - {:?}: {:?}", path, names);
                    }
                    if dups.len() > 25 {
                        log::warn!(" ... and {} more", dups.len() - 25);
                    }
                }
                // Provide debug-level details for duplicates (limited)
                for (path, names) in dups.iter().take(25) {
                    log::debug!("Duplicate rule detail: {:?} => {:?}", path, names);
                }
                if dups.len() > 25 {
                    log::debug!("Duplicate rule details truncated: {} more items", dups.len() - 25);
                }
            }
        }

        log::info!(
            "💾 Cache performance: {:.1}% hit rate ({} hits, {} misses)",
            cache_hit_rate, cache_hits, cache_misses
        );

        Ok(())
    }

    /// Lightweight prevalidation to quickly skip obviously broken rule files
    fn prevalidate_rule_file(rule_file: &Path) -> Result<bool> {
        // Read as UTF-8 text; reject non-UTF files early
        let content = match fs::read_to_string(rule_file) {
            Ok(c) => c,
            Err(e) => {
                // Not readable as text
                return Err(anyhow::anyhow!("Failed to read rule file: {}", e));
            }
        };

        let trimmed = content.trim();
        if trimmed.is_empty() {
            // Empty file
            return Ok(false);
        }

        // Must contain at least one 'rule' and 'condition' token
        let has_rule = trimmed.contains("rule ") || trimmed.contains("\nrule ");
        let has_condition = trimmed.contains("condition:") || trimmed.contains("\ncondition:");
        if !has_rule || !has_condition {
            return Ok(false);
        }

        // Basic brace balance check (cheap heuristic)
        let open_braces = content.matches('{').count();
        let close_braces = content.matches('}').count();
        if open_braces != close_braces {
            return Ok(false);
        }

        // Passes basic checks
        Ok(true)
    }

    /// Get a reference to the compiled YARA rules (thread-safe)
    pub fn get_rules(&self) -> Arc<RwLock<Option<Rules>>> {
        // Check if auto-reload is enabled and rules need to be reloaded
        if self.auto_reload {
            if let Err(e) = self.check_and_reload_if_needed() {
                log::error!("Failed to check for rule updates: {}", e);
            }
        }

        Arc::clone(&self.compiled_rules)
    }

    /// Check if rules are loaded
    pub fn is_loaded(&self) -> bool {
        self.compiled_rules.read().unwrap().is_some()
    }

    /// Check if rules need to be reloaded and reload if necessary
    pub fn check_and_reload_if_needed(&self) -> Result<bool> {
        let now = Instant::now();

        // Check if enough time has passed since last check
        {
            let last_check = self.last_check.read().unwrap();
            if now.duration_since(*last_check) < self.check_interval {
                return Ok(false);
            }
        }

        // Update last check time
        {
            let mut last_check = self.last_check.write().unwrap();
            *last_check = now;
        }

        // Check if any rule files have been modified
        let rule_files = self
            .find_rule_files()
            .context("Failed to find YARA rule files")?;

        let metadata = self.rule_metadata.read().unwrap();

        for rule_file in &rule_files {
            let file_name = rule_file
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown")
                .to_string();

            if let Ok(file_metadata) = fs::metadata(rule_file) {
                if let Ok(modified_time) = file_metadata.modified() {
                    if let Some(existing_metadata) = metadata.get(&file_name) {
                        if modified_time > existing_metadata.last_modified {
                            log::info!("Detected changes in rule file: {:?}", rule_file);
                            drop(metadata); // Release the read lock
                            return self.reload_rules();
                        }
                    } else {
                        // New rule file detected
                        log::info!("Detected new rule file: {:?}", rule_file);
                        drop(metadata); // Release the read lock
                        return self.reload_rules();
                    }
                }
            }
        }

        Ok(false)
    }

    /// Force reload all rules
    pub fn reload_rules(&self) -> Result<bool> {
        log::info!("Reloading YARA rules...");

        self.load_and_compile_rules()
            .context("Failed to reload YARA rules")?;

        Ok(true)
    }

    /// Get compilation statistics
    pub fn get_compilation_stats(&self) -> CompilationStats {
        let stats = self.compilation_stats.read().unwrap();
        stats.clone()
    }

    /// Clean up broken and duplicate rule files from rule directories
    pub fn cleanup_broken_and_duplicates(&self) -> Result<(usize, usize)> {
        let mut broken = 0usize;
        let mut duplicates = 0usize;
        let mut names_seen: HashSet<String> = HashSet::new();
        let files = self.find_rule_files()?;
        for path in files {
            match Self::prevalidate_rule_file(&path) {
                Ok(true) => {
                    let content = std::fs::read_to_string(&path).unwrap_or_default();
                    let mut names = Vec::new();
                    for line in content.lines() {
                        let l = line.trim();
                        if !(l.starts_with("rule ") || l.starts_with("private rule ") || l.starts_with("global rule ")) { continue; }
                        let mut tokens = l.split_whitespace();
                        let first = tokens.next();
                        let second = tokens.next();
                        let after_rule = if let Some(f) = first {
                            if f == "rule" { second } else if f == "private" || f == "global" { let maybe_rule = second; if let Some(mr) = maybe_rule { if mr == "rule" { tokens.next() } else { None } } else { None } } else { None }
                        } else { None };
                        if let Some(raw_name) = after_rule {
                            let mut ident = String::new();
                            for ch in raw_name.chars() { if ch.is_ascii_alphanumeric() || ch == '_' { ident.push(ch) } else { break; } }
                            if !ident.is_empty() { names.push(ident); }
                        }
                    }
                    let mut is_duplicate = false;
                    for n in &names { if names_seen.contains(n) { is_duplicate = true; break; } }
                    if is_duplicate {
                        if let Err(e) = std::fs::remove_file(&path) { log::warn!("Failed to delete duplicate rule {:?}: {}", &path, e); } else { duplicates += 1; }
                    } else {
                        for n in names { names_seen.insert(n); }
                    }
                }
                Ok(false) => {
                    if let Err(e) = std::fs::remove_file(&path) { log::warn!("Failed to delete broken rule {:?}: {}", &path, e); } else { broken += 1; }
                }
                Err(_) => {
                    if let Err(e) = std::fs::remove_file(&path) { log::warn!("Failed to delete invalid rule {:?}: {}", &path, e); } else { broken += 1; }
                }
            }
        }
        Ok((broken, duplicates))
    }

    /// Get rule metadata
    pub fn get_rule_metadata(&self) -> HashMap<String, RuleMetadata> {
        let metadata = self.rule_metadata.read().unwrap();
        metadata.clone()
    }

    /// Find all YARA rule files in the rules directory
    fn find_rule_files(&self) -> Result<Vec<PathBuf>> {
        let mut rule_files = Vec::new();
        let mut scanned_directories = 0;

        // Scan primary rules directory
        if self.rules_directory.exists() {
            log::info!("Scanning primary rules directory: {:?}", self.rules_directory);
            self.find_rule_files_recursive(&self.rules_directory, &mut rule_files)?;
            scanned_directories += 1;
        } else {
            log::warn!("Primary rules directory does not exist: {:?}", self.rules_directory);
        }

        // Scan additional rules directories for comprehensive coverage
        for additional_dir in &self.additional_rules_directories {
            if additional_dir.exists() {
                log::info!("Scanning additional rules directory: {:?}", additional_dir);
                self.find_rule_files_recursive(additional_dir, &mut rule_files)?;
                scanned_directories += 1;
            } else {
                log::warn!("Additional rules directory does not exist: {:?}", additional_dir);
            }
        }

        // Sort files for consistent ordering
        rule_files.sort();

        log::info!(
            "Found {} YARA rule files from {} directories (comprehensive rule loading enabled)", 
            rule_files.len(), 
            scanned_directories
        );

        Ok(rule_files)
    }

    /// Recursively find all YARA rule files in directory and subdirectories
    fn find_rule_files_recursive(&self, dir: &Path, rule_files: &mut Vec<PathBuf>) -> Result<()> {
        let entries = fs::read_dir(dir).with_context(|| {
            format!("Failed to read directory: {:?}", dir)
        })?;

        for entry in entries {
            let entry = entry.context("Failed to read directory entry")?;
            let path = entry.path();

            if path.is_file() {
                if let Some(extension) = path.extension() {
                    if extension == "yar" || extension == "yara" {
                        rule_files.push(path);
                    }
                }
            } else if path.is_dir() {
                // Skip certain directories that might cause issues
                if let Some(dir_name) = path.file_name().and_then(|n| n.to_str()) {
                    // Skip hidden directories, cache directories, and git directories
                    if !dir_name.starts_with('.') && 
                       dir_name != "cache" && 
                       dir_name != "temp" &&
                       dir_name != "tmp" {
                        // Recursively scan subdirectory
                        if let Err(e) = self.find_rule_files_recursive(&path, rule_files) {
                            log::warn!("Failed to scan subdirectory {:?}: {}", path, e);
                            // Continue with other directories instead of failing completely
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// ELITE GENIUS METHOD: Compile a single YARA rule file in isolation
    fn compile_single_rule_isolated(&self, rule_file: &Path) -> Result<(String, RuleMetadata)> {
        let start_time = Instant::now();

        // Read rule file content
        let content = fs::read_to_string(rule_file)
            .with_context(|| format!("Failed to read rule file: {:?}", rule_file))?;

        // Get file metadata
        let file_metadata = fs::metadata(rule_file)
            .with_context(|| format!("Failed to get metadata for rule file: {:?}", rule_file))?;

        let last_modified = file_metadata
            .modified()
            .context("Failed to get file modification time")?;

        let size = file_metadata.len();

        // Test compilation in isolation to validate rule
        let mut test_compiler = Compiler::new();
        test_compiler
            .add_source(content.as_str())
            .with_context(|| format!("Failed to validate rule in isolation: {:?}", rule_file))?;
        
        // If we get here, the rule is valid - build it to ensure it compiles
        let _test_rules = test_compiler.build();

        let file_name = rule_file
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();

        let compilation_time = start_time.elapsed();

        let metadata = RuleMetadata {
            name: file_name,
            file_path: rule_file.to_path_buf(),
            last_modified,
            size,
            compilation_time,
            load_count: 1,
        };

        Ok((content, metadata))
    }

    /// Legacy compile method (kept for compatibility)
    fn compile_single_rule(
        &self,
        compiler: &mut Compiler,
        rule_file: &Path,
    ) -> Result<RuleMetadata> {
        let start_time = Instant::now();

        // Read rule file content
        let content = fs::read_to_string(rule_file)
            .with_context(|| format!("Failed to read rule file: {:?}", rule_file))?;

        // Get file metadata
        let file_metadata = fs::metadata(rule_file)
            .with_context(|| format!("Failed to get metadata for rule file: {:?}", rule_file))?;

        let last_modified = file_metadata
            .modified()
            .context("Failed to get file modification time")?;

        let size = file_metadata.len();

        // Add rule to compiler
        let file_name = rule_file
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();

        // Add rule to compiler using add_source
        compiler
            .add_source(content.as_str())
            .with_context(|| format!("Failed to add rule to compiler: {:?}", rule_file))?;

        let compilation_time = start_time.elapsed();

        Ok(RuleMetadata {
            name: file_name,
            file_path: rule_file.to_path_buf(),
            last_modified,
            size,
            compilation_time,
            load_count: 1,
        })
    }

    /// Set the check interval for auto-reload
    pub fn set_check_interval(&mut self, interval: Duration) {
        self.check_interval = interval;
    }

    /// Enable or disable auto-reload
    pub fn set_auto_reload(&mut self, enabled: bool) {
        self.auto_reload = enabled;
    }

    /// Configure broken rule warning suppression
    pub fn set_suppress_broken_rule_warnings(&mut self, suppress: bool) {
        self.suppress_broken_rule_warnings = suppress;
    }

    /// Configure aggregated broken rule error summary behavior
    pub fn set_aggregate_broken_rule_errors(&mut self, aggregate: bool) {
        self.aggregate_broken_rule_errors = aggregate;
    }

    /// Configure duplicate rule warning suppression
    pub fn set_suppress_duplicate_rule_warnings(&mut self, suppress: bool) {
        self.suppress_duplicate_rule_warnings = suppress;
    }

    /// Configure aggregated duplicate rule warning summary behavior
    pub fn set_aggregate_duplicate_rule_warnings(&mut self, aggregate: bool) {
        self.aggregate_duplicate_rule_warnings = aggregate;
    }

    /// Get the number of loaded rules
    pub fn rule_count(&self) -> usize {
        let metadata = self.rule_metadata.read().unwrap();
        metadata.len()
    }

    /// Check if rules are loaded and ready
    pub fn is_ready(&self) -> bool {
        let compiled_rules = self.compiled_rules.read().unwrap();
        compiled_rules.is_some()
    }

    /// 💾 Get cache performance statistics
    pub fn get_cache_stats(&self) -> CacheStats {
        let cache_hits = *self.cache_hits.read().unwrap();
        let cache_misses = *self.cache_misses.read().unwrap();
        let total_requests = cache_hits + cache_misses;
        let hit_rate = if total_requests > 0 {
            (cache_hits as f64 / total_requests as f64) * 100.0
        } else {
            0.0
        };

        CacheStats {
            cache_hits,
            cache_misses,
            hit_rate,
            total_cached_rules: {
                let cache = self.rule_cache.read().unwrap();
                cache.get_cache_size()
            },
            cache_size_bytes: {
                let cache = self.rule_cache.read().unwrap();
                cache.get_cache_size_bytes()
            },
        }
    }

    /// 🧹 Clean up old cache entries
    pub fn cleanup_cache(&self, max_age_hours: u64) -> Result<usize> {
        let mut cache = self.rule_cache.write().unwrap();
        cache.cleanup_old_entries(max_age_hours)
    }

    /// 🔄 Clear all cache entries
    pub fn clear_cache(&self) -> Result<()> {
        let mut cache = self.rule_cache.write().unwrap();
        cache.clear_cache()
    }
}

/// Create a default YARA rule loader instance
pub fn create_rule_loader(rules_path: &str, auto_reload: bool) -> Result<YaraRuleLoader> {
    let loader = YaraRuleLoader::new(rules_path, auto_reload);
    loader
        .initialize()
        .context("Failed to initialize YARA rule loader")?;
    Ok(loader)
}

/// Create a comprehensive YARA rule loader with multiple rule directories for maximum coverage
pub fn create_comprehensive_rule_loader(
    primary_rules_path: &str, 
    additional_rules_paths: &[String], 
    auto_reload: bool
) -> Result<YaraRuleLoader> {
    let additional_paths: Vec<&str> = additional_rules_paths.iter().map(|s| s.as_str()).collect();
    let loader = YaraRuleLoader::new_with_multiple_dirs(primary_rules_path, additional_paths, auto_reload);
    loader
        .initialize()
        .context("Failed to initialize comprehensive YARA rule loader")?;
    Ok(loader)
}

/// Create sample YARA rules for testing if rules directory is empty
pub fn create_sample_rules(rules_directory: &Path) -> Result<()> {
    if !rules_directory.exists() {
        fs::create_dir_all(rules_directory).context("Failed to create rules directory")?;
    }

    // Check if directory is empty
    let entries: Vec<_> = fs::read_dir(rules_directory)
        .context("Failed to read rules directory")?
        .collect();

    if !entries.is_empty() {
        return Ok(()); // Directory is not empty, don't create sample rules
    }

    log::info!(
        "Creating sample YARA rules in empty directory: {:?}",
        rules_directory
    );

    // Sample ransomware detection rule
    let ransomware_rule = r#"
rule Ransomware_Behavior_Detection
{
    meta:
        description = "Detects potential ransomware behavior patterns"
        author = "RANSolution"
        date = "2024-01-01"
        severity = "high"
        
    strings:
        $encrypt1 = "CryptEncrypt" nocase
        $encrypt2 = "CryptGenKey" nocase
        $encrypt3 = "CryptCreateHash" nocase
        $file_ext1 = ".encrypted" nocase
        $file_ext2 = ".locked" nocase
        $file_ext3 = ".crypto" nocase
        $ransom_note1 = "your files have been encrypted" nocase
        $ransom_note2 = "pay the ransom" nocase
        $ransom_note3 = "bitcoin" nocase
        
    condition:
        (2 of ($encrypt*)) or (1 of ($file_ext*)) or (2 of ($ransom_note*))
}
"#;

    // Sample suspicious process rule
    let suspicious_process_rule = r#"
rule Suspicious_Process_Behavior
{
    meta:
        description = "Detects suspicious process behavior"
        author = "RANSolution"
        date = "2024-01-01"
        severity = "medium"
        
    strings:
        $cmd1 = "vssadmin delete shadows" nocase
        $cmd2 = "wbadmin delete catalog" nocase
        $cmd3 = "bcdedit /set {default} recoveryenabled no" nocase
        $cmd4 = "schtasks /create" nocase
        $reg1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        
    condition:
        any of ($cmd*) or $reg1
}
"#;

    // Write sample rules to files
    let ransomware_file = rules_directory.join("ransomware_detection.yar");
    fs::write(&ransomware_file, ransomware_rule)
        .context("Failed to write ransomware detection rule")?;

    let suspicious_file = rules_directory.join("suspicious_process.yar");
    fs::write(&suspicious_file, suspicious_process_rule)
        .context("Failed to write suspicious process rule")?;

    log::info!(
        "Created sample YARA rules: {:?}, {:?}",
        ransomware_file,
        suspicious_file
    );

    Ok(())
}
