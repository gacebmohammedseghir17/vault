//! YARA Engine for file scanning with chunked reading and comprehensive error handling
//!
//! This module provides a production-ready YARA scanning engine that:
//! - Scans files with configurable memory chunks for efficiency
//! - Handles inaccessible/locked files gracefully
//! - Integrates with YaraRuleManager for rule compilation and matching
//! - Returns structured, JSON-compatible results
//! - Provides comprehensive error handling and logging

use std::collections::HashMap;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use memmap2::MmapOptions;
#[cfg(windows)]
use memmap2::MmapOptions;

use lru::LruCache;
use sha2::{Digest, Sha256};
use std::num::NonZeroUsize;
use std::sync::Mutex;

use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use log::{debug, error, info, warn};
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use tokio::fs;
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;
use tokio::time::{sleep, Instant};

use crate::config::AgentConfig;
use crate::detection::yara_events::{helpers, YaraDetectionEvent};
use yara_x::{MetaValue, Scanner};
// Removed unused imports
use crate::error::yara_errors::{FileSystemErrorKind, ScanErrorKind, YaraError};

#[cfg(target_os = "windows")]
use scopeguard;

/// Rule hit tracking for dynamic anomaly scoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleHitRecord {
    pub rule_name: String,
    pub hit_count: u64,
    pub first_seen: SystemTime,
    pub last_seen: SystemTime,
    pub target_type: String, // "file" or "process"
    pub target_path: String,
}

/// Rule hit delta computation for anomaly detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleHitDelta {
    pub rule_name: String,
    pub current_hits: u64,
    pub previous_hits: u64,
    pub delta: i64,
    pub delta_percentage: f64,
    pub time_window_seconds: u64,
    pub anomaly_score: f64, // 0.0 to 1.0, higher = more anomalous
}

/// Time-windowed rule hit tracker
#[derive(Debug)]
struct RuleHitTracker {
    /// Current time window hits
    current_window: HashMap<String, RuleHitRecord>,
    /// Previous time window hits for delta computation
    previous_window: HashMap<String, RuleHitRecord>,
    /// Window duration in seconds
    window_duration: Duration,
    /// Last window rotation time
    last_rotation: SystemTime,
    /// Historical baseline for anomaly detection
    baseline_hits: HashMap<String, f64>, // Average hits per window
    /// Standard deviation for each rule
    hit_std_dev: HashMap<String, f64>,
}

impl RuleHitTracker {
    /// Create a new rule hit tracker with specified window duration
    fn new(window_duration_seconds: u64) -> Self {
        Self {
            current_window: HashMap::new(),
            previous_window: HashMap::new(),
            window_duration: Duration::from_secs(window_duration_seconds),
            last_rotation: SystemTime::now(),
            baseline_hits: HashMap::new(),
            hit_std_dev: HashMap::new(),
        }
    }

    /// Record a rule hit
    fn record_hit(&mut self, rule_name: &str, target_type: &str, target_path: &str) {
        self.check_window_rotation();

        let now = SystemTime::now();
        let entry = self
            .current_window
            .entry(rule_name.to_string())
            .or_insert_with(|| RuleHitRecord {
                rule_name: rule_name.to_string(),
                hit_count: 0,
                first_seen: now,
                last_seen: now,
                target_type: target_type.to_string(),
                target_path: target_path.to_string(),
            });

        entry.hit_count += 1;
        entry.last_seen = now;
    }

    /// Check if window should rotate and perform rotation if needed
    fn check_window_rotation(&mut self) {
        let now = SystemTime::now();
        if now.duration_since(self.last_rotation).unwrap_or_default() >= self.window_duration {
            self.rotate_window();
        }
    }

    /// Rotate the time window
    fn rotate_window(&mut self) {
        // Update baselines before rotation
        self.update_baselines();

        // Move current to previous
        self.previous_window = self.current_window.clone();
        self.current_window.clear();
        self.last_rotation = SystemTime::now();

        debug!("Rule hit tracker window rotated");
    }

    /// Update baseline statistics for anomaly detection
    fn update_baselines(&mut self) {
        for (rule_name, record) in &self.current_window {
            // Simple exponential moving average for baseline
            let current_hits = record.hit_count as f64;
            let alpha = 0.1; // Smoothing factor

            let baseline = self
                .baseline_hits
                .entry(rule_name.clone())
                .or_insert(current_hits);
            *baseline = alpha * current_hits + (1.0 - alpha) * *baseline;

            // Update standard deviation (simplified)
            let variance = (current_hits - *baseline).powi(2);
            let std_dev = self.hit_std_dev.entry(rule_name.clone()).or_insert(1.0);
            *std_dev = alpha * variance.sqrt() + (1.0 - alpha) * *std_dev;
        }
    }

    /// Compute rule hit deltas for anomaly detection
    fn compute_deltas(&self) -> Vec<RuleHitDelta> {
        let mut deltas = Vec::new();
        let window_seconds = self.window_duration.as_secs();

        // Get all unique rule names from both windows
        let mut all_rules = std::collections::HashSet::new();
        all_rules.extend(self.current_window.keys());
        all_rules.extend(self.previous_window.keys());

        for rule_name in all_rules {
            let current_hits = self
                .current_window
                .get(rule_name)
                .map(|r| r.hit_count)
                .unwrap_or(0);
            let previous_hits = self
                .previous_window
                .get(rule_name)
                .map(|r| r.hit_count)
                .unwrap_or(0);

            let delta = current_hits as i64 - previous_hits as i64;
            let delta_percentage = if previous_hits > 0 {
                (delta as f64 / previous_hits as f64) * 100.0
            } else if current_hits > 0 {
                100.0 // New rule appearing
            } else {
                0.0
            };

            // Calculate anomaly score based on deviation from baseline
            let anomaly_score = self.calculate_anomaly_score(rule_name, current_hits as f64);

            deltas.push(RuleHitDelta {
                rule_name: rule_name.clone(),
                current_hits,
                previous_hits,
                delta,
                delta_percentage,
                time_window_seconds: window_seconds,
                anomaly_score,
            });
        }

        deltas
    }

    /// Calculate anomaly score for a rule based on current hits vs baseline
    fn calculate_anomaly_score(&self, rule_name: &str, current_hits: f64) -> f64 {
        if let (Some(&baseline), Some(&std_dev)) = (
            self.baseline_hits.get(rule_name),
            self.hit_std_dev.get(rule_name),
        ) {
            if std_dev > 0.0 {
                // Z-score based anomaly detection
                let z_score = (current_hits - baseline).abs() / std_dev;
                // Convert to 0-1 scale using sigmoid function
                1.0 / (1.0 + (-z_score / 2.0).exp())
            } else {
                0.0
            }
        } else {
            // No baseline yet, consider moderate anomaly for new rules
            if current_hits > 0.0 {
                0.5
            } else {
                0.0
            }
        }
    }

    /// Get current window statistics
    fn get_current_stats(&self) -> HashMap<String, u64> {
        self.current_window
            .iter()
            .map(|(name, record)| (name.clone(), record.hit_count))
            .collect()
    }
}

/// YARA Engine specific error types
#[derive(Debug, thiserror::Error)]
pub enum YaraEngineError {
    #[error("Process access error: {0}")]
    ProcessAccess(String),

    #[error("File access error: {0}")]
    FileAccess(String),

    #[error("Timeout error: {0}")]
    Timeout(String),

    #[error("Memory error: {0}")]
    Memory(String),

    #[error("Configuration error: {0}")]
    Configuration(String),

    #[error("Compilation error: {0}")]
    CompilationError(String),
}

/// Bundle containing compiled YARA rules with metadata
#[derive(Clone)]
pub struct RulesBundle {
    /// Compiled YARA rules
    pub rules: Arc<yara_x::Rules>,
    /// Number of rules in the bundle
    pub count: usize,
    /// Timestamp when rules were compiled
    pub compiled_at: DateTime<Utc>,
}

/// Metrics for the rules manager
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulesMetrics {
    /// Number of rules currently loaded
    pub rules_loaded: usize,
    /// Timestamp of last successful reload
    pub last_reload_at: Option<DateTime<Utc>>,
    /// Last error message if reload failed
    pub last_error: Option<String>,
}

/// Rules manager with hot-reload capabilities
pub struct RulesManager {
    /// Current rules bundle (thread-safe)
    rules: ArcSwap<Option<RulesBundle>>,
    /// Directory being watched for rule changes
    watch_dir: Option<PathBuf>,
    /// File system watcher
    _watcher: Option<RecommendedWatcher>,
    /// Channel for receiving file system events
    event_rx: Option<mpsc::UnboundedReceiver<notify::Result<Event>>>,
    /// Metrics tracking
    metrics: Arc<std::sync::Mutex<RulesMetrics>>,
}

impl RulesManager {
    /// Create a new rules manager
    pub fn new() -> Self {
        Self {
            rules: ArcSwap::new(Arc::new(None)),
            watch_dir: None,
            _watcher: None,
            event_rx: None,
            metrics: Arc::new(std::sync::Mutex::new(RulesMetrics {
                rules_loaded: 0,
                last_reload_at: None,
                last_error: None,
            })),
        }
    }

    /// Load all YARA rules from a directory
    pub fn load_all(&self, dir: &Path) -> Result<RulesBundle, YaraEngineError> {
        info!("Loading YARA rules from directory: {}", dir.display());

        if !dir.exists() {
            return Err(YaraEngineError::Configuration(format!(
                "Rules directory does not exist: {}",
                dir.display()
            )));
        }

        if !dir.is_dir() {
            return Err(YaraEngineError::Configuration(format!(
                "Path is not a directory: {}",
                dir.display()
            )));
        }

        let mut compiler = yara_x::Compiler::new();
        let mut rule_count = 0;

        // Recursively find all rule files
        let rule_files = self.find_rule_files_recursive(dir)?;
        info!("Found {} YARA rule files in {}", rule_files.len(), dir.display());

        // Add all rule files to compiler and count individual rules
        for path in rule_files {
            debug!("Loading rule file: {}", path.display());
            match std::fs::read_to_string(&path) {
                Ok(content) => {
                    // Count individual rules in this file by counting "rule" declarations
                    let individual_rules = content
                        .lines()
                        .filter(|line| {
                            let trimmed = line.trim();
                            trimmed.starts_with("rule ") && !trimmed.starts_with("//")
                        })
                        .count();

                    match compiler.add_source(content.as_str()) {
                        Ok(_) => {
                            rule_count += individual_rules;
                            debug!(
                                "Successfully loaded rule file: {} ({} rules)",
                                path.display(),
                                individual_rules
                            );
                        }
                        Err(e) => {
                            warn!("Failed to compile rule file {}: {}", path.display(), e);
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to read rule file {}: {}", path.display(), e);
                }
            }
        }

        if rule_count == 0 {
            return Err(YaraEngineError::Configuration(
                "No valid YARA rule files found in directory".to_string(),
            ));
        }

        let rules = compiler.build();

        let bundle = RulesBundle {
            rules: Arc::new(rules),
            count: rule_count,
            compiled_at: Utc::now(),
        };

        // Update metrics
        if let Ok(mut metrics) = self.metrics.lock() {
            metrics.rules_loaded = rule_count;
            metrics.last_reload_at = Some(bundle.compiled_at);
            metrics.last_error = None;
        }

        // Store the new rules
        self.rules.store(Arc::new(Some(bundle.clone())));

        info!("Successfully loaded {} YARA rules", rule_count);
        Ok(bundle)
    }

    /// Load YARA rules from multiple directories recursively
    pub fn load_from_multiple_dirs(&self, dirs: &[&Path]) -> Result<RulesBundle, YaraEngineError> {
        info!("Loading YARA rules from {} directories", dirs.len());

        let mut compiler = yara_x::Compiler::new();
        let mut rule_count = 0;
        let mut total_files = 0;

        for dir in dirs {
            if !dir.exists() {
                warn!("Rules directory does not exist: {}", dir.display());
                continue;
            }

            if !dir.is_dir() {
                warn!("Path is not a directory: {}", dir.display());
                continue;
            }

            info!("Scanning directory: {}", dir.display());
            let rule_files = self.find_rule_files_recursive(dir)?;
            info!("Found {} YARA rule files in {}", rule_files.len(), dir.display());
            total_files += rule_files.len();

            // Add all rule files to compiler and count individual rules
            for path in rule_files {
                debug!("Loading rule file: {}", path.display());
                match std::fs::read_to_string(&path) {
                    Ok(content) => {
                        // Count individual rules in this file by counting "rule" declarations
                        let individual_rules = content
                            .lines()
                            .filter(|line| {
                                let trimmed = line.trim();
                                trimmed.starts_with("rule ") && !trimmed.starts_with("//")
                            })
                            .count();

                        match compiler.add_source(content.as_str()) {
                            Ok(_) => {
                                rule_count += individual_rules;
                                debug!(
                                    "Successfully loaded rule file: {} ({} rules)",
                                    path.display(),
                                    individual_rules
                                );
                            }
                            Err(e) => {
                                warn!("Failed to compile rule file {}: {}", path.display(), e);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to read rule file {}: {}", path.display(), e);
                    }
                }
            }
        }

        if rule_count == 0 {
            return Err(YaraEngineError::Configuration(
                "No valid YARA rule files found in any directory".to_string(),
            ));
        }

        let rules = compiler.build();

        let bundle = RulesBundle {
            rules: Arc::new(rules),
            count: rule_count,
            compiled_at: Utc::now(),
        };

        // Update metrics
        if let Ok(mut metrics) = self.metrics.lock() {
            metrics.rules_loaded = rule_count;
            metrics.last_reload_at = Some(bundle.compiled_at);
            metrics.last_error = None;
        }

        // Store the new rules
        self.rules.store(Arc::new(Some(bundle.clone())));

        info!("Successfully loaded {} YARA rules from {} files across {} directories", 
               rule_count, total_files, dirs.len());
        Ok(bundle)
    }

    /// Recursively find all YARA rule files in a directory
    fn find_rule_files_recursive(&self, dir: &Path) -> Result<Vec<PathBuf>, YaraEngineError> {
        let mut rule_files = Vec::new();
        self.find_rule_files_recursive_helper(dir, &mut rule_files)?;
        Ok(rule_files)
    }

    /// Helper function for recursive rule file discovery
    fn find_rule_files_recursive_helper(&self, dir: &Path, rule_files: &mut Vec<PathBuf>) -> Result<(), YaraEngineError> {
        let entries = std::fs::read_dir(dir)
            .map_err(|e| YaraEngineError::FileAccess(format!("Failed to read directory {}: {}", dir.display(), e)))?;

        for entry in entries {
            let entry = entry.map_err(|e| {
                YaraEngineError::FileAccess(format!("Failed to read directory entry in {}: {}", dir.display(), e))
            })?;
            let path = entry.path();

            if path.is_file() {
                if let Some(ext) = path.extension() {
                    if ext == "yar" || ext == "yara" {
                        rule_files.push(path);
                    }
                }
            } else if path.is_dir() {
                // Skip hidden directories and common cache/temp directories
                if let Some(dir_name) = path.file_name().and_then(|n| n.to_str()) {
                    if dir_name.starts_with('.') || 
                       dir_name == "cache" || 
                       dir_name == "temp" || 
                       dir_name == "tmp" ||
                       dir_name == "__pycache__" {
                        continue;
                    }
                }
                // Recursively scan subdirectory
                self.find_rule_files_recursive_helper(&path, rule_files)?;
            }
        }

        Ok(())
    }

    /// Start watching a directory for rule changes with hot-reload
    pub async fn watch(&mut self, dir: PathBuf) -> Result<(), YaraEngineError> {
        info!(
            "Starting hot-reload watcher for directory: {}",
            dir.display()
        );

        let (tx, rx) = mpsc::unbounded_channel();

        let mut watcher = RecommendedWatcher::new(
            move |res| {
                if let Err(e) = tx.send(res) {
                    error!("Failed to send file system event: {}", e);
                }
            },
            Config::default(),
        )
        .map_err(|e| YaraEngineError::Configuration(format!("Failed to create watcher: {}", e)))?;

        watcher.watch(&dir, RecursiveMode::Recursive).map_err(|e| {
            YaraEngineError::Configuration(format!("Failed to watch directory: {}", e))
        })?;

        self.watch_dir = Some(dir.clone());
        self._watcher = Some(watcher);
        self.event_rx = Some(rx);

        // Load initial rules
        if let Err(e) = self.load_all(&dir) {
            error!("Failed to load initial rules: {}", e);
            if let Ok(mut metrics) = self.metrics.lock() {
                metrics.last_error = Some(format!("Initial load failed: {}", e));
            }
        }

        // Start the hot-reload task
        self.start_reload_task().await;

        Ok(())
    }

    /// Start the background task for handling file system events with debouncing
    async fn start_reload_task(&mut self) {
        if let Some(mut rx) = self.event_rx.take() {
            let watch_dir = self.watch_dir.clone();
            let rules_manager_clone = Arc::new(std::sync::Mutex::new(RulesManager::new()));

            tokio::spawn(async move {
                let debounce_duration = Duration::from_millis(500);
                let mut _last_event_time: Option<Instant> = None;

                while let Some(event_result) = rx.recv().await {
                    match event_result {
                        Ok(event) => {
                            // Check if this is a relevant file change
                            if Self::is_relevant_event(&event) {
                                _last_event_time = Some(Instant::now());

                                // Wait for debounce period
                                sleep(debounce_duration).await;

                                // Check if no new events occurred during debounce
                                if let Some(event_time) = _last_event_time {
                                    if event_time.elapsed() >= debounce_duration {
                                        if let Some(ref dir) = watch_dir {
                                            info!("Reloading YARA rules due to file system change");

                                            // Reload rules in the background
                                            if let Ok(manager) = rules_manager_clone.lock() {
                                                if let Err(e) = manager.load_all(dir) {
                                                    error!("Failed to reload rules: {}", e);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            warn!("File system watcher error: {}", e);
                        }
                    }
                }
            });
        }
    }

    /// Check if a file system event is relevant for rule reloading
    fn is_relevant_event(event: &Event) -> bool {
        match event.kind {
            EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_) => {
                // Check if any path has .yar or .yara extension
                event.paths.iter().any(|path| {
                    if let Some(ext) = path.extension() {
                        ext == "yar" || ext == "yara"
                    } else {
                        false
                    }
                })
            }
            _ => false,
        }
    }

    /// Get current rules bundle
    pub fn get_rules(&self) -> Option<Arc<RulesBundle>> {
        let current = self.rules.load();
        current
            .as_ref()
            .clone()
            .map(|bundle| Arc::new(bundle.clone()))
    }

    /// Check if rules are loaded
    pub fn is_loaded(&self) -> bool {
        self.rules.load().is_some()
    }

    /// Get current metrics
    pub fn metrics(&self) -> RulesMetrics {
        match self.metrics.lock() {
            Ok(guard) => guard.clone(),
            Err(_) => RulesMetrics {
                rules_loaded: 0,
                last_reload_at: None,
                last_error: Some("Failed to acquire metrics lock".to_string()),
            },
        }
    }

    /// Trigger manual reload of rules
    pub fn reload(&self) -> Result<(), YaraEngineError> {
        if let Some(ref dir) = self.watch_dir {
            self.load_all(dir).map(|_| ())
        } else {
            Err(YaraEngineError::Configuration(
                "No watch directory configured for reload".to_string(),
            ))
        }
    }
}

/// YARA match result with additional metadata
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct YaraMatchResult {
    /// Timestamp when the match was found
    pub timestamp: u64,
    /// Name of the matched rule
    pub rule_name: String,
    /// Type of target ("file" or "process")
    pub target_type: String,
    /// Path to the target file or process name
    pub target_path: String,
    /// Process ID if this was a process scan
    pub target_pid: Option<u32>,
    /// Matched strings information
    pub match_strings: Vec<MatchString>,
    /// Severity level
    pub severity: String,
    /// Additional metadata
    pub metadata: std::collections::HashMap<String, String>,
}

/// JSON-compatible structure representing a YARA rule match
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct YaraMatch {
    /// Name of the matched YARA rule
    pub rule: String,
    /// List of matched strings within the rule
    pub strings: Vec<MatchString>,
    /// Rule metadata as key-value pairs
    pub meta: HashMap<String, String>,
}

/// JSON-compatible structure representing a matched string within a YARA rule
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct MatchString {
    /// String identifier from the YARA rule
    pub identifier: String,
    /// Byte offset where the match occurred
    pub offset: u64,
    /// Length of the matched data in bytes
    pub length: usize,
    /// Hex representation of matched data (truncated to 128 chars for readability)
    pub data: String,
}

/// File deduplication cache entry
#[derive(Debug, Clone)]
struct DeduplicationEntry {
    file_hash: String,
    #[allow(dead_code)]
    inode: Option<u64>,
    #[allow(dead_code)]
    size: u64,
    #[allow(dead_code)]
    modified_time: SystemTime,
    scan_result: Option<Vec<String>>, // Store rule names that matched
    last_scanned: SystemTime,
}

/// Deduplication cache for preventing redundant scans
struct DeduplicationCache {
    cache: LruCache<String, DeduplicationEntry>,
}

impl DeduplicationCache {
    fn new(capacity: usize) -> Self {
        Self {
            cache: LruCache::new(NonZeroUsize::new(capacity).unwrap()),
        }
    }

    fn get_cache_key(
        path: &Path,
        inode: Option<u64>,
        size: u64,
        modified_time: SystemTime,
    ) -> String {
        match inode {
            Some(inode_val) => format!(
                "{}:{}:{}:{}",
                path.display(),
                inode_val,
                size,
                modified_time
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
            ),
            None => format!(
                "{}:{}:{}",
                path.display(),
                size,
                modified_time
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
            ),
        }
    }

    fn should_rescan(&self, key: &str, file_hash: &str) -> bool {
        match self.cache.peek(key) {
            Some(entry) => {
                // Rescan if hash changed or if it's been more than 1 hour since last scan
                entry.file_hash != file_hash
                    || entry
                        .last_scanned
                        .elapsed()
                        .unwrap_or(Duration::from_secs(0))
                        > Duration::from_secs(3600)
            }
            None => true, // Not in cache, need to scan
        }
    }

    fn get_cached_result(&mut self, key: &str) -> Option<Vec<String>> {
        self.cache
            .get(key)
            .and_then(|entry| entry.scan_result.clone())
    }

    fn insert(&mut self, key: String, entry: DeduplicationEntry) {
        self.cache.put(key, entry);
    }

    fn clear(&mut self) {
        self.cache.clear();
    }
}

/// YARA scanning engine with file scanning capabilities
pub struct YaraEngine {
    /// Rule manager for YARA rule compilation and matching
    rules_manager: Arc<RulesManager>,
    /// Agent configuration for scanning parameters
    config: Arc<AgentConfig>,
    /// Deduplication cache to prevent redundant scans
    dedup_cache: Arc<Mutex<DeduplicationCache>>,
    /// Rule hit tracker for dynamic anomaly scoring
    hit_tracker: Arc<Mutex<RuleHitTracker>>,
}

impl YaraEngine {
    /// Create a new YARA engine instance
    pub fn new(config: Arc<AgentConfig>) -> Self {
        info!("Initializing YARA engine");
        Self {
            rules_manager: Arc::new(RulesManager::new()),
            config,
            dedup_cache: Arc::new(Mutex::new(DeduplicationCache::new(10000))),
            hit_tracker: Arc::new(Mutex::new(RuleHitTracker::new(3600))), // 1 hour window
        }
    }

    /// Create a new YARA engine with existing rules manager
    pub fn with_rules_manager(rules_manager: Arc<RulesManager>, config: Arc<AgentConfig>) -> Self {
        info!("Initializing YARA engine with existing rules manager");
        Self {
            rules_manager,
            config,
            dedup_cache: Arc::new(Mutex::new(DeduplicationCache::new(10000))),
            hit_tracker: Arc::new(Mutex::new(RuleHitTracker::new(3600))), // 1 hour window
        }
    }

    /// Get reference to the rules manager
    pub fn rules_manager(&self) -> Arc<RulesManager> {
        Arc::clone(&self.rules_manager)
    }

    /// Check if YARA rules are loaded
    pub async fn is_loaded(&self) -> bool {
        self.rules_manager.is_loaded()
    }

    /// Load YARA rules from directory
    pub async fn load_rules(&self, rules_dir: &str) -> Result<usize, YaraEngineError> {
        info!("Loading YARA rules from directory: {}", rules_dir);

        let rules_path = Path::new(rules_dir);
        match self.rules_manager.load_all(rules_path) {
            Ok(bundle) => {
                info!("Successfully loaded {} YARA rules", bundle.count);
                Ok(bundle.count)
            }
            Err(e) => {
                error!("Failed to load YARA rules: {}", e);
                Err(e)
            }
        }
    }

    /// Load YARA rules from multiple directories with comprehensive coverage
    pub async fn load_comprehensive_rules(&self, base_dir: &str) -> Result<usize, YaraEngineError> {
        info!("Loading comprehensive YARA rules from base directory: {}", base_dir);

        let base_path = Path::new(base_dir);
        
        // Define all professional rule directories to scan
        let rule_directories = vec![
            base_path.to_path_buf(),                                    // Base rules directory
            base_path.join("signature-base"),                           // APT and malware rules
            base_path.join("eset-malware-iocs"),                       // ESET threat intelligence
            base_path.join("yara-forge-full"),                         // Comprehensive rule collection
            base_path.join("elastic-security"),                        // Elastic Security rules
            base_path.join("reversinglabs-yara"),                      // ReversingLabs commercial rules
            base_path.join("yara-forge-core"),                         // Core YARA rules
            base_path.join("kaggle-yara-rules"),                       // Community rules
            base_path.join("awesome-yara"),                            // Curated awesome rules
        ];

        // Convert to Path references
        let rule_paths: Vec<&Path> = rule_directories.iter().map(|p| p.as_path()).collect();

        match self.rules_manager.load_from_multiple_dirs(&rule_paths) {
            Ok(bundle) => {
                info!("Successfully loaded {} comprehensive YARA rules from {} directories", 
                      bundle.count, rule_paths.len());
                Ok(bundle.count)
            }
            Err(e) => {
                error!("Failed to load comprehensive YARA rules: {}", e);
                Err(e)
            }
        }
    }

    /// Start watching rules directory for hot-reload
    pub async fn start_watching(&self, rules_dir: &str) -> Result<(), YaraEngineError> {
        info!(
            "Starting hot-reload watcher for rules directory: {}",
            rules_dir
        );

        let rules_path = PathBuf::from(rules_dir);
        // For now, just load the rules initially
        // Hot-reload watching will be implemented when RulesManager supports it with Arc
        self.rules_manager.load_all(&rules_path)?;

        info!("Rules loaded successfully from: {}", rules_dir);
        Ok(())
    }

    /// Get rules manager metrics
    pub fn get_metrics(&self) -> RulesMetrics {
        self.rules_manager.metrics()
    }

    /// Get rule hit deltas for anomaly analysis
    pub fn get_rule_hit_deltas(&self) -> Vec<RuleHitDelta> {
        if let Ok(tracker) = self.hit_tracker.lock() {
            tracker.compute_deltas()
        } else {
            Vec::new()
        }
    }

    /// Get anomaly score for a specific rule
    pub fn get_rule_anomaly_score(&self, rule_name: &str) -> f64 {
        if let Ok(tracker) = self.hit_tracker.lock() {
            // Get current hits from current window stats
            let current_stats = tracker.get_current_stats();
            let current_hits = current_stats.get(rule_name).unwrap_or(&0);
            tracker.calculate_anomaly_score(rule_name, *current_hits as f64)
        } else {
            0.0
        }
    }

    /// Update baseline for all tracked rules (should be called periodically)
    pub fn update_hit_baselines(&self) {
        if let Ok(mut tracker) = self.hit_tracker.lock() {
            tracker.update_baselines();
            info!("Updated rule hit baselines for anomaly detection");
        }
    }

    /// Trigger manual reload of rules
    pub fn reload_rules(&self) -> Result<(), YaraEngineError> {
        self.rules_manager.reload()
    }

    /// Scan a file for YARA rule matches with chunked reading
    ///
    /// # Arguments
    /// * `path` - Path to the file to scan
    ///
    /// # Returns
    /// Vector of rule names that matched the file
    ///
    /// # Behavior
    /// - Skips inaccessible/locked files gracefully (logs warning, returns empty vector)
    /// - Reads large files in configurable chunks for memory efficiency
    /// - Uses rule manager to match file content
    /// - Returns only rule names for simplified output
    pub async fn scan_file(&self, path: &Path) -> Result<Vec<String>, YaraError> {
        let start_time = std::time::Instant::now();
        let path_str = path.display().to_string();

        debug!("Starting YARA scan of file: {}", path_str);

        // Check if rules are loaded
        if !self.is_loaded().await {
            warn!("YARA rules not loaded, skipping scan of: {}", path_str);
            return Err(YaraError::InitializationError {
                message: "YARA rules not loaded".to_string(),
                source: None,
            });
        }

        // Check if file exists and is accessible
        let (file_size, modified_time, inode) = match fs::metadata(path).await {
            Ok(metadata) => {
                if !metadata.is_file() {
                    debug!("Path is not a file, skipping: {}", path_str);
                    return Ok(Vec::new());
                }

                let file_size = metadata.len();
                let modified_time = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);

                // Get inode on Unix systems
                #[cfg(unix)]
                let inode = {
                    use std::os::unix::fs::MetadataExt;
                    Some(metadata.ino())
                };
                #[cfg(not(unix))]
                let inode = None;

                debug!("File size: {} bytes", file_size);

                // Check file size limits from config
                let max_file_size =
                    self.config.yara.as_ref().unwrap().memory_chunk_size as u64 * 100; // Allow up to 100 chunks
                if file_size > max_file_size {
                    warn!(
                        "File too large for scanning: {} ({} bytes, limit {} bytes)",
                        path_str, file_size, max_file_size
                    );
                    return Err(YaraError::FileSystemError {
                        path: path.to_path_buf(),
                        kind: FileSystemErrorKind::FileTooLarge {
                            size: file_size,
                            limit: max_file_size,
                        },
                        source: None,
                    });
                }

                (file_size, modified_time, inode)
            }
            Err(e) => {
                // Handle different types of file access errors gracefully
                let error_kind = match e.kind() {
                    std::io::ErrorKind::NotFound => {
                        debug!("File not found, skipping: {}", path_str);
                        FileSystemErrorKind::NotFound
                    }
                    std::io::ErrorKind::PermissionDenied => {
                        warn!("Permission denied accessing file, skipping: {}", path_str);
                        FileSystemErrorKind::PermissionDenied
                    }
                    _ => {
                        // Check if it's a file lock error (common on Windows)
                        if e.to_string().contains("being used by another process")
                            || e.to_string().contains("locked")
                        {
                            warn!("File is locked by another process, skipping: {}", path_str);
                            FileSystemErrorKind::FileLocked
                        } else {
                            warn!("File access error, skipping: {} - {}", path_str, e);
                            FileSystemErrorKind::Other(e.to_string())
                        }
                    }
                };

                // For graceful handling, return empty results instead of error
                debug!(
                    "Gracefully skipping inaccessible file: {} ({})",
                    path_str, error_kind
                );
                return Ok(Vec::new());
            }
        };

        // Check deduplication cache
        let cache_key = DeduplicationCache::get_cache_key(path, inode, file_size, modified_time);

        // Try to get cached result first
        if let Ok(mut cache) = self.dedup_cache.lock() {
            if let Some(cached_result) = cache.get_cached_result(&cache_key) {
                debug!("Using cached scan result for: {}", path_str);

                // Update telemetry for cache hit
                tokio::spawn(async move {
                    #[cfg(feature = "telemetry")]
                    {
                        // Cache hit - using record_counter instead of increment_dedup_counters
                        // crate::telemetry::record_counter("dedup_cache_hits_total", 1.0).await;
                        crate::telemetry::update_file_size_distribution(file_size).await;
                    }
                });

                return Ok(cached_result);
            }
        }

        // Calculate file hash for deduplication
        let file_hash = match self.calculate_file_hash(path).await {
            Ok(hash) => hash,
            Err(e) => {
                warn!("Failed to calculate file hash for {}: {}", path_str, e);
                // Continue without deduplication if hash calculation fails
                String::new()
            }
        };

        // Check if we should rescan based on hash
        if !file_hash.is_empty() {
            if let Ok(mut cache) = self.dedup_cache.lock() {
                if !cache.should_rescan(&cache_key, &file_hash) {
                    debug!("File hash unchanged, using cached result for: {}", path_str);
                    if let Some(cached_result) = cache.get_cached_result(&cache_key) {
                        // Update telemetry for hash-based cache hit
                        tokio::spawn(async move {
                            #[cfg(feature = "telemetry")]
                            {
                                // Cache hit - using record_counter instead of increment_dedup_counters
                                // crate::telemetry::record_counter("dedup_cache_hits_total", 1.0).await;
                                crate::telemetry::update_file_size_distribution(file_size).await;
                            }
                        });

                        return Ok(cached_result);
                    }
                }
            }
        }

        // Read and scan file content in chunks
        let io_start = std::time::Instant::now();
        match self.read_and_scan_file(path).await {
            Ok(matches) => {
                let scan_duration = start_time.elapsed();
                let io_duration = io_start.elapsed();

                // Extract rule names from matches
                let rule_names: Vec<String> = matches.iter().map(|m| m.rule.clone()).collect();

                // Track rule hits for dynamic anomaly scoring
                if !rule_names.is_empty() {
                    if let Ok(mut tracker) = self.hit_tracker.lock() {
                        for rule_name in &rule_names {
                            tracker.record_hit(
                                rule_name,
                                "file",
                                path.to_str().unwrap_or("unknown"),
                            );

                            // Log anomaly scores for detected rules
                            let anomaly_score = tracker.calculate_anomaly_score(rule_name, 1.0);
                            if anomaly_score > 0.7 {
                                warn!("High anomaly score for rule '{}': {:.3} - unusual detection pattern", 
                                      rule_name, anomaly_score);
                            } else if anomaly_score > 0.5 {
                                info!(
                                    "Moderate anomaly score for rule '{}': {:.3}",
                                    rule_name, anomaly_score
                                );
                            }
                        }
                    }
                }

                // Update telemetry with detailed metrics
                let scan_duration_ms = scan_duration.as_millis() as f64;
                let io_duration_ms = io_duration.as_millis() as f64;
                #[cfg(feature = "telemetry")]
                let actual_scan_time_ms = scan_duration_ms - io_duration_ms;
                #[cfg(not(feature = "telemetry"))]
                let _actual_scan_time_ms = scan_duration_ms - io_duration_ms;

                // Clone values before moving into async closure
                #[cfg(feature = "telemetry")]
                let file_hash_clone = file_hash.clone();
                #[cfg(not(feature = "telemetry"))]
                let _file_hash_clone = file_hash.clone();
                #[cfg(feature = "telemetry")]
                let matches_len = matches.len();
                #[cfg(not(feature = "telemetry"))]
                let _matches_len = matches.len();

                // Update telemetry asynchronously (don't block on it)
                tokio::spawn(async move {
                    #[cfg(feature = "telemetry")]
                    {
                        crate::telemetry::update_file_size_distribution(file_size).await;
                        crate::telemetry::add_latency_sample(scan_duration_ms).await;
                        crate::telemetry::update_scan_performance(
                            io_duration_ms,
                            actual_scan_time_ms,
                            file_size,
                        )
                        .await;
                        crate::telemetry::increment_scan_counters(matches_len, false).await;

                        // Update deduplication counters
                        if !file_hash_clone.is_empty() {
                            // Cache miss - using record_counter instead of increment_dedup_counters
                            // crate::telemetry::record_counter("dedup_cache_misses_total", 1.0).await;
                            // This was a cache miss
                        }
                    }
                });

                // Cache the scan result
                if !file_hash.is_empty() {
                    let cache_entry = DeduplicationEntry {
                        file_hash: file_hash.clone(),
                        inode,
                        size: file_size,
                        modified_time,
                        scan_result: Some(rule_names.clone()),
                        last_scanned: SystemTime::now(),
                    };

                    if let Ok(mut cache) = self.dedup_cache.lock() {
                        cache.insert(cache_key.clone(), cache_entry);
                        debug!("Cached scan result for: {}", path_str);
                    }
                }

                // Send JSON detection event if matches found
                if !matches.is_empty() {
                    info!(
                        "YARA scan completed: {} matches found in {} ({:.2}ms)",
                        matches.len(),
                        path_str,
                        scan_duration.as_millis()
                    );

                    // Create and send detection event
                    let detection_event = helpers::create_file_detection_event(&path_str, matches);
                    if let Err(e) = self.send_detection_event(detection_event).await {
                        warn!(
                            "Failed to send file detection event for {}: {}",
                            path_str, e
                        );
                    }
                } else {
                    debug!(
                        "YARA scan completed: no matches in {} ({:.2}ms)",
                        path_str,
                        scan_duration.as_millis()
                    );
                }
                Ok(rule_names)
            }
            Err(e) => {
                error!("YARA scan failed for {}: {}", path_str, e);

                // Update telemetry for scan error
                tokio::spawn(async move {
                    #[cfg(feature = "telemetry")]
                    {
                        crate::telemetry::increment_scan_counters(0, true).await; // Error occurred
                        crate::telemetry::update_file_size_distribution(file_size).await;
                    }
                });

                Err(e)
            }
        }
    }

    /// Scan a running process for YARA rule matches
    ///
    /// # Arguments
    /// * `pid` - Process ID to scan
    ///
    /// # Returns
    /// Vector of YARA matches found in the process memory
    ///
    /// # Behavior
    /// - Cross-platform implementation for Windows and Linux
    /// - Reads process memory in configurable chunks
    /// - Handles access denied errors gracefully (never crashes)
    /// - Logs warnings for inaccessible regions
    /// - Returns empty Vec on complete failure
    pub async fn scan_process(&self, pid: u32) -> Result<Vec<YaraMatch>, YaraError> {
        let start_time = std::time::Instant::now();
        debug!("Starting YARA scan of process PID: {}", pid);

        // Check if rules are loaded
        if !self.is_loaded().await {
            warn!("YARA rules not loaded, skipping process scan: {}", pid);
            return Err(YaraError::InitializationError {
                message: "YARA rules not loaded".to_string(),
                source: None,
            });
        }

        // Platform-specific process memory scanning
        let matches = match self.scan_process_memory(pid).await {
            Ok(matches) => {
                let scan_duration = start_time.elapsed();
                if !matches.is_empty() {
                    info!(
                        "Process scan completed: {} matches found in PID {} ({:.2}ms)",
                        matches.len(),
                        pid,
                        scan_duration.as_millis()
                    );

                    // Create and send detection event
                    let detection_event =
                        helpers::create_process_detection_event(pid, None, matches.clone());
                    if let Err(e) = self.send_detection_event(detection_event).await {
                        warn!(
                            "Failed to send process detection event for PID {}: {}",
                            pid, e
                        );
                    }
                } else {
                    debug!(
                        "Process scan completed: no matches in PID {} ({:.2}ms)",
                        pid,
                        scan_duration.as_millis()
                    );
                }
                matches
            }
            Err(e) => {
                // Log error but don't fail completely - return empty results
                warn!(
                    "Process scan failed for PID {}: {} - returning empty results",
                    pid, e
                );
                Vec::new()
            }
        };

        Ok(matches)
    }

    /// Platform-specific process memory scanning implementation
    #[cfg(target_os = "windows")]
    async fn scan_process_memory(&self, pid: u32) -> Result<Vec<YaraMatch>, YaraError> {
        use windows::Win32::Foundation::CloseHandle;

        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        };

        use windows::Win32::System::Memory::{
            VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_EXECUTE_READ,
            PAGE_EXECUTE_READWRITE, PAGE_READONLY, PAGE_READWRITE,
        };

        debug!("Windows: Opening process PID {} for memory scanning", pid);

        // Open process with required permissions
        let process_handle =
            match unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) } {
                Ok(handle) => handle,
                Err(e) => {
                    let error_msg = format!("Failed to open process PID {}: {}", pid, e);
                    warn!("{}", error_msg);
                    return Err(YaraError::ScanError {
                        target: format!("process:{}", pid).into(),
                        kind: ScanErrorKind::PermissionDenied,
                        duration: None,
                    });
                }
            };

        // Ensure handle is closed when function exits
        let _handle_guard = scopeguard::guard(process_handle, |handle| unsafe {
            let _ = CloseHandle(handle);
        });

        let mut all_matches = Vec::new();
        let chunk_size = self.config.yara.as_ref().unwrap().memory_chunk_size;
        let mut address = 0usize;
        let mut regions_scanned = 0;
        let mut bytes_scanned = 0u64;

        debug!(
            "Windows: Starting memory region enumeration for PID {}",
            pid
        );

        // Enumerate memory regions
        loop {
            let (should_scan, base_addr, region_size, next_address) = {
                let mut mbi = MEMORY_BASIC_INFORMATION::default();
                let result = unsafe {
                    VirtualQueryEx(
                        process_handle,
                        Some(address as *const std::ffi::c_void),
                        &mut mbi,
                        std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                    )
                };

                if result == 0 {
                    debug!(
                        "Windows: Finished enumerating memory regions at address 0x{:x}",
                        address
                    );
                    break;
                }

                // Check if region is committed and readable
                let is_committed = mbi.State == MEM_COMMIT;
                let is_readable = matches!(
                    mbi.Protect,
                    PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE
                );

                let should_scan = is_committed && is_readable && mbi.RegionSize > 0;
                let base_addr = mbi.BaseAddress as usize;
                let region_size = mbi.RegionSize;
                let next_address = base_addr + region_size;

                (should_scan, base_addr, region_size, next_address)
            }; // mbi is dropped here

            if should_scan {
                debug!(
                    "Windows: Scanning memory region at 0x{:x}, size: {} bytes",
                    base_addr, region_size
                );

                // Scan this memory region in chunks
                match self
                    .scan_memory_region(process_handle, base_addr, region_size, chunk_size)
                    .await
                {
                    Ok(mut region_matches) => {
                        regions_scanned += 1;
                        bytes_scanned += region_size as u64;
                        all_matches.append(&mut region_matches);
                        debug!(
                            "Windows: Found {} matches in region 0x{:x}",
                            region_matches.len(),
                            base_addr
                        );
                    }
                    Err(e) => {
                        warn!(
                            "Windows: Failed to scan memory region 0x{:x}: {}",
                            base_addr, e
                        );
                        // Continue with next region
                    }
                }
            } else {
                debug!(
                    "Windows: Skipping memory region at 0x{:x} (not readable or not committed)",
                    base_addr
                );
            }

            // Move to next region
            address = next_address;

            // Safety check to prevent infinite loops
            if address >= 0x7FFFFFFF {
                debug!("Windows: Reached user-space memory limit");
                break;
            }
        }

        info!(
            "Windows: Process scan completed for PID {}: {} regions scanned, {} bytes, {} matches",
            pid,
            regions_scanned,
            bytes_scanned,
            all_matches.len()
        );

        Ok(all_matches)
    }

    /// Linux-specific process memory scanning implementation
    #[cfg(target_os = "linux")]
    async fn scan_process_memory(&self, pid: u32) -> Result<Vec<YaraMatch>, YaraError> {
        use std::fs::File;
        use std::io::{BufRead, BufReader, Seek, SeekFrom};

        debug!("Linux: Starting memory scan for process PID {}", pid);

        // Read /proc/{pid}/maps to get memory regions
        let maps_path = format!("/proc/{}/maps", pid);
        let maps_file = match File::open(&maps_path) {
            Ok(file) => file,
            Err(e) => {
                let error_msg = format!("Failed to open {}: {}", maps_path, e);
                warn!("{}", error_msg);
                return Err(YaraError::ScanError {
                    target: format!("process:{}", pid).into(),
                    kind: ScanErrorKind::PermissionDenied,
                    duration: None,
                });
            }
        };

        let reader = BufReader::new(maps_file);
        let mut memory_regions = Vec::new();

        // Parse memory maps
        for line in reader.lines() {
            let line = line.map_err(|e| YaraError::ScanError {
                target: format!("process:{}", pid).into(),
                kind: ScanErrorKind::ReadError,
                duration: None,
            })?;

            // Parse line format: address perms offset dev inode pathname
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }

            let address_range = parts[0];
            let permissions = parts[1];

            // Only scan readable regions
            if !permissions.starts_with('r') {
                continue;
            }

            // Parse address range (start-end)
            if let Some((start_str, end_str)) = address_range.split_once('-') {
                if let (Ok(start), Ok(end)) = (
                    usize::from_str_radix(start_str, 16),
                    usize::from_str_radix(end_str, 16),
                ) {
                    let size = end - start;
                    if size > 0 {
                        memory_regions.push((start, size));
                        debug!(
                            "Linux: Found readable memory region: 0x{:x}-0x{:x} ({} bytes)",
                            start, end, size
                        );
                    }
                }
            }
        }

        info!(
            "Linux: Found {} readable memory regions for PID {}",
            memory_regions.len(),
            pid
        );

        // Open /proc/{pid}/mem for reading
        let mem_path = format!("/proc/{}/mem", pid);
        let mut mem_file = match File::open(&mem_path) {
            Ok(file) => file,
            Err(e) => {
                let error_msg = format!("Failed to open {}: {}", mem_path, e);
                warn!("{}", error_msg);
                return Err(YaraError::ScanError {
                    target: format!("process:{}", pid).into(),
                    kind: ScanErrorKind::PermissionDenied,
                    duration: None,
                });
            }
        };

        let mut all_matches = Vec::new();
        let chunk_size = self.config.yara.memory_chunk_size;
        let mut regions_scanned = 0;
        let mut bytes_scanned = 0u64;

        // Scan each memory region
        for (start_addr, region_size) in memory_regions {
            debug!(
                "Linux: Scanning memory region 0x{:x}, size: {} bytes",
                start_addr, region_size
            );

            match self
                .scan_linux_memory_region(&mut mem_file, start_addr, region_size, chunk_size)
                .await
            {
                Ok(mut region_matches) => {
                    regions_scanned += 1;
                    bytes_scanned += region_size as u64;
                    all_matches.append(&mut region_matches);
                    debug!(
                        "Linux: Found {} matches in region 0x{:x}",
                        region_matches.len(),
                        start_addr
                    );
                }
                Err(e) => {
                    warn!(
                        "Linux: Failed to scan memory region 0x{:x}: {}",
                        start_addr, e
                    );
                    // Continue with next region
                }
            }
        }

        info!(
            "Linux: Process scan completed for PID {}: {} regions scanned, {} bytes, {} matches",
            pid,
            regions_scanned,
            bytes_scanned,
            all_matches.len()
        );

        Ok(all_matches)
    }

    /// Fallback implementation for unsupported platforms
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    async fn scan_process_memory(&self, pid: u32) -> Result<Vec<YaraMatch>, YaraError> {
        warn!(
            "Process memory scanning not supported on this platform for PID: {}",
            pid
        );
        Err(YaraError::ScanError {
            target: format!("process:{}", pid).into(),
            kind: ScanErrorKind::UnsupportedPlatform,
            duration: None,
        })
    }

    /// Windows helper function to scan a specific memory region
    #[cfg(target_os = "windows")]
    async fn scan_memory_region(
        &self,
        process_handle: windows::Win32::Foundation::HANDLE,
        start_addr: usize,
        region_size: usize,
        chunk_size: usize,
    ) -> Result<Vec<YaraMatch>, YaraError> {
        use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;

        let mut all_matches = Vec::new();
        let mut current_addr = start_addr;
        let end_addr = start_addr + region_size;

        while current_addr < end_addr {
            let remaining = end_addr - current_addr;
            let read_size = std::cmp::min(chunk_size, remaining);

            let mut buffer = vec![0u8; read_size];
            let mut bytes_read = 0usize;

            let success = unsafe {
                ReadProcessMemory(
                    process_handle,
                    current_addr as *const std::ffi::c_void,
                    buffer.as_mut_ptr() as *mut std::ffi::c_void,
                    read_size,
                    Some(&mut bytes_read),
                )
            };

            if success.is_ok() && bytes_read > 0 {
                // Truncate buffer to actual bytes read
                buffer.truncate(bytes_read);

                // Scan the memory chunk
                match self.scan_bytes(&buffer, current_addr as u64).await {
                    Ok(mut chunk_matches) => {
                        // Adjust offsets to reflect actual memory addresses
                        for yara_match in &mut chunk_matches {
                            for match_string in &mut yara_match.strings {
                                match_string.offset += current_addr as u64;
                            }
                        }
                        all_matches.extend(chunk_matches);
                    }
                    Err(e) => {
                        debug!(
                            "Windows: Failed to scan memory chunk at 0x{:x}: {}",
                            current_addr, e
                        );
                        // Continue with next chunk
                    }
                }
            } else {
                debug!(
                    "Windows: Failed to read memory at 0x{:x}, size: {}",
                    current_addr, read_size
                );
                // Skip this chunk and continue
            }

            current_addr += read_size;
        }

        Ok(all_matches)
    }

    /// Linux helper function to scan a specific memory region
    #[cfg(target_os = "linux")]
    async fn scan_linux_memory_region(
        &self,
        mem_file: &mut std::fs::File,
        start_addr: usize,
        region_size: usize,
        chunk_size: usize,
    ) -> Result<Vec<YaraMatch>, YaraError> {
        use std::io::{Read, Seek, SeekFrom};

        let mut all_matches = Vec::new();
        let mut current_addr = start_addr;
        let end_addr = start_addr + region_size;

        while current_addr < end_addr {
            let remaining = end_addr - current_addr;
            let read_size = std::cmp::min(chunk_size, remaining);

            // Seek to the memory address
            if let Err(e) = mem_file.seek(SeekFrom::Start(current_addr as u64)) {
                debug!(
                    "Linux: Failed to seek to address 0x{:x}: {}",
                    current_addr, e
                );
                current_addr += read_size;
                continue;
            }

            let mut buffer = vec![0u8; read_size];
            match mem_file.read_exact(&mut buffer) {
                Ok(_) => {
                    // Scan the memory chunk
                    match self.scan_bytes(&buffer, current_addr as u64).await {
                        Ok(mut chunk_matches) => {
                            // Adjust offsets to reflect actual memory addresses
                            for yara_match in &mut chunk_matches {
                                for match_string in &mut yara_match.strings {
                                    match_string.offset += current_addr as u64;
                                }
                            }
                            all_matches.extend(chunk_matches);
                        }
                        Err(e) => {
                            debug!(
                                "Linux: Failed to scan memory chunk at 0x{:x}: {}",
                                current_addr, e
                            );
                            // Continue with next chunk
                        }
                    }
                }
                Err(e) => {
                    debug!(
                        "Linux: Failed to read memory at 0x{:x}, size: {}: {}",
                        current_addr, read_size, e
                    );
                    // Skip this chunk and continue
                }
            }

            current_addr += read_size;
        }

        Ok(all_matches)
    }

    /// Read file content using optimized I/O and perform YARA scanning
    /// Uses mmap for files >1MB and buffered reads for smaller files
    pub async fn read_and_scan_file(&self, path: &Path) -> Result<Vec<YaraMatch>, YaraError> {
        let path_str = path.display().to_string();
        let scan_start = std::time::Instant::now();

        // Get file metadata to determine optimal I/O strategy
        let metadata = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(e) => {
                return Err(YaraError::FileSystemError {
                    path: path.to_path_buf(),
                    kind: match e.kind() {
                        std::io::ErrorKind::PermissionDenied => {
                            FileSystemErrorKind::PermissionDenied
                        }
                        std::io::ErrorKind::NotFound => FileSystemErrorKind::NotFound,
                        _ => FileSystemErrorKind::Other(e.to_string()),
                    },
                    source: Some(e),
                });
            }
        };

        let file_size = metadata.len();
        const MMAP_THRESHOLD: u64 = 1024 * 1024; // 1MB threshold

        debug!(
            "Scanning file {} ({} bytes) using {} I/O strategy",
            path_str,
            file_size,
            if file_size > MMAP_THRESHOLD {
                "mmap"
            } else {
                "buffered"
            }
        );

        let matches = if file_size > MMAP_THRESHOLD {
            // Use memory mapping for large files
            self.scan_file_with_mmap(path, file_size).await?
        } else {
            // Use buffered reading for small files
            self.scan_file_with_buffered_read(path).await?
        };

        let scan_duration = scan_start.elapsed();
        debug!(
            "File scan completed: {} matches found in {:.2}ms (file size: {} bytes)",
            matches.len(),
            scan_duration.as_millis(),
            file_size
        );

        Ok(matches)
    }

    /// Scan file using memory mapping (for large files >1MB)
    async fn scan_file_with_mmap(
        &self,
        path: &Path,
        _file_size: u64,
    ) -> Result<Vec<YaraMatch>, YaraError> {
        let path_str = path.display().to_string();

        // Open file for memory mapping
        let file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(e) => {
                return Err(YaraError::FileSystemError {
                    path: path.to_path_buf(),
                    kind: match e.kind() {
                        std::io::ErrorKind::PermissionDenied => {
                            FileSystemErrorKind::PermissionDenied
                        }
                        std::io::ErrorKind::NotFound => FileSystemErrorKind::NotFound,
                        _ => FileSystemErrorKind::Other(e.to_string()),
                    },
                    source: Some(e),
                });
            }
        };

        // Create memory map
        let mmap = match unsafe { MmapOptions::new().map(&file) } {
            Ok(m) => m,
            Err(e) => {
                warn!(
                    "Failed to create memory map for {}, falling back to buffered read: {}",
                    path_str, e
                );
                return self.scan_file_with_buffered_read(path).await;
            }
        };

        debug!("Created memory map for {} ({} bytes)", path_str, mmap.len());

        // For very large files, scan in chunks to avoid memory pressure
        let chunk_size = self.config.yara.as_ref().unwrap().memory_chunk_size;
        let max_scan_size = chunk_size * 10; // Max 10 chunks at once

        if mmap.len() <= max_scan_size {
            // Scan entire file at once
            self.scan_bytes_with_file_info(&mmap, 0, path).await
        } else {
            // Scan in overlapping chunks to ensure pattern detection across boundaries
            let mut all_matches = Vec::new();
            let overlap_size = 4096; // 4KB overlap to catch patterns at boundaries
            let mut offset = 0;

            while offset < mmap.len() {
                let end = std::cmp::min(offset + max_scan_size, mmap.len());
                let chunk_data = &mmap[offset..end];

                match self
                    .scan_bytes_with_file_info(chunk_data, offset as u64, path)
                    .await
                {
                    Ok(mut chunk_matches) => {
                        // Filter out duplicate matches from overlapping regions
                        if offset > 0 {
                            chunk_matches.retain(|m| {
                                m.strings
                                    .iter()
                                    .any(|s| s.offset >= offset as u64 + overlap_size as u64)
                            });
                        }
                        all_matches.extend(chunk_matches);
                    }
                    Err(e) => {
                        warn!("Error scanning mmap chunk at offset {}: {}", offset, e);
                    }
                }

                if end == mmap.len() {
                    break;
                }
                offset = end - overlap_size;
            }

            Ok(all_matches)
        }
    }

    /// Scan file using buffered reading (for small files <=1MB)
    async fn scan_file_with_buffered_read(&self, path: &Path) -> Result<Vec<YaraMatch>, YaraError> {
        let chunk_size = self.config.yara.as_ref().unwrap().memory_chunk_size;
        let path_str = path.display().to_string();

        // Open file for reading
        let file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(e) => {
                return Err(YaraError::FileSystemError {
                    path: path.to_path_buf(),
                    kind: match e.kind() {
                        std::io::ErrorKind::PermissionDenied => {
                            FileSystemErrorKind::PermissionDenied
                        }
                        std::io::ErrorKind::NotFound => FileSystemErrorKind::NotFound,
                        _ => FileSystemErrorKind::Other(e.to_string()),
                    },
                    source: Some(e),
                });
            }
        };

        let mut reader = BufReader::with_capacity(chunk_size, file);
        let mut all_matches = Vec::new();
        let mut buffer = vec![0u8; chunk_size];
        let mut total_bytes_read = 0u64;
        let mut chunk_number = 0;

        loop {
            match reader.read(&mut buffer) {
                Ok(0) => {
                    debug!(
                        "Reached end of file after reading {} bytes in {} chunks",
                        total_bytes_read, chunk_number
                    );
                    break; // End of file
                }
                Ok(bytes_read) => {
                    chunk_number += 1;
                    debug!(
                        "Processing buffered chunk {} ({} bytes)",
                        chunk_number, bytes_read
                    );

                    // Scan this chunk
                    let chunk_data = &buffer[..bytes_read];
                    match self
                        .scan_bytes_with_file_info(chunk_data, total_bytes_read, path)
                        .await
                    {
                        Ok(mut chunk_matches) => {
                            debug!(
                                "Found {} matches in buffered chunk {}",
                                chunk_matches.len(),
                                chunk_number
                            );
                            all_matches.append(&mut chunk_matches);
                        }
                        Err(e) => {
                            warn!(
                                "Error scanning buffered chunk {} of {}: {}",
                                chunk_number, path_str, e
                            );
                            // Continue with next chunk instead of failing completely
                        }
                    }

                    total_bytes_read += bytes_read as u64;
                }
                Err(e) => {
                    error!("Error reading file {}: {}", path_str, e);
                    return Err(YaraError::ScanError {
                        target: path.to_path_buf(),
                        kind: ScanErrorKind::ReadError,
                        duration: None,
                    });
                }
            }
        }

        debug!(
            "Buffered file scan completed: {} total matches from {} chunks",
            all_matches.len(),
            chunk_number
        );
        Ok(all_matches)
    }

    /// Calculate SHA-256 hash of a file for deduplication
    async fn calculate_file_hash(&self, path: &Path) -> Result<String, YaraError> {
        let mut file = match tokio::fs::File::open(path).await {
            Ok(file) => file,
            Err(e) => {
                return Err(YaraError::FileSystemError {
                    path: path.to_path_buf(),
                    kind: FileSystemErrorKind::Other(format!(
                        "Failed to open file for hashing: {}",
                        e
                    )),
                    source: Some(e),
                });
            }
        };

        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; 8192]; // 8KB buffer for hashing

        loop {
            match file.read(&mut buffer).await {
                Ok(0) => break, // EOF
                Ok(bytes_read) => {
                    hasher.update(&buffer[..bytes_read]);
                }
                Err(e) => {
                    return Err(YaraError::FileSystemError {
                        path: path.to_path_buf(),
                        kind: FileSystemErrorKind::Other(format!(
                            "Failed to read file for hashing: {}",
                            e
                        )),
                        source: Some(e),
                    });
                }
            }
        }

        let hash_result = hasher.finalize();
        Ok(format!("{:x}", hash_result))
    }

    /// Send detection event via IPC
    async fn send_detection_event(&self, event: YaraDetectionEvent) -> Result<(), YaraError> {
        // Serialize event to JSON
        let json_data = match serde_json::to_string(&event) {
            Ok(json) => json,
            Err(e) => {
                error!("Failed to serialize detection event to JSON: {}", e);
                return Err(YaraError::ScanError {
                    target: "json_serialization".into(),
                    kind: ScanErrorKind::EngineError(format!("JSON serialization failed: {}", e)),
                    duration: None,
                });
            }
        };

        // Create DetectionAlert for IPC
        let detection_alert = crate::detector::DetectionAlert::new(
            format!("yara_detection_{}", chrono::Utc::now().timestamp()),
            event.severity as u8,
            vec!["Review and investigate YARA detection".to_string()], // Evidence vector
            json_data,
        );

        // Send via IPC
        if let Err(e) = crate::ipc::send_signed_alert(&detection_alert).await {
            error!("Failed to send detection alert via IPC: {}", e);
            return Err(YaraError::ScanError {
                target: "ipc_send".into(),
                kind: ScanErrorKind::EngineError(format!("IPC send failed: {}", e)),
                duration: None,
            });
        }

        debug!("Successfully sent detection event via IPC");
        Ok(())
    }

    /// Scan byte data using YARA rules with file information for external variables
    async fn scan_bytes_with_file_info(
        &self,
        data: &[u8],
        base_offset: u64,
        file_path: &Path,
    ) -> Result<Vec<YaraMatch>, YaraError> {
        debug!(
            "Scanning {} bytes with base offset {} for file: {}",
            data.len(),
            base_offset,
            file_path.display()
        );

        // Get current rules from RulesManager
        let rules_bundle = self.rules_manager.get_rules();
        if rules_bundle.is_none() {
            return Err(YaraError::InitializationError {
                message: "YARA rules not loaded".to_string(),
                source: None,
            });
        }

        let bundle = rules_bundle.unwrap();

        // Use yara_x Scanner in spawn_blocking for thread safety
        let rules = bundle.rules.clone();
        let data_vec = data.to_vec();
        let _filename = file_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let _filepath = file_path.display().to_string();

        let scan_result =
            tokio::task::spawn_blocking(move || -> Result<Vec<YaraMatch>, YaraError> {
                let mut scanner = Scanner::new(&rules);
                scanner.set_timeout(std::time::Duration::from_secs(30));

                // External variables removed for compatibility

                match scanner.scan(&data_vec) {
                    Ok(scan_results) => {
                        let mut matches = Vec::new();

                        for rule in scan_results.matching_rules() {
                            let mut strings = Vec::new();

                            for pattern in rule.patterns() {
                                for m in pattern.matches() {
                                    // Adjust offset by base_offset for chunked reading
                                    let range = m.range();
                                    let adjusted_offset = base_offset + range.start as u64;
                                    let length = range.end - range.start;

                                    // Convert matched bytes to hex string representation
                                    let matched_data = &data_vec[range.start..range.end];
                                    let hex_data = matched_data
                                        .iter()
                                        .map(|b| format!("{:02x}", b))
                                        .collect::<String>();

                                    strings.push(MatchString {
                                        identifier: pattern.identifier().to_string(),
                                        offset: adjusted_offset,
                                        length,
                                        data: hex_data,
                                    });
                                }
                            }

                            // Extract metadata from the rule
                            let mut meta = std::collections::HashMap::new();
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
                                meta.insert(key.to_string(), value_str);
                            }

                            matches.push(YaraMatch {
                                rule: rule.identifier().to_string(),
                                strings,
                                meta,
                            });
                        }

                        Ok(matches)
                    }
                    Err(e) => Err(YaraError::ScanError {
                        target: "<memory>".into(),
                        kind: ScanErrorKind::EngineError(e.to_string()),
                        duration: None,
                    }),
                }
            })
            .await;

        let matches = scan_result.map_err(|e| {
            error!("Task join error during YARA scan: {}", e);
            YaraError::ScanError {
                target: "<memory>".into(),
                kind: ScanErrorKind::EngineError(format!("Task execution failed: {}", e)),
                duration: None,
            }
        })?;

        let matches = matches?;
        debug!("Found {} YARA matches", matches.len());
        Ok(matches)
    }

    /// Scan byte data using YARA rules (for memory scanning without file context)
    async fn scan_bytes(&self, data: &[u8], base_offset: u64) -> Result<Vec<YaraMatch>, YaraError> {
        debug!(
            "Scanning {} bytes with base offset {}",
            data.len(),
            base_offset
        );

        // Get current rules from RulesManager
        let rules_bundle = self.rules_manager.get_rules();
        if rules_bundle.is_none() {
            return Err(YaraError::InitializationError {
                message: "YARA rules not loaded".to_string(),
                source: None,
            });
        }

        let bundle = rules_bundle.unwrap();

        // Use yara_x Scanner in spawn_blocking for thread safety
        let rules = bundle.rules.clone();
        let data_vec = data.to_vec();

        let scan_result =
            tokio::task::spawn_blocking(move || -> Result<Vec<YaraMatch>, YaraError> {
                let mut scanner = Scanner::new(&rules);
                scanner.set_timeout(std::time::Duration::from_secs(30));

                // External variables removed for compatibility

                match scanner.scan(&data_vec) {
                    Ok(scan_results) => {
                        let mut matches = Vec::new();

                        for rule in scan_results.matching_rules() {
                            let mut strings = Vec::new();

                            for pattern in rule.patterns() {
                                for m in pattern.matches() {
                                    // Adjust offset by base_offset for chunked reading
                                    let range = m.range();
                                    let adjusted_offset = base_offset + range.start as u64;
                                    let length = range.end - range.start;

                                    // Convert matched bytes to hex string representation
                                    let matched_data = &data_vec[range.start..range.end];
                                    let hex_data = matched_data
                                        .iter()
                                        .map(|b| format!("{:02x}", b))
                                        .collect::<String>();

                                    strings.push(MatchString {
                                        identifier: pattern.identifier().to_string(),
                                        offset: adjusted_offset,
                                        length,
                                        data: hex_data,
                                    });
                                }
                            }

                            // Extract metadata from the rule
                            let mut meta = std::collections::HashMap::new();
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
                                meta.insert(key.to_string(), value_str);
                            }

                            matches.push(YaraMatch {
                                rule: rule.identifier().to_string(),
                                strings,
                                meta,
                            });
                        }

                        Ok(matches)
                    }
                    Err(e) => Err(YaraError::ScanError {
                        target: "<memory>".into(),
                        kind: ScanErrorKind::EngineError(e.to_string()),
                        duration: None,
                    }),
                }
            })
            .await;

        let matches = scan_result.map_err(|e| {
            error!("Task join error during YARA scan: {}", e);
            YaraError::ScanError {
                target: "<memory>".into(),
                kind: ScanErrorKind::EngineError(format!("Task execution failed: {}", e)),
                duration: None,
            }
        })?;

        let matches = matches?;
        debug!("Found {} YARA matches", matches.len());
        Ok(matches)
    }

    /// Get scanning statistics (metrics from RulesManager)
    pub async fn get_stats(&self) -> RulesMetrics {
        self.rules_manager.metrics()
    }

    /// Get information about loaded YARA rules
    pub async fn get_loaded_rules_info(&self) -> HashMap<String, String> {
        let mut info = HashMap::new();
        let metrics = self.rules_manager.metrics();
        info.insert("rules_loaded".to_string(), metrics.rules_loaded.to_string());
        if let Some(last_reload) = metrics.last_reload_at {
            info.insert("last_reload_at".to_string(), last_reload.to_rfc3339());
        }
        if let Some(error) = metrics.last_error {
            info.insert("last_error".to_string(), error);
        }
        info
    }

    /// Get the number of loaded YARA rules
    pub async fn get_rules_count(&self) -> usize {
        self.rules_manager.metrics().rules_loaded
    }

    /// Load YARA rules from directory (alias for load_rules)
    pub async fn load_rules_from_directory(&self, rules_dir: &str) -> Result<usize, YaraError> {
        self.load_rules(rules_dir)
            .await
            .map_err(|e| YaraError::InitializationError {
                message: format!("Failed to load rules: {}", e),
                source: None,
            })
    }

    /// Scan memory data for YARA rule matches
    pub async fn scan_memory(&self, data: &[u8]) -> Result<Vec<String>, YaraError> {
        debug!("Starting YARA scan of {} bytes in memory", data.len());

        // Check if rules are loaded
        if !self.is_loaded().await {
            warn!("YARA rules not loaded, skipping memory scan");
            return Err(YaraError::InitializationError {
                message: "YARA rules not loaded".to_string(),
                source: None,
            });
        }

        match self.scan_bytes(data, 0).await {
            Ok(matches) => {
                let rule_names: Vec<String> = matches.into_iter().map(|m| m.rule).collect();
                debug!("Memory scan found {} rule matches", rule_names.len());
                Ok(rule_names)
            }
            Err(e) => {
                error!("Memory scan failed: {}", e);
                Err(e)
            }
        }
    }

    /// Clear the deduplication cache
    pub async fn clear_dedup_cache(&self) {
        if let Ok(mut cache) = self.dedup_cache.lock() {
            cache.clear();
            debug!("Deduplication cache cleared");
        }
    }
}

// #[cfg(test)]
// mod yara_engine_integration_test;

#[cfg(all(test, feature = "yara"))]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn create_test_config() -> Arc<AgentConfig> {
        let mut config = AgentConfig::default();
        if let Some(ref mut yara_config) = config.yara {
            yara_config.memory_chunk_size = 1024; // 1KB chunks for testing
        }
        Arc::new(config)
    }

    #[tokio::test]
    async fn test_yara_engine_creation() {
        let config = create_test_config();
        let engine = YaraEngine::new(config);
        assert!(!engine.is_loaded().await);
    }

    #[tokio::test]
    async fn test_scan_nonexistent_file() {
        let config = create_test_config();
        let engine = YaraEngine::new(config);

        let result = engine.scan_file(Path::new("/nonexistent/file.txt")).await;
        // Should return error because no rules are loaded
        assert!(result.is_err());
        if let Err(YaraError::InitializationError { message, .. }) = result {
            assert!(message.contains("YARA rules not loaded"));
        } else {
            panic!("Expected InitializationError");
        }
    }

    #[tokio::test]
    async fn test_scan_without_rules() {
        let config = create_test_config();
        let engine = YaraEngine::new(config);

        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "test content").unwrap();

        let result = engine.scan_file(temp_file.path()).await;
        assert!(result.is_err());
        // Should fail because no rules are loaded
    }
}
