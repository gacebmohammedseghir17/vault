//! YARA File Scanner Module
//!
//! This module provides asynchronous file scanning capabilities using YARA rules
//! with performance monitoring, resource management, and comprehensive error handling.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::fs;
use tokio::sync::{RwLock, Semaphore};
use tokio::time::timeout;
use yara_x::Rules;

use crate::config::yara_config::Config;
use crate::yara::rule_loader::YaraRuleLoader;

/// YARA scan result for a single file
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub file_path: PathBuf,
    pub scan_time: SystemTime,
    pub duration: Duration,
    pub file_size: u64,
    pub matches: Vec<YaraMatch>,
    pub error: Option<String>,
    pub skipped: bool,
    pub skip_reason: Option<String>,
}

/// YARA rule match information
#[derive(Debug, Clone)]
pub struct YaraMatch {
    pub rule_name: String,
    pub namespace: Option<String>,
    pub tags: Vec<String>,
    pub metadata: HashMap<String, String>,
    pub strings: Vec<MatchedString>,
}

/// Matched string information
#[derive(Debug, Clone)]
pub struct MatchedString {
    pub identifier: String,
    pub offset: u64,
    pub length: usize,
    pub data: Vec<u8>,
}

/// Scan statistics and performance metrics
#[derive(Debug, Clone, Default)]
pub struct ScanStatistics {
    pub total_files_scanned: u64,
    pub total_files_skipped: u64,
    pub total_matches_found: u64,
    pub total_scan_time: Duration,
    pub average_scan_time: Duration,
    pub total_bytes_scanned: u64,
    pub files_per_second: f64,
    pub bytes_per_second: f64,
    pub memory_usage_mb: f64,
    pub active_scans: u32,
    pub queue_size: u32,
}

/// YARA file scanner with async capabilities
#[derive(Debug)]
pub struct YaraFileScanner {
    rule_loader: Arc<YaraRuleLoader>,
    config: Arc<Config>,
    scan_semaphore: Arc<Semaphore>,
    statistics: Arc<RwLock<ScanStatistics>>,
    active_scans: Arc<RwLock<HashMap<PathBuf, Instant>>>,
}

impl YaraFileScanner {
    /// Create a new YARA file scanner
    pub fn new(rule_loader: Arc<YaraRuleLoader>, config: Arc<Config>) -> Self {
        let max_concurrent = config.yara.max_concurrent_scans;

        Self {
            rule_loader,
            config,
            scan_semaphore: Arc::new(Semaphore::new(max_concurrent)),
            statistics: Arc::new(RwLock::new(ScanStatistics::default())),
            active_scans: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Scan a single file asynchronously
    pub async fn scan_file<P: AsRef<Path>>(&self, file_path: P) -> Result<ScanResult> {
        let file_path = file_path.as_ref().to_path_buf();
        let start_time = Instant::now();
        let scan_time = SystemTime::now();

        // Acquire semaphore permit to limit concurrent scans
        let _permit = self
            .scan_semaphore
            .acquire()
            .await
            .context("Failed to acquire scan semaphore")?;

        // Track active scan
        {
            let mut active_scans = self.active_scans.write().await;
            active_scans.insert(file_path.clone(), start_time);
        }

        let result = self
            .scan_file_internal(&file_path, scan_time, start_time)
            .await;

        // Remove from active scans
        {
            let mut active_scans = self.active_scans.write().await;
            active_scans.remove(&file_path);
        }

        // Update statistics
        if let Ok(ref scan_result) = result {
            self.update_statistics(scan_result).await;
        }

        result
    }

    /// Internal file scanning implementation
    async fn scan_file_internal(
        &self,
        file_path: &Path,
        scan_time: SystemTime,
        start_time: Instant,
    ) -> Result<ScanResult> {
        // Backpressure check: If system is under high load, throttle scan
        if crate::IS_SYSTEM_UNDER_LOAD.load(std::sync::atomic::Ordering::Relaxed) {
             tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // Check if file should be scanned
        if let Some((skipped, reason)) = self.should_skip_file(file_path).await? {
            if skipped {
                return Ok(ScanResult {
                    file_path: file_path.to_path_buf(),
                    scan_time,
                    duration: start_time.elapsed(),
                    file_size: 0,
                    matches: Vec::new(),
                    error: None,
                    skipped: true,
                    skip_reason: Some(reason),
                });
            }
        }

        // Get file metadata
        let metadata = fs::metadata(file_path)
            .await
            .with_context(|| format!("Failed to get metadata for file: {:?}", file_path))?;

        let file_size = metadata.len();

        // Check file size limit
        if file_size > self.config.max_file_size_bytes() {
            return Ok(ScanResult {
                file_path: file_path.to_path_buf(),
                scan_time,
                duration: start_time.elapsed(),
                file_size,
                matches: Vec::new(),
                error: None,
                skipped: true,
                skip_reason: Some(format!("File too large: {} bytes", file_size)),
            });
        }

        // Check if YARA rules are available
        let rules_arc = self.rule_loader.get_rules();
        let has_rules = {
            let rules_guard = rules_arc.read().unwrap();
            rules_guard.is_some()
        };

        if !has_rules {
            return Ok(ScanResult {
                file_path: file_path.to_path_buf(),
                scan_time,
                duration: start_time.elapsed(),
                file_size,
                matches: Vec::new(),
                error: Some("No YARA rules loaded".to_string()),
                skipped: true,
                skip_reason: Some("No rules available".to_string()),
            });
        }

        // Perform the actual scan with timeout
        let scan_timeout = self.config.scan_timeout();
        let scan_result = timeout(
            scan_timeout,
            self.perform_yara_scan_with_rules(rules_arc, file_path),
        )
        .await;

        let duration = start_time.elapsed();

        match scan_result {
            Ok(Ok(matches)) => Ok(ScanResult {
                file_path: file_path.to_path_buf(),
                scan_time,
                duration,
                file_size,
                matches,
                error: None,
                skipped: false,
                skip_reason: None,
            }),
            Ok(Err(e)) => Ok(ScanResult {
                file_path: file_path.to_path_buf(),
                scan_time,
                duration,
                file_size,
                matches: Vec::new(),
                error: Some(e.to_string()),
                skipped: false,
                skip_reason: None,
            }),
            Err(_) => Ok(ScanResult {
                file_path: file_path.to_path_buf(),
                scan_time,
                duration,
                file_size,
                matches: Vec::new(),
                error: Some("Scan timeout".to_string()),
                skipped: false,
                skip_reason: None,
            }),
        }
    }

    /// Perform the actual YARA scan with rules from Arc
    async fn perform_yara_scan_with_rules(
        &self,
        rules_arc: Arc<std::sync::RwLock<Option<Rules>>>,
        file_path: &Path,
    ) -> Result<Vec<YaraMatch>> {
        // Read file content first
        let content = fs::read(file_path)
            .await
            .with_context(|| format!("Failed to read file: {:?}", file_path))?;

        // Check if rules are available first
        {
            let rules_guard = rules_arc.read().unwrap();
            if rules_guard.is_none() {
                return Err(anyhow::anyhow!("No YARA rules available"));
            }
        }

        // Perform scan with rules and convert matches
        let matches = {
            let rules_guard = rules_arc.read().unwrap();
            let rules = rules_guard.as_ref().unwrap(); // Safe because we checked above

            // Create YARA scanner
            let mut scanner = yara_x::Scanner::new(rules);

            // Set scanner timeout
            scanner.set_timeout(std::time::Duration::from_secs(
                self.config.yara.scan_timeout_seconds,
            ));

            // Perform scan
            let scan_result = scanner
                .scan(&content)
                .map_err(|e| anyhow::anyhow!("YARA scan failed for file {:?}: {}", file_path, e))?;

            // Convert YARA matches to our format
            let mut matches = Vec::new();

            for rule in scan_result.matching_rules() {
                let rule_name = rule.identifier().to_string();
                let namespace = rule.namespace().to_string();
                let tags: Vec<String> = vec!["malware".to_string(), "yara".to_string()]; // Default YARA tags

                // Extract metadata
                let mut metadata = HashMap::new();
                for (key, value) in rule.metadata() {
                    let value_str = match value {
                        yara_x::MetaValue::Integer(i) => i.to_string(),
                        yara_x::MetaValue::Float(f) => f.to_string(),
                        yara_x::MetaValue::Bool(b) => b.to_string(),
                        yara_x::MetaValue::String(s) => s.to_string(),
                        yara_x::MetaValue::Bytes(b) => {
                            // Convert bytes to hex string
                            b.iter()
                                .map(|byte| format!("{:02x}", byte))
                                .collect::<String>()
                        }
                    };
                    metadata.insert(key.to_string(), value_str);
                }

                // Extract matched strings
                let mut strings = Vec::new();
                for pattern in rule.patterns() {
                    for m in pattern.matches() {
                        let range = m.range();
                        let matched_data = content[range.start..range.end].to_vec();

                        strings.push(MatchedString {
                            identifier: pattern.identifier().to_string(),
                            offset: range.start as u64,
                            length: range.end - range.start,
                            data: matched_data,
                        });
                    }
                }

                matches.push(YaraMatch {
                    rule_name,
                    namespace: Some(namespace),
                    tags,
                    metadata,
                    strings,
                });
            }

            matches
        };

        Ok(matches)
    }

    /// Check if a file should be skipped from scanning
    async fn should_skip_file(&self, file_path: &Path) -> Result<Option<(bool, String)>> {
        // Check if file exists
        if !file_path.exists() {
            return Ok(Some((true, "File does not exist".to_string())));
        }

        // Check if it's a directory
        if file_path.is_dir() {
            return Ok(Some((true, "Path is a directory".to_string())));
        }

        // Check if directory is excluded
        if let Some(parent) = file_path.parent() {
            let parent_str = parent.to_string_lossy();
            if self.config.is_directory_excluded(&parent_str) {
                return Ok(Some((true, "Directory is excluded".to_string())));
            }
        }

        // Check file extension
        if let Some(extension) = file_path.extension() {
            let ext_str = format!(".{}", extension.to_string_lossy());
            if !self.config.should_scan_extension(&ext_str) {
                return Ok(Some((true, "File extension not in scan list".to_string())));
            }
        }

        // Check file metadata and size
        match fs::metadata(file_path).await {
            Ok(metadata) => {
                if metadata.len() > self.config.max_file_size_bytes() {
                    return Ok(Some((true, format!("File too large: {} bytes", metadata.len()))));
                }
                // Skip files smaller than 4 bytes (can't even check magic header)
                if metadata.len() < 4 {
                    return Ok(Some((true, "File too small".to_string())));
                }
            },
            Err(e) => return Ok(Some((true, format!("Cannot access file: {}", e)))),
        }

        // Performance Optimization: Magic Header Check
        // Skip common media files and archives that are unlikely to be malware (unless targeted)
        // This avoids scanning huge MP4/ISO/etc. files
        if let Ok(mut file) = fs::File::open(file_path).await {
            let mut buffer = [0u8; 4];
            match tokio::io::AsyncReadExt::read_exact(&mut file, &mut buffer).await {
                Ok(_) => {
                    if self.is_excluded_magic(&buffer) {
                         return Ok(Some((true, format!("Excluded file magic: {:02X?}", buffer))));
                    }
                },
                Err(e) => return Ok(Some((true, format!("Failed to read file header: {}", e)))),
            }
        }

        Ok(Some((false, String::new())))
    }

    /// Check if magic bytes indicate an excluded file type
    fn is_excluded_magic(&self, magic: &[u8; 4]) -> bool {
        // Configurable magic bytes would be better, but hardcoded list is fine for now
        // TODO: Move this to Config
        match magic {
            [0x89, 0x50, 0x4E, 0x47] => true, // PNG
            [0xFF, 0xD8, 0xFF, 0xE0] => true, // JPG
            [0xFF, 0xD8, 0xFF, 0xE1] => true, // JPG
            [0x47, 0x49, 0x46, 0x38] => true, // GIF
            [0x66, 0x74, 0x79, 0x70] => true, // MP4 (ftyp)
            [0x49, 0x44, 0x33, 0x03] => true, // MP3 (ID3)
            [0x00, 0x00, 0x01, 0xBA] => true, // MPEG
            [0x52, 0x49, 0x46, 0x46] => true, // WAV/AVI (RIFF) - careful, some malware uses RIFF? keeping for now
            _ => false,
        }
    }

    /// Scan multiple files concurrently
    pub async fn scan_files<P: AsRef<Path>>(&self, file_paths: Vec<P>) -> Vec<ScanResult> {
        let mut tasks = Vec::new();

        for file_path in file_paths {
            let scanner = self.clone();
            let path = file_path.as_ref().to_path_buf();

            let task = tokio::spawn(async move {
                scanner
                    .scan_file(path)
                    .await
                    .unwrap_or_else(|e| ScanResult {
                        file_path: PathBuf::new(),
                        scan_time: SystemTime::now(),
                        duration: Duration::from_secs(0),
                        file_size: 0,
                        matches: Vec::new(),
                        error: Some(e.to_string()),
                        skipped: true,
                        skip_reason: Some("Task error".to_string()),
                    })
            });

            tasks.push(task);
        }

        let mut results = Vec::new();
        for task in tasks {
            if let Ok(result) = task.await {
                results.push(result);
            }
        }

        results
    }

    /// Scan a directory recursively
    pub async fn scan_directory<P: AsRef<Path>>(
        &self,
        directory: P,
        recursive: bool,
    ) -> Result<Vec<ScanResult>> {
        let directory = directory.as_ref();
        let mut file_paths = Vec::new();

        self.collect_files(directory, recursive, &mut file_paths)
            .await
            .with_context(|| format!("Failed to collect files from directory: {:?}", directory))?;

        log::info!(
            "Scanning {} files from directory: {:?}",
            file_paths.len(),
            directory
        );

        Ok(self.scan_files(file_paths).await)
    }

    /// Recursively collect files from a directory
    fn collect_files<'a>(
        &'a self,
        directory: &'a Path,
        recursive: bool,
        file_paths: &'a mut Vec<PathBuf>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            let mut entries = fs::read_dir(directory)
                .await
                .with_context(|| format!("Failed to read directory: {:?}", directory))?;

            while let Some(entry) = entries
                .next_entry()
                .await
                .with_context(|| format!("Failed to read directory entry in: {:?}", directory))?
            {
                let path = entry.path();

                if path.is_file() {
                    file_paths.push(path);
                } else if path.is_dir() && recursive {
                    // Recursively scan subdirectories
                    if !self.config.is_directory_excluded(&path.to_string_lossy()) {
                        self.collect_files(&path, recursive, file_paths).await?;
                    }
                }
            }

            Ok(())
        })
    }

    /// Update scan statistics
    async fn update_statistics(&self, result: &ScanResult) {
        let mut stats = self.statistics.write().await;

        if result.skipped {
            stats.total_files_skipped += 1;
        } else {
            stats.total_files_scanned += 1;
            stats.total_bytes_scanned += result.file_size;
            stats.total_matches_found += result.matches.len() as u64;
        }

        stats.total_scan_time += result.duration;

        // Calculate averages
        if stats.total_files_scanned > 0 {
            stats.average_scan_time = stats.total_scan_time / stats.total_files_scanned as u32;
            stats.files_per_second =
                stats.total_files_scanned as f64 / stats.total_scan_time.as_secs_f64();
            stats.bytes_per_second =
                stats.total_bytes_scanned as f64 / stats.total_scan_time.as_secs_f64();
        }

        // Update active scans count
        let active_scans = self.active_scans.read().await;
        stats.active_scans = active_scans.len() as u32;
    }

    /// Get current scan statistics
    pub async fn get_statistics(&self) -> ScanStatistics {
        let stats = self.statistics.read().await;
        stats.clone()
    }

    /// Reset scan statistics
    pub async fn reset_statistics(&self) {
        let mut stats = self.statistics.write().await;
        *stats = ScanStatistics::default();
    }

    /// Get active scans information
    pub async fn get_active_scans(&self) -> HashMap<PathBuf, Duration> {
        let active_scans = self.active_scans.read().await;
        let now = Instant::now();

        active_scans
            .iter()
            .map(|(path, start_time)| (path.clone(), now.duration_since(*start_time)))
            .collect()
    }

    /// Check if scanner is ready (has rules loaded)
    pub fn is_ready(&self) -> bool {
        self.rule_loader.is_ready()
    }

    /// Get the number of loaded rules
    pub fn rule_count(&self) -> usize {
        self.rule_loader.rule_count()
    }
}

// Implement Clone for YaraFileScanner to allow sharing between tasks
impl Clone for YaraFileScanner {
    fn clone(&self) -> Self {
        Self {
            rule_loader: Arc::clone(&self.rule_loader),
            config: Arc::clone(&self.config),
            scan_semaphore: Arc::clone(&self.scan_semaphore),
            statistics: Arc::clone(&self.statistics),
            active_scans: Arc::clone(&self.active_scans),
        }
    }
}

/// Create a new YARA file scanner instance
pub fn create_file_scanner(
    rule_loader: Arc<YaraRuleLoader>,
    config: Arc<Config>,
) -> YaraFileScanner {
    YaraFileScanner::new(rule_loader, config)
}
