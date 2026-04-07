//! Scanning Manager - Orchestrates all scanning operations
//!
//! This module provides the ScanningManager which coordinates different scanners,
//! manages scheduled scans, real-time monitoring, and integrates with the agent's
//! alert system.

use crate::config::{get_scanning_config, validate_scanning_config, AgentConfig};
use crate::metrics::get_metrics;
use crate::scanning::{
    detection_event::{DetectionEvent, ScanResult},
    traits::MalwareScanner,
    yara_scanner::YaraScanner,
};
use anyhow::{Context, Result};
use notify::event::{CreateKind, ModifyKind};
use notify::{Event, EventKind, RecursiveMode, Watcher};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};
use tokio::time::{interval, sleep};

/// Statistics for scanning operations
#[derive(Debug, Clone, Default)]
pub struct ScanningStats {
    pub files_scanned: u64,
    pub threats_detected: u64,
    pub scan_duration_ms: u64,
    pub last_scan_time: Option<std::time::SystemTime>,
    pub active_scanners: usize,
}

/// Manages all scanning operations for the agent
pub struct ScanningManager {
    config: Arc<AgentConfig>,
    scanners: HashMap<String, Arc<dyn MalwareScanner + Send + Sync>>,
    stats: Arc<RwLock<ScanningStats>>,
    detection_tx: Option<mpsc::Sender<DetectionEvent>>,
    shutdown_tx: mpsc::Sender<()>,
    shutdown_rx: mpsc::Receiver<()>,
}

impl ScanningManager {
    /// Create a new scanning manager
    pub async fn new(config: Arc<AgentConfig>) -> Result<Self> {
        let mut config_clone = (*config).clone();
        validate_scanning_config(&mut config_clone)
            .context("Failed to validate scanning configuration")?;

        let scanning_config = get_scanning_config(&config_clone);
        let mut scanners: HashMap<String, Arc<dyn MalwareScanner + Send + Sync>> = HashMap::new();

        // Initialize configured scanners
        for (name, scanner_config) in &scanning_config.scanners {
            if !scanner_config.enabled {
                log::info!("Scanner '{}' is disabled, skipping initialization", name);
                continue;
            }

            match name.as_str() {
                "yara" => {
                    match Self::create_yara_scanner(scanner_config, &scanning_config.global).await {
                        Ok(scanner) => {
                            log::info!("Initialized YARA scanner successfully");
                            scanners.insert(name.clone(), Arc::new(scanner));
                        }
                        Err(e) => {
                            log::error!("Failed to initialize YARA scanner: {}", e);
                            if name == &scanning_config.default_scanner {
                                return Err(e).context("Default scanner failed to initialize");
                            }
                        }
                    }
                }
                _ => {
                    log::warn!("Unknown scanner type: {}", name);
                }
            }
        }

        if scanners.is_empty() {
            anyhow::bail!("No scanners were successfully initialized");
        }

        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);

        Ok(Self {
            config,
            scanners,
            stats: Arc::new(RwLock::new(ScanningStats::default())),
            detection_tx: None,
            shutdown_tx,
            shutdown_rx,
        })
    }

    /// Create YARA scanner from configuration
    async fn create_yara_scanner(
        scanner_config: &crate::config::ScannerConfig,
        global_config: &crate::config::GlobalScanConfig,
    ) -> Result<YaraScanner> {
        let rules_path = scanner_config
            .settings
            .get("rules_path")
            .and_then(|v| v.as_str())
            .unwrap_or("./rules/yara");

        let yara_config = crate::scanning::yara_scanner::YaraScannerConfig {
            rules_path: PathBuf::from(rules_path),
            max_file_size: global_config.max_file_size,
            scan_timeout_secs: global_config.scan_timeout.as_secs(),
            max_concurrent_scans: global_config.concurrent_scans,
            force_scan_extensions: global_config.include_extensions.clone(),
            skip_extensions: global_config.exclude_extensions.clone(),
            ..Default::default()
        };

        YaraScanner::new(&yara_config.rules_path.to_string_lossy())
            .await
            .map_err(anyhow::Error::from)
    }

    /// Set detection event sender
    pub fn set_detection_sender(&mut self, sender: mpsc::Sender<DetectionEvent>) {
        self.detection_tx = Some(sender);
    }

    /// Start monitoring operations
    pub async fn start_monitoring(&mut self) -> Result<()> {
        let scanning_config = get_scanning_config(&self.config);

        // Start real-time monitoring if configured
        if !scanning_config.monitored_directories.is_empty() {
            self.start_realtime_monitoring().await?;
        }

        // Start scheduled scans if configured
        if !scanning_config.scheduled_scans.is_empty() {
            self.start_scheduled_scans().await?;
        }

        // Wait for shutdown signal
        let _ = self.shutdown_rx.recv().await;
        log::info!("Scanning manager shutting down");

        Ok(())
    }

    /// Start real-time file system monitoring
    async fn start_realtime_monitoring(&self) -> Result<()> {
        let scanning_config = get_scanning_config(&self.config);
        let stats = Arc::clone(&self.stats);
        let detection_tx = self.detection_tx.clone();

        for monitored_dir in &scanning_config.monitored_directories {
            if !monitored_dir.enabled {
                continue;
            }

            let path = PathBuf::from(&monitored_dir.path);
            if !path.exists() {
                log::warn!("Monitored directory does not exist: {}", monitored_dir.path);
                continue;
            }

            let scanner_name = monitored_dir
                .scanner
                .as_ref()
                .unwrap_or(&scanning_config.default_scanner)
                .clone();

            if let Some(scanner) = self.scanners.get(&scanner_name) {
                let scanner_clone = Arc::clone(scanner);
                let path_clone = path.clone();
                let stats_clone = Arc::clone(&stats);
                let detection_tx_clone = detection_tx.clone();
                let patterns = monitored_dir.file_patterns.clone();

                tokio::spawn(async move {
                    if let Err(e) = Self::monitor_directory(
                        path_clone,
                        scanner_clone,
                        stats_clone,
                        detection_tx_clone,
                        patterns,
                    )
                    .await
                    {
                        log::error!("Real-time monitoring error: {}", e);
                    }
                });

                log::info!("Started real-time monitoring for: {}", monitored_dir.path);
            } else {
                log::error!(
                    "Scanner '{}' not found for monitoring directory: {}",
                    scanner_name,
                    monitored_dir.path
                );
            }
        }

        Ok(())
    }

    /// Monitor a directory for file changes
    async fn monitor_directory(
        path: PathBuf,
        scanner: Arc<dyn MalwareScanner + Send + Sync>,
        stats: Arc<RwLock<ScanningStats>>,
        detection_tx: Option<mpsc::Sender<DetectionEvent>>,
        _patterns: Vec<String>,
    ) -> Result<()> {
        let (tx, mut rx) = mpsc::channel(1000);

        let mut watcher = notify::recommended_watcher(move |res: notify::Result<Event>| {
            if let Ok(event) = res {
                if let Err(e) = tx.blocking_send(event) {
                    log::error!("Failed to send file event: {}", e);
                }
            }
        })?;

        watcher.watch(&path, RecursiveMode::Recursive)?;
        log::info!("File watcher started for: {}", path.display());

        while let Some(event) = rx.recv().await {
            match event.kind {
                EventKind::Create(CreateKind::File) | EventKind::Modify(ModifyKind::Data(_)) => {
                    for event_path in event.paths {
                        if event_path.is_file() {
                            // Small delay to ensure file is fully written
                            sleep(Duration::from_millis(100)).await;

                            let start_time = Instant::now();
                            match scanner.scan_file(&event_path).await {
                                Ok(result) => {
                                    let duration = start_time.elapsed();

                                    // Update stats
                                    {
                                        let mut stats_guard = stats.write().await;
                                        stats_guard.files_scanned += 1;
                                        stats_guard.scan_duration_ms += duration.as_millis() as u64;

                                        if !result.detections.is_empty() {
                                            stats_guard.threats_detected +=
                                                result.detections.len() as u64;
                                        }
                                    }

                                    // Update global metrics
                                    if let Some(collector) = get_metrics().await {
                                        collector.record_counter("files_scanned_total", 1.0);
                                        collector.record_yara_scan_duration(duration.as_secs_f64());

                                        if !result.detections.is_empty() {
                                            for _ in &result.detections {
                                                collector.increment_threats_detected();
                                            }
                                        }
                                    }

                                    // Send detection events
                                    if let Some(ref tx) = detection_tx {
                                        for detection in &result.detections {
                                            if let Err(e) = tx.send(detection.clone()).await {
                                                log::error!(
                                                    "Failed to send detection event: {}",
                                                    e
                                                );
                                            }
                                        }
                                    }

                                    if !result.detections.is_empty() {
                                        log::warn!(
                                            "Threat detected in real-time scan: {}",
                                            event_path.display()
                                        );
                                    }
                                }
                                Err(e) => {
                                    log::debug!(
                                        "Failed to scan file {}: {}",
                                        event_path.display(),
                                        e
                                    );
                                }
                            }
                        }
                    }
                }
                _ => {} // Ignore other event types
            }
        }

        Ok(())
    }

    /// Start scheduled scans
    async fn start_scheduled_scans(&self) -> Result<()> {
        let scanning_config = get_scanning_config(&self.config);

        for scheduled_scan in &scanning_config.scheduled_scans {
            if !scheduled_scan.enabled {
                continue;
            }

            let scanner_name = &scheduled_scan.scanner;

            if let Some(scanner) = self.scanners.get(scanner_name) {
                let scanner_clone = Arc::clone(scanner);
                let scan_config = scheduled_scan.clone();
                let stats = Arc::clone(&self.stats);
                let detection_tx = self.detection_tx.clone();

                tokio::spawn(async move {
                    Self::run_scheduled_scan(scanner_clone, scan_config, stats, detection_tx).await;
                });

                log::info!("Started scheduled scan: {}", scheduled_scan.name);
            } else {
                log::error!(
                    "Scanner '{}' not found for scheduled scan: {}",
                    scanner_name,
                    scheduled_scan.name
                );
            }
        }

        Ok(())
    }

    /// Run a scheduled scan
    async fn run_scheduled_scan(
        scanner: Arc<dyn MalwareScanner + Send + Sync>,
        scan_config: crate::config::ScheduledScan,
        stats: Arc<RwLock<ScanningStats>>,
        detection_tx: Option<mpsc::Sender<DetectionEvent>>,
    ) {
        // For now, use a default interval of 1 hour since we don't have cron parsing yet
        let mut interval = interval(Duration::from_secs(3600)); // 1 hour

        loop {
            interval.tick().await;

            log::info!("Starting scheduled scan: {}", scan_config.name);
            let start_time = Instant::now();
            let mut total_files: usize = 0;

            for path in &scan_config.paths {
                // Use recursive=true as default since ScheduledScan doesn't have this field
                match scanner.scan_directory(Path::new(path), true).await {
                    Ok(results) => {
                        total_files += results.len();

                        // Send detection events
                        if let Some(ref tx) = detection_tx {
                            for result in results {
                                for detection in &result.detections {
                                    if let Err(e) = tx.send(detection.clone()).await {
                                        log::error!("Failed to send detection event: {}", e);
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        log::error!("Scan failed for path {}: {}", path, e);
                    }
                }
            }

            let duration = start_time.elapsed();
            log::info!(
                "Scheduled scan '{}' completed: {} files in {:?}",
                scan_config.name,
                total_files,
                duration
            );

            // Update statistics
            {
                let mut stats_guard = stats.write().await;
                // Note: ScanningStats doesn't have total_scans field, using files_scanned instead
                // stats_guard.total_scans += 1;
                stats_guard.files_scanned += total_files as u64;
                stats_guard.scan_duration_ms += duration.as_millis() as u64;
            }

            // Update global metrics
            if let Some(collector) = get_metrics().await {
                for _ in 0..total_files {
                    collector.record_counter("files_scanned_total", 1.0);
                }
                collector.record_yara_scan_duration(duration.as_secs_f64());
            }
        }
    }

    /// Scan a specific file with the default scanner
    pub async fn scan_file<P: AsRef<Path>>(&self, path: P) -> Result<ScanResult> {
        let scanning_config = get_scanning_config(&self.config);
        let scanner_name = &scanning_config.default_scanner;

        if let Some(scanner) = self.scanners.get(scanner_name) {
            let start_time = Instant::now();
            let result = scanner.scan_file(path.as_ref()).await?;
            let duration = start_time.elapsed();

            // Update stats
            {
                let mut stats_guard = self.stats.write().await;
                stats_guard.files_scanned += 1;
                stats_guard.scan_duration_ms += duration.as_millis() as u64;
                stats_guard.last_scan_time = Some(std::time::SystemTime::now());

                if !result.detections.is_empty() {
                    stats_guard.threats_detected += result.detections.len() as u64;
                }
            }

            // Update global metrics
            if let Some(collector) = get_metrics().await {
                collector.record_counter("files_scanned_total", 1.0);
                collector.record_yara_scan_duration(duration.as_secs_f64());

                if !result.detections.is_empty() {
                    for _ in &result.detections {
                        collector.increment_threats_detected();
                    }
                }
            }

            Ok(result)
        } else {
            anyhow::bail!("Default scanner '{}' not available", scanner_name);
        }
    }

    /// Scan a directory with the default scanner
    pub async fn scan_directory<P: AsRef<Path>>(
        &self,
        path: P,
        recursive: bool,
    ) -> Result<Vec<ScanResult>> {
        let scanning_config = get_scanning_config(&self.config);
        let scanner_name = &scanning_config.default_scanner;

        if let Some(scanner) = self.scanners.get(scanner_name) {
            let start_time = Instant::now();
            let results = scanner.scan_directory(path.as_ref(), recursive).await?;
            let duration = start_time.elapsed();

            // Update stats
            {
                let mut stats_guard = self.stats.write().await;
                stats_guard.files_scanned += results.len() as u64;
                stats_guard.scan_duration_ms += duration.as_millis() as u64;

                let total_detections: usize = results.iter().map(|r| r.detections.len()).sum();
                stats_guard.threats_detected += total_detections as u64;
            }

            // Update global metrics
            if let Some(collector) = get_metrics().await {
                for _ in &results {
                    collector.increment_files_scanned();
                }
                collector.record_yara_scan_duration(duration.as_secs_f64());

                let total_detections: usize = results.iter().map(|r| r.detections.len()).sum();
                for _ in 0..total_detections {
                    collector.increment_threats_detected();
                }
            }

            Ok(results)
        } else {
            anyhow::bail!("Default scanner '{}' not available", scanner_name);
        }
    }

    /// Get scanning statistics
    pub async fn get_stats(&self) -> ScanningStats {
        self.stats.read().await.clone()
    }

    /// Get available scanners
    pub fn get_available_scanners(&self) -> Vec<String> {
        self.scanners.keys().cloned().collect()
    }

    /// Shutdown the scanning manager
    pub async fn shutdown(&self) -> Result<()> {
        let _ = self.shutdown_tx.send(()).await;
        log::info!("Scanning manager shutdown initiated");
        Ok(())
    }
}

impl Drop for ScanningManager {
    fn drop(&mut self) {
        log::debug!("ScanningManager dropped");
    }
}
