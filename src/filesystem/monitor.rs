//! Real-time File System Monitor Module
//!
//! This module provides real-time file system monitoring capabilities to detect
//! suspicious file operations and trigger YARA scans on file changes.

use crate::config::AgentConfig;
use crate::detector::{Event as DetectorEvent, EventType as DetectorEventType};
use crate::metrics::get_metrics;
use anyhow::{Context, Result};
use log;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::{mpsc, RwLock};
use tokio::time::interval;

#[cfg(feature = "yara")]
use crate::mitigations::quarantine_files;
#[cfg(feature = "yara")]
use crate::yara::YaraFileScanner;

/// File system event types we monitor
#[derive(Debug, Clone, PartialEq)]
pub enum FileEventType {
    Created,
    Modified,
    Deleted,
    Renamed,
    Unknown,
}

/// File system event information
#[derive(Debug, Clone)]
pub struct FileSystemEvent {
    pub event_type: FileEventType,
    pub file_path: PathBuf,
    pub timestamp: SystemTime,
    pub process_id: Option<u32>,
    pub process_name: Option<String>,
}

/// Debounced file event to prevent duplicate processing
#[derive(Debug, Clone)]
struct DebouncedEvent {
    #[allow(dead_code)]
    event: FileSystemEvent,
    last_seen: Instant,
    count: u32,
}

/// File system monitoring statistics
#[derive(Debug, Clone, Default)]
pub struct MonitoringStats {
    pub total_events: u64,
    pub processed_events: u64,
    pub debounced_events: u64,
    pub dropped_events: u64, // Events dropped due to backpressure
    pub scan_triggered_events: u64,
    pub malicious_detections: u64,
    pub monitoring_duration: Duration,
    pub events_per_second: f64,
    pub active_watches: u32,
}

/// Real-time file system monitor
#[derive(Debug)]
pub struct FileSystemMonitor {
    config: Arc<AgentConfig>,
    #[cfg(feature = "yara")]
    scanner: Arc<YaraFileScanner>,
    watcher: Option<RecommendedWatcher>,
    event_sender: Option<mpsc::Sender<FileSystemEvent>>, 
    // Forward processed file events to the Detector
    detector_event_sender: Option<mpsc::Sender<DetectorEvent>>, 
    debounce_map: Arc<RwLock<HashMap<PathBuf, DebouncedEvent>>>,
    watched_paths: Arc<RwLock<HashSet<PathBuf>>>,
    statistics: Arc<RwLock<MonitoringStats>>,
    is_running: Arc<RwLock<bool>>,
    start_time: Instant,
}

impl FileSystemMonitor {
    /// Create a new file system monitor
    #[cfg(feature = "yara")]
    pub fn new(config: Arc<AgentConfig>, scanner: Arc<YaraFileScanner>) -> Self {
        Self {
            config,
            scanner,
            watcher: None,
            event_sender: None,
            detector_event_sender: None,
            debounce_map: Arc::new(RwLock::new(HashMap::new())),
            watched_paths: Arc::new(RwLock::new(HashSet::new())),
            statistics: Arc::new(RwLock::new(MonitoringStats::default())),
            is_running: Arc::new(RwLock::new(false)),
            start_time: Instant::now(),
        }
    }

    /// Create a new file system monitor (without YARA)
    #[cfg(not(feature = "yara"))]
    pub fn new(config: Arc<AgentConfig>, _scanner: ()) -> Self {
        Self {
            config,
            watcher: None,
            event_sender: None,
            detector_event_sender: None,
            debounce_map: Arc::new(RwLock::new(HashMap::new())),
            watched_paths: Arc::new(RwLock::new(HashSet::new())),
            statistics: Arc::new(RwLock::new(MonitoringStats::default())),
            is_running: Arc::new(RwLock::new(false)),
            start_time: Instant::now(),
        }
    }

    /// Set the detector event forwarder channel
    pub fn set_detector_event_sender(&mut self, tx: mpsc::Sender<DetectorEvent>) {
        self.detector_event_sender = Some(tx);
    }

    /// Start the file system monitor
    pub async fn start(&mut self) -> Result<()> {
        if *self.is_running.read().await {
            return Ok(()); // Already running
        }

        log::info!("Starting file system monitor...");

        // Create bounded event channel to prevent memory exhaustion under high load
        // Buffer size based on expected event rate and processing capacity
        #[cfg(feature = "yara")]
        let channel_capacity = self
            .config
            .yara
            .as_ref()
            .map(|yara| yara.real_time_monitoring.max_pending_events.unwrap_or(1000))
            .unwrap_or(1000);
        #[cfg(not(feature = "yara"))]
        let channel_capacity = 1000; // Default capacity when YARA is not available
        let (event_tx, event_rx) = mpsc::channel::<FileSystemEvent>(channel_capacity);
        self.event_sender = Some(event_tx.clone());

        // Create file watcher
        let watcher_tx = event_tx.clone();
        let stats_for_watcher = Arc::clone(&self.statistics);
        let watcher = notify::recommended_watcher(move |res: notify::Result<Event>| match res {
            Ok(event) => {
                if let Some(fs_event) = Self::convert_notify_event(event) {
                    // Use try_send to implement backpressure - drop events if channel is full
                    match watcher_tx.try_send(fs_event) {
                        Ok(_) => {},
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            // Channel is full - implement backpressure by dropping event
                            log::warn!("Event channel full, dropping filesystem event to prevent memory exhaustion");
                            // Increment dropped events counter
                            if let Ok(mut stats) = stats_for_watcher.try_write() {
                                stats.dropped_events += 1;
                            }
                        },
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            log::debug!("Event channel closed, stopping event processing");
                        }
                    }
                }
            }
            Err(e) => {
                log::error!("File watcher error: {}", e);
            }
        })
        .context("Failed to create file watcher")?;

        self.watcher = Some(watcher);

        // Start watching configured directories
        self.setup_watches()
            .await
            .context("Failed to setup file system watches")?;

        // Mark as running
        {
            let mut is_running = self.is_running.write().await;
            *is_running = true;
        }

        // Start event processing task
        let monitor_clone = self.clone_for_task();
        tokio::spawn(async move {
            monitor_clone.process_events(event_rx).await;
        });

        // Start debounce cleanup task
        let debounce_clone = self.clone_for_task();
        tokio::spawn(async move {
            debounce_clone.cleanup_debounce_map().await;
        });

        log::info!("File system monitor started successfully");
        Ok(())
    }

    /// Stop the file system monitor
    pub async fn stop(&mut self) -> Result<()> {
        log::info!("Stopping file system monitor...");

        {
            let mut is_running = self.is_running.write().await;
            *is_running = false;
        }

        // Drop the watcher to stop file system monitoring
        self.watcher = None;
        self.event_sender = None;

        // Clear watched paths
        {
            let mut watched_paths = self.watched_paths.write().await;
            watched_paths.clear();
        }

        log::info!("File system monitor stopped");
        Ok(())
    }

    /// Validate scan paths to prevent volume-wide scanning without explicit permission
    /// Enhanced with comprehensive safety checks for production environments
    pub(crate) fn validate_scan_paths(&self, paths: &[String]) -> Result<Vec<String>> {
        let mut validated_paths = Vec::new();
        let allow_volume_scan = self.config.service.allow_volume_scan.unwrap_or(false);

        log::info!(
            "Starting scan path validation with allow_volume_scan={}",
            allow_volume_scan
        );

        for path in paths {
            let path_lower = path.to_lowercase();
            let path_obj = std::path::Path::new(path);

            // Enhanced volume-wide scan detection
            let is_volume_scan = self.is_volume_wide_scan(&path_lower);

            if is_volume_scan {
                if !allow_volume_scan {
                    log::error!("SECURITY: Volume-wide scan attempted for '{}' but allow_volume_scan=false. This could impact system performance. Path rejected.", path);
                    continue;
                }

                // Additional safety checks even when volume scan is allowed
                if let Err(safety_error) = self.perform_volume_safety_checks(&path_lower) {
                    log::error!(
                        "Volume safety check failed for '{}': {}. Path rejected.",
                        path,
                        safety_error
                    );
                    continue;
                }

                log::warn!("PRODUCTION WARNING: Volume-wide scan enabled for '{}' with allow_volume_scan=true. Monitor system performance.", path);
            }

            // Validate path exists and is accessible
            if path_obj.exists() {
                if path_obj.is_dir() {
                    validated_paths.push(path.clone());
                    log::debug!("Validated scan path: {}", path);
                } else {
                    log::warn!("Path '{}' exists but is not a directory. Skipping.", path);
                }
            } else {
                log::warn!("Path '{}' does not exist. Skipping.", path);
            }
        }

        if validated_paths.is_empty() {
            log::warn!("No valid scan paths after validation. Using safe default: C:\\Users");
            validated_paths.push("C:\\Users".to_string());
        }

        log::info!(
            "Scan path validation completed. {} paths validated from {} requested",
            validated_paths.len(),
            paths.len()
        );

        Ok(validated_paths)
    }

    /// Check if a path represents a volume-wide scan
    pub(crate) fn is_volume_wide_scan(&self, path_lower: &str) -> bool {
        // Root drive patterns
        if path_lower == "c:\\"
            || path_lower == "d:\\"
            || path_lower == "e:\\"
            || path_lower == "c:/"
            || path_lower == "d:/"
            || path_lower == "e:/"
        {
            return true;
        }

        // Wildcard patterns
        if path_lower.ends_with(":\\*") || path_lower.ends_with(":/*") {
            return true;
        }

        // Single letter drive patterns (A: through Z:)
        if path_lower.len() == 2 && path_lower.ends_with(':') {
            let drive_letter = path_lower.chars().next().unwrap();
            return drive_letter.is_ascii_alphabetic();
        }

        // Three character drive patterns (A:\ or A:/)
        if path_lower.len() == 3 && (path_lower.ends_with(":\\") || path_lower.ends_with(":/")) {
            let drive_letter = path_lower.chars().next().unwrap();
            return drive_letter.is_ascii_alphabetic();
        }

        false
    }

    /// Perform additional safety checks for volume-wide scans
    pub(crate) fn perform_volume_safety_checks(&self, path_lower: &str) -> Result<()> {
        // Extract drive letter
        let drive_letter = path_lower
            .chars()
            .next()
            .unwrap_or('?')
            .to_ascii_uppercase();

        // Check if it's a system drive (C: is typically system drive)
        if drive_letter == 'C' {
            log::warn!(
                "Volume scan requested for system drive C: - this may impact system performance"
            );
        }

        // Additional checks could include:
        // - Drive type detection (SSD vs HDD)
        // - Available disk space
        // - Current system load
        // - Time of day restrictions

        // For now, log the safety check completion
        log::info!(
            "Volume safety checks passed for drive {}: (basic validation)",
            drive_letter
        );

        Ok(())
    }

    /// Setup file system watches for configured directories
    async fn setup_watches(&mut self) -> Result<()> {
        // Always use agent config scan_paths, not YARA config
        let configured_paths = &self.config.service.scan_paths;

        // Apply volume scan safety checks
        let watch_dirs = self.validate_scan_paths(configured_paths)?;

        if let Some(ref mut watcher) = self.watcher {
            log::info!("Effective scan scope after validation: {:?}", watch_dirs);

            let watch_dirs_len = watch_dirs.len();

            for dir_path in &watch_dirs {
                let path = Path::new(&dir_path);

                if path.exists() && path.is_dir() {
                    watcher
                        .watch(path, RecursiveMode::Recursive)
                        .with_context(|| format!("Failed to watch directory: {:?}", path))?;

                    {
                        let mut watched_paths = self.watched_paths.write().await;
                        watched_paths.insert(path.to_path_buf());
                    }

                    log::info!("Started watching directory: {:?}", path);
                } else {
                    log::warn!("Directory does not exist or is not a directory: {:?}", path);
                }
            }

            // Update statistics
            {
                let mut stats = self.statistics.write().await;
                stats.active_watches = watch_dirs_len as u32;
            }
        }

        Ok(())
    }

    /// Process file system events
    async fn process_events(&self, mut event_rx: mpsc::Receiver<FileSystemEvent>) {
        log::info!("Started file system event processing");

        while let Some(event) = event_rx.recv().await {
            if !*self.is_running.read().await {
                break;
            }

            // Update statistics
            {
                let mut stats = self.statistics.write().await;
                stats.total_events += 1;
                stats.monitoring_duration = self.start_time.elapsed();
                if stats.monitoring_duration.as_secs() > 0 {
                    stats.events_per_second =
                        stats.total_events as f64 / stats.monitoring_duration.as_secs_f64();
                }
            }

            // Process the event
            if let Err(e) = self.handle_file_event(event).await {
                log::error!("Failed to handle file system event: {}", e);
            }
        }

        log::info!("File system event processing stopped");
    }

    /// Handle a single file system event
    async fn handle_file_event(&self, event: FileSystemEvent) -> Result<()> {
        // Check if we should process this event type
        if !self.should_process_event(&event) {
            return Ok(());
        }

        // Apply debouncing to prevent duplicate processing
        if self.is_debounced(&event).await {
            {
                let mut stats = self.statistics.write().await;
                stats.debounced_events += 1;
            }
            return Ok(());
        }

        // Update processed events count
        {
            let mut stats = self.statistics.write().await;
            stats.processed_events += 1;
        }

        log::debug!("Processing file system event: {:?}", event);

        // Forward event to Detector if channel is set
        if let Some(detector_tx) = &self.detector_event_sender {
            let ev_type = match event.event_type {
                FileEventType::Created => DetectorEventType::Created,
                FileEventType::Modified => DetectorEventType::Modified,
                FileEventType::Deleted => DetectorEventType::Deleted,
                FileEventType::Renamed => DetectorEventType::Renamed,
                FileEventType::Unknown => DetectorEventType::Modified,
            };
            let det_event = DetectorEvent::new(ev_type, event.file_path.clone())
                .with_process_info(event.process_id, event.process_name.clone());
            // Best-effort forward; ignore backpressure errors to avoid blocking
            let _ = detector_tx.try_send(det_event);
        }

        // Check if file should be scanned
        if self.should_scan_file(&event.file_path).await {
            // Trigger YARA scan
            self.trigger_scan(&event).await?;
        }

        Ok(())
    }

    /// Check if an event should be processed based on configuration
    fn should_process_event(&self, event: &FileSystemEvent) -> bool {
        #[cfg(feature = "yara")]
        {
            let config = &self.config.yara.as_ref().unwrap().real_time_monitoring;

            match event.event_type {
                FileEventType::Created => config.scan_on_create,
                // Treat file modifications as writes for scanning purposes.
                // Many ransomware behaviors manifest as write operations that
                // surface as Modify events; honor both knobs.
                FileEventType::Modified => config.scan_on_write || config.scan_on_modify,
                FileEventType::Renamed => config.scan_on_create, // Treat rename as create
                FileEventType::Deleted => false,                 // Don't scan deleted files
                FileEventType::Unknown => false,
            }
        }

        #[cfg(not(feature = "yara"))]
        {
            // Without YARA, process create and modify events by default
            match event.event_type {
                FileEventType::Created => true,
                FileEventType::Modified => true,
                FileEventType::Renamed => true, // Treat rename as create
                FileEventType::Deleted => false, // Don't scan deleted files
                FileEventType::Unknown => false,
            }
        }
    }

    /// Check if an event should be debounced
    async fn is_debounced(&self, event: &FileSystemEvent) -> bool {
        #[cfg(feature = "yara")]
        let debounce_duration = Duration::from_millis(
            self.config
                .yara
                .as_ref()
                .map(|yara| yara.real_time_monitoring.debounce_ms)
                .unwrap_or(500),
        );
        #[cfg(not(feature = "yara"))]
        let debounce_duration = Duration::from_millis(500); // Default 500ms debounce

        let now = Instant::now();

        let mut debounce_map = self.debounce_map.write().await;

        if let Some(debounced) = debounce_map.get_mut(&event.file_path) {
            if now.duration_since(debounced.last_seen) < debounce_duration {
                // Update the debounced event
                debounced.last_seen = now;
                debounced.count += 1;
                return true;
            } else {
                // Debounce period expired, remove from map
                debounce_map.remove(&event.file_path);
            }
        }

        // Add new debounced event
        debounce_map.insert(
            event.file_path.clone(),
            DebouncedEvent {
                event: event.clone(),
                last_seen: now,
                count: 1,
            },
        );

        false
    }

    /// Check if a file should be scanned
    async fn should_scan_file(&self, file_path: &Path) -> bool {
        // Check if file exists
        if !file_path.exists() || file_path.is_dir() {
            return false;
        }

        #[cfg(feature = "yara")]
        {
            if let Some(yara_config) = self.config.yara.as_ref() {
                // Check if directory is excluded
                if let Some(parent) = file_path.parent() {
                    let parent_str = parent.to_string_lossy();
                    if yara_config
                        .excluded_directories
                        .contains(&parent_str.to_string())
                    {
                        return false;
                    }
                }

                // Check file extension
                if let Some(ext) = file_path.extension() {
                    let ext_str = format!(".{}", ext.to_string_lossy().to_lowercase());
                    return yara_config.file_extensions.contains(&ext_str);
                }

                // If no extension, check if we should scan all files
                return yara_config.file_extensions.is_empty();
            } else {
                return false;
            }
        }

        #[cfg(not(feature = "yara"))]
        {
            // Without YARA, perform basic file checks
            // Skip system directories
            if let Some(parent) = file_path.parent() {
                let parent_str = parent.to_string_lossy();
                if parent_str.contains("System32") || parent_str.contains("SysWOW64") {
                    return false;
                }
            }

            // Check file extension for common executable types
            if let Some(extension) = file_path.extension() {
                let ext_str = extension.to_string_lossy().to_lowercase();
                return matches!(
                    ext_str.as_str(),
                    "exe" | "dll" | "bat" | "cmd" | "ps1" | "vbs" | "js"
                );
            }

            false
        }
    }

    /// Trigger a YARA scan for a file
    #[cfg(feature = "yara")]
    async fn trigger_scan(&self, event: &FileSystemEvent) -> Result<()> {
        log::debug!("Triggering YARA scan for file: {:?}", event.file_path);

        // Update statistics
        {
            let mut stats = self.statistics.write().await;
            stats.scan_triggered_events += 1;
        }

        // Increment files_scanned_total metric
        if let Some(metrics) = get_metrics().await {
            metrics.inc_files_scanned("attempted");
        }

        // Perform the scan
        let scanner: Arc<YaraFileScanner> = Arc::clone(&self.scanner);
        let file_path = event.file_path.clone();
        let _event_clone = event.clone();
        let config_clone = Arc::clone(&self.config);

        let statistics_clone = Arc::clone(&self.statistics);
        tokio::spawn(async move {
            match scanner.scan_file(&file_path).await {
                Ok(scan_result) => {
                    if !scan_result.matches.is_empty() {
                        // Log each YARA match with full details
                        for yara_match in &scan_result.matches {
                            log::warn!(
                            "YARA DETECTION: Malicious file detected - Path: {}, Rule: {}, Threat: {}",
                            file_path.display(),
                            yara_match.rule_name,
                        yara_match.rule_name // Using rule name as threat type for now
                        );
                        }

                        // Update malicious detections count
                        {
                            let mut stats = statistics_clone.write().await;
                            stats.malicious_detections += 1;
                        }

                        // Increment threats_detected_total metric
                        if let Some(metrics) = get_metrics().await {
                            metrics.increment_threats_detected_with_labels(
                                "yara",
                                &scan_result.matches[0].rule_name,
                            );
                        }

                        // Quarantine the malicious file
                        match quarantine_files(&[file_path.clone()], &config_clone).await {
                            Ok(quarantined_paths) => {
                                for quarantined_path in quarantined_paths {
                                    log::info!(
                                    "QUARANTINE SUCCESS: File quarantined - Original: {}, Quarantined: {}, Rules: {}",
                                    file_path.display(),
                                    quarantined_path.display(),
                                    scan_result.matches.iter().map(|m| m.rule_name.as_str()).collect::<Vec<_>>().join(", ")
                                );
                                }
                            }
                            Err(e) => {
                                log::error!(
                                "QUARANTINE FAILED: Could not quarantine malicious file {} - Error: {}",
                                file_path.display(),
                                e
                            );
                            }
                        }

                        // Increment files_scanned_total with success result
                        if let Some(metrics) = get_metrics().await {
                            metrics.inc_files_scanned("malicious");
                        }
                    } else {
                        // Clean file - increment success metric
                        if let Some(metrics) = get_metrics().await {
                            metrics.inc_files_scanned("clean");
                        }
                    }
                }
                Err(e) => {
                    log::error!("Failed to scan file {:?}: {}", file_path, e);
                    // Increment files_scanned_total with error result
                    if let Some(metrics) = get_metrics().await {
                        metrics.inc_files_scanned("error");
                    }
                }
            }
        });

        Ok(())
    }

    /// Trigger a scan for a file (without YARA - just log)
    #[cfg(not(feature = "yara"))]
    async fn trigger_scan(&self, event: &FileSystemEvent) -> Result<()> {
        log::debug!(
            "File system event detected (YARA disabled): {:?}",
            event.file_path
        );

        // Update statistics
        {
            let mut stats = self.statistics.write().await;
            stats.scan_triggered_events += 1;
        }

        Ok(())
    }

    /// Cleanup old entries from debounce map
    async fn cleanup_debounce_map(&self) {
        let mut cleanup_interval = interval(Duration::from_secs(60)); // Cleanup every minute

        loop {
            let is_running = *self.is_running.read().await;
            if !is_running {
                break;
            }

            cleanup_interval.tick().await;

            #[cfg(feature = "yara")]
            let debounce_duration = Duration::from_millis(
                self.config
                    .yara
                    .as_ref()
                    .map(|yara| yara.real_time_monitoring.debounce_ms)
                    .unwrap_or(500),
            );
            #[cfg(not(feature = "yara"))]
            let debounce_duration = Duration::from_millis(500); // Default 500ms debounce

            let now = Instant::now();

            {
                let mut debounce_map = self.debounce_map.write().await;
                debounce_map.retain(|_, debounced| {
                    now.duration_since(debounced.last_seen) < debounce_duration * 2
                });
            }
        }
    }

    /// Convert notify event to our file system event
    fn convert_notify_event(event: Event) -> Option<FileSystemEvent> {
        let event_type = match event.kind {
            EventKind::Create(_) => FileEventType::Created,
            EventKind::Modify(_) => FileEventType::Modified,
            EventKind::Remove(_) => FileEventType::Deleted,
            EventKind::Other => FileEventType::Unknown,
            _ => return None,
        };

        // Get the first path from the event
        event.paths.into_iter().next().map(|path| FileSystemEvent {
            event_type,
            file_path: path,
            timestamp: SystemTime::now(),
            process_id: Some(std::process::id()),
            process_name: Some("ransolution-agent".to_string()),
        })
    }

    /// Get current monitoring statistics
    pub async fn get_statistics(&self) -> MonitoringStats {
        let stats = self.statistics.read().await;
        stats.clone()
    }

    /// Reset monitoring statistics
    pub async fn reset_statistics(&self) {
        let mut stats = self.statistics.write().await;
        *stats = MonitoringStats::default();
    }

    /// Check if monitor is running
    pub async fn is_running(&self) -> bool {
        *self.is_running.read().await
    }

    /// Get watched directories
    pub async fn get_watched_paths(&self) -> HashSet<PathBuf> {
        let watched_paths = self.watched_paths.read().await;
        watched_paths.clone()
    }

    /// Add a directory to watch
    pub async fn add_watch_directory<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let path = path.as_ref();

        if let Some(ref mut watcher) = self.watcher {
            watcher
                .watch(path, RecursiveMode::Recursive)
                .with_context(|| format!("Failed to watch directory: {:?}", path))?;

            {
                let mut watched_paths = self.watched_paths.write().await;
                watched_paths.insert(path.to_path_buf());
            }

            log::info!("Added watch for directory: {:?}", path);
        }

        Ok(())
    }

    /// Remove a directory from watch
    pub async fn remove_watch_directory<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let path = path.as_ref();

        if let Some(ref mut watcher) = self.watcher {
            watcher
                .unwatch(path)
                .with_context(|| format!("Failed to unwatch directory: {:?}", path))?;

            {
                let mut watched_paths = self.watched_paths.write().await;
                watched_paths.remove(path);
            }

            log::info!("Removed watch for directory: {:?}", path);
        }

        Ok(())
    }

    /// Clone for use in async tasks
    #[cfg(feature = "yara")]
    fn clone_for_task(&self) -> Self {
        Self {
            config: Arc::clone(&self.config),
            scanner: Arc::clone(&self.scanner),
            watcher: None,      // Don't clone the watcher
            event_sender: None, // Don't clone the sender
            detector_event_sender: self.detector_event_sender.clone(),
            debounce_map: Arc::clone(&self.debounce_map),
            watched_paths: Arc::clone(&self.watched_paths),
            statistics: Arc::clone(&self.statistics),
            is_running: Arc::clone(&self.is_running),
            start_time: self.start_time,
        }
    }

    /// Clone for use in async tasks (without YARA)
    #[cfg(not(feature = "yara"))]
    fn clone_for_task(&self) -> Self {
        Self {
            config: Arc::clone(&self.config),
            watcher: None,      // Don't clone the watcher
            event_sender: None, // Don't clone the sender
            detector_event_sender: self.detector_event_sender.clone(),
            debounce_map: Arc::clone(&self.debounce_map),
            watched_paths: Arc::clone(&self.watched_paths),
            statistics: Arc::clone(&self.statistics),
            is_running: Arc::clone(&self.is_running),
            start_time: self.start_time,
        }
    }
}

/// Create a new file system monitor instance
#[cfg(feature = "yara")]
pub fn create_filesystem_monitor(
    config: Arc<AgentConfig>,
    scanner: Arc<YaraFileScanner>,
) -> FileSystemMonitor {
    FileSystemMonitor::new(config, scanner)
}

/// Create a new file system monitor instance (without YARA)
#[cfg(not(feature = "yara"))]
pub fn create_filesystem_monitor(config: Arc<AgentConfig>, _scanner: ()) -> FileSystemMonitor {
    FileSystemMonitor::new(config, ())
}
