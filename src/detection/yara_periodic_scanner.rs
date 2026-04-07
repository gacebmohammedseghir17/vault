use crate::config::AgentConfig;
use crate::detection::yara_engine::{YaraEngine, YaraMatchResult};
use crate::detection::yara_events::{helpers, YaraDetectionEvent};
use crate::error::yara_errors::YaraError;
use log::{debug, error, info, warn};
use std::collections::HashMap;

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::RwLock;
use tokio::time::interval;

/// Circuit breaker state for error handling
#[derive(Debug, Clone)]
struct CircuitBreaker {
    failure_count: u32,
    last_failure: Option<Instant>,
    state: CircuitBreakerState,
}

#[derive(Debug, Clone, PartialEq)]
enum CircuitBreakerState {
    Closed,   // Normal operation
    Open,     // Failing, skip operations
    HalfOpen, // Testing if service recovered
}

impl CircuitBreaker {
    fn new() -> Self {
        Self {
            failure_count: 0,
            last_failure: None,
            state: CircuitBreakerState::Closed,
        }
    }

    fn should_allow_request(&self) -> bool {
        match self.state {
            CircuitBreakerState::Closed => true,
            CircuitBreakerState::Open => {
                // Check if enough time has passed to try again
                if let Some(last_failure) = self.last_failure {
                    last_failure.elapsed() > Duration::from_secs(300) // 5 minutes
                } else {
                    true
                }
            }
            CircuitBreakerState::HalfOpen => true,
        }
    }

    fn record_success(&mut self) {
        self.failure_count = 0;
        self.last_failure = None;
        self.state = CircuitBreakerState::Closed;
    }

    fn record_failure(&mut self) {
        self.failure_count += 1;
        self.last_failure = Some(Instant::now());

        if self.failure_count >= 5 {
            self.state = CircuitBreakerState::Open;
        } else if self.state == CircuitBreakerState::HalfOpen {
            self.state = CircuitBreakerState::Open;
        }
    }

    fn try_half_open(&mut self) {
        if self.state == CircuitBreakerState::Open {
            if let Some(last_failure) = self.last_failure {
                if last_failure.elapsed() > Duration::from_secs(300) {
                    self.state = CircuitBreakerState::HalfOpen;
                }
            }
        }
    }
}

/// Periodic YARA scanner for processes and directories
pub struct YaraPeriodicScanner {
    yara_engine: Arc<YaraEngine>,
    config: Arc<RwLock<AgentConfig>>,
    last_process_scan: Arc<RwLock<Instant>>,
    last_directory_scan: Arc<RwLock<Instant>>,
    scanned_files: Arc<RwLock<Vec<String>>>,
    process_circuit_breakers: Arc<RwLock<HashMap<u32, CircuitBreaker>>>,
    directory_circuit_breaker: Arc<RwLock<CircuitBreaker>>,
    stats: Arc<RwLock<ScanStats>>,
    running: Arc<RwLock<bool>>,
}

impl YaraPeriodicScanner {
    /// Create a new periodic scanner
    pub fn new(yara_engine: Arc<YaraEngine>, config: Arc<RwLock<AgentConfig>>) -> Self {
        Self {
            yara_engine,
            config,
            last_process_scan: Arc::new(RwLock::new(Instant::now())),
            last_directory_scan: Arc::new(RwLock::new(Instant::now())),
            scanned_files: Arc::new(RwLock::new(Vec::new())),
            process_circuit_breakers: Arc::new(RwLock::new(HashMap::new())),
            directory_circuit_breaker: Arc::new(RwLock::new(CircuitBreaker::new())),
            stats: Arc::new(RwLock::new(ScanStats::default())),
            running: Arc::new(RwLock::new(false)),
        }
    }

    /// Start the periodic scanning tasks
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let config = self.config.read().await;

        if !config.yara_enabled.unwrap_or(false) {
            info!("YARA periodic scanning is disabled");
            return Ok(());
        }

        info!("Starting YARA periodic scanner");

        // Start process scanning task
        if config.yara_process_scan_enabled.unwrap_or(false) {
            let scanner = self.clone();
            tokio::spawn(async move {
                scanner.process_scan_loop().await;
            });
        }

        // Start directory scanning task
        if config.yara_scan_downloads.unwrap_or(false) {
            let scanner = self.clone();
            tokio::spawn(async move {
                scanner.directory_scan_loop().await;
            });
        }

        Ok(())
    }

    /// Process scanning loop
    async fn process_scan_loop(&self) {
        loop {
            let scan_interval = {
                let config = self.config.read().await;
                Duration::from_secs(config.yara_process_scan_interval_minutes.unwrap_or(5) * 60)
            };

            let mut interval_timer = interval(scan_interval);
            interval_timer.tick().await; // Skip the first immediate tick

            loop {
                interval_timer.tick().await;

                let config = self.config.read().await;
                if !config.yara_enabled.unwrap_or(false)
                    || !config.yara_process_scan_enabled.unwrap_or(false)
                {
                    break;
                }

                if let Err(e) = self.scan_target_processes().await {
                    error!("Error during process scanning: {}", e);
                }
            }
        }
    }

    /// Directory scanning loop
    async fn directory_scan_loop(&self) {
        loop {
            let scan_interval = {
                let config = self.config.read().await;
                Duration::from_secs(config.yara_downloads_scan_interval_minutes.unwrap_or(30) * 60)
            };

            let mut interval_timer = interval(scan_interval);
            interval_timer.tick().await; // Skip the first immediate tick

            loop {
                interval_timer.tick().await;

                let config = self.config.read().await;
                if !config.yara_enabled.unwrap_or(false)
                    || !config.yara_scan_downloads.unwrap_or(false)
                {
                    break;
                }

                if let Err(e) = self.scan_target_directories().await {
                    error!("Error during directory scanning: {}", e);
                }
            }
        }
    }

    /// Scan target processes for malware
    async fn scan_target_processes(
        &self,
    ) -> Result<Vec<YaraMatchResult>, Box<dyn std::error::Error + Send + Sync>> {
        let scan_start = Instant::now();
        let config = self.config.read().await;
        let target_processes = match config.yara_target_processes.clone() {
            Some(processes) => processes,
            None => {
                debug!("No target processes configured");
                return Ok(Vec::new());
            }
        };
        drop(config);

        let mut all_matches = Vec::new();
        let mut stats = self.stats.write().await;

        let running_processes = match self.get_running_processes().await {
            Ok(processes) => processes,
            Err(e) => {
                error!("Failed to get running processes: {}", e);
                stats.scan_errors += 1;
                stats.process_scan_errors += 1;
                stats.consecutive_failures += 1;
                stats.last_error_time = Some(Instant::now());
                return Err(e);
            }
        };
        drop(stats);

        info!(
            "Starting YARA scan of {} target processes",
            target_processes.len()
        );

        for target_process in &target_processes {
            for (pid, process_name) in &running_processes {
                if process_name
                    .to_lowercase()
                    .contains(&target_process.to_lowercase())
                {
                    // Check circuit breaker for this PID
                    let should_scan = {
                        let mut breakers = self.process_circuit_breakers.write().await;
                        let breaker = breakers.entry(*pid).or_insert_with(CircuitBreaker::new);
                        breaker.try_half_open();
                        breaker.should_allow_request()
                    };

                    if !should_scan {
                        debug!(
                            "Circuit breaker open for process {} (PID: {}), skipping scan",
                            process_name, pid
                        );
                        continue;
                    }

                    debug!("Scanning process: {} (PID: {})", process_name, pid);

                    match self.yara_engine.scan_process(*pid).await {
                        Ok(matches) => {
                            // Record success in circuit breaker
                            {
                                let mut breakers = self.process_circuit_breakers.write().await;
                                if let Some(breaker) = breakers.get_mut(pid) {
                                    breaker.record_success();
                                }
                            }

                            if !matches.is_empty() {
                                warn!(
                                    "YARA matches found in process {} (PID: {}): {} matches",
                                    process_name,
                                    pid,
                                    matches.len()
                                );
                                let match_count = matches.len();

                                // Create and send JSON detection event
                                let yara_matches: Vec<crate::detection::yara_engine::YaraMatch> =
                                    matches
                                        .iter()
                                        .map(|yara_match| {
                                            crate::detection::yara_engine::YaraMatch {
                                                rule: yara_match.rule.clone(),
                                                meta: std::collections::HashMap::new(),
                                                strings: Vec::new(),
                                            }
                                        })
                                        .collect();

                                let detection_event = helpers::create_process_detection_event(
                                    *pid,
                                    Some(process_name.clone()),
                                    yara_matches,
                                );

                                // Send detection event via IPC
                                if let Err(e) = self.send_detection_event(detection_event).await {
                                    error!("Failed to send process detection event: {}", e);
                                }

                                // Convert simple matches to detailed matches for backward compatibility
                                for yara_match in matches {
                                    let match_result = YaraMatchResult {
                                        timestamp: SystemTime::now()
                                            .duration_since(std::time::UNIX_EPOCH)
                                            .unwrap()
                                            .as_secs(),
                                        rule_name: yara_match.rule,
                                        target_type: "process".to_string(),
                                        target_path: process_name.clone(),
                                        target_pid: Some(*pid),
                                        match_strings: Vec::new(),
                                        severity: "high".to_string(),
                                        metadata: std::collections::HashMap::new(),
                                    };
                                    all_matches.push(match_result);
                                }

                                // Update stats
                                let mut stats = self.stats.write().await;
                                stats.total_matches_found += match_count as u64;
                            }
                        }
                        Err(e) => {
                            // Record failure in circuit breaker
                            {
                                let mut breakers = self.process_circuit_breakers.write().await;
                                if let Some(breaker) = breakers.get_mut(pid) {
                                    breaker.record_failure();
                                }
                            }

                            // Update error stats based on error type
                            let mut stats = self.stats.write().await;
                            stats.scan_errors += 1;
                            stats.process_scan_errors += 1;
                            stats.last_error_time = Some(Instant::now());

                            match &e {
                                YaraError::SecurityError {
                                    kind:
                                        crate::error::yara_errors::SecurityErrorKind::UnauthorizedAccess,
                                    ..
                                } => {
                                    stats.access_errors += 1;
                                    debug!(
                                        "Access denied scanning process {} (PID: {}): {}",
                                        process_name, pid, e
                                    );
                                }
                                YaraError::TimeoutError { .. } => {
                                    stats.timeout_errors += 1;
                                    warn!(
                                        "Timeout scanning process {} (PID: {}): {}",
                                        process_name, pid, e
                                    );
                                }
                                YaraError::ResourceError {
                                    kind:
                                        crate::error::yara_errors::ResourceErrorKind::MemoryExhausted,
                                    ..
                                } => {
                                    warn!(
                                        "Memory error scanning process {} (PID: {}): {}",
                                        process_name, pid, e
                                    );
                                }
                                _ => {
                                    debug!(
                                        "Failed to scan process {} (PID: {}): {}",
                                        process_name, pid, e
                                    );
                                }
                            }
                        }
                    }

                    // Update process scan count
                    let mut stats = self.stats.write().await;
                    stats.total_processes_scanned += 1;
                }
            }
        }

        // Update scan statistics
        let mut stats = self.stats.write().await;
        *self.last_process_scan.write().await = Instant::now();
        stats.last_scan_duration = scan_start.elapsed();

        if all_matches.is_empty() {
            stats.consecutive_failures = 0; // Reset on successful scan with no errors
        }

        info!(
            "Process scanning completed in {:?}. Total matches: {}",
            scan_start.elapsed(),
            all_matches.len()
        );
        Ok(all_matches)
    }

    /// Scan target directories for malware
    async fn scan_target_directories(
        &self,
    ) -> Result<Vec<YaraMatchResult>, Box<dyn std::error::Error + Send + Sync>> {
        let scan_start = Instant::now();
        let config = self.config.read().await;
        let scan_directories = match config.yara_scan_directories.clone() {
            Some(dirs) => dirs,
            None => {
                debug!("No scan directories configured");
                return Ok(Vec::new());
            }
        };
        let max_file_size = config.yara_max_file_size_mb.unwrap_or(100) * 1024 * 1024; // Convert to bytes
        drop(config);

        let mut all_matches = Vec::new();

        // Check directory circuit breaker
        let should_scan = {
            let mut breaker = self.directory_circuit_breaker.write().await;
            breaker.try_half_open();
            breaker.should_allow_request()
        };

        if !should_scan {
            info!("Directory circuit breaker open, skipping directory scan");
            return Ok(all_matches);
        }

        info!(
            "Starting YARA scan of {} directories",
            scan_directories.len()
        );

        let mut scan_errors = 0;
        for directory in &scan_directories {
            if !Path::new(directory).exists() {
                debug!("Directory does not exist: {}", directory);
                continue;
            }

            match self
                .scan_directory_recursive(directory, max_file_size)
                .await
            {
                Ok(matches) => {
                    if !matches.is_empty() {
                        warn!(
                            "YARA matches found in directory {}: {} matches",
                            directory,
                            matches.len()
                        );
                        let match_count = matches.len();
                        all_matches.extend(matches);

                        // Update match stats
                        let mut stats = self.stats.write().await;
                        stats.total_matches_found += match_count as u64;
                    }
                }
                Err(e) => {
                    scan_errors += 1;
                    error!("Failed to scan directory {}: {}", directory, e);

                    // Update error stats
                    let mut stats = self.stats.write().await;
                    stats.scan_errors += 1;
                    stats.file_scan_errors += 1;
                    stats.last_error_time = Some(Instant::now());

                    // Check if this is a critical error that should trigger circuit breaker
                    if scan_errors > scan_directories.len() / 2 {
                        let mut breaker = self.directory_circuit_breaker.write().await;
                        breaker.record_failure();
                        warn!("Too many directory scan failures, circuit breaker activated");
                        break;
                    }
                }
            }
        }

        // Record success if no major failures
        if scan_errors <= scan_directories.len() / 2 {
            let mut breaker = self.directory_circuit_breaker.write().await;
            breaker.record_success();
        }

        // Update scan statistics
        let mut stats = self.stats.write().await;
        *self.last_directory_scan.write().await = Instant::now();
        stats.last_scan_duration = scan_start.elapsed();

        if scan_errors == 0 {
            stats.consecutive_failures = 0; // Reset on successful scan
        } else {
            stats.consecutive_failures += 1;
        }

        info!(
            "Directory scanning completed in {:?}. Total matches: {}, Errors: {}",
            scan_start.elapsed(),
            all_matches.len(),
            scan_errors
        );
        Ok(all_matches)
    }

    /// Recursively scan a directory
    async fn scan_directory_recursive(
        &self,
        directory: &str,
        max_file_size: u64,
    ) -> Result<Vec<YaraMatchResult>, Box<dyn std::error::Error + Send + Sync>> {
        let mut matches = Vec::new();
        let mut entries = match tokio::fs::read_dir(directory).await {
            Ok(entries) => entries,
            Err(e) => {
                error!("Failed to read directory {}: {}", directory, e);
                return Err(Box::new(e));
            }
        };

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();

            if path.is_dir() {
                // Recursively scan subdirectories with depth limit
                if let Some(path_str) = path.to_str() {
                    // Simple depth check to prevent infinite recursion
                    let depth = path_str.matches(std::path::MAIN_SEPARATOR).count();
                    if depth > 10 {
                        debug!("Skipping deep directory: {} (depth: {})", path_str, depth);
                        continue;
                    }

                    match Box::pin(self.scan_directory_recursive(path_str, max_file_size)).await {
                        Ok(sub_matches) => matches.extend(sub_matches),
                        Err(e) => {
                            debug!("Failed to scan subdirectory {}: {}", path_str, e);
                        }
                    }
                }
            } else if path.is_file() {
                // Check if file was already scanned recently
                let path_str = path.to_string_lossy().to_string();
                {
                    let scanned_files = self.scanned_files.read().await;
                    if scanned_files.iter().any(|f| f == &path_str) {
                        continue;
                    }
                }

                // Check file size and metadata
                let metadata = match entry.metadata().await {
                    Ok(metadata) => metadata,
                    Err(e) => {
                        debug!("Failed to get metadata for {}: {}", path.display(), e);
                        continue;
                    }
                };

                if metadata.len() > max_file_size {
                    debug!(
                        "Skipping large file: {} ({} bytes)",
                        path.display(),
                        metadata.len()
                    );
                    continue;
                }

                // Skip system and hidden files on Windows
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
                    const FILE_ATTRIBUTE_SYSTEM: u32 = 0x4;
                    let attributes = metadata.file_attributes();
                    if (attributes & FILE_ATTRIBUTE_HIDDEN) != 0
                        || (attributes & FILE_ATTRIBUTE_SYSTEM) != 0
                    {
                        debug!("Skipping system/hidden file: {}", path.display());
                        continue;
                    }
                }

                // Scan the file
                match self
                    .yara_engine
                    .scan_file(std::path::Path::new(&path_str))
                    .await
                {
                    Ok(file_matches) => {
                        // Update file scan count
                        {
                            let mut stats = self.stats.write().await;
                            stats.total_files_scanned += 1;
                        }

                        if !file_matches.is_empty() {
                            // Create and send JSON detection event
                            let yara_matches: Vec<crate::detection::yara_engine::YaraMatch> =
                                file_matches
                                    .iter()
                                    .map(|rule_name| crate::detection::yara_engine::YaraMatch {
                                        rule: rule_name.clone(),
                                        meta: std::collections::HashMap::new(),
                                        strings: Vec::new(),
                                    })
                                    .collect();

                            let detection_event =
                                helpers::create_file_detection_event(&path_str, yara_matches);

                            // Send detection event via IPC
                            if let Err(e) = self.send_detection_event(detection_event).await {
                                error!("Failed to send file detection event: {}", e);
                            }

                            // Convert simple matches to detailed matches for backward compatibility
                            for rule_name in file_matches {
                                let match_result = YaraMatchResult {
                                    timestamp: SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap()
                                        .as_secs(),
                                    rule_name,
                                    target_type: "file".to_string(),
                                    target_path: path_str.clone(),
                                    target_pid: None,
                                    match_strings: Vec::new(), // File scanning doesn't provide detailed string matches yet
                                    severity: "high".to_string(),
                                    metadata: std::collections::HashMap::new(),
                                };
                                matches.push(match_result);
                            }
                        }

                        // Mark file as scanned
                        self.scanned_files.write().await.push(path_str);
                    }
                    Err(e) => {
                        // Update error stats based on error type
                        let mut stats = self.stats.write().await;
                        stats.scan_errors += 1;
                        stats.file_scan_errors += 1;
                        stats.last_error_time = Some(Instant::now());

                        match &e {
                            YaraError::FileSystemError { .. } => {
                                stats.access_errors += 1;
                                debug!("File access error scanning file {}: {}", path_str, e);
                            }
                            YaraError::TimeoutError { .. } => {
                                stats.timeout_errors += 1;
                                warn!("Timeout error for file {}: {}", path_str, e);
                            }
                            YaraError::ConfigurationError { .. } => {
                                error!("Configuration error scanning file {}: {}", path_str, e);
                            }
                            _ => {
                                debug!("Failed to scan file {}: {}", path_str, e);
                            }
                        }
                    }
                }
            }
        }

        Ok(matches)
    }

    /// Get list of running processes
    async fn get_running_processes(
        &self,
    ) -> Result<Vec<(u32, String)>, Box<dyn std::error::Error + Send + Sync>> {
        #[cfg(windows)]
        {
            self.get_running_processes_windows().await
        }

        #[cfg(unix)]
        {
            self.get_running_processes_unix().await
        }
    }

    #[cfg(windows)]
    async fn get_running_processes_windows(
        &self,
    ) -> Result<Vec<(u32, String)>, Box<dyn std::error::Error + Send + Sync>> {
        use std::process::Command;

        let output = Command::new("tasklist")
            .args(["/fo", "csv", "/nh"])
            .output()?;

        let output_str = String::from_utf8_lossy(&output.stdout);
        let mut processes = Vec::new();

        for line in output_str.lines() {
            let fields: Vec<&str> = line.split(',').collect();
            if fields.len() >= 2 {
                let process_name = fields[0].trim_matches('"');
                if let Ok(pid) = fields[1].trim_matches('"').parse::<u32>() {
                    processes.push((pid, process_name.to_string()));
                }
            }
        }

        Ok(processes)
    }

    #[cfg(unix)]
    async fn get_running_processes_unix(
        &self,
    ) -> Result<Vec<(u32, String)>, Box<dyn std::error::Error + Send + Sync>> {
        let mut processes = Vec::new();
        let mut entries = tokio::fs::read_dir("/proc").await?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if let Some(filename) = path.file_name() {
                if let Some(filename_str) = filename.to_str() {
                    if let Ok(pid) = filename_str.parse::<u32>() {
                        let comm_path = path.join("comm");
                        if let Ok(process_name) = tokio::fs::read_to_string(&comm_path).await {
                            processes.push((pid, process_name.trim().to_string()));
                        }
                    }
                }
            }
        }

        Ok(processes)
    }

    /// Send detection event via IPC
    async fn send_detection_event(&self, event: YaraDetectionEvent) -> Result<(), anyhow::Error> {
        // Serialize the event to JSON
        let json_data = match serde_json::to_string(&event) {
            Ok(json) => json,
            Err(e) => {
                error!("Failed to serialize detection event to JSON: {}", e);
                return Err(anyhow::Error::from(e));
            }
        };

        // Create a DetectionAlert for the IPC system
        let alert = crate::detector::DetectionAlert::new(
            "yara_detection".to_string(),
            5,          // Default severity
            Vec::new(), // Empty evidence vector
            json_data,
        );

        // Send via IPC
        if let Err(e) = crate::ipc::send_signed_alert(&alert).await {
            error!("Failed to send detection alert via IPC: {}", e);
            return Err(anyhow::Error::from(e));
        }

        debug!("Successfully sent detection event via IPC");
        Ok(())
    }

    /// Get scanning statistics
    pub async fn get_scan_stats(&self) -> ScanStats {
        let last_process_scan = *self.last_process_scan.read().await;
        let last_directory_scan = *self.last_directory_scan.read().await;
        let scanned_files_count = self.scanned_files.read().await.len();
        let stats = self.stats.read().await;

        ScanStats {
            last_process_scan,
            last_directory_scan,
            scanned_files_count,
            total_files_scanned: stats.total_files_scanned,
            total_processes_scanned: stats.total_processes_scanned,
            total_matches_found: stats.total_matches_found,
            last_scan_duration: stats.last_scan_duration,
            scan_errors: stats.scan_errors,
            process_scan_errors: stats.process_scan_errors,
            file_scan_errors: stats.file_scan_errors,
            timeout_errors: stats.timeout_errors,
            access_errors: stats.access_errors,
            last_error_time: stats.last_error_time,
            consecutive_failures: stats.consecutive_failures,
        }
    }

    /// Get current scanning statistics
    pub async fn get_stats(&self) -> ScanStats {
        self.stats.read().await.clone()
    }

    /// Get detailed health information about the scanner
    pub async fn get_health_info(&self) -> ScannerHealthInfo {
        let stats = self.stats.read().await;
        let process_breakers = self.process_circuit_breakers.read().await;
        let directory_breaker = self.directory_circuit_breaker.read().await;

        let failed_processes = process_breakers
            .iter()
            .filter(|(_, breaker)| breaker.state == CircuitBreakerState::Open)
            .count();

        let directory_health = match directory_breaker.state {
            CircuitBreakerState::Closed => "Healthy".to_string(),
            CircuitBreakerState::HalfOpen => "Recovering".to_string(),
            CircuitBreakerState::Open => "Failed".to_string(),
        };

        ScannerHealthInfo {
            is_healthy: stats.consecutive_failures < 3
                && directory_breaker.state != CircuitBreakerState::Open,
            total_scans: stats.total_files_scanned + stats.total_processes_scanned,
            error_rate: if stats.total_files_scanned + stats.total_processes_scanned > 0 {
                stats.scan_errors as f64
                    / (stats.total_files_scanned + stats.total_processes_scanned) as f64
            } else {
                0.0
            },
            failed_processes,
            directory_health,
            last_error: stats.last_error_time,
            consecutive_failures: stats.consecutive_failures,
        }
    }

    /// Reset circuit breakers (for manual recovery)
    pub async fn reset_circuit_breakers(&self) {
        {
            let mut process_breakers = self.process_circuit_breakers.write().await;
            for breaker in process_breakers.values_mut() {
                breaker.record_success();
            }
        }

        {
            let mut directory_breaker = self.directory_circuit_breaker.write().await;
            directory_breaker.record_success();
        }

        info!("All circuit breakers have been reset");
    }

    /// Stop the periodic scanner
    pub async fn stop(&self) {
        *self.running.write().await = false;
        info!("YARA periodic scanner stopped");
    }

    /// Clear the scanned files cache (useful for forcing re-scans)
    pub async fn clear_scanned_files_cache(&self) {
        self.scanned_files.write().await.clear();
        info!("Cleared scanned files cache");
    }
}

impl Clone for YaraPeriodicScanner {
    fn clone(&self) -> Self {
        Self {
            yara_engine: Arc::clone(&self.yara_engine),
            config: Arc::clone(&self.config),
            last_process_scan: Arc::clone(&self.last_process_scan),
            last_directory_scan: Arc::clone(&self.last_directory_scan),
            scanned_files: Arc::clone(&self.scanned_files),
            process_circuit_breakers: Arc::clone(&self.process_circuit_breakers),
            directory_circuit_breaker: Arc::clone(&self.directory_circuit_breaker),
            stats: Arc::clone(&self.stats),
            running: Arc::clone(&self.running),
        }
    }
}

/// Health information about the scanner
#[derive(Debug, Clone)]
pub struct ScannerHealthInfo {
    pub is_healthy: bool,
    pub total_scans: u64,
    pub error_rate: f64,
    pub failed_processes: usize,
    pub directory_health: String,
    pub last_error: Option<Instant>,
    pub consecutive_failures: u32,
}

/// Statistics about scanning operations
#[derive(Debug, Clone)]
pub struct ScanStats {
    pub last_process_scan: Instant,
    pub last_directory_scan: Instant,
    pub scanned_files_count: usize,
    pub total_files_scanned: u64,
    pub total_processes_scanned: u64,
    pub total_matches_found: u64,
    pub last_scan_duration: Duration,
    pub scan_errors: u64,
    pub process_scan_errors: u64,
    pub file_scan_errors: u64,
    pub timeout_errors: u64,
    pub access_errors: u64,
    pub last_error_time: Option<Instant>,
    pub consecutive_failures: u32,
}

impl Default for ScanStats {
    fn default() -> Self {
        let now = Instant::now();
        Self {
            last_process_scan: now,
            last_directory_scan: now,
            scanned_files_count: 0,
            total_files_scanned: 0,
            total_processes_scanned: 0,
            total_matches_found: 0,
            last_scan_duration: Duration::from_secs(0),
            scan_errors: 0,
            process_scan_errors: 0,
            file_scan_errors: 0,
            timeout_errors: 0,
            access_errors: 0,
            last_error_time: None,
            consecutive_failures: 0,
        }
    }
}
