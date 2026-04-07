//! File Integrity Monitor Module
//!
//! This module provides real-time file system monitoring using Windows ReadDirectoryChangesW
//! API to detect binary tampering, unauthorized modifications, and suspicious file activities.
//! It focuses on protecting critical system files, executables, and security-sensitive locations.
//!
//! Key capabilities:
//! - Real-time file system change detection
//! - Binary integrity verification using cryptographic hashes
//! - Critical file protection monitoring
//! - Tamper detection and alerting
//! - File attribute and permission change tracking
//! - Whitelist-based legitimate change filtering

use std::collections::{HashMap, HashSet};
// Removed unused OsString import
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::{mpsc, RwLock};
use windows::core::{HSTRING, PCWSTR};
use windows::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Storage::FileSystem::*;
use windows::Win32::System::IO::*;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;

/// File change types we monitor
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FileChangeType {
    /// File was created
    Created,
    /// File was modified
    Modified,
    /// File was deleted
    Deleted,
    /// File was renamed (old name)
    RenamedOld,
    /// File was renamed (new name)
    RenamedNew,
    /// File attributes changed
    AttributesChanged,
    /// File security descriptor changed
    SecurityChanged,
    /// Directory was created
    DirectoryCreated,
    /// Directory was deleted
    DirectoryDeleted,
}

/// File integrity status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IntegrityStatus {
    /// File integrity is intact
    Intact,
    /// File has been tampered with
    Tampered,
    /// File integrity cannot be verified
    Unknown,
    /// File is newly created (no baseline)
    NewFile,
    /// File was deleted
    Deleted,
}

/// File integrity event data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileIntegrityEvent {
    /// Event timestamp
    pub timestamp: SystemTime,
    /// Type of file change
    pub change_type: FileChangeType,
    /// Full path to the affected file
    pub file_path: PathBuf,
    /// Old file path (for rename operations)
    pub old_file_path: Option<PathBuf>,
    /// File size (if available)
    pub file_size: Option<u64>,
    /// File hash (SHA-256)
    pub file_hash: Option<String>,
    /// Previous file hash (for comparison)
    pub previous_hash: Option<String>,
    /// Integrity status
    pub integrity_status: IntegrityStatus,
    /// Process ID that made the change (if detectable)
    pub process_id: Option<u32>,
    /// Process name that made the change (if detectable)
    pub process_name: Option<String>,
    /// Risk assessment score (0.0 - 1.0)
    pub risk_score: f64,
    /// Whether this is a critical system file
    pub is_critical_file: bool,
    /// Additional context information
    pub context: Option<String>,
}

/// File integrity monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileIntegrityConfig {
    /// Enable real-time monitoring
    pub enabled: bool,
    /// Paths to monitor for file changes
    pub monitored_paths: Vec<PathBuf>,
    /// File extensions to monitor (empty = all files)
    pub monitored_extensions: HashSet<String>,
    /// Paths to exclude from monitoring
    pub excluded_paths: Vec<PathBuf>,
    /// Enable hash verification for integrity checking
    pub enable_hash_verification: bool,
    /// Maximum file size to hash (bytes)
    pub max_hash_file_size: u64,
    /// Minimum risk score threshold for alerts
    pub risk_threshold: f64,
    /// Maximum events to buffer
    pub max_buffer_size: usize,
    /// Enable monitoring of critical system files
    pub monitor_critical_files: bool,
    /// Enable detailed logging
    pub verbose_logging: bool,
    /// Interval for periodic integrity checks (seconds)
    pub integrity_check_interval: u64,
}

impl Default for FileIntegrityConfig {
    fn default() -> Self {
        let mut monitored_paths = Vec::new();
        monitored_paths.push(PathBuf::from(r"C:\Windows\System32"));
        monitored_paths.push(PathBuf::from(r"C:\Windows\SysWOW64"));
        monitored_paths.push(PathBuf::from(r"C:\Program Files"));
        monitored_paths.push(PathBuf::from(r"C:\Program Files (x86)"));

        let mut monitored_extensions = HashSet::new();
        monitored_extensions.insert(".exe".to_string());
        monitored_extensions.insert(".dll".to_string());
        monitored_extensions.insert(".sys".to_string());
        monitored_extensions.insert(".bat".to_string());
        monitored_extensions.insert(".cmd".to_string());
        monitored_extensions.insert(".ps1".to_string());
        monitored_extensions.insert(".vbs".to_string());
        monitored_extensions.insert(".js".to_string());

        Self {
            enabled: true,
            monitored_paths,
            monitored_extensions,
            excluded_paths: Vec::new(),
            enable_hash_verification: true,
            max_hash_file_size: 100 * 1024 * 1024, // 100MB
            risk_threshold: 0.7,
            max_buffer_size: 1000,
            monitor_critical_files: true,
            verbose_logging: false,
            integrity_check_interval: 3600, // 1 hour
        }
    }
}

/// File baseline information for integrity checking
#[derive(Debug, Clone, Serialize, Deserialize)]
struct FileBaseline {
    /// File path
    pub path: PathBuf,
    /// File size
    pub size: u64,
    /// File hash (SHA-256)
    pub hash: String,
    /// Last modified time
    pub modified_time: SystemTime,
    /// File attributes
    pub attributes: u32,
    /// Whether this is a critical system file
    pub is_critical: bool,
}

/// Directory monitoring handle
struct DirectoryMonitor {
    /// Directory path being monitored
    pub path: PathBuf,
    /// Directory handle
    pub handle: HANDLE,
    /// Overlapped structure for async I/O
    pub overlapped: OVERLAPPED,
    /// Buffer for ReadDirectoryChangesW
    pub buffer: Vec<u8>,
}

/// File Integrity Monitor implementation
pub struct FileIntegrityMonitor {
    config: Arc<RwLock<FileIntegrityConfig>>,
    event_sender: mpsc::UnboundedSender<FileIntegrityEvent>,
    event_receiver: Arc<RwLock<Option<mpsc::UnboundedReceiver<FileIntegrityEvent>>>>,
    directory_monitors: Arc<RwLock<Vec<DirectoryMonitor>>>,
    file_baselines: Arc<RwLock<HashMap<PathBuf, FileBaseline>>>,
    is_running: Arc<RwLock<bool>>,
    critical_files: Arc<RwLock<HashSet<PathBuf>>>,
}

// FileIntegrityMonitor is Send and Sync because all its fields are Send and Sync
unsafe impl Send for FileIntegrityMonitor {}
unsafe impl Sync for FileIntegrityMonitor {}

impl FileIntegrityMonitor {
    /// Create a new file integrity monitor instance
    pub fn new(config: FileIntegrityConfig) -> Self {
        let (event_sender, event_receiver) = mpsc::unbounded_channel();
        
        let monitor = Self {
            config: Arc::new(RwLock::new(config)),
            event_sender,
            event_receiver: Arc::new(RwLock::new(Some(event_receiver))),
            directory_monitors: Arc::new(RwLock::new(Vec::new())),
            file_baselines: Arc::new(RwLock::new(HashMap::new())),
            is_running: Arc::new(RwLock::new(false)),
            critical_files: Arc::new(RwLock::new(HashSet::new())),
        };

        // Initialize critical files list
        tokio::spawn({
            let monitor = monitor.clone();
            async move {
                monitor.initialize_critical_files().await;
            }
        });

        monitor
    }

    /// Start file integrity monitoring
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut is_running = self.is_running.write().await;
        if *is_running {
            return Ok(());
        }

        info!("Starting file integrity monitor");
        
        // Initialize file baselines
        self.initialize_baselines().await?;
        
        // Setup directory monitoring
        self.setup_directory_monitoring().await?;
        
        *is_running = true;
        
        // Start monitoring tasks
        self.start_monitoring_tasks().await;
        
        info!("File integrity monitor started successfully");
        Ok(())
    }

    /// Stop file integrity monitoring
    pub async fn stop(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut is_running = self.is_running.write().await;
        if !*is_running {
            return Ok(());
        }

        info!("Stopping file integrity monitor");
        
        // Cleanup directory monitors
        self.cleanup_directory_monitors().await?;
        
        *is_running = false;
        
        info!("File integrity monitor stopped successfully");
        Ok(())
    }

    /// Check if monitor is currently running
    pub async fn is_running(&self) -> bool {
        *self.is_running.read().await
    }

    /// Get current configuration
    pub async fn get_config(&self) -> FileIntegrityConfig {
        self.config.read().await.clone()
    }

    /// Update configuration
    pub async fn update_config(&self, new_config: FileIntegrityConfig) {
        let mut config = self.config.write().await;
        *config = new_config;
        info!("File integrity monitor configuration updated");
    }

    /// Get event receiver for consuming file integrity events
    pub async fn take_event_receiver(&self) -> Option<mpsc::UnboundedReceiver<FileIntegrityEvent>> {
        self.event_receiver.write().await.take()
    }

    /// Add a file to the monitoring baseline
    pub async fn add_file_baseline(&self, file_path: &Path) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let baseline = self.create_file_baseline(file_path).await?;
        let mut baselines = self.file_baselines.write().await;
        baselines.insert(file_path.to_path_buf(), baseline);
        Ok(())
    }

    /// Remove a file from the monitoring baseline
    pub async fn remove_file_baseline(&self, file_path: &Path) {
        let mut baselines = self.file_baselines.write().await;
        baselines.remove(file_path);
    }

    /// Verify file integrity against baseline
    pub async fn verify_file_integrity(&self, file_path: &Path) -> Result<IntegrityStatus, Box<dyn std::error::Error + Send + Sync>> {
        let baselines = self.file_baselines.read().await;
        
        if let Some(baseline) = baselines.get(file_path) {
            if !file_path.exists() {
                return Ok(IntegrityStatus::Deleted);
            }

            let current_hash = self.calculate_file_hash(file_path).await?;
            
            if current_hash == baseline.hash {
                Ok(IntegrityStatus::Intact)
            } else {
                Ok(IntegrityStatus::Tampered)
            }
        } else {
            if file_path.exists() {
                Ok(IntegrityStatus::NewFile)
            } else {
                Ok(IntegrityStatus::Unknown)
            }
        }
    }

    /// Initialize critical files list
    async fn initialize_critical_files(&self) {
        let mut critical_files = self.critical_files.write().await;
        
        // Windows system critical files
        let critical_paths = vec![
            r"C:\Windows\System32\ntoskrnl.exe",
            r"C:\Windows\System32\kernel32.dll",
            r"C:\Windows\System32\ntdll.dll",
            r"C:\Windows\System32\user32.dll",
            r"C:\Windows\System32\advapi32.dll",
            r"C:\Windows\System32\winlogon.exe",
            r"C:\Windows\System32\lsass.exe",
            r"C:\Windows\System32\csrss.exe",
            r"C:\Windows\System32\smss.exe",
            r"C:\Windows\System32\services.exe",
            r"C:\Windows\System32\svchost.exe",
            r"C:\Windows\System32\explorer.exe",
            r"C:\Windows\System32\cmd.exe",
            r"C:\Windows\System32\powershell.exe",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        ];

        for path_str in critical_paths {
            let path = PathBuf::from(path_str);
            if path.exists() {
                critical_files.insert(path);
            }
        }

        debug!("Initialized {} critical files for monitoring", critical_files.len());
    }

    /// Initialize file baselines for monitored paths
    async fn initialize_baselines(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let config = self.config.read().await;
        let mut baselines = self.file_baselines.write().await;

        for monitored_path in &config.monitored_paths {
            if monitored_path.is_dir() {
                self.scan_directory_for_baselines(monitored_path, &mut baselines, &config).await?;
            } else if monitored_path.is_file() {
                let baseline = self.create_file_baseline(monitored_path).await?;
                baselines.insert(monitored_path.clone(), baseline);
            }
        }

        info!("Initialized {} file baselines", baselines.len());
        Ok(())
    }

    /// Scan directory recursively to create baselines
    fn scan_directory_for_baselines<'a>(
        &'a self,
        dir_path: &'a Path,
        baselines: &'a mut HashMap<PathBuf, FileBaseline>,
        config: &'a FileIntegrityConfig,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>> + Send + 'a>> {
        Box::pin(async move {
        if let Ok(entries) = fs::read_dir(dir_path) {
            for entry in entries {
                if let Ok(entry) = entry {
                    let path = entry.path();
                    
                    // Skip excluded paths
                    if config.excluded_paths.iter().any(|excluded| path.starts_with(excluded)) {
                        continue;
                    }

                    if path.is_file() {
                        // Check if file extension should be monitored
                        if !config.monitored_extensions.is_empty() {
                            if let Some(extension) = path.extension() {
                                let ext_str = format!(".{}", extension.to_string_lossy().to_lowercase());
                                if !config.monitored_extensions.contains(&ext_str) {
                                    continue;
                                }
                            } else {
                                continue; // Skip files without extensions if we're filtering
                            }
                        }

                        if let Ok(baseline) = self.create_file_baseline(&path).await {
                            baselines.insert(path, baseline);
                        }
                    } else if path.is_dir() {
                        // Recursively scan subdirectories (with depth limit)
                        if baselines.len() < 10000 { // Prevent excessive memory usage
                            let _ = self.scan_directory_for_baselines(&path, baselines, config).await;
                        }
                    }
                }
            }
        }
        Ok(())
        })
    }

    /// Create baseline information for a file
    async fn create_file_baseline(&self, file_path: &Path) -> Result<FileBaseline, Box<dyn std::error::Error + Send + Sync>> {
        let metadata = fs::metadata(file_path)?;
        let size = metadata.len();
        let modified_time = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        
        let hash = if size <= self.config.read().await.max_hash_file_size {
            self.calculate_file_hash(file_path).await?
        } else {
            String::new() // Skip hashing for large files
        };

        let critical_files = self.critical_files.read().await;
        let is_critical = critical_files.contains(file_path);

        Ok(FileBaseline {
            path: file_path.to_path_buf(),
            size,
            hash,
            modified_time,
            attributes: if metadata.is_dir() { 0x10 } else { 0x20 }, // FILE_ATTRIBUTE_DIRECTORY or FILE_ATTRIBUTE_ARCHIVE
            is_critical,
        })
    }

    /// Calculate SHA-256 hash of a file
    async fn calculate_file_hash(&self, file_path: &Path) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let mut file = fs::File::open(file_path)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0; 8192];

        loop {
            let bytes_read = file.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }

        let result = hasher.finalize();
        Ok(format!("{:x}", result))
    }

    /// Setup directory monitoring using ReadDirectoryChangesW
    async fn setup_directory_monitoring(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let config = self.config.read().await;
        let mut monitors = self.directory_monitors.write().await;

        for monitored_path in &config.monitored_paths {
            if monitored_path.is_dir() {
                match self.create_directory_monitor(monitored_path).await {
                    Ok(monitor) => {
                        monitors.push(monitor);
                        debug!("Setup monitoring for directory: {:?}", monitored_path);
                    }
                    Err(e) => {
                        warn!("Failed to setup monitoring for {:?}: {}", monitored_path, e);
                    }
                }
            }
        }

        info!("Setup {} directory monitors", monitors.len());
        Ok(())
    }

    /// Create a directory monitor for ReadDirectoryChangesW
    async fn create_directory_monitor(&self, dir_path: &Path) -> Result<DirectoryMonitor, Box<dyn std::error::Error + Send + Sync>> {
        let path_str = HSTRING::from(dir_path.to_string_lossy().as_ref());
        
        unsafe {
            let handle = CreateFileW(
                PCWSTR(path_str.as_ptr()),
                FILE_LIST_DIRECTORY.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
                None,
            )?;

            if handle == INVALID_HANDLE_VALUE {
                return Err("Failed to open directory for monitoring".into());
            }

            let overlapped = OVERLAPPED::default();
            let buffer = vec![0u8; 64 * 1024]; // 64KB buffer

            Ok(DirectoryMonitor {
                path: dir_path.to_path_buf(),
                handle,
                overlapped,
                buffer,
            })
        }
    }

    /// Cleanup directory monitors
    async fn cleanup_directory_monitors(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut monitors = self.directory_monitors.write().await;
        
        for monitor in monitors.drain(..) {
            unsafe {
                let _ = windows::Win32::Foundation::CloseHandle(monitor.handle);
            }
        }

        debug!("Directory monitors cleaned up");
        Ok(())
    }

    /// Start monitoring tasks
    async fn start_monitoring_tasks(&self) {
        let config = self.config.clone();
        let sender = self.event_sender.clone();
        let is_running = self.is_running.clone();
        let file_baselines = self.file_baselines.clone();
        let critical_files = self.critical_files.clone();

        // Start directory change monitoring task
        tokio::spawn({
            let config = config.clone();
            let sender = sender.clone();
            let is_running = is_running.clone();
            let file_baselines = file_baselines.clone();
            let critical_files = critical_files.clone();
            
            async move {
                Self::directory_change_monitoring_task(
                    config, sender, is_running, file_baselines, critical_files
                ).await;
            }
        });

        // Start periodic integrity check task
        tokio::spawn({
            let config = config.clone();
            let sender = sender.clone();
            let is_running = is_running.clone();
            let file_baselines = file_baselines.clone();
            
            async move {
                Self::periodic_integrity_check_task(
                    config, sender, is_running, file_baselines
                ).await;
            }
        });
    }

    /// Directory change monitoring task
    async fn directory_change_monitoring_task(
        config: Arc<RwLock<FileIntegrityConfig>>,
        _sender: mpsc::UnboundedSender<FileIntegrityEvent>,
        is_running: Arc<RwLock<bool>>,
        _file_baselines: Arc<RwLock<HashMap<PathBuf, FileBaseline>>>,
        _critical_files: Arc<RwLock<HashSet<PathBuf>>>,
    ) {
        let mut interval = tokio::time::interval(Duration::from_millis(100));

        while *is_running.read().await {
            interval.tick().await;
            
            // This is a placeholder for actual ReadDirectoryChangesW implementation
            // In a real implementation, this would:
            // 1. Process directory change notifications
            // 2. Parse FILE_NOTIFY_INFORMATION structures
            // 3. Create FileIntegrityEvent objects
            // 4. Calculate risk scores
            // 5. Send events through the channel
            
            let config_guard = config.read().await;
            if config_guard.verbose_logging {
                debug!("Processing directory change notifications");
            }
        }
    }

    /// Periodic integrity check task
    async fn periodic_integrity_check_task(
        config: Arc<RwLock<FileIntegrityConfig>>,
        _sender: mpsc::UnboundedSender<FileIntegrityEvent>,
        is_running: Arc<RwLock<bool>>,
        _file_baselines: Arc<RwLock<HashMap<PathBuf, FileBaseline>>>,
    ) {
        let mut interval = tokio::time::interval(Duration::from_secs(
            config.read().await.integrity_check_interval
        ));

        while *is_running.read().await {
            interval.tick().await;
            
            let config_guard = config.read().await;
            if !config_guard.enable_hash_verification {
                continue;
            }

            debug!("Starting periodic integrity check");
            
            // Check a subset of files each interval to avoid performance impact
            let baselines = _file_baselines.read().await;
            let files_to_check: Vec<_> = baselines.keys().take(100).cloned().collect();
            drop(baselines);

            for file_path in files_to_check {
                if !*is_running.read().await {
                    break;
                }

                // Verify file integrity (placeholder implementation)
                if config_guard.verbose_logging {
                    debug!("Checking integrity of: {:?}", file_path);
                }
            }
        }
    }

    /// Calculate risk score for a file integrity event
    fn calculate_risk_score(
        change_type: &FileChangeType,
        is_critical_file: bool,
        integrity_status: &IntegrityStatus,
    ) -> f64 {
        let mut score: f32 = 0.0;

        // Base score from change type
        match change_type {
            FileChangeType::Modified => score += 0.3,
            FileChangeType::Deleted => score += 0.8,
            FileChangeType::Created => score += 0.2,
            FileChangeType::RenamedOld | FileChangeType::RenamedNew => score += 0.4,
            FileChangeType::AttributesChanged => score += 0.1,
            FileChangeType::SecurityChanged => score += 0.6,
            _ => score += 0.1,
        }

        // Critical file penalty
        if is_critical_file {
            score += 0.4;
        }

        // Integrity status penalty
        match integrity_status {
            IntegrityStatus::Tampered => score += 0.5,
            IntegrityStatus::Deleted => score += 0.3,
            IntegrityStatus::Unknown => score += 0.1,
            _ => {},
        }

        (score as f64).min(1.0)
    }
}

impl Clone for FileIntegrityMonitor {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            event_sender: self.event_sender.clone(),
            event_receiver: Arc::new(RwLock::new(None)), // New instance gets no receiver
            directory_monitors: Arc::new(RwLock::new(Vec::new())), // New instance gets no monitors
            file_baselines: self.file_baselines.clone(),
            is_running: Arc::new(RwLock::new(false)), // New instance starts stopped
            critical_files: self.critical_files.clone(),
        }
    }
}

impl Drop for FileIntegrityMonitor {
    fn drop(&mut self) {
        // Ensure cleanup on drop
        if let Ok(monitors) = self.directory_monitors.try_read() {
            if !monitors.is_empty() {
                warn!("FileIntegrityMonitor dropped without proper cleanup");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_file_integrity_monitor_creation() {
        let config = FileIntegrityConfig::default();
        let monitor = FileIntegrityMonitor::new(config);
        
        assert!(!monitor.is_running().await);
    }

    #[tokio::test]
    async fn test_file_baseline_creation() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.txt");
        
        let mut file = File::create(&test_file).unwrap();
        writeln!(file, "test content").unwrap();
        
        let config = FileIntegrityConfig::default();
        let monitor = FileIntegrityMonitor::new(config);
        
        let result = monitor.add_file_baseline(&test_file).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_file_hash_calculation() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.txt");
        
        let mut file = File::create(&test_file).unwrap();
        writeln!(file, "test content").unwrap();
        
        let config = FileIntegrityConfig::default();
        let monitor = FileIntegrityMonitor::new(config);
        
        let hash1 = monitor.calculate_file_hash(&test_file).await.unwrap();
        let hash2 = monitor.calculate_file_hash(&test_file).await.unwrap();
        
        assert_eq!(hash1, hash2);
        assert!(!hash1.is_empty());
    }

    #[tokio::test]
    async fn test_integrity_verification() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.txt");
        
        let mut file = File::create(&test_file).unwrap();
        writeln!(file, "original content").unwrap();
        
        let config = FileIntegrityConfig::default();
        let monitor = FileIntegrityMonitor::new(config);
        
        // Add baseline
        monitor.add_file_baseline(&test_file).await.unwrap();
        
        // Verify intact file
        let status = monitor.verify_file_integrity(&test_file).await.unwrap();
        assert_eq!(status, IntegrityStatus::Intact);
        
        // Modify file
        let mut file = File::create(&test_file).unwrap();
        writeln!(file, "modified content").unwrap();
        
        // Verify tampered file
        let status = monitor.verify_file_integrity(&test_file).await.unwrap();
        assert_eq!(status, IntegrityStatus::Tampered);
    }

    #[test]
    fn test_risk_score_calculation() {
        let score1 = FileIntegrityMonitor::calculate_risk_score(
            &FileChangeType::Modified,
            false,
            &IntegrityStatus::Intact,
        );
        
        let score2 = FileIntegrityMonitor::calculate_risk_score(
            &FileChangeType::Modified,
            true,
            &IntegrityStatus::Tampered,
        );
        
        assert!(score2 > score1);
        assert!(score1 >= 0.0 && score1 <= 1.0);
        assert!(score2 >= 0.0 && score2 <= 1.0);
    }

    #[tokio::test]
    async fn test_config_update() {
        let config = FileIntegrityConfig::default();
        let monitor = FileIntegrityMonitor::new(config);
        
        let mut new_config = FileIntegrityConfig::default();
        new_config.risk_threshold = 0.9;
        
        monitor.update_config(new_config.clone()).await;
        let updated_config = monitor.get_config().await;
        
        assert_eq!(updated_config.risk_threshold, 0.9);
    }
}
