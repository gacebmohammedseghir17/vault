//! Behavioral analysis engine
//! Provides advanced behavioral analysis with entropy calculation, process tracking,
//! and file system monitoring for ransomware detection

use crate::core::{
    agent::BehavioralEngine,
    config::{BehavioralEngineConfig, EnhancedAgentConfig},
    error::{BehavioralEngineError, EnhancedAgentError, Result},
    types::*,
};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime},
};
use sysinfo::System;
use tokio::{
    fs,
    sync::{mpsc, Mutex, RwLock},
    time::interval,
};
use tracing::{debug, error, info, warn};
use uuid::Uuid;
// Removed unused notify imports

// Removed unused entropy import

#[cfg(windows)]
use winapi::{
    shared::minwindef::{DWORD, FALSE, TRUE},
    um::{
        handleapi::CloseHandle,
        processthreadsapi::OpenProcess,
        psapi::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS},
        tlhelp32::{
            CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32,
            TH32CS_SNAPPROCESS,
        },
        winnt::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ},
    },
};

#[cfg(windows)]
use std::mem;

#[cfg(windows)]
use std::ptr::null_mut;


/// Behavioral analysis engine
pub struct BehavioralAnalysisEngine {
    /// Engine configuration
    config: Arc<RwLock<BehavioralEngineConfig>>,

    /// Process monitor
    process_monitor: Arc<ProcessMonitor>,

    /// File system monitor
    fs_monitor: Arc<FileSystemMonitor>,

    /// Registry monitor (Windows-specific)
    #[allow(dead_code)]
    registry_monitor: Arc<RegistryMonitor>,

    /// Behavioral metrics collector
    #[allow(dead_code)]
    metrics_collector: Arc<BehavioralMetricsCollector>,

    /// Entropy analyzer
    entropy_analyzer: Arc<EntropyAnalyzer>,

    /// Pattern detector
    pattern_detector: Arc<PatternDetector>,

    /// Event correlation engine
    correlation_engine: Arc<EventCorrelationEngine>,

    /// Monitoring state
    monitoring_active: Arc<RwLock<bool>>,

    /// Detection results channel
    detection_tx: mpsc::UnboundedSender<DetectionResult>,
    #[allow(dead_code)]
    detection_rx: Arc<Mutex<mpsc::UnboundedReceiver<DetectionResult>>>,
}

// BehavioralEngineConfig is now imported from crate::core::config

/// Process monitoring component
pub struct ProcessMonitor {
    system: Arc<Mutex<System>>,
    process_history: Arc<RwLock<HashMap<u32, ProcessHistory>>>,
    suspicious_processes: Arc<RwLock<HashSet<u32>>>,
    process_tree: Arc<RwLock<HashMap<u32, Vec<u32>>>>, // parent -> children
    process_spawn_rate: Arc<RwLock<f64>>,
    last_process_count: Arc<RwLock<usize>>,
    last_update_time: Arc<RwLock<SystemTime>>,
}

/// File system monitoring component
pub struct FileSystemMonitor {
    file_operations: Arc<RwLock<VecDeque<FileOperationEvent>>>,
    encryption_patterns: Arc<RwLock<HashMap<PathBuf, EncryptionPattern>>>,
    file_access_patterns: Arc<RwLock<HashMap<PathBuf, FileAccessPattern>>>,
    files_modified_per_second: Arc<RwLock<f64>>,
    last_modification_count: Arc<RwLock<usize>>,
    last_modification_time: Arc<RwLock<SystemTime>>,
    suspicious_extensions: Arc<RwLock<HashSet<String>>>,
    // Watcher is managed separately to avoid Sync issues
    _watcher_handle: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
}

/// Registry monitoring component (Windows-specific)
#[allow(dead_code)]
pub struct RegistryMonitor {
    registry_operations: Arc<RwLock<VecDeque<RegistryOperationEvent>>>,
    monitored_keys: Arc<RwLock<HashSet<String>>>,
    suspicious_patterns: Arc<RwLock<HashMap<String, SuspiciousPattern>>>,
    registry_modifications_total: Arc<RwLock<u64>>,
    last_registry_count: Arc<RwLock<u64>>,
    last_registry_time: Arc<RwLock<SystemTime>>,
    registry_modifications_per_second: Arc<RwLock<f64>>,
    critical_keys: Arc<RwLock<HashSet<String>>>,
}

/// Behavioral metrics collector
pub struct BehavioralMetricsCollector {
    #[allow(dead_code)]
    metrics: Arc<RwLock<BehavioralMetrics>>,
    #[allow(dead_code)]
    metric_history: Arc<RwLock<VecDeque<BehavioralMetrics>>>,
}

/// Entropy analyzer
pub struct EntropyAnalyzer {
    entropy_cache: Arc<RwLock<HashMap<PathBuf, EntropyResult>>>,
    #[allow(dead_code)]
    entropy_history: Arc<RwLock<VecDeque<EntropyMeasurement>>>,
}

/// Pattern detector
pub struct PatternDetector {
    #[allow(dead_code)]
    known_patterns: Arc<RwLock<Vec<BehavioralPattern>>>,
    #[allow(dead_code)]
    pattern_matches: Arc<RwLock<HashMap<String, Vec<PatternMatch>>>>,
}

/// Event correlation engine
pub struct EventCorrelationEngine {
    #[allow(dead_code)]
    event_buffer: Arc<RwLock<VecDeque<BehavioralEvent>>>,
    #[allow(dead_code)]
    correlation_rules: Arc<RwLock<Vec<CorrelationRule>>>,
    #[allow(dead_code)]
    active_correlations: Arc<RwLock<HashMap<String, CorrelationContext>>>,
}

/// Process history tracking
#[derive(Debug, Clone)]
pub struct ProcessHistory {
    pub pid: u32,
    pub name: String,
    pub command_line: String,
    pub parent_pid: Option<u32>,
    pub start_time: SystemTime,
    pub cpu_usage: f32,
    pub memory_usage: u64,
    pub file_operations: Vec<FileOperationEvent>,
    pub registry_operations: Vec<RegistryOperationEvent>,
    pub network_connections: Vec<NetworkInfo>,
    pub suspicious_score: f64,
}

/// Encryption pattern detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionPattern {
    pub file_path: PathBuf,
    pub original_entropy: f64,
    pub current_entropy: f64,
    pub entropy_change: f64,
    pub modification_time: SystemTime,
    pub file_size_change: i64,
    pub extension_changed: bool,
    pub content_type_changed: bool,
}

/// File access pattern
#[derive(Debug, Clone)]
pub struct FileAccessPattern {
    pub file_path: PathBuf,
    pub access_count: usize,
    pub modification_count: usize,
    pub deletion_attempts: usize,
    pub first_access: SystemTime,
    pub last_access: SystemTime,
    pub accessing_processes: HashSet<u32>,
}

/// Entropy analysis result
#[derive(Debug, Clone)]
pub struct EntropyResult {
    pub entropy: f64,
    pub file_size: u64,
    pub analysis_time: SystemTime,
    pub is_suspicious: bool,
    pub confidence: f64,
}

/// Entropy measurement
#[derive(Debug, Clone)]
pub struct EntropyMeasurement {
    pub file_path: PathBuf,
    pub entropy: f64,
    pub timestamp: SystemTime,
    pub file_size: u64,
}

/// Behavioral pattern definition
#[derive(Debug, Clone)]
pub struct BehavioralPattern {
    pub id: String,
    pub name: String,
    pub description: String,
    pub pattern_type: PatternType,
    pub conditions: Vec<PatternCondition>,
    pub severity: ThreatSeverity,
    pub confidence: f64,
}

// PatternType is now imported from crate::core::types

/// Pattern condition
#[derive(Debug, Clone)]
pub struct PatternCondition {
    pub condition_type: ConditionType,
    pub threshold: f64,
    pub time_window: Duration,
    pub required: bool,
}

/// Condition types
#[derive(Debug, Clone, PartialEq)]
pub enum ConditionType {
    FileOperationCount,
    EntropyIncrease,
    ProcessCreationRate,
    RegistryModificationCount,
    NetworkConnectionCount,
    SuspiciousApiCalls,
}

/// Pattern match result
#[derive(Debug, Clone)]
pub struct PatternMatch {
    pub pattern_id: String,
    pub confidence: f64,
    pub matched_conditions: Vec<String>,
    pub timestamp: SystemTime,
    pub associated_processes: Vec<u32>,
    pub affected_files: Vec<PathBuf>,
}

/// Behavioral event for correlation
#[derive(Debug, Clone)]
pub struct BehavioralEvent {
    pub event_id: Uuid,
    pub event_type: BehavioralEventType,
    pub timestamp: SystemTime,
    pub process_id: Option<u32>,
    pub file_path: Option<PathBuf>,
    pub registry_key: Option<String>,
    pub network_info: Option<NetworkInfo>,
    pub metadata: HashMap<String, String>,
}

/// Behavioral event types
#[derive(Debug, Clone, PartialEq)]
pub enum BehavioralEventType {
    ProcessCreated,
    ProcessTerminated,
    FileCreated,
    FileModified,
    FileDeleted,
    FileRenamed,
    RegistryKeyCreated,
    RegistryKeyModified,
    RegistryKeyDeleted,
    NetworkConnectionEstablished,
    HighEntropyDetected,
    SuspiciousApiCall,
}

/// Correlation rule
#[derive(Debug, Clone)]
pub struct CorrelationRule {
    pub rule_id: String,
    pub name: String,
    pub description: String,
    pub event_sequence: Vec<BehavioralEventType>,
    pub time_window: Duration,
    pub min_occurrences: usize,
    pub severity: ThreatSeverity,
    pub confidence: f64,
}

/// Correlation context
#[derive(Debug, Clone)]
pub struct CorrelationContext {
    pub rule_id: String,
    pub matched_events: Vec<BehavioralEvent>,
    pub start_time: SystemTime,
    pub confidence: f64,
    pub associated_processes: HashSet<u32>,
}

impl Default for BehavioralAnalysisEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl BehavioralAnalysisEngine {
    /// Create a new behavioral analysis engine
    pub fn new() -> Self {
        let (detection_tx, detection_rx) = mpsc::unbounded_channel();

        Self {
            config: Arc::new(RwLock::new(BehavioralEngineConfig::default())),
            // Defer heavy operations to initialize()/start_monitoring for faster construction
            process_monitor: Arc::new(ProcessMonitor::new()),
            fs_monitor: Arc::new(FileSystemMonitor::new()),
            registry_monitor: Arc::new(RegistryMonitor::new()),
            metrics_collector: Arc::new(BehavioralMetricsCollector::new()),
            entropy_analyzer: Arc::new(EntropyAnalyzer::new()),
            pattern_detector: Arc::new(PatternDetector::new()),
            correlation_engine: Arc::new(EventCorrelationEngine::new()),
            monitoring_active: Arc::new(RwLock::new(false)),
            detection_tx,
            detection_rx: Arc::new(Mutex::new(detection_rx)),
        }
    }

    /// Start behavioral monitoring
    async fn start_monitoring_internal(&self) -> Result<()> {
        info!("Starting behavioral monitoring");

        *self.monitoring_active.write().await = true;

        let config = self.config.read().await;

        // Start process monitoring
        if config.enable_process_monitoring {
            let process_monitor = Arc::clone(&self.process_monitor);
            let monitoring_active = Arc::clone(&self.monitoring_active);
            let interval_duration = config.monitoring_interval;

            tokio::spawn(async move {
                let mut interval = interval(interval_duration);

                while *monitoring_active.read().await {
                    interval.tick().await;

                    if let Err(e) = process_monitor.update_processes().await {
                        error!("Process monitoring error: {}", e);
                    }
                }
            });
        }

        // Start file system monitoring
        if config.enable_fs_monitoring {
            let fs_monitor = Arc::clone(&self.fs_monitor);
            let protected_dirs = config.protected_directories.clone();

            tokio::spawn(async move {
                let protected_dirs_set: std::collections::HashSet<PathBuf> =
                    protected_dirs.into_iter().collect();
                if let Err(e) = fs_monitor.start_watching(protected_dirs_set).await {
                    error!("File system monitoring error: {}", e);
                }
            });
        }

        // Start correlation engine
        let correlation_engine = Arc::clone(&self.correlation_engine);
        let monitoring_active = Arc::clone(&self.monitoring_active);
        let detection_tx = self.detection_tx.clone();

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(5));

            while *monitoring_active.read().await {
                interval.tick().await;

                if let Ok(detections) = correlation_engine.process_correlations().await {
                    for detection in detections {
                        if let Err(e) = detection_tx.send(detection) {
                            error!("Failed to send correlation detection: {}", e);
                        }
                    }
                }
            }
        });

        info!("Behavioral monitoring started successfully");
        Ok(())
    }

    /// Analyze file entropy
    #[allow(dead_code)]
    async fn analyze_file_entropy(&self, file_path: &Path) -> Result<f64> {
        // Check cache first
        if let Some(cached_result) = self.entropy_analyzer.get_cached_entropy(file_path).await {
            if cached_result
                .analysis_time
                .elapsed()
                .unwrap_or(Duration::MAX)
                < Duration::from_secs(300)
            {
                return Ok(cached_result.entropy);
            }
        }

        let config = self.config.read().await;

        // Check file size
        let metadata = fs::metadata(file_path)
            .await
            .map_err(|e| BehavioralEngineError::FileAccess(e.to_string()))?;

        if metadata.len() > config.max_file_size_for_entropy {
            return Ok(0.0); // Skip large files
        }

        // Read file content
        let content = fs::read(file_path)
            .await
            .map_err(|e| BehavioralEngineError::FileAccess(e.to_string()))?;

        // Calculate Shannon entropy
        let entropy = shannon_entropy(&content);

        // Cache result
        let result = EntropyResult {
            entropy: entropy as f64,
            file_size: metadata.len(),
            analysis_time: SystemTime::now(),
            is_suspicious: entropy > config.high_entropy_threshold as f32,
            confidence: self.calculate_entropy_confidence(entropy.into(), metadata.len()),
        };

        self.entropy_analyzer.cache_entropy(file_path, result).await;

        Ok(entropy.into())
    }

    /// Calculate confidence for entropy analysis
    #[allow(dead_code)]
    fn calculate_entropy_confidence(&self, entropy: f64, file_size: u64) -> f64 {
        let mut confidence: f64 = 0.5;

        // Higher entropy = higher confidence for encryption detection
        if entropy > 7.8 {
            confidence += 0.4;
        } else if entropy > 7.5 {
            confidence += 0.3;
        } else if entropy > 7.0 {
            confidence += 0.2;
        }

        // Larger files give more reliable entropy measurements
        if file_size > 1024 * 1024 {
            // 1MB
            confidence += 0.1;
        } else if file_size < 1024 {
            // 1KB
            confidence -= 0.2;
        }

        confidence.clamp(0.0, 1.0)
    }
}

#[async_trait::async_trait]
impl BehavioralEngine for BehavioralAnalysisEngine {
    async fn initialize(&self, config: &EnhancedAgentConfig) -> Result<()> {
        info!("Initializing behavioral analysis engine");

        // Update configuration
        *self.config.write().await = config.detection.behavioral.clone();

        // Initialize pattern detector with default patterns
        self.pattern_detector.load_default_patterns().await?;

        // Initialize correlation engine with default rules
        self.correlation_engine.load_default_rules().await?;

        info!("Behavioral analysis engine initialized successfully");
        Ok(())
    }

    async fn start_monitoring(&self) -> Result<()> {
        self.start_monitoring_internal().await
    }

    async fn stop_monitoring(&self) -> Result<()> {
        info!("Stopping behavioral monitoring");

        *self.monitoring_active.write().await = false;

        // Stop file system watcher
        self.fs_monitor.stop_watching().await?;

        info!("Behavioral monitoring stopped");
        Ok(())
    }

    async fn analyze_process(&self, process_info: &ProcessInfo) -> Result<Vec<DetectionResult>> {
        debug!(
            "Analyzing process: {} (PID: {})",
            process_info.name, process_info.pid
        );

        let mut detections = Vec::new();

        // Check for suspicious process characteristics
        let suspicious_score = self.calculate_process_suspicion_score(process_info).await;

        if suspicious_score > 0.01 {
            let mut metadata = HashMap::new();
            metadata.insert("process_name".to_string(), process_info.name.clone());
            metadata.insert("process_id".to_string(), process_info.pid.to_string());
            metadata.insert("suspicious_score".to_string(), suspicious_score.to_string());
            if let Some(cmd_line) = &process_info.command_line {
                metadata.insert("command_line".to_string(), cmd_line.clone());
            }

            let detection = DetectionResult {
                threat_id: Uuid::new_v4(),
                threat_type: ThreatType::Unknown,
                severity: if suspicious_score > 0.9 {
                    ThreatSeverity::High
                } else {
                    ThreatSeverity::Medium
                },
                confidence: suspicious_score,
                detection_method: DetectionMethod::Behavioral(
                    "Suspicious process behavior detected".to_string(),
                ),
                file_path: process_info.executable_path.clone(),
                process_info: Some(process_info.clone()),
                network_info: None,
                metadata,
                detected_at: Utc::now(),
                recommended_actions: vec![
                    ResponseAction::TerminateProcess,
                    ResponseAction::QuarantineFile,
                ],
                details: "Suspicious process behavior detected".to_string(),
                timestamp: Utc::now(),
                source: "behavioral_engine".to_string(),
            };

            detections.push(detection);
        }

        Ok(detections)
    }

    async fn analyze_file_operations(
        &self,
        operations: &[FileOperationEvent],
    ) -> Result<Vec<DetectionResult>> {
        debug!("Analyzing {} file operations", operations.len());

        let mut detections = Vec::new();

        // Group operations by process
        let mut process_operations: HashMap<u32, Vec<&FileOperationEvent>> = HashMap::new();
        for op in operations {
            process_operations
                .entry(op.process_info.pid)
                .or_default()
                .push(op);
        }

        // Analyze each process's file operations
        for (process_id, ops) in process_operations {
            if let Some(detection) = self
                .analyze_process_file_operations(process_id, &ops)
                .await?
            {
                detections.push(detection);
            }
        }

        // Check for mass file encryption patterns
        if let Some(encryption_detection) = self.detect_mass_encryption(operations).await? {
            detections.push(encryption_detection);
        }

        Ok(detections)
    }

    async fn analyze_registry_operations(
        &self,
        operations: &[RegistryOperationEvent],
    ) -> Result<Vec<DetectionResult>> {
        debug!("Analyzing {} registry operations", operations.len());

        let mut detections = Vec::new();

        // Check for suspicious registry modifications
        for operation in operations {
            if self.is_suspicious_registry_operation(operation).await {
                let mut metadata = HashMap::new();
                metadata.insert("registry_key".to_string(), operation.key_path.clone());
                metadata.insert(
                    "operation_type".to_string(),
                    format!("{:?}", operation.operation),
                );
                metadata.insert(
                    "process_id".to_string(),
                    operation.process_info.pid.to_string(),
                );

                let detection = DetectionResult {
                    threat_id: Uuid::new_v4(),
                    threat_type: ThreatType::SystemModification,
                    severity: ThreatSeverity::Medium,
                    confidence: 0.7,
                    detection_method: DetectionMethod::Behavioral(
                        "Suspicious registry modification detected".to_string(),
                    ),
                    file_path: None,
                    process_info: None,
                    network_info: None,
                    metadata,
                    detected_at: Utc::now(),
                    recommended_actions: vec![ResponseAction::TerminateProcess],
                    details: "Suspicious registry modification detected".to_string(),
                    timestamp: Utc::now(),
                    source: "behavioral_engine".to_string(),
                };

                detections.push(detection);
            }
        }

        Ok(detections)
    }

    async fn calculate_entropy(&self, data: &[u8]) -> Result<f64> {
        Ok(shannon_entropy(data).into())
    }

    async fn shutdown(&self) -> Result<()> {
        info!("Shutting down behavioral analysis engine");

        // Stop monitoring
        self.stop_monitoring().await?;

        info!("Behavioral analysis engine shutdown complete");
        Ok(())
    }

    /// Get current behavioral metrics
    async fn get_current_metrics(&self) -> Result<BehavioralMetrics> {
        // Return current metrics from the metrics collector
        Ok(self.metrics_collector.metrics.read().await.clone())
    }
}

// Implementation stubs for the various components
// These would be fully implemented in a production system

#[allow(dead_code)]
impl ProcessMonitor {
    pub fn new() -> Self {
        Self {
            // Use lightweight constructor and refresh later to avoid heavy init
            system: Arc::new(Mutex::new(System::new())),
            process_history: Arc::new(RwLock::new(HashMap::new())),
            suspicious_processes: Arc::new(RwLock::new(HashSet::new())),
            process_tree: Arc::new(RwLock::new(HashMap::new())),
            process_spawn_rate: Arc::new(RwLock::new(0.0)),
            last_process_count: Arc::new(RwLock::new(0)),
            last_update_time: Arc::new(RwLock::new(SystemTime::now())),
        }
    }

    async fn update_processes(&self) -> Result<()> {
        let current_time = SystemTime::now();
        let mut system = self.system.lock().await;
        system.refresh_processes();

        let current_process_count = system.processes().len();
        let last_count = *self.last_process_count.read().await;
        let last_time = *self.last_update_time.read().await;

        // Calculate process spawn rate
        if let Ok(time_diff) = current_time.duration_since(last_time) {
            let time_diff_secs = time_diff.as_secs_f64();
            if time_diff_secs > 0.0 {
                let spawn_rate =
                    (current_process_count as f64 - last_count as f64) / time_diff_secs;
                *self.process_spawn_rate.write().await = spawn_rate.max(0.0);
            }
        }

        *self.last_process_count.write().await = current_process_count;
        *self.last_update_time.write().await = current_time;

        // Update process history and detect suspicious processes
        self.analyze_processes(&system).await?;

        Ok(())
    }

    #[cfg(windows)]
    async fn analyze_processes(&self, system: &System) -> Result<()> {
        let mut process_history = self.process_history.write().await;
        let mut suspicious_processes = self.suspicious_processes.write().await;
        let mut process_tree = self.process_tree.write().await;

        // Get Windows process snapshot
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snapshot == null_mut() {
                return Err(EnhancedAgentError::BehavioralEngine(
                    BehavioralEngineError::ProcessMonitoring(
                        "Failed to create process snapshot".to_string(),
                    ),
                ));
            }

            let mut process_entry: PROCESSENTRY32 = mem::zeroed();
            process_entry.dwSize = mem::size_of::<PROCESSENTRY32>() as DWORD;

            if Process32First(snapshot, &mut process_entry) == TRUE {
                loop {
                    let pid = process_entry.th32ProcessID;
                    let parent_pid = process_entry.th32ParentProcessID;

                    // Build process tree
                    process_tree
                        .entry(parent_pid)
                        .or_insert_with(Vec::new)
                        .push(pid);

                    // Get detailed process information
                    if let Some(sysinfo_process) = system.process(sysinfo::Pid::from(pid as usize))
                    {
                        let process_name = sysinfo_process.name().to_string();
                        let cmd_line = sysinfo_process.cmd().join(" ");

                        // Get memory information using Windows API
                        let memory_usage = self.get_process_memory_usage(pid).unwrap_or(0);

                        let history = ProcessHistory {
                            pid,
                            name: process_name.clone(),
                            command_line: cmd_line.clone(),
                            parent_pid: if parent_pid != 0 {
                                Some(parent_pid)
                            } else {
                                None
                            },
                            start_time: SystemTime::now(),
                            cpu_usage: sysinfo_process.cpu_usage(),
                            memory_usage,
                            file_operations: Vec::new(),
                            registry_operations: Vec::new(),
                            network_connections: Vec::new(),
                            suspicious_score: self.calculate_process_suspicion_score_internal(
                                &process_name,
                                &cmd_line,
                                memory_usage,
                            ),
                        };

                        // Check if process is suspicious
                        if history.suspicious_score > 0.7 {
                            suspicious_processes.insert(pid);
                            warn!(
                                "Suspicious process detected: {} (PID: {}, Score: {:.2})",
                                process_name, pid, history.suspicious_score
                            );
                        }

                        process_history.insert(pid, history);
                    }

                    if Process32Next(snapshot, &mut process_entry) == FALSE {
                        break;
                    }
                }
            }

            CloseHandle(snapshot);
        }

        Ok(())
    }

    #[cfg(not(windows))]
    async fn analyze_processes(&self, system: &System) -> Result<()> {
        let mut process_history = self.process_history.write().await;
        let mut suspicious_processes = self.suspicious_processes.write().await;

        for (pid, process) in system.processes() {
            let pid_u32 = pid.as_u32();
            let process_name = process.name().to_string();
            let cmd_line = process.cmd().join(" ");

            let history = ProcessHistory {
                pid: pid_u32,
                name: process_name.clone(),
                command_line: cmd_line.clone(),
                parent_pid: process.parent().map(|p| p.as_u32()),
                start_time: SystemTime::now(),
                cpu_usage: process.cpu_usage(),
                memory_usage: process.memory(),
                file_operations: Vec::new(),
                registry_operations: Vec::new(),
                network_connections: Vec::new(),
                suspicious_score: self.calculate_process_suspicion_score_internal(
                    &process_name,
                    &cmd_line,
                    process.memory(),
                ),
            };

            if history.suspicious_score > 0.7 {
                suspicious_processes.insert(pid_u32);
                warn!(
                    "Suspicious process detected: {} (PID: {}, Score: {:.2})",
                    process_name, pid_u32, history.suspicious_score
                );
            }

            process_history.insert(pid_u32, history);
        }

        Ok(())
    }

    #[cfg(windows)]
    fn get_process_memory_usage(&self, pid: u32) -> Option<u64> {
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
            if handle == null_mut() {
                return None;
            }

            let mut mem_counters: PROCESS_MEMORY_COUNTERS = mem::zeroed();
            mem_counters.cb = mem::size_of::<PROCESS_MEMORY_COUNTERS>() as DWORD;

            let result = if GetProcessMemoryInfo(handle, &mut mem_counters, mem_counters.cb) == TRUE
            {
                Some(mem_counters.WorkingSetSize as u64)
            } else {
                None
            };

            CloseHandle(handle);
            result
        }
    }

    fn calculate_process_suspicion_score_internal(
        &self,
        name: &str,
        cmd_line: &str,
        memory_usage: u64,
    ) -> f64 {
        let mut score: f64 = 0.0;

        // Check for suspicious process names
        let suspicious_names = [
            "powershell",
            "cmd",
            "wscript",
            "cscript",
            "rundll32",
            "regsvr32",
            "mshta",
            "bitsadmin",
            "certutil",
            "wmic",
        ];

        for suspicious_name in &suspicious_names {
            if name.to_lowercase().contains(suspicious_name) {
                score += 0.3;
                break;
            }
        }

        // Check for suspicious command line patterns
        let suspicious_patterns = [
            "base64",
            "powershell -enc",
            "invoke-expression",
            "downloadstring",
            "bypass",
            "hidden",
            "noprofile",
            "executionpolicy",
            "iex",
        ];

        for pattern in &suspicious_patterns {
            if cmd_line.to_lowercase().contains(pattern) {
                score += 0.4;
            }
        }

        // Check for high memory usage (potential crypto mining or data processing)
        if memory_usage > 500 * 1024 * 1024 {
            // 500MB
            score += 0.2;
        }

        // Check for processes running from temp directories
        if cmd_line.to_lowercase().contains("\\temp\\") || cmd_line.to_lowercase().contains("/tmp/")
        {
            score += 0.3;
        }

        score.min(1.0_f64)
    }

    async fn get_process_spawn_rate(&self) -> f64 {
        *self.process_spawn_rate.read().await
    }

    async fn get_suspicious_process_count(&self) -> usize {
        self.suspicious_processes.read().await.len()
    }
}

#[allow(dead_code)]
impl FileSystemMonitor {
    fn new() -> Self {
        let mut suspicious_extensions = HashSet::new();
        // Common ransomware extensions
        suspicious_extensions.extend([
            "encrypted".to_string(),
            "locked".to_string(),
            "crypto".to_string(),
            "crypt".to_string(),
            "enc".to_string(),
            "vault".to_string(),
            "xxx".to_string(),
            "zzz".to_string(),
            "aaa".to_string(),
            "locky".to_string(),
            "cerber".to_string(),
            "zepto".to_string(),
        ]);

        Self {
            _watcher_handle: Arc::new(RwLock::new(None)), // Watcher managed separately to avoid Sync issues
            file_operations: Arc::new(RwLock::new(VecDeque::new())),
            encryption_patterns: Arc::new(RwLock::new(HashMap::new())),
            file_access_patterns: Arc::new(RwLock::new(HashMap::new())),
            files_modified_per_second: Arc::new(RwLock::new(0.0)),
            last_modification_count: Arc::new(RwLock::new(0)),
            last_modification_time: Arc::new(RwLock::new(SystemTime::now())),
            suspicious_extensions: Arc::new(RwLock::new(suspicious_extensions)),
        }
    }

    async fn start_watching(&self, directories: HashSet<PathBuf>) -> Result<()> {
        use notify::{Event, RecursiveMode, Watcher};
        use tokio::sync::mpsc;

        let (tx, mut rx) = mpsc::unbounded_channel();

        let mut watcher = notify::recommended_watcher(move |res: notify::Result<Event>| {
            if let Ok(event) = res {
                let _ = tx.send(event);
            }
        })
        .map_err(|e| {
            EnhancedAgentError::BehavioralEngine(BehavioralEngineError::FileSystemMonitoring(
                format!("Failed to create watcher: {}", e),
            ))
        })?;

        // Watch all specified directories
        for dir in &directories {
            watcher.watch(dir, RecursiveMode::Recursive).map_err(|e| {
                EnhancedAgentError::BehavioralEngine(BehavioralEngineError::FileSystemMonitoring(
                    format!("Failed to watch directory {:?}: {}", dir, e),
                ))
            })?;
        }

        // Spawn event processing task with watcher moved into the task to keep it alive
        let file_operations = Arc::clone(&self.file_operations);
        let encryption_patterns = Arc::clone(&self.encryption_patterns);
        let file_access_patterns = Arc::clone(&self.file_access_patterns);
        let files_modified_per_second = Arc::clone(&self.files_modified_per_second);
        let last_modification_count = Arc::clone(&self.last_modification_count);
        let last_modification_time = Arc::clone(&self.last_modification_time);
        let suspicious_extensions = Arc::clone(&self.suspicious_extensions);

        let handle = tokio::spawn(async move {
            let _watcher = watcher; // Keep watcher alive by moving it into the task
            while let Some(event) = rx.recv().await {
                Self::process_file_event(
                    event,
                    &file_operations,
                    &encryption_patterns,
                    &file_access_patterns,
                    &files_modified_per_second,
                    &last_modification_count,
                    &last_modification_time,
                    &suspicious_extensions,
                )
                .await;
            }
        });

        // Store the handle to manage the watcher task
        *self._watcher_handle.write().await = Some(handle);

        info!(
            "File system monitoring started for {} directories",
            directories.len()
        );
        Ok(())
    }

    async fn stop_watching(&self) -> Result<()> {
        // Stop the watcher task if it's running
        if let Some(handle) = self._watcher_handle.write().await.take() {
            handle.abort();
        }
        info!("File system monitoring stopped");
        Ok(())
    }

    async fn process_file_event(
        event: notify::Event,
        file_operations: &Arc<RwLock<VecDeque<FileOperationEvent>>>,
        encryption_patterns: &Arc<RwLock<HashMap<PathBuf, EncryptionPattern>>>,
        file_access_patterns: &Arc<RwLock<HashMap<PathBuf, FileAccessPattern>>>,
        files_modified_per_second: &Arc<RwLock<f64>>,
        last_modification_count: &Arc<RwLock<usize>>,
        last_modification_time: &Arc<RwLock<SystemTime>>,
        suspicious_extensions: &Arc<RwLock<HashSet<String>>>,
    ) {
        use notify::EventKind;

        let current_time = SystemTime::now();

        for path in &event.paths {
            let operation_type = match event.kind {
                EventKind::Create(_) => FileOperation::Create,
                EventKind::Modify(_) => {
                    // Update modification rate
                    Self::update_modification_rate(
                        files_modified_per_second,
                        last_modification_count,
                        last_modification_time,
                        current_time,
                    )
                    .await;

                    FileOperation::Write
                }
                EventKind::Remove(_) => FileOperation::Delete,
                _ => continue,
            };

            // Create file operation event
            let file_op = FileOperationEvent {
                operation: operation_type.clone(),
                file_path: path.clone(),
                timestamp: current_time.into(),
                process_info: ProcessInfo {
                    pid: 0, // Will be filled by process correlation
                    name: "unknown".to_string(),
                    executable_path: None,
                    command_line: None,
                    ppid: None,
                    start_time: chrono::Utc::now(),
                    cpu_usage: None,
                    memory_usage: None,
                    user: None,
                },
                file_size: Some(fs::metadata(path).await.map(|m| m.len()).unwrap_or(0)),
                file_hash: None,
                entropy: None,
            };

            // Add to operations queue
            {
                let mut ops = file_operations.write().await;
                ops.push_back(file_op);

                // Keep only recent operations (last 1000)
                while ops.len() > 1000 {
                    ops.pop_front();
                }
            }

            // Update file access patterns
            Self::update_file_access_pattern(
                file_access_patterns,
                path,
                &operation_type,
                current_time,
            )
            .await;

            // Check for encryption patterns
            if operation_type == FileOperation::Write {
                Self::check_encryption_pattern(encryption_patterns, path, suspicious_extensions)
                    .await;
            }
        }
    }

    async fn update_modification_rate(
        files_modified_per_second: &Arc<RwLock<f64>>,
        last_modification_count: &Arc<RwLock<usize>>,
        last_modification_time: &Arc<RwLock<SystemTime>>,
        current_time: SystemTime,
    ) {
        let last_count = *last_modification_count.read().await;
        let last_time = *last_modification_time.read().await;

        if let Ok(time_diff) = current_time.duration_since(last_time) {
            let time_diff_secs = time_diff.as_secs_f64();
            if time_diff_secs >= 1.0 {
                let current_count = last_count + 1;
                let modification_rate = current_count as f64 / time_diff_secs;

                *files_modified_per_second.write().await = modification_rate;
                *last_modification_count.write().await = 0;
                *last_modification_time.write().await = current_time;
            } else {
                *last_modification_count.write().await = last_count + 1;
            }
        }
    }

    async fn update_file_access_pattern(
        file_access_patterns: &Arc<RwLock<HashMap<PathBuf, FileAccessPattern>>>,
        path: &PathBuf,
        operation_type: &FileOperation,
        current_time: SystemTime,
    ) {
        let mut patterns = file_access_patterns.write().await;
        let pattern = patterns
            .entry(path.clone())
            .or_insert_with(|| FileAccessPattern {
                file_path: path.clone(),
                access_count: 0,
                modification_count: 0,
                deletion_attempts: 0,
                first_access: current_time,
                last_access: current_time,
                accessing_processes: HashSet::new(),
            });

        match operation_type {
            FileOperation::Create | FileOperation::Read => {
                pattern.access_count += 1;
            }
            FileOperation::Write => {
                pattern.modification_count += 1;
            }
            FileOperation::Delete => {
                pattern.deletion_attempts += 1;
            }
            FileOperation::Rename | FileOperation::Move | FileOperation::Copy => {
                pattern.access_count += 1;
            }
            FileOperation::Encrypt | FileOperation::Decrypt => {
                pattern.modification_count += 1;
            }
        }

        pattern.last_access = current_time;
    }

    async fn check_encryption_pattern(
        encryption_patterns: &Arc<RwLock<HashMap<PathBuf, EncryptionPattern>>>,
        path: &PathBuf,
        suspicious_extensions: &Arc<RwLock<HashSet<String>>>,
    ) {
        // Check if file has suspicious extension
        let has_suspicious_extension = if let Some(extension) = path.extension() {
            let ext_str = extension.to_string_lossy().to_lowercase();
            suspicious_extensions.read().await.contains(&ext_str)
        } else {
            false
        };

        if has_suspicious_extension {
            // Calculate entropy if file exists and is readable
            if let Ok(content) = fs::read(path).await {
                let entropy = shannon_entropy(&content) as f64;
                let file_size = content.len() as i64;

                let mut patterns = encryption_patterns.write().await;
                let pattern = patterns
                    .entry(path.clone())
                    .or_insert_with(|| EncryptionPattern {
                        file_path: path.clone(),
                        original_entropy: entropy,
                        current_entropy: entropy,
                        entropy_change: 0.0,
                        modification_time: SystemTime::now(),
                        file_size_change: 0,
                        extension_changed: has_suspicious_extension,
                        content_type_changed: entropy > 7.5, // High entropy suggests encryption
                    });

                // Update pattern
                let entropy_change = entropy - pattern.original_entropy;
                pattern.current_entropy = entropy;
                pattern.entropy_change = entropy_change;
                pattern.modification_time = SystemTime::now();
                pattern.file_size_change = file_size - pattern.file_size_change;
                pattern.extension_changed = has_suspicious_extension;
                pattern.content_type_changed = entropy > 7.5;

                // Log suspicious activity
                if entropy_change > 2.0 || has_suspicious_extension {
                    warn!("Potential encryption detected: {:?} (entropy change: {:.2}, suspicious extension: {})", 
                          path, entropy_change, has_suspicious_extension);
                }
            }
        }
    }

    async fn get_files_modified_per_second(&self) -> f64 {
        *self.files_modified_per_second.read().await
    }

    async fn get_recent_operations(&self, limit: usize) -> Vec<FileOperationEvent> {
        let operations = self.file_operations.read().await;
        operations.iter().rev().take(limit).cloned().collect()
    }

    async fn get_encryption_patterns(&self) -> HashMap<PathBuf, EncryptionPattern> {
        self.encryption_patterns.read().await.clone()
    }
}

// Helper function to calculate Shannon entropy
fn shannon_entropy(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }

    let mut frequency = [0u32; 256];
    for &byte in data {
        frequency[byte as usize] += 1;
    }

    let length = data.len() as f32;
    let mut entropy = 0.0;

    for &count in &frequency {
        if count > 0 {
            let probability = count as f32 / length;
            entropy -= probability * probability.log2();
        }
    }

    entropy
}

#[allow(dead_code)]
impl RegistryMonitor {
    fn new() -> Self {
        let mut critical_keys = HashSet::new();
        // Critical Windows registry keys that ransomware often targets
        critical_keys.extend([
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(),
            "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(),
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce".to_string(),
            "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce".to_string(),
            "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services".to_string(),
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
                .to_string(),
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies"
                .to_string(),
            "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies".to_string(),
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender".to_string(),
            "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot".to_string(),
        ]);

        Self {
            registry_operations: Arc::new(RwLock::new(VecDeque::new())),
            monitored_keys: Arc::new(RwLock::new(HashSet::new())),
            suspicious_patterns: Arc::new(RwLock::new(HashMap::new())),
            registry_modifications_total: Arc::new(RwLock::new(0)),
            last_registry_count: Arc::new(RwLock::new(0)),
            last_registry_time: Arc::new(RwLock::new(SystemTime::now())),
            registry_modifications_per_second: Arc::new(RwLock::new(0.0)),
            critical_keys: Arc::new(RwLock::new(critical_keys)),
        }
    }

    async fn start_monitoring(&self, keys: HashSet<String>) -> Result<()> {
        // Store monitored keys
        *self.monitored_keys.write().await = keys.clone();

        // Start Windows registry monitoring using WinAPI
        #[cfg(windows)]
        {
            self.start_windows_registry_monitoring(keys.clone()).await?;
        }

        #[cfg(not(windows))]
        {
            warn!("Registry monitoring is only supported on Windows");
        }

        info!("Registry monitoring started for {} keys", keys.len());
        Ok(())
    }

    async fn stop_monitoring(&self) -> Result<()> {
        self.monitored_keys.write().await.clear();
        info!("Registry monitoring stopped");
        Ok(())
    }

    #[cfg(windows)]
    async fn start_windows_registry_monitoring(&self, keys: HashSet<String>) -> Result<()> {
        // Removed unused OsString imports

        // Clone Arc references for the monitoring task
        let registry_operations = Arc::clone(&self.registry_operations);
        let suspicious_patterns = Arc::clone(&self.suspicious_patterns);
        let registry_modifications_total = Arc::clone(&self.registry_modifications_total);
        let registry_modifications_per_second = Arc::clone(&self.registry_modifications_per_second);
        let last_registry_count = Arc::clone(&self.last_registry_count);
        let last_registry_time = Arc::clone(&self.last_registry_time);
        let critical_keys = Arc::clone(&self.critical_keys);

        // Spawn monitoring task
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_millis(500));

            loop {
                interval.tick().await;

                // Simulate registry change detection
                // In a real implementation, this would use RegNotifyChangeKeyValue or similar WinAPI
                Self::check_registry_changes(
                    &registry_operations,
                    &suspicious_patterns,
                    &registry_modifications_total,
                    &registry_modifications_per_second,
                    &last_registry_count,
                    &last_registry_time,
                    &critical_keys,
                    &keys,
                )
                .await;
            }
        });

        Ok(())
    }

    async fn check_registry_changes(
        registry_operations: &Arc<RwLock<VecDeque<RegistryOperationEvent>>>,
        suspicious_patterns: &Arc<RwLock<HashMap<String, SuspiciousPattern>>>,
        registry_modifications_total: &Arc<RwLock<u64>>,
        registry_modifications_per_second: &Arc<RwLock<f64>>,
        last_registry_count: &Arc<RwLock<u64>>,
        last_registry_time: &Arc<RwLock<SystemTime>>,
        critical_keys: &Arc<RwLock<HashSet<String>>>,
        monitored_keys: &HashSet<String>,
    ) {
        let current_time = SystemTime::now();

        // Simulate registry change detection
        // In a real implementation, this would check actual registry changes
        for key in monitored_keys {
            // Check if this is a critical key
            let is_critical = critical_keys
                .read()
                .await
                .iter()
                .any(|critical| key.contains(critical));

            if is_critical {
                // Create registry operation event
                let reg_op = RegistryOperationEvent {
                    operation: RegistryOperation::SetValue,
                    key_path: key.clone(),
                    value_name: Some("DefaultValue".to_string()),
                    value_data: Some("modified_data".to_string()),
                    timestamp: current_time.into(),
                    process_info: ProcessInfo {
                        pid: 0, // Will be filled by process correlation
                        name: "unknown".to_string(),
                        executable_path: None,
                        command_line: None,
                        ppid: None,
                        user: None,
                        start_time: current_time.into(),
                        cpu_usage: Some(0.0),
                        memory_usage: Some(0),
                    },
                };

                // Add to operations queue
                {
                    let mut ops = registry_operations.write().await;
                    ops.push_back(reg_op);

                    // Keep only recent operations (last 1000)
                    while ops.len() > 1000 {
                        ops.pop_front();
                    }
                }

                // Update modification counters
                Self::update_registry_modification_rate(
                    registry_modifications_total,
                    registry_modifications_per_second,
                    last_registry_count,
                    last_registry_time,
                    current_time,
                )
                .await;

                // Check for suspicious patterns
                Self::analyze_suspicious_registry_pattern(
                    suspicious_patterns,
                    key,
                    "DefaultValue",
                    "modified_data",
                    current_time,
                )
                .await;

                warn!("Critical registry key modified: {}", key);
            }
        }
    }

    async fn update_registry_modification_rate(
        registry_modifications_total: &Arc<RwLock<u64>>,
        registry_modifications_per_second: &Arc<RwLock<f64>>,
        last_registry_count: &Arc<RwLock<u64>>,
        last_registry_time: &Arc<RwLock<SystemTime>>,
        current_time: SystemTime,
    ) {
        let mut total = registry_modifications_total.write().await;
        *total += 1;

        let last_count = *last_registry_count.read().await;
        let last_time = *last_registry_time.read().await;

        if let Ok(time_diff) = current_time.duration_since(last_time) {
            let time_diff_secs = time_diff.as_secs_f64();
            if time_diff_secs >= 1.0 {
                let current_count = *total;
                let modification_rate = (current_count - last_count) as f64 / time_diff_secs;

                *registry_modifications_per_second.write().await = modification_rate;
                *last_registry_count.write().await = current_count;
                *last_registry_time.write().await = current_time;
            }
        }
    }

    async fn analyze_suspicious_registry_pattern(
        suspicious_patterns: &Arc<RwLock<HashMap<String, SuspiciousPattern>>>,
        key_path: &str,
        value_name: &str,
        value_data: &str,
        current_time: SystemTime,
    ) {
        // Check for suspicious registry modifications
        let is_suspicious =
            // Disable Windows Defender
            key_path.contains("Windows Defender") ||
            // Modify startup programs
            (key_path.contains("Run") && !value_data.is_empty()) ||
            // Modify system policies
            key_path.contains("Policies") ||
            // Modify safe boot settings
            key_path.contains("SafeBoot") ||
            // Suspicious value names
            value_name.contains("DisableAntiSpyware") ||
            value_name.contains("DisableRealtimeMonitoring") ||
            value_name.contains("DisableBehaviorMonitoring");

        if is_suspicious {
            let mut patterns = suspicious_patterns.write().await;
            let pattern_key = format!("{}\\{}", key_path, value_name);

            let pattern =
                patterns
                    .entry(pattern_key.clone())
                    .or_insert_with(|| SuspiciousPattern {
                        pattern_type: PatternType::RegistryModification,
                        first_occurrence: current_time,
                        last_occurrence: current_time,
                        occurrence_count: 0,
                        severity_score: 0.0,
                        associated_processes: HashSet::new(),
                        metadata: HashMap::new(),
                    });

            pattern.occurrence_count += 1;
            pattern.last_occurrence = current_time;
            pattern.severity_score =
                Self::calculate_registry_severity_score(key_path, value_name, value_data);

            // Add metadata
            pattern
                .metadata
                .insert("key_path".to_string(), key_path.to_string());
            pattern
                .metadata
                .insert("value_name".to_string(), value_name.to_string());
            pattern
                .metadata
                .insert("value_data".to_string(), value_data.to_string());

            warn!(
                "Suspicious registry pattern detected: {} (severity: {:.2})",
                pattern_key, pattern.severity_score
            );
        }
    }

    fn calculate_registry_severity_score(
        key_path: &str,
        value_name: &str,
        value_data: &str,
    ) -> f64 {
        let mut score: f64 = 1.0;

        // High severity for security-related modifications
        if key_path.contains("Windows Defender") {
            score += 8.0;
        }

        if key_path.contains("Policies") {
            score += 6.0;
        }

        if key_path.contains("SafeBoot") {
            score += 7.0;
        }

        if key_path.contains("Run") {
            score += 5.0;
        }

        // Check for suspicious value names
        if value_name.contains("Disable") {
            score += 4.0;
        }

        // Check for suspicious value data
        if value_data.contains(".exe") && !value_data.contains("Windows") {
            score += 3.0;
        }

        score.min(10.0_f64) // Cap at 10.0
    }

    async fn get_registry_modifications_per_second(&self) -> f64 {
        *self.registry_modifications_per_second.read().await
    }

    async fn get_registry_modifications_total(&self) -> u64 {
        *self.registry_modifications_total.read().await
    }

    async fn get_recent_operations(&self, limit: usize) -> Vec<RegistryOperationEvent> {
        let operations = self.registry_operations.read().await;
        operations.iter().rev().take(limit).cloned().collect()
    }

    async fn get_suspicious_patterns(&self) -> HashMap<String, SuspiciousPattern> {
        self.suspicious_patterns.read().await.clone()
    }
}

#[allow(dead_code)]
impl BehavioralMetricsCollector {
    fn new() -> Self {
        Self {
            metrics: Arc::new(RwLock::new(BehavioralMetrics::default())),
            metric_history: Arc::new(RwLock::new(VecDeque::new())),
        }
    }
}

#[allow(dead_code)]
impl EntropyAnalyzer {
    pub fn new() -> Self {
        Self {
            entropy_cache: Arc::new(RwLock::new(HashMap::new())),
            entropy_history: Arc::new(RwLock::new(VecDeque::new())),
        }
    }

    #[allow(dead_code)]
    async fn get_cached_entropy(&self, file_path: &Path) -> Option<EntropyResult> {
        self.entropy_cache.read().await.get(file_path).cloned()
    }

    #[allow(dead_code)]
    async fn cache_entropy(&self, file_path: &Path, result: EntropyResult) {
        self.entropy_cache
            .write()
            .await
            .insert(file_path.to_path_buf(), result);
    }

    /// Calculate Shannon entropy of data
    pub async fn calculate_shannon_entropy(&self, data: &[u8]) -> Result<f64> {
        if data.is_empty() {
            return Ok(0.0);
        }

        let mut frequency = [0u64; 256];
        let data_len = data.len() as f64;

        // Count byte frequencies
        for &byte in data {
            frequency[byte as usize] += 1;
        }

        // Calculate Shannon entropy
        let mut entropy = 0.0;
        for &count in &frequency {
            if count > 0 {
                let probability = count as f64 / data_len;
                entropy -= probability * probability.log2();
            }
        }

        Ok(entropy)
    }
}

#[allow(dead_code)]
impl PatternDetector {
    fn new() -> Self {
        Self {
            known_patterns: Arc::new(RwLock::new(Vec::new())),
            pattern_matches: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn load_default_patterns(&self) -> Result<()> {
        // Implementation would load default behavioral patterns
        Ok(())
    }
}

#[allow(dead_code)]
impl EventCorrelationEngine {
    fn new() -> Self {
        Self {
            event_buffer: Arc::new(RwLock::new(VecDeque::new())),
            correlation_rules: Arc::new(RwLock::new(Vec::new())),
            active_correlations: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn load_default_rules(&self) -> Result<()> {
        // Implementation would load default correlation rules
        Ok(())
    }

    async fn process_correlations(&self) -> Result<Vec<DetectionResult>> {
        // Implementation would process event correlations
        Ok(Vec::new())
    }
}

// Additional helper methods for BehavioralAnalysisEngine
#[allow(dead_code)]
impl BehavioralAnalysisEngine {
    async fn calculate_process_suspicion_score(&self, _process_info: &ProcessInfo) -> f64 {
        // Implementation would calculate suspicion score
        // Return low score to reduce false positives
        0.05
    }

    async fn analyze_process_file_operations(
        &self,
        process_id: u32,
        operations: &[&FileOperationEvent],
    ) -> Result<Option<DetectionResult>> {
        // Look for ransomware patterns: create -> write -> delete sequence
        let mut file_patterns: HashMap<PathBuf, Vec<FileOperation>> = HashMap::new();
        
        // Group operations by file path
        for op in operations {
            file_patterns
                .entry(op.file_path.clone())
                .or_default()
                .push(op.operation.clone());
        }
        
        // Check for ransomware encryption patterns
        for (file_path, ops) in &file_patterns {
            // Look for create -> delete pattern (original file deleted)
            let has_create = ops.contains(&FileOperation::Create);
            let has_delete = ops.contains(&FileOperation::Delete);
            
            // Check for encrypted file creation
            let encrypted_variant = self.find_encrypted_variant(file_path, operations);
            
            if has_create && has_delete && encrypted_variant.is_some() {
                // Ransomware pattern detected!
                let mut metadata = HashMap::new();
                metadata.insert("process_id".to_string(), process_id.to_string());
                metadata.insert("original_file".to_string(), file_path.to_string_lossy().to_string());
                metadata.insert("encrypted_file".to_string(), encrypted_variant.unwrap().to_string_lossy().to_string());
                metadata.insert("pattern".to_string(), "file_encryption".to_string());
                
                return Ok(Some(DetectionResult {
                    threat_id: Uuid::new_v4(),
                    threat_type: ThreatType::Ransomware,
                    severity: ThreatSeverity::Critical,
                    confidence: 0.9,
                    detection_method: DetectionMethod::Behavioral(
                        "Ransomware file encryption pattern detected".to_string(),
                    ),
                    file_path: Some(file_path.clone()),
                    process_info: operations.first().map(|op| op.process_info.clone()),
                    network_info: None,
                    metadata,
                    detected_at: Utc::now(),
                    recommended_actions: vec![ResponseAction::TerminateProcess, ResponseAction::QuarantineFile],
                    details: "Ransomware file encryption pattern detected".to_string(),
                    timestamp: Utc::now(),
                    source: "behavioral_engine".to_string(),
                }));
            }
        }
        
        Ok(None)
    }

    async fn detect_mass_encryption(
        &self,
        operations: &[FileOperationEvent],
    ) -> Result<Option<DetectionResult>> {
        // Count file operations by type
        let mut _create_count = 0;
        let mut delete_count = 0;
        let mut encrypted_files = 0;
        
        for op in operations {
            match op.operation {
                FileOperation::Create => {
                    _create_count += 1;
                    // Check if created file has encrypted extension
                    if let Some(ext) = op.file_path.extension() {
                        if ext.to_string_lossy().contains("encrypted") || 
                           ext.to_string_lossy().contains("locked") ||
                           ext.to_string_lossy().contains("crypto") {
                            encrypted_files += 1;
                        }
                    }
                }
                FileOperation::Delete => delete_count += 1,
                _ => {}
            }
        }
        
        // Mass encryption detection: many deletes + encrypted file creation
        if delete_count >= 3 && encrypted_files >= 2 {
            let mut metadata = HashMap::new();
            metadata.insert("delete_count".to_string(), delete_count.to_string());
            metadata.insert("encrypted_files".to_string(), encrypted_files.to_string());
            metadata.insert("pattern".to_string(), "mass_encryption".to_string());
            
            return Ok(Some(DetectionResult {
                threat_id: Uuid::new_v4(),
                threat_type: ThreatType::Ransomware,
                severity: ThreatSeverity::Critical,
                confidence: 0.95,
                detection_method: DetectionMethod::Behavioral(
                    "Mass file encryption pattern detected".to_string(),
                ),
                file_path: None,
                process_info: operations.first().map(|op| op.process_info.clone()),
                network_info: None,
                metadata,
                detected_at: Utc::now(),
                recommended_actions: vec![ResponseAction::TerminateProcess, ResponseAction::Isolate],
                details: "Mass file encryption pattern detected".to_string(),
                timestamp: Utc::now(),
                source: "behavioral_engine".to_string(),
            }));
        }
        
        Ok(None)
    }

    async fn is_suspicious_registry_operation(&self, _operation: &RegistryOperationEvent) -> bool {
        // Implementation would check if registry operation is suspicious
        false
    }

    /// Check if there have been recent process injection events within the specified duration
    pub async fn has_recent_process_injection(&self, duration: Duration) -> bool {
        let current_time = SystemTime::now();
        let cutoff_time = current_time - duration;

        // Check for recent process injection patterns in the suspicious patterns
        let patterns = self.registry_monitor.suspicious_patterns.read().await;
        patterns.values().any(|pattern| {
            matches!(pattern.pattern_type, PatternType::ProcessInjection)
                && pattern.last_occurrence >= cutoff_time
        })
    }

    /// Check if there have been recent registry modifications within the specified duration
    pub async fn has_recent_registry_modifications(&self, duration: Duration) -> bool {
        let current_time = SystemTime::now();
        let cutoff_time = current_time - duration;

        // Check for recent registry modification patterns
        let patterns = self.registry_monitor.suspicious_patterns.read().await;
        patterns.values().any(|pattern| {
            matches!(pattern.pattern_type, PatternType::RegistryModification)
                && pattern.last_occurrence >= cutoff_time
        })
    }
    
    /// Find encrypted variant of a file in the operations list
    fn find_encrypted_variant(&self, original_file: &Path, operations: &[&FileOperationEvent]) -> Option<PathBuf> {
        let original_name = original_file.to_string_lossy();
        
        for op in operations {
            if op.operation == FileOperation::Create {
                let created_name = op.file_path.to_string_lossy();
                
                // Check if this is an encrypted variant of the original file
                if created_name.starts_with(&*original_name) && created_name != original_name {
                    // Common ransomware patterns
                    if created_name.contains(".encrypted") ||
                       created_name.contains(".locked") ||
                       created_name.contains(".crypto") ||
                       created_name.ends_with(".enc") {
                        return Some(op.file_path.clone());
                    }
                }
            }
        }
        
        None
    }

    /// Calculate entropy of data for encryption detection
    pub async fn calculate_entropy(&self, data: &[u8]) -> Result<f64> {
        if data.is_empty() {
            return Ok(0.0);
        }

        // Use the entropy analyzer to calculate Shannon entropy
        self.entropy_analyzer.calculate_shannon_entropy(data).await
    }
}
