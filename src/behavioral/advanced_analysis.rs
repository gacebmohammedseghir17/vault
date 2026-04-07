//! Advanced Behavioral Analysis for ERDPS
//! Implements process genealogy tracking, advanced entropy analysis,
//! lateral movement detection, and persistence mechanism detection

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, info};
use anyhow::Result;
use regex;
use crate::performance::OptimizationEngine;

/// Configuration for advanced behavioral analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedBehavioralConfig {
    /// Enable process genealogy tracking
    pub enable_genealogy_tracking: bool,
    /// Enable advanced entropy analysis
    pub enable_entropy_analysis: bool,
    /// Enable lateral movement detection
    pub enable_lateral_movement: bool,
    /// Enable persistence detection
    pub enable_persistence_detection: bool,
    /// Maximum process tree depth to track
    pub max_tree_depth: usize,
    /// Time window for behavioral analysis (seconds)
    pub analysis_window_secs: u64,
    /// Minimum entropy threshold for encrypted payloads
    pub entropy_threshold: f64,
    /// Maximum number of processes to track
    pub max_tracked_processes: usize,
    /// Lateral movement detection sensitivity
    pub lateral_movement_sensitivity: f64,
}

impl Default for AdvancedBehavioralConfig {
    fn default() -> Self {
        Self {
            enable_genealogy_tracking: true,
            enable_entropy_analysis: true,
            enable_lateral_movement: true,
            enable_persistence_detection: true,
            max_tree_depth: 10,
            analysis_window_secs: 300, // 5 minutes
            entropy_threshold: 7.5,
            max_tracked_processes: 10000,
            lateral_movement_sensitivity: 0.7,
        }
    }
}

/// Process genealogy node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessNode {
    pub process_id: u32,
    pub parent_id: Option<u32>,
    pub process_name: String,
    pub command_line: String,
    pub executable_path: String,
    pub user: String,
    pub session_id: u32,
    pub creation_time: SystemTime,
    pub termination_time: Option<SystemTime>,
    pub children: Vec<u32>,
    pub depth: usize,
    pub integrity_level: IntegrityLevel,
    pub privileges: Vec<String>,
    pub network_connections: Vec<NetworkConnection>,
    pub file_operations: Vec<FileOperation>,
    pub registry_operations: Vec<RegistryOperation>,
    pub behavioral_score: f64,
    pub anomaly_indicators: Vec<AnomalyIndicator>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IntegrityLevel {
    Untrusted,
    Low,
    Medium,
    High,
    System,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
    pub local_address: String,
    pub local_port: u16,
    pub remote_address: String,
    pub remote_port: u16,
    pub protocol: String,
    pub state: String,
    pub timestamp: SystemTime,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileOperation {
    pub operation_type: FileOperationType,
    pub file_path: String,
    pub timestamp: SystemTime,
    pub bytes_affected: u64,
    pub entropy: Option<f64>,
    pub file_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FileOperationType {
    Create,
    Read,
    Write,
    Delete,
    Rename,
    SetAttributes,
    Encrypt,
    Decrypt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryOperation {
    pub operation_type: RegistryOperationType,
    pub key_path: String,
    pub value_name: Option<String>,
    pub value_data: Option<String>,
    pub timestamp: SystemTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RegistryOperationType {
    CreateKey,
    DeleteKey,
    SetValue,
    DeleteValue,
    QueryKey,
    QueryValue,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyIndicator {
    pub indicator_type: AnomalyType,
    pub severity: f64,
    pub description: String,
    pub timestamp: SystemTime,
    pub evidence: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnomalyType {
    UnusualProcessSpawning,
    SuspiciousNetworkActivity,
    HighEntropyFileOperations,
    PrivilegeEscalation,
    LateralMovement,
    PersistenceMechanism,
    DataExfiltration,
    RansomwareIndicator,
    ProcessHollowing,
    DllInjection,
    AntiAnalysis,
}

/// Lateral movement detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LateralMovementDetection {
    pub source_process: u32,
    pub target_systems: Vec<String>,
    pub movement_type: LateralMovementType,
    pub confidence: f64,
    pub timestamp: SystemTime,
    pub indicators: Vec<String>,
    pub attack_path: Vec<AttackStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LateralMovementType {
    PsExec,
    WmiExec,
    SmbRelay,
    RdpBruteforce,
    PassTheHash,
    PassTheTicket,
    DcomExec,
    PowershellRemoting,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackStep {
    pub step_type: String,
    pub source: String,
    pub target: String,
    pub timestamp: SystemTime,
    pub success: bool,
}

/// Persistence mechanism detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceDetection {
    pub mechanism_type: PersistenceType,
    pub location: String,
    pub process_id: u32,
    pub confidence: f64,
    pub timestamp: SystemTime,
    pub details: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PersistenceType {
    RegistryRun,
    ScheduledTask,
    ServiceInstallation,
    StartupFolder,
    WmiEventSubscription,
    DllHijacking,
    ProcessInjection,
    BootkitRootkit,
    FilelessPersistence,
    Custom(String),
}

/// Advanced behavioral analysis engine
pub struct AdvancedBehavioralAnalyzer {
    config: AdvancedBehavioralConfig,
    process_tree: Arc<RwLock<HashMap<u32, ProcessNode>>>,
    genealogy_cache: Arc<RwLock<HashMap<u32, Vec<u32>>>>, // PID -> ancestors
    lateral_movement_detector: LateralMovementDetector,
    persistence_detector: PersistenceDetector,
    entropy_analyzer: EntropyAnalyzer,
    optimization_engine: Arc<OptimizationEngine>,
    metrics: AdvancedBehavioralMetrics,
}

impl AdvancedBehavioralAnalyzer {
    pub fn new(
        config: AdvancedBehavioralConfig,
        optimization_engine: Arc<OptimizationEngine>,
    ) -> Self {
        Self {
            config: config.clone(),
            process_tree: Arc::new(RwLock::new(HashMap::new())),
            genealogy_cache: Arc::new(RwLock::new(HashMap::new())),
            lateral_movement_detector: LateralMovementDetector::new(config.clone()),
            persistence_detector: PersistenceDetector::new(config.clone()),
            entropy_analyzer: EntropyAnalyzer::new(config.clone()),
            optimization_engine,
            metrics: AdvancedBehavioralMetrics::default(),
        }
    }
    
    /// Start the advanced behavioral analyzer
    pub async fn start(&self) -> Result<()> {
        info!("Starting Advanced Behavioral Analyzer");
        
        // Start cleanup task
        self.start_cleanup_task().await;
        
        // Start analysis task
        self.start_analysis_task().await;
        
        info!("Advanced Behavioral Analyzer started successfully");
        Ok(())
    }
    
    /// Add or update process in the genealogy tree
    pub async fn add_process(&self, mut process: ProcessNode) -> Result<()> {
        if !self.config.enable_genealogy_tracking {
            return Ok(());
        }
        
        let mut tree = self.process_tree.write().await;
        
        // Check size limit
        if tree.len() >= self.config.max_tracked_processes {
            self.evict_old_processes(&mut tree).await;
        }
        
        // Calculate depth and update genealogy
        if let Some(parent_id) = process.parent_id {
            if let Some(parent) = tree.get_mut(&parent_id) {
                parent.children.push(process.process_id);
                process.depth = parent.depth + 1;
            }
        }
        
        // Update genealogy cache
        let ancestors = self.build_ancestor_chain(&tree, &process).await;
        let mut cache = self.genealogy_cache.write().await;
        cache.insert(process.process_id, ancestors);
        
        tree.insert(process.process_id, process);
        self.metrics.processes_tracked.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        
        Ok(())
    }
    
    /// Analyze process behavior for anomalies
    pub async fn analyze_process_behavior(&self, process_id: u32) -> Result<Vec<AnomalyIndicator>> {
        let tree = self.process_tree.read().await;
        let process = tree.get(&process_id)
            .ok_or_else(|| anyhow::anyhow!("Process not found: {}", process_id))?;
        
        let mut anomalies = Vec::new();
        
        // Check for unusual process spawning patterns
        if let Some(spawning_anomaly) = self.detect_unusual_spawning(process, &tree).await? {
            anomalies.push(spawning_anomaly);
        }
        
        // Check for privilege escalation
        if let Some(privilege_anomaly) = self.detect_privilege_escalation(process).await? {
            anomalies.push(privilege_anomaly);
        }
        
        // Check for process hollowing
        if let Some(hollowing_anomaly) = self.detect_process_hollowing(process).await? {
            anomalies.push(hollowing_anomaly);
        }
        
        // Analyze file operations for high entropy
        if self.config.enable_entropy_analysis {
            let entropy_anomalies = self.entropy_analyzer.analyze_file_operations(&process.file_operations).await?;
            anomalies.extend(entropy_anomalies);
        }
        
        // Update metrics
        self.metrics.behavioral_analyses.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.metrics.anomalies_detected.fetch_add(
            anomalies.len() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        
        Ok(anomalies)
    }
    
    /// Detect lateral movement attempts
    pub async fn detect_lateral_movement(&self, process_id: u32) -> Result<Vec<LateralMovementDetection>> {
        if !self.config.enable_lateral_movement {
            return Ok(Vec::new());
        }
        
        let tree = self.process_tree.read().await;
        let process = tree.get(&process_id)
            .ok_or_else(|| anyhow::anyhow!("Process not found: {}", process_id))?;
        
        self.lateral_movement_detector.detect(process).await
    }
    
    /// Detect persistence mechanisms
    pub async fn detect_persistence(&self, process_id: u32) -> Result<Vec<PersistenceDetection>> {
        if !self.config.enable_persistence_detection {
            return Ok(Vec::new());
        }
        
        let tree = self.process_tree.read().await;
        let process = tree.get(&process_id)
            .ok_or_else(|| anyhow::anyhow!("Process not found: {}", process_id))?;
        
        self.persistence_detector.detect(process).await
    }
    
    /// Get process genealogy
    pub async fn get_process_genealogy(&self, process_id: u32) -> Result<Vec<ProcessNode>> {
        let cache = self.genealogy_cache.read().await;
        let tree = self.process_tree.read().await;
        
        if let Some(ancestors) = cache.get(&process_id) {
            let mut genealogy = Vec::new();
            
            for &ancestor_id in ancestors {
                if let Some(ancestor) = tree.get(&ancestor_id) {
                    genealogy.push(ancestor.clone());
                }
            }
            
            Ok(genealogy)
        } else {
            Ok(Vec::new())
        }
    }
    
    /// Get metrics
    pub fn get_metrics(&self) -> AdvancedBehavioralMetrics {
        self.metrics.clone()
    }
    
    // Private helper methods
    
    async fn start_cleanup_task(&self) {
        let tree = Arc::clone(&self.process_tree);
        let cache = Arc::clone(&self.genealogy_cache);
        let window_secs = self.config.analysis_window_secs;
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(window_secs / 4));
            
            loop {
                interval.tick().await;
                let cutoff = SystemTime::now() - Duration::from_secs(window_secs);
                
                // Clean up old processes
                let mut tree_guard = tree.write().await;
                let mut cache_guard = cache.write().await;
                
                let old_pids: Vec<u32> = tree_guard
                    .iter()
                    .filter(|(_, process)| {
                        process.termination_time
                            .map(|t| t < cutoff)
                            .unwrap_or(false)
                    })
                    .map(|(&pid, _)| pid)
                    .collect();
                
                for pid in old_pids {
                    tree_guard.remove(&pid);
                    cache_guard.remove(&pid);
                }
            }
        });
    }
    
    async fn start_analysis_task(&self) {
        let analyzer = self.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60)); // Analyze every minute
            
            loop {
                interval.tick().await;
                
                let tree = analyzer.process_tree.read().await;
                let process_ids: Vec<u32> = tree.keys().cloned().collect();
                drop(tree);
                
                for process_id in process_ids {
                    if let Err(e) = analyzer.analyze_process_behavior(process_id).await {
                        debug!("Failed to analyze process {}: {}", process_id, e);
                    }
                }
            }
        });
    }
    
    async fn evict_old_processes(&self, tree: &mut HashMap<u32, ProcessNode>) {
        let evict_count = tree.len() / 10; // Evict 10%
        let mut processes: Vec<_> = tree.iter().collect();
        processes.sort_by_key(|(_, process)| process.creation_time);
        
        let pids_to_remove: Vec<u32> = processes.iter().take(evict_count).map(|(pid, _)| **pid).collect();
        for pid in pids_to_remove {
            tree.remove(&pid);
        }
    }
    
    async fn build_ancestor_chain(
        &self,
        tree: &HashMap<u32, ProcessNode>,
        process: &ProcessNode,
    ) -> Vec<u32> {
        let mut ancestors = Vec::new();
        let mut current_id = process.parent_id;
        
        while let Some(pid) = current_id {
            ancestors.push(pid);
            if let Some(parent) = tree.get(&pid) {
                current_id = parent.parent_id;
                if ancestors.len() >= self.config.max_tree_depth {
                    break;
                }
            } else {
                break;
            }
        }
        
        ancestors
    }
    
    async fn detect_unusual_spawning(
        &self,
        process: &ProcessNode,
        tree: &HashMap<u32, ProcessNode>,
    ) -> Result<Option<AnomalyIndicator>> {
        // Check for rapid child process creation
        if process.children.len() > 10 {
            let mut evidence = HashMap::new();
            evidence.insert("child_count".to_string(), process.children.len().to_string());
            evidence.insert("process_name".to_string(), process.process_name.clone());
            
            return Ok(Some(AnomalyIndicator {
                indicator_type: AnomalyType::UnusualProcessSpawning,
                severity: 0.8,
                description: format!("Process {} spawned {} children rapidly", 
                    process.process_name, process.children.len()),
                timestamp: SystemTime::now(),
                evidence,
            }));
        }
        
        // Check for unusual parent-child relationships
        if let Some(parent_id) = process.parent_id {
            if let Some(parent) = tree.get(&parent_id) {
                if self.is_unusual_parent_child_relationship(&parent.process_name, &process.process_name) {
                    let mut evidence = HashMap::new();
                    evidence.insert("parent_process".to_string(), parent.process_name.clone());
                    evidence.insert("child_process".to_string(), process.process_name.clone());
                    
                    return Ok(Some(AnomalyIndicator {
                        indicator_type: AnomalyType::UnusualProcessSpawning,
                        severity: 0.7,
                        description: format!("Unusual parent-child relationship: {} -> {}", 
                            parent.process_name, process.process_name),
                        timestamp: SystemTime::now(),
                        evidence,
                    }));
                }
            }
        }
        
        Ok(None)
    }
    
    async fn detect_privilege_escalation(&self, process: &ProcessNode) -> Result<Option<AnomalyIndicator>> {
        // Check for privilege escalation indicators
        let suspicious_privileges = [
            "SeDebugPrivilege",
            "SeTcbPrivilege",
            "SeBackupPrivilege",
            "SeRestorePrivilege",
            "SeTakeOwnershipPrivilege",
        ];
        
        let found_privileges: Vec<_> = process.privileges
            .iter()
            .filter(|p| suspicious_privileges.contains(&p.as_str()))
            .collect();
        
        if !found_privileges.is_empty() {
            let mut evidence = HashMap::new();
            evidence.insert("privileges".to_string(), found_privileges.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "));
            evidence.insert("process_name".to_string(), process.process_name.clone());
            
            return Ok(Some(AnomalyIndicator {
                indicator_type: AnomalyType::PrivilegeEscalation,
                severity: 0.9,
                description: format!("Process {} has suspicious privileges: {}", 
                    process.process_name, found_privileges.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")),
                timestamp: SystemTime::now(),
                evidence,
            }));
        }
        
        Ok(None)
    }
    
    async fn detect_process_hollowing(&self, process: &ProcessNode) -> Result<Option<AnomalyIndicator>> {
        // Simple heuristic: check if process name doesn't match executable path
        let exe_name = std::path::Path::new(&process.executable_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        
        if !exe_name.is_empty() && !process.process_name.to_lowercase().contains(&exe_name.to_lowercase()) {
            let mut evidence = HashMap::new();
            evidence.insert("process_name".to_string(), process.process_name.clone());
            evidence.insert("executable_path".to_string(), process.executable_path.clone());
            
            return Ok(Some(AnomalyIndicator {
                indicator_type: AnomalyType::ProcessHollowing,
                severity: 0.8,
                description: format!("Possible process hollowing: {} vs {}", 
                    process.process_name, exe_name),
                timestamp: SystemTime::now(),
                evidence,
            }));
        }
        
        Ok(None)
    }
    
    fn is_unusual_parent_child_relationship(&self, parent: &str, child: &str) -> bool {
        // Define unusual parent-child relationships
        let unusual_pairs = [
            ("winword.exe", "cmd.exe"),
            ("excel.exe", "powershell.exe"),
            ("outlook.exe", "cmd.exe"),
            ("acrobat.exe", "powershell.exe"),
            ("iexplore.exe", "cmd.exe"),
            ("chrome.exe", "powershell.exe"),
        ];
        
        let parent_lower = parent.to_lowercase();
        let child_lower = child.to_lowercase();
        
        unusual_pairs.iter().any(|(p, c)| {
            parent_lower.contains(p) && child_lower.contains(c)
        })
    }
}

// Clone implementation
impl Clone for AdvancedBehavioralAnalyzer {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            process_tree: Arc::clone(&self.process_tree),
            genealogy_cache: Arc::clone(&self.genealogy_cache),
            lateral_movement_detector: self.lateral_movement_detector.clone(),
            persistence_detector: self.persistence_detector.clone(),
            entropy_analyzer: self.entropy_analyzer.clone(),
            optimization_engine: Arc::clone(&self.optimization_engine),
            metrics: self.metrics.clone(),
        }
    }
}

/// Lateral movement detector
#[derive(Debug, Clone)]
pub struct LateralMovementDetector {
    config: AdvancedBehavioralConfig,
}

impl LateralMovementDetector {
    pub fn new(config: AdvancedBehavioralConfig) -> Self {
        Self { config }
    }
    
    pub async fn detect(&self, process: &ProcessNode) -> Result<Vec<LateralMovementDetection>> {
        let mut detections = Vec::new();
        
        // Check for PsExec-like behavior
        if let Some(detection) = self.detect_psexec_behavior(process).await? {
            detections.push(detection);
        }
        
        // Check for WMI execution
        if let Some(detection) = self.detect_wmi_execution(process).await? {
            detections.push(detection);
        }
        
        // Check for suspicious network connections
        if let Some(detection) = self.detect_suspicious_network_activity(process).await? {
            detections.push(detection);
        }
        
        Ok(detections)
    }
    
    async fn detect_psexec_behavior(&self, process: &ProcessNode) -> Result<Option<LateralMovementDetection>> {
        if process.command_line.to_lowercase().contains("psexec") ||
           process.process_name.to_lowercase().contains("psexec") {
            
            let target_systems = self.extract_target_systems_from_cmdline(&process.command_line);
            
            return Ok(Some(LateralMovementDetection {
                source_process: process.process_id,
                target_systems,
                movement_type: LateralMovementType::PsExec,
                confidence: 0.9,
                timestamp: SystemTime::now(),
                indicators: vec!["PsExec usage detected".to_string()],
                attack_path: vec![],
            }));
        }
        
        Ok(None)
    }
    
    async fn detect_wmi_execution(&self, process: &ProcessNode) -> Result<Option<LateralMovementDetection>> {
        if process.command_line.to_lowercase().contains("wmic") &&
           process.command_line.to_lowercase().contains("process") &&
           process.command_line.to_lowercase().contains("call") &&
           process.command_line.to_lowercase().contains("create") {
            
            return Ok(Some(LateralMovementDetection {
                source_process: process.process_id,
                target_systems: vec![],
                movement_type: LateralMovementType::WmiExec,
                confidence: 0.8,
                timestamp: SystemTime::now(),
                indicators: vec!["WMI remote execution detected".to_string()],
                attack_path: vec![],
            }));
        }
        
        Ok(None)
    }
    
    async fn detect_suspicious_network_activity(&self, process: &ProcessNode) -> Result<Option<LateralMovementDetection>> {
        // Check for multiple outbound connections to different systems
        let unique_targets: HashSet<String> = process.network_connections
            .iter()
            .map(|conn| conn.remote_address.clone())
            .collect();
        
        if unique_targets.len() > 5 {
            let target_count = unique_targets.len();
            return Ok(Some(LateralMovementDetection {
                source_process: process.process_id,
                target_systems: unique_targets.into_iter().collect(),
                movement_type: LateralMovementType::Custom("Multiple network targets".to_string()),
                confidence: 0.7,
                timestamp: SystemTime::now(),
                indicators: vec![format!("Multiple network targets: {}", target_count)],
                attack_path: vec![],
            }));
        }
        
        Ok(None)
    }
    
    fn extract_target_systems_from_cmdline(&self, cmdline: &str) -> Vec<String> {
        // Simple regex to extract IP addresses or hostnames
        let ip_regex = regex::Regex::new(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b").unwrap();
        
        ip_regex.find_iter(cmdline)
            .map(|m| m.as_str().to_string())
            .collect()
    }
}

/// Persistence detector
#[derive(Debug, Clone)]
pub struct PersistenceDetector {
    config: AdvancedBehavioralConfig,
}

impl PersistenceDetector {
    pub fn new(config: AdvancedBehavioralConfig) -> Self {
        Self { config }
    }
    
    pub async fn detect(&self, process: &ProcessNode) -> Result<Vec<PersistenceDetection>> {
        let mut detections = Vec::new();
        
        // Check registry operations for persistence
        for reg_op in &process.registry_operations {
            if let Some(detection) = self.check_registry_persistence(process, reg_op).await? {
                detections.push(detection);
            }
        }
        
        // Check for scheduled task creation
        if let Some(detection) = self.detect_scheduled_task_persistence(process).await? {
            detections.push(detection);
        }
        
        // Check for service installation
        if let Some(detection) = self.detect_service_persistence(process).await? {
            detections.push(detection);
        }
        
        Ok(detections)
    }
    
    async fn check_registry_persistence(
        &self,
        process: &ProcessNode,
        reg_op: &RegistryOperation,
    ) -> Result<Option<PersistenceDetection>> {
        let persistence_keys = [
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices",
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        ];
        
        for &key in &persistence_keys {
            if reg_op.key_path.to_lowercase().contains(&key.to_lowercase()) {
                let mut details = HashMap::new();
                details.insert("registry_key".to_string(), reg_op.key_path.clone());
                details.insert("operation".to_string(), format!("{:?}", reg_op.operation_type));
                
                if let Some(ref value_name) = reg_op.value_name {
                    details.insert("value_name".to_string(), value_name.clone());
                }
                
                return Ok(Some(PersistenceDetection {
                    mechanism_type: PersistenceType::RegistryRun,
                    location: reg_op.key_path.clone(),
                    process_id: process.process_id,
                    confidence: 0.9,
                    timestamp: reg_op.timestamp,
                    details,
                }));
            }
        }
        
        Ok(None)
    }
    
    async fn detect_scheduled_task_persistence(&self, process: &ProcessNode) -> Result<Option<PersistenceDetection>> {
        if process.command_line.to_lowercase().contains("schtasks") &&
           process.command_line.to_lowercase().contains("/create") {
            
            let mut details = HashMap::new();
            details.insert("command_line".to_string(), process.command_line.clone());
            
            return Ok(Some(PersistenceDetection {
                mechanism_type: PersistenceType::ScheduledTask,
                location: "Task Scheduler".to_string(),
                process_id: process.process_id,
                confidence: 0.8,
                timestamp: SystemTime::now(),
                details,
            }));
        }
        
        Ok(None)
    }
    
    async fn detect_service_persistence(&self, process: &ProcessNode) -> Result<Option<PersistenceDetection>> {
        if process.command_line.to_lowercase().contains("sc") &&
           process.command_line.to_lowercase().contains("create") {
            
            let mut details = HashMap::new();
            details.insert("command_line".to_string(), process.command_line.clone());
            
            return Ok(Some(PersistenceDetection {
                mechanism_type: PersistenceType::ServiceInstallation,
                location: "Service Control Manager".to_string(),
                process_id: process.process_id,
                confidence: 0.9,
                timestamp: SystemTime::now(),
                details,
            }));
        }
        
        Ok(None)
    }
}

/// Entropy analyzer for encrypted payloads
#[derive(Debug, Clone)]
pub struct EntropyAnalyzer {
    config: AdvancedBehavioralConfig,
}

impl EntropyAnalyzer {
    pub fn new(config: AdvancedBehavioralConfig) -> Self {
        Self { config }
    }
    
    pub async fn analyze_file_operations(
        &self,
        file_ops: &[FileOperation],
    ) -> Result<Vec<AnomalyIndicator>> {
        let mut anomalies = Vec::new();
        
        for file_op in file_ops {
            if let Some(entropy) = file_op.entropy {
                if entropy > self.config.entropy_threshold {
                    let mut evidence = HashMap::new();
                    evidence.insert("file_path".to_string(), file_op.file_path.clone());
                    evidence.insert("entropy".to_string(), entropy.to_string());
                    evidence.insert("operation".to_string(), format!("{:?}", file_op.operation_type));
                    
                    anomalies.push(AnomalyIndicator {
                        indicator_type: AnomalyType::HighEntropyFileOperations,
                        severity: (entropy - self.config.entropy_threshold) / (8.0 - self.config.entropy_threshold),
                        description: format!("High entropy file operation: {} (entropy: {:.2})", 
                            file_op.file_path, entropy),
                        timestamp: file_op.timestamp,
                        evidence,
                    });
                }
            }
        }
        
        Ok(anomalies)
    }
}

/// Advanced behavioral analysis metrics
#[derive(Debug, Default)]
pub struct AdvancedBehavioralMetrics {
    pub processes_tracked: std::sync::atomic::AtomicU64,
    pub behavioral_analyses: std::sync::atomic::AtomicU64,
    pub anomalies_detected: std::sync::atomic::AtomicU64,
    pub lateral_movement_detections: std::sync::atomic::AtomicU64,
    pub persistence_detections: std::sync::atomic::AtomicU64,
    pub entropy_analyses: std::sync::atomic::AtomicU64,
}

impl Clone for AdvancedBehavioralMetrics {
    fn clone(&self) -> Self {
        use std::sync::atomic::Ordering;
        Self {
            processes_tracked: std::sync::atomic::AtomicU64::new(self.processes_tracked.load(Ordering::SeqCst)),
            behavioral_analyses: std::sync::atomic::AtomicU64::new(self.behavioral_analyses.load(Ordering::SeqCst)),
            anomalies_detected: std::sync::atomic::AtomicU64::new(self.anomalies_detected.load(Ordering::SeqCst)),
            lateral_movement_detections: std::sync::atomic::AtomicU64::new(self.lateral_movement_detections.load(Ordering::SeqCst)),
            persistence_detections: std::sync::atomic::AtomicU64::new(self.persistence_detections.load(Ordering::SeqCst)),
            entropy_analyses: std::sync::atomic::AtomicU64::new(self.entropy_analyses.load(Ordering::SeqCst)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::performance::OptimizationConfig;
    
    #[tokio::test]
    async fn test_process_genealogy() {
        let config = AdvancedBehavioralConfig::default();
        let opt_engine = Arc::new(
            OptimizationEngine::new(OptimizationConfig::default())
                .expect("Failed to create OptimizationEngine"),
        );
        let analyzer = AdvancedBehavioralAnalyzer::new(config, opt_engine);
        
        let parent_process = ProcessNode {
            process_id: 1000,
            parent_id: None,
            process_name: "parent.exe".to_string(),
            command_line: "parent.exe".to_string(),
            executable_path: "C:\\parent.exe".to_string(),
            user: "SYSTEM".to_string(),
            session_id: 0,
            creation_time: SystemTime::now(),
            termination_time: None,
            children: vec![],
            depth: 0,
            integrity_level: IntegrityLevel::High,
            privileges: vec![],
            network_connections: vec![],
            file_operations: vec![],
            registry_operations: vec![],
            behavioral_score: 0.0,
            anomaly_indicators: vec![],
        };
        
        let child_process = ProcessNode {
            process_id: 2000,
            parent_id: Some(1000),
            process_name: "child.exe".to_string(),
            command_line: "child.exe".to_string(),
            executable_path: "C:\\child.exe".to_string(),
            user: "SYSTEM".to_string(),
            session_id: 0,
            creation_time: SystemTime::now(),
            termination_time: None,
            children: vec![],
            depth: 0,
            integrity_level: IntegrityLevel::High,
            privileges: vec![],
            network_connections: vec![],
            file_operations: vec![],
            registry_operations: vec![],
            behavioral_score: 0.0,
            anomaly_indicators: vec![],
        };
        
        analyzer.add_process(parent_process).await.unwrap();
        analyzer.add_process(child_process).await.unwrap();
        
        let genealogy = analyzer.get_process_genealogy(2000).await.unwrap();
        assert_eq!(genealogy.len(), 1);
        assert_eq!(genealogy[0].process_id, 1000);
    }
    
    #[tokio::test]
    async fn test_anomaly_detection() {
        let config = AdvancedBehavioralConfig::default();
        let opt_engine = Arc::new(
            OptimizationEngine::new(OptimizationConfig::default())
                .expect("Failed to create OptimizationEngine"),
        );
        let analyzer = AdvancedBehavioralAnalyzer::new(config, opt_engine);
        
        let suspicious_process = ProcessNode {
            process_id: 3000,
            parent_id: None,
            process_name: "suspicious.exe".to_string(),
            command_line: "suspicious.exe".to_string(),
            executable_path: "C:\\suspicious.exe".to_string(),
            user: "SYSTEM".to_string(),
            session_id: 0,
            creation_time: SystemTime::now(),
            termination_time: None,
            children: (0..15).collect(), // Many children
            depth: 0,
            integrity_level: IntegrityLevel::High,
            privileges: vec!["SeDebugPrivilege".to_string()],
            network_connections: vec![],
            file_operations: vec![],
            registry_operations: vec![],
            behavioral_score: 0.0,
            anomaly_indicators: vec![],
        };
        
        analyzer.add_process(suspicious_process).await.unwrap();
        
        let anomalies = analyzer.analyze_process_behavior(3000).await.unwrap();
        assert!(!anomalies.is_empty());
        
        // Should detect unusual spawning and privilege escalation
        let spawning_detected = anomalies.iter().any(|a| matches!(a.indicator_type, AnomalyType::UnusualProcessSpawning));
        let privilege_detected = anomalies.iter().any(|a| matches!(a.indicator_type, AnomalyType::PrivilegeEscalation));
        
        assert!(spawning_detected);
        assert!(privilege_detected);
    }
}
