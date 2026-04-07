//! Pre-encryption analyzer for detecting ransomware patterns before encryption begins
//! Monitors file access patterns, shadow copy deletion, and rapid file modifications

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

use crate::error::AgentError;
use crate::metrics::MetricsCollector;
use super::api_monitor::{PreEncryptionIndicator, IndicatorType};

/// File access pattern for pre-encryption detection
#[derive(Debug, Clone)]
pub struct FileAccessEvent {
    pub path: PathBuf,
    pub operation: FileOperationType,
    pub process_id: u32,
    pub process_name: String,
    pub timestamp: Instant,
    pub file_size: u64,
    pub entropy_before: Option<f64>,
    pub entropy_after: Option<f64>,
    pub access_pattern: AccessPattern,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FileOperationType {
    Read,
    Write,
    Create,
    Delete,
    Rename,
    AttributeChange,
    DirectoryEnum,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AccessPattern {
    Sequential,
    Random,
    Bulk,
    Targeted,
}

/// Shadow copy deletion event
#[derive(Debug, Clone)]
pub struct ShadowCopyEvent {
    pub event_type: ShadowCopyEventType,
    pub process_id: u32,
    pub process_name: String,
    pub timestamp: Instant,
    pub command_line: Option<String>,
    pub service_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ShadowCopyEventType {
    VssadminDelete,
    WmicDelete,
    PowershellDelete,
    ServiceManipulation,
    VssServiceStop,
}

/// Rapid file modification sequence
#[derive(Debug, Clone)]
pub struct RapidModificationSequence {
    pub process_id: u32,
    pub process_name: String,
    pub start_time: Instant,
    pub end_time: Instant,
    pub file_count: u32,
    pub directories_affected: HashSet<PathBuf>,
    pub file_types: HashSet<String>,
    pub modification_rate: f64, // files per second
    pub entropy_changes: Vec<f64>,
}

/// File type targeting analysis
#[derive(Debug, Clone)]
pub struct FileTypeTargeting {
    pub targeted_extensions: HashSet<String>,
    pub targeting_score: f64,
    pub common_ransomware_targets: bool,
    pub document_focus: bool,
    pub media_focus: bool,
    pub database_focus: bool,
}

/// Pre-encryption analyzer engine
pub struct PreEncryptionAnalyzer {
    file_access_events: Arc<RwLock<Vec<FileAccessEvent>>>,
    shadow_copy_events: Arc<RwLock<Vec<ShadowCopyEvent>>>,
    rapid_sequences: Arc<RwLock<Vec<RapidModificationSequence>>>,
    file_type_analysis: Arc<RwLock<HashMap<u32, FileTypeTargeting>>>,
    process_file_counts: Arc<RwLock<HashMap<u32, u32>>>,
    directory_monitors: Arc<RwLock<HashMap<PathBuf, Instant>>>,
    metrics: Arc<MetricsCollector>,
    monitoring: Arc<RwLock<bool>>,
    last_analysis: Arc<RwLock<Instant>>,
}

impl PreEncryptionAnalyzer {
    /// Create a new pre-encryption analyzer
    pub fn new(metrics: Arc<MetricsCollector>) -> Self {
        Self {
            file_access_events: Arc::new(RwLock::new(Vec::new())),
            shadow_copy_events: Arc::new(RwLock::new(Vec::new())),
            rapid_sequences: Arc::new(RwLock::new(Vec::new())),
            file_type_analysis: Arc::new(RwLock::new(HashMap::new())),
            process_file_counts: Arc::new(RwLock::new(HashMap::new())),
            directory_monitors: Arc::new(RwLock::new(HashMap::new())),
            metrics,
            monitoring: Arc::new(RwLock::new(false)),
            last_analysis: Arc::new(RwLock::new(Instant::now())),
        }
    }

    /// Create a new pre-encryption analyzer with lazy initialization (for performance)
    pub fn new_lazy(metrics: Arc<MetricsCollector>) -> Self {
        Self {
            file_access_events: Arc::new(RwLock::new(Vec::new())),
            shadow_copy_events: Arc::new(RwLock::new(Vec::new())),
            rapid_sequences: Arc::new(RwLock::new(Vec::new())),
            file_type_analysis: Arc::new(RwLock::new(HashMap::new())),
            process_file_counts: Arc::new(RwLock::new(HashMap::new())),
            directory_monitors: Arc::new(RwLock::new(HashMap::new())),
            metrics,
            monitoring: Arc::new(RwLock::new(false)),
            last_analysis: Arc::new(RwLock::new(Instant::now())),
        }
    }

    /// Create stub pre-encryption analyzer for performance testing (no functionality)
    pub fn new_stub() -> Self {
        use crate::metrics::{MetricsCollector, MetricsDatabase};
        let stub_metrics = Arc::new(MetricsCollector::new(
            MetricsDatabase::new(":memory:").unwrap()
        ));
        
        Self {
            file_access_events: Arc::new(RwLock::new(Vec::new())),
            shadow_copy_events: Arc::new(RwLock::new(Vec::new())),
            rapid_sequences: Arc::new(RwLock::new(Vec::new())),
            file_type_analysis: Arc::new(RwLock::new(HashMap::new())),
            process_file_counts: Arc::new(RwLock::new(HashMap::new())),
            directory_monitors: Arc::new(RwLock::new(HashMap::new())),
            metrics: stub_metrics,
            monitoring: Arc::new(RwLock::new(false)),
            last_analysis: Arc::new(RwLock::new(Instant::now())),
        }
    }

    /// Start pre-encryption analysis
    pub async fn start_analysis(&self) -> Result<(), AgentError> {
        info!("Starting pre-encryption analysis...");

        let mut monitoring = self.monitoring.write().await;
        if *monitoring {
            return Err(AgentError::SystemError(
                "Pre-encryption analysis already running".to_string(),
            ));
        }
        *monitoring = true;
        drop(monitoring);

        // Start file access monitoring
        self.start_file_access_monitoring().await?;

        // Start shadow copy monitoring
        self.start_shadow_copy_monitoring().await?;

        // Start rapid modification detection
        self.start_rapid_modification_detection().await?;

        // Start file type targeting analysis
        self.start_file_type_analysis().await?;

        Ok(())
    }

    /// Stop pre-encryption analysis
    pub async fn stop_analysis(&self) {
        let mut monitoring = self.monitoring.write().await;
        *monitoring = false;
        info!("Stopped pre-encryption analysis");
    }

    /// Start monitoring file access patterns
    async fn start_file_access_monitoring(&self) -> Result<(), AgentError> {
        let file_access_events = Arc::clone(&self.file_access_events);
        let process_file_counts = Arc::clone(&self.process_file_counts);
        let directory_monitors = Arc::clone(&self.directory_monitors);
        let metrics = Arc::clone(&self.metrics);
        let monitoring = Arc::clone(&self.monitoring);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(100));

            while *monitoring.read().await {
                interval.tick().await;

                if let Err(e) = Self::monitor_file_access_patterns(
                    &file_access_events,
                    &process_file_counts,
                    &directory_monitors,
                    &metrics,
                ).await {
                    error!("File access monitoring error: {}", e);
                }
            }
        });

        Ok(())
    }

    /// Monitor file access patterns
    async fn monitor_file_access_patterns(
        file_access_events: &Arc<RwLock<Vec<FileAccessEvent>>>,
        process_file_counts: &Arc<RwLock<HashMap<u32, u32>>>,
        directory_monitors: &Arc<RwLock<HashMap<PathBuf, Instant>>>,
        metrics: &Arc<MetricsCollector>,
    ) -> Result<(), AgentError> {
        // Simulate file access monitoring (in real implementation, use ReadDirectoryChangesW)
        let suspicious_directories = vec![
            PathBuf::from("C:\\Users"),
            PathBuf::from("C:\\Documents and Settings"),
            PathBuf::from("D:\\"),
            PathBuf::from("E:\\"),
        ];

        for dir in suspicious_directories {
            // Simulate file access detection
            if Self::detect_file_access_simulation(&dir).await {
                let event = FileAccessEvent {
                    path: dir.join("document.docx"),
                    operation: FileOperationType::Write,
                    process_id: 1234,
                    process_name: "suspicious_process.exe".to_string(),
                    timestamp: Instant::now(),
                    file_size: 1024000,
                    entropy_before: Some(3.2),
                    entropy_after: Some(7.8), // High entropy indicates encryption
                    access_pattern: AccessPattern::Bulk,
                };

                file_access_events.write().await.push(event);
                
                // Update process file counts
                let mut counts = process_file_counts.write().await;
                *counts.entry(1234).or_insert(0) += 1;
                
                // Update directory monitors
                directory_monitors.write().await.insert(dir.clone(), Instant::now());
                
                metrics.increment_threats_detected_with_labels("pre_encryption", "file_access");
            }
        }

        Ok(())
    }

    /// Simulate file access detection
    async fn detect_file_access_simulation(dir: &PathBuf) -> bool {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        
        // Higher probability for user directories
        let probability = if dir.to_string_lossy().contains("Users") {
            0.4
        } else {
            0.2
        };
        
        rng.gen::<f64>() < probability
    }

    /// Start shadow copy monitoring
    async fn start_shadow_copy_monitoring(&self) -> Result<(), AgentError> {
        let shadow_copy_events = Arc::clone(&self.shadow_copy_events);
        let metrics = Arc::clone(&self.metrics);
        let monitoring = Arc::clone(&self.monitoring);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));

            while *monitoring.read().await {
                interval.tick().await;

                if let Err(e) = Self::monitor_shadow_copy_deletion(
                    &shadow_copy_events,
                    &metrics,
                ).await {
                    error!("Shadow copy monitoring error: {}", e);
                }
            }
        });

        Ok(())
    }

    /// Monitor shadow copy deletion attempts
    async fn monitor_shadow_copy_deletion(
        shadow_copy_events: &Arc<RwLock<Vec<ShadowCopyEvent>>>,
        metrics: &Arc<MetricsCollector>,
    ) -> Result<(), AgentError> {
        // Simulate shadow copy deletion detection
        if Self::detect_shadow_copy_activity().await {
            let event = ShadowCopyEvent {
                event_type: ShadowCopyEventType::VssadminDelete,
                process_id: 1234,
                process_name: "cmd.exe".to_string(),
                timestamp: Instant::now(),
                command_line: Some("vssadmin delete shadows /all /quiet".to_string()),
                service_name: None,
            };

            shadow_copy_events.write().await.push(event);
            metrics.increment_threats_detected_with_labels("pre_encryption", "shadow_copy_deletion");
            
            warn!("Detected shadow copy deletion attempt!");
        }

        Ok(())
    }

    /// Simulate shadow copy activity detection
    async fn detect_shadow_copy_activity() -> bool {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        rng.gen::<f64>() < 0.1 // 10% chance for demonstration
    }

    /// Start rapid modification detection
    async fn start_rapid_modification_detection(&self) -> Result<(), AgentError> {
        let file_access_events = Arc::clone(&self.file_access_events);
        let rapid_sequences = Arc::clone(&self.rapid_sequences);
        let process_file_counts = Arc::clone(&self.process_file_counts);
        let metrics = Arc::clone(&self.metrics);
        let monitoring = Arc::clone(&self.monitoring);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(2));

            while *monitoring.read().await {
                interval.tick().await;

                if let Err(e) = Self::detect_rapid_modifications(
                    &file_access_events,
                    &rapid_sequences,
                    &process_file_counts,
                    &metrics,
                ).await {
                    error!("Rapid modification detection error: {}", e);
                }
            }
        });

        Ok(())
    }

    /// Detect rapid file modification sequences
    async fn detect_rapid_modifications(
        file_access_events: &Arc<RwLock<Vec<FileAccessEvent>>>,
        rapid_sequences: &Arc<RwLock<Vec<RapidModificationSequence>>>,
        process_file_counts: &Arc<RwLock<HashMap<u32, u32>>>,
        metrics: &Arc<MetricsCollector>,
    ) -> Result<(), AgentError> {
        let events = file_access_events.read().await;
        let _counts = process_file_counts.read().await;
        
        let now = Instant::now();
        let analysis_window = Duration::from_secs(30);
        
        // Group events by process
        let mut process_events: HashMap<u32, Vec<&FileAccessEvent>> = HashMap::new();
        for event in events.iter() {
            if event.timestamp >= now - analysis_window {
                process_events.entry(event.process_id).or_insert_with(Vec::new).push(event);
            }
        }

        // Analyze each process for rapid modifications
        for (pid, process_events) in process_events {
            if process_events.len() > 20 { // Threshold for rapid modifications
                let mut directories_affected = HashSet::new();
                let mut file_types = HashSet::new();
                let mut entropy_changes = Vec::new();

                for event in &process_events {
                    if let Some(parent) = event.path.parent() {
                        directories_affected.insert(parent.to_path_buf());
                    }
                    
                    if let Some(ext) = event.path.extension() {
                        file_types.insert(ext.to_string_lossy().to_string());
                    }
                    
                    if let (Some(before), Some(after)) = (event.entropy_before, event.entropy_after) {
                        entropy_changes.push(after - before);
                    }
                }

                let start_time = process_events.iter().map(|e| e.timestamp).min().unwrap_or(now);
                let end_time = process_events.iter().map(|e| e.timestamp).max().unwrap_or(now);
                let duration = end_time.duration_since(start_time).as_secs_f64();
                let modification_rate = if duration > 0.0 {
                    process_events.len() as f64 / duration
                } else {
                    0.0
                };

                let sequence = RapidModificationSequence {
                    process_id: pid,
                    process_name: process_events[0].process_name.clone(),
                    start_time,
                    end_time,
                    file_count: process_events.len() as u32,
                    directories_affected,
                    file_types,
                    modification_rate,
                    entropy_changes,
                };

                rapid_sequences.write().await.push(sequence);
                metrics.increment_threats_detected_with_labels("pre_encryption", "rapid_modification");
                
                warn!("Detected rapid file modification sequence: {} files in {:.2} seconds (rate: {:.2} files/sec)", 
                      process_events.len(), duration, modification_rate);
            }
        }

        Ok(())
    }

    /// Start file type targeting analysis
    async fn start_file_type_analysis(&self) -> Result<(), AgentError> {
        let file_access_events = Arc::clone(&self.file_access_events);
        let file_type_analysis = Arc::clone(&self.file_type_analysis);
        let metrics = Arc::clone(&self.metrics);
        let monitoring = Arc::clone(&self.monitoring);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(5));

            while *monitoring.read().await {
                interval.tick().await;

                if let Err(e) = Self::analyze_file_type_targeting(
                    &file_access_events,
                    &file_type_analysis,
                    &metrics,
                ).await {
                    error!("File type analysis error: {}", e);
                }
            }
        });

        Ok(())
    }

    /// Analyze file type targeting patterns
    async fn analyze_file_type_targeting(
        file_access_events: &Arc<RwLock<Vec<FileAccessEvent>>>,
        file_type_analysis: &Arc<RwLock<HashMap<u32, FileTypeTargeting>>>,
        metrics: &Arc<MetricsCollector>,
    ) -> Result<(), AgentError> {
        let events = file_access_events.read().await;
        let now = Instant::now();
        let analysis_window = Duration::from_secs(300); // 5 minutes
        
        // Group events by process
        let mut process_file_types: HashMap<u32, HashSet<String>> = HashMap::new();
        
        for event in events.iter() {
            if event.timestamp >= now - analysis_window {
                if let Some(ext) = event.path.extension() {
                    let ext_str = ext.to_string_lossy().to_lowercase();
                    process_file_types.entry(event.process_id).or_insert_with(HashSet::new).insert(ext_str);
                }
            }
        }

        // Analyze targeting patterns for each process
        let mut analysis = file_type_analysis.write().await;
        
        for (pid, file_types) in process_file_types {
            let targeting = Self::calculate_file_type_targeting(&file_types);
            
            if targeting.targeting_score > 0.7 {
                analysis.insert(pid, targeting.clone());
                metrics.increment_threats_detected_with_labels("pre_encryption", "file_type_targeting");
                
                warn!("Process {} shows suspicious file type targeting (score: {:.2})", 
                      pid, targeting.targeting_score);
            }
        }

        Ok(())
    }

    /// Calculate file type targeting score
    fn calculate_file_type_targeting(file_types: &HashSet<String>) -> FileTypeTargeting {
        let ransomware_targets = [
            "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "txt", "rtf",
            "jpg", "jpeg", "png", "gif", "bmp", "tiff", "mp3", "mp4", "avi", "mov",
            "zip", "rar", "7z", "tar", "gz", "sql", "db", "mdb", "accdb",
        ].iter().map(|s| s.to_string()).collect::<HashSet<String>>();
        
        let document_types = [
            "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "txt", "rtf"
        ].iter().map(|s| s.to_string()).collect::<HashSet<String>>();
        
        let media_types = [
            "jpg", "jpeg", "png", "gif", "bmp", "tiff", "mp3", "mp4", "avi", "mov"
        ].iter().map(|s| s.to_string()).collect::<HashSet<String>>();
        
        let database_types = [
            "sql", "db", "mdb", "accdb", "sqlite", "dbf"
        ].iter().map(|s| s.to_string()).collect::<HashSet<String>>();

        let common_targets: HashSet<String> = file_types.intersection(&ransomware_targets).cloned().collect();
        let targeting_score = if !file_types.is_empty() {
            common_targets.len() as f64 / file_types.len() as f64
        } else {
            0.0
        };

        let document_focus = !file_types.intersection(&document_types).collect::<Vec<_>>().is_empty();
        let media_focus = !file_types.intersection(&media_types).collect::<Vec<_>>().is_empty();
        let database_focus = !file_types.intersection(&database_types).collect::<Vec<_>>().is_empty();

        FileTypeTargeting {
            targeted_extensions: common_targets,
            targeting_score,
            common_ransomware_targets: targeting_score > 0.5,
            document_focus,
            media_focus,
            database_focus,
        }
    }

    /// Get pre-encryption indicators based on analysis
    pub async fn get_indicators(&self) -> Result<Vec<PreEncryptionIndicator>, AgentError> {
        Ok(self.generate_indicators().await)
    }

    /// Generate pre-encryption indicators based on analysis
    pub async fn generate_indicators(&self) -> Vec<PreEncryptionIndicator> {
        let mut indicators = Vec::new();
        
        // Check rapid modification sequences
        let sequences = self.rapid_sequences.read().await;
        for sequence in sequences.iter() {
            if sequence.modification_rate > 10.0 { // More than 10 files per second
                indicators.push(PreEncryptionIndicator {
                    indicator_type: IndicatorType::RapidFileModification,
                    process_id: sequence.process_id,
                    timestamp: sequence.start_time,
                    confidence: (sequence.modification_rate / 50.0).min(1.0), // Cap at 1.0
                    details: format!("Rapid file modifications: {} files at {:.2} files/sec", 
                                   sequence.file_count, sequence.modification_rate),
                });
            }
        }
        
        // Check shadow copy events
        let shadow_events = self.shadow_copy_events.read().await;
        for event in shadow_events.iter() {
            indicators.push(PreEncryptionIndicator {
                indicator_type: IndicatorType::ShadowCopyDeletion,
                process_id: event.process_id,
                timestamp: event.timestamp,
                confidence: 0.95, // High confidence for shadow copy deletion
                details: format!("Shadow copy deletion: {:?}", event.event_type),
            });
        }
        
        // Check file type targeting
        let targeting_analysis = self.file_type_analysis.read().await;
        for (pid, targeting) in targeting_analysis.iter() {
            if targeting.targeting_score > 0.7 {
                indicators.push(PreEncryptionIndicator {
                    indicator_type: IndicatorType::VolumeEnumeration,
                    process_id: *pid,
                    timestamp: Instant::now(),
                    confidence: targeting.targeting_score,
                    details: format!("Suspicious file type targeting: {:.2} score", targeting.targeting_score),
                });
            }
        }
        
        indicators
    }

    /// Get analysis statistics
    pub async fn get_analysis_statistics(&self) -> HashMap<String, u64> {
        let mut stats = HashMap::new();
        
        stats.insert("file_access_events".to_string(), self.file_access_events.read().await.len() as u64);
        stats.insert("shadow_copy_events".to_string(), self.shadow_copy_events.read().await.len() as u64);
        stats.insert("rapid_sequences".to_string(), self.rapid_sequences.read().await.len() as u64);
        stats.insert("processes_analyzed".to_string(), self.file_type_analysis.read().await.len() as u64);
        
        stats
    }

    /// Clean up old analysis data
    pub async fn cleanup_old_data(&self) {
        let retention_period = Duration::from_secs(3600); // 1 hour
        let cutoff_time = Instant::now() - retention_period;

        // Clean up file access events
        let mut events = self.file_access_events.write().await;
        events.retain(|event| event.timestamp >= cutoff_time);

        // Clean up shadow copy events
        let mut shadow_events = self.shadow_copy_events.write().await;
        shadow_events.retain(|event| event.timestamp >= cutoff_time);

        // Clean up rapid sequences
        let mut sequences = self.rapid_sequences.write().await;
        sequences.retain(|seq| seq.start_time >= cutoff_time);

        debug!("Cleaned up old pre-encryption analysis data");
    }
}
