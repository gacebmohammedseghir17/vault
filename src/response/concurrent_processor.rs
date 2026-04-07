//! Concurrent Event Processor
//!
//! Safe concurrency implementation using tokio::mpsc channels for producer-consumer pattern
//! with file integrity watchers and graceful shutdown management.

use std::sync::Arc;
use std::time::{Duration, SystemTime};
use std::collections::HashMap;
use std::hash::Hasher;
use tokio::sync::{mpsc, RwLock, Mutex, oneshot};
use tokio::time::{interval, timeout};
use tokio::fs;
use tokio::task::JoinHandle;
use serde::{Deserialize, Serialize};
use log::{info, debug, warn, error};
use crate::metrics::MetricsCollector;
use super::{SecurityEvent, ResponseAction};

/// Configuration for concurrent event processing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConcurrentProcessorConfig {
    /// Maximum number of events in the processing queue
    pub max_queue_size: usize,
    /// Number of worker threads for event processing
    pub worker_count: usize,
    /// Timeout for processing individual events (seconds)
    pub event_processing_timeout: u64,
    /// File integrity check interval (seconds)
    pub file_integrity_check_interval: u64,
    /// Maximum number of file watchers
    pub max_file_watchers: usize,
    /// Graceful shutdown timeout (seconds)
    pub shutdown_timeout: u64,
    /// Enable file integrity monitoring
    pub enable_file_integrity: bool,
    /// Enable event batching
    pub enable_event_batching: bool,
    /// Batch size for event processing
    pub batch_size: usize,
    /// Batch timeout (milliseconds)
    pub batch_timeout_ms: u64,
}

/// Event processing request
#[derive(Debug)]
pub struct EventProcessingRequest {
    pub event: SecurityEvent,
    pub priority: EventPriority,
    pub response_sender: Option<oneshot::Sender<Vec<ResponseAction>>>,
    pub timestamp: SystemTime,
}

/// Event processing priority
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum EventPriority {
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

/// File integrity monitoring entry
#[derive(Debug, Clone)]
struct FileIntegrityEntry {
    path: String,
    last_modified: SystemTime,
    size: u64,
    hash: Option<String>,
    watch_reason: String,
}

/// Event batch for processing
#[derive(Debug)]
struct EventBatch {
    events: Vec<EventProcessingRequest>,
    created_at: SystemTime,
}

/// Shutdown signal for graceful termination
#[derive(Debug, Clone)]
pub struct ShutdownSignal {
    sender: Arc<Mutex<Option<oneshot::Sender<()>>>>,
    receiver: Arc<Mutex<Option<oneshot::Receiver<()>>>>,
}

impl ShutdownSignal {
    pub fn new() -> Self {
        let (sender, receiver) = oneshot::channel();
        ShutdownSignal {
            sender: Arc::new(Mutex::new(Some(sender))),
            receiver: Arc::new(Mutex::new(Some(receiver))),
        }
    }
    
    pub async fn signal_shutdown(&self) {
        if let Some(sender) = self.sender.lock().await.take() {
            let _ = sender.send(());
        }
    }
    
    pub async fn wait_for_shutdown(&self) {
        if let Some(receiver) = self.receiver.lock().await.take() {
            let _ = receiver.await;
        }
    }
}

/// Concurrent event processor with safe concurrency patterns
pub struct ConcurrentEventProcessor {
    config: ConcurrentProcessorConfig,
    metrics: Arc<MetricsCollector>,
    
    // Event processing channels
    event_sender: mpsc::Sender<EventProcessingRequest>,
    event_receiver: Arc<Mutex<mpsc::Receiver<EventProcessingRequest>>>,
    
    // File integrity monitoring
    file_watchers: Arc<RwLock<HashMap<String, FileIntegrityEntry>>>,
    file_integrity_sender: mpsc::Sender<String>, // file path to check
    file_integrity_receiver: Arc<Mutex<mpsc::Receiver<String>>>,
    
    // Worker management
    worker_handles: Arc<Mutex<Vec<JoinHandle<()>>>>,
    shutdown_signal: ShutdownSignal,
    
    // Event batching
    batch_sender: mpsc::Sender<EventBatch>,
    batch_receiver: Arc<Mutex<mpsc::Receiver<EventBatch>>>,
    
    // Processing statistics
    processing_stats: Arc<RwLock<ProcessingStats>>,
}

/// Processing statistics
#[derive(Debug, Default)]
pub struct ProcessingStats {
    events_processed: u64,
    events_failed: u64,
    batches_processed: u64,
    files_monitored: u64,
    integrity_violations: u64,
    average_processing_time_ms: f64,
    queue_size: usize,
}

impl ConcurrentEventProcessor {
    /// Create a new concurrent event processor
    pub fn new(
        config: ConcurrentProcessorConfig,
        metrics: Arc<MetricsCollector>,
    ) -> Self {
        let (event_sender, event_receiver) = mpsc::channel(config.max_queue_size);
        let (file_integrity_sender, file_integrity_receiver) = mpsc::channel(config.max_file_watchers);
        let (batch_sender, batch_receiver) = mpsc::channel(100); // Reasonable batch queue size
        
        ConcurrentEventProcessor {
            config,
            metrics,
            event_sender,
            event_receiver: Arc::new(Mutex::new(event_receiver)),
            file_watchers: Arc::new(RwLock::new(HashMap::new())),
            file_integrity_sender,
            file_integrity_receiver: Arc::new(Mutex::new(file_integrity_receiver)),
            worker_handles: Arc::new(Mutex::new(Vec::new())),
            shutdown_signal: ShutdownSignal::new(),
            batch_sender,
            batch_receiver: Arc::new(Mutex::new(batch_receiver)),
            processing_stats: Arc::new(RwLock::new(ProcessingStats::default())),
        }
    }
    
    /// Start the concurrent event processor
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Starting concurrent event processor with {} workers", self.config.worker_count);
        
        let mut handles = self.worker_handles.lock().await;
        
        // Start event processing workers
        for worker_id in 0..self.config.worker_count {
            let handle = self.start_event_worker(worker_id).await?;
            handles.push(handle);
        }
        
        // Start file integrity monitoring if enabled
        if self.config.enable_file_integrity {
            let integrity_handle = self.start_file_integrity_monitor().await?;
            handles.push(integrity_handle);
        }
        
        // Start event batching if enabled
        if self.config.enable_event_batching {
            let batch_handle = self.start_batch_processor().await?;
            handles.push(batch_handle);
        }
        
        // Start metrics collection
        let metrics_handle = self.start_metrics_collector().await?;
        handles.push(metrics_handle);
        
        info!("Concurrent event processor started successfully");
        Ok(())
    }
    
    /// Submit an event for processing
    pub async fn submit_event(
        &self,
        event: SecurityEvent,
        priority: EventPriority,
    ) -> Result<Vec<ResponseAction>, Box<dyn std::error::Error + Send + Sync>> {
        let (response_sender, response_receiver) = oneshot::channel();
        
        let request = EventProcessingRequest {
            event,
            priority,
            response_sender: Some(response_sender),
            timestamp: SystemTime::now(),
        };
        
        // Send event to processing queue
        self.event_sender.send(request).await
            .map_err(|e| format!("Failed to submit event: {}", e))?;
        
        // Wait for response with timeout
        let timeout_duration = Duration::from_secs(self.config.event_processing_timeout);
        let response = timeout(timeout_duration, response_receiver).await
            .map_err(|_| "Event processing timeout")?
            .map_err(|e| format!("Event processing failed: {:?}", e))?;
        
        Ok(response)
    }
    
    /// Submit an event for fire-and-forget processing
    pub async fn submit_event_async(
        &self,
        event: SecurityEvent,
        priority: EventPriority,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let request = EventProcessingRequest {
            event,
            priority,
            response_sender: None,
            timestamp: SystemTime::now(),
        };
        
        self.event_sender.send(request).await
            .map_err(|e| format!("Failed to submit async event: {}", e))?;
        
        Ok(())
    }
    
    /// Add a file to integrity monitoring
    pub async fn add_file_watcher(
        &self,
        file_path: String,
        reason: String,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !self.config.enable_file_integrity {
            return Err("File integrity monitoring is disabled".into());
        }
        
        // Get file metadata
        let metadata = fs::metadata(&file_path).await
            .map_err(|e| format!("Failed to get file metadata for {}: {}", file_path, e))?;
        
        let entry = FileIntegrityEntry {
            path: file_path.clone(),
            last_modified: metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
            size: metadata.len(),
            hash: Some(format!("sha256:{:x}", std::collections::hash_map::DefaultHasher::new().finish())),
            watch_reason: reason,
        };
        
        // Add to watchers
        let mut watchers = self.file_watchers.write().await;
        if watchers.len() >= self.config.max_file_watchers {
            return Err("Maximum file watchers limit reached".into());
        }
        
        watchers.insert(file_path.clone(), entry);
        
        // Trigger immediate integrity check
        self.file_integrity_sender.send(file_path).await
            .map_err(|e| format!("Failed to trigger integrity check: {}", e))?;
        
        Ok(())
    }
    
    /// Remove a file from integrity monitoring
    pub async fn remove_file_watcher(&self, file_path: &str) {
        let mut watchers = self.file_watchers.write().await;
        watchers.remove(file_path);
    }
    
    /// Start an event processing worker
    async fn start_event_worker(
        &self,
        worker_id: usize,
    ) -> Result<JoinHandle<()>, Box<dyn std::error::Error + Send + Sync>> {
        let receiver = Arc::clone(&self.event_receiver);
        let metrics = Arc::clone(&self.metrics);
        let stats = Arc::clone(&self.processing_stats);
        let shutdown_signal = self.shutdown_signal.clone();
        let _config = self.config.clone();
        
        let handle = tokio::spawn(async move {
            info!("Event processing worker {} started", worker_id);
            
            loop {
                tokio::select! {
                    // Check for shutdown signal
                    _ = shutdown_signal.wait_for_shutdown() => {
                        info!("Worker {} received shutdown signal", worker_id);
                        break;
                    }
                    
                    // Process events
                    event_result = async {
                        let mut receiver = receiver.lock().await;
                        receiver.recv().await
                    } => {
                        match event_result {
                            Some(request) => {
                                let start_time = std::time::Instant::now();
                                
                                // Process the event
                                let result = Self::process_event_request(request, &metrics).await;
                                
                                // Update statistics
                                let processing_time = start_time.elapsed();
                                let mut stats_guard = stats.write().await;
                                
                                match result {
                                    Ok(_) => {
                                        stats_guard.events_processed += 1;
                                    }
                                    Err(e) => {
                                        stats_guard.events_failed += 1;
                                        error!("Worker {} failed to process event: {}", worker_id, e);
                                    }
                                }
                                
                                // Update average processing time
                                let total_events = stats_guard.events_processed + stats_guard.events_failed;
                                if total_events > 0 {
                                    stats_guard.average_processing_time_ms = 
                                        (stats_guard.average_processing_time_ms * (total_events - 1) as f64 + 
                                         processing_time.as_millis() as f64) / total_events as f64;
                                }
                            }
                            None => {
                                debug!("Worker {} event channel closed", worker_id);
                                break;
                            }
                        }
                    }
                }
            }
            
            info!("Event processing worker {} stopped", worker_id);
        });
        
        Ok(handle)
    }
    
    /// Process an individual event request
    async fn process_event_request(
        request: EventProcessingRequest,
        metrics: &Arc<MetricsCollector>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        debug!("Processing event: {:?} with priority: {:?}", request.event.event_type, request.priority);
        
        // Policy engine integration - using default security policies
        // For now, we'll simulate event processing
        let actions = Self::simulate_event_processing(&request.event).await?;
        
        // Record metrics
        metrics.record_counter("concurrent_events_processed_total", 1.0);
        metrics.record_counter(
            "response_requests_processed_total",
            1.0,
        );
        
        // Send response if requested
        if let Some(sender) = request.response_sender {
            let _ = sender.send(actions);
        }
        
        Ok(())
    }
    
    /// Simulate event processing (placeholder for actual integration)
    async fn simulate_event_processing(
        event: &SecurityEvent,
    ) -> Result<Vec<ResponseAction>, Box<dyn std::error::Error + Send + Sync>> {
        // This is a placeholder - in the actual implementation,
        // this would integrate with the enterprise policy engine
        
        let mut actions = Vec::new();
        
        // Generate appropriate actions based on event type
        match event.event_type {
            super::SecurityEventType::RansomwareDetected => {
                if let Some(pid_str) = event.metadata.get("pid") {
                    if let Ok(pid) = pid_str.parse::<u32>() {
                        actions.push(ResponseAction::ProcessSuspend {
                            pid,
                            reason: "Ransomware detected - immediate containment".to_string(),
                            duration: Some(Duration::from_secs(600)),
                        });
                    }
                }
            }
            super::SecurityEventType::EntropySpike => {
                if let Some(file_path) = event.metadata.get("file_path") {
                    actions.push(ResponseAction::FileQuarantine {
                        path: file_path.clone(),
                        backup_location: format!("quarantine/entropy_{}", 
                            SystemTime::now().duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default().as_secs()),
                    });
                }
            }
            _ => {
                // Default risk assessment
                actions.push(ResponseAction::RiskAssessment {
                    event_id: format!("evt_{}", SystemTime::now().duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default().as_secs()),
                    risk_score: event.severity * event.confidence,
                    recommendations: vec!["Monitor for additional suspicious activity".to_string()],
                });
            }
        }
        
        Ok(actions)
    }
    
    /// Start file integrity monitoring
    async fn start_file_integrity_monitor(
        &self,
    ) -> Result<JoinHandle<()>, Box<dyn std::error::Error + Send + Sync>> {
        let receiver = Arc::clone(&self.file_integrity_receiver);
        let watchers = Arc::clone(&self.file_watchers);
        let metrics = Arc::clone(&self.metrics);
        let stats = Arc::clone(&self.processing_stats);
        let shutdown_signal = self.shutdown_signal.clone();
        let check_interval = self.config.file_integrity_check_interval;
        
        let handle = tokio::spawn(async move {
            info!("File integrity monitor started");
            let mut interval = interval(Duration::from_secs(check_interval));
            
            loop {
                tokio::select! {
                    _ = shutdown_signal.wait_for_shutdown() => {
                        info!("File integrity monitor received shutdown signal");
                        break;
                    }
                    
                    _ = interval.tick() => {
                        // Periodic integrity check for all watched files
                        let watchers_guard = watchers.read().await;
                        for (path, entry) in watchers_guard.iter() {
                            if let Err(e) = Self::check_file_integrity(path, entry, &metrics, &stats).await {
                                error!("File integrity check failed for {}: {}", path, e);
                            }
                        }
                    }
                    
                    file_path = async {
                        let mut receiver = receiver.lock().await;
                        receiver.recv().await
                    } => {
                        if let Some(path) = file_path {
                            // Immediate integrity check for specific file
                            let watchers_guard = watchers.read().await;
                            if let Some(entry) = watchers_guard.get(&path) {
                                if let Err(e) = Self::check_file_integrity(&path, entry, &metrics, &stats).await {
                                    error!("Immediate file integrity check failed for {}: {}", path, e);
                                }
                            }
                        } else {
                            debug!("File integrity channel closed");
                            break;
                        }
                    }
                }
            }
            
            info!("File integrity monitor stopped");
        });
        
        Ok(handle)
    }
    
    /// Check integrity of a specific file
    async fn check_file_integrity(
        path: &str,
        entry: &FileIntegrityEntry,
        metrics: &Arc<MetricsCollector>,
        stats: &Arc<RwLock<ProcessingStats>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match fs::metadata(path).await {
            Ok(metadata) => {
                let current_modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                let current_size = metadata.len();
                
                // Check for modifications
                if current_modified != entry.last_modified || current_size != entry.size {
                    warn!("File integrity violation detected: {} (reason: {})", path, entry.watch_reason);
                    
                    metrics.record_counter("file_integrity_violations_total", 1.0);
                    
                    let mut stats_guard = stats.write().await;
                    stats_guard.integrity_violations += 1;
                    
                    // Generate security event for integrity violation
                    // File integrity violation already logged above
                }
                
                metrics.record_counter("file_integrity_checks_total", 1.0);
            }
            Err(e) => {
                warn!("File no longer accessible: {} - {}", path, e);
                metrics.record_counter("file_integrity_check_errors_total", 1.0);
            }
        }
        
        Ok(())
    }
    
    /// Start batch processor
    async fn start_batch_processor(
        &self,
    ) -> Result<JoinHandle<()>, Box<dyn std::error::Error + Send + Sync>> {
        let receiver = Arc::clone(&self.batch_receiver);
        let metrics = Arc::clone(&self.metrics);
        let stats = Arc::clone(&self.processing_stats);
        let shutdown_signal = self.shutdown_signal.clone();
        
        let handle = tokio::spawn(async move {
            info!("Batch processor started");
            
            loop {
                tokio::select! {
                    _ = shutdown_signal.wait_for_shutdown() => {
                        info!("Batch processor received shutdown signal");
                        break;
                    }
                    
                    batch_result = async {
                        let mut receiver = receiver.lock().await;
                        receiver.recv().await
                    } => {
                        match batch_result {
                            Some(batch) => {
                                debug!("Processing batch of {} events", batch.events.len());
                                
                                // Process batch
                                for request in batch.events {
                                    if let Err(e) = Self::process_event_request(request, &metrics).await {
                                        error!("Batch event processing failed: {}", e);
                                    }
                                }
                                
                                // Update batch statistics
                                let mut stats_guard = stats.write().await;
                                stats_guard.batches_processed += 1;
                                
                                metrics.record_counter("event_batches_processed_total", 1.0);
                            }
                            None => {
                                debug!("Batch processor channel closed");
                                break;
                            }
                        }
                    }
                }
            }
            
            info!("Batch processor stopped");
        });
        
        Ok(handle)
    }
    
    /// Start metrics collection
    async fn start_metrics_collector(
        &self,
    ) -> Result<JoinHandle<()>, Box<dyn std::error::Error + Send + Sync>> {
        let stats = Arc::clone(&self.processing_stats);
        let metrics = Arc::clone(&self.metrics);
        let shutdown_signal = self.shutdown_signal.clone();
        
        let handle = tokio::spawn(async move {
            info!("Metrics collector started");
            let mut interval = interval(Duration::from_secs(30)); // Collect metrics every 30 seconds
            
            loop {
                tokio::select! {
                    _ = shutdown_signal.wait_for_shutdown() => {
                        info!("Metrics collector received shutdown signal");
                        break;
                    }
                    
                    _ = interval.tick() => {
                        let stats_guard = stats.read().await;
                        
                        // Record processing statistics
                        metrics.record_gauge("concurrent_events_processed", stats_guard.events_processed as f64);
                        metrics.record_gauge("concurrent_events_failed", stats_guard.events_failed as f64);
                        metrics.record_gauge("concurrent_batches_processed", stats_guard.batches_processed as f64);
                        metrics.record_gauge("concurrent_files_monitored", stats_guard.files_monitored as f64);
                        metrics.record_gauge("concurrent_integrity_violations", stats_guard.integrity_violations as f64);
                        metrics.record_gauge("concurrent_avg_processing_time_ms", stats_guard.average_processing_time_ms);
                        metrics.record_gauge("concurrent_queue_size", stats_guard.queue_size as f64);
                    }
                }
            }
            
            info!("Metrics collector stopped");
        });
        
        Ok(handle)
    }
    
    /// Gracefully shutdown the processor
    pub async fn shutdown(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Initiating graceful shutdown of concurrent event processor");
        
        // Signal shutdown to all workers
        self.shutdown_signal.signal_shutdown().await;
        
        // Wait for all workers to finish with timeout
        let shutdown_timeout = Duration::from_secs(self.config.shutdown_timeout);
        let handles = {
            let mut handles_guard = self.worker_handles.lock().await;
            std::mem::take(&mut *handles_guard)
        };
        
        for handle in handles {
            if let Err(e) = timeout(shutdown_timeout, handle).await {
                warn!("Worker did not shutdown gracefully within timeout: {:?}", e);
            }
        }
        
        info!("Concurrent event processor shutdown completed");
        Ok(())
    }
    
    /// Get processing statistics
    pub async fn get_stats(&self) -> ProcessingStats {
        let stats = self.processing_stats.read().await;
        ProcessingStats {
            events_processed: stats.events_processed,
            events_failed: stats.events_failed,
            batches_processed: stats.batches_processed,
            files_monitored: self.file_watchers.read().await.len() as u64,
            integrity_violations: stats.integrity_violations,
            average_processing_time_ms: stats.average_processing_time_ms,
            queue_size: stats.queue_size,
        }
    }
}

/// Default configuration for concurrent processor
impl Default for ConcurrentProcessorConfig {
    fn default() -> Self {
        ConcurrentProcessorConfig {
            max_queue_size: 10000,
            worker_count: num_cpus::get().max(2),
            event_processing_timeout: 30,
            file_integrity_check_interval: 60,
            max_file_watchers: 1000,
            shutdown_timeout: 30,
            enable_file_integrity: true,
            enable_event_batching: false,
            batch_size: 50,
            batch_timeout_ms: 1000,
        }
    }
}

/// Convert event type to priority
impl From<&super::SecurityEventType> for EventPriority {
    fn from(event_type: &super::SecurityEventType) -> Self {
        match event_type {
            super::SecurityEventType::RansomwareDetected => EventPriority::Critical,
            super::SecurityEventType::EntropySpike => EventPriority::High,
            super::SecurityEventType::BehavioralAnomaly => EventPriority::High,
            super::SecurityEventType::SuspiciousProcess => EventPriority::Medium,
            super::SecurityEventType::AnomalousFileActivity => EventPriority::Medium,
            super::SecurityEventType::NetworkThreatDetected => EventPriority::Medium,
            _ => EventPriority::Low,
        }
    }
}
