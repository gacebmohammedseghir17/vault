//! Resource Tracker Component
//!
//! This module provides comprehensive resource tracking and management,
//! including memory limits, CPU throttling, and resource allocation monitoring.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use tokio::time::interval;
use tracing::{debug, error, info, warn};

use crate::error::{AgentError, AgentResult};
use super::MonitoringConfig;

/// Resource usage limits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub max_memory_bytes: Option<u64>,
    pub max_memory_percent: Option<f64>,
    pub max_cpu_percent: Option<f64>,
    pub max_disk_io_bytes_per_sec: Option<u64>,
    pub max_network_io_bytes_per_sec: Option<u64>,
    pub max_open_files: Option<u32>,
    pub max_concurrent_scans: Option<u32>,
    pub scan_timeout_seconds: Option<u64>,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_memory_bytes: Some(2 * 1024 * 1024 * 1024), // 2GB
            max_memory_percent: Some(80.0), // 80% of system memory
            max_cpu_percent: Some(75.0), // 75% CPU usage
            max_disk_io_bytes_per_sec: Some(100 * 1024 * 1024), // 100MB/s
            max_network_io_bytes_per_sec: Some(50 * 1024 * 1024), // 50MB/s
            max_open_files: Some(1000),
            max_concurrent_scans: Some(4),
            scan_timeout_seconds: Some(300), // 5 minutes
        }
    }
}

/// Resource usage snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceSnapshot {
    pub timestamp: u64,
    pub memory_usage_bytes: u64,
    pub memory_usage_percent: f64,
    pub cpu_usage_percent: f64,
    pub disk_io_read_bytes_per_sec: u64,
    pub disk_io_write_bytes_per_sec: u64,
    pub network_rx_bytes_per_sec: u64,
    pub network_tx_bytes_per_sec: u64,
    pub open_files_count: u32,
    pub active_scans_count: u32,
    pub thread_count: u32,
    pub handle_count: u32,
}

/// Resource allocation tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceAllocation {
    pub component: String,
    pub memory_allocated: u64,
    pub cpu_time_ms: u64,
    pub files_opened: u32,
    pub network_connections: u32,
    pub allocation_time: u64,
    pub last_activity: u64,
}

/// Resource violation event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceViolation {
    pub id: String,
    pub resource_type: String,
    pub current_value: f64,
    pub limit_value: f64,
    pub severity: ViolationSeverity,
    pub timestamp: u64,
    pub component: Option<String>,
    pub action_taken: Option<String>,
}

/// Violation severity levels
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ViolationSeverity {
    Warning,
    Critical,
    Emergency,
}

/// Resource management action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResourceAction {
    Throttle { component: String, percentage: f64 },
    Pause { component: String, duration_seconds: u64 },
    Terminate { component: String, reason: String },
    CleanupMemory { target_bytes: u64 },
    ReduceConcurrency { new_limit: u32 },
    Alert { message: String },
}

/// Resource tracker statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceTrackerStats {
    pub snapshots_taken: u64,
    pub violations_detected: u64,
    pub actions_executed: u64,
    pub memory_cleanups: u64,
    pub throttling_events: u64,
    pub peak_memory_usage: u64,
    pub peak_cpu_usage: f64,
    pub average_memory_usage: f64,
    pub average_cpu_usage: f64,
}

/// Resource tracker implementation
#[derive(Debug)]
pub struct ResourceTracker {
    config: Arc<RwLock<MonitoringConfig>>,
    limits: Arc<RwLock<ResourceLimits>>,
    snapshots: Arc<RwLock<VecDeque<ResourceSnapshot>>>,
    allocations: Arc<RwLock<HashMap<String, ResourceAllocation>>>,
    violations: Arc<RwLock<Vec<ResourceViolation>>>,
    stats: Arc<RwLock<ResourceTrackerStats>>,
    running: Arc<RwLock<bool>>,
    last_snapshot_time: Arc<RwLock<Option<Instant>>>,
}

impl ResourceTracker {
    /// Create a new resource tracker
    pub fn new(config: Arc<RwLock<MonitoringConfig>>) -> AgentResult<Self> {
        Ok(Self {
            config,
            limits: Arc::new(RwLock::new(ResourceLimits::default())),
            snapshots: Arc::new(RwLock::new(VecDeque::new())),
            allocations: Arc::new(RwLock::new(HashMap::new())),
            violations: Arc::new(RwLock::new(Vec::new())),
            stats: Arc::new(RwLock::new(ResourceTrackerStats {
                snapshots_taken: 0,
                violations_detected: 0,
                actions_executed: 0,
                memory_cleanups: 0,
                throttling_events: 0,
                peak_memory_usage: 0,
                peak_cpu_usage: 0.0,
                average_memory_usage: 0.0,
                average_cpu_usage: 0.0,
            })),
            running: Arc::new(RwLock::new(false)),
            last_snapshot_time: Arc::new(RwLock::new(None)),
        })
    }
    
    /// Start the resource tracker
    pub async fn start(&self) -> AgentResult<()> {
        info!("Starting resource tracker");
        
        {
            let mut running = self.running.write().map_err(|e| {
            AgentError::Service { 
                message: format!("Failed to acquire running lock: {}", e),
                service: "resource_tracker".to_string(),
                    context: None
                }
        })?;
            
            if *running {
                return Err(AgentError::Service { message: "Resource tracker is already running".to_string(), service: "resource_tracker".to_string(),
                    context: None
                });
            }
            
            *running = true;
        }
        
        // Start resource monitoring loop
        self.start_monitoring_loop().await?;
        
        info!("Resource tracker started successfully");
        Ok(())
    }
    
    /// Stop the resource tracker
    pub async fn stop(&self) -> AgentResult<()> {
        info!("Stopping resource tracker");
        
        {
            let mut running = self.running.write().map_err(|e| {
                AgentError::Service { 
                    message: format!("Failed to acquire running lock: {}", e),
                    service: "resource_tracker".to_string(),
                    context: None
                }
            })?;
            
            if !*running {
                return Ok(());
            }
            
            *running = false;
        }
        
        info!("Resource tracker stopped successfully");
        Ok(())
    }
    
    /// Take a resource usage snapshot
    pub async fn take_snapshot(&self) -> AgentResult<ResourceSnapshot> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let snapshot = ResourceSnapshot {
            timestamp,
            memory_usage_bytes: self.get_memory_usage().await?,
            memory_usage_percent: self.get_memory_usage_percent().await?,
            cpu_usage_percent: self.get_cpu_usage().await?,
            disk_io_read_bytes_per_sec: self.get_disk_read_rate().await?,
            disk_io_write_bytes_per_sec: self.get_disk_write_rate().await?,
            network_rx_bytes_per_sec: self.get_network_rx_rate().await?,
            network_tx_bytes_per_sec: self.get_network_tx_rate().await?,
            open_files_count: self.get_open_files_count().await?,
            active_scans_count: self.get_active_scans_count().await?,
            thread_count: self.get_thread_count().await?,
            handle_count: self.get_handle_count().await?,
        };
        
        // Store snapshot
        {
            let mut snapshots = self.snapshots.write().map_err(|e| {
                AgentError::Service { 
                    message: format!("Failed to write snapshots: {}", e),
                    service: "resource_tracker".to_string(),
                    context: None
                }
            })?;
            
            snapshots.push_back(snapshot.clone());
            
            // Keep only recent snapshots (last hour)
            let retention_limit = 3600; // 1 hour in seconds
            while let Some(front) = snapshots.front() {
                if timestamp - front.timestamp > retention_limit {
                    snapshots.pop_front();
                } else {
                    break;
                }
            }
        }
        
        // Update statistics
        self.update_stats(&snapshot).await?;
        
        // Check for violations
        self.check_violations(&snapshot).await?;
        
        // Update last snapshot time
        {
            let mut last_time = self.last_snapshot_time.write().map_err(|e| {
                AgentError::Service { 
                    message: format!("Failed to write last snapshot time: {}", e),
                    service: "resource_tracker".to_string(),
                    context: None
                }
            })?;
            *last_time = Some(Instant::now());
        }
        
        Ok(snapshot)
    }
    
    /// Get current resource limits
    pub fn get_limits(&self) -> AgentResult<ResourceLimits> {
        let limits = self.limits.read().map_err(|e| {
            AgentError::Service {
                message: format!("Failed to read resource limits: {}", e),
                service: "resource_tracker".to_string(),
                context: None
            }
        })?;
        
        Ok(limits.clone())
    }
    
    /// Update resource limits
    pub fn set_limits(&self, new_limits: ResourceLimits) -> AgentResult<()> {
        let mut limits = self.limits.write().map_err(|e| {
            AgentError::Service {
                message: format!("Failed to write resource limits: {}", e),
                service: "resource_tracker".to_string(),
                context: None
            }
        })?;
        
        *limits = new_limits;
        info!("Resource limits updated");
        Ok(())
    }
    
    /// Get recent snapshots
    pub fn get_snapshots(&self, limit: Option<usize>) -> AgentResult<Vec<ResourceSnapshot>> {
        let snapshots = self.snapshots.read().map_err(|e| {
            AgentError::Service {
                message: format!("Failed to read snapshots: {}", e),
                service: "resource_tracker".to_string(),
                context: None
            }
        })?;
        
        let result: Vec<ResourceSnapshot> = if let Some(limit) = limit {
            snapshots.iter().rev().take(limit).cloned().collect()
        } else {
            snapshots.iter().cloned().collect()
        };
        
        Ok(result)
    }
    
    /// Get resource violations
    pub fn get_violations(&self, limit: Option<usize>) -> AgentResult<Vec<ResourceViolation>> {
        let violations = self.violations.read().map_err(|e| {
            AgentError::Service {
                message: format!("Failed to read violations: {}", e),
                service: "resource_tracker".to_string(),
                context: None
            }
        })?;
        
        let result: Vec<ResourceViolation> = if let Some(limit) = limit {
            violations.iter().rev().take(limit).cloned().collect()
        } else {
            violations.iter().cloned().collect()
        };
        
        Ok(result)
    }
    
    /// Get resource allocations
    pub fn get_allocations(&self) -> AgentResult<HashMap<String, ResourceAllocation>> {
        let allocations = self.allocations.read().map_err(|e| {
            AgentError::Service { 
                message: format!("Failed to read allocations: {}", e),
                service: "resource_tracker".to_string(),
                context: None
            }
        })?;
        
        Ok(allocations.clone())
    }
    
    /// Register resource allocation
    pub fn register_allocation(&self, component: &str, allocation: ResourceAllocation) -> AgentResult<()> {
        let mut allocations = self.allocations.write().map_err(|e| {
            AgentError::Service { 
                message: format!("Failed to write allocations: {}", e),
                service: "resource_tracker".to_string(),
                context: None
            }
        })?;
        
        allocations.insert(component.to_string(), allocation);
        debug!("Resource allocation registered for component: {}", component);
        Ok(())
    }
    
    /// Unregister resource allocation
    pub fn unregister_allocation(&self, component: &str) -> AgentResult<()> {
        let mut allocations = self.allocations.write().map_err(|e| {
            AgentError::Service { 
                message: format!("Failed to write allocations: {}", e),
                service: "resource_tracker".to_string(),
                context: None
            }
        })?;
        
        allocations.remove(component);
        debug!("Resource allocation unregistered for component: {}", component);
        Ok(())
    }
    
    /// Get tracker statistics
    pub fn get_stats(&self) -> AgentResult<ResourceTrackerStats> {
        let stats = self.stats.read().map_err(|e| {
            AgentError::Service {
                message: format!("Failed to read tracker stats: {}", e),
                service: "resource_tracker".to_string(),
                context: None
            }
        })?;
        
        Ok(stats.clone())
    }
    
    /// Reset tracker statistics
    pub fn reset_stats(&self) -> AgentResult<()> {
        let mut stats = self.stats.write().map_err(|e| {
            AgentError::Service { 
                message: format!("Failed to write tracker stats: {}", e),
                service: "resource_tracker".to_string(),
                context: None
            }
        })?;
        
        *stats = ResourceTrackerStats {
            snapshots_taken: 0,
            violations_detected: 0,
            actions_executed: 0,
            memory_cleanups: 0,
            throttling_events: 0,
            peak_memory_usage: 0,
            peak_cpu_usage: 0.0,
            average_memory_usage: 0.0,
            average_cpu_usage: 0.0,
        };
        
        // Clear snapshots and violations
        {
            let mut snapshots = self.snapshots.write().map_err(|e| {
                AgentError::Service {
                    message: format!("Failed to write snapshots: {}", e),
                    service: "resource_tracker".to_string(),
                    context: None
                }
            })?;
            snapshots.clear();
        }
        
        {
            let mut violations = self.violations.write().map_err(|e| {
                AgentError::Service { 
                    message: format!("Failed to write violations: {}", e),
                    service: "resource_tracker".to_string(),
                    context: None
                }
            })?;
            violations.clear();
        }
        
        info!("Resource tracker statistics reset");
        Ok(())
    }
    
    /// Check if tracker is running
    pub fn is_running(&self) -> AgentResult<bool> {
        let running = self.running.read().map_err(|e| {
            AgentError::Service {
                message: format!("Failed to read running status: {}", e),
                service: "resource_tracker".to_string(),
                context: None
            }
        })?;
        
        Ok(*running)
    }
    
    /// Execute resource management action
    pub async fn execute_action(&self, action: ResourceAction) -> AgentResult<()> {
        match action {
            ResourceAction::Throttle { component, percentage } => {
                info!("Throttling component '{}' to {}%", component, percentage);
                // Implementation would depend on the specific component
                // Record throttling event
                // self.record_counter("throttling_events_total", 1.0);
            }
            ResourceAction::Pause { component, duration_seconds } => {
                info!("Pausing component '{}' for {} seconds", component, duration_seconds);
                // Implementation would depend on the specific component
            }
            ResourceAction::Terminate { component, reason } => {
                warn!("Terminating component '{}': {}", component, reason);
                // Implementation would depend on the specific component
            }
            ResourceAction::CleanupMemory { target_bytes } => {
                info!("Cleaning up {} bytes of memory", target_bytes);
                self.perform_memory_cleanup(target_bytes).await?;
            }
            ResourceAction::ReduceConcurrency { new_limit } => {
                info!("Reducing concurrency limit to {}", new_limit);
                // Implementation would update the concurrency limits
            }
            ResourceAction::Alert { message } => {
                warn!("Resource alert: {}", message);
            }
        }
        
        // Record action executed
        // self.record_counter("actions_executed_total", 1.0);
        Ok(())
    }
    
    /// Start the monitoring loop
    async fn start_monitoring_loop(&self) -> AgentResult<()> {
        let config = {
            let config = self.config.read().map_err(|e| {
                AgentError::Service { 
                    message: format!("Failed to read config: {}", e),
                    service: "resource_tracker".to_string(),
                    context: None
                }
            })?;
            config.clone()
        };
        
        // Clone Arc fields for the spawned task
        let config_arc = Arc::clone(&self.config);
        let running_arc = Arc::clone(&self.running);
        let snapshots_arc = Arc::clone(&self.snapshots);
        let stats_arc = Arc::clone(&self.stats);
        let limits_arc = Arc::clone(&self.limits);
        let violations_arc = Arc::clone(&self.violations);
        let allocations_arc = Arc::clone(&self.allocations);
        let last_snapshot_time_arc = Arc::clone(&self.last_snapshot_time);
        
        let interval_duration = Duration::from_secs(config.collection_interval_seconds);
        
        tokio::spawn(async move {
            let mut interval = interval(interval_duration);
            
            loop {
                interval.tick().await;
                
                // Check if still running
                let is_running = {
                    match running_arc.read() {
                        Ok(running_guard) => *running_guard,
                        Err(e) => {
                            error!("Failed to read running status: {}", e);
                            false
                        }
                    }
                };
                
                if !is_running {
                    break;
                }
                
                // Create a temporary ResourceTracker for method calls
                let temp_tracker = ResourceTracker {
                    config: Arc::clone(&config_arc),
                    running: Arc::clone(&running_arc),
                    snapshots: Arc::clone(&snapshots_arc),
                    stats: Arc::clone(&stats_arc),
                    limits: Arc::clone(&limits_arc),
                    violations: Arc::clone(&violations_arc),
                    allocations: Arc::clone(&allocations_arc),
                    last_snapshot_time: Arc::clone(&last_snapshot_time_arc),
                };
                
                // Take resource snapshot
                if let Err(e) = temp_tracker.take_snapshot().await {
                    error!("Failed to take resource snapshot: {}", e);
                }
            }
            
            debug!("Resource tracker monitoring loop stopped");
        });
        
        Ok(())
    }
    
    /// Get current memory usage in bytes
    async fn get_memory_usage(&self) -> AgentResult<u64> {
        // This would use system APIs to get actual memory usage
        // For now, return a mock value
        Ok(512 * 1024 * 1024) // 512MB
    }
    
    /// Get current memory usage percentage
    async fn get_memory_usage_percent(&self) -> AgentResult<f64> {
        // This would calculate based on total system memory
        // For now, return a mock value
        Ok(25.0)
    }
    
    /// Get current CPU usage percentage
    async fn get_cpu_usage(&self) -> AgentResult<f64> {
        // This would use system APIs to get actual CPU usage
        // For now, return a mock value
        Ok(35.0)
    }
    
    /// Get disk read rate in bytes per second
    async fn get_disk_read_rate(&self) -> AgentResult<u64> {
        // This would calculate based on disk I/O statistics
        // For now, return a mock value
        Ok(1024 * 1024) // 1MB/s
    }
    
    /// Get disk write rate in bytes per second
    async fn get_disk_write_rate(&self) -> AgentResult<u64> {
        // This would calculate based on disk I/O statistics
        // For now, return a mock value
        Ok(512 * 1024) // 512KB/s
    }
    
    /// Get network receive rate in bytes per second
    async fn get_network_rx_rate(&self) -> AgentResult<u64> {
        // This would calculate based on network statistics
        // For now, return a mock value
        Ok(256 * 1024) // 256KB/s
    }
    
    /// Get network transmit rate in bytes per second
    async fn get_network_tx_rate(&self) -> AgentResult<u64> {
        // This would calculate based on network statistics
        // For now, return a mock value
        Ok(128 * 1024) // 128KB/s
    }
    
    /// Get number of open files
    async fn get_open_files_count(&self) -> AgentResult<u32> {
        // This would use system APIs to get actual open file count
        // For now, return a mock value
        Ok(50)
    }
    
    /// Get number of active scans
    async fn get_active_scans_count(&self) -> AgentResult<u32> {
        // This would be provided by the YARA integration
        // For now, return a mock value
        Ok(2)
    }
    
    /// Get number of threads
    async fn get_thread_count(&self) -> AgentResult<u32> {
        // This would use system APIs to get actual thread count
        // For now, return a mock value
        Ok(8)
    }
    
    /// Get number of handles (Windows) or file descriptors (Unix)
    async fn get_handle_count(&self) -> AgentResult<u32> {
        // This would use system APIs to get actual handle count
        // For now, return a mock value
        Ok(150)
    }
    
    /// Update statistics with new snapshot
    async fn update_stats(&self, snapshot: &ResourceSnapshot) -> AgentResult<()> {
        let mut stats = self.stats.write().map_err(|e| {
            AgentError::Service {
                message: format!("Failed to write tracker stats: {}", e),
                service: "resource_tracker".to_string(),
                    context: None
                }
        })?;
        
        stats.snapshots_taken += 1;
        
        // Update peak values
        if snapshot.memory_usage_bytes > stats.peak_memory_usage {
            stats.peak_memory_usage = snapshot.memory_usage_bytes;
        }
        
        if snapshot.cpu_usage_percent > stats.peak_cpu_usage {
            stats.peak_cpu_usage = snapshot.cpu_usage_percent;
        }
        
        // Update averages
        let total_samples = stats.snapshots_taken as f64;
        stats.average_memory_usage = 
            (stats.average_memory_usage * (total_samples - 1.0) + snapshot.memory_usage_bytes as f64) / total_samples;
        
        stats.average_cpu_usage = 
            (stats.average_cpu_usage * (total_samples - 1.0) + snapshot.cpu_usage_percent) / total_samples;
        
        Ok(())
    }
    
    /// Check for resource violations
    async fn check_violations(&self, snapshot: &ResourceSnapshot) -> AgentResult<()> {
        let limits = {
            let limits = self.limits.read().map_err(|e| {
                AgentError::Service { 
                    message: format!("Failed to read resource limits: {}", e),
                    service: "resource_tracker".to_string(),
                    context: None
                }
            })?;
            limits.clone()
        };
        
        let timestamp = snapshot.timestamp;
        
        // Check memory usage
        if let Some(max_memory) = limits.max_memory_bytes {
            if snapshot.memory_usage_bytes > max_memory {
                let violation = ResourceViolation {
                    id: format!("memory-bytes-{}", timestamp),
                    resource_type: "memory_bytes".to_string(),
                    current_value: snapshot.memory_usage_bytes as f64,
                    limit_value: max_memory as f64,
                    severity: ViolationSeverity::Critical,
                    timestamp,
                    component: None,
                    action_taken: Some("memory_cleanup".to_string()),
                };
                
                self.record_violation(violation).await?;
                
                // Execute cleanup action
                let cleanup_target = snapshot.memory_usage_bytes - max_memory;
                self.execute_action(ResourceAction::CleanupMemory { 
                    target_bytes: cleanup_target 
                }).await?;
            }
        }
        
        if let Some(max_memory_percent) = limits.max_memory_percent {
            if snapshot.memory_usage_percent > max_memory_percent {
                let violation = ResourceViolation {
                    id: format!("memory-percent-{}", timestamp),
                    resource_type: "memory_percent".to_string(),
                    current_value: snapshot.memory_usage_percent,
                    limit_value: max_memory_percent,
                    severity: ViolationSeverity::Warning,
                    timestamp,
                    component: None,
                    action_taken: None,
                };
                
                self.record_violation(violation).await?;
            }
        }
        
        // Check CPU usage
        if let Some(max_cpu) = limits.max_cpu_percent {
            if snapshot.cpu_usage_percent > max_cpu {
                let severity = if snapshot.cpu_usage_percent > max_cpu * 1.2 {
                    ViolationSeverity::Critical
                } else {
                    ViolationSeverity::Warning
                };
                
                let violation = ResourceViolation {
                    id: format!("cpu-{}", timestamp),
                    resource_type: "cpu_percent".to_string(),
                    current_value: snapshot.cpu_usage_percent,
                    limit_value: max_cpu,
                    severity: severity.clone(),
                    timestamp,
                    component: None,
                    action_taken: if severity == ViolationSeverity::Critical {
                        Some("throttle".to_string())
                    } else {
                        None
                    },
                };
                
                self.record_violation(violation).await?;
                
                // Execute throttling action for critical violations
                if severity == ViolationSeverity::Critical {
                    self.execute_action(ResourceAction::Throttle {
                        component: "yara_scanner".to_string(),
                        percentage: 50.0,
                    }).await?;
                }
            }
        }
        
        // Check concurrent scans
        if let Some(max_scans) = limits.max_concurrent_scans {
            if snapshot.active_scans_count > max_scans {
                let violation = ResourceViolation {
                    id: format!("concurrent-scans-{}", timestamp),
                    resource_type: "concurrent_scans".to_string(),
                    current_value: snapshot.active_scans_count as f64,
                    limit_value: max_scans as f64,
                    severity: ViolationSeverity::Warning,
                    timestamp,
                    component: Some("yara_scanner".to_string()),
                    action_taken: Some("reduce_concurrency".to_string()),
                };
                
                self.record_violation(violation).await?;
                
                // Reduce concurrency
                self.execute_action(ResourceAction::ReduceConcurrency {
                    new_limit: max_scans,
                }).await?;
            }
        }
        
        Ok(())
    }
    
    /// Record a resource violation
    async fn record_violation(&self, violation: ResourceViolation) -> AgentResult<()> {
        {
            let mut violations = self.violations.write().map_err(|e| {
                AgentError::Service { 
                    message: format!("Failed to write violations: {}", e),
                    service: "resource_tracker".to_string(),
                    context: None
                }
            })?;
            violations.push(violation.clone());
        }
        
        // Update statistics
        {
            let mut stats = self.stats.write().map_err(|e| {
                AgentError::Service { 
                    message: format!("Failed to write tracker stats: {}", e),
                    service: "resource_tracker".to_string(),
                    context: None
                }
            })?;
            stats.violations_detected += 1;
        }
        
        match violation.severity {
            ViolationSeverity::Emergency => {
                error!("RESOURCE VIOLATION [EMERGENCY]: {} = {} > {}", 
                       violation.resource_type, violation.current_value, violation.limit_value);
            }
            ViolationSeverity::Critical => {
                error!("RESOURCE VIOLATION [CRITICAL]: {} = {} > {}", 
                       violation.resource_type, violation.current_value, violation.limit_value);
            }
            ViolationSeverity::Warning => {
                warn!("RESOURCE VIOLATION [WARNING]: {} = {} > {}", 
                      violation.resource_type, violation.current_value, violation.limit_value);
            }
        }
        
        Ok(())
    }
    
    /// Perform memory cleanup
    async fn perform_memory_cleanup(&self, target_bytes: u64) -> AgentResult<()> {
        info!("Performing memory cleanup, target: {} bytes", target_bytes);
        
        // In a real implementation, this would:
        // 1. Clear caches
        // 2. Force garbage collection
        // 3. Release unused buffers
        // 4. Compact memory pools
        
        // Update statistics
        {
            let mut stats = self.stats.write().map_err(|e| {
                AgentError::Service { 
                    message: format!("Failed to write tracker stats: {}", e),
                    service: "resource_tracker".to_string(),
                    context: None
                }
            })?;
            stats.memory_cleanups += 1;
        }
        
        Ok(())
    }
    
    /// Increment throttling events counter
    async fn increment_throttling_events(&self) -> AgentResult<()> {
        let mut stats = self.stats.write().map_err(|e| {
            AgentError::Service { 
                message: format!("Failed to write tracker stats: {}", e),
                service: "resource_tracker".to_string(),
                    context: None
                }
        })?;
        stats.throttling_events += 1;
        Ok(())
    }
    
    /// Increment actions executed counter
    async fn increment_actions_executed(&self) -> AgentResult<()> {
        let mut stats = self.stats.write().map_err(|e| {
            AgentError::Service { 
                message: format!("Failed to write tracker stats: {}", e),
                service: "resource_tracker".to_string(),
                    context: None
                }
        })?;
        stats.actions_executed += 1;
        Ok(())
    }
}

#[cfg(all(test, feature = "metrics"))]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_resource_tracker_creation() {
        let config = Arc::new(RwLock::new(MonitoringConfig::default()));
        let tracker = ResourceTracker::new(config);
        assert!(tracker.is_ok());
    }
    
    #[tokio::test]
    async fn test_resource_limits() {
        let config = Arc::new(RwLock::new(MonitoringConfig::default()));
        let tracker = ResourceTracker::new(config).unwrap();
        
        let limits = tracker.get_limits().unwrap();
        assert!(limits.max_memory_bytes.is_some());
        assert!(limits.max_cpu_percent.is_some());
        
        let new_limits = ResourceLimits {
            max_memory_bytes: Some(1024 * 1024 * 1024), // 1GB
            ..Default::default()
        };
        
        tracker.set_limits(new_limits.clone()).unwrap();
        let updated_limits = tracker.get_limits().unwrap();
        assert_eq!(updated_limits.max_memory_bytes, new_limits.max_memory_bytes);
    }
    
    #[tokio::test]
    async fn test_resource_allocation() {
        let config = Arc::new(RwLock::new(MonitoringConfig::default()));
        let tracker = ResourceTracker::new(config).unwrap();
        
        let allocation = ResourceAllocation {
            component: "test_component".to_string(),
            memory_allocated: 1024 * 1024, // 1MB
            cpu_time_ms: 1000,
            files_opened: 5,
            network_connections: 2,
            allocation_time: 1234567890,
            last_activity: 1234567890,
        };
        
        tracker.register_allocation("test", allocation.clone()).unwrap();
        
        let allocations = tracker.get_allocations().unwrap();
        assert!(allocations.contains_key("test"));
        
        tracker.unregister_allocation("test").unwrap();
        
        let allocations = tracker.get_allocations().unwrap();
        assert!(!allocations.contains_key("test"));
    }
    
    #[test]
    fn test_resource_limits_default() {
        let limits = ResourceLimits::default();
        assert!(limits.max_memory_bytes.is_some());
        assert!(limits.max_cpu_percent.is_some());
        assert!(limits.max_concurrent_scans.is_some());
    }
    
    #[test]
    fn test_violation_severity() {
        assert_eq!(ViolationSeverity::Critical, ViolationSeverity::Critical);
        assert_ne!(ViolationSeverity::Warning, ViolationSeverity::Critical);
    }
}
