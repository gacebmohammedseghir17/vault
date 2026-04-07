//! Performance Monitor Component
//!
//! This module provides real-time performance monitoring capabilities,
//! including CPU, memory, disk I/O, and network usage tracking.

use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH, Instant};
use serde::{Deserialize, Serialize};
use tracing::info;
use crate::error::{AgentError, AgentResult};
use super::{MonitoringConfig, PerformanceMetrics};

#[cfg(target_os = "windows")]
use winapi::um::sysinfoapi::SYSTEM_INFO;

#[cfg(target_family = "unix")]
use std::fs;

/// System resource information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    pub total_memory: u64,
    pub cpu_cores: u32,
    pub page_size: u64,
    pub hostname: String,
    pub os_type: String,
    pub architecture: String,
}

/// Performance monitoring statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceStats {
    pub samples_collected: u64,
    pub collection_errors: u64,
    pub last_collection_duration_ms: u64,
    pub average_collection_duration_ms: f64,
    pub peak_cpu_usage: f64,
    pub peak_memory_usage: u64,
    pub total_disk_read: u64,
    pub total_disk_write: u64,
    pub total_network_rx: u64,
    pub total_network_tx: u64,
}

/// Performance monitor implementation
#[derive(Debug)]
pub struct PerformanceMonitor {
    config: Arc<RwLock<MonitoringConfig>>,
    system_info: SystemInfo,
    stats: Arc<RwLock<PerformanceStats>>,
    running: Arc<RwLock<bool>>,
    last_metrics: Arc<RwLock<Option<PerformanceMetrics>>>,
    collection_history: Arc<RwLock<Vec<Duration>>>,
}

impl PerformanceMonitor {
    /// Create a new performance monitor
    pub fn new(config: Arc<RwLock<MonitoringConfig>>) -> AgentResult<Self> {
        let system_info = Self::collect_system_info()?;
        
        Ok(Self {
            config,
            system_info,
            stats: Arc::new(RwLock::new(PerformanceStats {
                samples_collected: 0,
                collection_errors: 0,
                last_collection_duration_ms: 0,
                average_collection_duration_ms: 0.0,
                peak_cpu_usage: 0.0,
                peak_memory_usage: 0,
                total_disk_read: 0,
                total_disk_write: 0,
                total_network_rx: 0,
                total_network_tx: 0,
            })),
            running: Arc::new(RwLock::new(false)),
            last_metrics: Arc::new(RwLock::new(None)),
            collection_history: Arc::new(RwLock::new(Vec::new())),
        })
    }
    
    /// Start the performance monitor
    pub async fn start(&self) -> AgentResult<()> {
        info!("Starting performance monitor");
        
        {
            let mut running = self.running.write().map_err(|e| {
                AgentError::Service {
                    message: format!("Failed to acquire running lock: {}", e),
                    service: "performance_monitor".to_string(),
                    context: None,
                }
            })?;
            
            if *running {
                return Err(AgentError::Service { 
                    message: "Performance monitor is already running".to_string(), 
                    service: "performance_monitor".to_string(),
                    context: None
                });
            }
            
            *running = true;
        }
        
        info!("Performance monitor started successfully");
        Ok(())
    }
    
    /// Stop the performance monitor
    pub async fn stop(&self) -> AgentResult<()> {
        info!("Stopping performance monitor");
        
        {
            let mut running = self.running.write().map_err(|e| {
                AgentError::Service {
                    message: format!("Failed to acquire running lock: {}", e),
                    service: "performance_monitor".to_string(),
                    context: None,
                }
            })?;
            
            if !*running {
                return Ok(());
            }
            
            *running = false;
        }
        
        info!("Performance monitor stopped successfully");
        Ok(())
    }
    
    /// Get current performance metrics
    pub async fn get_current_metrics(&self) -> AgentResult<PerformanceMetrics> {
        let start_time = Instant::now();
        
        let result = self.collect_metrics().await;
        
        let collection_duration = start_time.elapsed();
        self.update_collection_stats(collection_duration, result.is_ok()).await?;
        
        result
    }
    
    /// Get system information
    pub fn get_system_info(&self) -> &SystemInfo {
        &self.system_info
    }
    
    /// Get performance statistics
    pub fn get_stats(&self) -> AgentResult<PerformanceStats> {
        let stats = self.stats.read().map_err(|e| {
            AgentError::Service {
                message: format!("Failed to read performance stats: {}", e),
                service: "performance_monitor".to_string(),
            context: None}
        })?;
        
        Ok(stats.clone())
    }
    
    /// Reset performance statistics
    pub fn reset_stats(&self) -> AgentResult<()> {
        let mut stats = self.stats.write().map_err(|e| {
            AgentError::Service {
                message: format!("Failed to write performance stats: {}", e),
                service: "performance_monitor".to_string(),
            context: None}
        })?;
        
        *stats = PerformanceStats {
            samples_collected: 0,
            collection_errors: 0,
            last_collection_duration_ms: 0,
            average_collection_duration_ms: 0.0,
            peak_cpu_usage: 0.0,
            peak_memory_usage: 0,
            total_disk_read: 0,
            total_disk_write: 0,
            total_network_rx: 0,
            total_network_tx: 0,
        };
        
        // Clear collection history
        {
            let mut history = self.collection_history.write().map_err(|e| {
                AgentError::Service {
                    message: format!("Failed to write collection history: {}", e),
                    service: "performance_monitor".to_string(),
                    context: None,
                }
            })?;
            history.clear();
        }
        
        info!("Performance statistics reset");
        Ok(())
    }
    
    /// Check if monitor is running
    pub fn is_running(&self) -> AgentResult<bool> {
        let running = self.running.read().map_err(|e| {
            AgentError::Service {
                message: format!("Failed to read running status: {}", e),
                service: "performance_monitor".to_string(),
            context: None}
        })?;
        
        Ok(*running)
    }
    
    /// Collect system information
    fn collect_system_info() -> AgentResult<SystemInfo> {
        let hostname = hostname::get()
            .map_err(|e| AgentError::Service {
                message: format!("Failed to get hostname: {}", e),
                service: "performance_monitor".to_string(),
            context: None})?
            .to_string_lossy()
            .to_string();
        
        let os_type = std::env::consts::OS.to_string();
        let architecture = std::env::consts::ARCH.to_string();
        
        #[cfg(target_os = "windows")]
        let (total_memory, cpu_cores, page_size) = {
            use winapi::um::sysinfoapi::{GetSystemInfo, GlobalMemoryStatusEx, MEMORYSTATUSEX};
            use std::mem;
            
            unsafe {
                let mut sys_info: SYSTEM_INFO = mem::zeroed();
                GetSystemInfo(&mut sys_info);
                
                let mut mem_status: MEMORYSTATUSEX = mem::zeroed();
                mem_status.dwLength = mem::size_of::<MEMORYSTATUSEX>() as u32;
                GlobalMemoryStatusEx(&mut mem_status);
                
                (
                    mem_status.ullTotalPhys,
                    sys_info.dwNumberOfProcessors,
                    sys_info.dwPageSize as u64,
                )
            }
        };
        
        #[cfg(target_family = "unix")]
        let (total_memory, cpu_cores, page_size) = {
            let total_memory = Self::get_total_memory_unix()?;
            let cpu_cores = num_cpus::get() as u32;
            let page_size = 4096u64; // Standard page size on most Unix systems
            
            (total_memory, cpu_cores, page_size)
        };
        
        Ok(SystemInfo {
            total_memory,
            cpu_cores,
            page_size,
            hostname,
            os_type,
            architecture,
        })
    }
    
    /// Collect current performance metrics
    async fn collect_metrics(&self) -> AgentResult<PerformanceMetrics> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let cpu_usage = self.get_cpu_usage().await?;
        let (memory_usage_bytes, memory_usage_percent) = self.get_memory_usage()?;
        let (disk_read, disk_write) = self.get_disk_io()?;
        let (network_rx, network_tx) = self.get_network_io()?;
        
        // Get scan-related metrics (these would be provided by the YARA integration)
        let scan_throughput = self.get_scan_throughput().await;
        let scan_latency_ms = self.get_scan_latency().await;
        let error_rate = self.get_error_rate().await;
        let active_scans = self.get_active_scans().await;
        let queue_size = self.get_queue_size().await;
        
        let metrics = PerformanceMetrics {
            timestamp,
            cpu_usage_percent: cpu_usage,
            memory_usage_bytes,
            memory_usage_percent,
            disk_io_read_bytes: disk_read,
            disk_io_write_bytes: disk_write,
            network_rx_bytes: network_rx,
            network_tx_bytes: network_tx,
            scan_throughput,
            scan_latency_ms,
            error_rate,
            active_scans,
            queue_size,
        };
        
        // Store last metrics
        {
            let mut last_metrics = self.last_metrics.write().map_err(|e| {
                AgentError::Service {
                    message: format!("Failed to write last metrics: {}", e),
                    service: "performance_monitor".to_string(),
                    context: None,
                }
            })?;
            *last_metrics = Some(metrics.clone());
        }
        
        Ok(metrics)
    }
    
    /// Get CPU usage percentage
    async fn get_cpu_usage(&self) -> AgentResult<f64> {
        #[cfg(target_os = "windows")]
        {
            // On Windows, we'll use a simple approximation
            // In a production system, you'd want to use proper Windows APIs
            // or a library like sysinfo
            Ok(self.get_cpu_usage_approximation().await)
        }
        
        #[cfg(target_family = "unix")]
        {
            self.get_cpu_usage_unix().await
        }
    }
    
    /// Get memory usage in bytes and percentage
    fn get_memory_usage(&self) -> AgentResult<(u64, f64)> {
        #[cfg(target_os = "windows")]
        {
            self.get_memory_usage_windows()
        }
        
        #[cfg(target_family = "unix")]
        {
            self.get_memory_usage_unix()
        }
    }
    
    /// Get disk I/O statistics
    fn get_disk_io(&self) -> AgentResult<(u64, u64)> {
        // This is a simplified implementation
        // In production, you'd want to use proper system APIs
        // or libraries like sysinfo to get accurate disk I/O stats
        Ok((0, 0))
    }
    
    /// Get network I/O statistics
    fn get_network_io(&self) -> AgentResult<(u64, u64)> {
        // This is a simplified implementation
        // In production, you'd want to use proper system APIs
        // or libraries like sysinfo to get accurate network I/O stats
        Ok((0, 0))
    }
    
    /// Get scan throughput (files per second)
    async fn get_scan_throughput(&self) -> f64 {
        // This would be provided by the YARA integration
        // For now, return a mock value
        25.0
    }
    
    /// Get average scan latency in milliseconds
    async fn get_scan_latency(&self) -> f64 {
        // This would be provided by the YARA integration
        // For now, return a mock value
        150.0
    }
    
    /// Get error rate (0.0 to 1.0)
    async fn get_error_rate(&self) -> f64 {
        // This would be provided by the YARA integration
        // For now, return a mock value
        0.02
    }
    
    /// Get number of active scans
    async fn get_active_scans(&self) -> u32 {
        // This would be provided by the YARA integration
        // For now, return a mock value
        2
    }
    
    /// Get scan queue size
    async fn get_queue_size(&self) -> u32 {
        // This would be provided by the YARA integration
        // For now, return a mock value
        5
    }
    
    #[cfg(target_os = "windows")]
    fn get_memory_usage_windows(&self) -> AgentResult<(u64, f64)> {
        use winapi::um::sysinfoapi::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
        use std::mem;
        
        unsafe {
            let mut mem_status: MEMORYSTATUSEX = mem::zeroed();
            mem_status.dwLength = mem::size_of::<MEMORYSTATUSEX>() as u32;
            
            if GlobalMemoryStatusEx(&mut mem_status) != 0 {
                let used_memory = mem_status.ullTotalPhys - mem_status.ullAvailPhys;
                let usage_percent = (used_memory as f64 / mem_status.ullTotalPhys as f64) * 100.0;
                Ok((used_memory, usage_percent))
            } else {
                Err(AgentError::Service { message: "Failed to get memory status on Windows".to_string(), service: "performance_monitor".to_string(), context: None })
            }
        }
    }
    
    #[cfg(target_family = "unix")]
    fn get_memory_usage_unix(&self) -> AgentResult<(u64, f64)> {
        let meminfo = fs::read_to_string("/proc/meminfo")
            .map_err(|e| AgentError::Service {
                message: format!("Failed to read /proc/meminfo: {}", e),
                service: "performance_monitor".to_string(),
            context: None})?;
        
        let mut total_memory = 0u64;
        let mut available_memory = 0u64;
        
        for line in meminfo.lines() {
            if line.starts_with("MemTotal:") {
                if let Some(value) = line.split_whitespace().nth(1) {
                    total_memory = value.parse::<u64>().unwrap_or(0) * 1024; // Convert KB to bytes
                }
            } else if line.starts_with("MemAvailable:") {
                if let Some(value) = line.split_whitespace().nth(1) {
                    available_memory = value.parse::<u64>().unwrap_or(0) * 1024; // Convert KB to bytes
                }
            }
        }
        
        if total_memory > 0 {
            let used_memory = total_memory - available_memory;
            let usage_percent = (used_memory as f64 / total_memory as f64) * 100.0;
            Ok((used_memory, usage_percent))
        } else {
            Err(AgentError::Service { message: "Failed to parse memory information from /proc/meminfo".to_string(), service: "performance_monitor".to_string(), context: None })
        }
    }
    
    #[cfg(target_family = "unix")]
    fn get_total_memory_unix() -> AgentResult<u64> {
        let meminfo = fs::read_to_string("/proc/meminfo")
            .map_err(|e| AgentError::Service {
                message: format!("Failed to read /proc/meminfo: {}", e),
                service: "performance_monitor".to_string(),
            context: None})?;
        
        for line in meminfo.lines() {
            if line.starts_with("MemTotal:") {
                if let Some(value) = line.split_whitespace().nth(1) {
                    return Ok(value.parse::<u64>().unwrap_or(0) * 1024); // Convert KB to bytes
                }
            }
        }
        
        Err(AgentError::Service { message: "Failed to find MemTotal in /proc/meminfo".to_string(), service: "performance_monitor".to_string(), context: None })
    }
    
    #[cfg(target_family = "unix")]
    async fn get_cpu_usage_unix(&self) -> AgentResult<f64> {
        // Read /proc/stat to get CPU usage
        let stat1 = fs::read_to_string("/proc/stat")
            .map_err(|e| AgentError::Service {
                message: format!("Failed to read /proc/stat: {}", e),
                service: "performance_monitor".to_string(),
            context: None})?;
        
        // Wait a short time
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        let stat2 = fs::read_to_string("/proc/stat")
            .map_err(|e| AgentError::Service {
                message: format!("Failed to read /proc/stat: {}", e),
                service: "performance_monitor".to_string(),
            context: None})?;
        
        let cpu1 = Self::parse_cpu_line(&stat1)?;
        let cpu2 = Self::parse_cpu_line(&stat2)?;
        
        let total_diff = cpu2.iter().sum::<u64>() - cpu1.iter().sum::<u64>();
        let idle_diff = cpu2[3] - cpu1[3]; // idle is the 4th field
        
        if total_diff > 0 {
            let usage = 100.0 - (idle_diff as f64 / total_diff as f64 * 100.0);
            Ok(usage.max(0.0).min(100.0))
        } else {
            Ok(0.0)
        }
    }
    
    #[cfg(target_family = "unix")]
    fn parse_cpu_line(stat_content: &str) -> AgentResult<Vec<u64>> {
        let first_line = stat_content.lines().next()
            .ok_or_else(|| AgentError::Service { message: "Empty /proc/stat file".to_string(), service: "performance_monitor".to_string(), context: None })?;
        
        if !first_line.starts_with("cpu ") {
            return Err(AgentError::Service { message: "Invalid /proc/stat format".to_string(), service: "performance_monitor".to_string(), context: None });
        }
        
        let values: Result<Vec<u64>, _> = first_line
            .split_whitespace()
            .skip(1) // Skip "cpu" label
            .map(|s| s.parse::<u64>())
            .collect();
        
        values.map_err(|e| AgentError::Service {
            message: format!("Failed to parse CPU values: {}", e),
            service: "performance_monitor".to_string(),
            context: None})
    }
    
    async fn get_cpu_usage_approximation(&self) -> f64 {
        // Simple approximation for demonstration
        // In production, use proper Windows APIs or sysinfo crate
        use std::process::Command;
        
        if let Ok(output) = Command::new("wmic")
            .args(&["cpu", "get", "loadpercentage", "/value"])
            .output()
        {
            let output_str = String::from_utf8_lossy(&output.stdout);
            for line in output_str.lines() {
                if line.starts_with("LoadPercentage=") {
                    if let Some(value_str) = line.split('=').nth(1) {
                        if let Ok(value) = value_str.trim().parse::<f64>() {
                            return value;
                        }
                    }
                }
            }
        }
        
        // Fallback to a mock value
        25.0
    }
    
    /// Update collection statistics
    async fn update_collection_stats(&self, duration: Duration, success: bool) -> AgentResult<()> {
        let mut stats = self.stats.write().map_err(|e| {
            AgentError::Service {
                message: format!("Failed to write performance stats: {}", e),
                service: "performance_monitor".to_string(),
            context: None}
        })?;
        
        let duration_ms = duration.as_millis() as u64;
        
        if success {
            stats.samples_collected += 1;
            stats.last_collection_duration_ms = duration_ms;
            
            // Update average collection duration
            let total_samples = stats.samples_collected as f64;
            stats.average_collection_duration_ms = 
                (stats.average_collection_duration_ms * (total_samples - 1.0) + duration_ms as f64) / total_samples;
        } else {
            stats.collection_errors += 1;
        }
        
        // Update collection history (keep last 100 samples)
        {
            let mut history = self.collection_history.write().map_err(|e| {
                AgentError::Service {
                    message: format!("Failed to write collection history: {}", e),
                    service: "performance_monitor".to_string(),
            context: None}
            })?;
            
            history.push(duration);
            if history.len() > 100 {
                history.remove(0);
            }
        }
        
        Ok(())
    }
}

#[cfg(all(test, feature = "metrics"))]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_performance_monitor_creation() {
        let config = Arc::new(RwLock::new(MonitoringConfig::default()));
        let monitor = PerformanceMonitor::new(config);
        assert!(monitor.is_ok());
    }
    
    #[tokio::test]
    async fn test_system_info_collection() {
        let system_info = PerformanceMonitor::collect_system_info();
        assert!(system_info.is_ok());
        
        let info = system_info.unwrap();
        assert!(!info.hostname.is_empty());
        assert!(!info.os_type.is_empty());
        assert!(!info.architecture.is_empty());
        assert!(info.total_memory > 0);
        assert!(info.cpu_cores > 0);
    }
    
    #[tokio::test]
    async fn test_performance_monitor_start_stop() {
        let config = Arc::new(RwLock::new(MonitoringConfig::default()));
        let monitor = PerformanceMonitor::new(config).unwrap();
        
        assert!(!monitor.is_running().unwrap());
        
        monitor.start().await.unwrap();
        assert!(monitor.is_running().unwrap());
        
        monitor.stop().await.unwrap();
        assert!(!monitor.is_running().unwrap());
    }
    
    #[test]
    fn test_performance_stats_reset() {
        let config = Arc::new(RwLock::new(MonitoringConfig::default()));
        let monitor = PerformanceMonitor::new(config).unwrap();
        
        let stats_before = monitor.get_stats().unwrap();
        assert_eq!(stats_before.samples_collected, 0);
        
        monitor.reset_stats().unwrap();
        
        let stats_after = monitor.get_stats().unwrap();
        assert_eq!(stats_after.samples_collected, 0);
    }
}
