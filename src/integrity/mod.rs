//! Integrity Monitoring Module
//!
//! This module provides comprehensive file and process integrity monitoring capabilities
//! for the ERDPS Agent Phase 2 enhancement. It includes real-time monitoring of
//! file system changes, binary tampering detection, and process creation chains
//! using Windows APIs and Event Tracing (ETW).
//!
//! Key components:
//! - File integrity monitoring with real-time change detection
//! - Binary tampering and modification detection
//! - Process creation chain monitoring and analysis
//! - Suspicious process behavior detection

pub mod file_integrity;
pub mod process_watch;

pub use file_integrity::{FileIntegrityConfig, FileIntegrityEvent, FileIntegrityMonitor};
pub use process_watch::{ProcessWatchConfig, ProcessWatchEvent, ProcessWatchMonitor};

use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info};

/// Integrity monitoring system that coordinates all integrity-related monitoring
pub struct IntegrityMonitoringSystem {
    file_integrity_monitor: Arc<RwLock<Option<FileIntegrityMonitor>>>,
    process_watch_monitor: Arc<RwLock<Option<ProcessWatchMonitor>>>,
    is_running: Arc<RwLock<bool>>,
}

impl IntegrityMonitoringSystem {
    /// Create a new integrity monitoring system
    pub fn new() -> Self {
        Self {
            file_integrity_monitor: Arc::new(RwLock::new(None)),
            process_watch_monitor: Arc::new(RwLock::new(None)),
            is_running: Arc::new(RwLock::new(false)),
        }
    }

    /// Start all integrity monitoring components
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut is_running = self.is_running.write().await;
        if *is_running {
            return Ok(());
        }

        info!("Starting integrity monitoring system");

        // Initialize and start file integrity monitor
        let file_integrity_config = FileIntegrityConfig::default();
        let file_integrity_monitor = FileIntegrityMonitor::new(file_integrity_config);
        file_integrity_monitor.start().await?;
        *self.file_integrity_monitor.write().await = Some(file_integrity_monitor);

        // Initialize and start process watch monitor
        let process_watch_config = ProcessWatchConfig::default();
        let process_watch_monitor = ProcessWatchMonitor::new(process_watch_config);
        process_watch_monitor.start().await?;
        *self.process_watch_monitor.write().await = Some(process_watch_monitor);

        *is_running = true;
        info!("Integrity monitoring system started successfully");
        Ok(())
    }

    /// Stop all integrity monitoring components
    pub async fn stop(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut is_running = self.is_running.write().await;
        if !*is_running {
            return Ok(());
        }

        info!("Stopping integrity monitoring system");

        // Stop file integrity monitor
        if let Some(monitor) = self.file_integrity_monitor.write().await.take() {
            if let Err(e) = monitor.stop().await {
                error!("Failed to stop file integrity monitor: {}", e);
            }
        }

        // Stop process watch monitor
        if let Some(monitor) = self.process_watch_monitor.write().await.take() {
            if let Err(e) = monitor.stop().await {
                error!("Failed to stop process watch monitor: {}", e);
            }
        }

        *is_running = false;
        info!("Integrity monitoring system stopped successfully");
        Ok(())
    }

    /// Check if the integrity monitoring system is running
    pub async fn is_running(&self) -> bool {
        *self.is_running.read().await
    }

    /// Get file integrity monitor reference
    pub async fn get_file_integrity_monitor(&self) -> Option<FileIntegrityMonitor> {
        self.file_integrity_monitor.read().await.clone()
    }

    /// Get process watch monitor reference
    pub async fn get_process_watch_monitor(&self) -> Option<ProcessWatchMonitor> {
        self.process_watch_monitor.read().await.clone()
    }
}

impl Default for IntegrityMonitoringSystem {
    fn default() -> Self {
        Self::new()
    }
}
