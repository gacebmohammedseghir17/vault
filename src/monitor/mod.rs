//! Monitoring module for the ERDPS Agent
//!
//! This module provides various monitoring capabilities including:
//! - Filesystem monitoring for continuous scanning
//! - Process monitoring
//! - System resource monitoring
//! - Performance monitoring with SLO enforcement

pub mod fs;
pub mod performance;

use crate::monitor::performance::{PerformanceMonitor, SloViolationHandler};
use tokio::task;
use tracing::info;

/// Initialize the monitoring subsystem
pub fn init() {
    info!("Initializing monitoring subsystem");
    // Additional initialization logic can be added here
}

/// Initialize the monitoring subsystem with SLO enforcement (async version)
pub async fn init_async() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!("Initializing monitoring subsystem with SLO enforcement");

    // Create performance monitor with strict SLO thresholds
    let (monitor, violation_receiver) = PerformanceMonitor::new();
    let mut violation_handler = SloViolationHandler::new(violation_receiver);

    // Start performance monitoring in background
    let _monitor_handle = {
        let monitor = std::sync::Arc::new(monitor);
        let monitor_clone = monitor.clone();
        task::spawn(async move {
            monitor_clone.start_monitoring().await;
        })
    };

    // Start violation handler in background
    let _handler_handle = task::spawn(async move {
        violation_handler.start_handling().await;
    });

    info!("Performance monitoring and SLO enforcement started");

    // Store handles for cleanup (in a real implementation)
    // For now, we'll let them run in the background

    Ok(())
}
