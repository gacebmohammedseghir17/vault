//! Identity Monitoring Module
//!
//! This module provides comprehensive identity and credential monitoring capabilities
//! for the ERDPS Agent Phase 2 enhancement. It includes real-time monitoring of
//! LSASS processes, PowerShell execution, and other identity-related security events
//! using Windows Event Tracing (ETW).
//!
//! Key components:
//! - LSASS monitoring for credential access detection
//! - PowerShell script block execution monitoring
//! - Identity-based threat detection and analysis

pub mod lsass_monitor;
pub mod powershell_monitor;

pub use lsass_monitor::{LsassEvent, LsassMonitor, LsassMonitorConfig};
pub use powershell_monitor::{PowerShellEvent, PowerShellMonitor, PowerShellMonitorConfig};

use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info};



/// Identity monitoring system that coordinates all identity-related monitoring
pub struct IdentityMonitoringSystem {
    lsass_monitor: Arc<RwLock<Option<LsassMonitor>>>,
    powershell_monitor: Arc<RwLock<Option<PowerShellMonitor>>>,
    is_running: Arc<RwLock<bool>>,
}

impl IdentityMonitoringSystem {
    /// Create a new identity monitoring system
    pub fn new() -> Self {
        Self {
            lsass_monitor: Arc::new(RwLock::new(None)),
            powershell_monitor: Arc::new(RwLock::new(None)),
            is_running: Arc::new(RwLock::new(false)),
        }
    }

    /// Start all identity monitoring components
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut is_running = self.is_running.write().await;
        if *is_running {
            return Ok(());
        }

        info!("Starting identity monitoring system");

        // Initialize and start LSASS monitor
        let lsass_config = LsassMonitorConfig::default();
        let lsass_monitor = LsassMonitor::new(lsass_config);
        lsass_monitor.start().await?;
        *self.lsass_monitor.write().await = Some(lsass_monitor);

        // Initialize and start PowerShell monitor
        let powershell_config = PowerShellMonitorConfig::default();
        let powershell_monitor = PowerShellMonitor::new(powershell_config);
        powershell_monitor.start().await?;
        *self.powershell_monitor.write().await = Some(powershell_monitor);

        *is_running = true;
        info!("Identity monitoring system started successfully");
        Ok(())
    }

    /// Stop all identity monitoring components
    pub async fn stop(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut is_running = self.is_running.write().await;
        if !*is_running {
            return Ok(());
        }

        info!("Stopping identity monitoring system");

        // Stop LSASS monitor
        if let Some(monitor) = self.lsass_monitor.write().await.take() {
            if let Err(e) = monitor.stop().await {
                error!("Failed to stop LSASS monitor: {}", e);
            }
        }

        // Stop PowerShell monitor
        if let Some(monitor) = self.powershell_monitor.write().await.take() {
            if let Err(e) = monitor.stop().await {
                error!("Failed to stop PowerShell monitor: {}", e);
            }
        }

        *is_running = false;
        info!("Identity monitoring system stopped successfully");
        Ok(())
    }

    /// Check if the identity monitoring system is running
    pub async fn is_running(&self) -> bool {
        *self.is_running.read().await
    }
}

impl Default for IdentityMonitoringSystem {
    fn default() -> Self {
        Self::new()
    }
}
