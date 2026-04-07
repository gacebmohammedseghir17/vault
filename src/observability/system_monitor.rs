use std::sync::Arc;
use std::time::Duration;
use sysinfo::{CpuRefreshKind, RefreshKind, System, MemoryRefreshKind};
use tokio::time::interval;
use log::{info, warn};
use crate::metrics::MetricsCollector;

use std::sync::atomic::Ordering;

pub enum SystemStatus {
    Normal,
    HighLoad,
    Critical,
}

pub struct SystemMonitor {
    metrics: Arc<MetricsCollector>,
}

impl SystemMonitor {
    pub fn new(metrics: Arc<MetricsCollector>) -> Self {
        Self { metrics }
    }

    pub async fn start(self) {
        info!("Starting system resource monitor...");
        let mut sys = System::new_with_specifics(
            RefreshKind::new().with_cpu(CpuRefreshKind::everything()).with_memory(MemoryRefreshKind::everything()),
        );
        
        // Wait a bit to collect first sample
        tokio::time::sleep(Duration::from_millis(500)).await;
        sys.refresh_all();

        let mut ticker = interval(Duration::from_secs(5));

        loop {
            ticker.tick().await;
            sys.refresh_all();

            let cpu_usage = sys.global_cpu_info().cpu_usage();
            let memory_used = sys.used_memory() as f64 / 1024.0 / 1024.0; // MB
            let total_memory = sys.total_memory() as f64 / 1024.0 / 1024.0; // MB

            // Record metrics
            if let Err(e) = self.metrics.record_performance("system", "cpu_usage", cpu_usage as f64, "percent") {
                log::trace!("Failed to record CPU usage: {}", e);
            }
            if let Err(e) = self.metrics.record_performance("system", "memory_usage", memory_used, "mb") {
                log::trace!("Failed to record memory usage: {}", e);
            }
            
            // Backpressure signaling
            match self.check_thresholds(cpu_usage, memory_used, total_memory) {
                SystemStatus::Critical => {
                    warn!("CRITICAL SYSTEM LOAD: CPU {:.1}% | Mem {:.1}MB. Signaling backpressure.", cpu_usage, memory_used);
                    crate::IS_SYSTEM_UNDER_LOAD.store(true, Ordering::Relaxed);
                },
                SystemStatus::HighLoad => {
                    info!("High system load detected: CPU {:.1}%", cpu_usage);
                    crate::IS_SYSTEM_UNDER_LOAD.store(true, Ordering::Relaxed);
                },
                SystemStatus::Normal => {
                    crate::IS_SYSTEM_UNDER_LOAD.store(false, Ordering::Relaxed);
                }
            }
        }
    }

    fn check_thresholds(&self, cpu: f32, mem_used: f64, mem_total: f64) -> SystemStatus {
        if cpu > 90.0 || mem_used > (mem_total * 0.95) {
            SystemStatus::Critical
        } else if cpu > 70.0 || mem_used > (mem_total * 0.85) {
            SystemStatus::HighLoad
        } else {
            SystemStatus::Normal
        }
    }
}
