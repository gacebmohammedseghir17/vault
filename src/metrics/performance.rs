//! Performance monitoring and metrics collection

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

/// Performance metric data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetric {
    pub timestamp: DateTime<Utc>,
    pub component: String,
    pub metric_name: String,
    pub value: f64,
    pub unit: String,
    pub tags: std::collections::HashMap<String, String>,
}

/// Performance monitoring configuration
#[derive(Debug, Clone)]
pub struct PerformanceConfig {
    pub collection_interval: Duration,
    pub retention_period: Duration,
    pub alert_thresholds: std::collections::HashMap<String, f64>,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            collection_interval: Duration::from_secs(60),
            retention_period: Duration::from_secs(86400 * 7), // 7 days
            alert_thresholds: std::collections::HashMap::new(),
        }
    }
}

/// Performance monitor for collecting system metrics
#[derive(Debug)]
pub struct PerformanceMonitor {
    config: PerformanceConfig,
    start_time: Instant,
    metrics: std::sync::Arc<std::sync::RwLock<Vec<PerformanceMetric>>>,
}

impl PerformanceMonitor {
    /// Create a new performance monitor
    pub fn new(config: PerformanceConfig) -> Self {
        Self {
            config,
            start_time: Instant::now(),
            metrics: std::sync::Arc::new(std::sync::RwLock::new(Vec::new())),
        }
    }

    /// Record a performance metric
    pub fn record_metric(&self, metric: PerformanceMetric) -> anyhow::Result<()> {
        let mut metrics = self
            .metrics
            .write()
            .map_err(|_| anyhow::anyhow!("Failed to acquire write lock"))?;
        metrics.push(metric);
        Ok(())
    }

    /// Get metrics for a specific component
    pub fn get_component_metrics(&self, component: &str) -> anyhow::Result<Vec<PerformanceMetric>> {
        let metrics = self
            .metrics
            .read()
            .map_err(|_| anyhow::anyhow!("Failed to acquire read lock"))?;
        Ok(metrics
            .iter()
            .filter(|m| m.component == component)
            .cloned()
            .collect())
    }

    /// Get system uptime
    pub fn get_uptime(&self) -> Duration {
        self.start_time.elapsed()
    }
}
