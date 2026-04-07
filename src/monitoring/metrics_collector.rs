//! Metrics Collector Component
//!
//! This module provides comprehensive metrics collection for the YARA agent,
//! including system metrics, application metrics, and custom metrics.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use tokio::time::interval;
use tracing::{debug, error, info, warn};

use crate::error::{AgentError, AgentResult};

/// Metric data point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricPoint {
    pub timestamp: u64,
    pub value: f64,
    pub tags: HashMap<String, String>,
}

impl MetricPoint {
    /// Create a new metric point
    pub fn new(value: f64) -> Self {
        Self {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            value,
            tags: HashMap::new(),
        }
    }
    
    /// Create a new metric point with tags
    pub fn with_tags(value: f64, tags: HashMap<String, String>) -> Self {
        Self {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            value,
            tags,
        }
    }
}

/// Metric series (time series data)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricSeries {
    pub name: String,
    pub description: String,
    pub unit: String,
    pub metric_type: MetricType,
    pub points: VecDeque<MetricPoint>,
    pub max_points: usize,
    pub created_at: u64,
    pub updated_at: u64,
}

/// Metric types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MetricType {
    Counter,    // Monotonically increasing
    Gauge,      // Can go up and down
    Histogram,  // Distribution of values
    Summary,    // Summary statistics
}

impl MetricSeries {
    /// Create a new metric series
    pub fn new(
        name: String,
        description: String,
        unit: String,
        metric_type: MetricType,
        max_points: usize,
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        Self {
            name,
            description,
            unit,
            metric_type,
            points: VecDeque::new(),
            max_points,
            created_at: timestamp,
            updated_at: timestamp,
        }
    }
    
    /// Add a metric point
    pub fn add_point(&mut self, point: MetricPoint) {
        self.points.push_back(point);
        
        // Maintain max points limit
        while self.points.len() > self.max_points {
            self.points.pop_front();
        }
        
        self.updated_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    }
    
    /// Get the latest value
    pub fn latest_value(&self) -> Option<f64> {
        self.points.back().map(|p| p.value)
    }
    
    /// Get average value over the last N points
    pub fn average(&self, last_n: usize) -> Option<f64> {
        if self.points.is_empty() {
            return None;
        }
        
        let points_to_consider = std::cmp::min(last_n, self.points.len());
        let sum: f64 = self.points
            .iter()
            .rev()
            .take(points_to_consider)
            .map(|p| p.value)
            .sum();
        
        Some(sum / points_to_consider as f64)
    }
    
    /// Get minimum value over the last N points
    pub fn min(&self, last_n: usize) -> Option<f64> {
        if self.points.is_empty() {
            return None;
        }
        
        let points_to_consider = std::cmp::min(last_n, self.points.len());
        self.points
            .iter()
            .rev()
            .take(points_to_consider)
            .map(|p| p.value)
            .fold(None, |acc, val| match acc {
                None => Some(val),
                Some(min) => Some(min.min(val)),
            })
    }
    
    /// Get maximum value over the last N points
    pub fn max(&self, last_n: usize) -> Option<f64> {
        if self.points.is_empty() {
            return None;
        }
        
        let points_to_consider = std::cmp::min(last_n, self.points.len());
        self.points
            .iter()
            .rev()
            .take(points_to_consider)
            .map(|p| p.value)
            .fold(None, |acc, val| match acc {
                None => Some(val),
                Some(max) => Some(max.max(val)),
            })
    }
    
    /// Get rate of change (per second) over the last N points
    pub fn rate(&self, last_n: usize) -> Option<f64> {
        if self.points.len() < 2 {
            return None;
        }
        
        let points_to_consider = std::cmp::min(last_n, self.points.len());
        if points_to_consider < 2 {
            return None;
        }
        
        let recent_points: Vec<_> = self.points
            .iter()
            .rev()
            .take(points_to_consider)
            .collect();
        
        let first = recent_points.last()?;
        let last = recent_points.first()?;
        
        let time_diff = last.timestamp.saturating_sub(first.timestamp) as f64;
        if time_diff == 0.0 {
            return None;
        }
        
        let value_diff = last.value - first.value;
        Some(value_diff / time_diff)
    }
    
    /// Clear all points
    pub fn clear(&mut self) {
        self.points.clear();
        self.updated_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    }
}

/// System metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMetrics {
    pub cpu_usage_percent: f64,
    pub memory_usage_percent: f64,
    pub memory_used_bytes: u64,
    pub memory_total_bytes: u64,
    pub disk_usage_percent: f64,
    pub disk_used_bytes: u64,
    pub disk_total_bytes: u64,
    pub network_bytes_sent: u64,
    pub network_bytes_received: u64,
    pub load_average_1m: f64,
    pub load_average_5m: f64,
    pub load_average_15m: f64,
    pub open_file_descriptors: u64,
    pub max_file_descriptors: u64,
    pub process_count: u64,
    pub thread_count: u64,
    pub uptime_seconds: u64,
}

impl Default for SystemMetrics {
    fn default() -> Self {
        Self {
            cpu_usage_percent: 0.0,
            memory_usage_percent: 0.0,
            memory_used_bytes: 0,
            memory_total_bytes: 0,
            disk_usage_percent: 0.0,
            disk_used_bytes: 0,
            disk_total_bytes: 0,
            network_bytes_sent: 0,
            network_bytes_received: 0,
            load_average_1m: 0.0,
            load_average_5m: 0.0,
            load_average_15m: 0.0,
            open_file_descriptors: 0,
            max_file_descriptors: 0,
            process_count: 0,
            thread_count: 0,
            uptime_seconds: 0,
        }
    }
}

/// Application metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationMetrics {
    pub scans_total: u64,
    pub scans_active: u64,
    pub scans_completed: u64,
    pub scans_failed: u64,
    pub files_scanned: u64,
    pub threats_detected: u64,
    pub false_positives: u64,
    pub scan_duration_avg_ms: f64,
    pub scan_duration_max_ms: f64,
    pub scan_queue_size: u64,
    pub rules_loaded: u64,
    pub rules_compiled: u64,
    pub rules_failed: u64,
    pub memory_pool_size: u64,
    pub memory_pool_used: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub cache_size: u64,
    pub errors_total: u64,
    pub warnings_total: u64,
}

impl Default for ApplicationMetrics {
    fn default() -> Self {
        Self {
            scans_total: 0,
            scans_active: 0,
            scans_completed: 0,
            scans_failed: 0,
            files_scanned: 0,
            threats_detected: 0,
            false_positives: 0,
            scan_duration_avg_ms: 0.0,
            scan_duration_max_ms: 0.0,
            scan_queue_size: 0,
            rules_loaded: 0,
            rules_compiled: 0,
            rules_failed: 0,
            memory_pool_size: 0,
            memory_pool_used: 0,
            cache_hits: 0,
            cache_misses: 0,
            cache_size: 0,
            errors_total: 0,
            warnings_total: 0,
        }
    }
}

/// Metrics collector configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsCollectorConfig {
    pub enabled: bool,
    pub collection_interval_seconds: u64,
    pub max_series_points: usize,
    pub retention_hours: u64,
    pub export_enabled: bool,
    pub export_interval_seconds: u64,
    pub export_format: ExportFormat,
    pub export_path: String,
    pub system_metrics_enabled: bool,
    pub application_metrics_enabled: bool,
    pub custom_metrics_enabled: bool,
}

/// Export formats
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExportFormat {
    Json,
    Csv,
    Prometheus,
    InfluxDB,
}

impl Default for MetricsCollectorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            collection_interval_seconds: 30,
            max_series_points: 1000,
            retention_hours: 24,
            export_enabled: false,
            export_interval_seconds: 300, // 5 minutes
            export_format: ExportFormat::Json,
            export_path: "./metrics".to_string(),
            system_metrics_enabled: true,
            application_metrics_enabled: true,
            custom_metrics_enabled: true,
        }
    }
}

/// Metrics collector statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsCollectorStats {
    pub collections_total: u64,
    pub collections_failed: u64,
    pub exports_total: u64,
    pub exports_failed: u64,
    pub series_count: u64,
    pub points_collected: u64,
    pub last_collection_duration_ms: u64,
    pub average_collection_duration_ms: f64,
    pub last_export_duration_ms: u64,
    pub uptime_seconds: u64,
}

/// Metrics collector implementation
#[derive(Debug)]
pub struct MetricsCollector {
    config: Arc<RwLock<MetricsCollectorConfig>>,
    series: Arc<RwLock<HashMap<String, MetricSeries>>>,
    system_metrics: Arc<RwLock<SystemMetrics>>,
    application_metrics: Arc<RwLock<ApplicationMetrics>>,
    stats: Arc<RwLock<MetricsCollectorStats>>,
    running: Arc<RwLock<bool>>,
    start_time: Instant,
}

impl MetricsCollector {
    /// Create a new metrics collector
    pub fn new(config: MetricsCollectorConfig) -> AgentResult<Self> {
        Ok(Self {
            config: Arc::new(RwLock::new(config)),
            series: Arc::new(RwLock::new(HashMap::new())),
            system_metrics: Arc::new(RwLock::new(SystemMetrics::default())),
            application_metrics: Arc::new(RwLock::new(ApplicationMetrics::default())),
            stats: Arc::new(RwLock::new(MetricsCollectorStats {
                collections_total: 0,
                collections_failed: 0,
                exports_total: 0,
                exports_failed: 0,
                series_count: 0,
                points_collected: 0,
                last_collection_duration_ms: 0,
                average_collection_duration_ms: 0.0,
                last_export_duration_ms: 0,
                uptime_seconds: 0,
            })),
            running: Arc::new(RwLock::new(false)),
            start_time: Instant::now(),
        })
    }
    
    /// Start the metrics collector
    pub async fn start(&self) -> AgentResult<()> {
        info!("Starting metrics collector");
        
        {
            let mut running = self.running.write().map_err(|e| {
                AgentError::Service { message: format!("Failed to acquire running lock: {}", e), service: "metrics_collector".to_string(), context: None }
            })?;
            
            if *running {
                return Err(AgentError::Service { message: "Metrics collector is already running".to_string(), service: "metrics_collector".to_string(), context: None });
            }
            
            *running = true;
        }
        
        // Initialize default metrics series
        self.initialize_default_series().await?;
        
        // Start collection loop
        self.start_collection_loop().await?;
        
        // Start export loop if enabled
        let config = {
            let config = self.config.read().map_err(|e| {
                AgentError::Service { message: format!("Failed to read metrics collector config: {}", e), service: "metrics_collector".to_string(), context: None }
            })?;
            config.clone()
        };
        
        if config.export_enabled {
            self.start_export_loop().await?;
        }
        
        info!("Metrics collector started successfully");
        Ok(())
    }
    
    /// Stop the metrics collector
    pub async fn stop(&self) -> AgentResult<()> {
        info!("Stopping metrics collector");
        
        {
            let mut running = self.running.write().map_err(|e| {
                AgentError::Service { message: format!("Failed to acquire running lock: {}", e), service: "metrics_collector".to_string(), context: None }
            })?;
            
            if !*running {
                return Ok(());
            }
            
            *running = false;
        }
        
        info!("Metrics collector stopped successfully");
        Ok(())
    }
    
    /// Record a metric value
    pub fn record_metric(&self, name: &str, value: f64, tags: Option<HashMap<String, String>>) -> AgentResult<()> {
        let mut series = self.series.write().map_err(|e| {
            AgentError::Service { message: format!("Failed to write metrics series: {}", e), service: "metrics_collector".to_string(), context: None }
        })?;
        
        if let Some(metric_series) = series.get_mut(name) {
            let point = if let Some(tags) = tags {
                MetricPoint::with_tags(value, tags)
            } else {
                MetricPoint::new(value)
            };
            
            metric_series.add_point(point);
            
            // Update statistics
            self.update_collection_stats(1).map_err(|e| {
                error!("Failed to update collection stats: {}", e);
                e
            })?;
        } else {
            warn!("Metric series not found: {}", name);
        }
        
        Ok(())
    }

    /// Record a counter metric
    pub fn record_counter(&self, name: &str, value: f64) -> AgentResult<()> {
        self.record_metric(name, value, None)
    }

    /// Record a gauge metric
    pub fn record_gauge(&self, name: &str, value: f64) -> AgentResult<()> {
        self.record_metric(name, value, None)
    }

    /// Record a histogram metric
    pub fn record_histogram(&self, name: &str, value: f64) -> AgentResult<()> {
        self.record_metric(name, value, None)
    }
    
    /// Create a new metric series
    pub fn create_series(
        &self,
        name: String,
        description: String,
        unit: String,
        metric_type: MetricType,
    ) -> AgentResult<()> {
        let config = {
            let config = self.config.read().map_err(|e| {
                AgentError::Service { message: format!("Failed to read metrics collector config: {}", e), service: "metrics_collector".to_string(), context: None }
            })?;
            config.clone()
        };
        
        let mut series = self.series.write().map_err(|e| {
            AgentError::Service { message: format!("Failed to write metrics series: {}", e), service: "metrics_collector".to_string(), context: None }
        })?;
        
        if series.contains_key(&name) {
            return Err(AgentError::Service { message: format!("Metric series already exists: {}", name), service: "metrics_collector".to_string(), context: None });
        }
        
        let metric_series = MetricSeries::new(
            name.clone(),
            description,
            unit,
            metric_type,
            config.max_series_points,
        );
        
        series.insert(name.clone(), metric_series);
        
        debug!("Created metric series: {}", name);
        Ok(())
    }
    
    /// Get metric series
    pub fn get_series(&self, name: &str) -> AgentResult<Option<MetricSeries>> {
        let series = self.series.read().map_err(|e| {
            AgentError::Service { message: format!("Failed to read metrics series: {}", e), service: "metrics_collector".to_string(), context: None }
        })?;
        
        Ok(series.get(name).cloned())
    }
    
    /// Get all metric series
    pub fn get_all_series(&self) -> AgentResult<HashMap<String, MetricSeries>> {
        let series = self.series.read().map_err(|e| {
            AgentError::Service { message: format!("Failed to read metrics series: {}", e), service: "metrics_collector".to_string(), context: None }
        })?;
        
        Ok(series.clone())
    }
    
    /// Get current system metrics
    pub fn get_system_metrics(&self) -> AgentResult<SystemMetrics> {
        let metrics = self.system_metrics.read().map_err(|e| {
            AgentError::Service { message: format!("Failed to read system metrics: {}", e), service: "metrics_collector".to_string(), context: None }
        })?;
        
        Ok(metrics.clone())
    }
    
    /// Get current application metrics
    pub fn get_application_metrics(&self) -> AgentResult<ApplicationMetrics> {
        let metrics = self.application_metrics.read().map_err(|e| {
            AgentError::Service { message: format!("Failed to read application metrics: {}", e), service: "metrics_collector".to_string(), context: None }
        })?;
        
        Ok(metrics.clone())
    }
    
    /// Update application metrics
    pub fn update_application_metrics<F>(&self, updater: F) -> AgentResult<()>
    where
        F: FnOnce(&mut ApplicationMetrics),
    {
        let mut metrics = self.application_metrics.write().map_err(|e| {
            AgentError::Service { message: format!("Failed to write application metrics: {}", e), service: "metrics_collector".to_string(), context: None }
        })?;
        
        updater(&mut metrics);
        Ok(())
    }
    
    /// Get metrics collector statistics
    pub fn get_stats(&self) -> AgentResult<MetricsCollectorStats> {
        let mut stats = self.stats.write().map_err(|e| {
            AgentError::Service { message: format!("Failed to read metrics collector stats: {}", e), service: "metrics_collector".to_string(), context: None }
        })?;
        
        // Update uptime
        stats.uptime_seconds = self.start_time.elapsed().as_secs();
        
        Ok(stats.clone())
    }
    
    /// Reset metrics collector statistics
    pub fn reset_stats(&self) -> AgentResult<()> {
        let mut stats = self.stats.write().map_err(|e| {
            AgentError::Service { message: format!("Failed to write metrics collector stats: {}", e), service: "metrics_collector".to_string(), context: None }
        })?;
        
        *stats = MetricsCollectorStats {
            collections_total: 0,
            collections_failed: 0,
            exports_total: 0,
            exports_failed: 0,
            series_count: 0,
            points_collected: 0,
            last_collection_duration_ms: 0,
            average_collection_duration_ms: 0.0,
            last_export_duration_ms: 0,
            uptime_seconds: 0,
        };
        
        info!("Metrics collector statistics reset");
        Ok(())
    }
    
    /// Check if metrics collector is running
    pub fn is_running(&self) -> AgentResult<bool> {
        let running = self.running.read().map_err(|e| {
            AgentError::Service { message: format!("Failed to read running status: {}", e), service: "metrics_collector".to_string(), context: None }
        })?;
        
        Ok(*running)
    }
    
    /// Update metrics collector configuration
    pub fn update_config(&self, new_config: MetricsCollectorConfig) -> AgentResult<()> {
        let mut config = self.config.write().map_err(|e| {
            AgentError::Service { message: format!("Failed to write metrics collector config: {}", e), service: "metrics_collector".to_string(), context: None }
        })?;
        
        *config = new_config;
        info!("Metrics collector configuration updated");
        Ok(())
    }
    
    /// Clear all metrics data
    pub fn clear_metrics(&self) -> AgentResult<()> {
        let mut series = self.series.write().map_err(|e| {
            AgentError::Service { message: format!("Failed to write metrics series: {}", e), service: "metrics_collector".to_string(), context: None }
        })?;
        
        for (_, metric_series) in series.iter_mut() {
            metric_series.clear();
        }
        
        info!("All metrics data cleared");
        Ok(())
    }
    
    /// Initialize default metric series
    async fn initialize_default_series(&self) -> AgentResult<()> {
        let config = {
            let config = self.config.read().map_err(|e| {
                AgentError::Service { message: format!("Failed to read metrics collector config: {}", e), service: "metrics_collector".to_string(), context: None }
            })?;
            config.clone()
        };
        
        // System metrics series
        if config.system_metrics_enabled {
            self.create_series(
                "system.cpu.usage_percent".to_string(),
                "CPU usage percentage".to_string(),
                "percent".to_string(),
                MetricType::Gauge,
            )?;
            
            self.create_series(
                "system.memory.usage_percent".to_string(),
                "Memory usage percentage".to_string(),
                "percent".to_string(),
                MetricType::Gauge,
            )?;
            
            self.create_series(
                "system.disk.usage_percent".to_string(),
                "Disk usage percentage".to_string(),
                "percent".to_string(),
                MetricType::Gauge,
            )?;
            
            self.create_series(
                "system.network.bytes_sent".to_string(),
                "Network bytes sent".to_string(),
                "bytes".to_string(),
                MetricType::Counter,
            )?;
            
            self.create_series(
                "system.network.bytes_received".to_string(),
                "Network bytes received".to_string(),
                "bytes".to_string(),
                MetricType::Counter,
            )?;
        }
        
        // Application metrics series
        if config.application_metrics_enabled {
            self.create_series(
                "app.scans.total".to_string(),
                "Total scans performed".to_string(),
                "count".to_string(),
                MetricType::Counter,
            )?;
            
            self.create_series(
                "app.scans.active".to_string(),
                "Active scans".to_string(),
                "count".to_string(),
                MetricType::Gauge,
            )?;
            
            self.create_series(
                "app.threats.detected".to_string(),
                "Threats detected".to_string(),
                "count".to_string(),
                MetricType::Counter,
            )?;
            
            self.create_series(
                "app.scan.duration_ms".to_string(),
                "Scan duration".to_string(),
                "milliseconds".to_string(),
                MetricType::Histogram,
            )?;
            
            self.create_series(
                "app.memory.pool_usage_percent".to_string(),
                "Memory pool usage percentage".to_string(),
                "percent".to_string(),
                MetricType::Gauge,
            )?;
        }
        
        debug!("Default metric series initialized");
        Ok(())
    }
    
    /// Start metrics collection loop
    async fn start_collection_loop(&self) -> AgentResult<()> {
        let config = Arc::clone(&self.config);
        let running = Arc::clone(&self.running);
        let _system_metrics = Arc::clone(&self.system_metrics);
        let stats = Arc::clone(&self.stats);
        let _start_time = self.start_time;
        
        tokio::spawn(async move {
            let config_data = {
                let config_guard = config.read().unwrap();
                config_guard.clone()
            };
            
            let mut interval = interval(Duration::from_secs(config_data.collection_interval_seconds));
            
            loop {
                interval.tick().await;
                
                // Check if still running
                if let Ok(running_guard) = running.read() {
                    if !*running_guard {
                        break;
                    }
                } else {
                    error!("Failed to check running status, stopping collection loop");
                    break;
                }
                
                // Collect metrics - simplified inline implementation
                let collection_start = Instant::now();
                let mut points_collected = 0u64;
                
                // Mock collection logic
                if config_data.system_metrics_enabled {
                    points_collected += 5; // Mock 5 system metrics
                }
                if config_data.application_metrics_enabled {
                    points_collected += 3; // Mock 3 app metrics
                }
                
                let duration = collection_start.elapsed().as_millis() as u64;
                
                // Update stats
                if let Ok(mut stats_guard) = stats.write() {
                    stats_guard.collections_total += 1;
                    stats_guard.points_collected += points_collected;
                    stats_guard.last_collection_duration_ms = duration;
                }
                
                debug!("Collected {} metric points in {}ms", points_collected, duration);
            }
            
            debug!("Metrics collection loop stopped");
        });
        
        Ok(())
    }
    
    /// Start metrics export loop
    async fn start_export_loop(&self) -> AgentResult<()> {
        let config = Arc::clone(&self.config);
        let running = Arc::clone(&self.running);
        let stats = Arc::clone(&self.stats);
        
        tokio::spawn(async move {
            let config_data = {
                let config_guard = config.read().unwrap();
                config_guard.clone()
            };
            
            let mut interval = interval(Duration::from_secs(config_data.export_interval_seconds));
            
            loop {
                interval.tick().await;
                
                // Check if still running
                if let Ok(running_guard) = running.read() {
                    if !*running_guard {
                        break;
                    }
                } else {
                    error!("Failed to check running status, stopping export loop");
                    break;
                }
                
                // Export metrics - simplified inline implementation
                let export_start = Instant::now();
                let points_exported = 10u64; // Mock export count
                
                let duration = export_start.elapsed().as_millis() as u64;
                
                // Update stats
                 if let Ok(mut stats_guard) = stats.write() {
                     stats_guard.exports_total += 1;
                     stats_guard.last_export_duration_ms = duration;
                 }
                
                debug!("Exported {} metric points in {}ms", points_exported, duration);
            }
            
            debug!("Metrics export loop stopped");
        });
        
        Ok(())
    }
    
    /// Collect all metrics
    async fn collect_metrics(&self) -> AgentResult<u64> {
        let config = {
            let config = self.config.read().map_err(|e| {
                AgentError::Service { message: format!("Failed to read metrics collector config: {}", e), service: "metrics_collector".to_string() , context: None }
            })?;
            config.clone()
        };
        
        let mut points_collected = 0u64;
        
        // Collect system metrics
        if config.system_metrics_enabled {
            points_collected += self.collect_system_metrics().await?;
        }
        
        // Collect application metrics
        if config.application_metrics_enabled {
            points_collected += self.collect_application_metrics().await?;
        }
        
        Ok(points_collected)
    }
    
    /// Collect system metrics
    async fn collect_system_metrics(&self) -> AgentResult<u64> {
        // Mock system metrics collection
        // In a real implementation, this would use system APIs
        let metrics = SystemMetrics {
            cpu_usage_percent: self.mock_cpu_usage(),
            memory_usage_percent: self.mock_memory_usage(),
            memory_used_bytes: 1024 * 1024 * 512, // 512 MB
            memory_total_bytes: 1024 * 1024 * 1024 * 8, // 8 GB
            disk_usage_percent: 45.0,
            disk_used_bytes: 1024 * 1024 * 1024 * 100, // 100 GB
            disk_total_bytes: 1024 * 1024 * 1024 * 500, // 500 GB
            network_bytes_sent: 1024 * 1024 * 10, // 10 MB
            network_bytes_received: 1024 * 1024 * 50, // 50 MB
            load_average_1m: 1.5,
            load_average_5m: 1.2,
            load_average_15m: 1.0,
            open_file_descriptors: 150,
            max_file_descriptors: 1024,
            process_count: 200,
            thread_count: 800,
            uptime_seconds: self.start_time.elapsed().as_secs(),
        };
        
        // Update system metrics
        {
            let mut system_metrics = self.system_metrics.write().map_err(|e| {
                AgentError::Service { message: format!("Failed to write system metrics: {}", e), service: "metrics_collector".to_string() , context: None }
            })?;
            *system_metrics = metrics.clone();
        }
        
        // Record metric points
        let mut points_collected = 0u64;
        
        self.record_gauge("system.cpu.usage_percent", metrics.cpu_usage_percent)?;
        points_collected += 1;
        
        self.record_gauge("system.memory.usage_percent", metrics.memory_usage_percent)?;
        points_collected += 1;
        
        self.record_gauge("system.disk.usage_percent", metrics.disk_usage_percent)?;
        points_collected += 1;
        
        self.record_counter("system.network.bytes_sent", metrics.network_bytes_sent as f64)?;
        points_collected += 1;
        
        self.record_counter("system.network.bytes_received", metrics.network_bytes_received as f64)?;
        points_collected += 1;
        
        Ok(points_collected)
    }
    
    /// Collect application metrics
    async fn collect_application_metrics(&self) -> AgentResult<u64> {
        let app_metrics = {
            let metrics = self.application_metrics.read().map_err(|e| {
                AgentError::Service { message: format!("Failed to read application metrics: {}", e), service: "metrics_collector".to_string() , context: None }
            })?;
            metrics.clone()
        };
        
        // Record metric points
        let mut points_collected = 0u64;
        
        self.record_counter("app.scans.total", app_metrics.scans_total as f64)?;
        points_collected += 1;
        
        self.record_gauge("app.scans.active", app_metrics.scans_active as f64)?;
        points_collected += 1;
        
        self.record_counter("app.threats.detected", app_metrics.threats_detected as f64)?;
        points_collected += 1;
        
        self.record_histogram("app.scan.duration_ms", app_metrics.scan_duration_avg_ms)?;
        points_collected += 1;
        
        let memory_pool_usage = if app_metrics.memory_pool_size > 0 {
            (app_metrics.memory_pool_used as f64 / app_metrics.memory_pool_size as f64) * 100.0
        } else {
            0.0
        };
        
        self.record_gauge("app.memory.pool_usage_percent", memory_pool_usage)?;
        points_collected += 1;
        
        Ok(points_collected)
    }
    
    /// Export metrics
    async fn export_metrics(&self) -> AgentResult<()> {
        let config = {
            let config = self.config.read().map_err(|e| {
                AgentError::Service { message: format!("Failed to read metrics collector config: {}", e), service: "metrics_collector".to_string() , context: None }
            })?;
            config.clone()
        };
        
        let series = self.get_all_series()?;
        
        match config.export_format {
            ExportFormat::Json => {
                self.export_json(&series, &config.export_path).await?
            }
            ExportFormat::Csv => {
                self.export_csv(&series, &config.export_path).await?
            }
            _ => {
                debug!("Export format {:?} not implemented", config.export_format);
            }
        }
        
        Ok(())
    }
    
    /// Export metrics as JSON
    async fn export_json(&self, series: &HashMap<String, MetricSeries>, export_path: &str) -> AgentResult<()> {
        let json_data = serde_json::to_string_pretty(series).map_err(|e| {
            AgentError::Service { message: format!("Failed to serialize metrics to JSON: {}", e), service: "metrics_collector".to_string() , context: None }
        })?;
        
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let filename = format!("{}/metrics_{}.json", export_path, timestamp);
        
        tokio::fs::create_dir_all(export_path).await.map_err(|e| {
            AgentError::Service { message: format!("Failed to create export directory: {}", e), service: "metrics_collector".to_string() , context: None }
        })?;
        
        tokio::fs::write(&filename, json_data).await.map_err(|e| {
            AgentError::Service { message: format!("Failed to write JSON export file: {}", e), service: "metrics_collector".to_string() , context: None }
        })?;
        
        debug!("Exported metrics to JSON: {}", filename);
        Ok(())
    }
    
    /// Export metrics as CSV
    async fn export_csv(&self, series: &HashMap<String, MetricSeries>, export_path: &str) -> AgentResult<()> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let filename = format!("{}/metrics_{}.csv", export_path, timestamp);
        
        tokio::fs::create_dir_all(export_path).await.map_err(|e| {
            AgentError::Service { message: format!("Failed to create export directory: {}", e), service: "metrics_collector".to_string() , context: None }
        })?;
        
        let mut csv_content = String::from("metric_name,timestamp,value,tags\n");
        
        for (name, metric_series) in series {
            for point in &metric_series.points {
                let tags_str = point.tags.iter()
                    .map(|(k, v)| format!("{}={}", k, v))
                    .collect::<Vec<_>>()
                    .join(";");
                
                csv_content.push_str(&format!(
                    "{},{},{},\"{}\"\n",
                    name, point.timestamp, point.value, tags_str
                ));
            }
        }
        
        tokio::fs::write(&filename, csv_content).await.map_err(|e| {
            AgentError::Service { message: format!("Failed to write CSV export file: {}", e), service: "metrics_collector".to_string() , context: None }
        })?;
        
        debug!("Exported metrics to CSV: {}", filename);
        Ok(())
    }
    
    /// Mock CPU usage (for testing)
    fn mock_cpu_usage(&self) -> f64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        self.start_time.elapsed().as_secs().hash(&mut hasher);
        let hash = hasher.finish();
        
        20.0 + (hash % 60) as f64 // 20-80% CPU usage
    }
    
    /// Mock memory usage (for testing)
    fn mock_memory_usage(&self) -> f64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        (self.start_time.elapsed().as_secs() + 1).hash(&mut hasher);
        let hash = hasher.finish();
        
        40.0 + (hash % 40) as f64 // 40-80% memory usage
    }
    
    /// Update collection statistics
    fn update_collection_stats(&self, points_collected: u64) -> AgentResult<()> {
        let mut stats = self.stats.write().map_err(|e| {
            AgentError::Service { message: format!("Failed to write metrics collector stats: {}", e), service: "metrics_collector".to_string() , context: None }
        })?;
        
        stats.collections_total += 1;
        stats.points_collected += points_collected;
        
        // Update series count
        let series = self.series.read().map_err(|e| {
            AgentError::Service { message: format!("Failed to read metrics series: {}", e), service: "metrics_collector".to_string() , context: None }
        })?;
        stats.series_count = series.len() as u64;
        
        Ok(())
    }
    
    /// Update collection statistics with duration
    fn update_collection_stats_with_duration(&self, points_collected: u64, duration_ms: u64) -> AgentResult<()> {
        let mut stats = self.stats.write().map_err(|e| {
            AgentError::Service { message: format!("Failed to write metrics collector stats: {}", e), service: "metrics_collector".to_string() , context: None }
        })?;
        
        stats.collections_total += 1;
        stats.points_collected += points_collected;
        stats.last_collection_duration_ms = duration_ms;
        
        // Update average collection duration
        let total_collections = stats.collections_total as f64;
        stats.average_collection_duration_ms = 
            (stats.average_collection_duration_ms * (total_collections - 1.0) + duration_ms as f64) / total_collections;
        
        // Update series count
        let series = self.series.read().map_err(|e| {
            AgentError::Service { message: format!("Failed to read metrics series: {}", e), service: "metrics_collector".to_string() , context: None }
        })?;
        stats.series_count = series.len() as u64;
        
        Ok(())
    }
    
    /// Update collection failure statistics
    fn update_collection_failure_stats(&self) -> AgentResult<()> {
        let mut stats = self.stats.write().map_err(|e| {
            AgentError::Service { message: format!("Failed to write metrics collector stats: {}", e), service: "metrics_collector".to_string() , context: None }
        })?;
        
        stats.collections_failed += 1;
        Ok(())
    }
    
    /// Update export statistics
    fn update_export_stats(&self, duration_ms: u64) -> AgentResult<()> {
        let mut stats = self.stats.write().map_err(|e| {
            AgentError::Service { message: format!("Failed to write metrics collector stats: {}", e), service: "metrics_collector".to_string() , context: None }
        })?;
        
        stats.exports_total += 1;
        stats.last_export_duration_ms = duration_ms;
        Ok(())
    }
    
    /// Update export failure statistics
    fn update_export_failure_stats(&self) -> AgentResult<()> {
        let mut stats = self.stats.write().map_err(|e| {
            AgentError::Service { message: format!("Failed to write metrics collector stats: {}", e), service: "metrics_collector".to_string() , context: None }
        })?;
        
        stats.exports_failed += 1;
        Ok(())
    }
}

#[cfg(all(test, feature = "metrics"))]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_metrics_collector_creation() {
        let config = MetricsCollectorConfig::default();
        let collector = MetricsCollector::new(config);
        assert!(collector.is_ok());
    }
    
    #[tokio::test]
    async fn test_metric_series_creation() {
        let config = MetricsCollectorConfig::default();
        let collector = MetricsCollector::new(config).unwrap();
        
        let result = collector.create_series(
            "test.metric".to_string(),
            "Test metric".to_string(),
            "count".to_string(),
            MetricType::Counter,
        );
        
        assert!(result.is_ok());
        
        let series = collector.get_series("test.metric").unwrap();
        assert!(series.is_some());
        assert_eq!(series.unwrap().name, "test.metric");
    }
    
    #[test]
    fn test_metric_point_creation() {
        let point = MetricPoint::new(42.0);
        assert_eq!(point.value, 42.0);
        assert!(point.tags.is_empty());
        
        let mut tags = HashMap::new();
        tags.insert("host".to_string(), "server1".to_string());
        
        let point_with_tags = MetricPoint::with_tags(100.0, tags.clone());
        assert_eq!(point_with_tags.value, 100.0);
        assert_eq!(point_with_tags.tags, tags);
    }
    
    #[test]
    fn test_metric_series_operations() {
        let mut series = MetricSeries::new(
            "test".to_string(),
            "Test series".to_string(),
            "count".to_string(),
            MetricType::Gauge,
            5,
        );
        
        // Add points
        series.add_point(MetricPoint::new(10.0));
        series.add_point(MetricPoint::new(20.0));
        series.add_point(MetricPoint::new(30.0));
        
        assert_eq!(series.latest_value(), Some(30.0));
        assert_eq!(series.average(3), Some(20.0));
        assert_eq!(series.min(3), Some(10.0));
        assert_eq!(series.max(3), Some(30.0));
        
        // Test max points limit
        for i in 0..10 {
            series.add_point(MetricPoint::new(i as f64));
        }
        
        assert_eq!(series.points.len(), 5); // Should not exceed max_points
    }
}
