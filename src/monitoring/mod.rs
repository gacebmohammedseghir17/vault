//! Monitoring and Performance Management Module
//!
//! This module provides comprehensive monitoring, performance tracking, and resource management
//! capabilities for the YARA agent. It includes real-time metrics collection, health checks,
//! alerting, and resource optimization.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use tokio::time::interval;
use tracing::{info, warn, error, debug};

use crate::error::{AgentError, AgentResult};

// Sub-modules
pub mod performance_monitor;
pub mod performance_gate;
pub mod resource_tracker;
pub mod health_checker;
pub mod alert_manager;
pub mod metrics_collector;
pub mod log_analyzer;
pub mod observability;

// Re-exports for convenience
pub use performance_monitor::{PerformanceMonitor, PerformanceStats, SystemInfo};
pub use performance_gate::{PerformanceGate, PerformanceGateConfig, PerformanceViolation, ViolationType, ViolationSeverity};
pub use resource_tracker::{ResourceTracker, ResourceLimits, ResourceSnapshot, ResourceViolation};
pub use health_checker::{HealthChecker};
pub use alert_manager::{AlertManager, AlertStatus, AlertCategory};
pub use metrics_collector::{MetricsCollector, MetricSeries, SystemMetrics, ApplicationMetrics};
pub use log_analyzer::{LogAnalyzer, LogEntry, LogLevel, LogPattern, AnomalyDetection};

/// System performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub timestamp: u64,
    pub cpu_usage_percent: f64,
    pub memory_usage_bytes: u64,
    pub memory_usage_percent: f64,
    pub disk_io_read_bytes: u64,
    pub disk_io_write_bytes: u64,
    pub network_rx_bytes: u64,
    pub network_tx_bytes: u64,
    pub scan_throughput: f64,  // files per second
    pub scan_latency_ms: f64,  // average scan time
    pub error_rate: f64,       // errors per scan
    pub active_scans: u32,
    pub queue_size: u32,
}

/// Resource usage thresholds for alerting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceThresholds {
    pub cpu_warning: f64,      // 70%
    pub cpu_critical: f64,     // 90%
    pub memory_warning: f64,   // 80%
    pub memory_critical: f64,  // 95%
    pub disk_warning: f64,     // 85%
    pub disk_critical: f64,    // 95%
    pub throughput_warning: f64, // files/sec
    pub error_rate_warning: f64, // 5%
    pub error_rate_critical: f64, // 15%
}

impl Default for ResourceThresholds {
    fn default() -> Self {
        Self {
            cpu_warning: 70.0,
            cpu_critical: 90.0,
            memory_warning: 80.0,
            memory_critical: 95.0,
            disk_warning: 85.0,
            disk_critical: 95.0,
            throughput_warning: 10.0,
            error_rate_warning: 0.05,
            error_rate_critical: 0.15,
        }
    }
}

// Use HealthStatus from health_checker module
pub use health_checker::HealthStatus;

// Use HealthReport from health_checker module
pub use health_checker::HealthReport;

/// Individual health check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckResult {
    pub name: String,
    pub status: HealthStatus,
    pub value: f64,
    pub threshold: f64,
    pub message: String,
    pub timestamp: u64,
}

// Use AlertSeverity from alert_manager module
pub use alert_manager::AlertSeverity;

/// System alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub severity: AlertSeverity,
    pub title: String,
    pub message: String,
    pub component: String,
    pub timestamp: u64,
    pub resolved: bool,
    pub metadata: HashMap<String, String>,
}

/// Monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    pub enabled: bool,
    pub collection_interval_seconds: u64,
    pub retention_hours: u64,
    pub thresholds: ResourceThresholds,
    pub health_check_interval_seconds: u64,
    pub alert_cooldown_minutes: u64,
    pub metrics_export_enabled: bool,
    pub metrics_export_endpoint: Option<String>,
    pub webhook_url: Option<String>,
    pub email_alerts: Vec<String>,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            collection_interval_seconds: 60,
            retention_hours: 24,
            thresholds: ResourceThresholds::default(),
            health_check_interval_seconds: 300, // 5 minutes
            alert_cooldown_minutes: 15,
            metrics_export_enabled: false,
            metrics_export_endpoint: None,
            webhook_url: None,
            email_alerts: Vec::new(),
        }
    }
}

/// Main monitoring system
#[derive(Debug)]
pub struct MonitoringSystem {
    config: Arc<RwLock<MonitoringConfig>>,
    metrics_history: Arc<RwLock<VecDeque<PerformanceMetrics>>>,
    alerts: Arc<RwLock<Vec<Alert>>>,
    health_status: Arc<RwLock<HealthReport>>,
    performance_monitor: Arc<performance_monitor::PerformanceMonitor>,
    resource_tracker: Arc<resource_tracker::ResourceTracker>,
    health_checker: Arc<health_checker::HealthChecker>,
    alerting_system: Arc<alert_manager::AlertManager>,
    metrics_collector: Arc<crate::monitoring::metrics_collector::MetricsCollector>,
    running: Arc<RwLock<bool>>,
    last_collection: Arc<RwLock<Option<Instant>>>,
}

impl MonitoringSystem {
    /// Create a new monitoring system
    pub fn new(config: MonitoringConfig) -> AgentResult<Self> {
        let config = Arc::new(RwLock::new(config));
        
        let performance_monitor = Arc::new(
            performance_monitor::PerformanceMonitor::new(config.clone())?
        );
        
        let resource_tracker = Arc::new(
            resource_tracker::ResourceTracker::new(config.clone())?
        );
        
        let health_checker = Arc::new(
            health_checker::HealthChecker::new(
                health_checker::HealthCheckConfig::default(),
                config.clone()
            )?
        );
        
        let alerting_system = Arc::new(
            alert_manager::AlertManager::new(config.clone())?
        );
        
        let metrics_collector = Arc::new(
            crate::monitoring::metrics_collector::MetricsCollector::new(
                crate::monitoring::metrics_collector::MetricsCollectorConfig::default()
            )?
        );
        
        Ok(Self {
            config,
            metrics_history: Arc::new(RwLock::new(VecDeque::new())),
            alerts: Arc::new(RwLock::new(Vec::new())),
            health_status: Arc::new(RwLock::new(HealthReport {
                overall_status: HealthStatus::Unknown,
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                uptime_seconds: 0,
                component_results: Vec::new(),
                system_metrics: health_checker::SystemHealthMetrics {
                    memory_usage_percent: 0.0,
                    cpu_usage_percent: 0.0,
                    disk_usage_percent: 0.0,
                    network_connectivity: false,
                    file_system_accessible: false,
                    yara_engine_status: HealthStatus::Unknown,
                    configuration_valid: false,
                    log_system_working: false,
                },
                dependencies: Vec::new(),
                warnings: Vec::new(),
                errors: Vec::new(),
            })),
            performance_monitor,
            resource_tracker,
            health_checker,
            alerting_system,
            metrics_collector,
            running: Arc::new(RwLock::new(false)),
            last_collection: Arc::new(RwLock::new(None)),
        })
    }
    
    /// Start the monitoring system
    pub async fn start(&self) -> AgentResult<()> {
        info!("Starting monitoring system");
        
        {
            let mut running = self.running.write().map_err(|e| {
                AgentError::Service { message: format!("Failed to acquire running lock: {}", e), service: "monitoring_system".to_string(), context: None }
            })?;
            
            if *running {
                return Err(AgentError::Service { 
                    message: "Monitoring system is already running".to_string(), 
                    service: "monitoring_system".to_string(),
                    context: None
                });
            }
            
            *running = true;
        }
        
        // Start all monitoring components
        self.performance_monitor.start().await?;
        self.resource_tracker.start().await?;
        self.health_checker.start().await?;
        self.alerting_system.start().await?;
        self.metrics_collector.start().await?;
        
        // Start main monitoring loop
        self.start_monitoring_loop().await?;
        
        info!("Monitoring system started successfully");
        Ok(())
    }
    
    /// Stop the monitoring system
    pub async fn stop(&self) -> AgentResult<()> {
        info!("Stopping monitoring system");
        
        {
            let mut running = self.running.write().map_err(|e| {
                AgentError::Service { message: format!("Failed to acquire running lock: {}", e), service: "monitoring_system".to_string(), context: None }
            })?;
            
            if !*running {
                return Ok(());
            }
            
            *running = false;
        }
        
        // Stop all monitoring components
        self.performance_monitor.stop().await?;
        self.resource_tracker.stop().await?;
        self.health_checker.stop().await?;
        self.alerting_system.stop().await?;
        self.metrics_collector.stop().await?;
        
        info!("Monitoring system stopped successfully");
        Ok(())
    }
    
    /// Get current performance metrics
    pub async fn get_current_metrics(&self) -> AgentResult<PerformanceMetrics> {
        self.performance_monitor.get_current_metrics().await
    }
    
    /// Get metrics history
    pub fn get_metrics_history(&self, limit: Option<usize>) -> AgentResult<Vec<PerformanceMetrics>> {
        let history = self.metrics_history.read().map_err(|e| {
            AgentError::Service { message: format!("Failed to read metrics history: {}", e), service: "monitoring_system".to_string(), context: None }
        })?;
        
        let metrics: Vec<PerformanceMetrics> = if let Some(limit) = limit {
            history.iter().rev().take(limit).cloned().collect()
        } else {
            history.iter().cloned().collect()
        };
        
        Ok(metrics)
    }
    
    /// Get current health status
    pub fn get_health_status(&self) -> AgentResult<HealthReport> {
        let health = self.health_status.read().map_err(|e| {
            AgentError::Service { message: format!("Failed to read health status: {}", e), service: "monitoring_system".to_string(), context: None }
        })?;
        
        Ok(health.clone())
    }
    
    /// Get active alerts
    pub fn get_active_alerts(&self) -> AgentResult<Vec<Alert>> {
        let alerts = self.alerts.read().map_err(|e| {
            AgentError::Service { message: format!("Failed to read alerts: {}", e), service: "monitoring_system".to_string(), context: None }
        })?;
        
        Ok(alerts.iter().filter(|a| !a.resolved).cloned().collect())
    }
    
    /// Get all alerts
    pub fn get_all_alerts(&self, limit: Option<usize>) -> AgentResult<Vec<Alert>> {
        let alerts = self.alerts.read().map_err(|e| {
            AgentError::Service { message: format!("Failed to read alerts: {}", e), service: "monitoring_system".to_string(), context: None }
        })?;
        
        let result: Vec<Alert> = if let Some(limit) = limit {
            alerts.iter().rev().take(limit).cloned().collect()
        } else {
            alerts.iter().cloned().collect()
        };
        
        Ok(result)
    }
    
    /// Resolve an alert
    pub fn resolve_alert(&self, alert_id: &str) -> AgentResult<bool> {
        let mut alerts = self.alerts.write().map_err(|e| {
            AgentError::Service { message: format!("Failed to write alerts: {}", e), service: "monitoring_system".to_string(), context: None }
        })?;
        
        for alert in alerts.iter_mut() {
            if alert.id == alert_id && !alert.resolved {
                alert.resolved = true;
                info!("Alert resolved: {} - {}", alert_id, alert.title);
                return Ok(true);
            }
        }
        
        Ok(false)
    }
    
    /// Update monitoring configuration
    pub async fn update_config(&self, new_config: MonitoringConfig) -> AgentResult<()> {
        {
            let mut config = self.config.write().map_err(|e| {
                AgentError::Service { message: format!("Failed to update config: {}", e), service: "monitoring_system".to_string(), context: None }
            })?;
            *config = new_config;
        }
        
        // Restart components with new configuration
        if self.is_running()? {
            info!("Restarting monitoring system with new configuration");
            self.stop().await?;
            self.start().await?;
        }
        
        Ok(())
    }
    
    /// Check if monitoring system is running
    pub fn is_running(&self) -> AgentResult<bool> {
        let running = self.running.read().map_err(|e| {
            AgentError::Service { message: format!("Failed to read running status: {}", e), service: "monitoring_system".to_string(), context: None }
        })?;
        
        Ok(*running)
    }
    
    /// Get system statistics
    pub fn get_statistics(&self) -> AgentResult<MonitoringStatistics> {
        let metrics_count = {
            let history = self.metrics_history.read().map_err(|e| {
                AgentError::Service { message: format!("Failed to read metrics history: {}", e), service: "monitoring_system".to_string(), context: None }
            })?;
            history.len()
        };
        
        let alerts_count = {
            let alerts = self.alerts.read().map_err(|e| {
                AgentError::Service { message: format!("Failed to read alerts: {}", e), service: "monitoring_system".to_string(), context: None }
            })?;
            alerts.len()
        };
        
        let active_alerts_count = {
            let alerts = self.alerts.read().map_err(|e| {
                AgentError::Service { message: format!("Failed to read alerts: {}", e), service: "monitoring_system".to_string(), context: None }
            })?;
            alerts.iter().filter(|a| !a.resolved).count()
        };
        
        let last_collection = {
            let last = self.last_collection.read().map_err(|e| {
                AgentError::Service { message: format!("Failed to read last collection time: {}", e), service: "monitoring_system".to_string(), context: None }
            })?;
            *last
        };
        
        Ok(MonitoringStatistics {
            metrics_collected: metrics_count,
            alerts_generated: alerts_count,
            active_alerts: active_alerts_count,
            last_collection_time: last_collection,
            uptime: self.get_uptime()?,
        })
    }
    
    /// Start the main monitoring loop
    async fn start_monitoring_loop(&self) -> AgentResult<()> {
        let config = {
            let config = self.config.read().map_err(|e| {
                AgentError::Service { message: format!("Failed to read config: {}", e), service: "monitoring_system".to_string(), context: None }
            })?;
            config.clone()
        };
        
        let interval_duration = Duration::from_secs(config.collection_interval_seconds);
        
        // Clone the necessary components for the async task
        let performance_monitor = Arc::clone(&self.performance_monitor);
        let health_checker = Arc::clone(&self.health_checker);
        let metrics_history = Arc::clone(&self.metrics_history);
        let health_status = Arc::clone(&self.health_status);
        let last_collection = Arc::clone(&self.last_collection);
        let running = Arc::clone(&self.running);
        let config_arc = Arc::clone(&self.config);
        
        tokio::spawn(async move {
            let mut interval = interval(interval_duration);
            
            loop {
                interval.tick().await;
                
                // Check if still running
                {
                    let running_guard = running.read().map_err(|e| {
                        error!("Failed to read running status: {}", e);
                    });
                    if let Ok(guard) = running_guard {
                        if !*guard {
                            break;
                        }
                    } else {
                        error!("Failed to check running status, stopping monitoring loop");
                        break;
                    }
                }
                
                // Collect metrics
                if let Ok(metrics) = performance_monitor.get_current_metrics().await {
                    // Store metrics in history
                    {
                        if let Ok(mut history) = metrics_history.write() {
                            history.push_back(metrics.clone());
                            
                            // Limit history size based on retention policy
                            if let Ok(config) = config_arc.read() {
                                let max_entries = (config.retention_hours * 3600) / config.collection_interval_seconds;
                                while history.len() > max_entries as usize {
                                    history.pop_front();
                                }
                            }
                        }
                    }
                    
                    // Update last collection time
                    if let Ok(mut last_coll) = last_collection.write() {
                        *last_coll = Some(Instant::now());
                    }
                } else {
                    error!("Failed to collect metrics");
                }
                
                // Perform health checks
                if let Ok(health_report) = health_checker.check_health().await {
                    if let Ok(mut health_stat) = health_status.write() {
                        *health_stat = health_report;
                    }
                } else {
                    error!("Failed to perform health checks");
                }
            }
            
            debug!("Monitoring loop stopped");
        });
        
        Ok(())
    }
    
    /// Collect current metrics
    async fn collect_metrics(&self) -> AgentResult<()> {
        let metrics = self.performance_monitor.get_current_metrics().await?;
        
        // Store metrics in history
        {
            let mut history = self.metrics_history.write().map_err(|e| {
                AgentError::Service { message: format!("Failed to write metrics history: {}", e), service: "monitoring_system".to_string(), context: None }
            })?;
            
            history.push_back(metrics.clone());
            
            // Limit history size based on retention policy
            let config = self.config.read().map_err(|e| {
                AgentError::Service { message: format!("Failed to read config: {}", e), service: "monitoring_system".to_string(), context: None }
            })?;
            
            let max_entries = (config.retention_hours * 3600) / config.collection_interval_seconds;
            while history.len() > max_entries as usize {
                history.pop_front();
            }
        }
        
        // Update last collection time
        {
            let mut last_collection = self.last_collection.write().map_err(|e| {
                AgentError::Service { message: format!("Failed to write last collection time: {}", e), service: "monitoring_system".to_string(), context: None }
            })?;
            *last_collection = Some(Instant::now());
        }
        
        // Check for threshold violations and generate alerts
        self.check_thresholds(&metrics).await?;
        
        debug!("Metrics collected: CPU: {:.1}%, Memory: {:.1}%, Throughput: {:.1} files/sec", 
               metrics.cpu_usage_percent, metrics.memory_usage_percent, metrics.scan_throughput);
        
        Ok(())
    }
    
    /// Perform health checks
    async fn perform_health_checks(&self) -> AgentResult<()> {
        let health_report = self.health_checker.check_health().await?;
        
        {
            let mut health_status = self.health_status.write().map_err(|e| {
                AgentError::Service { message: format!("Failed to write health status: {}", e), service: "monitoring_system".to_string(), context: None }
            })?;
            *health_status = health_report.clone();
        }
        
        // Generate alerts for critical health issues
        if health_report.overall_status == HealthStatus::Critical {
            let alert = Alert {
                id: format!("health-critical-{}", health_report.timestamp),
                severity: AlertSeverity::Critical,
                title: "System Health Critical".to_string(),
                message: format!("System health status: {:?}", 
                               health_report.overall_status),
                component: "health_checker".to_string(),
                timestamp: health_report.timestamp,
                resolved: false,
                metadata: HashMap::new(),
            };
            
            self.add_alert(alert).await?;
        }
        
        Ok(())
    }
    
    /// Check performance thresholds and generate alerts
    async fn check_thresholds(&self, metrics: &PerformanceMetrics) -> AgentResult<()> {
        let config = {
            let config = self.config.read().map_err(|e| {
                AgentError::Service { message: format!("Failed to read config: {}", e), service: "monitoring_system".to_string(), context: None }
            })?;
            config.thresholds.clone()
        };
        
        let timestamp = metrics.timestamp;
        
        // CPU usage alerts
        if metrics.cpu_usage_percent > config.cpu_critical {
            let alert = Alert {
                id: format!("cpu-critical-{}", timestamp),
                severity: AlertSeverity::Critical,
                title: "Critical CPU Usage".to_string(),
                message: format!("CPU usage: {:.1}% > {:.1}%", 
                               metrics.cpu_usage_percent, config.cpu_critical),
                component: "performance_monitor".to_string(),
                timestamp,
                resolved: false,
                metadata: HashMap::from([
                    ("cpu_usage".to_string(), metrics.cpu_usage_percent.to_string()),
                    ("threshold".to_string(), config.cpu_critical.to_string()),
                ]),
            };
            self.add_alert(alert).await?;
        } else if metrics.cpu_usage_percent > config.cpu_warning {
            let alert = Alert {
                id: format!("cpu-warning-{}", timestamp),
                severity: AlertSeverity::Warning,
                title: "High CPU Usage".to_string(),
                message: format!("CPU usage: {:.1}% > {:.1}%", 
                               metrics.cpu_usage_percent, config.cpu_warning),
                component: "performance_monitor".to_string(),
                timestamp,
                resolved: false,
                metadata: HashMap::from([
                    ("cpu_usage".to_string(), metrics.cpu_usage_percent.to_string()),
                    ("threshold".to_string(), config.cpu_warning.to_string()),
                ]),
            };
            self.add_alert(alert).await?;
        }
        
        // Memory usage alerts
        if metrics.memory_usage_percent > config.memory_critical {
            let alert = Alert {
                id: format!("memory-critical-{}", timestamp),
                severity: AlertSeverity::Critical,
                title: "Critical Memory Usage".to_string(),
                message: format!("Memory usage: {:.1}% > {:.1}%", 
                               metrics.memory_usage_percent, config.memory_critical),
                component: "performance_monitor".to_string(),
                timestamp,
                resolved: false,
                metadata: HashMap::from([
                    ("memory_usage".to_string(), metrics.memory_usage_percent.to_string()),
                    ("memory_bytes".to_string(), metrics.memory_usage_bytes.to_string()),
                    ("threshold".to_string(), config.memory_critical.to_string()),
                ]),
            };
            self.add_alert(alert).await?;
        } else if metrics.memory_usage_percent > config.memory_warning {
            let alert = Alert {
                id: format!("memory-warning-{}", timestamp),
                severity: AlertSeverity::Warning,
                title: "High Memory Usage".to_string(),
                message: format!("Memory usage: {:.1}% > {:.1}%", 
                               metrics.memory_usage_percent, config.memory_warning),
                component: "performance_monitor".to_string(),
                timestamp,
                resolved: false,
                metadata: HashMap::from([
                    ("memory_usage".to_string(), metrics.memory_usage_percent.to_string()),
                    ("memory_bytes".to_string(), metrics.memory_usage_bytes.to_string()),
                    ("threshold".to_string(), config.memory_warning.to_string()),
                ]),
            };
            self.add_alert(alert).await?;
        }
        
        // Throughput alerts
        if metrics.scan_throughput < config.throughput_warning {
            let alert = Alert {
                id: format!("throughput-warning-{}", timestamp),
                severity: AlertSeverity::Warning,
                title: "Low Scan Throughput".to_string(),
                message: format!("Scan throughput: {:.1} files/sec < {:.1} files/sec", 
                               metrics.scan_throughput, config.throughput_warning),
                component: "performance_monitor".to_string(),
                timestamp,
                resolved: false,
                metadata: HashMap::from([
                    ("throughput".to_string(), metrics.scan_throughput.to_string()),
                    ("threshold".to_string(), config.throughput_warning.to_string()),
                ]),
            };
            self.add_alert(alert).await?;
        }
        
        // Error rate alerts
        if metrics.error_rate > config.error_rate_critical {
            let alert = Alert {
                id: format!("error-rate-critical-{}", timestamp),
                severity: AlertSeverity::Critical,
                title: "Critical Error Rate".to_string(),
                message: format!("Error rate: {:.1}% > {:.1}%", 
                               metrics.error_rate * 100.0, config.error_rate_critical * 100.0),
                component: "performance_monitor".to_string(),
                timestamp,
                resolved: false,
                metadata: HashMap::from([
                    ("error_rate".to_string(), metrics.error_rate.to_string()),
                    ("threshold".to_string(), config.error_rate_critical.to_string()),
                ]),
            };
            self.add_alert(alert).await?;
        } else if metrics.error_rate > config.error_rate_warning {
            let alert = Alert {
                id: format!("error-rate-warning-{}", timestamp),
                severity: AlertSeverity::Warning,
                title: "High Error Rate".to_string(),
                message: format!("Error rate: {:.1}% > {:.1}%", 
                               metrics.error_rate * 100.0, config.error_rate_warning * 100.0),
                component: "performance_monitor".to_string(),
                timestamp,
                resolved: false,
                metadata: HashMap::from([
                    ("error_rate".to_string(), metrics.error_rate.to_string()),
                    ("threshold".to_string(), config.error_rate_warning.to_string()),
                ]),
            };
            self.add_alert(alert).await?;
        }
        
        Ok(())
    }
    
    /// Add an alert to the system
    async fn add_alert(&self, alert: Alert) -> AgentResult<()> {
        // Check for duplicate alerts (cooldown period)
        let config = {
            let config = self.config.read().map_err(|e| {
                AgentError::Service { message: format!("Failed to read config: {}", e), service: "monitoring_system".to_string(), context: None }
            })?;
            config.clone()
        };
        
        let cooldown_seconds = config.alert_cooldown_minutes * 60;
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        {
            let alerts = self.alerts.read().map_err(|e| {
                AgentError::Service { message: format!("Failed to read alerts: {}", e), service: "monitoring_system".to_string(), context: None }
            })?;
            
            // Check for recent similar alerts
            for existing_alert in alerts.iter().rev().take(100) {
                if existing_alert.component == alert.component &&
                   existing_alert.title == alert.title &&
                   (current_time - existing_alert.timestamp) < cooldown_seconds {
                    debug!("Skipping duplicate alert: {} (cooldown active)", alert.title);
                    return Ok(());
                }
            }
        }
        
        // Add the alert
        {
            let mut alerts = self.alerts.write().map_err(|e| {
                AgentError::Service { message: format!("Failed to write alerts: {}", e), service: "monitoring_system".to_string(), context: None }
            })?;
            alerts.push(alert.clone());
        }
        
        // Log the alert first
        match alert.severity {
            AlertSeverity::Critical | AlertSeverity::Error => {
                error!("ALERT [{}]: {} - {}", alert.severity, alert.title, alert.message);
            }
            AlertSeverity::Warning => {
                warn!("ALERT [{}]: {} - {}", alert.severity, alert.title, alert.message);
            }
            AlertSeverity::Info => {
                info!("ALERT [{}]: {} - {}", alert.severity, alert.title, alert.message);
            }
        }
        
        // Send alert through alerting system
        self.alerting_system.create_alert(
            alert.title,
            alert.message,
            alert.severity,
            AlertCategory::System,
            alert.component
        ).await?;
        
        Ok(())
    }
    
    /// Clean up old data based on retention policy
    async fn cleanup_old_data(&self) -> AgentResult<()> {
        let config = {
            let config = self.config.read().map_err(|e| {
                AgentError::Service { message: format!("Failed to read config: {}", e), service: "monitoring_system".to_string(), context: None }
            })?;
            config.clone()
        };
        
        let retention_seconds = config.retention_hours * 3600;
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        // Clean up old alerts
        {
            let mut alerts = self.alerts.write().map_err(|e| {
                AgentError::Service { message: format!("Failed to write alerts: {}", e), service: "monitoring_system".to_string(), context: None }
            })?;
            
            let initial_count = alerts.len();
            alerts.retain(|alert| {
                (current_time - alert.timestamp) < retention_seconds
            });
            
            let removed_count = initial_count - alerts.len();
            if removed_count > 0 {
                debug!("Cleaned up {} old alerts", removed_count);
            }
        }
        
        Ok(())
    }
    
    /// Get system uptime
    fn get_uptime(&self) -> AgentResult<Duration> {
        let last_collection = self.last_collection.read().map_err(|e| {
            AgentError::Service { message: format!("Failed to read last collection time: {}", e), service: "monitoring_system".to_string(), context: None }
        })?;
        
        if let Some(start_time) = *last_collection {
            Ok(start_time.elapsed())
        } else {
            Ok(Duration::from_secs(0))
        }
    }
}

/// Monitoring system statistics
#[derive(Debug, Clone)]
pub struct MonitoringStatistics {
    pub metrics_collected: usize,
    pub alerts_generated: usize,
    pub active_alerts: usize,
    pub last_collection_time: Option<Instant>,
    pub uptime: Duration,
}

#[cfg(all(test, feature = "metrics"))]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_monitoring_system_creation() {
        let config = MonitoringConfig::default();
        let monitoring_system = MonitoringSystem::new(config);
        assert!(monitoring_system.is_ok());
    }
    
    #[tokio::test]
    async fn test_monitoring_system_start_stop() {
        let config = MonitoringConfig::default();
        let monitoring_system = MonitoringSystem::new(config).unwrap();
        
        assert!(!monitoring_system.is_running().unwrap());
        
        // Note: In a real test, we would start and stop the system
        // but that requires implementing all the sub-components
    }
    
    #[test]
    fn test_resource_thresholds_default() {
        let thresholds = ResourceThresholds::default();
        assert_eq!(thresholds.cpu_warning, 70.0);
        assert_eq!(thresholds.cpu_critical, 90.0);
        assert_eq!(thresholds.memory_warning, 80.0);
        assert_eq!(thresholds.memory_critical, 95.0);
    }
    
    #[test]
    fn test_health_status_levels() {
        assert_eq!(HealthStatus::Healthy, HealthStatus::Healthy);
        assert_ne!(HealthStatus::Healthy, HealthStatus::Critical);
    }
    
    #[test]
    fn test_alert_severity_levels() {
        assert_eq!(AlertSeverity::Critical, AlertSeverity::Critical);
        assert_ne!(AlertSeverity::Warning, AlertSeverity::Critical);
    }
}
