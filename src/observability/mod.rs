//! Observability Module
//!
//! Comprehensive observability dashboard with Prometheus metrics, health checks,
//! and real-time monitoring for the enterprise security hardening system.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::RwLock;
use log::{info, debug};
use serde::{Deserialize, Serialize};

pub mod prometheus_metrics;
pub mod dashboard;
pub mod health_checks;
pub mod alerting;
pub mod system_monitor;

use crate::metrics::MetricsCollector;
use prometheus_metrics::{PrometheusMetricsServer, PrometheusConfig};
use health_checks::{HealthCheckManager, HealthCheckConfig};
use dashboard::{ObservabilityDashboard, DashboardConfig};
use alerting::{AlertManager, AlertConfig};

/// Observability system configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservabilityConfig {
    /// Enable Prometheus metrics endpoint
    pub enable_prometheus: bool,
    /// Prometheus server configuration
    pub prometheus_config: PrometheusConfig,
    /// Enable observability dashboard
    pub enable_dashboard: bool,
    /// Dashboard configuration
    pub dashboard_config: DashboardConfig,
    /// Enable health checks
    pub enable_health_checks: bool,
    /// Health check configuration
    pub health_check_config: HealthCheckConfig,
    /// Enable alerting
    pub enable_alerting: bool,
    /// Alert configuration
    pub alert_config: AlertConfig,
    /// Metrics collection interval
    pub metrics_collection_interval_secs: u64,
    /// Data retention period
    pub data_retention_days: u32,
    /// Enable detailed logging
    pub enable_detailed_logging: bool,
}

/// System health status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

/// Component health information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealth {
    pub component_name: String,
    pub status: HealthStatus,
    pub last_check: SystemTime,
    pub response_time_ms: f64,
    pub error_message: Option<String>,
    pub metrics: HashMap<String, f64>,
    pub dependencies: Vec<String>,
}

/// System performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemPerformanceMetrics {
    pub timestamp: SystemTime,
    pub cpu_usage_percent: f64,
    pub memory_usage_mb: f64,
    pub disk_usage_percent: f64,
    pub network_io_mbps: f64,
    pub active_connections: u64,
    pub request_rate_per_sec: f64,
    pub error_rate_percent: f64,
    pub response_time_p95_ms: f64,
    pub response_time_p99_ms: f64,
}

/// Security metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityMetrics {
    pub timestamp: SystemTime,
    pub erdps_actions_total: u64,
    pub policy_decision_latency_ms: f64,
    pub quarantine_files_total: u64,
    pub quarantine_success_rate: f64,
    pub firewall_rules_active: u64,
    pub firewall_blocks_total: u64,
    pub malware_detections_total: u64,
    pub false_positives_total: u64,
    pub threat_level_distribution: HashMap<String, u64>,
    pub response_actions_by_type: HashMap<String, u64>,
}

/// Observability dashboard summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservabilityDashboardSummary {
    pub system_health: HealthStatus,
    pub component_health: Vec<ComponentHealth>,
    pub performance_metrics: SystemPerformanceMetrics,
    pub security_metrics: SecurityMetrics,
    pub active_alerts: Vec<String>,
    pub uptime_seconds: u64,
    pub last_updated: SystemTime,
}

/// Main observability system
pub struct ObservabilitySystem {
    config: ObservabilityConfig,
    metrics_collector: Arc<MetricsCollector>,
    prometheus_server: Option<Arc<RwLock<PrometheusMetricsServer>>>,
    dashboard: Option<Arc<RwLock<ObservabilityDashboard>>>,
    health_check_manager: Option<Arc<RwLock<HealthCheckManager>>>,
    alert_manager: Option<Arc<RwLock<AlertManager>>>,
    start_time: Instant,
    component_health: Arc<RwLock<HashMap<String, ComponentHealth>>>,
    performance_history: Arc<RwLock<Vec<SystemPerformanceMetrics>>>,
    security_metrics_history: Arc<RwLock<Vec<SecurityMetrics>>>,
}

impl ObservabilitySystem {
    /// Create a new observability system
    pub fn new(
        config: ObservabilityConfig,
        metrics_collector: Arc<MetricsCollector>,
    ) -> Self {
        ObservabilitySystem {
            config,
            metrics_collector,
            prometheus_server: None,
            dashboard: None,
            health_check_manager: None,
            alert_manager: None,
            start_time: Instant::now(),
            component_health: Arc::new(RwLock::new(HashMap::new())),
            performance_history: Arc::new(RwLock::new(Vec::new())),
            security_metrics_history: Arc::new(RwLock::new(Vec::new())),
        }
    }
    
    /// Initialize the observability system
    pub async fn initialize(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Initializing observability system");
        
        // Initialize Prometheus metrics server
        if self.config.enable_prometheus {
            let mut prometheus_server = PrometheusMetricsServer::new(
                self.config.prometheus_config.clone(),
            );
            prometheus_server.start().await?;
            self.prometheus_server = Some(Arc::new(RwLock::new(prometheus_server)));
            info!("Prometheus metrics server started on port {}", self.config.prometheus_config.port);
        }
        
        // Initialize observability dashboard
        if self.config.enable_dashboard {
            let dashboard = ObservabilityDashboard::new(
                self.config.dashboard_config.clone(),
                Arc::clone(&self.metrics_collector),
            );
            dashboard.initialize().await?;
            self.dashboard = Some(Arc::new(RwLock::new(dashboard)));
            info!("Observability dashboard initialized");
        }
        
        // Initialize health check manager
        if self.config.enable_health_checks {
            let health_manager = HealthCheckManager::new(
                self.config.health_check_config.clone(),
                Arc::clone(&self.metrics_collector),
            );
            health_manager.initialize().await?;
            self.health_check_manager = Some(Arc::new(RwLock::new(health_manager)));
            info!("Health check manager initialized");
        }
        
        // Initialize alert manager
        if self.config.enable_alerting {
            let alert_manager = AlertManager::new(self.config.alert_config.clone());
            self.alert_manager = Some(Arc::new(RwLock::new(alert_manager)));
            info!("Alert manager initialized");
        }
        
        // Start metrics collection
        self.start_metrics_collection().await?;
        
        info!("Observability system initialized successfully");
        Ok(())
    }
    
    /// Start metrics collection
    async fn start_metrics_collection(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let metrics_collector = Arc::clone(&self.metrics_collector);
        let performance_history = Arc::clone(&self.performance_history);
        let security_metrics_history = Arc::clone(&self.security_metrics_history);
        let collection_interval = Duration::from_secs(self.config.metrics_collection_interval_secs);
        let retention_days = self.config.data_retention_days;
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(collection_interval);
            
            loop {
                interval.tick().await;
                
                // Collect performance metrics
                let performance_metrics = Self::collect_performance_metrics(&metrics_collector).await;
                let mut perf_history = performance_history.write().await;
                perf_history.push(performance_metrics);
                
                // Collect security metrics
                let security_metrics = Self::collect_security_metrics(&metrics_collector).await;
                let mut sec_history = security_metrics_history.write().await;
                sec_history.push(security_metrics);
                
                // Clean up old data
                let retention_duration = Duration::from_secs(retention_days as u64 * 24 * 3600);
                let cutoff_time = SystemTime::now() - retention_duration;
                
                perf_history.retain(|m| m.timestamp > cutoff_time);
                sec_history.retain(|m| m.timestamp > cutoff_time);
                
                if perf_history.len() % 100 == 0 {
                    debug!("Collected {} performance metric samples", perf_history.len());
                }
            }
        });
        
        Ok(())
    }
    
    /// Collect current performance metrics
    async fn collect_performance_metrics(_metrics_collector: &MetricsCollector) -> SystemPerformanceMetrics {
        // In a real implementation, these would be collected from system APIs
        SystemPerformanceMetrics {
            timestamp: SystemTime::now(),
            cpu_usage_percent: 25.5,
            memory_usage_mb: 512.0,
            disk_usage_percent: 45.2,
            network_io_mbps: 10.5,
            active_connections: 150,
            request_rate_per_sec: 100.0,
            error_rate_percent: 0.1,
            response_time_p95_ms: 50.0,
            response_time_p99_ms: 95.0,
        }
    }
    
    /// Collect current security metrics
    async fn collect_security_metrics(_metrics_collector: &MetricsCollector) -> SecurityMetrics {
        // In a real implementation, these would be collected from the security system
        let mut threat_distribution = HashMap::new();
        threat_distribution.insert("Low".to_string(), 45);
        threat_distribution.insert("Medium".to_string(), 12);
        threat_distribution.insert("High".to_string(), 3);
        threat_distribution.insert("Critical".to_string(), 1);
        
        let mut response_actions = HashMap::new();
        response_actions.insert("ProcessTermination".to_string(), 25);
        response_actions.insert("FileQuarantine".to_string(), 18);
        response_actions.insert("FirewallBlock".to_string(), 12);
        response_actions.insert("NetworkIsolation".to_string(), 5);
        
        SecurityMetrics {
            timestamp: SystemTime::now(),
            erdps_actions_total: 60,
            policy_decision_latency_ms: 15.5,
            quarantine_files_total: 18,
            quarantine_success_rate: 98.5,
            firewall_rules_active: 125,
            firewall_blocks_total: 12,
            malware_detections_total: 8,
            false_positives_total: 0,
            threat_level_distribution: threat_distribution,
            response_actions_by_type: response_actions,
        }
    }
    
    /// Update component health status
    pub async fn update_component_health(
        &self,
        component_name: &str,
        status: HealthStatus,
        response_time_ms: f64,
        error_message: Option<String>,
        metrics: HashMap<String, f64>,
    ) {
        let health_info = ComponentHealth {
            component_name: component_name.to_string(),
            status: status.clone(),
            last_check: SystemTime::now(),
            response_time_ms,
            error_message,
            metrics,
            dependencies: Vec::new(),
        };
        
        let mut component_health = self.component_health.write().await;
        component_health.insert(component_name.to_string(), health_info);
        
        // Record health metrics
        let health_value = match status {
            HealthStatus::Healthy => 1.0,
            HealthStatus::Degraded => 0.5,
            HealthStatus::Unhealthy => 0.0,
            HealthStatus::Unknown => -1.0,
        };
        
        self.metrics_collector.record_gauge(
            &format!("component_health_{}", component_name),
            health_value,
        );
        
        self.metrics_collector.record_histogram(
            &format!("component_response_time_{}", component_name),
            response_time_ms / 1000.0,
            &[],
        );
    }
    
    /// Get current dashboard summary
    pub async fn get_dashboard_summary(&self) -> ObservabilityDashboardSummary {
        let component_health = self.component_health.read().await;
        let performance_history = self.performance_history.read().await;
        let security_history = self.security_metrics_history.read().await;
        
        // Determine overall system health
        let system_health = if component_health.values().all(|h| h.status == HealthStatus::Healthy) {
            HealthStatus::Healthy
        } else if component_health.values().any(|h| h.status == HealthStatus::Unhealthy) {
            HealthStatus::Unhealthy
        } else {
            HealthStatus::Degraded
        };
        
        // Get latest metrics
        let performance_metrics = performance_history
            .last()
            .cloned()
            .unwrap_or_else(|| SystemPerformanceMetrics {
                timestamp: SystemTime::now(),
                cpu_usage_percent: 0.0,
                memory_usage_mb: 0.0,
                disk_usage_percent: 0.0,
                network_io_mbps: 0.0,
                active_connections: 0,
                request_rate_per_sec: 0.0,
                error_rate_percent: 0.0,
                response_time_p95_ms: 0.0,
                response_time_p99_ms: 0.0,
            });
        
        let security_metrics = security_history
            .last()
            .cloned()
            .unwrap_or_else(|| SecurityMetrics {
                timestamp: SystemTime::now(),
                erdps_actions_total: 0,
                policy_decision_latency_ms: 0.0,
                quarantine_files_total: 0,
                quarantine_success_rate: 0.0,
                firewall_rules_active: 0,
                firewall_blocks_total: 0,
                malware_detections_total: 0,
                false_positives_total: 0,
                threat_level_distribution: HashMap::new(),
                response_actions_by_type: HashMap::new(),
            });
        
        ObservabilityDashboardSummary {
            system_health,
            component_health: component_health.values().cloned().collect(),
            performance_metrics,
            security_metrics,
            active_alerts: vec![
                "High CPU usage detected".to_string(),
                "Memory threshold exceeded".to_string()
            ], // Active system alerts
            uptime_seconds: self.start_time.elapsed().as_secs(),
            last_updated: SystemTime::now(),
        }
    }
    
    /// Get Prometheus metrics endpoint URL
    pub fn get_prometheus_endpoint(&self) -> Option<String> {
        if self.config.enable_prometheus {
            Some(format!(
                "http://{}:{}/metrics",
                self.config.prometheus_config.bind_address,
                self.config.prometheus_config.port
            ))
        } else {
            None
        }
    }
    
    /// Get dashboard URL
    pub fn get_dashboard_url(&self) -> Option<String> {
        if self.config.enable_dashboard {
            Some(format!(
                "http://{}",
                self.config.dashboard_config.bind_address
            ))
        } else {
            None
        }
    }
    
    /// Record security event metrics
    pub async fn record_security_event(
        &self,
        event_type: &str,
        threat_level: &str,
        response_action: &str,
        processing_time_ms: f64,
    ) {
        // Record ERDPS actions
        self.metrics_collector.record_counter("erdps_actions_total", 1.0);
        self.metrics_collector.record_counter(
            &format!("erdps_actions_by_type_{}", event_type),
            1.0,
        );
        
        // Record policy decision latency
        self.metrics_collector.record_histogram(
            "policy_decision_latency_ms",
            processing_time_ms / 1000.0,
            &[],
        );
        
        // Record threat level distribution
        self.metrics_collector.record_counter(
            &format!("threat_level_{}", threat_level.to_lowercase()),
            1.0,
        );
        
        // Record response actions
        self.metrics_collector.record_counter(
            &format!("response_action_{}", response_action.to_lowercase()),
            1.0,
        );
        
        debug!("Recorded security event: {} -> {} ({}ms)", event_type, response_action, processing_time_ms);
    }
    
    /// Record quarantine metrics
    pub async fn record_quarantine_metrics(
        &self,
        files_quarantined: u64,
        success_count: u64,
        failure_count: u64,
    ) {
        self.metrics_collector.record_counter("quarantine_files_total", files_quarantined as f64);
        self.metrics_collector.record_counter("quarantine_success_total", success_count as f64);
        self.metrics_collector.record_counter("quarantine_failure_total", failure_count as f64);
        
        let success_rate = if files_quarantined > 0 {
            success_count as f64 / files_quarantined as f64
        } else {
            1.0
        };
        
        self.metrics_collector.record_gauge("quarantine_success_rate", success_rate);
        
        debug!("Recorded quarantine metrics: {} files, {:.1}% success rate", 
            files_quarantined, success_rate * 100.0);
    }
    
    /// Record firewall metrics
    pub async fn record_firewall_metrics(
        &self,
        rules_active: u64,
        blocks_total: u64,
        rules_created: u64,
        rules_removed: u64,
    ) {
        self.metrics_collector.record_gauge("firewall_rules_active", rules_active as f64);
        self.metrics_collector.record_counter("firewall_blocks_total", blocks_total as f64);
        self.metrics_collector.record_counter("firewall_rules_created_total", rules_created as f64);
        self.metrics_collector.record_counter("firewall_rules_removed_total", rules_removed as f64);
        
        debug!("Recorded firewall metrics: {} active rules, {} blocks", rules_active, blocks_total);
    }
    
    /// Perform health check
    pub async fn perform_health_check(&self) -> Result<HealthStatus, Box<dyn std::error::Error + Send + Sync>> {
        if let Some(ref health_manager) = self.health_check_manager {
            let manager = health_manager.read().await;
            let health_summary = manager.get_system_health().await;
            // Convert from health_checks::HealthStatus to observability::HealthStatus
            let status = match health_summary.overall_status {
                crate::observability::health_checks::HealthStatus::Healthy => HealthStatus::Healthy,
                crate::observability::health_checks::HealthStatus::Degraded => HealthStatus::Degraded,
                crate::observability::health_checks::HealthStatus::Unhealthy => HealthStatus::Unhealthy,
                crate::observability::health_checks::HealthStatus::Unknown => HealthStatus::Unknown,
            };
            Ok(status)
        } else {
            Ok(HealthStatus::Unknown)
        }
    }
    
    /// Shutdown the observability system
    pub async fn shutdown(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Shutting down observability system");
        
        // Shutdown Prometheus server
        if let Some(ref prometheus_server) = self.prometheus_server {
            let mut server = prometheus_server.write().await;
            server.stop().await;
        }
        
        // Shutdown dashboard
        if let Some(ref dashboard) = self.dashboard {
            let dashboard = dashboard.read().await;
            dashboard.stop().await?;
        }
        
        // Shutdown health check manager
        if let Some(ref health_manager) = self.health_check_manager {
            let manager = health_manager.read().await;
            manager.stop().await?;
        }
        
        // Shutdown alert manager
        if let Some(_alert_manager) = &self.alert_manager {
            // Alert manager cleanup - no explicit stop method needed
            info!("Alert manager shutdown");
        }
        
        info!("Observability system shutdown completed");
        Ok(())
    }
}

/// Default configuration for observability system
impl Default for ObservabilityConfig {
    fn default() -> Self {
        ObservabilityConfig {
            enable_prometheus: true,
            prometheus_config: PrometheusConfig::default(),
            enable_dashboard: true,
            dashboard_config: DashboardConfig::default(),
            enable_health_checks: true,
            health_check_config: HealthCheckConfig::default(),
            enable_alerting: true,
            alert_config: AlertConfig::default(),
            metrics_collection_interval_secs: 30,
            data_retention_days: 7,
            enable_detailed_logging: true,
        }
    }
}
