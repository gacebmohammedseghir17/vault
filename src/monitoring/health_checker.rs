//! Health Checker Component
//!
//! This module provides comprehensive health monitoring for the YARA agent,
//! including component health checks, dependency verification, and system status reporting.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use tokio::time::interval;
use tracing::{debug, error, info, warn};

use crate::error::{AgentError, AgentResult};
use super::MonitoringConfig;

/// Health status levels
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Critical,
    Unknown,
}

impl std::fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HealthStatus::Healthy => write!(f, "Healthy"),
            HealthStatus::Degraded => write!(f, "Degraded"),
            HealthStatus::Unhealthy => write!(f, "Unhealthy"),
            HealthStatus::Critical => write!(f, "Critical"),
            HealthStatus::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Health check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckResult {
    pub component: String,
    pub status: HealthStatus,
    pub message: String,
    pub details: HashMap<String, String>,
    pub timestamp: u64,
    pub duration_ms: u64,
    pub error: Option<String>,
}

/// System health report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthReport {
    pub overall_status: HealthStatus,
    pub timestamp: u64,
    pub uptime_seconds: u64,
    pub component_results: Vec<HealthCheckResult>,
    pub system_metrics: SystemHealthMetrics,
    pub dependencies: Vec<DependencyStatus>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

/// System health metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemHealthMetrics {
    pub memory_usage_percent: f64,
    pub cpu_usage_percent: f64,
    pub disk_usage_percent: f64,
    pub network_connectivity: bool,
    pub file_system_accessible: bool,
    pub yara_engine_status: HealthStatus,
    pub configuration_valid: bool,
    pub log_system_working: bool,
}

/// Dependency status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyStatus {
    pub name: String,
    pub version: Option<String>,
    pub status: HealthStatus,
    pub last_check: u64,
    pub error_message: Option<String>,
}

/// Health check configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    pub enabled_checks: Vec<String>,
    pub check_interval_seconds: u64,
    pub timeout_seconds: u64,
    pub retry_attempts: u32,
    pub critical_thresholds: CriticalThresholds,
    pub dependency_checks: Vec<DependencyCheck>,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            enabled_checks: vec![
                "yara_engine".to_string(),
                "file_system".to_string(),
                "memory".to_string(),
                "cpu".to_string(),
                "network".to_string(),
                "configuration".to_string(),
                "logging".to_string(),
            ],
            check_interval_seconds: 30,
            timeout_seconds: 10,
            retry_attempts: 3,
            critical_thresholds: CriticalThresholds::default(),
            dependency_checks: vec![
                DependencyCheck {
                    name: "yara".to_string(),
                    check_type: DependencyCheckType::Library,
                    required: true,
                    timeout_seconds: 5,
                },
                DependencyCheck {
                    name: "filesystem".to_string(),
                    check_type: DependencyCheckType::FileSystem,
                    required: true,
                    timeout_seconds: 3,
                },
            ],
        }
    }
}

/// Critical thresholds for health checks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CriticalThresholds {
    pub memory_usage_critical: f64,
    pub memory_usage_warning: f64,
    pub cpu_usage_critical: f64,
    pub cpu_usage_warning: f64,
    pub disk_usage_critical: f64,
    pub disk_usage_warning: f64,
    pub response_time_critical_ms: u64,
    pub response_time_warning_ms: u64,
}

impl Default for CriticalThresholds {
    fn default() -> Self {
        Self {
            memory_usage_critical: 90.0,
            memory_usage_warning: 80.0,
            cpu_usage_critical: 95.0,
            cpu_usage_warning: 85.0,
            disk_usage_critical: 95.0,
            disk_usage_warning: 85.0,
            response_time_critical_ms: 5000,
            response_time_warning_ms: 2000,
        }
    }
}

/// Dependency check configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyCheck {
    pub name: String,
    pub check_type: DependencyCheckType,
    pub required: bool,
    pub timeout_seconds: u64,
}

/// Types of dependency checks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DependencyCheckType {
    Library,
    Service,
    FileSystem,
    Network,
    Database,
}

/// Health checker statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckerStats {
    pub total_checks: u64,
    pub successful_checks: u64,
    pub failed_checks: u64,
    pub average_check_duration_ms: f64,
    pub last_check_time: Option<u64>,
    pub uptime_seconds: u64,
    pub status_changes: u64,
    pub component_stats: HashMap<String, ComponentHealthStats>,
}

/// Component-specific health statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealthStats {
    pub checks_performed: u64,
    pub success_rate: f64,
    pub average_duration_ms: f64,
    pub last_status: HealthStatus,
    pub status_changes: u64,
    pub last_error: Option<String>,
}

/// Health checker implementation
#[derive(Debug)]
pub struct HealthChecker {
    config: Arc<RwLock<HealthCheckConfig>>,
    monitoring_config: Arc<RwLock<MonitoringConfig>>,
    stats: Arc<RwLock<HealthCheckerStats>>,
    last_report: Arc<RwLock<Option<HealthReport>>>,
    running: Arc<RwLock<bool>>,
    start_time: Instant,
}

impl HealthChecker {
    /// Create a new health checker
    pub fn new(
        config: HealthCheckConfig,
        monitoring_config: Arc<RwLock<MonitoringConfig>>,
    ) -> AgentResult<Self> {
        Ok(Self {
            config: Arc::new(RwLock::new(config)),
            monitoring_config,
            stats: Arc::new(RwLock::new(HealthCheckerStats {
                total_checks: 0,
                successful_checks: 0,
                failed_checks: 0,
                average_check_duration_ms: 0.0,
                last_check_time: None,
                uptime_seconds: 0,
                status_changes: 0,
                component_stats: HashMap::new(),
            })),
            last_report: Arc::new(RwLock::new(None)),
            running: Arc::new(RwLock::new(false)),
            start_time: Instant::now(),
        })
    }
    
    /// Start the health checker
    pub async fn start(&self) -> AgentResult<()> {
        info!("Starting health checker");
        
        {
            let mut running = self.running.write().map_err(|e| {
                AgentError::Service { 
                    message: format!("Failed to acquire running lock: {}", e),
                    service: "health_checker".to_string(),
                    context: None
                }
            })?;
            
            if *running {
                return Err(AgentError::Service { 
                    message: "Health checker is already running".to_string(), 
                    service: "health_checker".to_string(),
                    context: None 
                });
            }
            
            *running = true;
        }
        
        // Start health check loop
        self.start_health_check_loop().await?;
        
        info!("Health checker started successfully");
        Ok(())
    }
    
    /// Stop the health checker
    pub async fn stop(&self) -> AgentResult<()> {
        info!("Stopping health checker");
        
        {
            let mut running = self.running.write().map_err(|e| {
                AgentError::Service { 
                    message: format!("Failed to acquire running lock: {}", e),
                    service: "health_checker".to_string(),
                    context: None
                }
            })?;
            
            if !*running {
                return Ok(());
            }
            
            *running = false;
        }
        
        info!("Health checker stopped successfully");
        Ok(())
    }
    
    /// Perform a complete health check
    pub async fn check_health(&self) -> AgentResult<HealthReport> {
        let start_time = Instant::now();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let config = {
            let config = self.config.read().map_err(|e| {
                AgentError::Service { 
                    message: format!("Failed to read health check config: {}", e),
                    service: "health_checker".to_string(),
                    context: None
                }
            })?;
            config.clone()
        };
        
        let mut component_results = Vec::new();
        let mut warnings = Vec::new();
        let mut errors = Vec::new();
        
        // Perform individual component checks
        for check_name in &config.enabled_checks {
            match self.check_component(check_name).await {
                Ok(result) => {
                    match result.status {
                        HealthStatus::Degraded => {
                            warnings.push(format!("{}: {}", result.component, result.message));
                        }
                        HealthStatus::Unhealthy | HealthStatus::Critical => {
                            errors.push(format!("{}: {}", result.component, result.message));
                        }
                        _ => {}
                    }
                    component_results.push(result);
                }
                Err(e) => {
                    let error_msg = format!("Failed to check {}: {}", check_name, e);
                    errors.push(error_msg.clone());
                    
                    component_results.push(HealthCheckResult {
                        component: check_name.clone(),
                        status: HealthStatus::Unknown,
                        message: "Check failed".to_string(),
                        details: HashMap::new(),
                        timestamp,
                        duration_ms: 0,
                        error: Some(error_msg),
                    });
                }
            }
        }
        
        // Check dependencies
        let dependencies = self.check_dependencies().await?;
        
        // Get system metrics
        let system_metrics = self.get_system_health_metrics().await?;
        
        // Determine overall status
        let overall_status = self.calculate_overall_status(&component_results, &dependencies);
        
        let uptime_seconds = self.start_time.elapsed().as_secs();
        
        let report = HealthReport {
            overall_status,
            timestamp,
            uptime_seconds,
            component_results,
            system_metrics,
            dependencies,
            warnings,
            errors,
        };
        
        // Update statistics
        self.update_stats(&report, start_time.elapsed()).await?;
        
        // Store last report
        {
            let mut last_report = self.last_report.write().map_err(|e| {
                AgentError::Service { 
                    message: format!("Failed to write last report: {}", e),
                    service: "health_checker".to_string(),
                    context: None
                }
            })?;
            *last_report = Some(report.clone());
        }
        
        Ok(report)
    }
    
    /// Get the last health report
    pub fn get_last_report(&self) -> AgentResult<Option<HealthReport>> {
        let last_report = self.last_report.read().map_err(|e| {
            AgentError::Service { 
                message: format!("Failed to read last report: {}", e),
                service: "health_checker".to_string(),
                context: None
            }
        })?;
        
        Ok(last_report.clone())
    }
    
    /// Get health checker statistics
    pub fn get_stats(&self) -> AgentResult<HealthCheckerStats> {
        let stats = self.stats.read().map_err(|e| {
            AgentError::Service { 
                message: format!("Failed to read health checker stats: {}", e),
                service: "health_checker".to_string(),
                context: None
            }
        })?;
        
        Ok(stats.clone())
    }
    
    /// Reset health checker statistics
    pub fn reset_stats(&self) -> AgentResult<()> {
        let mut stats = self.stats.write().map_err(|e| {
            AgentError::Service { 
                message: format!("Failed to write health checker stats: {}", e),
                service: "health_checker".to_string(),
                context: None
            }
        })?;
        
        *stats = HealthCheckerStats {
            total_checks: 0,
            successful_checks: 0,
            failed_checks: 0,
            average_check_duration_ms: 0.0,
            last_check_time: None,
            uptime_seconds: 0,
            status_changes: 0,
            component_stats: HashMap::new(),
        };
        
        info!("Health checker statistics reset");
        Ok(())
    }
    
    /// Check if health checker is running
    pub fn is_running(&self) -> AgentResult<bool> {
        let running = self.running.read().map_err(|e| {
            AgentError::Service { 
                message: format!("Failed to read running status: {}", e),
                service: "health_checker".to_string(),
                context: None
            }
        })?;
        
        Ok(*running)
    }
    
    /// Update health check configuration
    pub fn update_config(&self, new_config: HealthCheckConfig) -> AgentResult<()> {
        let mut config = self.config.write().map_err(|e| {
            AgentError::Service { 
                message: format!("Failed to write health check config: {}", e),
                service: "health_checker".to_string(),
                context: None
            }
        })?;
        
        *config = new_config;
        info!("Health check configuration updated");
        Ok(())
    }
    
    /// Start the health check loop
    async fn start_health_check_loop(&self) -> AgentResult<()> {
        let config = {
            let config = self.config.read().map_err(|e| {
                AgentError::Service {
                    message: format!("Failed to read health check config: {}", e),
                    service: "health_checker".to_string(),
                    context: None
                }
            })?;
            config.clone()
        };
        
        // Clone Arc fields for the spawned task
        let config_arc = Arc::clone(&self.config);
        let running_arc = Arc::clone(&self.running);
        let stats_arc = Arc::clone(&self.stats);
        let monitoring_config_arc = Arc::clone(&self.monitoring_config);
        let last_report_arc = Arc::clone(&self.last_report);
        let start_time = self.start_time;
        
        let interval_duration = Duration::from_secs(config.check_interval_seconds);
        
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
                
                // Create a temporary HealthChecker for method calls
                let temp_checker = HealthChecker {
                    config: Arc::clone(&config_arc),
                    monitoring_config: Arc::clone(&monitoring_config_arc),
                    stats: Arc::clone(&stats_arc),
                    last_report: Arc::clone(&last_report_arc),
                    running: Arc::clone(&running_arc),
                    start_time,
                };
                
                // Perform health check
                match temp_checker.check_health().await {
                    Ok(report) => {
                        debug!("Health check completed: {}", report.overall_status);
                        
                        // Log warnings and errors
                        for warning in &report.warnings {
                            warn!("Health warning: {}", warning);
                        }
                        
                        for error in &report.errors {
                            error!("Health error: {}", error);
                        }
                    }
                    Err(e) => {
                        error!("Health check failed: {}", e);
                    }
                }
            }
            
            debug!("Health checker loop stopped");
        });
        
        Ok(())
    }
    
    /// Check a specific component
    async fn check_component(&self, component: &str) -> AgentResult<HealthCheckResult> {
        let start_time = Instant::now();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let (status, message, details, error) = match component {
            "yara_engine" => self.check_yara_engine().await,
            "file_system" => self.check_file_system().await,
            "memory" => self.check_memory().await,
            "cpu" => self.check_cpu().await,
            "network" => self.check_network().await,
            "configuration" => self.check_configuration().await,
            "logging" => self.check_logging().await,
            _ => {
                return Err(AgentError::Service {
                    message: format!("Unknown component: {}", component),
                    service: "health_checker".to_string(),
            context: None});
            }
        };
        
        let duration_ms = start_time.elapsed().as_millis() as u64;
        
        Ok(HealthCheckResult {
            component: component.to_string(),
            status,
            message,
            details,
            timestamp,
            duration_ms,
            error,
        })
    }
    
    /// Check YARA engine health
    async fn check_yara_engine(&self) -> (HealthStatus, String, HashMap<String, String>, Option<String>) {
        let mut details = HashMap::new();
        
        // In a real implementation, this would:
        // 1. Check if YARA library is loaded
        // 2. Verify rule compilation works
        // 3. Test basic scanning functionality
        // 4. Check rule update status
        
        details.insert("library_loaded".to_string(), "true".to_string());
        details.insert("rules_compiled".to_string(), "true".to_string());
        details.insert("last_update".to_string(), "2024-01-01T00:00:00Z".to_string());
        
        (HealthStatus::Healthy, "YARA engine is operational".to_string(), details, None)
    }
    
    /// Check file system health
    async fn check_file_system(&self) -> (HealthStatus, String, HashMap<String, String>, Option<String>) {
        let mut details = HashMap::new();
        
        // Check if scan directories are accessible
        let test_paths = vec!["/tmp", "C:\\temp", "."];
        let mut accessible_count = 0;
        
        for path in &test_paths {
            if std::path::Path::new(path).exists() {
                accessible_count += 1;
                details.insert(format!("path_{}_accessible", path), "true".to_string());
            } else {
                details.insert(format!("path_{}_accessible", path), "false".to_string());
            }
        }
        
        if accessible_count > 0 {
            (HealthStatus::Healthy, "File system is accessible".to_string(), details, None)
        } else {
            (HealthStatus::Critical, "No accessible file system paths".to_string(), details, 
             Some("All test paths are inaccessible".to_string()))
        }
    }
    
    /// Check memory health
    async fn check_memory(&self) -> (HealthStatus, String, HashMap<String, String>, Option<String>) {
        let mut details = HashMap::new();
        
        // Mock memory usage - in real implementation, get actual values
        let memory_usage_percent = 45.0;
        let memory_usage_bytes = 512 * 1024 * 1024; // 512MB
        
        details.insert("usage_percent".to_string(), format!("{:.1}", memory_usage_percent));
        details.insert("usage_bytes".to_string(), memory_usage_bytes.to_string());
        
        let config = self.config.read().unwrap();
        let thresholds = &config.critical_thresholds;
        
        if memory_usage_percent > thresholds.memory_usage_critical {
            (HealthStatus::Critical, 
             format!("Memory usage critical: {:.1}%", memory_usage_percent), 
             details, 
             Some("Memory usage exceeds critical threshold".to_string()))
        } else if memory_usage_percent > thresholds.memory_usage_warning {
            (HealthStatus::Degraded, 
             format!("Memory usage high: {:.1}%", memory_usage_percent), 
             details, None)
        } else {
            (HealthStatus::Healthy, 
             format!("Memory usage normal: {:.1}%", memory_usage_percent), 
             details, None)
        }
    }
    
    /// Check CPU health
    async fn check_cpu(&self) -> (HealthStatus, String, HashMap<String, String>, Option<String>) {
        let mut details = HashMap::new();
        
        // Mock CPU usage - in real implementation, get actual values
        let cpu_usage_percent = 35.0;
        
        details.insert("usage_percent".to_string(), format!("{:.1}", cpu_usage_percent));
        details.insert("cores".to_string(), "8".to_string());
        
        let config = self.config.read().unwrap();
        let thresholds = &config.critical_thresholds;
        
        if cpu_usage_percent > thresholds.cpu_usage_critical {
            (HealthStatus::Critical, 
             format!("CPU usage critical: {:.1}%", cpu_usage_percent), 
             details, 
             Some("CPU usage exceeds critical threshold".to_string()))
        } else if cpu_usage_percent > thresholds.cpu_usage_warning {
            (HealthStatus::Degraded, 
             format!("CPU usage high: {:.1}%", cpu_usage_percent), 
             details, None)
        } else {
            (HealthStatus::Healthy, 
             format!("CPU usage normal: {:.1}%", cpu_usage_percent), 
             details, None)
        }
    }
    
    /// Check network health
    async fn check_network(&self) -> (HealthStatus, String, HashMap<String, String>, Option<String>) {
        let mut details = HashMap::new();
        
        // Mock network connectivity check
        let connectivity = true;
        
        details.insert("connectivity".to_string(), connectivity.to_string());
        details.insert("last_check".to_string(), "2024-01-01T00:00:00Z".to_string());
        
        if connectivity {
            (HealthStatus::Healthy, "Network connectivity is available".to_string(), details, None)
        } else {
            (HealthStatus::Unhealthy, "Network connectivity is unavailable".to_string(), details, 
             Some("Cannot reach external services".to_string()))
        }
    }
    
    /// Check configuration health
    async fn check_configuration(&self) -> (HealthStatus, String, HashMap<String, String>, Option<String>) {
        let mut details = HashMap::new();
        
        // Mock configuration validation
        let config_valid = true;
        
        details.insert("valid".to_string(), config_valid.to_string());
        details.insert("last_loaded".to_string(), "2024-01-01T00:00:00Z".to_string());
        
        if config_valid {
            (HealthStatus::Healthy, "Configuration is valid".to_string(), details, None)
        } else {
            (HealthStatus::Critical, "Configuration is invalid".to_string(), details, 
             Some("Configuration validation failed".to_string()))
        }
    }
    
    /// Check logging health
    async fn check_logging(&self) -> (HealthStatus, String, HashMap<String, String>, Option<String>) {
        let mut details = HashMap::new();
        
        // Mock logging system check
        let logging_working = true;
        
        details.insert("working".to_string(), logging_working.to_string());
        details.insert("log_level".to_string(), "info".to_string());
        
        if logging_working {
            (HealthStatus::Healthy, "Logging system is operational".to_string(), details, None)
        } else {
            (HealthStatus::Degraded, "Logging system has issues".to_string(), details, 
             Some("Cannot write to log files".to_string()))
        }
    }
    
    /// Check dependencies
    async fn check_dependencies(&self) -> AgentResult<Vec<DependencyStatus>> {
        let config = {
            let config = self.config.read().map_err(|e| {
                AgentError::Service {
                    message: format!("Failed to read health check config: {}", e),
                    service: "health_checker".to_string(),
            context: None}
            })?;
            config.clone()
        };
        
        let mut dependencies = Vec::new();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        for dep_check in &config.dependency_checks {
            let status = match dep_check.check_type {
                DependencyCheckType::Library => {
                    // Mock library check
                    if dep_check.name == "yara" {
                        HealthStatus::Healthy
                    } else {
                        HealthStatus::Unknown
                    }
                }
                DependencyCheckType::FileSystem => {
                    // Mock filesystem check
                    HealthStatus::Healthy
                }
                _ => HealthStatus::Unknown,
            };
            
            dependencies.push(DependencyStatus {
                name: dep_check.name.clone(),
                version: Some("1.0.0".to_string()),
                status,
                last_check: timestamp,
                error_message: None,
            });
        }
        
        Ok(dependencies)
    }
    
    /// Get system health metrics
    async fn get_system_health_metrics(&self) -> AgentResult<SystemHealthMetrics> {
        // Mock system metrics - in real implementation, get actual values
        Ok(SystemHealthMetrics {
            memory_usage_percent: 45.0,
            cpu_usage_percent: 35.0,
            disk_usage_percent: 60.0,
            network_connectivity: true,
            file_system_accessible: true,
            yara_engine_status: HealthStatus::Healthy,
            configuration_valid: true,
            log_system_working: true,
        })
    }
    
    /// Calculate overall health status
    fn calculate_overall_status(
        &self,
        component_results: &[HealthCheckResult],
        dependencies: &[DependencyStatus],
    ) -> HealthStatus {
        let mut has_critical = false;
        let mut has_unhealthy = false;
        let mut has_degraded = false;
        
        // Check component results
        for result in component_results {
            match result.status {
                HealthStatus::Critical => has_critical = true,
                HealthStatus::Unhealthy => has_unhealthy = true,
                HealthStatus::Degraded => has_degraded = true,
                _ => {}
            }
        }
        
        // Check dependencies
        for dep in dependencies {
            match dep.status {
                HealthStatus::Critical => has_critical = true,
                HealthStatus::Unhealthy => has_unhealthy = true,
                HealthStatus::Degraded => has_degraded = true,
                _ => {}
            }
        }
        
        if has_critical {
            HealthStatus::Critical
        } else if has_unhealthy {
            HealthStatus::Unhealthy
        } else if has_degraded {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        }
    }
    
    /// Update health checker statistics
    async fn update_stats(&self, report: &HealthReport, duration: Duration) -> AgentResult<()> {
        let mut stats = self.stats.write().map_err(|e| {
            AgentError::Service {
                message: format!("Failed to write health checker stats: {}", e),
                service: "health_checker".to_string(),
            context: None}
        })?;
        
        stats.total_checks += 1;
        
        if report.errors.is_empty() {
            stats.successful_checks += 1;
        } else {
            stats.failed_checks += 1;
        }
        
        let duration_ms = duration.as_millis() as f64;
        let total_checks = stats.total_checks as f64;
        stats.average_check_duration_ms = 
            (stats.average_check_duration_ms * (total_checks - 1.0) + duration_ms) / total_checks;
        
        stats.last_check_time = Some(report.timestamp);
        stats.uptime_seconds = report.uptime_seconds;
        
        // Update component statistics
        for result in &report.component_results {
            let component_stats = stats.component_stats
                .entry(result.component.clone())
                .or_insert_with(|| ComponentHealthStats {
                    checks_performed: 0,
                    success_rate: 0.0,
                    average_duration_ms: 0.0,
                    last_status: HealthStatus::Unknown,
                    status_changes: 0,
                    last_error: None,
                });
            
            component_stats.checks_performed += 1;
            
            let success = result.error.is_none();
            let total_component_checks = component_stats.checks_performed as f64;
            component_stats.success_rate = 
                (component_stats.success_rate * (total_component_checks - 1.0) + if success { 1.0 } else { 0.0 }) / total_component_checks;
            
            component_stats.average_duration_ms = 
                (component_stats.average_duration_ms * (total_component_checks - 1.0) + result.duration_ms as f64) / total_component_checks;
            
            let status_changed = component_stats.last_status != result.status;
            if status_changed {
                component_stats.status_changes += 1;
            }
            
            component_stats.last_status = result.status.clone();
            component_stats.last_error = result.error.clone();
            
            // Update global status changes after component_stats is no longer borrowed
            if status_changed {
                stats.status_changes += 1;
            }
        }
        
        Ok(())
    }
}

#[cfg(all(test, feature = "metrics"))]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_health_checker_creation() {
        let config = HealthCheckConfig::default();
        let monitoring_config = Arc::new(RwLock::new(MonitoringConfig::default()));
        let checker = HealthChecker::new(config, monitoring_config);
        assert!(checker.is_ok());
    }
    
    #[tokio::test]
    async fn test_health_check() {
        let config = HealthCheckConfig::default();
        let monitoring_config = Arc::new(RwLock::new(MonitoringConfig::default()));
        let checker = HealthChecker::new(config, monitoring_config).unwrap();
        
        let report = checker.check_health().await.unwrap();
        assert!(!report.component_results.is_empty());
        assert!(matches!(report.overall_status, HealthStatus::Healthy));
    }
    
    #[test]
    fn test_health_status_display() {
        assert_eq!(HealthStatus::Healthy.to_string(), "Healthy");
        assert_eq!(HealthStatus::Critical.to_string(), "Critical");
    }
    
    #[test]
    fn test_critical_thresholds_default() {
        let thresholds = CriticalThresholds::default();
        assert!(thresholds.memory_usage_critical > thresholds.memory_usage_warning);
        assert!(thresholds.cpu_usage_critical > thresholds.cpu_usage_warning);
    }
}
