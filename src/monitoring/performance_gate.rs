//! Performance Gate Component
//!
//! This module provides performance gate enforcement with configurable
//! CPU and memory thresholds to ensure system stability during operations.

use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

use crate::error::{AgentError, AgentResult};
use super::PerformanceMonitor;

/// Performance gate configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceGateConfig {
    /// Maximum CPU usage percentage (0.0 to 100.0)
    pub max_cpu_percent: f64,
    /// Maximum memory usage in bytes
    pub max_memory_bytes: u64,
    /// Maximum memory usage percentage (0.0 to 100.0)
    pub max_memory_percent: f64,
    /// Duration to wait before checking thresholds again
    pub check_interval: Duration,
    /// Number of consecutive violations before taking action
    pub violation_threshold: u32,
    /// Enable automatic throttling when thresholds are exceeded
    pub enable_auto_throttling: bool,
    /// Throttling delay when limits are exceeded
    pub throttling_delay: Duration,
}

impl Default for PerformanceGateConfig {
    fn default() -> Self {
        Self {
            max_cpu_percent: 6.0,  // 6% CPU threshold
            max_memory_bytes: 350 * 1024 * 1024,  // 350MB memory threshold
            max_memory_percent: 80.0,
            check_interval: Duration::from_secs(1),
            violation_threshold: 3,
            enable_auto_throttling: true,
            throttling_delay: Duration::from_millis(100),
        }
    }
}

/// Performance gate violation details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceViolation {
    pub timestamp: u64,
    pub violation_type: ViolationType,
    pub current_value: f64,
    pub threshold_value: f64,
    pub severity: ViolationSeverity,
    pub action_taken: Option<String>,
}

/// Types of performance violations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ViolationType {
    CpuUsage,
    MemoryBytes,
    MemoryPercent,
}

/// Severity levels for violations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ViolationSeverity {
    Warning,
    Critical,
    Emergency,
}

/// Performance gate statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceGateStats {
    pub total_checks: u64,
    pub total_violations: u64,
    pub cpu_violations: u64,
    pub memory_violations: u64,
    pub throttling_events: u64,
    pub last_violation: Option<PerformanceViolation>,
    pub consecutive_violations: u32,
    pub uptime_seconds: u64,
}

/// Performance gate implementation
#[derive(Debug)]
pub struct PerformanceGate {
    config: Arc<RwLock<PerformanceGateConfig>>,
    performance_monitor: Arc<PerformanceMonitor>,
    stats: Arc<RwLock<PerformanceGateStats>>,
    running: Arc<RwLock<bool>>,
    start_time: Instant,
    violation_history: Arc<RwLock<Vec<PerformanceViolation>>>,
}

impl PerformanceGate {
    /// Create a new performance gate
    pub fn new(
        config: PerformanceGateConfig,
        performance_monitor: Arc<PerformanceMonitor>,
    ) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            performance_monitor,
            stats: Arc::new(RwLock::new(PerformanceGateStats {
                total_checks: 0,
                total_violations: 0,
                cpu_violations: 0,
                memory_violations: 0,
                throttling_events: 0,
                last_violation: None,
                consecutive_violations: 0,
                uptime_seconds: 0,
            })),
            running: Arc::new(RwLock::new(false)),
            start_time: Instant::now(),
            violation_history: Arc::new(RwLock::new(Vec::new())),
        }
    }
    
    /// Start the performance gate monitoring
    pub async fn start(&self) -> AgentResult<()> {
        info!("Starting performance gate monitoring");
        
        {
            let mut running = self.running.write().map_err(|e| {
                AgentError::Service {
                    message: format!("Failed to acquire running lock: {}", e),
                    service: "performance_gate".to_string(),
            context: None}
            })?;
            
            if *running {
                return Err(AgentError::Service { message: "Performance gate is already running".to_string(), service: "performance_gate".to_string(), context: None });
            }
            
            *running = true;
        }
        
        // Start monitoring loop
        let gate = Arc::new(self.clone());
        tokio::spawn(async move {
            if let Err(e) = gate.monitoring_loop().await {
                error!("Performance gate monitoring loop failed: {}", e);
            }
        });
        
        info!("Performance gate monitoring started successfully");
        Ok(())
    }
    
    /// Stop the performance gate monitoring
    pub async fn stop(&self) -> AgentResult<()> {
        info!("Stopping performance gate monitoring");
        
        {
            let mut running = self.running.write().map_err(|e| {
                AgentError::Service {
                    message: format!("Failed to acquire running lock: {}", e),
                    service: "performance_gate".to_string(),
            context: None}
            })?;
            
            if !*running {
                return Ok(());
            }
            
            *running = false;
        }
        
        info!("Performance gate monitoring stopped successfully");
        Ok(())
    }
    
    /// Check if performance thresholds are met
    pub async fn check_thresholds(&self) -> AgentResult<bool> {
        let metrics = self.performance_monitor.get_current_metrics().await?;
        let config = self.get_config()?;
        
        let mut violations = Vec::new();
        
        // Check CPU usage
        if metrics.cpu_usage_percent > config.max_cpu_percent {
            violations.push(PerformanceViolation {
                timestamp: metrics.timestamp,
                violation_type: ViolationType::CpuUsage,
                current_value: metrics.cpu_usage_percent,
                threshold_value: config.max_cpu_percent,
                severity: self.determine_severity(metrics.cpu_usage_percent, config.max_cpu_percent),
                action_taken: None,
            });
        }
        
        // Check memory usage (bytes)
        if metrics.memory_usage_bytes > config.max_memory_bytes {
            violations.push(PerformanceViolation {
                timestamp: metrics.timestamp,
                violation_type: ViolationType::MemoryBytes,
                current_value: metrics.memory_usage_bytes as f64,
                threshold_value: config.max_memory_bytes as f64,
                severity: self.determine_severity(
                    metrics.memory_usage_bytes as f64,
                    config.max_memory_bytes as f64
                ),
                action_taken: None,
            });
        }
        
        // Check memory usage (percentage)
        if metrics.memory_usage_percent > config.max_memory_percent {
            violations.push(PerformanceViolation {
                timestamp: metrics.timestamp,
                violation_type: ViolationType::MemoryPercent,
                current_value: metrics.memory_usage_percent,
                threshold_value: config.max_memory_percent,
                severity: self.determine_severity(metrics.memory_usage_percent, config.max_memory_percent),
                action_taken: None,
            });
        }
        
        // Update statistics and handle violations
        self.update_stats(&violations).await?;
        
        if !violations.is_empty() {
            self.handle_violations(violations).await?;
            return Ok(false);
        }
        
        // Reset consecutive violations if no violations found
        {
            let mut stats = self.stats.write().map_err(|e| {
                AgentError::Service {
                    message: format!("Failed to write stats: {}", e),
                    service: "performance_gate".to_string(),
            context: None}
            })?;
            stats.consecutive_violations = 0;
        }
        
        Ok(true)
    }
    
    /// Enforce performance gate (blocks if thresholds exceeded)
    pub async fn enforce(&self) -> AgentResult<()> {
        let config = self.get_config()?;
        
        loop {
            if self.check_thresholds().await? {
                break;
            }
            
            if config.enable_auto_throttling {
                debug!("Performance thresholds exceeded, throttling for {:?}", config.throttling_delay);
                sleep(config.throttling_delay).await;
                
                // Update throttling stats
                {
                    let mut stats = self.stats.write().map_err(|e| {
                        AgentError::Service {
                            message: format!("Failed to write stats: {}", e),
                            service: "performance_gate".to_string(),
            context: None}
                    })?;
                    stats.throttling_events += 1;
                }
            } else {
                return Err(AgentError::Service { message: "Performance thresholds exceeded and auto-throttling is disabled".to_string(), service: "performance_gate".to_string(), context: None });
            }
        }
        
        Ok(())
    }
    
    /// Get current performance gate statistics
    pub fn get_stats(&self) -> AgentResult<PerformanceGateStats> {
        let mut stats = self.stats.read().map_err(|e| {
            AgentError::Service {
                message: format!("Failed to read stats: {}", e),
                service: "performance_gate".to_string(),
            context: None}
        })?.clone();
        
        stats.uptime_seconds = self.start_time.elapsed().as_secs();
        Ok(stats)
    }
    
    /// Get violation history
    pub fn get_violation_history(&self) -> AgentResult<Vec<PerformanceViolation>> {
        let history = self.violation_history.read().map_err(|e| {
            AgentError::Service {
                message: format!("Failed to read violation history: {}", e),
                service: "performance_gate".to_string(),
            context: None}
        })?;
        
        Ok(history.clone())
    }
    
    /// Update configuration
    pub fn update_config(&self, new_config: PerformanceGateConfig) -> AgentResult<()> {
        let mut config = self.config.write().map_err(|e| {
            AgentError::Service {
                message: format!("Failed to write config: {}", e),
                service: "performance_gate".to_string(),
            context: None}
        })?;
        
        *config = new_config;
        info!("Performance gate configuration updated");
        Ok(())
    }
    
    /// Get current configuration
    fn get_config(&self) -> AgentResult<PerformanceGateConfig> {
        let config = self.config.read().map_err(|e| {
            AgentError::Service {
                message: format!("Failed to read config: {}", e),
                service: "performance_gate".to_string(),
            context: None}
        })?;
        
        Ok(config.clone())
    }
    
    /// Main monitoring loop
    async fn monitoring_loop(&self) -> AgentResult<()> {
        let config = self.get_config()?;
        let mut interval = tokio::time::interval(config.check_interval);
        
        while self.is_running()? {
            interval.tick().await;
            
            if let Err(e) = self.check_thresholds().await {
                error!("Failed to check performance thresholds: {}", e);
            }
            
            // Update uptime in stats
            {
                let mut stats = self.stats.write().map_err(|e| {
                    AgentError::Service {
                        message: format!("Failed to write stats: {}", e),
                        service: "performance_gate".to_string(),
            context: None}
                })?;
                stats.uptime_seconds = self.start_time.elapsed().as_secs();
                stats.total_checks += 1;
            }
        }
        
        Ok(())
    }
    
    /// Check if monitoring is running
    fn is_running(&self) -> AgentResult<bool> {
        let running = self.running.read().map_err(|e| {
            AgentError::Service {
                message: format!("Failed to read running status: {}", e),
                service: "performance_gate".to_string(),
            context: None}
        })?;
        
        Ok(*running)
    }
    
    /// Update statistics with violations
    async fn update_stats(&self, violations: &[PerformanceViolation]) -> AgentResult<()> {
        let mut stats = self.stats.write().map_err(|e| {
            AgentError::Service {
                message: format!("Failed to write stats: {}", e),
                service: "performance_gate".to_string(),
            context: None}
        })?;
        
        if violations.is_empty() {
            stats.consecutive_violations = 0;
        } else {
            stats.total_violations += violations.len() as u64;
            stats.consecutive_violations += 1;
            
            for violation in violations {
                match violation.violation_type {
                    ViolationType::CpuUsage => stats.cpu_violations += 1,
                    ViolationType::MemoryBytes | ViolationType::MemoryPercent => {
                        stats.memory_violations += 1;
                    }
                }
                
                stats.last_violation = Some(violation.clone());
            }
        }
        
        Ok(())
    }
    
    /// Handle performance violations
    async fn handle_violations(&self, mut violations: Vec<PerformanceViolation>) -> AgentResult<()> {
        let config = self.get_config()?;
        
        for violation in &mut violations {
            let action = match violation.severity {
                ViolationSeverity::Warning => {
                    warn!("Performance warning: {:?} = {:.2} exceeds threshold {:.2}",
                          violation.violation_type, violation.current_value, violation.threshold_value);
                    "logged_warning"
                }
                ViolationSeverity::Critical => {
                    error!("Performance critical: {:?} = {:.2} exceeds threshold {:.2}",
                           violation.violation_type, violation.current_value, violation.threshold_value);
                    "logged_critical"
                }
                ViolationSeverity::Emergency => {
                    error!("Performance emergency: {:?} = {:.2} exceeds threshold {:.2}",
                           violation.violation_type, violation.current_value, violation.threshold_value);
                    "logged_emergency"
                }
            };
            
            violation.action_taken = Some(action.to_string());
        }
        
        // Store violations in history
        {
            let mut history = self.violation_history.write().map_err(|e| {
                AgentError::Service {
                    message: format!("Failed to write violation history: {}", e),
                    service: "performance_gate".to_string(),
            context: None}
            })?;
            
            history.extend(violations);
            
            // Keep only recent violations (last 1000)
            if history.len() > 1000 {
                let excess = history.len() - 1000;
                history.drain(0..excess);
            }
        }
        
        // Check if we need to take more drastic action
        let stats = self.get_stats()?;
        if stats.consecutive_violations >= config.violation_threshold {
            warn!("Performance gate: {} consecutive violations detected, consider system intervention",
                  stats.consecutive_violations);
        }
        
        Ok(())
    }
    
    /// Determine violation severity based on how much the threshold is exceeded
    fn determine_severity(&self, current: f64, threshold: f64) -> ViolationSeverity {
        let ratio = current / threshold;
        
        if ratio >= 2.0 {
            ViolationSeverity::Emergency
        } else if ratio >= 1.5 {
            ViolationSeverity::Critical
        } else {
            ViolationSeverity::Warning
        }
    }
}

impl Clone for PerformanceGate {
    fn clone(&self) -> Self {
        Self {
            config: Arc::clone(&self.config),
            performance_monitor: Arc::clone(&self.performance_monitor),
            stats: Arc::clone(&self.stats),
            running: Arc::clone(&self.running),
            start_time: self.start_time,
            violation_history: Arc::clone(&self.violation_history),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, RwLock};
    use crate::monitoring::{MonitoringConfig, PerformanceMonitor};
    
    fn create_test_performance_gate() -> PerformanceGate {
        let config = Arc::new(RwLock::new(MonitoringConfig::default()));
        let monitor = Arc::new(PerformanceMonitor::new(config).unwrap());
        
        let gate_config = PerformanceGateConfig {
            max_cpu_percent: 6.0,
            max_memory_bytes: 350 * 1024 * 1024,
            max_memory_percent: 80.0,
            check_interval: Duration::from_millis(100),
            violation_threshold: 2,
            enable_auto_throttling: true,
            throttling_delay: Duration::from_millis(50),
        };
        
        PerformanceGate::new(gate_config, monitor)
    }
    
    #[test]
    fn test_performance_gate_creation() {
        let gate = create_test_performance_gate();
        let stats = gate.get_stats().unwrap();
        
        assert_eq!(stats.total_checks, 0);
        assert_eq!(stats.total_violations, 0);
        assert_eq!(stats.consecutive_violations, 0);
    }
    
    #[test]
    fn test_config_update() {
        let gate = create_test_performance_gate();
        
        let new_config = PerformanceGateConfig {
            max_cpu_percent: 10.0,
            max_memory_bytes: 500 * 1024 * 1024,
            ..Default::default()
        };
        
        gate.update_config(new_config.clone()).unwrap();
        let updated_config = gate.get_config().unwrap();
        
        assert_eq!(updated_config.max_cpu_percent, 10.0);
        assert_eq!(updated_config.max_memory_bytes, 500 * 1024 * 1024);
    }
    
    #[test]
    fn test_violation_severity_determination() {
        let gate = create_test_performance_gate();
        
        // Warning level (1.0 < ratio < 1.5)
        let severity = gate.determine_severity(7.0, 5.0);
        matches!(severity, ViolationSeverity::Warning);
        
        // Critical level (1.5 <= ratio < 2.0)
        let severity = gate.determine_severity(8.0, 5.0);
        matches!(severity, ViolationSeverity::Critical);
        
        // Emergency level (ratio >= 2.0)
        let severity = gate.determine_severity(12.0, 5.0);
        matches!(severity, ViolationSeverity::Emergency);
    }
}
