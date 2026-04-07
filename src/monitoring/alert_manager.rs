//! Alert Manager Component
//!
//! This module provides comprehensive alert management for the YARA agent,
//! including alert generation, notification delivery, escalation, and lifecycle management.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use tokio::time::interval;
use tracing::{debug, error, info, warn};

use crate::error::{AgentError, AgentResult};
use super::health_checker::{HealthReport, HealthStatus};
use super::MonitoringConfig;

/// Alert severity levels
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AlertSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

impl std::fmt::Display for AlertSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertSeverity::Info => write!(f, "Info"),
            AlertSeverity::Warning => write!(f, "Warning"),
            AlertSeverity::Error => write!(f, "Error"),
            AlertSeverity::Critical => write!(f, "Critical"),
        }
    }
}

/// Alert status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlertStatus {
    Active,
    Acknowledged,
    Resolved,
    Suppressed,
    Escalated,
}

impl std::fmt::Display for AlertStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertStatus::Active => write!(f, "Active"),
            AlertStatus::Acknowledged => write!(f, "Acknowledged"),
            AlertStatus::Resolved => write!(f, "Resolved"),
            AlertStatus::Suppressed => write!(f, "Suppressed"),
            AlertStatus::Escalated => write!(f, "Escalated"),
        }
    }
}

/// Alert categories
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AlertCategory {
    System,
    Performance,
    Security,
    Configuration,
    Network,
    Storage,
    Application,
}

/// Alert information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: AlertSeverity,
    pub status: AlertStatus,
    pub category: AlertCategory,
    pub source: String,
    pub created_at: u64,
    pub updated_at: u64,
    pub resolved_at: Option<u64>,
    pub acknowledged_at: Option<u64>,
    pub acknowledged_by: Option<String>,
    pub tags: HashMap<String, String>,
    pub metadata: HashMap<String, String>,
    pub escalation_level: u32,
    pub notification_count: u32,
    pub last_notification: Option<u64>,
}

impl Alert {
    /// Create a new alert
    pub fn new(
        title: String,
        description: String,
        severity: AlertSeverity,
        category: AlertCategory,
        source: String,
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            title,
            description,
            severity,
            status: AlertStatus::Active,
            category,
            source,
            created_at: timestamp,
            updated_at: timestamp,
            resolved_at: None,
            acknowledged_at: None,
            acknowledged_by: None,
            tags: HashMap::new(),
            metadata: HashMap::new(),
            escalation_level: 0,
            notification_count: 0,
            last_notification: None,
        }
    }
    
    /// Add a tag to the alert
    pub fn add_tag(&mut self, key: String, value: String) {
        self.tags.insert(key, value);
        self.update_timestamp();
    }
    
    /// Add metadata to the alert
    pub fn add_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
        self.update_timestamp();
    }
    
    /// Acknowledge the alert
    pub fn acknowledge(&mut self, acknowledged_by: String) {
        self.status = AlertStatus::Acknowledged;
        self.acknowledged_at = Some(SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs());
        self.acknowledged_by = Some(acknowledged_by);
        self.update_timestamp();
    }
    
    /// Resolve the alert
    pub fn resolve(&mut self) {
        self.status = AlertStatus::Resolved;
        self.resolved_at = Some(SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs());
        self.update_timestamp();
    }
    
    /// Escalate the alert
    pub fn escalate(&mut self) {
        self.escalation_level += 1;
        self.status = AlertStatus::Escalated;
        self.update_timestamp();
    }
    
    /// Suppress the alert
    pub fn suppress(&mut self) {
        self.status = AlertStatus::Suppressed;
        self.update_timestamp();
    }
    
    /// Record notification sent
    pub fn record_notification(&mut self) {
        self.notification_count += 1;
        self.last_notification = Some(SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs());
        self.update_timestamp();
    }
    
    /// Update the timestamp
    fn update_timestamp(&mut self) {
        self.updated_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    }
    
    /// Check if alert is active
    pub fn is_active(&self) -> bool {
        matches!(self.status, AlertStatus::Active | AlertStatus::Escalated)
    }
    
    /// Get alert age in seconds
    pub fn age_seconds(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .saturating_sub(self.created_at)
    }
}

/// Alert rule for automatic alert generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub condition: AlertCondition,
    pub severity: AlertSeverity,
    pub category: AlertCategory,
    pub cooldown_seconds: u64,
    pub last_triggered: Option<u64>,
    pub trigger_count: u64,
}

/// Alert condition for rule evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertCondition {
    MemoryUsageAbove(f64),
    CpuUsageAbove(f64),
    DiskUsageAbove(f64),
    ErrorRateAbove(f64),
    ResponseTimeAbove(u64),
    HealthStatusEquals(HealthStatus),
    ComponentDown(String),
    Custom(String), // Custom condition expression
}

/// Notification channel configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationChannel {
    pub id: String,
    pub name: String,
    pub channel_type: NotificationChannelType,
    pub enabled: bool,
    pub config: HashMap<String, String>,
    pub severity_filter: Vec<AlertSeverity>,
    pub category_filter: Vec<AlertCategory>,
    pub rate_limit_seconds: u64,
    pub last_notification: Option<u64>,
}

/// Notification channel types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NotificationChannelType {
    Email,
    Slack,
    Webhook,
    Log,
    Console,
    Sms,
    PagerDuty,
}

/// Alert manager configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertManagerConfig {
    pub enabled: bool,
    pub max_alerts: usize,
    pub alert_retention_hours: u64,
    pub escalation_timeout_minutes: u64,
    pub notification_retry_attempts: u32,
    pub notification_retry_delay_seconds: u64,
    pub auto_resolve_timeout_hours: u64,
    pub duplicate_detection_window_minutes: u64,
    pub rules: Vec<AlertRule>,
    pub channels: Vec<NotificationChannel>,
}

impl Default for AlertManagerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_alerts: 1000,
            alert_retention_hours: 24 * 7, // 7 days
            escalation_timeout_minutes: 30,
            notification_retry_attempts: 3,
            notification_retry_delay_seconds: 60,
            auto_resolve_timeout_hours: 24,
            duplicate_detection_window_minutes: 5,
            rules: vec![
                AlertRule {
                    id: "high_memory_usage".to_string(),
                    name: "High Memory Usage".to_string(),
                    description: "Memory usage exceeds threshold".to_string(),
                    enabled: true,
                    condition: AlertCondition::MemoryUsageAbove(85.0),
                    severity: AlertSeverity::Warning,
                    category: AlertCategory::Performance,
                    cooldown_seconds: 300, // 5 minutes
                    last_triggered: None,
                    trigger_count: 0,
                },
                AlertRule {
                    id: "critical_memory_usage".to_string(),
                    name: "Critical Memory Usage".to_string(),
                    description: "Memory usage critically high".to_string(),
                    enabled: true,
                    condition: AlertCondition::MemoryUsageAbove(95.0),
                    severity: AlertSeverity::Critical,
                    category: AlertCategory::Performance,
                    cooldown_seconds: 60, // 1 minute
                    last_triggered: None,
                    trigger_count: 0,
                },
            ],
            channels: vec![
                NotificationChannel {
                    id: "console".to_string(),
                    name: "Console Output".to_string(),
                    channel_type: NotificationChannelType::Console,
                    enabled: true,
                    config: HashMap::new(),
                    severity_filter: vec![
                        AlertSeverity::Warning,
                        AlertSeverity::Error,
                        AlertSeverity::Critical,
                    ],
                    category_filter: vec![], // All categories
                    rate_limit_seconds: 30,
                    last_notification: None,
                },
                NotificationChannel {
                    id: "log".to_string(),
                    name: "Log File".to_string(),
                    channel_type: NotificationChannelType::Log,
                    enabled: true,
                    config: HashMap::new(),
                    severity_filter: vec![], // All severities
                    category_filter: vec![], // All categories
                    rate_limit_seconds: 0, // No rate limit for logs
                    last_notification: None,
                },
            ],
        }
    }
}

/// Alert manager statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertManagerStats {
    pub total_alerts: u64,
    pub active_alerts: u64,
    pub resolved_alerts: u64,
    pub acknowledged_alerts: u64,
    pub suppressed_alerts: u64,
    pub escalated_alerts: u64,
    pub notifications_sent: u64,
    pub notification_failures: u64,
    pub rules_triggered: u64,
    pub average_resolution_time_seconds: f64,
    pub alert_rate_per_hour: f64,
    pub severity_distribution: HashMap<AlertSeverity, u64>,
    pub category_distribution: HashMap<AlertCategory, u64>,
}

/// Alert manager implementation
#[derive(Debug)]
pub struct AlertManager {
    config: Arc<RwLock<AlertManagerConfig>>,
    alerts: Arc<RwLock<HashMap<String, Alert>>>,
    alert_history: Arc<RwLock<VecDeque<Alert>>>,
    stats: Arc<RwLock<AlertManagerStats>>,
    running: Arc<RwLock<bool>>,
    start_time: Instant,
}

impl AlertManager {
    /// Create a new alert manager
    pub fn new(_monitoring_config: Arc<RwLock<MonitoringConfig>>) -> AgentResult<Self> {
        let config = AlertManagerConfig::default();
        Ok(Self {
            config: Arc::new(RwLock::new(config)),
            alerts: Arc::new(RwLock::new(HashMap::new())),
            alert_history: Arc::new(RwLock::new(VecDeque::new())),
            stats: Arc::new(RwLock::new(AlertManagerStats {
                total_alerts: 0,
                active_alerts: 0,
                resolved_alerts: 0,
                acknowledged_alerts: 0,
                suppressed_alerts: 0,
                escalated_alerts: 0,
                notifications_sent: 0,
                notification_failures: 0,
                rules_triggered: 0,
                average_resolution_time_seconds: 0.0,
                alert_rate_per_hour: 0.0,
                severity_distribution: HashMap::new(),
                category_distribution: HashMap::new(),
            })),
            running: Arc::new(RwLock::new(false)),
            start_time: Instant::now(),
        })
    }
    
    /// Start the alert manager
    pub async fn start(&self) -> AgentResult<()> {
        info!("Starting alert manager");
        
        {
            let mut running = self.running.write().map_err(|e| {
                AgentError::Service {
                    message: format!("Failed to acquire running lock: {}", e),
                    service: "alert_manager".to_string(),
                    context: None
                }
            })?;
            
            if *running {
                return Err(AgentError::Service { 
                    message: "Alert manager is already running".to_string(), 
                    service: "alert_manager".to_string(),
                    context: None 
                });
            }
            
            *running = true;
        }
        
        // Start alert processing loop
        self.start_alert_processing_loop().await?;
        
        info!("Alert manager started successfully");
        Ok(())
    }
    
    /// Stop the alert manager
    pub async fn stop(&self) -> AgentResult<()> {
        info!("Stopping alert manager");
        
        {
            let mut running = self.running.write().map_err(|e| {
                AgentError::Service {
                    message: format!("Failed to acquire running lock: {}", e),
                    service: "alert_manager".to_string(),
                    context: None
                }
            })?;
            
            if !*running {
                return Ok(());
            }
            
            *running = false;
        }
        
        info!("Alert manager stopped successfully");
        Ok(())
    }
    
    /// Create a new alert
    pub async fn create_alert(
        &self,
        title: String,
        description: String,
        severity: AlertSeverity,
        category: AlertCategory,
        source: String,
    ) -> AgentResult<String> {
        let config = {
            let config = self.config.read().map_err(|e| {
                AgentError::Service { 
                    message: format!("Failed to read alert manager config: {}", e),
                    service: "alert_manager".to_string(),
                    context: None,
                }
            })?;
            config.clone()
        };
        
        if !config.enabled {
            return Err(AgentError::Service { 
                message: "Alert manager is disabled".to_string(), 
                service: "alert_manager".to_string(),
                context: None 
            });
        }
        
        // Check for duplicates
        if self.is_duplicate_alert(&title, &source, config.duplicate_detection_window_minutes).await? {
            debug!("Duplicate alert detected, skipping: {}", title);
            return Err(AgentError::Service { 
                message: "Duplicate alert detected".to_string(), 
                service: "alert_manager".to_string(),
                context: None 
            });
        }
        
        let alert = Alert::new(title, description, severity.clone(), category.clone(), source);
        let alert_id = alert.id.clone();
        
        // Add to alerts collection
        {
            let mut alerts = self.alerts.write().map_err(|e| {
                AgentError::Service { 
                    message: format!("Failed to write alerts: {}", e),
                    service: "alert_manager".to_string(),
                    context: None
                }
            })?;
            
            // Check max alerts limit
            if alerts.len() >= config.max_alerts {
                self.cleanup_old_alerts().await?;
            }
            
            alerts.insert(alert_id.clone(), alert.clone());
        }
        
        // Update statistics
        self.update_alert_stats(&alert, "created").await?;
        
        // Send notifications
        self.send_notifications(&alert).await?;
        
        info!("Alert created: {} ({})", alert.title, alert.id);
        Ok(alert_id)
    }
    
    /// Acknowledge an alert
    pub async fn acknowledge_alert(&self, alert_id: &str, acknowledged_by: String) -> AgentResult<()> {
        let mut alerts = self.alerts.write().map_err(|e| {
            AgentError::Service { 
                message: format!("Failed to write alerts: {}", e),
                service: "alert_manager".to_string(),
                    context: None
                }
        })?;
        
        let alert_clone = if let Some(alert) = alerts.get_mut(alert_id) {
            alert.acknowledge(acknowledged_by);
            let cloned = alert.clone();
            info!("Alert acknowledged: {} ({})", alert.title, alert.id);
            Some(cloned)
        } else {
            None
        };
        
        // Drop the lock before async operation
        drop(alerts);
        
        if let Some(alert) = alert_clone {
            self.update_alert_stats(&alert, "acknowledged").await?;
            Ok(())
        } else {
            Err(AgentError::Service {
                message: format!("Alert not found: {}", alert_id),
                service: "alert_manager".to_string(),
                    context: None
                })
        }
    }
    
    /// Resolve an alert
    pub async fn resolve_alert(&self, alert_id: &str) -> AgentResult<()> {
        let mut alerts = self.alerts.write().map_err(|e| {
            AgentError::Service {
                message: format!("Failed to write alerts: {}", e),
                service: "alert_manager".to_string(),
                    context: None
                }
        })?;
        
        let alert_clone = if let Some(alert) = alerts.get_mut(alert_id) {
            alert.resolve();
            let cloned = alert.clone();
            
            // Move to history
            {
                let mut history = self.alert_history.write().map_err(|e| {
                    AgentError::Service {
                        message: format!("Failed to write alert history: {}", e),
                        service: "alert_manager".to_string(),
                    context: None
                }
                })?;
                history.push_back(cloned.clone());
            }
            
            info!("Alert resolved: {} ({})", alert.title, alert.id);
            Some(cloned)
        } else {
            None
        };
        
        // Drop the lock before async operation
        drop(alerts);
        
        if let Some(alert) = alert_clone {
            self.update_alert_stats(&alert, "resolved").await?;
            Ok(())
        } else {
            Err(AgentError::Service {
                message: format!("Alert not found: {}", alert_id),
                service: "alert_manager".to_string(),
                    context: None
                })
        }
    }
    
    /// Get all active alerts
    pub fn get_active_alerts(&self) -> AgentResult<Vec<Alert>> {
        let alerts = self.alerts.read().map_err(|e| {
            AgentError::Service {
                message: format!("Failed to read alerts: {}", e),
                service: "alert_manager".to_string(),
                context: None
            }
        })?;
        
        Ok(alerts.values()
            .filter(|alert| alert.is_active())
            .cloned()
            .collect())
    }
    
    /// Get alerts by severity
    pub fn get_alerts_by_severity(&self, severity: AlertSeverity) -> AgentResult<Vec<Alert>> {
        let alerts = self.alerts.read().map_err(|e| {
            AgentError::Service {
                message: format!("Failed to read alerts: {}", e),
                service: "alert_manager".to_string(),
                context: None
            }
        })?;
        
        Ok(alerts.values()
            .filter(|alert| alert.severity == severity)
            .cloned()
            .collect())
    }
    
    /// Get alert by ID
    pub fn get_alert(&self, alert_id: &str) -> AgentResult<Option<Alert>> {
        let alerts = self.alerts.read().map_err(|e| {
            AgentError::Service {
                message: format!("Failed to read alerts: {}", e),
                service: "alert_manager".to_string(),
                context: None
            }
        })?;
        
        Ok(alerts.get(alert_id).cloned())
    }
    
    /// Get alert manager statistics
    pub fn get_stats(&self) -> AgentResult<AlertManagerStats> {
        let stats = self.stats.read().map_err(|e| {
            AgentError::Service {
                message: format!("Failed to read alert manager stats: {}", e),
                service: "alert_manager".to_string(),
                context: None
            }
        })?;
        
        Ok(stats.clone())
    }
    
    /// Reset alert manager statistics
    pub fn reset_stats(&self) -> AgentResult<()> {
        let mut stats = self.stats.write().map_err(|e| {
            AgentError::Service { 
                message: format!("Failed to write alert manager stats: {}", e),
                service: "alert_manager".to_string(),
                context: None
            }
        })?;
        
        *stats = AlertManagerStats {
            total_alerts: 0,
            active_alerts: 0,
            resolved_alerts: 0,
            acknowledged_alerts: 0,
            suppressed_alerts: 0,
            escalated_alerts: 0,
            notifications_sent: 0,
            notification_failures: 0,
            rules_triggered: 0,
            average_resolution_time_seconds: 0.0,
            alert_rate_per_hour: 0.0,
            severity_distribution: HashMap::new(),
            category_distribution: HashMap::new(),
        };
        
        info!("Alert manager statistics reset");
        Ok(())
    }
    
    /// Check if alert manager is running
    pub fn is_running(&self) -> AgentResult<bool> {
        let running = self.running.read().map_err(|e| {
            AgentError::Service {
                message: format!("Failed to read running status: {}", e),
                service: "alert_manager".to_string(),
                context: None
            }
        })?;
        
        Ok(*running)
    }
    
    /// Update alert manager configuration
    pub fn update_config(&self, new_config: AlertManagerConfig) -> AgentResult<()> {
        let mut config = self.config.write().map_err(|e| {
            AgentError::Service {
                message: format!("Failed to write alert manager config: {}", e),
                service: "alert_manager".to_string(),
                context: None
            }
        })?;
        
        *config = new_config;
        info!("Alert manager configuration updated");
        Ok(())
    }
    
    /// Evaluate alert rules against health report
    pub async fn evaluate_rules(&self, health_report: &HealthReport) -> AgentResult<()> {
        let config = {
            let config = self.config.read().map_err(|e| {
                AgentError::Service { 
                message: format!("Failed to read alert manager config: {}", e),
                service: "alert_manager".to_string(),
                    context: None
                }
            })?;
            config.clone()
        };
        
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        for rule in &config.rules {
            if !rule.enabled {
                continue;
            }
            
            // Check cooldown
            if let Some(last_triggered) = rule.last_triggered {
                if current_time - last_triggered < rule.cooldown_seconds {
                    continue;
                }
            }
            
            // Evaluate condition
            let triggered = self.evaluate_condition(&rule.condition, health_report).await?;
            
            if triggered {
                // Create alert
                let title = format!("Rule triggered: {}", rule.name);
                let description = format!("{}: {}", rule.description, self.format_condition_details(&rule.condition, health_report));
                
                match self.create_alert(
                    title,
                    description,
                    rule.severity.clone(),
                    rule.category.clone(),
                    format!("rule:{}", rule.id),
                ).await {
                    Ok(_) => {
                        info!("Alert rule triggered: {}", rule.name);
                        self.update_rule_stats(&rule.id).await?;
                    }
                    Err(e) => {
                        warn!("Failed to create alert for rule {}: {}", rule.name, e);
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// Start alert processing loop
    async fn start_alert_processing_loop(&self) -> AgentResult<()> {
        let config = Arc::clone(&self.config);
        let alerts = Arc::clone(&self.alerts);
        let _alert_history = Arc::clone(&self.alert_history);
        let stats = Arc::clone(&self.stats);
        let running = Arc::clone(&self.running);
        let start_time = self.start_time;
        
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(60)); // Check every minute
            
            loop {
                interval.tick().await;
                
                // Check if still running
                let is_running = {
                    match running.read() {
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
                
                // Process escalations inline to avoid Send issues
                if let Err(e) = Self::process_escalations_static(
                    Arc::clone(&config),
                    Arc::clone(&alerts),
                    Arc::clone(&stats),
                    start_time,
                ).await {
                    error!("Failed to process escalations: {}", e);
                }
                
                // Cleanup old alerts inline
                if let Err(e) = Self::cleanup_old_alerts_static(
                    Arc::clone(&config),
                    Arc::clone(&alerts),
                ).await {
                    error!("Failed to cleanup old alerts: {}", e);
                }
                
                // Auto-resolve old alerts inline
                if let Err(e) = Self::auto_resolve_alerts_static(
                    Arc::clone(&config),
                    Arc::clone(&alerts),
                    Arc::clone(&stats),
                    start_time,
                ).await {
                    error!("Failed to auto-resolve alerts: {}", e);
                }
            }
            
            debug!("Alert manager processing loop stopped");
        });
        
        Ok(())
    }
    
    /// Check for duplicate alerts
    async fn is_duplicate_alert(&self, title: &str, source: &str, window_minutes: u64) -> AgentResult<bool> {
        let alerts = self.alerts.read().map_err(|e| {
            AgentError::Service {
                message: format!("Failed to read alerts: {}", e),
                service: "alert_manager".to_string(),
                    context: None
                }
        })?;
        
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let window_seconds = window_minutes * 60;
        
        for alert in alerts.values() {
            if alert.title == title && 
               alert.source == source && 
               alert.is_active() &&
               current_time - alert.created_at < window_seconds {
                return Ok(true);
            }
        }
        
        Ok(false)
    }
    
    /// Send notifications for an alert
    async fn send_notifications(&self, alert: &Alert) -> AgentResult<()> {
        let config = {
            let config = self.config.read().map_err(|e| {
                AgentError::Service {
                    message: format!("Failed to read alert manager config: {}", e),
                    service: "alert_manager".to_string(),
                    context: None
                }
            })?;
            config.clone()
        };
        
        for channel in &config.channels {
            if !channel.enabled {
                continue;
            }
            
            // Check severity filter
            if !channel.severity_filter.is_empty() && 
               !channel.severity_filter.contains(&alert.severity) {
                continue;
            }
            
            // Check category filter
            if !channel.category_filter.is_empty() && 
               !channel.category_filter.contains(&alert.category) {
                continue;
            }
            
            // Check rate limit
            if let Some(last_notification) = channel.last_notification {
                let current_time = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                
                if current_time - last_notification < channel.rate_limit_seconds {
                    continue;
                }
            }
            
            // Send notification
            match self.send_notification_to_channel(alert, channel).await {
                Ok(_) => {
                    debug!("Notification sent to channel: {}", channel.name);
                    self.update_notification_stats(true).await?;
                }
                Err(e) => {
                    warn!("Failed to send notification to channel {}: {}", channel.name, e);
                    self.update_notification_stats(false).await?;
                }
            }
        }
        
        Ok(())
    }
    
    /// Send notification to a specific channel
    async fn send_notification_to_channel(
        &self,
        alert: &Alert,
        channel: &NotificationChannel,
    ) -> AgentResult<()> {
        match channel.channel_type {
            NotificationChannelType::Console => {
                println!("[ALERT] {} - {} - {}", alert.severity, alert.title, alert.description);
            }
            NotificationChannelType::Log => {
                match alert.severity {
                    AlertSeverity::Info => info!("[ALERT] {} - {}", alert.title, alert.description),
                    AlertSeverity::Warning => warn!("[ALERT] {} - {}", alert.title, alert.description),
                    AlertSeverity::Error => error!("[ALERT] {} - {}", alert.title, alert.description),
                    AlertSeverity::Critical => error!("[CRITICAL ALERT] {} - {}", alert.title, alert.description),
                }
            }
            _ => {
                // Other notification types would be implemented here
                debug!("Notification type {:?} not implemented", channel.channel_type);
            }
        }
        
        Ok(())
    }
    
    /// Evaluate alert condition
    async fn evaluate_condition(
        &self,
        condition: &AlertCondition,
        health_report: &HealthReport,
    ) -> AgentResult<bool> {
        match condition {
            AlertCondition::MemoryUsageAbove(threshold) => {
                // Extract memory usage from system metrics
                Ok(health_report.system_metrics.memory_usage_percent > *threshold)
            }
            AlertCondition::CpuUsageAbove(threshold) => {
                // Extract CPU usage from system metrics
                Ok(health_report.system_metrics.cpu_usage_percent > *threshold)
            }
            AlertCondition::DiskUsageAbove(threshold) => {
                // Extract disk usage from system metrics
                Ok(health_report.system_metrics.disk_usage_percent > *threshold)
            }
            AlertCondition::HealthStatusEquals(status) => {
                Ok(health_report.overall_status == *status)
            }
            AlertCondition::ComponentDown(component) => {
                // Check if the specific component is in critical state
                Ok(health_report.component_results.iter()
                    .find(|result| result.component == *component)
                    .map(|result| matches!(result.status, HealthStatus::Critical | HealthStatus::Unhealthy))
                    .unwrap_or(false))
            }
            _ => {
                // Other conditions would be implemented here
                Ok(false)
            }
        }
    }
    
    /// Format condition details for alert description
    fn format_condition_details(&self, condition: &AlertCondition, health_report: &HealthReport) -> String {
        match condition {
            AlertCondition::MemoryUsageAbove(threshold) => {
                format!("Memory usage: {:.1}% (threshold: {:.1}%)", 
                       health_report.system_metrics.memory_usage_percent, threshold)
            }
            AlertCondition::CpuUsageAbove(threshold) => {
                format!("CPU usage: {:.1}% (threshold: {:.1}%)", 
                       health_report.system_metrics.cpu_usage_percent, threshold)
            }
            AlertCondition::DiskUsageAbove(threshold) => {
                format!("Disk usage: {:.1}% (threshold: {:.1}%)", 
                       health_report.system_metrics.disk_usage_percent, threshold)
            }
            AlertCondition::HealthStatusEquals(status) => {
                format!("Health status: {:?} (expected: {:?})", health_report.overall_status, status)
            }
            AlertCondition::ComponentDown(component) => {
                format!("Component {} is down", component)
            }
            _ => "Condition details not available".to_string(),
        }
    }
    
    /// Process alert escalations
    async fn process_escalations(&self) -> AgentResult<()> {
        let config = {
            let config = self.config.read().map_err(|e| {
                AgentError::Service { 
                    message: format!("Failed to read alert manager config: {}", e),
                    service: "alert_manager".to_string(),
                    context: None
                }
            })?;
            config.clone()
        };
        
        let mut alerts = self.alerts.write().map_err(|e| {
            AgentError::Service { 
                message: format!("Failed to write alerts: {}", e),
                service: "alert_manager".to_string(),
                    context: None
                }
        })?;
        
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let escalation_timeout_seconds = config.escalation_timeout_minutes * 60;
        let mut escalated_alerts = Vec::new();
        
        for alert in alerts.values_mut() {
            if alert.is_active() && 
               alert.status != AlertStatus::Escalated &&
               current_time - alert.created_at > escalation_timeout_seconds {
                alert.escalate();
                info!("Alert escalated: {} ({})", alert.title, alert.id);
                escalated_alerts.push(alert.clone());
            }
        }
        
        // Drop the lock before async operations
        drop(alerts);
        
        // Update stats for escalated alerts
        for alert in escalated_alerts {
            self.update_alert_stats(&alert, "escalated").await?;
        }
        
        Ok(())
    }
    
    /// Cleanup old alerts
    async fn cleanup_old_alerts(&self) -> AgentResult<()> {
        let config = {
            let config = self.config.read().map_err(|e| {
                AgentError::Service { 
                    message: format!("Failed to read alert manager config: {}", e),
                    service: "alert_manager".to_string(),
                    context: None
                }
            })?;
            config.clone()
        };
        
        let mut alerts = self.alerts.write().map_err(|e| {
            AgentError::Service { 
                message: format!("Failed to write alerts: {}", e),
                service: "alert_manager".to_string(),
                    context: None
                }
        })?;
        
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let retention_seconds = config.alert_retention_hours * 3600u64;
        
        alerts.retain(|_, alert| {
            current_time - alert.created_at < retention_seconds
        });
        
        Ok(())
    }
    
    /// Auto-resolve old alerts
    async fn auto_resolve_alerts(&self) -> AgentResult<()> {
        let config = {
            let config = self.config.read().map_err(|e| {
                AgentError::Service {
                    message: format!("Failed to read alert manager config: {}", e),
                    service: "alert_manager".to_string(),
                    context: None
                }
            })?;
            config.clone()
        };
        
        let mut alerts = self.alerts.write().map_err(|e| {
            AgentError::Service {
                message: format!("Failed to write alerts: {}", e),
                service: "alert_manager".to_string(),
                    context: None
                }
        })?;
        
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let auto_resolve_seconds = config.auto_resolve_timeout_hours * 3600u64;
        let mut resolved_alerts = Vec::new();
        
        for alert in alerts.values_mut() {
            if alert.is_active() && 
               current_time - alert.created_at > auto_resolve_seconds {
                alert.resolve();
                info!("Alert auto-resolved: {} ({})", alert.title, alert.id);
                resolved_alerts.push(alert.clone());
            }
        }
        
        // Drop the lock before async operations
        drop(alerts);
        
        // Update stats for resolved alerts
        for alert in resolved_alerts {
            self.update_alert_stats(&alert, "resolved").await?;
        }
        
        Ok(())
    }
    
    /// Update alert statistics
    async fn update_alert_stats(&self, alert: &Alert, action: &str) -> AgentResult<()> {
        let mut stats = self.stats.write().map_err(|e| {
            AgentError::Service { 
                message: format!("Failed to write alert manager stats: {}", e),
                service: "alert_manager".to_string(),
                    context: None
                }
        })?;
        
        match action {
            "created" => {
                stats.total_alerts += 1;
                stats.active_alerts += 1;
                
                *stats.severity_distribution.entry(alert.severity.clone()).or_insert(0) += 1;
                *stats.category_distribution.entry(alert.category.clone()).or_insert(0) += 1;
            }
            "acknowledged" => {
                stats.acknowledged_alerts += 1;
                if stats.active_alerts > 0 {
                    stats.active_alerts -= 1;
                }
            }
            "resolved" => {
                stats.resolved_alerts += 1;
                if stats.active_alerts > 0 {
                    stats.active_alerts -= 1;
                }
                
                // Update average resolution time
                if let Some(resolved_at) = alert.resolved_at {
                    let resolution_time = resolved_at - alert.created_at;
                    let total_resolved = stats.resolved_alerts as f64;
                    stats.average_resolution_time_seconds = 
                        (stats.average_resolution_time_seconds * (total_resolved - 1.0) + resolution_time as f64) / total_resolved;
                }
            }
            "escalated" => {
                stats.escalated_alerts += 1;
            }
            _ => {}
        }
        
        // Update alert rate
        let uptime_hours = self.start_time.elapsed().as_secs() as f64 / 3600.0;
        if uptime_hours > 0.0 {
            stats.alert_rate_per_hour = stats.total_alerts as f64 / uptime_hours;
        }
        
        Ok(())
    }
    
    /// Update notification statistics
    async fn update_notification_stats(&self, success: bool) -> AgentResult<()> {
        let mut stats = self.stats.write().map_err(|e| {
            AgentError::Service { 
                message: format!("Failed to write alert manager stats: {}", e),
                service: "alert_manager".to_string(),
                    context: None
                }
        })?;
        
        if success {
            stats.notifications_sent += 1;
        } else {
            stats.notification_failures += 1;
        }
        
        Ok(())
    }
    
    /// Update rule statistics
    async fn update_rule_stats(&self, _rule_id: &str) -> AgentResult<()> {
        let mut stats = self.stats.write().map_err(|e| {
            AgentError::Service { 
                message: format!("Failed to write alert manager stats: {}", e),
                service: "alert_manager".to_string(),
                    context: None
                }
        })?;
        
        stats.rules_triggered += 1;
        
        Ok(())
    }
    
    /// Static version of process_escalations for use in spawned tasks
    async fn process_escalations_static(
        config: Arc<RwLock<AlertManagerConfig>>,
        alerts: Arc<RwLock<HashMap<String, Alert>>>,
        stats: Arc<RwLock<AlertManagerStats>>,
        start_time: Instant,
    ) -> AgentResult<()> {
        let config = {
            let config = config.read().map_err(|e| {
                AgentError::Service { 
                    message: format!("Failed to read alert manager config: {}", e),
                    service: "alert_manager".to_string(),
                    context: None
                }
            })?;
            config.clone()
        };
        
        let mut alerts_guard = alerts.write().map_err(|e| {
            AgentError::Service { 
                message: format!("Failed to write alerts: {}", e),
                service: "alert_manager".to_string(),
                    context: None
                }
        })?;
        
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let escalation_timeout_seconds = config.escalation_timeout_minutes * 60;
        let mut escalated_alerts = Vec::new();
        
        for alert in alerts_guard.values_mut() {
            if alert.is_active() && 
               alert.status != AlertStatus::Escalated &&
               current_time - alert.created_at > escalation_timeout_seconds {
                alert.escalate();
                info!("Alert escalated: {} ({})", alert.title, alert.id);
                escalated_alerts.push(alert.clone());
            }
        }
        
        // Drop the lock before async operations
        drop(alerts_guard);
        
        // Update stats for escalated alerts
        for alert in escalated_alerts {
            Self::update_alert_stats_static(&stats, &alert, "escalated", start_time)?;
        }
        
        Ok(())
    }
    
    /// Static version of cleanup_old_alerts for use in spawned tasks
    async fn cleanup_old_alerts_static(
        config: Arc<RwLock<AlertManagerConfig>>,
        alerts: Arc<RwLock<HashMap<String, Alert>>>,
    ) -> AgentResult<()> {
        let config = {
            let config = config.read().map_err(|e| {
                AgentError::Service { 
                    message: format!("Failed to read alert manager config: {}", e),
                    service: "alert_manager".to_string(),
                    context: None
                }
            })?;
            config.clone()
        };
        
        let mut alerts_guard = alerts.write().map_err(|e| {
            AgentError::Service { 
                message: format!("Failed to write alerts: {}", e),
                service: "alert_manager".to_string(),
                    context: None
                }
        })?;
        
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let retention_seconds = config.alert_retention_hours * 3600;
        
        alerts_guard.retain(|_, alert| {
            current_time - alert.created_at < retention_seconds
        });
        
        Ok(())
    }
    
    /// Static version of auto_resolve_alerts for use in spawned tasks
    async fn auto_resolve_alerts_static(
        config: Arc<RwLock<AlertManagerConfig>>,
        alerts: Arc<RwLock<HashMap<String, Alert>>>,
        stats: Arc<RwLock<AlertManagerStats>>,
        start_time: Instant,
    ) -> AgentResult<()> {
        let config = {
            let config = config.read().map_err(|e| {
                AgentError::Service {
                    message: format!("Failed to read alert manager config: {}", e),
                    service: "alert_manager".to_string(),
                    context: None
                }
            })?;
            config.clone()
        };
        
        let mut alerts_guard = alerts.write().map_err(|e| {
            AgentError::Service {
                message: format!("Failed to write alerts: {}", e),
                service: "alert_manager".to_string(),
                    context: None
                }
        })?;
        
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let auto_resolve_seconds = config.auto_resolve_timeout_hours * 3600;
        let mut resolved_alerts = Vec::new();
        
        for alert in alerts_guard.values_mut() {
            if alert.is_active() && 
               current_time - alert.created_at > auto_resolve_seconds {
                alert.resolve();
                info!("Alert auto-resolved: {} ({})", alert.title, alert.id);
                resolved_alerts.push(alert.clone());
            }
        }
        
        // Drop the lock before async operations
        drop(alerts_guard);
        
        // Update stats for resolved alerts
        for alert in resolved_alerts {
            Self::update_alert_stats_static(&stats, &alert, "resolved", start_time)?;
        }
        
        Ok(())
    }
    
    /// Static version of update_alert_stats for use in spawned tasks
    fn update_alert_stats_static(
        stats: &Arc<RwLock<AlertManagerStats>>,
        alert: &Alert,
        action: &str,
        start_time: Instant,
    ) -> AgentResult<()> {
        let mut stats_guard = stats.write().map_err(|e| {
            AgentError::Service { 
                message: format!("Failed to write alert manager stats: {}", e),
                service: "alert_manager".to_string(),
                context: None
            }
        })?;
        
        match action {
            "created" => {
                stats_guard.total_alerts += 1;
                stats_guard.active_alerts += 1;
                
                *stats_guard.severity_distribution.entry(alert.severity.clone()).or_insert(0) += 1;
                *stats_guard.category_distribution.entry(alert.category.clone()).or_insert(0) += 1;
            }
            "acknowledged" => {
                stats_guard.acknowledged_alerts += 1;
                if stats_guard.active_alerts > 0 {
                    stats_guard.active_alerts -= 1;
                }
            }
            "resolved" => {
                stats_guard.resolved_alerts += 1;
                if stats_guard.active_alerts > 0 {
                    stats_guard.active_alerts -= 1;
                }
                
                // Update average resolution time
                if let Some(resolved_at) = alert.resolved_at {
                    let resolution_time = resolved_at - alert.created_at;
                    let total_resolved = stats_guard.resolved_alerts as f64;
                    stats_guard.average_resolution_time_seconds = 
                        (stats_guard.average_resolution_time_seconds * (total_resolved - 1.0) + resolution_time as f64) / total_resolved;
                }
            }
            "escalated" => {
                stats_guard.escalated_alerts += 1;
            }
            _ => {}
        }
        
        // Update alert rate
        let uptime_hours = start_time.elapsed().as_secs() as f64 / 3600.0;
        if uptime_hours > 0.0 {
            stats_guard.alert_rate_per_hour = stats_guard.total_alerts as f64 / uptime_hours;
        }
        
        Ok(())
    }
}

#[cfg(all(test, feature = "metrics"))]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_alert_manager_creation() {
        let monitoring_config = Arc::new(RwLock::new(MonitoringConfig::default()));
        let manager = AlertManager::new(monitoring_config);
        assert!(manager.is_ok());
    }
    
    #[tokio::test]
    async fn test_alert_creation() {
        let monitoring_config = Arc::new(RwLock::new(MonitoringConfig::default()));
        let manager = AlertManager::new(monitoring_config).unwrap();
        
        let alert_id = manager.create_alert(
            "Test Alert".to_string(),
            "Test Description".to_string(),
            AlertSeverity::Warning,
            AlertCategory::System,
            "test".to_string(),
        ).await.unwrap();
        
        assert!(!alert_id.is_empty());
        
        let alert = manager.get_alert(&alert_id).unwrap();
        assert!(alert.is_some());
        assert_eq!(alert.unwrap().title, "Test Alert");
    }
    
    #[test]
    fn test_alert_severity_ordering() {
        assert!(AlertSeverity::Critical > AlertSeverity::Error);
        assert!(AlertSeverity::Error > AlertSeverity::Warning);
        assert!(AlertSeverity::Warning > AlertSeverity::Info);
    }
    
    #[test]
    fn test_alert_lifecycle() {
        let mut alert = Alert::new(
            "Test".to_string(),
            "Description".to_string(),
            AlertSeverity::Warning,
            AlertCategory::System,
            "test".to_string(),
        );
        
        assert_eq!(alert.status, AlertStatus::Active);
        assert!(alert.is_active());
        
        alert.acknowledge("user".to_string());
        assert_eq!(alert.status, AlertStatus::Acknowledged);
        assert!(!alert.is_active());
        
        alert.resolve();
        assert_eq!(alert.status, AlertStatus::Resolved);
        assert!(!alert.is_active());
    }
}
