//! Alerting Module
//! Provides comprehensive alerting capabilities for security events and system health

use crate::core::{
    error::Result,
    // Removed unused types import
};
use crate::observability::health_checks::HealthStatus;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::{
    sync::{mpsc, RwLock},
    // Removed unused timeout import
};
use tracing::{error, info, warn};
use uuid::Uuid;


/// Alert severity levels
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AlertSeverity {
    /// Critical alert requiring immediate attention
    Critical,
    /// High priority alert
    High,
    /// Medium priority alert
    Medium,
    /// Low priority alert
    Low,
    /// Warning alert
    Warning,
    /// Informational alert
    Info,
}

impl std::fmt::Display for AlertSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertSeverity::Critical => write!(f, "CRITICAL"),
            AlertSeverity::High => write!(f, "HIGH"),
            AlertSeverity::Medium => write!(f, "MEDIUM"),
            AlertSeverity::Low => write!(f, "LOW"),
            AlertSeverity::Warning => write!(f, "WARNING"),
            AlertSeverity::Info => write!(f, "INFO"),
        }
    }
}

/// Alert categories
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AlertCategory {
    /// Security-related alerts
    Security,
    /// System health alerts
    Health,
    /// Performance alerts
    Performance,
    /// Configuration alerts
    Configuration,
    /// Network alerts
    Network,
    /// Storage alerts
    Storage,
    /// Application alerts
    Application,
}

/// Alert status
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AlertStatus {
    /// Alert is active
    Active,
    /// Alert has been acknowledged
    Acknowledged,
    /// Alert has been resolved
    Resolved,
    /// Alert has been suppressed
    Suppressed,
}

/// Escalation level for alerts
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum EscalationLevel {
    /// No escalation
    None,
    /// Level 1 escalation
    Level1,
    /// Level 2 escalation
    Level2,
    /// Level 3 escalation
    Level3,
    /// Maximum escalation
    Maximum,
}

/// Alert configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertConfig {
    /// Enable alerting
    pub enabled: bool,
    /// Alert channels configuration
    pub channels: Vec<AlertChannel>,
    /// Alert rules
    pub rules: Vec<AlertRule>,
    /// Rate limiting configuration
    pub rate_limiting: RateLimitConfig,
    /// Escalation configuration
    pub escalation: EscalationConfig,
    /// Notification templates
    pub templates: HashMap<String, NotificationTemplate>,
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            channels: vec![
                AlertChannel {
                    name: "email".to_string(),
                    channel_type: AlertChannelType::Email,
                    enabled: true,
                    config: HashMap::new(),
                },
                AlertChannel {
                    name: "webhook".to_string(),
                    channel_type: AlertChannelType::Webhook,
                    enabled: true,
                    config: HashMap::new(),
                },
            ],
            rules: vec![
                AlertRule {
                    name: "critical_component_down".to_string(),
                    condition: AlertCondition::ComponentHealth {
                        component: "*".to_string(),
                        status: HealthStatus::Unhealthy,
                        critical_only: true,
                    },
                    severity: AlertSeverity::Critical,
                    category: AlertCategory::Health,
                    enabled: true,
                    cooldown: Duration::from_secs(300),
                },
                AlertRule {
                    name: "high_threat_detection_rate".to_string(),
                    condition: AlertCondition::MetricThreshold {
                        metric: "threats_detected_per_minute".to_string(),
                        threshold: 10.0,
                        operator: ThresholdOperator::GreaterThan,
                    },
                    severity: AlertSeverity::High,
                    category: AlertCategory::Security,
                    enabled: true,
                    cooldown: Duration::from_secs(60),
                },
            ],
            rate_limiting: RateLimitConfig::default(),
            escalation: EscalationConfig::default(),
            templates: HashMap::new(),
        }
    }
}

/// Alert channel configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertChannel {
    /// Channel name
    pub name: String,
    /// Channel type
    pub channel_type: AlertChannelType,
    /// Whether channel is enabled
    pub enabled: bool,
    /// Channel-specific configuration
    pub config: HashMap<String, String>,
}

/// Alert channel types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertChannelType {
    /// Email notifications
    Email,
    /// Webhook notifications
    Webhook,
    /// Slack notifications
    Slack,
    /// SMS notifications
    Sms,
    /// PagerDuty integration
    PagerDuty,
    /// Custom notification handler
    Custom(String),
}

/// Alert rule configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    /// Rule name
    pub name: String,
    /// Alert condition
    pub condition: AlertCondition,
    /// Alert severity
    pub severity: AlertSeverity,
    /// Alert category
    pub category: AlertCategory,
    /// Whether rule is enabled
    pub enabled: bool,
    /// Cooldown period between alerts
    pub cooldown: Duration,
}

/// Alert conditions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertCondition {
    /// Component health condition
    ComponentHealth {
        component: String,
        status: HealthStatus,
        critical_only: bool,
    },
    /// Metric threshold condition
    MetricThreshold {
        metric: String,
        threshold: f64,
        operator: ThresholdOperator,
    },
    /// Event pattern condition
    EventPattern {
        pattern: String,
        count: u32,
        window: Duration,
    },
    /// Custom condition
    Custom(String),
}

/// Threshold operators
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThresholdOperator {
    GreaterThan,
    GreaterThanOrEqual,
    LessThan,
    LessThanOrEqual,
    Equal,
    NotEqual,
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum alerts per minute
    pub max_alerts_per_minute: u32,
    /// Maximum alerts per hour
    pub max_alerts_per_hour: u32,
    /// Burst allowance
    pub burst_allowance: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_alerts_per_minute: 10,
            max_alerts_per_hour: 100,
            burst_allowance: 5,
        }
    }
}

/// Escalation step configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationStep {
    /// Delay before escalation
    pub delay: Duration,
    /// Notification channels for this level
    pub channels: Vec<String>,
}

/// Escalation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationConfig {
    /// Enable escalation
    pub enabled: bool,
    /// Escalation levels
    pub levels: Vec<EscalationStep>,
}

impl Default for EscalationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            levels: vec![
                EscalationStep {
                    delay: Duration::from_secs(300),
                    channels: vec!["email".to_string()],
                },
                EscalationStep {
                    delay: Duration::from_secs(900),
                    channels: vec!["webhook".to_string(), "email".to_string()],
                },
            ],
        }
    }
}

/// Notification template
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationTemplate {
    /// Template name
    pub name: String,
    /// Subject template
    pub subject: String,
    /// Body template
    pub body: String,
    /// Template variables
    pub variables: HashMap<String, String>,
}

/// Alert information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    /// Alert ID
    pub id: String,
    /// Alert name
    pub name: String,
    /// Alert description
    pub description: String,
    /// Alert severity
    pub severity: AlertSeverity,
    /// Alert category
    pub category: AlertCategory,
    /// Alert status
    pub status: AlertStatus,
    /// Alert source
    pub source: String,
    /// Alert timestamp
    pub timestamp: chrono::DateTime<Utc>,
    /// Alert metadata
    pub metadata: HashMap<String, String>,
    /// Alert tags
    pub tags: Vec<String>,
    /// Acknowledgment information
    pub acknowledgment: Option<AlertAcknowledgment>,
    /// Resolution information
    pub resolution: Option<AlertResolution>,
}

/// Alert acknowledgment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertAcknowledgment {
    /// Acknowledged by
    pub acknowledged_by: String,
    /// Acknowledgment timestamp
    pub timestamp: chrono::DateTime<Utc>,
    /// Acknowledgment notes
    pub notes: Option<String>,
}

/// Alert resolution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertResolution {
    /// Resolved by
    pub resolved_by: String,
    /// Resolution timestamp
    pub timestamp: chrono::DateTime<Utc>,
    /// Resolution notes
    pub notes: Option<String>,
    /// Resolution action taken
    pub action: Option<String>,
}

/// Alert statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertStatistics {
    /// Total alerts generated
    pub total_alerts: u64,
    /// Active alerts
    pub active_alerts: u64,
    /// Acknowledged alerts
    pub acknowledged_alerts: u64,
    /// Resolved alerts
    pub resolved_alerts: u64,
    /// Alerts by severity
    pub alerts_by_severity: HashMap<String, u64>,
    /// Alerts by category
    pub alerts_by_category: HashMap<String, u64>,
    /// Average resolution time
    pub avg_resolution_time_minutes: f64,
    /// Alert rate (per hour)
    pub alert_rate_per_hour: f64,
}

/// Alert manager
pub struct AlertManager {
    /// Configuration
    config: Arc<RwLock<AlertConfig>>,

    /// Active alerts
    active_alerts: Arc<RwLock<HashMap<String, Alert>>>,

    /// Alert history
    alert_history: Arc<RwLock<Vec<Alert>>>,

    /// Alert statistics
    statistics: Arc<RwLock<AlertStatistics>>,

    /// Alert sender channel
    alert_sender: mpsc::UnboundedSender<Alert>,

    /// Alert receiver channel
    alert_receiver: Arc<RwLock<Option<mpsc::UnboundedReceiver<Alert>>>>,

    /// Rate limiter
    rate_limiter: Arc<RwLock<RateLimiter>>,
}

/// Rate limiter for alerts
#[derive(Debug)]
struct RateLimiter {
    /// Alert timestamps for rate limiting
    alert_timestamps: Vec<chrono::DateTime<Utc>>,
    /// Configuration
    config: RateLimitConfig,
}

impl RateLimiter {
    fn new(config: RateLimitConfig) -> Self {
        Self {
            alert_timestamps: Vec::new(),
            config,
        }
    }

    fn can_send_alert(&mut self) -> bool {
        let now = Utc::now();

        // Clean old timestamps
        self.alert_timestamps
            .retain(|&timestamp| now.signed_duration_since(timestamp).num_minutes() < 60);

        // Check rate limits
        let recent_count = self
            .alert_timestamps
            .iter()
            .filter(|&&timestamp| now.signed_duration_since(timestamp).num_minutes() < 1)
            .count() as u32;

        if recent_count >= self.config.max_alerts_per_minute {
            return false;
        }

        let hourly_count = self.alert_timestamps.len() as u32;
        if hourly_count >= self.config.max_alerts_per_hour {
            return false;
        }

        // Record this alert
        self.alert_timestamps.push(now);
        true
    }
}

impl AlertManager {
    /// Create a new alert manager
    pub fn new(config: AlertConfig) -> Self {
        let (alert_sender, alert_receiver) = mpsc::unbounded_channel();

        Self {
            config: Arc::new(RwLock::new(config.clone())),
            active_alerts: Arc::new(RwLock::new(HashMap::new())),
            alert_history: Arc::new(RwLock::new(Vec::new())),
            statistics: Arc::new(RwLock::new(AlertStatistics {
                total_alerts: 0,
                active_alerts: 0,
                acknowledged_alerts: 0,
                resolved_alerts: 0,
                alerts_by_severity: HashMap::new(),
                alerts_by_category: HashMap::new(),
                avg_resolution_time_minutes: 0.0,
                alert_rate_per_hour: 0.0,
            })),
            alert_sender,
            alert_receiver: Arc::new(RwLock::new(Some(alert_receiver))),
            rate_limiter: Arc::new(RwLock::new(RateLimiter::new(config.rate_limiting))),
        }
    }

    /// Initialize the alert manager
    pub async fn initialize(&self) -> Result<()> {
        info!("Initializing alert manager");

        // Start alert processing task
        self.start_alert_processor().await?;

        info!("Alert manager initialized successfully");
        Ok(())
    }

    /// Start alert processing task
    async fn start_alert_processor(&self) -> Result<()> {
        let mut receiver = self.alert_receiver.write().await.take().ok_or_else(|| {
            crate::core::error::EnhancedAgentError::Configuration(
                "Alert receiver already taken".to_string(),
            )
        })?;

        let config = Arc::clone(&self.config);
        let active_alerts = Arc::clone(&self.active_alerts);
        let alert_history = Arc::clone(&self.alert_history);
        let statistics = Arc::clone(&self.statistics);
        let rate_limiter = Arc::clone(&self.rate_limiter);

        tokio::spawn(async move {
            while let Some(alert) = receiver.recv().await {
                if let Err(e) = Self::process_alert(
                    alert,
                    &config,
                    &active_alerts,
                    &alert_history,
                    &statistics,
                    &rate_limiter,
                )
                .await
                {
                    error!("Failed to process alert: {}", e);
                }
            }
        });

        Ok(())
    }

    /// Process an alert
    async fn process_alert(
        alert: Alert,
        config: &Arc<RwLock<AlertConfig>>,
        active_alerts: &Arc<RwLock<HashMap<String, Alert>>>,
        alert_history: &Arc<RwLock<Vec<Alert>>>,
        statistics: &Arc<RwLock<AlertStatistics>>,
        rate_limiter: &Arc<RwLock<RateLimiter>>,
    ) -> Result<()> {
        // Check rate limiting
        {
            let mut limiter = rate_limiter.write().await;
            if !limiter.can_send_alert() {
                warn!("Alert rate limit exceeded, dropping alert: {}", alert.name);
                return Ok(());
            }
        }

        // Add to active alerts
        {
            let mut alerts = active_alerts.write().await;
            alerts.insert(alert.id.clone(), alert.clone());
        }

        // Add to history
        {
            let mut history = alert_history.write().await;
            history.push(alert.clone());

            // Keep only last 1000 alerts in memory
            if history.len() > 1000 {
                history.remove(0);
            }
        }

        // Update statistics
        Self::update_statistics(&alert, statistics).await;

        // Send notifications
        let config_guard = config.read().await;
        if config_guard.enabled {
            Self::send_notifications(&alert, &config_guard).await?;
        }

        info!("Processed alert: {} ({})", alert.name, alert.severity);
        Ok(())
    }

    /// Update alert statistics
    async fn update_statistics(alert: &Alert, statistics: &Arc<RwLock<AlertStatistics>>) {
        let mut stats = statistics.write().await;

        stats.total_alerts += 1;

        match alert.status {
            AlertStatus::Active => stats.active_alerts += 1,
            AlertStatus::Acknowledged => stats.acknowledged_alerts += 1,
            AlertStatus::Resolved => stats.resolved_alerts += 1,
            AlertStatus::Suppressed => {}
        }

        // Update severity counts
        let severity_key = alert.severity.to_string();
        *stats.alerts_by_severity.entry(severity_key).or_insert(0) += 1;

        // Update category counts
        let category_key = format!("{:?}", alert.category);
        *stats.alerts_by_category.entry(category_key).or_insert(0) += 1;

        // Calculate alert rate (simplified)
        stats.alert_rate_per_hour = stats.total_alerts as f64;
    }

    /// Send notifications for an alert
    async fn send_notifications(alert: &Alert, config: &AlertConfig) -> Result<()> {
        for channel in &config.channels {
            if channel.enabled {
                if let Err(e) = Self::send_notification(alert, channel).await {
                    error!("Failed to send notification via {}: {}", channel.name, e);
                }
            }
        }
        Ok(())
    }

    /// Send notification via specific channel
    async fn send_notification(alert: &Alert, channel: &AlertChannel) -> Result<()> {
        match &channel.channel_type {
            AlertChannelType::Email => {
                info!("Sending email notification for alert: {}", alert.name);
                // Email notification implementation would go here
            }
            AlertChannelType::Webhook => {
                info!("Sending webhook notification for alert: {}", alert.name);
                // Webhook notification implementation would go here
            }
            AlertChannelType::Slack => {
                info!("Sending Slack notification for alert: {}", alert.name);
                // Slack notification implementation would go here
            }
            AlertChannelType::Sms => {
                info!("Sending SMS notification for alert: {}", alert.name);
                // SMS notification implementation would go here
            }
            AlertChannelType::PagerDuty => {
                info!("Sending PagerDuty notification for alert: {}", alert.name);
                // PagerDuty notification implementation would go here
            }
            AlertChannelType::Custom(handler) => {
                info!(
                    "Sending custom notification via {}: {}",
                    handler, alert.name
                );
                // Custom notification implementation would go here
            }
        }
        Ok(())
    }

    /// Send an alert
    pub async fn send_alert(&self, alert: Alert) -> Result<()> {
        self.alert_sender.send(alert).map_err(|e| {
            crate::core::error::EnhancedAgentError::Configuration(format!(
                "Failed to send alert: {}",
                e
            ))
        })?;
        Ok(())
    }

    /// Create a security alert
    pub async fn create_security_alert(
        &self,
        name: String,
        description: String,
        severity: AlertSeverity,
        source: String,
        metadata: HashMap<String, String>,
    ) -> Result<()> {
        let alert = Alert {
            id: Uuid::new_v4().to_string(),
            name,
            description,
            severity,
            category: AlertCategory::Security,
            status: AlertStatus::Active,
            source,
            timestamp: Utc::now(),
            metadata,
            tags: vec!["security".to_string()],
            acknowledgment: None,
            resolution: None,
        };

        self.send_alert(alert).await
    }

    /// Create a health alert
    pub async fn create_health_alert(
        &self,
        component: String,
        status: HealthStatus,
        description: String,
    ) -> Result<()> {
        let severity = match status {
            HealthStatus::Unhealthy => AlertSeverity::Critical,
            HealthStatus::Degraded => AlertSeverity::High,
            _ => AlertSeverity::Info,
        };

        let alert = Alert {
            id: Uuid::new_v4().to_string(),
            name: format!("Component Health: {}", component),
            description,
            severity,
            category: AlertCategory::Health,
            status: AlertStatus::Active,
            source: "HealthCheckManager".to_string(),
            timestamp: Utc::now(),
            metadata: HashMap::from([
                ("component".to_string(), component),
                ("health_status".to_string(), status.to_string()),
            ]),
            tags: vec!["health".to_string(), "component".to_string()],
            acknowledgment: None,
            resolution: None,
        };

        self.send_alert(alert).await
    }

    /// Acknowledge an alert
    pub async fn acknowledge_alert(
        &self,
        alert_id: &str,
        acknowledged_by: String,
        notes: Option<String>,
    ) -> Result<()> {
        let mut alerts = self.active_alerts.write().await;

        if let Some(alert) = alerts.get_mut(alert_id) {
            alert.status = AlertStatus::Acknowledged;
            alert.acknowledgment = Some(AlertAcknowledgment {
                acknowledged_by,
                timestamp: Utc::now(),
                notes,
            });

            info!("Alert acknowledged: {}", alert.name);
        }

        Ok(())
    }

    /// Resolve an alert
    pub async fn resolve_alert(
        &self,
        alert_id: &str,
        resolved_by: String,
        notes: Option<String>,
        action: Option<String>,
    ) -> Result<()> {
        let mut alerts = self.active_alerts.write().await;

        if let Some(alert) = alerts.get_mut(alert_id) {
            alert.status = AlertStatus::Resolved;
            alert.resolution = Some(AlertResolution {
                resolved_by,
                timestamp: Utc::now(),
                notes,
                action,
            });

            info!("Alert resolved: {}", alert.name);
        }

        Ok(())
    }

    /// Get active alerts
    pub async fn get_active_alerts(&self) -> Vec<Alert> {
        self.active_alerts.read().await.values().cloned().collect()
    }

    /// Get alert statistics
    pub async fn get_statistics(&self) -> AlertStatistics {
        self.statistics.read().await.clone()
    }

    /// Stop the alert manager
    pub async fn stop(&self) -> Result<()> {
        info!("Stopping alert manager");
        // Alert processing task will stop when sender is dropped
        info!("Alert manager stopped");
        Ok(())
    }
}
