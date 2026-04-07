//! Circuit Breaker Implementation
//!
//! This module provides circuit breaker patterns for resilient service communication
//! and fault tolerance in distributed systems.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::core::error::Result;

/// Circuit breaker manager
#[derive(Debug)]
pub struct CircuitBreakerManager {
    /// Circuit breaker configuration
    config: CircuitBreakerConfig,
    /// Circuit breakers by service
    breakers: Arc<RwLock<HashMap<String, CircuitBreaker>>>,
    /// Metrics collector
    metrics: Arc<RwLock<CircuitBreakerMetrics>>,
    /// Event listeners
    listeners: Arc<RwLock<Vec<Box<dyn CircuitBreakerListener + Send + Sync>>>>,
}

/// Circuit breaker configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    /// Global circuit breaker settings
    pub global: GlobalCircuitBreakerConfig,
    /// Service-specific configurations
    pub services: HashMap<String, ServiceCircuitBreakerConfig>,
    /// Failure detection configuration
    pub failure_detection: FailureDetectionConfig,
    /// Recovery configuration
    pub recovery: RecoveryConfig,
    /// Monitoring configuration
    pub monitoring: MonitoringConfig,
    /// Notification configuration
    pub notifications: NotificationConfig,
}

/// Global circuit breaker configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalCircuitBreakerConfig {
    /// Default failure threshold
    pub default_failure_threshold: u32,
    /// Default success threshold
    pub default_success_threshold: u32,
    /// Default timeout
    pub default_timeout: Duration,
    /// Default half-open max calls
    pub default_half_open_max_calls: u32,
    /// Enable automatic recovery
    pub auto_recovery_enabled: bool,
    /// Recovery check interval
    pub recovery_check_interval: Duration,
    /// Enable metrics collection
    pub metrics_enabled: bool,
    /// Enable notifications
    pub notifications_enabled: bool,
}

/// Service-specific circuit breaker configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceCircuitBreakerConfig {
    /// Service name
    pub service_name: String,
    /// Failure threshold
    pub failure_threshold: u32,
    /// Success threshold for recovery
    pub success_threshold: u32,
    /// Timeout duration
    pub timeout: Duration,
    /// Half-open state max calls
    pub half_open_max_calls: u32,
    /// Failure rate threshold (0.0 to 1.0)
    pub failure_rate_threshold: f64,
    /// Minimum number of calls before evaluation
    pub minimum_number_of_calls: u32,
    /// Sliding window type
    pub sliding_window_type: SlidingWindowType,
    /// Sliding window size
    pub sliding_window_size: u32,
    /// Permitted number of calls in half-open state
    pub permitted_calls_in_half_open_state: u32,
    /// Wait duration in open state
    pub wait_duration_in_open_state: Duration,
    /// Slow call duration threshold
    pub slow_call_duration_threshold: Duration,
    /// Slow call rate threshold
    pub slow_call_rate_threshold: f64,
    /// Enable automatic transition from open to half-open
    pub automatic_transition_enabled: bool,
    /// Custom failure predicates
    pub failure_predicates: Vec<FailurePredicate>,
}

/// Sliding window types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SlidingWindowType {
    CountBased,
    TimeBased,
}

/// Failure predicate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailurePredicate {
    /// Predicate type
    pub predicate_type: FailurePredicateType,
    /// Predicate parameters
    pub parameters: HashMap<String, String>,
}

/// Failure predicate types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FailurePredicateType {
    StatusCode,
    Exception,
    Timeout,
    ResponseTime,
    Custom(String),
}

/// Failure detection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailureDetectionConfig {
    /// Enable failure detection
    pub enabled: bool,
    /// Detection strategies
    pub strategies: Vec<FailureDetectionStrategy>,
    /// Health check configuration
    pub health_check: HealthCheckConfig,
    /// Anomaly detection configuration
    pub anomaly_detection: AnomalyDetectionConfig,
}

/// Failure detection strategies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FailureDetectionStrategy {
    ThresholdBased,
    RateBased,
    AnomalyBased,
    HealthCheckBased,
    Custom(String),
}

/// Health check configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    /// Enable health checks
    pub enabled: bool,
    /// Health check interval
    pub interval: Duration,
    /// Health check timeout
    pub timeout: Duration,
    /// Health check endpoint
    pub endpoint: String,
    /// Expected status codes
    pub expected_status_codes: Vec<u16>,
    /// Health check retries
    pub retries: u32,
}

/// Anomaly detection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyDetectionConfig {
    /// Enable anomaly detection
    pub enabled: bool,
    /// Detection algorithm
    pub algorithm: AnomalyDetectionAlgorithm,
    /// Sensitivity level (0.0 to 1.0)
    pub sensitivity: f64,
    /// Learning period
    pub learning_period: Duration,
    /// Minimum data points
    pub minimum_data_points: u32,
}

/// Anomaly detection algorithms
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnomalyDetectionAlgorithm {
    StatisticalOutlier,
    MovingAverage,
    ExponentialSmoothing,
    MachineLearning,
    Custom(String),
}

/// Recovery configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryConfig {
    /// Enable automatic recovery
    pub auto_recovery_enabled: bool,
    /// Recovery strategies
    pub strategies: Vec<RecoveryStrategy>,
    /// Recovery validation
    pub validation: RecoveryValidationConfig,
    /// Backoff configuration
    pub backoff: BackoffConfig,
}

/// Recovery strategies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecoveryStrategy {
    Immediate,
    Gradual,
    Exponential,
    Linear,
    Custom(String),
}

/// Recovery validation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryValidationConfig {
    /// Enable validation
    pub enabled: bool,
    /// Validation method
    pub method: RecoveryValidationMethod,
    /// Validation timeout
    pub timeout: Duration,
    /// Required success rate
    pub required_success_rate: f64,
    /// Validation sample size
    pub sample_size: u32,
}

/// Recovery validation methods
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecoveryValidationMethod {
    HealthCheck,
    SampleRequests,
    LoadTest,
    Custom(String),
}

/// Backoff configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackoffConfig {
    /// Backoff strategy
    pub strategy: BackoffStrategy,
    /// Initial delay
    pub initial_delay: Duration,
    /// Maximum delay
    pub max_delay: Duration,
    /// Multiplier
    pub multiplier: f64,
    /// Jitter enabled
    pub jitter_enabled: bool,
}

/// Backoff strategies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BackoffStrategy {
    Fixed,
    Linear,
    Exponential,
    Fibonacci,
    Custom(String),
}

/// Monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    /// Enable monitoring
    pub enabled: bool,
    /// Metrics collection interval
    pub metrics_interval: Duration,
    /// Event logging
    pub event_logging: EventLoggingConfig,
    /// Dashboard configuration
    pub dashboard: DashboardConfig,
    /// Alerting configuration
    pub alerting: AlertingConfig,
}

/// Event logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventLoggingConfig {
    /// Enable event logging
    pub enabled: bool,
    /// Log level
    pub log_level: LogLevel,
    /// Log format
    pub log_format: LogFormat,
    /// Log destination
    pub destination: LogDestination,
}

/// Log levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

/// Log formats
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogFormat {
    Json,
    Text,
    Structured,
    Custom(String),
}

/// Log destinations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogDestination {
    Console,
    File,
    Database,
    External,
    Custom(String),
}

/// Dashboard configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardConfig {
    /// Enable dashboard
    pub enabled: bool,
    /// Dashboard port
    pub port: u16,
    /// Dashboard path
    pub path: String,
    /// Refresh interval
    pub refresh_interval: Duration,
    /// Authentication required
    pub auth_required: bool,
}

/// Alerting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertingConfig {
    /// Enable alerting
    pub enabled: bool,
    /// Alert rules
    pub rules: Vec<AlertRule>,
    /// Notification channels
    pub channels: Vec<NotificationChannel>,
}

/// Alert rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    /// Rule name
    pub name: String,
    /// Rule condition
    pub condition: AlertCondition,
    /// Alert severity
    pub severity: AlertSeverity,
    /// Notification channels
    pub channels: Vec<String>,
    /// Cooldown period
    pub cooldown: Duration,
}

/// Alert condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertCondition {
    /// Metric name
    pub metric: String,
    /// Comparison operator
    pub operator: ComparisonOperator,
    /// Threshold value
    pub threshold: f64,
    /// Evaluation window
    pub window: Duration,
}

/// Comparison operators
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComparisonOperator {
    GreaterThan,
    GreaterThanOrEqual,
    LessThan,
    LessThanOrEqual,
    Equal,
    NotEqual,
}

/// Alert severity levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// Notification channel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationChannel {
    /// Channel name
    pub name: String,
    /// Channel type
    pub channel_type: NotificationChannelType,
    /// Channel configuration
    pub config: HashMap<String, String>,
}

/// Notification channel types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NotificationChannelType {
    Email,
    Slack,
    Webhook,
    SMS,
    PagerDuty,
    Custom(String),
}

/// Notification configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationConfig {
    /// Enable notifications
    pub enabled: bool,
    /// Notification events
    pub events: Vec<NotificationEvent>,
    /// Notification channels
    pub channels: Vec<NotificationChannel>,
    /// Rate limiting
    pub rate_limiting: NotificationRateLimiting,
}

/// Notification events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NotificationEvent {
    StateChange,
    FailureThresholdReached,
    RecoveryStarted,
    RecoveryCompleted,
    HealthCheckFailed,
    Custom(String),
}

/// Notification rate limiting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationRateLimiting {
    /// Enable rate limiting
    pub enabled: bool,
    /// Maximum notifications per window
    pub max_notifications: u32,
    /// Time window
    pub window: Duration,
    /// Burst allowance
    pub burst_allowance: u32,
}

/// Circuit breaker states
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum CircuitBreakerState {
    Closed,
    Open,
    HalfOpen,
}

/// Circuit breaker
#[derive(Debug, Clone)]
pub struct CircuitBreaker {
    /// Service name
    pub service_name: String,
    /// Current state
    pub state: CircuitBreakerState,
    /// Configuration
    pub config: ServiceCircuitBreakerConfig,
    /// Statistics
    pub stats: CircuitBreakerStats,
    /// State change timestamp
    pub state_changed_at: SystemTime,
    /// Last failure timestamp
    pub last_failure_at: Option<SystemTime>,
    /// Last success timestamp
    pub last_success_at: Option<SystemTime>,
    /// Sliding window
    pub sliding_window: SlidingWindow,
}

/// Circuit breaker statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerStats {
    /// Total calls
    pub total_calls: u64,
    /// Successful calls
    pub successful_calls: u64,
    /// Failed calls
    pub failed_calls: u64,
    /// Slow calls
    pub slow_calls: u64,
    /// Rejected calls
    pub rejected_calls: u64,
    /// Current failure rate
    pub failure_rate: f64,
    /// Current slow call rate
    pub slow_call_rate: f64,
    /// Average response time
    pub avg_response_time: Duration,
    /// State transitions
    pub state_transitions: u64,
    /// Time in each state
    pub time_in_states: HashMap<CircuitBreakerState, Duration>,
}

/// Sliding window for call tracking
#[derive(Debug, Clone)]
pub struct SlidingWindow {
    /// Window type
    pub window_type: SlidingWindowType,
    /// Window size
    pub size: u32,
    /// Call records
    pub calls: std::collections::VecDeque<CallRecord>,
    /// Window start time (for time-based windows)
    pub window_start: SystemTime,
}

/// Call record
#[derive(Debug, Clone)]
pub struct CallRecord {
    /// Call timestamp
    pub timestamp: SystemTime,
    /// Call duration
    pub duration: Duration,
    /// Call result
    pub result: CallResult,
    /// Response status code (if applicable)
    pub status_code: Option<u16>,
    /// Error message (if failed)
    pub error_message: Option<String>,
}

/// Call result
#[derive(Debug, Clone, PartialEq)]
pub enum CallResult {
    Success,
    Failure,
    Slow,
    Timeout,
    Rejected,
}

/// Circuit breaker metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerMetrics {
    /// Total circuit breakers
    pub total_breakers: u64,
    /// Breakers by state
    pub breakers_by_state: HashMap<CircuitBreakerState, u64>,
    /// Total calls across all breakers
    pub total_calls: u64,
    /// Total successful calls
    pub total_successful_calls: u64,
    /// Total failed calls
    pub total_failed_calls: u64,
    /// Total rejected calls
    pub total_rejected_calls: u64,
    /// Overall failure rate
    pub overall_failure_rate: f64,
    /// Average response time
    pub avg_response_time: Duration,
    /// State transition events
    pub state_transitions: u64,
    /// Most active services
    pub most_active_services: Vec<(String, u64)>,
    /// Most failing services
    pub most_failing_services: Vec<(String, f64)>,
}

/// Circuit breaker event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerEvent {
    /// Event type
    pub event_type: CircuitBreakerEventType,
    /// Service name
    pub service_name: String,
    /// Previous state
    pub previous_state: Option<CircuitBreakerState>,
    /// New state
    pub new_state: CircuitBreakerState,
    /// Event timestamp
    pub timestamp: SystemTime,
    /// Event metadata
    pub metadata: HashMap<String, String>,
}

/// Circuit breaker event types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CircuitBreakerEventType {
    StateChanged,
    CallExecuted,
    CallRejected,
    FailureThresholdReached,
    RecoveryStarted,
    RecoveryCompleted,
    ConfigurationChanged,
}

/// Circuit breaker listener trait
pub trait CircuitBreakerListener: std::fmt::Debug {
    /// Handle circuit breaker event
    fn on_event(&self, event: CircuitBreakerEvent);
    
    /// Handle state change
    fn on_state_change(&self, service_name: &str, old_state: CircuitBreakerState, new_state: CircuitBreakerState);
    
    /// Handle call execution
    fn on_call_executed(&self, service_name: &str, result: CallResult, duration: Duration);
    
    /// Handle call rejection
    fn on_call_rejected(&self, service_name: &str, reason: &str);
}

/// Call execution result
#[derive(Debug)]
pub struct CallExecutionResult<T> {
    /// Result value
    pub result: Result<T>,
    /// Call duration
    pub duration: Duration,
    /// Call record
    pub call_record: CallRecord,
}

// Default implementations
impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            global: GlobalCircuitBreakerConfig::default(),
            services: HashMap::new(),
            failure_detection: FailureDetectionConfig::default(),
            recovery: RecoveryConfig::default(),
            monitoring: MonitoringConfig::default(),
            notifications: NotificationConfig::default(),
        }
    }
}

impl Default for GlobalCircuitBreakerConfig {
    fn default() -> Self {
        Self {
            default_failure_threshold: 5,
            default_success_threshold: 3,
            default_timeout: Duration::from_secs(30),
            default_half_open_max_calls: 10,
            auto_recovery_enabled: true,
            recovery_check_interval: Duration::from_secs(60),
            metrics_enabled: true,
            notifications_enabled: true,
        }
    }
}

impl Default for ServiceCircuitBreakerConfig {
    fn default() -> Self {
        Self {
            service_name: "default".to_string(),
            failure_threshold: 5,
            success_threshold: 3,
            timeout: Duration::from_secs(30),
            half_open_max_calls: 10,
            failure_rate_threshold: 0.5,
            minimum_number_of_calls: 10,
            sliding_window_type: SlidingWindowType::CountBased,
            sliding_window_size: 100,
            permitted_calls_in_half_open_state: 10,
            wait_duration_in_open_state: Duration::from_secs(60),
            slow_call_duration_threshold: Duration::from_secs(5),
            slow_call_rate_threshold: 0.5,
            automatic_transition_enabled: true,
            failure_predicates: vec![],
        }
    }
}

impl Default for FailureDetectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            strategies: vec![FailureDetectionStrategy::ThresholdBased],
            health_check: HealthCheckConfig::default(),
            anomaly_detection: AnomalyDetectionConfig::default(),
        }
    }
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval: Duration::from_secs(30),
            timeout: Duration::from_secs(5),
            endpoint: "/health".to_string(),
            expected_status_codes: vec![200],
            retries: 3,
        }
    }
}

impl Default for AnomalyDetectionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            algorithm: AnomalyDetectionAlgorithm::StatisticalOutlier,
            sensitivity: 0.8,
            learning_period: Duration::from_secs(3600),
            minimum_data_points: 100,
        }
    }
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            auto_recovery_enabled: true,
            strategies: vec![RecoveryStrategy::Gradual],
            validation: RecoveryValidationConfig::default(),
            backoff: BackoffConfig::default(),
        }
    }
}

impl Default for RecoveryValidationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            method: RecoveryValidationMethod::HealthCheck,
            timeout: Duration::from_secs(10),
            required_success_rate: 0.8,
            sample_size: 10,
        }
    }
}

impl Default for BackoffConfig {
    fn default() -> Self {
        Self {
            strategy: BackoffStrategy::Exponential,
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(300),
            multiplier: 2.0,
            jitter_enabled: true,
        }
    }
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            metrics_interval: Duration::from_secs(60),
            event_logging: EventLoggingConfig::default(),
            dashboard: DashboardConfig::default(),
            alerting: AlertingConfig::default(),
        }
    }
}

impl Default for EventLoggingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            log_level: LogLevel::Info,
            log_format: LogFormat::Json,
            destination: LogDestination::Console,
        }
    }
}

impl Default for DashboardConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            port: 8080,
            path: "/circuit-breaker".to_string(),
            refresh_interval: Duration::from_secs(5),
            auth_required: false,
        }
    }
}

impl Default for AlertingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rules: vec![],
            channels: vec![],
        }
    }
}

impl Default for NotificationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            events: vec![
                NotificationEvent::StateChange,
                NotificationEvent::FailureThresholdReached,
            ],
            channels: vec![],
            rate_limiting: NotificationRateLimiting {
                enabled: true,
                max_notifications: 10,
                window: Duration::from_secs(300),
                burst_allowance: 3,
            },
        }
    }
}

impl Default for CircuitBreakerStats {
    fn default() -> Self {
        Self {
            total_calls: 0,
            successful_calls: 0,
            failed_calls: 0,
            slow_calls: 0,
            rejected_calls: 0,
            failure_rate: 0.0,
            slow_call_rate: 0.0,
            avg_response_time: Duration::from_millis(0),
            state_transitions: 0,
            time_in_states: HashMap::new(),
        }
    }
}

impl Default for CircuitBreakerMetrics {
    fn default() -> Self {
        Self {
            total_breakers: 0,
            breakers_by_state: HashMap::new(),
            total_calls: 0,
            total_successful_calls: 0,
            total_failed_calls: 0,
            total_rejected_calls: 0,
            overall_failure_rate: 0.0,
            avg_response_time: Duration::from_millis(0),
            state_transitions: 0,
            most_active_services: vec![],
            most_failing_services: vec![],
        }
    }
}

// Implementation
impl CircuitBreakerManager {
    /// Create a new circuit breaker manager
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            config,
            breakers: Arc::new(RwLock::new(HashMap::new())),
            metrics: Arc::new(RwLock::new(CircuitBreakerMetrics::default())),
            listeners: Arc::new(RwLock::new(vec![])),
        }
    }

    /// Get or create circuit breaker for service
    pub async fn get_circuit_breaker(&self, service_name: &str) -> CircuitBreaker {
        let mut breakers = self.breakers.write().await;
        
        if let Some(breaker) = breakers.get(service_name) {
            breaker.clone()
        } else {
            let config = self.config.services.get(service_name)
                .cloned()
                .unwrap_or_else(|| {
                    let mut default_config = ServiceCircuitBreakerConfig::default();
                    default_config.service_name = service_name.to_string();
                    default_config.failure_threshold = self.config.global.default_failure_threshold;
                    default_config.success_threshold = self.config.global.default_success_threshold;
                    default_config.timeout = self.config.global.default_timeout;
                    default_config.half_open_max_calls = self.config.global.default_half_open_max_calls;
                    default_config
                });
            
            let breaker = CircuitBreaker::new(service_name.to_string(), config);
            breakers.insert(service_name.to_string(), breaker.clone());
            
            let mut metrics = self.metrics.write().await;
            metrics.total_breakers += 1;
            
            info!("Created circuit breaker for service: {}", service_name);
            breaker
        }
    }

    /// Execute a call through circuit breaker
    pub async fn execute<T, F, Fut>(&self, service_name: &str, call: F) -> CallExecutionResult<T>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let start_time = SystemTime::now();
        let mut breaker = self.get_circuit_breaker(service_name).await;
        
        // Check if call should be rejected
        if breaker.should_reject_call() {
            let duration = start_time.elapsed().unwrap_or(Duration::from_millis(0));
            let call_record = CallRecord {
                timestamp: start_time,
                duration,
                result: CallResult::Rejected,
                status_code: None,
                error_message: Some("Circuit breaker is open".to_string()),
            };
            
            breaker.record_call(call_record.clone()).await;
            let breaker_state = breaker.state.clone();
            self.update_circuit_breaker(service_name, breaker).await;
            
            self.notify_listeners(CircuitBreakerEvent {
                event_type: CircuitBreakerEventType::CallRejected,
                service_name: service_name.to_string(),
                previous_state: None,
                new_state: breaker_state,
                timestamp: SystemTime::now(),
                metadata: HashMap::new(),
            }).await;
            
            return CallExecutionResult {
                result: Err(crate::core::error::Error::CircuitBreakerOpen(service_name.to_string())),
                duration,
                call_record,
            };
        }
        
        // Execute the call
        let result = call().await;
        let duration = start_time.elapsed().unwrap_or(Duration::from_millis(0));
        
        // Clone necessary values before moving breaker
        let slow_call_threshold = breaker.config.slow_call_duration_threshold;
        
        let call_result = match &result {
            Ok(_) => {
                if duration > slow_call_threshold {
                    CallResult::Slow
                } else {
                    CallResult::Success
                }
            },
            Err(_) => CallResult::Failure,
        };
        
        let call_record = CallRecord {
            timestamp: start_time,
            duration,
            result: call_result.clone(),
            status_code: None,
            error_message: if result.is_err() {
                Some("Call failed".to_string())
            } else {
                None
            },
        };
        
        breaker.record_call(call_record.clone()).await;
        let breaker_state = breaker.state.clone();
        self.update_circuit_breaker(service_name, breaker).await;
        
        self.notify_listeners(CircuitBreakerEvent {
            event_type: CircuitBreakerEventType::CallExecuted,
            service_name: service_name.to_string(),
            previous_state: None,
            new_state: breaker_state,
            timestamp: SystemTime::now(),
            metadata: HashMap::new(),
        }).await;
        
        CallExecutionResult {
            result,
            duration,
            call_record,
        }
    }

    /// Update circuit breaker
    async fn update_circuit_breaker(&self, service_name: &str, breaker: CircuitBreaker) {
        let mut breakers = self.breakers.write().await;
        breakers.insert(service_name.to_string(), breaker);
    }

    /// Add event listener
    pub async fn add_listener(&self, listener: Box<dyn CircuitBreakerListener + Send + Sync>) {
        let mut listeners = self.listeners.write().await;
        listeners.push(listener);
    }

    /// Notify event listeners
    async fn notify_listeners(&self, event: CircuitBreakerEvent) {
        let listeners = self.listeners.read().await;
        for listener in listeners.iter() {
            listener.on_event(event.clone());
        }
    }

    /// Get circuit breaker metrics
    pub async fn get_metrics(&self) -> CircuitBreakerMetrics {
        let metrics = self.metrics.read().await;
        metrics.clone()
    }

    /// Get all circuit breakers
    pub async fn get_all_breakers(&self) -> HashMap<String, CircuitBreaker> {
        let breakers = self.breakers.read().await;
        breakers.clone()
    }

    /// Reset circuit breaker
    pub async fn reset_circuit_breaker(&self, service_name: &str) -> Result<()> {
        let mut breakers = self.breakers.write().await;
        
        if let Some(breaker) = breakers.get_mut(service_name) {
            breaker.reset();
            info!("Reset circuit breaker for service: {}", service_name);
            Ok(())
        } else {
            Err(crate::core::error::Error::ServiceNotFound(service_name.to_string()))
        }
    }

    /// Force circuit breaker state
    pub async fn force_state(&self, service_name: &str, state: CircuitBreakerState) -> Result<()> {
        let mut breakers = self.breakers.write().await;
        
        if let Some(breaker) = breakers.get_mut(service_name) {
            let old_state = breaker.state.clone();
            breaker.force_state(state.clone());
            
            self.notify_listeners(CircuitBreakerEvent {
                event_type: CircuitBreakerEventType::StateChanged,
                service_name: service_name.to_string(),
                previous_state: Some(old_state),
                new_state: state,
                timestamp: SystemTime::now(),
                metadata: HashMap::new(),
            }).await;
            
            info!("Forced circuit breaker state for service: {} to {:?}", service_name, breaker.state);
            Ok(())
        } else {
            Err(crate::core::error::Error::ServiceNotFound(service_name.to_string()))
        }
    }
}

impl CircuitBreaker {
    /// Create a new circuit breaker
    pub fn new(service_name: String, config: ServiceCircuitBreakerConfig) -> Self {
        Self {
            service_name,
            state: CircuitBreakerState::Closed,
            config: config.clone(),
            stats: CircuitBreakerStats::default(),
            state_changed_at: SystemTime::now(),
            last_failure_at: None,
            last_success_at: None,
            sliding_window: SlidingWindow::new(config.sliding_window_type, config.sliding_window_size),
        }
    }

    /// Check if call should be rejected
    pub fn should_reject_call(&self) -> bool {
        match self.state {
            CircuitBreakerState::Open => {
                // Check if we should transition to half-open
                if self.config.automatic_transition_enabled {
                    let elapsed = self.state_changed_at.elapsed().unwrap_or(Duration::from_secs(0));
                    elapsed < self.config.wait_duration_in_open_state
                } else {
                    true
                }
            },
            CircuitBreakerState::HalfOpen => {
                // Allow limited calls in half-open state
                self.sliding_window.calls.len() >= self.config.permitted_calls_in_half_open_state as usize
            },
            CircuitBreakerState::Closed => false,
        }
    }

    /// Record a call result
    pub async fn record_call(&mut self, call_record: CallRecord) {
        self.sliding_window.add_call(call_record.clone());
        self.update_stats(&call_record);
        
        match call_record.result {
            CallResult::Success => {
                self.last_success_at = Some(call_record.timestamp);
                self.handle_success().await;
            },
            CallResult::Failure | CallResult::Timeout => {
                self.last_failure_at = Some(call_record.timestamp);
                self.handle_failure().await;
            },
            CallResult::Slow => {
                self.handle_slow_call().await;
            },
            CallResult::Rejected => {
                self.stats.rejected_calls += 1;
            },
        }
    }

    /// Handle successful call
    async fn handle_success(&mut self) {
        match self.state {
            CircuitBreakerState::HalfOpen => {
                let success_count = self.sliding_window.calls.iter()
                    .filter(|c| c.result == CallResult::Success)
                    .count() as u32;
                
                if success_count >= self.config.success_threshold {
                    self.transition_to_closed().await;
                }
            },
            _ => {}
        }
    }

    /// Handle failed call
    async fn handle_failure(&mut self) {
        if self.should_open_circuit() {
            self.transition_to_open().await;
        }
    }

    /// Handle slow call
    async fn handle_slow_call(&mut self) {
        if self.should_open_circuit_for_slow_calls() {
            self.transition_to_open().await;
        }
    }

    /// Check if circuit should open
    fn should_open_circuit(&self) -> bool {
        if self.sliding_window.calls.len() < self.config.minimum_number_of_calls as usize {
            return false;
        }
        
        let failure_rate = self.calculate_failure_rate();
        failure_rate >= self.config.failure_rate_threshold
    }

    /// Check if circuit should open for slow calls
    fn should_open_circuit_for_slow_calls(&self) -> bool {
        if self.sliding_window.calls.len() < self.config.minimum_number_of_calls as usize {
            return false;
        }
        
        let slow_call_rate = self.calculate_slow_call_rate();
        slow_call_rate >= self.config.slow_call_rate_threshold
    }

    /// Calculate failure rate
    fn calculate_failure_rate(&self) -> f64 {
        if self.sliding_window.calls.is_empty() {
            return 0.0;
        }
        
        let failed_calls = self.sliding_window.calls.iter()
            .filter(|c| matches!(c.result, CallResult::Failure | CallResult::Timeout))
            .count();
        
        failed_calls as f64 / self.sliding_window.calls.len() as f64
    }

    /// Calculate slow call rate
    fn calculate_slow_call_rate(&self) -> f64 {
        if self.sliding_window.calls.is_empty() {
            return 0.0;
        }
        
        let slow_calls = self.sliding_window.calls.iter()
            .filter(|c| c.result == CallResult::Slow)
            .count();
        
        slow_calls as f64 / self.sliding_window.calls.len() as f64
    }

    /// Transition to closed state
    async fn transition_to_closed(&mut self) {
        self.state = CircuitBreakerState::Closed;
        self.state_changed_at = SystemTime::now();
        self.stats.state_transitions += 1;
        debug!("Circuit breaker for {} transitioned to CLOSED", self.service_name);
    }

    /// Transition to open state
    async fn transition_to_open(&mut self) {
        self.state = CircuitBreakerState::Open;
        self.state_changed_at = SystemTime::now();
        self.stats.state_transitions += 1;
        warn!("Circuit breaker for {} transitioned to OPEN", self.service_name);
    }

    /// Transition to half-open state
    async fn transition_to_half_open(&mut self) {
        self.state = CircuitBreakerState::HalfOpen;
        self.state_changed_at = SystemTime::now();
        self.stats.state_transitions += 1;
        self.sliding_window.calls.clear(); // Reset for half-open evaluation
        info!("Circuit breaker for {} transitioned to HALF_OPEN", self.service_name);
    }

    /// Update statistics
    fn update_stats(&mut self, call_record: &CallRecord) {
        self.stats.total_calls += 1;
        
        match call_record.result {
            CallResult::Success => self.stats.successful_calls += 1,
            CallResult::Failure | CallResult::Timeout => self.stats.failed_calls += 1,
            CallResult::Slow => self.stats.slow_calls += 1,
            CallResult::Rejected => self.stats.rejected_calls += 1,
        }
        
        // Update failure rate
        if self.stats.total_calls > 0 {
            self.stats.failure_rate = self.stats.failed_calls as f64 / self.stats.total_calls as f64;
            self.stats.slow_call_rate = self.stats.slow_calls as f64 / self.stats.total_calls as f64;
        }
        
        // Update average response time
        let total_time = self.stats.avg_response_time.as_nanos() as u64 * (self.stats.total_calls - 1) + call_record.duration.as_nanos() as u64;
        self.stats.avg_response_time = Duration::from_nanos(total_time / self.stats.total_calls);
    }

    /// Reset circuit breaker
    pub fn reset(&mut self) {
        self.state = CircuitBreakerState::Closed;
        self.state_changed_at = SystemTime::now();
        self.stats = CircuitBreakerStats::default();
        self.sliding_window.calls.clear();
        self.last_failure_at = None;
        self.last_success_at = None;
    }

    /// Force circuit breaker state
    pub fn force_state(&mut self, state: CircuitBreakerState) {
        self.state = state;
        self.state_changed_at = SystemTime::now();
        self.stats.state_transitions += 1;
    }
}

impl SlidingWindow {
    /// Create a new sliding window
    pub fn new(window_type: SlidingWindowType, size: u32) -> Self {
        Self {
            window_type,
            size,
            calls: std::collections::VecDeque::new(),
            window_start: SystemTime::now(),
        }
    }

    /// Add a call to the window
    pub fn add_call(&mut self, call_record: CallRecord) {
        match self.window_type {
            SlidingWindowType::CountBased => {
                self.calls.push_back(call_record);
                
                // Remove old calls if window is full
                while self.calls.len() > self.size as usize {
                    self.calls.pop_front();
                }
            },
            SlidingWindowType::TimeBased => {
                self.calls.push_back(call_record);
                
                // Remove calls older than window size (in seconds)
                let window_duration = Duration::from_secs(self.size as u64);
                let cutoff_time = SystemTime::now() - window_duration;
                
                while let Some(front) = self.calls.front() {
                    if front.timestamp < cutoff_time {
                        self.calls.pop_front();
                    } else {
                        break;
                    }
                }
            },
        }
    }
}

/// Utility functions
pub fn create_default_circuit_breaker_manager() -> CircuitBreakerManager {
    CircuitBreakerManager::new(CircuitBreakerConfig::default())
}

pub fn validate_circuit_breaker_config(config: &CircuitBreakerConfig) -> bool {
    // Validate global configuration
    if config.global.default_failure_threshold == 0 {
        return false;
    }
    
    if config.global.default_success_threshold == 0 {
        return false;
    }
    
    if config.global.default_timeout.as_secs() == 0 {
        return false;
    }
    
    // Validate service configurations
    for service_config in config.services.values() {
        if service_config.failure_threshold == 0 {
            return false;
        }
        
        if service_config.success_threshold == 0 {
            return false;
        }
        
        if service_config.timeout.as_secs() == 0 {
            return false;
        }
        
        if service_config.failure_rate_threshold < 0.0 || service_config.failure_rate_threshold > 1.0 {
            return false;
        }
        
        if service_config.slow_call_rate_threshold < 0.0 || service_config.slow_call_rate_threshold > 1.0 {
            return false;
        }
    }
    
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_circuit_breaker_creation() {
        let config = CircuitBreakerConfig::default();
        let manager = CircuitBreakerManager::new(config);
        
        let breaker = manager.get_circuit_breaker("test-service").await;
        assert_eq!(breaker.service_name, "test-service");
        assert_eq!(breaker.state, CircuitBreakerState::Closed);
    }
    
    #[tokio::test]
    async fn test_circuit_breaker_execution() {
        let config = CircuitBreakerConfig::default();
        let manager = CircuitBreakerManager::new(config);
        
        let result = manager.execute("test-service", || async {
            Ok::<String, crate::core::error::Error>("success".to_string())
        }).await;
        
        assert!(result.result.is_ok());
        assert_eq!(result.call_record.result, CallResult::Success);
    }
    
    #[test]
    fn test_sliding_window_count_based() {
        let mut window = SlidingWindow::new(SlidingWindowType::CountBased, 3);
        
        for _ in 0..5 {
            let call_record = CallRecord {
                timestamp: SystemTime::now(),
                duration: Duration::from_millis(100),
                result: CallResult::Success,
                status_code: Some(200),
                error_message: None,
            };
            window.add_call(call_record);
        }
        
        assert_eq!(window.calls.len(), 3);
    }
    
    #[test]
    fn test_config_validation() {
        let valid_config = CircuitBreakerConfig::default();
        assert!(validate_circuit_breaker_config(&valid_config));
        
        let mut invalid_config = valid_config.clone();
        invalid_config.global.default_failure_threshold = 0;
        assert!(!validate_circuit_breaker_config(&invalid_config));
    }
    
    #[test]
    fn test_circuit_breaker_states() {
        let state = CircuitBreakerState::Closed;
        assert_eq!(state, CircuitBreakerState::Closed);
        assert_ne!(state, CircuitBreakerState::Open);
    }
    
    #[test]
    fn test_call_result_types() {
        let result = CallResult::Success;
        assert_eq!(result, CallResult::Success);
        assert_ne!(result, CallResult::Failure);
    }
    
    #[test]
    fn test_enum_serialization() {
        let state = CircuitBreakerState::HalfOpen;
        let serialized = serde_json::to_string(&state).unwrap();
        let deserialized: CircuitBreakerState = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, CircuitBreakerState::HalfOpen);
    }
    
    #[test]
    fn test_default_configurations() {
        let config = CircuitBreakerConfig::default();
        assert_eq!(config.global.default_failure_threshold, 5);
        assert_eq!(config.global.default_success_threshold, 3);
        assert!(config.global.auto_recovery_enabled);
        assert!(config.global.metrics_enabled);
    }
    
    #[test]
    fn test_failure_rate_calculation() {
        let config = ServiceCircuitBreakerConfig::default();
        let mut breaker = CircuitBreaker::new("test".to_string(), config);
        
        // Add some successful calls
        for _ in 0..7 {
            let call_record = CallRecord {
                timestamp: SystemTime::now(),
                duration: Duration::from_millis(100),
                result: CallResult::Success,
                status_code: Some(200),
                error_message: None,
            };
            breaker.sliding_window.add_call(call_record);
        }
        
        // Add some failed calls
        for _ in 0..3 {
            let call_record = CallRecord {
                timestamp: SystemTime::now(),
                duration: Duration::from_millis(100),
                result: CallResult::Failure,
                status_code: Some(500),
                error_message: Some("Error".to_string()),
            };
            breaker.sliding_window.add_call(call_record);
        }
        
        let failure_rate = breaker.calculate_failure_rate();
        assert_eq!(failure_rate, 0.3); // 3 failures out of 10 calls
    }
}
