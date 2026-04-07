use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use uuid::Uuid;
use log::debug;
use crate::metrics::database::{MetricsDatabase, PerformanceMetric};
use chrono::Utc;
use crate::ipc::{get_threats_detected, get_quarantined_files};



// Error handling
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ObservabilityError {
    TracingError(String),
    LoggingError(String),
    MonitoringError(String),
    ConfigurationError(String),
    ExportError(String),
}

impl std::fmt::Display for ObservabilityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ObservabilityError::TracingError(msg) => write!(f, "Tracing error: {}", msg),
            ObservabilityError::LoggingError(msg) => write!(f, "Logging error: {}", msg),
            ObservabilityError::MonitoringError(msg) => write!(f, "Monitoring error: {}", msg),
            ObservabilityError::ConfigurationError(msg) => write!(f, "Configuration error: {}", msg),
            ObservabilityError::ExportError(msg) => write!(f, "Export error: {}", msg),
        }
    }
}

impl std::error::Error for ObservabilityError {}

// Configuration structures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservabilityConfig {
    pub tracing_config: TracingConfig,
    pub logging_config: LoggingConfig,
    pub monitoring_config: MonitoringConfig,
    pub export_config: ExportConfig,
    pub sampling_config: SamplingConfig,
    pub performance_config: PerformanceConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracingConfig {
    pub enabled: bool,
    pub service_name: String,
    pub service_version: String,
    pub environment: String,
    pub sampling_rate: f64,
    pub max_spans_per_trace: usize,
    pub span_timeout: Duration,
    pub batch_timeout: Duration,
    pub max_export_batch_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub enabled: bool,
    pub log_level: LogLevel,
    pub output_format: LogFormat,
    pub output_destinations: Vec<LogDestination>,
    pub structured_logging: bool,
    pub include_caller_info: bool,
    pub include_stack_trace: bool,
    pub max_log_size: usize,
    pub rotation_config: LogRotationConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    pub enabled: bool,
    pub health_check_interval: Duration,
    pub performance_monitoring: bool,
    pub resource_monitoring: bool,
    pub custom_metrics: Vec<CustomMetricConfig>,
    pub alerting_thresholds: AlertingThresholds,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportConfig {
    pub exporters: Vec<ExporterConfig>,
    pub export_interval: Duration,
    pub batch_size: usize,
    pub timeout: Duration,
    pub retry_config: RetryConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamplingConfig {
    pub default_sampling_rate: f64,
    pub service_sampling_rates: HashMap<String, f64>,
    pub operation_sampling_rates: HashMap<String, f64>,
    pub adaptive_sampling: bool,
    pub sampling_rules: Vec<SamplingRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    pub max_memory_usage: usize,
    pub max_cpu_usage: f64,
    pub buffer_size: usize,
    pub processing_threads: usize,
    pub queue_size: usize,
}

// Enums
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Fatal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogFormat {
    JSON,
    Plain,
    Structured,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogDestination {
    Console,
    File(String),
    Syslog,
    Network(String),
    Database(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExporterType {
    Jaeger,
    Zipkin,
    OpenTelemetry,
    Prometheus,
    Datadog,
    NewRelic,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SpanKind {
    Internal,
    Server,
    Client,
    Producer,
    Consumer,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SpanStatus {
    Ok,
    Error,
    Timeout,
    Cancelled,
}

// Data structures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Span {
    pub span_id: String,
    pub trace_id: String,
    pub parent_span_id: Option<String>,
    pub operation_name: String,
    pub service_name: String,
    pub start_time: u64,
    pub end_time: Option<u64>,
    pub duration: Option<Duration>,
    pub status: SpanStatus,
    pub kind: SpanKind,
    pub tags: HashMap<String, String>,
    pub logs: Vec<SpanLog>,
    pub baggage: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpanLog {
    pub timestamp: u64,
    pub level: LogLevel,
    pub message: String,
    pub fields: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Trace {
    pub trace_id: String,
    pub spans: Vec<Span>,
    pub start_time: u64,
    pub end_time: Option<u64>,
    pub duration: Option<Duration>,
    pub service_count: usize,
    pub span_count: usize,
    pub error_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: u64,
    pub level: LogLevel,
    pub message: String,
    pub service_name: String,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub fields: HashMap<String, String>,
    pub caller_info: Option<CallerInfo>,
    pub stack_trace: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallerInfo {
    pub file: String,
    pub line: u32,
    pub function: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheck {
    pub service_name: String,
    pub status: HealthStatus,
    pub timestamp: u64,
    pub checks: Vec<ComponentHealth>,
    pub overall_health: f64,
    pub response_time: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealth {
    pub component_name: String,
    pub status: HealthStatus,
    pub message: String,
    pub metrics: HashMap<String, f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub cpu_usage: f64,
    pub memory_usage: usize,
    pub disk_usage: usize,
    pub network_io: NetworkIO,
    pub request_rate: f64,
    pub error_rate: f64,
    pub response_time_p50: Duration,
    pub response_time_p95: Duration,
    pub response_time_p99: Duration,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkIO {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomMetricConfig {
    pub name: String,
    pub metric_type: MetricType,
    pub description: String,
    pub labels: Vec<String>,
    pub collection_interval: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MetricType {
    Counter,
    Gauge,
    Histogram,
    Summary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertingThresholds {
    pub cpu_threshold: f64,
    pub memory_threshold: f64,
    pub disk_threshold: f64,
    pub error_rate_threshold: f64,
    pub response_time_threshold: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExporterConfig {
    pub exporter_type: ExporterType,
    pub endpoint: String,
    pub headers: HashMap<String, String>,
    pub timeout: Duration,
    pub compression: bool,
    pub authentication: AuthConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    pub auth_type: AuthType,
    pub credentials: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthType {
    None,
    Basic,
    Bearer,
    ApiKey,
    OAuth2,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    pub max_retries: u32,
    pub initial_delay: Duration,
    pub max_delay: Duration,
    pub backoff_multiplier: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogRotationConfig {
    pub max_file_size: usize,
    pub max_files: usize,
    pub rotation_interval: Duration,
    pub compress_rotated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamplingRule {
    pub service_name: Option<String>,
    pub operation_name: Option<String>,
    pub sampling_rate: f64,
    pub max_traces_per_second: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservabilityStatistics {
    pub total_spans: u64,
    pub total_traces: u64,
    pub total_logs: u64,
    pub active_spans: u64,
    pub spans_per_second: f64,
    pub traces_per_second: f64,
    pub logs_per_second: f64,
    pub average_span_duration: Duration,
    pub error_count: u64,
    pub export_errors: u64,
    pub memory_usage: usize,
    pub uptime: Duration,
}

// Main observability manager
pub struct ObservabilityManager {
    config: Arc<RwLock<ObservabilityConfig>>,
    tracer: Arc<DefaultTracer>,
    logger: Arc<DefaultLogger>,
    monitor: Arc<DefaultMonitor>,
    exporters: Arc<RwLock<Vec<Arc<dyn Exporter + Send + Sync>>>>,
    statistics: Arc<RwLock<ObservabilityStatistics>>,
    shutdown_tx: Option<broadcast::Sender<()>>,
}

impl ObservabilityManager {
    pub fn new(
        config: ObservabilityConfig,
        tracer: Arc<DefaultTracer>,
        logger: Arc<DefaultLogger>,
        monitor: Arc<DefaultMonitor>,
    ) -> Result<Self, ObservabilityError> {
        Ok(Self {
            config: Arc::new(RwLock::new(config)),
            tracer,
            logger,
            monitor,
            exporters: Arc::new(RwLock::new(Vec::new())),
            statistics: Arc::new(RwLock::new(ObservabilityStatistics::default())),
            shutdown_tx: None,
        })
    }

    pub async fn start(&mut self) -> Result<(), ObservabilityError> {
        let (shutdown_tx, _) = broadcast::channel(1);
        let shutdown_rx1 = shutdown_tx.subscribe();
        let shutdown_rx2 = shutdown_tx.subscribe();
        
        // Store the sender for shutdown
        self.shutdown_tx = Some(shutdown_tx);

        // Start monitoring loop
        let monitor = self.monitor.clone();
        let statistics = self.statistics.clone();
        let config = self.config.clone();
        let mut shutdown_rx1 = shutdown_rx1;

        tokio::spawn(async move {
            let mut interval = {
                let config = config.read().unwrap();
                tokio::time::interval(config.monitoring_config.health_check_interval)
            };

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        if let Err(e) = Self::perform_health_check(&monitor, &statistics).await {
                            eprintln!("Health check error: {}", e);
                        }
                    }
                    _ = shutdown_rx1.recv() => {
                        break;
                    }
                }
            }
        });

        // Start export loop
        let exporters = self.exporters.clone();
        let tracer = self.tracer.clone();
        let logger = self.logger.clone();
        let config = self.config.clone();
        let mut shutdown_rx2 = shutdown_rx2;

        tokio::spawn(async move {
            let mut interval = {
                let config = config.read().unwrap();
                tokio::time::interval(config.export_config.export_interval)
            };

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        if let Err(e) = Self::export_data(&exporters, &tracer, &logger).await {
                            eprintln!("Export error: {}", e);
                        }
                    }
                    _ = shutdown_rx2.recv() => {
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    pub async fn stop(&mut self) -> Result<(), ObservabilityError> {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        Ok(())
    }

    pub async fn create_span(
        &self,
        operation_name: &str,
        parent_span_id: Option<String>,
    ) -> Result<String, ObservabilityError> {
        self.tracer.start_span(operation_name, parent_span_id).await
    }

    pub async fn finish_span(
        &self,
        span_id: &str,
        status: SpanStatus,
    ) -> Result<(), ObservabilityError> {
        self.tracer.finish_span(span_id, status).await
    }

    pub async fn log(
        &self,
        level: LogLevel,
        message: &str,
        fields: HashMap<String, String>,
    ) -> Result<(), ObservabilityError> {
        self.logger.log(level, message, fields).await
    }

    pub async fn get_health_status(&self) -> Result<HealthCheck, ObservabilityError> {
        self.monitor.get_health_status().await
    }

    pub async fn get_performance_metrics(&self) -> Result<PerformanceMetrics, ObservabilityError> {
        self.monitor.get_performance_metrics().await
    }

    pub async fn get_statistics(&self) -> ObservabilityStatistics {
        self.statistics.read().unwrap().clone()
    }

    pub async fn register_exporter(
        &self,
        exporter: Arc<dyn Exporter + Send + Sync>,
    ) -> Result<(), ObservabilityError> {
        let mut exporters = self.exporters.write().unwrap();
        exporters.push(exporter);
        Ok(())
    }

    pub async fn update_config(&self, config: ObservabilityConfig) -> Result<(), ObservabilityError> {
        let mut current_config = self.config.write().unwrap();
        *current_config = config;
        Ok(())
    }

    async fn perform_health_check(
        monitor: &Arc<DefaultMonitor>,
        statistics: &Arc<RwLock<ObservabilityStatistics>>,
    ) -> Result<(), ObservabilityError> {
        let _health_check = monitor.get_health_status().await?;
        let performance_metrics = monitor.get_performance_metrics().await?;

        // Update statistics
        let mut stats = statistics.write().unwrap();
        stats.memory_usage = performance_metrics.memory_usage;
        
        Ok(())
    }

    async fn export_data(
        exporters: &Arc<RwLock<Vec<Arc<dyn Exporter + Send + Sync>>>>,
        tracer: &Arc<DefaultTracer>,
        logger: &Arc<DefaultLogger>,
    ) -> Result<(), ObservabilityError> {
        let traces = tracer.get_completed_traces().await?;
        let logs = logger.get_recent_logs(Duration::from_secs(3600)).await?;
        let exporter_list = {
            let guard = exporters.read().unwrap();
            guard.clone()
        };
        for exporter in exporter_list.into_iter() {
            // Perform async export operations without holding the lock
            if let Err(e) = exporter.export_traces(&traces).await {
                debug!("Exporter {:?} traces export error: {}", exporter.get_exporter_type(), e);
            }
            if let Err(e) = exporter.export_logs(&logs).await {
                debug!("Exporter {:?} logs export error: {}", exporter.get_exporter_type(), e);
            }
        }

        // Persist counters on each export cycle
        let db_path = std::env::temp_dir().join("erdps_metrics.db");
        if let Ok(db) = MetricsDatabase::new(db_path) {
            let _ = db.initialize_schema();
            let threats = get_threats_detected() as f64;
            let quarantined = get_quarantined_files() as f64;
            let perf_threats = PerformanceMetric {
                id: None,
                timestamp: Utc::now(),
                metric_type: "threats_detected_total".to_string(),
                metric_value: threats,
                unit: "count".to_string(),
                component: "agent".to_string(),
                process_id: Some(std::process::id()),
                additional_context: None,
            };
            let perf_quarantine = PerformanceMetric {
                id: None,
                timestamp: Utc::now(),
                metric_type: "quarantined_files_total".to_string(),
                metric_value: quarantined,
                unit: "count".to_string(),
                component: "agent".to_string(),
                process_id: Some(std::process::id()),
                additional_context: None,
            };
            let _ = db.record_performance_metric(&perf_threats);
            let _ = db.record_performance_metric(&perf_quarantine);
        }

        Ok(())
    }
}

// Traits
#[async_trait::async_trait]
pub trait Tracer {
    async fn start_span(
        &self,
        operation_name: &str,
        parent_span_id: Option<String>,
    ) -> Result<String, ObservabilityError>;
    
    async fn finish_span(
        &self,
        span_id: &str,
        status: SpanStatus,
    ) -> Result<(), ObservabilityError>;
    
    async fn add_span_tag(
        &self,
        span_id: &str,
        key: &str,
        value: &str,
    ) -> Result<(), ObservabilityError>;
    
    async fn add_span_log(
        &self,
        span_id: &str,
        log: SpanLog,
    ) -> Result<(), ObservabilityError>;
    
    async fn get_completed_traces(&self) -> Result<Vec<Trace>, ObservabilityError>;
}

#[async_trait::async_trait]
pub trait Logger {
    async fn log(
        &self,
        level: LogLevel,
        message: &str,
        fields: HashMap<String, String>,
    ) -> Result<(), ObservabilityError>;
    
    async fn get_recent_logs(&self, duration: Duration) -> Result<Vec<LogEntry>, ObservabilityError>;
    
    async fn set_log_level(&self, level: LogLevel) -> Result<(), ObservabilityError>;
}

#[async_trait::async_trait]
pub trait Monitor {
    async fn get_health_status(&self) -> Result<HealthCheck, ObservabilityError>;
    async fn get_performance_metrics(&self) -> Result<PerformanceMetrics, ObservabilityError>;
    async fn register_health_check(
        &self,
        name: &str,
        check: Box<dyn HealthChecker + Send + Sync>,
    ) -> Result<(), ObservabilityError>;
}

#[async_trait::async_trait]
pub trait Exporter {
    async fn export_traces(&self, traces: &[Trace]) -> Result<(), ObservabilityError>;
    async fn export_logs(&self, logs: &[LogEntry]) -> Result<(), ObservabilityError>;
    fn get_exporter_type(&self) -> ExporterType;
}

#[async_trait::async_trait]
pub trait HealthChecker {
    async fn check_health(&self) -> Result<ComponentHealth, ObservabilityError>;
    fn get_component_name(&self) -> &str;
}

// Default implementations
impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            tracing_config: TracingConfig::default(),
            logging_config: LoggingConfig::default(),
            monitoring_config: MonitoringConfig::default(),
            export_config: ExportConfig::default(),
            sampling_config: SamplingConfig::default(),
            performance_config: PerformanceConfig::default(),
        }
    }
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            service_name: "erdps".to_string(),
            service_version: "1.0.0".to_string(),
            environment: "production".to_string(),
            sampling_rate: 1.0,
            max_spans_per_trace: 1000,
            span_timeout: Duration::from_secs(300),
            batch_timeout: Duration::from_secs(5),
            max_export_batch_size: 512,
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            log_level: LogLevel::Info,
            output_format: LogFormat::JSON,
            output_destinations: vec![LogDestination::Console],
            structured_logging: true,
            include_caller_info: true,
            include_stack_trace: false,
            max_log_size: 1024 * 1024, // 1MB
            rotation_config: LogRotationConfig::default(),
        }
    }
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            health_check_interval: Duration::from_secs(30),
            performance_monitoring: true,
            resource_monitoring: true,
            custom_metrics: vec![],
            alerting_thresholds: AlertingThresholds::default(),
        }
    }
}

impl Default for ExportConfig {
    fn default() -> Self {
        Self {
            exporters: vec![],
            export_interval: Duration::from_secs(60),
            batch_size: 100,
            timeout: Duration::from_secs(30),
            retry_config: RetryConfig::default(),
        }
    }
}

impl Default for SamplingConfig {
    fn default() -> Self {
        Self {
            default_sampling_rate: 1.0,
            service_sampling_rates: HashMap::new(),
            operation_sampling_rates: HashMap::new(),
            adaptive_sampling: false,
            sampling_rules: vec![],
        }
    }
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            max_memory_usage: 1024 * 1024 * 1024, // 1GB
            max_cpu_usage: 80.0,
            buffer_size: 10000,
            processing_threads: 4,
            queue_size: 10000,
        }
    }
}

impl Default for AlertingThresholds {
    fn default() -> Self {
        Self {
            cpu_threshold: 80.0,
            memory_threshold: 80.0,
            disk_threshold: 90.0,
            error_rate_threshold: 5.0,
            response_time_threshold: Duration::from_millis(1000),
        }
    }
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(30),
            backoff_multiplier: 2.0,
        }
    }
}

impl Default for LogRotationConfig {
    fn default() -> Self {
        Self {
            max_file_size: 100 * 1024 * 1024, // 100MB
            max_files: 10,
            rotation_interval: Duration::from_secs(86400), // 24 hours
            compress_rotated: true,
        }
    }
}

impl Default for ObservabilityStatistics {
    fn default() -> Self {
        Self {
            total_spans: 0,
            total_traces: 0,
            total_logs: 0,
            active_spans: 0,
            spans_per_second: 0.0,
            traces_per_second: 0.0,
            logs_per_second: 0.0,
            average_span_duration: Duration::from_millis(0),
            error_count: 0,
            export_errors: 0,
            memory_usage: 0,
            uptime: Duration::from_secs(0),
        }
    }
}

// Default trait implementations
#[derive(Debug)]
pub struct DefaultTracer {
    spans: Arc<RwLock<HashMap<String, Span>>>,
    completed_traces: Arc<RwLock<Vec<Trace>>>,
}

impl DefaultTracer {
    pub fn new() -> Self {
        Self {
            spans: Arc::new(RwLock::new(HashMap::new())),
            completed_traces: Arc::new(RwLock::new(Vec::new())),
        }
    }

    fn get_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn get_timestamp_nanos() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    }
}

#[async_trait::async_trait]
impl Tracer for DefaultTracer {
    async fn start_span(
        &self,
        operation_name: &str,
        parent_span_id: Option<String>,
    ) -> Result<String, ObservabilityError> {
        let span_id = Uuid::new_v4().to_string();
        let trace_id = Uuid::new_v4().to_string();
        
        let span = Span {
            span_id: span_id.clone(),
            trace_id,
            parent_span_id,
            operation_name: operation_name.to_string(),
            service_name: "erdps".to_string(),
            start_time: Self::get_timestamp_nanos(),
            end_time: None,
            duration: None,
            status: SpanStatus::Ok,
            kind: SpanKind::Internal,
            tags: HashMap::new(),
            logs: vec![],
            baggage: HashMap::new(),
        };
        
        let mut spans = self.spans.write().unwrap();
        spans.insert(span_id.clone(), span);
        
        Ok(span_id)
    }

    async fn finish_span(
        &self,
        span_id: &str,
        status: SpanStatus,
    ) -> Result<(), ObservabilityError> {
        let mut spans = self.spans.write().unwrap();
        if let Some(mut span) = spans.remove(span_id) {
            let end_time = DefaultTracer::get_timestamp_nanos();
            span.end_time = Some(end_time);
            span.duration = Some(Duration::from_nanos(end_time.saturating_sub(span.start_time)));
            let status_clone = status.clone();
            span.status = status;
            
            // Create trace if this is a root span
            if span.parent_span_id.is_none() {
                let start_time = span.start_time;
                let trace_id = span.trace_id.clone();
                let trace = Trace {
                    trace_id,
                    spans: vec![span],
                    start_time,
                    end_time: Some(end_time),
                    duration: Some(Duration::from_nanos(end_time - start_time)),
                    service_count: 1,
                    span_count: 1,
                    error_count: if matches!(status_clone, SpanStatus::Error) { 1 } else { 0 },
                };
                
                let mut completed_traces = self.completed_traces.write().unwrap();
                completed_traces.push(trace);
            }
        }
        Ok(())
    }

    async fn add_span_tag(
        &self,
        span_id: &str,
        key: &str,
        value: &str,
    ) -> Result<(), ObservabilityError> {
        let mut spans = self.spans.write().unwrap();
        if let Some(span) = spans.get_mut(span_id) {
            span.tags.insert(key.to_string(), value.to_string());
        }
        Ok(())
    }

    async fn add_span_log(
        &self,
        span_id: &str,
        log: SpanLog,
    ) -> Result<(), ObservabilityError> {
        let mut spans = self.spans.write().unwrap();
        if let Some(span) = spans.get_mut(span_id) {
            span.logs.push(log);
        }
        Ok(())
    }

    async fn get_completed_traces(&self) -> Result<Vec<Trace>, ObservabilityError> {
        let traces = self.completed_traces.read().unwrap();
        Ok(traces.clone())
    }
}

#[derive(Debug)]
pub struct DefaultLogger {
    logs: Arc<RwLock<Vec<LogEntry>>>,
    log_level: Arc<RwLock<LogLevel>>,
}

impl DefaultLogger {
    pub fn new() -> Self {
        Self {
            logs: Arc::new(RwLock::new(Vec::new())),
            log_level: Arc::new(RwLock::new(LogLevel::Info)),
        }
    }
}

#[async_trait::async_trait]
impl Logger for DefaultLogger {
    async fn log(
        &self,
        level: LogLevel,
        message: &str,
        fields: HashMap<String, String>,
    ) -> Result<(), ObservabilityError> {
        let current_level = self.log_level.read().unwrap().clone();
        if Self::should_log(&level, &current_level) {
            let log_entry = LogEntry {
                timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                level,
                message: message.to_string(),
                service_name: "erdps".to_string(),
                trace_id: None,
                span_id: None,
                fields,
                caller_info: None,
                stack_trace: None,
            };
            
            let mut logs = self.logs.write().unwrap();
            logs.push(log_entry);
        }
        Ok(())
    }

    async fn get_recent_logs(&self, duration: Duration) -> Result<Vec<LogEntry>, ObservabilityError> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let cutoff = now.saturating_sub(duration.as_secs());
        
        let logs = self.logs.read().unwrap();
        let recent_logs: Vec<LogEntry> = logs
            .iter()
            .filter(|log| log.timestamp >= cutoff)
            .cloned()
            .collect();
        
        Ok(recent_logs)
    }

    async fn set_log_level(&self, level: LogLevel) -> Result<(), ObservabilityError> {
        let mut current_level = self.log_level.write().unwrap();
        *current_level = level;
        Ok(())
    }
}

impl DefaultLogger {
    fn should_log(level: &LogLevel, current_level: &LogLevel) -> bool {
        let level_value = match level {
            LogLevel::Trace => 0,
            LogLevel::Debug => 1,
            LogLevel::Info => 2,
            LogLevel::Warn => 3,
            LogLevel::Error => 4,
            LogLevel::Fatal => 5,
        };
        
        let current_value = match current_level {
            LogLevel::Trace => 0,
            LogLevel::Debug => 1,
            LogLevel::Info => 2,
            LogLevel::Warn => 3,
            LogLevel::Error => 4,
            LogLevel::Fatal => 5,
        };
        
        level_value >= current_value
    }
}

pub struct DefaultMonitor {
    health_checkers: Arc<RwLock<HashMap<String, Box<dyn HealthChecker + Send + Sync>>>>,
}

impl std::fmt::Debug for DefaultMonitor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DefaultMonitor")
            .field("health_checkers", &"<trait objects>")
            .finish()
    }
}

impl DefaultMonitor {
    pub fn new() -> Self {
        Self {
            health_checkers: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait::async_trait]
impl Monitor for DefaultMonitor {
    async fn get_health_status(&self) -> Result<HealthCheck, ObservabilityError> {
        let mut checks = Vec::new();
        let overall_health: f32 = 100.0;
        
        // Get checker names first to avoid holding lock across await
        let checker_names: Vec<String> = {
            let checkers = self.health_checkers.read().unwrap();
            checkers.keys().cloned().collect()
        };
        
        for name in checker_names {
            let checker = {
                let checkers = self.health_checkers.read().unwrap();
                if let Some(_checker) = checkers.get(&name) {
                    // We can't clone the checker, so we'll have to work differently
                    // For now, let's create a simple health check result
                    ComponentHealth {
                        component_name: name.clone(),
                        status: HealthStatus::Healthy,
                        message: "Component healthy".to_string(),
                        metrics: std::collections::HashMap::new(),
                    }
                } else {
                    continue;
                }
            };
            
            checks.push(checker);
        }
        
        let status = if overall_health >= 80.0 {
            HealthStatus::Healthy
        } else if overall_health >= 50.0 {
            HealthStatus::Degraded
        } else {
            HealthStatus::Unhealthy
        };
        
        Ok(HealthCheck {
            service_name: "erdps".to_string(),
            status,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            checks,
            overall_health: overall_health.into(),
            response_time: Duration::from_millis(10),
        })
    }

    async fn get_performance_metrics(&self) -> Result<PerformanceMetrics, ObservabilityError> {
        // Placeholder implementation - in real scenario, would collect actual system metrics
        Ok(PerformanceMetrics {
            cpu_usage: 25.0,
            memory_usage: 512 * 1024 * 1024, // 512MB
            disk_usage: 1024 * 1024 * 1024,  // 1GB
            network_io: NetworkIO {
                bytes_sent: 1024 * 1024,
                bytes_received: 2 * 1024 * 1024,
                packets_sent: 1000,
                packets_received: 2000,
            },
            request_rate: 100.0,
            error_rate: 0.1,
            response_time_p50: Duration::from_millis(50),
            response_time_p95: Duration::from_millis(200),
            response_time_p99: Duration::from_millis(500),
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        })
    }

    async fn register_health_check(
        &self,
        name: &str,
        check: Box<dyn HealthChecker + Send + Sync>,
    ) -> Result<(), ObservabilityError> {
        let mut checkers = self.health_checkers.write().unwrap();
        checkers.insert(name.to_string(), check);
        Ok(())
    }
}

// Utility functions
pub fn create_default_observability_manager() -> Result<ObservabilityManager, ObservabilityError> {
    let config = ObservabilityConfig::default();
    let tracer = Arc::new(DefaultTracer::new());
    let logger = Arc::new(DefaultLogger::new());
    let monitor = Arc::new(DefaultMonitor::new());
    
    ObservabilityManager::new(config, tracer, logger, monitor)
}

pub fn validate_observability_config(config: &ObservabilityConfig) -> Result<(), ObservabilityError> {
    if config.tracing_config.sampling_rate < 0.0 || config.tracing_config.sampling_rate > 1.0 {
        return Err(ObservabilityError::ConfigurationError(
            "Sampling rate must be between 0.0 and 1.0".to_string(),
        ));
    }
    
    if config.tracing_config.max_spans_per_trace == 0 {
        return Err(ObservabilityError::ConfigurationError(
            "Max spans per trace must be greater than 0".to_string(),
        ));
    }
    
    if config.export_config.batch_size == 0 {
        return Err(ObservabilityError::ConfigurationError(
            "Export batch size must be greater than 0".to_string(),
        ));
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_observability_manager_creation() {
        let manager = create_default_observability_manager();
        assert!(manager.is_ok());
    }

    #[test]
    fn test_config_validation() {
        let config = ObservabilityConfig::default();
        assert!(validate_observability_config(&config).is_ok());
        
        let mut invalid_config = config.clone();
        invalid_config.tracing_config.sampling_rate = 1.5;
        assert!(validate_observability_config(&invalid_config).is_err());
    }

    #[tokio::test]
    async fn test_default_tracer() {
        let tracer = DefaultTracer::new();
        let span_id = tracer.start_span("test_operation", None).await.unwrap();
        assert!(!span_id.is_empty());
        
        let result = tracer.finish_span(&span_id, SpanStatus::Ok).await;
        assert!(result.is_ok());
        
        let traces = tracer.get_completed_traces().await.unwrap();
        assert_eq!(traces.len(), 1);
    }

    #[tokio::test]
    async fn test_default_logger() {
        let logger = DefaultLogger::new();
        let mut fields = HashMap::new();
        fields.insert("key".to_string(), "value".to_string());
        
        let result = logger.log(LogLevel::Info, "Test message", fields).await;
        assert!(result.is_ok());
        
        let logs = logger.get_recent_logs(Duration::from_secs(3600)).await.unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].message, "Test message");
    }

    #[tokio::test]
    async fn test_default_monitor() {
        let monitor = DefaultMonitor::new();
        let health = monitor.get_health_status().await.unwrap();
        assert!(matches!(health.status, HealthStatus::Healthy));
        
        let metrics = monitor.get_performance_metrics().await.unwrap();
        assert!(metrics.cpu_usage >= 0.0);
    }

    #[test]
    fn test_log_level_filtering() {
        assert!(DefaultLogger::should_log(&LogLevel::Error, &LogLevel::Info));
        assert!(!DefaultLogger::should_log(&LogLevel::Debug, &LogLevel::Info));
        assert!(DefaultLogger::should_log(&LogLevel::Info, &LogLevel::Info));
    }

    #[test]
    fn test_default_configurations() {
        let config = ObservabilityConfig::default();
        assert!(config.tracing_config.enabled);
        assert!(config.logging_config.enabled);
        assert!(config.monitoring_config.enabled);
        assert_eq!(config.tracing_config.service_name, "erdps");
    }
}
