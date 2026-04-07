use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::time::interval;

// Error handling
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MetricsError {
    CollectionError(String),
    ExportError(String),
    ConfigurationError(String),
    StorageError(String),
    NetworkError(String),
}

impl std::fmt::Display for MetricsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MetricsError::CollectionError(msg) => write!(f, "Metrics collection error: {}", msg),
            MetricsError::ExportError(msg) => write!(f, "Metrics export error: {}", msg),
            MetricsError::ConfigurationError(msg) => write!(f, "Configuration error: {}", msg),
            MetricsError::StorageError(msg) => write!(f, "Storage error: {}", msg),
            MetricsError::NetworkError(msg) => write!(f, "Network error: {}", msg),
        }
    }
}

impl std::error::Error for MetricsError {}

// Configuration structures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    pub collection_config: CollectionConfig,
    pub storage_config: StorageConfig,
    pub export_config: ExportConfig,
    pub alerting_config: AlertingConfig,
    pub retention_config: RetentionConfig,
    pub performance_config: PerformanceConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionConfig {
    pub collection_interval: Duration,
    pub batch_size: usize,
    pub buffer_size: usize,
    pub enabled_metrics: Vec<MetricType>,
    pub sampling_rate: f64,
    pub collection_timeout: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub storage_type: StorageType,
    pub connection_string: String,
    pub database_name: String,
    pub table_prefix: String,
    pub compression_enabled: bool,
    pub encryption_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportConfig {
    pub exporters: Vec<ExporterConfig>,
    pub export_interval: Duration,
    pub export_format: ExportFormat,
    pub compression_enabled: bool,
    pub retry_config: RetryConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExporterConfig {
    pub exporter_type: ExporterType,
    pub endpoint: String,
    pub authentication: AuthenticationConfig,
    pub headers: HashMap<String, String>,
    pub timeout: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertingConfig {
    pub enabled: bool,
    pub alert_rules: Vec<AlertRule>,
    pub notification_channels: Vec<NotificationChannel>,
    pub escalation_policies: Vec<EscalationPolicy>,
    pub cooldown_period: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionConfig {
    pub default_retention: Duration,
    pub metric_specific_retention: HashMap<MetricType, Duration>,
    pub aggregation_rules: Vec<AggregationRule>,
    pub cleanup_interval: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    pub max_memory_usage: usize,
    pub max_cpu_usage: f64,
    pub max_disk_usage: usize,
    pub collection_parallelism: usize,
    pub processing_queue_size: usize,
}

// Enums
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum MetricType {
    Counter,
    Gauge,
    Histogram,
    Summary,
    Timer,
    Rate,
    Distribution,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageType {
    InMemory,
    PostgreSQL,
    InfluxDB,
    Prometheus,
    Elasticsearch,
    TimescaleDB,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExporterType {
    Prometheus,
    Grafana,
    Datadog,
    NewRelic,
    Splunk,
    ElasticSearch,
    InfluxDB,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExportFormat {
    JSON,
    Prometheus,
    OpenTelemetry,
    StatsD,
    Graphite,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComparisonOperator {
    GreaterThan,
    LessThan,
    Equal,
    NotEqual,
    GreaterThanOrEqual,
    LessThanOrEqual,
}

// Data structures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metric {
    pub name: String,
    pub metric_type: MetricType,
    pub value: MetricValue,
    pub labels: HashMap<String, String>,
    pub timestamp: u64,
    pub source: String,
    pub unit: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MetricValue {
    Counter(u64),
    Gauge(f64),
    Histogram(HistogramData),
    Summary(SummaryData),
    Timer(Duration),
    Rate(f64),
    Distribution(Vec<f64>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistogramData {
    pub buckets: Vec<HistogramBucket>,
    pub count: u64,
    pub sum: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistogramBucket {
    pub upper_bound: f64,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SummaryData {
    pub count: u64,
    pub sum: f64,
    pub quantiles: Vec<Quantile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Quantile {
    pub quantile: f64,
    pub value: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub metric_name: String,
    pub condition: AlertCondition,
    pub severity: AlertSeverity,
    pub enabled: bool,
    pub notification_channels: Vec<String>,
    pub cooldown_period: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertCondition {
    pub operator: ComparisonOperator,
    pub threshold: f64,
    pub duration: Duration,
    pub aggregation_window: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationChannel {
    pub id: String,
    pub channel_type: NotificationChannelType,
    pub configuration: HashMap<String, String>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NotificationChannelType {
    Email,
    Slack,
    PagerDuty,
    Webhook,
    SMS,
    Teams,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationPolicy {
    pub id: String,
    pub name: String,
    pub steps: Vec<EscalationStep>,
    pub repeat_interval: Option<Duration>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationStep {
    pub delay: Duration,
    pub notification_channels: Vec<String>,
    pub auto_resolve: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregationRule {
    pub metric_pattern: String,
    pub aggregation_type: AggregationType,
    pub window_size: Duration,
    pub retention_period: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AggregationType {
    Sum,
    Average,
    Min,
    Max,
    Count,
    Percentile(f64),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationConfig {
    pub auth_type: AuthenticationType,
    pub credentials: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthenticationType {
    None,
    Basic,
    Bearer,
    ApiKey,
    OAuth2,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    pub max_retries: u32,
    pub initial_delay: Duration,
    pub max_delay: Duration,
    pub backoff_multiplier: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsStatistics {
    pub total_metrics_collected: u64,
    pub metrics_per_second: f64,
    pub collection_errors: u64,
    pub export_errors: u64,
    pub storage_usage: u64,
    pub memory_usage: u64,
    pub active_alerts: u64,
    pub uptime: Duration,
    pub last_collection_time: u64,
    pub last_export_time: u64,
}

// Main metrics manager
#[derive(Debug)]
pub struct MetricsManager {
    config: Arc<RwLock<MetricsConfig>>,
    collectors: Arc<RwLock<HashMap<String, Box<dyn MetricCollector + Send + Sync>>>>,
    storage: Arc<dyn MetricStorage + Send + Sync>,
    exporters: Arc<RwLock<Vec<Box<dyn MetricExporter + Send + Sync>>>>,
    alerting: Arc<dyn AlertingManager + Send + Sync>,
    statistics: Arc<RwLock<MetricsStatistics>>,
    shutdown_tx: Option<mpsc::Sender<()>>,
}

impl MetricsManager {
    pub fn new(
        config: MetricsConfig,
        storage: Arc<dyn MetricStorage + Send + Sync>,
        alerting: Arc<dyn AlertingManager + Send + Sync>,
    ) -> Result<Self, MetricsError> {
        Ok(Self {
            config: Arc::new(RwLock::new(config)),
            collectors: Arc::new(RwLock::new(HashMap::new())),
            storage,
            exporters: Arc::new(RwLock::new(Vec::new())),
            alerting,
            statistics: Arc::new(RwLock::new(MetricsStatistics::default())),
            shutdown_tx: None,
        })
    }

    pub async fn start(&mut self) -> Result<(), MetricsError> {
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);
        self.shutdown_tx = Some(shutdown_tx);

        // Start collection loop
        let config = self.config.clone();
        let collectors = self.collectors.clone();
        let storage = self.storage.clone();
        let statistics = self.statistics.clone();

        tokio::spawn(async move {
            let mut interval = {
                let config = config.read().unwrap();
                interval(config.collection_config.collection_interval)
            };

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        if let Err(e) = Self::collect_metrics(&collectors, &storage, &statistics).await {
                            eprintln!("Metrics collection error: {}", e);
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        break;
                    }
                }
            }
        });

        // Start export loop
        let config = self.config.clone();
        let exporters = self.exporters.clone();
        let storage = self.storage.clone();

        tokio::spawn(async move {
            let mut interval = {
                let config = config.read().unwrap();
                interval(config.export_config.export_interval)
            };

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        if let Err(e) = Self::export_metrics(&exporters, &storage).await {
                            eprintln!("Metrics export error: {}", e);
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    pub async fn stop(&mut self) -> Result<(), MetricsError> {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(()).await;
        }
        Ok(())
    }

    pub async fn register_collector(
        &self,
        name: String,
        collector: Box<dyn MetricCollector + Send + Sync>,
    ) -> Result<(), MetricsError> {
        let mut collectors = self.collectors.write().unwrap();
        collectors.insert(name, collector);
        Ok(())
    }

    pub async fn register_exporter(
        &self,
        exporter: Box<dyn MetricExporter + Send + Sync>,
    ) -> Result<(), MetricsError> {
        let mut exporters = self.exporters.write().unwrap();
        exporters.push(exporter);
        Ok(())
    }

    pub async fn get_statistics(&self) -> MetricsStatistics {
        self.statistics.read().unwrap().clone()
    }

    pub async fn update_config(&self, config: MetricsConfig) -> Result<(), MetricsError> {
        let mut current_config = self.config.write().unwrap();
        *current_config = config;
        Ok(())
    }

    async fn collect_metrics(
        collectors: &Arc<RwLock<HashMap<String, Box<dyn MetricCollector + Send + Sync>>>>,
        storage: &Arc<dyn MetricStorage + Send + Sync>,
        statistics: &Arc<RwLock<MetricsStatistics>>,
    ) -> Result<(), MetricsError> {
        let start_time = Instant::now();
        let collectors = collectors.read().unwrap();
        let mut all_metrics = Vec::new();

        for (name, collector) in collectors.iter() {
            match collector.collect().await {
                Ok(mut metrics) => {
                    all_metrics.append(&mut metrics);
                }
                Err(e) => {
                    eprintln!("Error collecting metrics from {}: {}", name, e);
                    let mut stats = statistics.write().unwrap();
                    stats.collection_errors += 1;
                }
            }
        }

        if !all_metrics.is_empty() {
            storage.store_metrics(all_metrics.clone()).await?;
            
            let mut stats = statistics.write().unwrap();
            stats.total_metrics_collected += all_metrics.len() as u64;
            stats.last_collection_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            
            let collection_duration = start_time.elapsed();
            if collection_duration.as_secs() > 0 {
                stats.metrics_per_second = all_metrics.len() as f64 / collection_duration.as_secs_f64();
            }
        }

        Ok(())
    }

    async fn export_metrics(
        exporters: &Arc<RwLock<Vec<Box<dyn MetricExporter + Send + Sync>>>>,
        storage: &Arc<dyn MetricStorage + Send + Sync>,
    ) -> Result<(), MetricsError> {
        let exporters = exporters.read().unwrap();
        let metrics = storage.get_recent_metrics(Duration::from_secs(3600)).await?;

        for exporter in exporters.iter() {
            if let Err(e) = exporter.export(&metrics).await {
                eprintln!("Export error: {}", e);
            }
        }

        Ok(())
    }
}

// Traits
pub trait MetricCollector {
    async fn collect(&self) -> Result<Vec<Metric>, MetricsError>;
    fn get_name(&self) -> &str;
    fn is_enabled(&self) -> bool;
}

pub trait MetricStorage {
    async fn store_metrics(&self, metrics: Vec<Metric>) -> Result<(), MetricsError>;
    async fn get_metrics(
        &self,
        query: MetricQuery,
    ) -> Result<Vec<Metric>, MetricsError>;
    async fn get_recent_metrics(
        &self,
        duration: Duration,
    ) -> Result<Vec<Metric>, MetricsError>;
    async fn cleanup_old_metrics(&self, retention: Duration) -> Result<(), MetricsError>;
}

pub trait MetricExporter {
    async fn export(&self, metrics: &[Metric]) -> Result<(), MetricsError>;
    fn get_format(&self) -> ExportFormat;
    fn is_enabled(&self) -> bool;
}

pub trait AlertingManager {
    async fn evaluate_alerts(&self, metrics: &[Metric]) -> Result<Vec<Alert>, MetricsError>;
    async fn send_alert(&self, alert: &Alert) -> Result<(), MetricsError>;
    async fn resolve_alert(&self, alert_id: &str) -> Result<(), MetricsError>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricQuery {
    pub metric_names: Vec<String>,
    pub labels: HashMap<String, String>,
    pub start_time: u64,
    pub end_time: u64,
    pub aggregation: Option<AggregationType>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub rule_id: String,
    pub metric_name: String,
    pub severity: AlertSeverity,
    pub message: String,
    pub timestamp: u64,
    pub resolved: bool,
    pub labels: HashMap<String, String>,
}

// Default implementations
impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            collection_config: CollectionConfig::default(),
            storage_config: StorageConfig::default(),
            export_config: ExportConfig::default(),
            alerting_config: AlertingConfig::default(),
            retention_config: RetentionConfig::default(),
            performance_config: PerformanceConfig::default(),
        }
    }
}

impl Default for CollectionConfig {
    fn default() -> Self {
        Self {
            collection_interval: Duration::from_secs(10),
            batch_size: 1000,
            buffer_size: 10000,
            enabled_metrics: vec![
                MetricType::Counter,
                MetricType::Gauge,
                MetricType::Histogram,
            ],
            sampling_rate: 1.0,
            collection_timeout: Duration::from_secs(30),
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            storage_type: StorageType::InMemory,
            connection_string: "memory://".to_string(),
            database_name: "metrics".to_string(),
            table_prefix: "erdps_".to_string(),
            compression_enabled: true,
            encryption_enabled: false,
        }
    }
}

impl Default for ExportConfig {
    fn default() -> Self {
        Self {
            exporters: vec![],
            export_interval: Duration::from_secs(60),
            export_format: ExportFormat::Prometheus,
            compression_enabled: true,
            retry_config: RetryConfig::default(),
        }
    }
}

impl Default for AlertingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            alert_rules: vec![],
            notification_channels: vec![],
            escalation_policies: vec![],
            cooldown_period: Duration::from_secs(300),
        }
    }
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            default_retention: Duration::from_secs(86400 * 30), // 30 days
            metric_specific_retention: HashMap::new(),
            aggregation_rules: vec![],
            cleanup_interval: Duration::from_secs(3600),
        }
    }
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            max_memory_usage: 1024 * 1024 * 1024, // 1GB
            max_cpu_usage: 80.0,
            max_disk_usage: 10 * 1024 * 1024 * 1024, // 10GB
            collection_parallelism: 4,
            processing_queue_size: 10000,
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

impl Default for MetricsStatistics {
    fn default() -> Self {
        Self {
            total_metrics_collected: 0,
            metrics_per_second: 0.0,
            collection_errors: 0,
            export_errors: 0,
            storage_usage: 0,
            memory_usage: 0,
            active_alerts: 0,
            uptime: Duration::from_secs(0),
            last_collection_time: 0,
            last_export_time: 0,
        }
    }
}

// Utility functions
pub fn create_default_metrics_manager() -> Result<MetricsManager, MetricsError> {
    let config = MetricsConfig::default();
    let storage = Arc::new(InMemoryMetricStorage::new());
    let alerting = Arc::new(DefaultAlertingManager::new());
    
    MetricsManager::new(config, storage, alerting)
}

pub fn validate_metrics_config(config: &MetricsConfig) -> Result<(), MetricsError> {
    if config.collection_config.collection_interval.as_secs() == 0 {
        return Err(MetricsError::ConfigurationError(
            "Collection interval must be greater than 0".to_string(),
        ));
    }
    
    if config.collection_config.batch_size == 0 {
        return Err(MetricsError::ConfigurationError(
            "Batch size must be greater than 0".to_string(),
        ));
    }
    
    if config.collection_config.sampling_rate < 0.0 || config.collection_config.sampling_rate > 1.0 {
        return Err(MetricsError::ConfigurationError(
            "Sampling rate must be between 0.0 and 1.0".to_string(),
        ));
    }
    
    Ok(())
}

// Default implementations for traits
#[derive(Debug)]
pub struct InMemoryMetricStorage {
    metrics: Arc<RwLock<Vec<Metric>>>,
}

impl InMemoryMetricStorage {
    pub fn new() -> Self {
        Self {
            metrics: Arc::new(RwLock::new(Vec::new())),
        }
    }
}

#[async_trait::async_trait]
impl MetricStorage for InMemoryMetricStorage {
    async fn store_metrics(&self, mut metrics: Vec<Metric>) -> Result<(), MetricsError> {
        let mut storage = self.metrics.write().unwrap();
        storage.append(&mut metrics);
        Ok(())
    }

    async fn get_metrics(&self, query: MetricQuery) -> Result<Vec<Metric>, MetricsError> {
        let storage = self.metrics.read().unwrap();
        let filtered: Vec<Metric> = storage
            .iter()
            .filter(|metric| {
                query.metric_names.is_empty() || query.metric_names.contains(&metric.name)
            })
            .filter(|metric| {
                metric.timestamp >= query.start_time && metric.timestamp <= query.end_time
            })
            .cloned()
            .collect();
        Ok(filtered)
    }

    async fn get_recent_metrics(&self, duration: Duration) -> Result<Vec<Metric>, MetricsError> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let start_time = now.saturating_sub(duration.as_secs());
        
        let query = MetricQuery {
            metric_names: vec![],
            labels: HashMap::new(),
            start_time,
            end_time: now,
            aggregation: None,
        };
        
        self.get_metrics(query).await
    }

    async fn cleanup_old_metrics(&self, retention: Duration) -> Result<(), MetricsError> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let cutoff_time = now.saturating_sub(retention.as_secs());
        
        let mut storage = self.metrics.write().unwrap();
        storage.retain(|metric| metric.timestamp >= cutoff_time);
        Ok(())
    }
}

#[derive(Debug)]
pub struct DefaultAlertingManager {
    alerts: Arc<RwLock<Vec<Alert>>>,
}

impl DefaultAlertingManager {
    pub fn new() -> Self {
        Self {
            alerts: Arc::new(RwLock::new(Vec::new())),
        }
    }
}

#[async_trait::async_trait]
impl AlertingManager for DefaultAlertingManager {
    async fn evaluate_alerts(&self, _metrics: &[Metric]) -> Result<Vec<Alert>, MetricsError> {
        // Placeholder implementation
        Ok(vec![])
    }

    async fn send_alert(&self, alert: &Alert) -> Result<(), MetricsError> {
        let mut alerts = self.alerts.write().unwrap();
        alerts.push(alert.clone());
        Ok(())
    }

    async fn resolve_alert(&self, alert_id: &str) -> Result<(), MetricsError> {
        let mut alerts = self.alerts.write().unwrap();
        if let Some(alert) = alerts.iter_mut().find(|a| a.id == alert_id) {
            alert.resolved = true;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_metrics_manager_creation() {
        let manager = create_default_metrics_manager();
        assert!(manager.is_ok());
    }

    #[test]
    fn test_config_validation() {
        let config = MetricsConfig::default();
        assert!(validate_metrics_config(&config).is_ok());
        
        let mut invalid_config = config.clone();
        invalid_config.collection_config.batch_size = 0;
        assert!(validate_metrics_config(&invalid_config).is_err());
    }

    #[tokio::test]
    async fn test_in_memory_storage() {
        let storage = InMemoryMetricStorage::new();
        let metric = Metric {
            name: "test_metric".to_string(),
            metric_type: MetricType::Counter,
            value: MetricValue::Counter(42),
            labels: HashMap::new(),
            timestamp: 1234567890,
            source: "test".to_string(),
            unit: None,
            description: None,
        };
        
        let result = storage.store_metrics(vec![metric.clone()]).await;
        assert!(result.is_ok());
        
        let query = MetricQuery {
            metric_names: vec!["test_metric".to_string()],
            labels: HashMap::new(),
            start_time: 0,
            end_time: u64::MAX,
            aggregation: None,
        };
        
        let retrieved = storage.get_metrics(query).await.unwrap();
        assert_eq!(retrieved.len(), 1);
        assert_eq!(retrieved[0].name, "test_metric");
    }

    #[test]
    fn test_default_configurations() {
        let config = MetricsConfig::default();
        assert_eq!(config.collection_config.collection_interval, Duration::from_secs(10));
        assert_eq!(config.storage_config.storage_type, StorageType::InMemory);
        assert_eq!(config.export_config.export_format, ExportFormat::Prometheus);
    }

    #[tokio::test]
    async fn test_alerting_manager() {
        let manager = DefaultAlertingManager::new();
        let alert = Alert {
            id: "test_alert".to_string(),
            rule_id: "test_rule".to_string(),
            metric_name: "test_metric".to_string(),
            severity: AlertSeverity::High,
            message: "Test alert".to_string(),
            timestamp: 1234567890,
            resolved: false,
            labels: HashMap::new(),
        };
        
        let result = manager.send_alert(&alert).await;
        assert!(result.is_ok());
        
        let result = manager.resolve_alert("test_alert").await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_metric_value_types() {
        let counter = MetricValue::Counter(100);
        let gauge = MetricValue::Gauge(75.5);
        let timer = MetricValue::Timer(Duration::from_millis(250));
        
        match counter {
            MetricValue::Counter(value) => assert_eq!(value, 100),
            _ => panic!("Expected counter value"),
        }
        
        match gauge {
            MetricValue::Gauge(value) => assert_eq!(value, 75.5),
            _ => panic!("Expected gauge value"),
        }
        
        match timer {
            MetricValue::Timer(duration) => assert_eq!(duration, Duration::from_millis(250)),
            _ => panic!("Expected timer value"),
        }
    }
}
