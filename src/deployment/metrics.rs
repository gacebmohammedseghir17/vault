//! Deployment Metrics and Observability
//!
//! This module provides comprehensive metrics collection, monitoring,
//! and observability capabilities for deployment systems.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use tracing::{debug, error};

use crate::core::error::Result;

/// Deployment metrics manager
#[derive(Debug)]
pub struct DeploymentMetricsManager {
    /// Metrics store
    metrics_store: Arc<RwLock<MetricsStore>>,
    /// Metrics configuration
    config: MetricsConfig,
    /// Metrics collectors
    collectors: Arc<RwLock<HashMap<String, Box<dyn MetricsCollector + Send + Sync>>>>,
    /// Metrics exporters
    exporters: Arc<RwLock<Vec<Box<dyn MetricsExporter + Send + Sync>>>>,
}

/// Metrics store
#[derive(Debug, Clone)]
pub struct MetricsStore {
    /// Time series metrics
    time_series: HashMap<String, TimeSeries>,
    /// Counter metrics
    counters: HashMap<String, Counter>,
    /// Gauge metrics
    gauges: HashMap<String, Gauge>,
    /// Histogram metrics
    histograms: HashMap<String, Histogram>,
    /// Summary metrics
    summaries: HashMap<String, Summary>,
    /// Custom metrics
    custom_metrics: HashMap<String, CustomMetric>,
}

/// Time series data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeSeries {
    /// Metric name
    pub name: String,
    /// Data points
    pub data_points: Vec<DataPoint>,
    /// Metric metadata
    pub metadata: MetricMetadata,
    /// Retention policy
    pub retention: RetentionPolicy,
}

/// Data point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataPoint {
    /// Timestamp
    pub timestamp: SystemTime,
    /// Value
    pub value: f64,
    /// Labels
    pub labels: HashMap<String, String>,
    /// Tags
    pub tags: Vec<String>,
}

/// Counter metric
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Counter {
    /// Counter name
    pub name: String,
    /// Current value
    pub value: u64,
    /// Labels
    pub labels: HashMap<String, String>,
    /// Last updated
    pub last_updated: SystemTime,
    /// Metadata
    pub metadata: MetricMetadata,
}

/// Gauge metric
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Gauge {
    /// Gauge name
    pub name: String,
    /// Current value
    pub value: f64,
    /// Labels
    pub labels: HashMap<String, String>,
    /// Last updated
    pub last_updated: SystemTime,
    /// Metadata
    pub metadata: MetricMetadata,
}

/// Histogram metric
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Histogram {
    /// Histogram name
    pub name: String,
    /// Buckets
    pub buckets: Vec<HistogramBucket>,
    /// Total count
    pub count: u64,
    /// Sum of all values
    pub sum: f64,
    /// Labels
    pub labels: HashMap<String, String>,
    /// Last updated
    pub last_updated: SystemTime,
    /// Metadata
    pub metadata: MetricMetadata,
}

/// Histogram bucket
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistogramBucket {
    /// Upper bound
    pub upper_bound: f64,
    /// Count of values in bucket
    pub count: u64,
}

/// Summary metric
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Summary {
    /// Summary name
    pub name: String,
    /// Quantiles
    pub quantiles: Vec<Quantile>,
    /// Total count
    pub count: u64,
    /// Sum of all values
    pub sum: f64,
    /// Labels
    pub labels: HashMap<String, String>,
    /// Last updated
    pub last_updated: SystemTime,
    /// Metadata
    pub metadata: MetricMetadata,
}

/// Quantile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Quantile {
    /// Quantile value (0.0 to 1.0)
    pub quantile: f64,
    /// Value at quantile
    pub value: f64,
}

/// Custom metric
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomMetric {
    /// Metric name
    pub name: String,
    /// Metric type
    pub metric_type: CustomMetricType,
    /// Metric value
    pub value: serde_json::Value,
    /// Labels
    pub labels: HashMap<String, String>,
    /// Last updated
    pub last_updated: SystemTime,
    /// Metadata
    pub metadata: MetricMetadata,
}

/// Custom metric types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CustomMetricType {
    Event,
    State,
    Trace,
    Log,
    Custom(String),
}

/// Metric metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricMetadata {
    /// Description
    pub description: String,
    /// Unit
    pub unit: String,
    /// Metric type
    pub metric_type: MetricType,
    /// Collection interval
    pub collection_interval: Duration,
    /// Tags
    pub tags: Vec<String>,
    /// Created timestamp
    pub created_at: SystemTime,
}

/// Metric types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MetricType {
    Counter,
    Gauge,
    Histogram,
    Summary,
    TimeSeries,
    Custom,
}

/// Retention policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPolicy {
    /// Retention duration
    pub duration: Duration,
    /// Aggregation rules
    pub aggregation: Vec<AggregationRule>,
    /// Compression settings
    pub compression: CompressionSettings,
}

/// Aggregation rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregationRule {
    /// Aggregation interval
    pub interval: Duration,
    /// Aggregation function
    pub function: AggregationFunction,
    /// Retention after aggregation
    pub retention: Duration,
}

/// Aggregation functions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AggregationFunction {
    Average,
    Sum,
    Min,
    Max,
    Count,
    Percentile(f64),
    Custom(String),
}

/// Compression settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressionSettings {
    /// Enable compression
    pub enabled: bool,
    /// Compression algorithm
    pub algorithm: CompressionAlgorithm,
    /// Compression level
    pub level: u8,
}

/// Compression algorithms
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CompressionAlgorithm {
    Gzip,
    Zstd,
    Lz4,
    Snappy,
}

/// Metrics configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    /// Collection configuration
    pub collection: CollectionConfig,
    /// Storage configuration
    pub storage: StorageConfig,
    /// Export configuration
    pub export: ExportConfig,
    /// Alerting configuration
    pub alerting: AlertingConfig,
    /// Performance configuration
    pub performance: PerformanceConfig,
}

/// Collection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionConfig {
    /// Enable collection
    pub enabled: bool,
    /// Collection interval
    pub interval: Duration,
    /// Batch size
    pub batch_size: usize,
    /// Collection timeout
    pub timeout: Duration,
    /// Retry configuration
    pub retry: RetryConfig,
}

/// Retry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum retries
    pub max_retries: u32,
    /// Retry delay
    pub delay: Duration,
    /// Backoff strategy
    pub backoff: BackoffStrategy,
}

/// Backoff strategies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BackoffStrategy {
    Fixed,
    Linear,
    Exponential,
    Custom(String),
}

/// Storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Storage backend
    pub backend: StorageBackend,
    /// Storage path
    pub path: String,
    /// Retention policy
    pub retention: RetentionPolicy,
    /// Sharding configuration
    pub sharding: ShardingConfig,
}

/// Storage backends
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageBackend {
    Memory,
    File,
    Database,
    TimeSeries,
    Custom(String),
}

/// Sharding configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardingConfig {
    /// Enable sharding
    pub enabled: bool,
    /// Number of shards
    pub shard_count: u32,
    /// Sharding strategy
    pub strategy: ShardingStrategy,
}

/// Sharding strategies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ShardingStrategy {
    Hash,
    Range,
    Time,
    Custom(String),
}

/// Export configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportConfig {
    /// Enable export
    pub enabled: bool,
    /// Export interval
    pub interval: Duration,
    /// Export format
    pub format: ExportFormat,
    /// Export destinations
    pub destinations: Vec<ExportDestination>,
}

/// Export formats
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExportFormat {
    Prometheus,
    OpenTelemetry,
    JSON,
    CSV,
    Custom(String),
}

/// Export destination
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportDestination {
    /// Destination type
    pub destination_type: DestinationType,
    /// Destination configuration
    pub config: HashMap<String, String>,
    /// Authentication
    pub auth: Option<AuthConfig>,
}

/// Destination types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DestinationType {
    HTTP,
    File,
    Database,
    MessageQueue,
    Custom(String),
}

/// Authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// Authentication type
    pub auth_type: AuthType,
    /// Credentials
    pub credentials: HashMap<String, String>,
}

/// Authentication types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthType {
    Basic,
    Bearer,
    ApiKey,
    OAuth2,
    Custom(String),
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
    /// Alert manager configuration
    pub manager: AlertManagerConfig,
}

/// Alert rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    /// Rule name
    pub name: String,
    /// Rule query
    pub query: String,
    /// Alert condition
    pub condition: AlertCondition,
    /// Alert severity
    pub severity: AlertSeverity,
    /// Alert labels
    pub labels: HashMap<String, String>,
    /// Alert annotations
    pub annotations: HashMap<String, String>,
}

/// Alert condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertCondition {
    /// Condition type
    pub condition_type: ConditionType,
    /// Threshold value
    pub threshold: f64,
    /// Evaluation duration
    pub duration: Duration,
    /// Comparison operator
    pub operator: ComparisonOperator,
}

/// Condition types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConditionType {
    Threshold,
    Rate,
    Anomaly,
    Custom(String),
}

/// Comparison operators
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComparisonOperator {
    GreaterThan,
    LessThan,
    Equal,
    NotEqual,
    GreaterThanOrEqual,
    LessThanOrEqual,
}

/// Alert severity levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

/// Notification channel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationChannel {
    /// Channel name
    pub name: String,
    /// Channel type
    pub channel_type: ChannelType,
    /// Channel configuration
    pub config: HashMap<String, String>,
    /// Channel filters
    pub filters: Vec<ChannelFilter>,
}

/// Channel types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChannelType {
    Email,
    Slack,
    PagerDuty,
    Webhook,
    SMS,
    Custom(String),
}

/// Channel filter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelFilter {
    /// Filter type
    pub filter_type: FilterType,
    /// Filter value
    pub value: String,
    /// Filter operator
    pub operator: FilterOperator,
}

/// Filter types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FilterType {
    Severity,
    Label,
    Tag,
    Custom(String),
}

/// Filter operators
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FilterOperator {
    Equals,
    NotEquals,
    Contains,
    NotContains,
    Regex,
}

/// Alert manager configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertManagerConfig {
    /// Enable alert manager
    pub enabled: bool,
    /// Alert manager URL
    pub url: String,
    /// Authentication
    pub auth: Option<AuthConfig>,
    /// Timeout
    pub timeout: Duration,
}

/// Performance configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    /// Buffer size
    pub buffer_size: usize,
    /// Worker threads
    pub worker_threads: usize,
    /// Memory limit
    pub memory_limit: usize,
    /// CPU limit
    pub cpu_limit: f64,
    /// Optimization settings
    pub optimization: OptimizationSettings,
}

/// Optimization settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationSettings {
    /// Enable compression
    pub compression: bool,
    /// Enable batching
    pub batching: bool,
    /// Enable caching
    pub caching: bool,
    /// Enable sampling
    pub sampling: SamplingConfig,
}

/// Sampling configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamplingConfig {
    /// Enable sampling
    pub enabled: bool,
    /// Sampling rate (0.0 to 1.0)
    pub rate: f64,
    /// Sampling strategy
    pub strategy: SamplingStrategy,
}

/// Sampling strategies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SamplingStrategy {
    Random,
    Systematic,
    Stratified,
    Custom(String),
}

/// Metrics collector trait
pub trait MetricsCollector: std::fmt::Debug + Send + Sync {
    /// Collect metrics
    fn collect(&self) -> Result<Vec<MetricSample>>;
    
    /// Get collector name
    fn name(&self) -> &str;
    
    /// Get collector metadata
    fn metadata(&self) -> CollectorMetadata;
}

/// Metric sample
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricSample {
    /// Sample name
    pub name: String,
    /// Sample value
    pub value: f64,
    /// Sample labels
    pub labels: HashMap<String, String>,
    /// Sample timestamp
    pub timestamp: SystemTime,
    /// Sample metadata
    pub metadata: SampleMetadata,
}

/// Sample metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SampleMetadata {
    /// Sample type
    pub sample_type: SampleType,
    /// Sample unit
    pub unit: String,
    /// Sample description
    pub description: String,
}

/// Sample types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SampleType {
    Counter,
    Gauge,
    Histogram,
    Summary,
}

/// Collector metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectorMetadata {
    /// Collector description
    pub description: String,
    /// Collector version
    pub version: String,
    /// Collector author
    pub author: String,
    /// Supported metrics
    pub supported_metrics: Vec<String>,
}

/// Metrics exporter trait
pub trait MetricsExporter: std::fmt::Debug {
    /// Export metrics
    fn export(&self, metrics: &[MetricSample]) -> Result<()>;
    
    /// Get exporter name
    fn name(&self) -> &str;
    
    /// Get exporter metadata
    fn metadata(&self) -> ExporterMetadata;
}

/// Exporter metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExporterMetadata {
    /// Exporter description
    pub description: String,
    /// Exporter version
    pub version: String,
    /// Supported formats
    pub supported_formats: Vec<ExportFormat>,
}

/// Deployment-specific metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentMetrics {
    /// Deployment duration
    pub deployment_duration: Duration,
    /// Success rate
    pub success_rate: f64,
    /// Failure rate
    pub failure_rate: f64,
    /// Rollback rate
    pub rollback_rate: f64,
    /// Average response time
    pub avg_response_time: Duration,
    /// Error rate
    pub error_rate: f64,
    /// Throughput
    pub throughput: f64,
    /// Resource utilization
    pub resource_utilization: ResourceUtilization,
    /// Health score
    pub health_score: f64,
}

/// Resource utilization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUtilization {
    /// CPU utilization
    pub cpu: f64,
    /// Memory utilization
    pub memory: f64,
    /// Disk utilization
    pub disk: f64,
    /// Network utilization
    pub network: f64,
}

// Default implementations
impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            collection: CollectionConfig::default(),
            storage: StorageConfig::default(),
            export: ExportConfig::default(),
            alerting: AlertingConfig::default(),
            performance: PerformanceConfig::default(),
        }
    }
}

impl Default for CollectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval: Duration::from_secs(60),
            batch_size: 100,
            timeout: Duration::from_secs(30),
            retry: RetryConfig::default(),
        }
    }
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            delay: Duration::from_secs(1),
            backoff: BackoffStrategy::Exponential,
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            backend: StorageBackend::Memory,
            path: "/tmp/metrics".to_string(),
            retention: RetentionPolicy::default(),
            sharding: ShardingConfig::default(),
        }
    }
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            duration: Duration::from_secs(86400 * 7), // 7 days
            aggregation: vec![
                AggregationRule {
                    interval: Duration::from_secs(300), // 5 minutes
                    function: AggregationFunction::Average,
                    retention: Duration::from_secs(86400), // 1 day
                },
            ],
            compression: CompressionSettings::default(),
        }
    }
}

impl Default for CompressionSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            algorithm: CompressionAlgorithm::Gzip,
            level: 6,
        }
    }
}

impl Default for ShardingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            shard_count: 4,
            strategy: ShardingStrategy::Hash,
        }
    }
}

impl Default for ExportConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval: Duration::from_secs(300),
            format: ExportFormat::Prometheus,
            destinations: vec![],
        }
    }
}

impl Default for AlertingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rules: vec![],
            channels: vec![],
            manager: AlertManagerConfig::default(),
        }
    }
}

impl Default for AlertManagerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: "http://localhost:9093".to_string(),
            auth: None,
            timeout: Duration::from_secs(30),
        }
    }
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            buffer_size: 10000,
            worker_threads: 4,
            memory_limit: 1024 * 1024 * 1024, // 1GB
            cpu_limit: 0.8,
            optimization: OptimizationSettings::default(),
        }
    }
}

impl Default for OptimizationSettings {
    fn default() -> Self {
        Self {
            compression: true,
            batching: true,
            caching: true,
            sampling: SamplingConfig::default(),
        }
    }
}

impl Default for SamplingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            rate: 1.0,
            strategy: SamplingStrategy::Random,
        }
    }
}

impl Default for MetricsStore {
    fn default() -> Self {
        Self {
            time_series: HashMap::new(),
            counters: HashMap::new(),
            gauges: HashMap::new(),
            histograms: HashMap::new(),
            summaries: HashMap::new(),
            custom_metrics: HashMap::new(),
        }
    }
}

// Implementation
impl DeploymentMetricsManager {
    /// Create a new metrics manager
    pub async fn new(config: MetricsConfig) -> Result<Self> {
        Ok(Self {
            metrics_store: Arc::new(RwLock::new(MetricsStore::default())),
            config,
            collectors: Arc::new(RwLock::new(HashMap::new())),
            exporters: Arc::new(RwLock::new(Vec::new())),
        })
    }

    /// Record a counter metric
    pub async fn record_counter(&self, name: &str, value: u64, labels: HashMap<String, String>) -> Result<()> {
        let mut store = self.metrics_store.write().await;
        
        let counter = store.counters.entry(name.to_string()).or_insert_with(|| Counter {
            name: name.to_string(),
            value: 0,
            labels: labels.clone(),
            last_updated: SystemTime::now(),
            metadata: MetricMetadata {
                description: format!("Counter metric: {}", name),
                unit: "count".to_string(),
                metric_type: MetricType::Counter,
                collection_interval: self.config.collection.interval,
                tags: vec![],
                created_at: SystemTime::now(),
            },
        });
        
        counter.value += value;
        counter.last_updated = SystemTime::now();
        counter.labels.extend(labels);
        
        debug!("Recorded counter metric: {} = {}", name, counter.value);
        Ok(())
    }

    /// Record a gauge metric
    pub async fn record_gauge(&self, name: &str, value: f64, labels: HashMap<String, String>) -> Result<()> {
        let mut store = self.metrics_store.write().await;
        
        let gauge = store.gauges.entry(name.to_string()).or_insert_with(|| Gauge {
            name: name.to_string(),
            value: 0.0,
            labels: labels.clone(),
            last_updated: SystemTime::now(),
            metadata: MetricMetadata {
                description: format!("Gauge metric: {}", name),
                unit: "value".to_string(),
                metric_type: MetricType::Gauge,
                collection_interval: self.config.collection.interval,
                tags: vec![],
                created_at: SystemTime::now(),
            },
        });
        
        gauge.value = value;
        gauge.last_updated = SystemTime::now();
        gauge.labels.extend(labels);
        
        debug!("Recorded gauge metric: {} = {}", name, value);
        Ok(())
    }

    /// Record a histogram metric
    pub async fn record_histogram(&self, name: &str, value: f64, labels: HashMap<String, String>) -> Result<()> {
        let mut store = self.metrics_store.write().await;
        
        let histogram = store.histograms.entry(name.to_string()).or_insert_with(|| {
            let buckets = vec![
                HistogramBucket { upper_bound: 0.1, count: 0 },
                HistogramBucket { upper_bound: 0.5, count: 0 },
                HistogramBucket { upper_bound: 1.0, count: 0 },
                HistogramBucket { upper_bound: 5.0, count: 0 },
                HistogramBucket { upper_bound: 10.0, count: 0 },
                HistogramBucket { upper_bound: f64::INFINITY, count: 0 },
            ];
            
            Histogram {
                name: name.to_string(),
                buckets,
                count: 0,
                sum: 0.0,
                labels: labels.clone(),
                last_updated: SystemTime::now(),
                metadata: MetricMetadata {
                    description: format!("Histogram metric: {}", name),
                    unit: "seconds".to_string(),
                    metric_type: MetricType::Histogram,
                    collection_interval: self.config.collection.interval,
                    tags: vec![],
                    created_at: SystemTime::now(),
                },
            }
        });
        
        // Update buckets
        for bucket in &mut histogram.buckets {
            if value <= bucket.upper_bound {
                bucket.count += 1;
            }
        }
        
        histogram.count += 1;
        histogram.sum += value;
        histogram.last_updated = SystemTime::now();
        histogram.labels.extend(labels);
        
        debug!("Recorded histogram metric: {} = {}", name, value);
        Ok(())
    }

    /// Get deployment metrics
    pub async fn get_deployment_metrics(&self, deployment_id: &str) -> Result<DeploymentMetrics> {
        let store = self.metrics_store.read().await;
        
        // Calculate metrics from stored data
        let deployment_duration = self.calculate_deployment_duration(&store, deployment_id)?;
        let success_rate = self.calculate_success_rate(&store, deployment_id)?;
        let failure_rate = 1.0 - success_rate;
        let rollback_rate = self.calculate_rollback_rate(&store, deployment_id)?;
        let avg_response_time = self.calculate_avg_response_time(&store, deployment_id)?;
        let error_rate = self.calculate_error_rate(&store, deployment_id)?;
        let throughput = self.calculate_throughput(&store, deployment_id)?;
        let resource_utilization = self.calculate_resource_utilization(&store, deployment_id)?;
        let health_score = self.calculate_health_score(&store, deployment_id)?;
        
        Ok(DeploymentMetrics {
            deployment_duration,
            success_rate,
            failure_rate,
            rollback_rate,
            avg_response_time,
            error_rate,
            throughput,
            resource_utilization,
            health_score,
        })
    }

    /// Calculate deployment duration
    fn calculate_deployment_duration(&self, _store: &MetricsStore, _deployment_id: &str) -> Result<Duration> {
        // Implementation would calculate from deployment start/end timestamps
        Ok(Duration::from_secs(300)) // Placeholder
    }

    /// Calculate success rate
    fn calculate_success_rate(&self, _store: &MetricsStore, _deployment_id: &str) -> Result<f64> {
        // Implementation would calculate from success/failure counters
        Ok(0.95) // Placeholder
    }

    /// Calculate rollback rate
    fn calculate_rollback_rate(&self, _store: &MetricsStore, _deployment_id: &str) -> Result<f64> {
        // Implementation would calculate from rollback counters
        Ok(0.02) // Placeholder
    }

    /// Calculate average response time
    fn calculate_avg_response_time(&self, _store: &MetricsStore, _deployment_id: &str) -> Result<Duration> {
        // Implementation would calculate from response time histograms
        Ok(Duration::from_millis(150)) // Placeholder
    }

    /// Calculate error rate
    fn calculate_error_rate(&self, _store: &MetricsStore, _deployment_id: &str) -> Result<f64> {
        // Implementation would calculate from error counters
        Ok(0.01) // Placeholder
    }

    /// Calculate throughput
    fn calculate_throughput(&self, _store: &MetricsStore, _deployment_id: &str) -> Result<f64> {
        // Implementation would calculate requests per second
        Ok(1000.0) // Placeholder
    }

    /// Calculate resource utilization
    fn calculate_resource_utilization(&self, _store: &MetricsStore, _deployment_id: &str) -> Result<ResourceUtilization> {
        // Implementation would calculate from resource gauges
        Ok(ResourceUtilization {
            cpu: 0.65,
            memory: 0.70,
            disk: 0.45,
            network: 0.30,
        })
    }

    /// Calculate health score
    fn calculate_health_score(&self, _store: &MetricsStore, _deployment_id: &str) -> Result<f64> {
        // Implementation would calculate composite health score
        Ok(0.92) // Placeholder
    }

    /// Export metrics
    pub async fn export_metrics(&self) -> Result<()> {
        if !self.config.export.enabled {
            return Ok(());
        }
        
        let store = self.metrics_store.read().await;
        let exporters = self.exporters.read().await;
        
        // Convert stored metrics to samples
        let mut samples = Vec::new();
        
        // Export counters
        for counter in store.counters.values() {
            samples.push(MetricSample {
                name: counter.name.clone(),
                value: counter.value as f64,
                labels: counter.labels.clone(),
                timestamp: counter.last_updated,
                metadata: SampleMetadata {
                    sample_type: SampleType::Counter,
                    unit: counter.metadata.unit.clone(),
                    description: counter.metadata.description.clone(),
                },
            });
        }
        
        // Export gauges
        for gauge in store.gauges.values() {
            samples.push(MetricSample {
                name: gauge.name.clone(),
                value: gauge.value,
                labels: gauge.labels.clone(),
                timestamp: gauge.last_updated,
                metadata: SampleMetadata {
                    sample_type: SampleType::Gauge,
                    unit: gauge.metadata.unit.clone(),
                    description: gauge.metadata.description.clone(),
                },
            });
        }
        
        // Export to all configured exporters
        for exporter in exporters.iter() {
            if let Err(e) = exporter.export(&samples) {
                error!("Failed to export metrics with {}: {}", exporter.name(), e);
            } else {
                debug!("Successfully exported {} samples with {}", samples.len(), exporter.name());
            }
        }
        
        Ok(())
    }

    /// Add metrics collector
    pub async fn add_collector(&self, name: String, collector: Box<dyn MetricsCollector + Send + Sync>) {
        let mut collectors = self.collectors.write().await;
        collectors.insert(name, collector);
    }

    /// Add metrics exporter
    pub async fn add_exporter(&self, exporter: Box<dyn MetricsExporter + Send + Sync>) {
        let mut exporters = self.exporters.write().await;
        exporters.push(exporter);
    }

    /// Collect metrics from all collectors
    pub async fn collect_metrics(&self) -> Result<()> {
        let collectors = self.collectors.read().await;
        
        for (name, collector) in collectors.iter() {
            match collector.collect() {
                Ok(samples) => {
                    debug!("Collected {} samples from collector: {}", samples.len(), name);
                    // Process samples and store them
                    for sample in samples {
                        self.process_sample(sample).await?;
                    }
                },
                Err(e) => {
                    error!("Failed to collect metrics from {}: {}", name, e);
                }
            }
        }
        
        Ok(())
    }

    /// Process a metric sample
    async fn process_sample(&self, sample: MetricSample) -> Result<()> {
        match sample.metadata.sample_type {
            SampleType::Counter => {
                self.record_counter(&sample.name, sample.value as u64, sample.labels).await?
            },
            SampleType::Gauge => {
                self.record_gauge(&sample.name, sample.value, sample.labels).await?
            },
            SampleType::Histogram => {
                self.record_histogram(&sample.name, sample.value, sample.labels).await?
            },
            SampleType::Summary => {
                // Handle summary metrics
                debug!("Processing summary sample: {}", sample.name);
            },
        }
        
        Ok(())
    }
}

/// Utility functions
pub fn create_default_metrics_manager() -> DeploymentMetricsManager {
    DeploymentMetricsManager {
        metrics_store: Arc::new(RwLock::new(MetricsStore::default())),
        config: MetricsConfig::default(),
        collectors: Arc::new(RwLock::new(HashMap::new())),
        exporters: Arc::new(RwLock::new(Vec::new())),
    }
}

pub fn validate_metrics_config(config: &MetricsConfig) -> bool {
    // Validate collection configuration
    if config.collection.enabled && config.collection.interval.as_secs() == 0 {
        return false;
    }
    
    if config.collection.batch_size == 0 {
        return false;
    }
    
    if config.collection.timeout.as_secs() == 0 {
        return false;
    }
    
    // Validate performance configuration
    if config.performance.buffer_size == 0 {
        return false;
    }
    
    if config.performance.worker_threads == 0 {
        return false;
    }
    
    if config.performance.memory_limit == 0 {
        return false;
    }
    
    if config.performance.cpu_limit <= 0.0 || config.performance.cpu_limit > 1.0 {
        return false;
    }
    
    // Validate sampling configuration
    if config.performance.optimization.sampling.enabled {
        let rate = config.performance.optimization.sampling.rate;
        if rate < 0.0 || rate > 1.0 {
            return false;
        }
    }
    
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_metrics_manager_creation() {
        let config = MetricsConfig::default();
        let manager = DeploymentMetricsManager::new(config).await;
        assert!(manager.is_ok());
    }
    
    #[tokio::test]
    async fn test_counter_recording() {
        let config = MetricsConfig::default();
        let manager = DeploymentMetricsManager::new(config).await.unwrap();
        
        let labels = HashMap::new();
        let result = manager.record_counter("test_counter", 5, labels).await;
        assert!(result.is_ok());
        
        // Verify counter was recorded
        let _store = manager.metrics_store.read().await;
        assert!(_store.counters.contains_key("test_counter"));
        assert_eq!(_store.counters["test_counter"].value, 5);
    }
    
    #[tokio::test]
    async fn test_gauge_recording() {
        let config = MetricsConfig::default();
        let manager = DeploymentMetricsManager::new(config).await.unwrap();
        
        let labels = HashMap::new();
        let result = manager.record_gauge("test_gauge", 42.5, labels).await;
        assert!(result.is_ok());
        
        // Verify gauge was recorded
        let _store = manager.metrics_store.read().await;
        assert!(_store.gauges.contains_key("test_gauge"));
        assert_eq!(_store.gauges["test_gauge"].value, 42.5);
    }
    
    #[test]
    fn test_config_validation() {
        let valid_config = MetricsConfig::default();
        assert!(validate_metrics_config(&valid_config));
        
        let mut invalid_config = valid_config.clone();
        invalid_config.collection.batch_size = 0;
        assert!(!validate_metrics_config(&invalid_config));
    }
    
    #[test]
    fn test_default_configurations() {
        let config = MetricsConfig::default();
        assert!(config.collection.enabled);
        assert_eq!(config.collection.interval, Duration::from_secs(60));
        assert_eq!(config.collection.batch_size, 100);
        assert_eq!(config.performance.worker_threads, 4);
    }
    
    #[test]
    fn test_enum_serialization() {
        let metric_type = MetricType::Counter;
        let serialized = serde_json::to_string(&metric_type).unwrap();
        let deserialized: MetricType = serde_json::from_str(&serialized).unwrap();
        assert!(matches!(deserialized, MetricType::Counter));
    }
    
    #[test]
    fn test_resource_utilization() {
        let utilization = ResourceUtilization {
            cpu: 0.75,
            memory: 0.80,
            disk: 0.50,
            network: 0.25,
        };
        
        assert_eq!(utilization.cpu, 0.75);
        assert_eq!(utilization.memory, 0.80);
        assert_eq!(utilization.disk, 0.50);
        assert_eq!(utilization.network, 0.25);
    }
}
