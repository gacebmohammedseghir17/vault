use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use serde::{Deserialize, Serialize};

use uuid::Uuid;
use reqwest::Client;
use serde_json::{json, Value};

// Error handling
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SiemError {
    ConnectionError(String),
    AuthenticationError(String),
    ConfigurationError(String),
    DataFormatError(String),
    NetworkError(String),
    ApiError(String),
    ValidationError(String),
    IntegrationError(String),
}

impl std::fmt::Display for SiemError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SiemError::ConnectionError(msg) => write!(f, "Connection error: {}", msg),
            SiemError::AuthenticationError(msg) => write!(f, "Authentication error: {}", msg),
            SiemError::ConfigurationError(msg) => write!(f, "Configuration error: {}", msg),
            SiemError::DataFormatError(msg) => write!(f, "Data format error: {}", msg),
            SiemError::NetworkError(msg) => write!(f, "Network error: {}", msg),
            SiemError::ApiError(msg) => write!(f, "API error: {}", msg),
            SiemError::ValidationError(msg) => write!(f, "Validation error: {}", msg),
            SiemError::IntegrationError(msg) => write!(f, "Integration error: {}", msg),
        }
    }
}

impl std::error::Error for SiemError {}

// Configuration structures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemConfig {
    pub splunk_config: Option<SplunkConfig>,
    pub qradar_config: Option<QRadarConfig>,
    pub sentinel_config: Option<SentinelConfig>,
    pub general_config: GeneralSiemConfig,
    pub data_mapping: DataMappingConfig,
    pub retry_config: RetryConfig,
    pub security_config: SecurityConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SplunkConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub index: String,
    pub source_type: String,
    pub use_ssl: bool,
    pub verify_ssl: bool,
    pub hec_token: Option<String>,
    pub hec_endpoint: Option<String>,
    pub batch_size: usize,
    pub flush_interval: Duration,
    pub compression: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QRadarConfig {
    pub host: String,
    pub port: u16,
    pub api_token: String,
    pub api_version: String,
    pub use_ssl: bool,
    pub verify_ssl: bool,
    pub log_source_id: Option<u32>,
    pub event_category: u32,
    pub severity: u32,
    pub batch_size: usize,
    pub flush_interval: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentinelConfig {
    pub workspace_id: String,
    pub shared_key: String,
    pub log_type: String,
    pub api_version: String,
    pub endpoint: String,
    pub batch_size: usize,
    pub flush_interval: Duration,
    pub time_generated_field: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralSiemConfig {
    pub enabled_integrations: Vec<SiemType>,
    pub default_severity: SeverityLevel,
    pub event_buffer_size: usize,
    pub max_retry_attempts: u32,
    pub health_check_interval: Duration,
    pub metrics_collection: bool,
    pub debug_mode: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataMappingConfig {
    pub field_mappings: HashMap<String, String>,
    pub custom_fields: HashMap<String, Value>,
    pub timestamp_format: String,
    pub timezone: String,
    pub normalize_data: bool,
    pub enrich_data: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    pub max_retries: u32,
    pub initial_delay: Duration,
    pub max_delay: Duration,
    pub backoff_multiplier: f64,
    pub retry_on_errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub encrypt_data: bool,
    pub sign_data: bool,
    pub certificate_path: Option<String>,
    pub private_key_path: Option<String>,
    pub trusted_ca_path: Option<String>,
    pub client_cert_auth: bool,
}

// Enums
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum SiemType {
    Splunk,
    QRadar,
    Sentinel,
    Generic,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum SeverityLevel {
    Critical = 1,
    High = 2,
    Medium = 3,
    Low = 4,
    Info = 5,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum EventType {
    ThreatDetection,
    Anomaly,
    SecurityAlert,
    SystemEvent,
    AuditLog,
    NetworkEvent,
    FileEvent,
    ProcessEvent,
    UserActivity,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DataFormat {
    Json,
    Cef,
    Leef,
    Syslog,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConnectionStatus {
    Connected,
    Disconnected,
    Connecting,
    Error(String),
    Authenticating,
}

// Data structures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemEvent {
    pub event_id: String,
    pub timestamp: u64,
    pub event_type: EventType,
    pub severity: SeverityLevel,
    pub source: String,
    pub destination: Option<String>,
    pub message: String,
    pub details: HashMap<String, Value>,
    pub raw_data: Option<String>,
    pub tags: Vec<String>,
    pub correlation_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemAlert {
    pub alert_id: String,
    pub timestamp: u64,
    pub title: String,
    pub description: String,
    pub severity: SeverityLevel,
    pub category: String,
    pub source_events: Vec<String>,
    pub indicators: Vec<ThreatIndicator>,
    pub remediation: Option<String>,
    pub status: AlertStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIndicator {
    pub indicator_type: IndicatorType,
    pub value: String,
    pub confidence: f64,
    pub source: String,
    pub first_seen: u64,
    pub last_seen: u64,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemMetrics {
    pub events_sent: u64,
    pub events_failed: u64,
    pub alerts_generated: u64,
    pub connection_uptime: Duration,
    pub average_latency: Duration,
    pub error_rate: f64,
    pub throughput: f64,
    pub last_successful_send: Option<u64>,
    pub integration_health: HashMap<SiemType, ConnectionStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemStatistics {
    pub total_events_processed: u64,
    pub events_by_type: HashMap<EventType, u64>,
    pub events_by_severity: HashMap<SeverityLevel, u64>,
    pub integration_statistics: HashMap<SiemType, IntegrationStats>,
    pub performance_metrics: PerformanceMetrics,
    pub error_statistics: ErrorStatistics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationStats {
    pub events_sent: u64,
    pub events_failed: u64,
    pub success_rate: f64,
    pub average_response_time: Duration,
    pub last_error: Option<String>,
    pub uptime_percentage: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub events_per_second: f64,
    pub memory_usage: u64,
    pub cpu_usage: f64,
    pub network_io: NetworkIO,
    pub queue_size: usize,
    pub processing_latency: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkIO {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub requests_sent: u64,
    pub responses_received: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorStatistics {
    pub total_errors: u64,
    pub errors_by_type: HashMap<String, u64>,
    pub recent_errors: Vec<ErrorRecord>,
    pub error_rate_trend: Vec<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorRecord {
    pub timestamp: u64,
    pub error_type: String,
    pub message: String,
    pub integration: SiemType,
    pub retry_count: u32,
}

// Additional enums
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum IndicatorType {
    IpAddress,
    Domain,
    Url,
    FileHash,
    Email,
    UserAgent,
    Registry,
    Mutex,
    Certificate,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertStatus {
    New,
    InProgress,
    Resolved,
    FalsePositive,
    Suppressed,
}

// Main SIEM integration manager
#[derive(Debug)]
pub struct SiemIntegrationManager {
    config: Arc<RwLock<SiemConfig>>,
    splunk_client: Option<Arc<SplunkClient>>,
    qradar_client: Option<Arc<QRadarClient>>,
    sentinel_client: Option<Arc<SentinelClient>>,
    event_buffer: Arc<RwLock<Vec<SiemEvent>>>,
    metrics: Arc<RwLock<SiemMetrics>>,
    statistics: Arc<RwLock<SiemStatistics>>,
    http_client: Client,
}

impl SiemIntegrationManager {
    pub fn new(config: SiemConfig) -> Result<Self, SiemError> {
        let http_client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| SiemError::ConfigurationError(format!("Failed to create HTTP client: {}", e)))?;
        
        let mut manager = Self {
            config: Arc::new(RwLock::new(config.clone())),
            splunk_client: None,
            qradar_client: None,
            sentinel_client: None,
            event_buffer: Arc::new(RwLock::new(Vec::new())),
            metrics: Arc::new(RwLock::new(SiemMetrics::default())),
            statistics: Arc::new(RwLock::new(SiemStatistics::default())),
            http_client,
        };
        
        // Initialize clients based on configuration
        if let Some(splunk_config) = &config.splunk_config {
            manager.splunk_client = Some(Arc::new(SplunkClient::new(splunk_config.clone())?));
        }
        
        if let Some(qradar_config) = &config.qradar_config {
            manager.qradar_client = Some(Arc::new(QRadarClient::new(qradar_config.clone())?));
        }
        
        if let Some(sentinel_config) = &config.sentinel_config {
            manager.sentinel_client = Some(Arc::new(SentinelClient::new(sentinel_config.clone())?));
        }
        
        Ok(manager)
    }

    pub async fn send_event(&self, event: SiemEvent) -> Result<(), SiemError> {
        let config = self.config.read().unwrap();
        let mut results = Vec::new();
        
        // Send to enabled integrations
        for integration in &config.general_config.enabled_integrations {
            match integration {
                SiemType::Splunk => {
                    if let Some(client) = &self.splunk_client {
                        let result = client.send_event(&event).await;
                        results.push((SiemType::Splunk, result));
                    }
                },
                SiemType::QRadar => {
                    if let Some(client) = &self.qradar_client {
                        let result = client.send_event(&event).await;
                        results.push((SiemType::QRadar, result));
                    }
                },
                SiemType::Sentinel => {
                    if let Some(client) = &self.sentinel_client {
                        let result = client.send_event(&event).await;
                        results.push((SiemType::Sentinel, result));
                    }
                },
                _ => {}
            }
        }
        
        // Update metrics
        self.update_metrics(&results).await;
        
        // Check if any integration succeeded
        let any_success = results.iter().any(|(_, result)| result.is_ok());
        if !any_success && !results.is_empty() {
            return Err(SiemError::IntegrationError(
                "Failed to send event to any SIEM integration".to_string(),
            ));
        }
        
        Ok(())
    }

    pub async fn send_batch_events(&self, events: Vec<SiemEvent>) -> Result<(), SiemError> {
        let config = self.config.read().unwrap();
        let mut all_results = Vec::new();
        
        for integration in &config.general_config.enabled_integrations {
            match integration {
                SiemType::Splunk => {
                    if let Some(client) = &self.splunk_client {
                        let result = client.send_batch_events(&events).await;
                        all_results.push((SiemType::Splunk, result));
                    }
                },
                SiemType::QRadar => {
                    if let Some(client) = &self.qradar_client {
                        let result = client.send_batch_events(&events).await;
                        all_results.push((SiemType::QRadar, result));
                    }
                },
                SiemType::Sentinel => {
                    if let Some(client) = &self.sentinel_client {
                        let result = client.send_batch_events(&events).await;
                        all_results.push((SiemType::Sentinel, result));
                    }
                },
                _ => {}
            }
        }
        
        self.update_metrics(&all_results).await;
        
        Ok(())
    }

    pub async fn send_alert(&self, alert: SiemAlert) -> Result<(), SiemError> {
        // Convert alert to event format
        let event = self.alert_to_event(alert).await?;
        self.send_event(event).await
    }

    pub async fn test_connections(&self) -> Result<HashMap<SiemType, bool>, SiemError> {
        let mut results = HashMap::new();
        
        if let Some(client) = &self.splunk_client {
            let test_result = client.test_connection().await.is_ok();
            results.insert(SiemType::Splunk, test_result);
        }
        
        if let Some(client) = &self.qradar_client {
            let test_result = client.test_connection().await.is_ok();
            results.insert(SiemType::QRadar, test_result);
        }
        
        if let Some(client) = &self.sentinel_client {
            let test_result = client.test_connection().await.is_ok();
            results.insert(SiemType::Sentinel, test_result);
        }
        
        Ok(results)
    }

    pub async fn get_metrics(&self) -> SiemMetrics {
        self.metrics.read().unwrap().clone()
    }

    pub async fn get_statistics(&self) -> SiemStatistics {
        self.statistics.read().unwrap().clone()
    }

    pub async fn update_config(&self, config: SiemConfig) -> Result<(), SiemError> {
        let mut current_config = self.config.write().unwrap();
        *current_config = config;
        Ok(())
    }

    // Private helper methods
    async fn update_metrics(&self, results: &[(SiemType, Result<(), SiemError>)]) {
        let mut metrics = self.metrics.write().unwrap();
        let mut statistics = self.statistics.write().unwrap();
        
        for (siem_type, result) in results {
            match result {
                Ok(_) => {
                    metrics.events_sent += 1;
                    statistics.total_events_processed += 1;
                    
                    let integration_stats = statistics.integration_statistics
                        .entry(siem_type.clone())
                        .or_insert_with(IntegrationStats::default);
                    integration_stats.events_sent += 1;
                    integration_stats.success_rate = 
                        integration_stats.events_sent as f64 / 
                        (integration_stats.events_sent + integration_stats.events_failed) as f64;
                },
                Err(error) => {
                    metrics.events_failed += 1;
                    
                    let integration_stats = statistics.integration_statistics
                        .entry(siem_type.clone())
                        .or_insert_with(IntegrationStats::default);
                    integration_stats.events_failed += 1;
                    integration_stats.last_error = Some(error.to_string());
                    integration_stats.success_rate = 
                        integration_stats.events_sent as f64 / 
                        (integration_stats.events_sent + integration_stats.events_failed) as f64;
                    
                    // Record error
                    let error_record = ErrorRecord {
                        timestamp: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                        error_type: format!("{:?}", error),
                        message: error.to_string(),
                        integration: siem_type.clone(),
                        retry_count: 0,
                    };
                    
                    statistics.error_statistics.recent_errors.push(error_record);
                    statistics.error_statistics.total_errors += 1;
                }
            }
        }
        
        // Update error rate
        metrics.error_rate = metrics.events_failed as f64 / 
            (metrics.events_sent + metrics.events_failed) as f64;
    }

    async fn alert_to_event(&self, alert: SiemAlert) -> Result<SiemEvent, SiemError> {
        let mut details = HashMap::new();
        details.insert("alert_id".to_string(), json!(alert.alert_id));
        details.insert("title".to_string(), json!(alert.title));
        details.insert("description".to_string(), json!(alert.description));
        details.insert("category".to_string(), json!(alert.category));
        details.insert("source_events".to_string(), json!(alert.source_events));
        details.insert("indicators".to_string(), json!(alert.indicators));
        details.insert("status".to_string(), json!(alert.status));
        
        if let Some(remediation) = alert.remediation {
            details.insert("remediation".to_string(), json!(remediation));
        }
        
        Ok(SiemEvent {
            event_id: Uuid::new_v4().to_string(),
            timestamp: alert.timestamp,
            event_type: EventType::SecurityAlert,
            severity: alert.severity,
            source: "ERDPS".to_string(),
            destination: None,
            message: format!("Security Alert: {}", alert.title),
            details,
            raw_data: None,
            tags: vec!["alert".to_string(), "security".to_string()],
            correlation_id: Some(alert.alert_id),
        })
    }
}

// SIEM client implementations
#[derive(Debug)]
pub struct SplunkClient {
    config: SplunkConfig,
    client: Client,
}

impl SplunkClient {
    pub fn new(config: SplunkConfig) -> Result<Self, SiemError> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .danger_accept_invalid_certs(!config.verify_ssl)
            .build()
            .map_err(|e| SiemError::ConfigurationError(format!("Failed to create Splunk client: {}", e)))?;
        
        Ok(Self { config, client })
    }

    pub async fn send_event(&self, event: &SiemEvent) -> Result<(), SiemError> {
        let url = if let Some(hec_endpoint) = &self.config.hec_endpoint {
            format!("{}/services/collector/event", hec_endpoint)
        } else {
            let protocol = if self.config.use_ssl { "https" } else { "http" };
            format!("{}://{}:{}/services/collector/event", protocol, self.config.host, self.config.port)
        };
        
        let splunk_event = json!({
            "time": event.timestamp,
            "host": event.source,
            "source": "erdps",
            "sourcetype": self.config.source_type,
            "index": self.config.index,
            "event": {
                "event_id": event.event_id,
                "event_type": event.event_type,
                "severity": event.severity,
                "message": event.message,
                "details": event.details,
                "tags": event.tags
            }
        });
        
        let mut request = self.client.post(&url)
            .json(&splunk_event);
        
        if let Some(token) = &self.config.hec_token {
            request = request.header("Authorization", format!("Splunk {}", token));
        } else {
            request = request.basic_auth(&self.config.username, Some(&self.config.password));
        }
        
        let response = request.send().await
            .map_err(|e| SiemError::NetworkError(format!("Failed to send to Splunk: {}", e)))?;
        
        if !response.status().is_success() {
            return Err(SiemError::ApiError(
                format!("Splunk API error: {}", response.status())
            ));
        }
        
        Ok(())
    }

    pub async fn send_batch_events(&self, events: &[SiemEvent]) -> Result<(), SiemError> {
        for chunk in events.chunks(self.config.batch_size) {
            for event in chunk {
                self.send_event(event).await?;
            }
        }
        Ok(())
    }

    pub async fn test_connection(&self) -> Result<(), SiemError> {
        let url = if self.config.use_ssl { "https" } else { "http" };
        let test_url = format!("{}://{}:{}/services/server/info", url, self.config.host, self.config.port);
        
        let response = self.client.get(&test_url)
            .basic_auth(&self.config.username, Some(&self.config.password))
            .send().await
            .map_err(|e| SiemError::ConnectionError(format!("Splunk connection test failed: {}", e)))?;
        
        if response.status().is_success() {
            Ok(())
        } else {
            Err(SiemError::ConnectionError(
                format!("Splunk connection test failed with status: {}", response.status())
            ))
        }
    }
}

#[derive(Debug)]
pub struct QRadarClient {
    config: QRadarConfig,
    client: Client,
}

impl QRadarClient {
    pub fn new(config: QRadarConfig) -> Result<Self, SiemError> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .danger_accept_invalid_certs(!config.verify_ssl)
            .build()
            .map_err(|e| SiemError::ConfigurationError(format!("Failed to create QRadar client: {}", e)))?;
        
        Ok(Self { config, client })
    }

    pub async fn send_event(&self, event: &SiemEvent) -> Result<(), SiemError> {
        let protocol = if self.config.use_ssl { "https" } else { "http" };
        let url = format!("{}://{}:{}/api/siem/offenses", protocol, self.config.host, self.config.port);
        
        let qradar_event = json!({
            "offense_type": self.config.event_category,
            "severity": event.severity as u32,
            "description": event.message,
            "source_ip": event.source,
            "destination_ip": event.destination,
            "start_time": event.timestamp * 1000, // QRadar expects milliseconds
            "event_count": 1,
            "magnitude": self.config.severity,
            "credibility": 5,
            "relevance": 5,
            "categories": [self.config.event_category],
            "properties": event.details
        });
        
        let response = self.client.post(&url)
            .header("SEC", &self.config.api_token)
            .header("Version", &self.config.api_version)
            .json(&qradar_event)
            .send().await
            .map_err(|e| SiemError::NetworkError(format!("Failed to send to QRadar: {}", e)))?;
        
        if !response.status().is_success() {
            return Err(SiemError::ApiError(
                format!("QRadar API error: {}", response.status())
            ));
        }
        
        Ok(())
    }

    pub async fn send_batch_events(&self, events: &[SiemEvent]) -> Result<(), SiemError> {
        for chunk in events.chunks(self.config.batch_size) {
            for event in chunk {
                self.send_event(event).await?;
            }
        }
        Ok(())
    }

    pub async fn test_connection(&self) -> Result<(), SiemError> {
        let protocol = if self.config.use_ssl { "https" } else { "http" };
        let test_url = format!("{}://{}:{}/api/system/about", protocol, self.config.host, self.config.port);
        
        let response = self.client.get(&test_url)
            .header("SEC", &self.config.api_token)
            .header("Version", &self.config.api_version)
            .send().await
            .map_err(|e| SiemError::ConnectionError(format!("QRadar connection test failed: {}", e)))?;
        
        if response.status().is_success() {
            Ok(())
        } else {
            Err(SiemError::ConnectionError(
                format!("QRadar connection test failed with status: {}", response.status())
            ))
        }
    }
}

#[derive(Debug)]
pub struct SentinelClient {
    config: SentinelConfig,
    client: Client,
}

impl SentinelClient {
    pub fn new(config: SentinelConfig) -> Result<Self, SiemError> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| SiemError::ConfigurationError(format!("Failed to create Sentinel client: {}", e)))?;
        
        Ok(Self { config, client })
    }

    pub async fn send_event(&self, event: &SiemEvent) -> Result<(), SiemError> {
        let url = format!(
            "{}/api/logs?api-version={}",
            self.config.endpoint,
            self.config.api_version
        );
        
        let sentinel_event = json!({
            "TimeGenerated": event.timestamp,
            "EventId": event.event_id,
            "EventType": event.event_type,
            "Severity": event.severity,
            "Source": event.source,
            "Destination": event.destination,
            "Message": event.message,
            "Details": event.details,
            "Tags": event.tags.join(","),
            "CorrelationId": event.correlation_id
        });
        
        let body = serde_json::to_string(&[sentinel_event])
            .map_err(|e| SiemError::DataFormatError(format!("Failed to serialize event: {}", e)))?;
        
        let date = chrono::Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        let content_length = body.len();
        let string_to_hash = format!(
            "POST\n{}\napplication/json\nx-ms-date:{}\n/api/logs",
            content_length, date
        );
        
        let signature = self.build_signature(&string_to_hash)?;
        let authorization = format!(
            "SharedKey {}:{}",
            self.config.workspace_id, signature
        );
        
        let response = self.client.post(&url)
            .header("Content-Type", "application/json")
            .header("Log-Type", &self.config.log_type)
            .header("Authorization", authorization)
            .header("x-ms-date", date)
            .header("time-generated-field", &self.config.time_generated_field)
            .body(body)
            .send().await
            .map_err(|e| SiemError::NetworkError(format!("Failed to send to Sentinel: {}", e)))?;
        
        if !response.status().is_success() {
            return Err(SiemError::ApiError(
                format!("Sentinel API error: {}", response.status())
            ));
        }
        
        Ok(())
    }

    pub async fn send_batch_events(&self, events: &[SiemEvent]) -> Result<(), SiemError> {
        for chunk in events.chunks(self.config.batch_size) {
            let sentinel_events: Vec<Value> = chunk.iter().map(|event| {
                json!({
                    "TimeGenerated": event.timestamp,
                    "EventId": event.event_id,
                    "EventType": event.event_type,
                    "Severity": event.severity,
                    "Source": event.source,
                    "Destination": event.destination,
                    "Message": event.message,
                    "Details": event.details,
                    "Tags": event.tags.join(","),
                    "CorrelationId": event.correlation_id
                })
            }).collect();
            
            let body = serde_json::to_string(&sentinel_events)
                .map_err(|e| SiemError::DataFormatError(format!("Failed to serialize events: {}", e)))?;
            
            // Send batch using similar logic as single event
            self.send_batch_to_sentinel(body).await?;
        }
        Ok(())
    }

    pub async fn test_connection(&self) -> Result<(), SiemError> {
        // Test by sending a minimal test event
        let test_event = SiemEvent {
            event_id: "test-connection".to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            event_type: EventType::SystemEvent,
            severity: SeverityLevel::Info,
            source: "erdps-test".to_string(),
            destination: None,
            message: "Connection test".to_string(),
            details: HashMap::new(),
            raw_data: None,
            tags: vec!["test".to_string()],
            correlation_id: None,
        };
        
        self.send_event(&test_event).await
    }

    // Private helper methods
    fn build_signature(&self, string_to_hash: &str) -> Result<String, SiemError> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        use base64::{Engine as _, engine::general_purpose};
        
        type HmacSha256 = Hmac<Sha256>;
        
        let decoded_key = general_purpose::STANDARD.decode(&self.config.shared_key)
            .map_err(|e| SiemError::AuthenticationError(format!("Failed to decode shared key: {}", e)))?;
        
        let mut mac = HmacSha256::new_from_slice(&decoded_key)
            .map_err(|e| SiemError::AuthenticationError(format!("Failed to create HMAC: {}", e)))?;
        
        mac.update(string_to_hash.as_bytes());
        let result = mac.finalize();
        
        Ok(general_purpose::STANDARD.encode(result.into_bytes()))
    }

    async fn send_batch_to_sentinel(&self, body: String) -> Result<(), SiemError> {
        let url = format!(
            "{}/api/logs?api-version={}",
            self.config.endpoint,
            self.config.api_version
        );
        
        let date = chrono::Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        let content_length = body.len();
        let string_to_hash = format!(
            "POST\n{}\napplication/json\nx-ms-date:{}\n/api/logs",
            content_length, date
        );
        
        let signature = self.build_signature(&string_to_hash)?;
        let authorization = format!(
            "SharedKey {}:{}",
            self.config.workspace_id, signature
        );
        
        let response = self.client.post(&url)
            .header("Content-Type", "application/json")
            .header("Log-Type", &self.config.log_type)
            .header("Authorization", authorization)
            .header("x-ms-date", date)
            .header("time-generated-field", &self.config.time_generated_field)
            .body(body)
            .send().await
            .map_err(|e| SiemError::NetworkError(format!("Failed to send batch to Sentinel: {}", e)))?;
        
        if !response.status().is_success() {
            return Err(SiemError::ApiError(
                format!("Sentinel batch API error: {}", response.status())
            ));
        }
        
        Ok(())
    }
}

// Default implementations
impl Default for SiemConfig {
    fn default() -> Self {
        Self {
            splunk_config: None,
            qradar_config: None,
            sentinel_config: None,
            general_config: GeneralSiemConfig::default(),
            data_mapping: DataMappingConfig::default(),
            retry_config: RetryConfig::default(),
            security_config: SecurityConfig::default(),
        }
    }
}

impl Default for GeneralSiemConfig {
    fn default() -> Self {
        Self {
            enabled_integrations: vec![SiemType::Splunk],
            default_severity: SeverityLevel::Medium,
            event_buffer_size: 1000,
            max_retry_attempts: 3,
            health_check_interval: Duration::from_secs(60),
            metrics_collection: true,
            debug_mode: false,
        }
    }
}

impl Default for DataMappingConfig {
    fn default() -> Self {
        Self {
            field_mappings: HashMap::new(),
            custom_fields: HashMap::new(),
            timestamp_format: "%Y-%m-%dT%H:%M:%S%.3fZ".to_string(),
            timezone: "UTC".to_string(),
            normalize_data: true,
            enrich_data: false,
        }
    }
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(60),
            backoff_multiplier: 2.0,
            retry_on_errors: vec![
                "NetworkError".to_string(),
                "ConnectionError".to_string(),
            ],
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            encrypt_data: false,
            sign_data: false,
            certificate_path: None,
            private_key_path: None,
            trusted_ca_path: None,
            client_cert_auth: false,
        }
    }
}

impl Default for SiemMetrics {
    fn default() -> Self {
        Self {
            events_sent: 0,
            events_failed: 0,
            alerts_generated: 0,
            connection_uptime: Duration::from_secs(0),
            average_latency: Duration::from_millis(0),
            error_rate: 0.0,
            throughput: 0.0,
            last_successful_send: None,
            integration_health: HashMap::new(),
        }
    }
}

impl Default for SiemStatistics {
    fn default() -> Self {
        Self {
            total_events_processed: 0,
            events_by_type: HashMap::new(),
            events_by_severity: HashMap::new(),
            integration_statistics: HashMap::new(),
            performance_metrics: PerformanceMetrics::default(),
            error_statistics: ErrorStatistics::default(),
        }
    }
}

impl Default for IntegrationStats {
    fn default() -> Self {
        Self {
            events_sent: 0,
            events_failed: 0,
            success_rate: 0.0,
            average_response_time: Duration::from_millis(0),
            last_error: None,
            uptime_percentage: 0.0,
        }
    }
}

impl Default for PerformanceMetrics {
    fn default() -> Self {
        Self {
            events_per_second: 0.0,
            memory_usage: 0,
            cpu_usage: 0.0,
            network_io: NetworkIO::default(),
            queue_size: 0,
            processing_latency: Duration::from_millis(0),
        }
    }
}

impl Default for NetworkIO {
    fn default() -> Self {
        Self {
            bytes_sent: 0,
            bytes_received: 0,
            requests_sent: 0,
            responses_received: 0,
        }
    }
}

impl Default for ErrorStatistics {
    fn default() -> Self {
        Self {
            total_errors: 0,
            errors_by_type: HashMap::new(),
            recent_errors: Vec::new(),
            error_rate_trend: Vec::new(),
        }
    }
}

// Utility functions
pub fn create_default_siem_manager() -> Result<SiemIntegrationManager, SiemError> {
    let config = SiemConfig::default();
    SiemIntegrationManager::new(config)
}

pub fn validate_siem_config(config: &SiemConfig) -> Result<(), SiemError> {
    if config.general_config.enabled_integrations.is_empty() {
        return Err(SiemError::ConfigurationError(
            "At least one SIEM integration must be enabled".to_string(),
        ));
    }
    
    if config.general_config.event_buffer_size == 0 {
        return Err(SiemError::ConfigurationError(
            "Event buffer size must be greater than 0".to_string(),
        ));
    }
    
    // Validate individual SIEM configurations
    if config.general_config.enabled_integrations.contains(&SiemType::Splunk) {
        if config.splunk_config.is_none() {
            return Err(SiemError::ConfigurationError(
                "Splunk configuration is required when Splunk integration is enabled".to_string(),
            ));
        }
    }
    
    if config.general_config.enabled_integrations.contains(&SiemType::QRadar) {
        if config.qradar_config.is_none() {
            return Err(SiemError::ConfigurationError(
                "QRadar configuration is required when QRadar integration is enabled".to_string(),
            ));
        }
    }
    
    if config.general_config.enabled_integrations.contains(&SiemType::Sentinel) {
        if config.sentinel_config.is_none() {
            return Err(SiemError::ConfigurationError(
                "Sentinel configuration is required when Sentinel integration is enabled".to_string(),
            ));
        }
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_siem_manager_creation() {
        let manager = create_default_siem_manager();
        assert!(manager.is_ok());
    }

    #[test]
    fn test_config_validation() {
        let config = SiemConfig::default();
        assert!(validate_siem_config(&config).is_ok());
        
        let mut invalid_config = config.clone();
        invalid_config.general_config.enabled_integrations.clear();
        assert!(validate_siem_config(&invalid_config).is_err());
    }

    #[test]
    fn test_splunk_client_creation() {
        let config = SplunkConfig {
            host: "localhost".to_string(),
            port: 8088,
            username: "admin".to_string(),
            password: "password".to_string(),
            index: "main".to_string(),
            source_type: "erdps".to_string(),
            use_ssl: false,
            verify_ssl: false,
            hec_token: None,
            hec_endpoint: None,
            batch_size: 100,
            flush_interval: Duration::from_secs(30),
            compression: false,
        };
        
        let client = SplunkClient::new(config);
        assert!(client.is_ok());
    }

    #[test]
    fn test_qradar_client_creation() {
        let config = QRadarConfig {
            host: "localhost".to_string(),
            port: 443,
            api_token: "test-token".to_string(),
            api_version: "14.0".to_string(),
            use_ssl: true,
            verify_ssl: false,
            log_source_id: Some(1),
            event_category: 1000,
            severity: 5,
            batch_size: 100,
            flush_interval: Duration::from_secs(30),
        };
        
        let client = QRadarClient::new(config);
        assert!(client.is_ok());
    }

    #[test]
    fn test_sentinel_client_creation() {
        let config = SentinelConfig {
            workspace_id: "test-workspace".to_string(),
            shared_key: "dGVzdC1rZXk=".to_string(), // base64 encoded "test-key"
            log_type: "ERDPS".to_string(),
            api_version: "2016-04-01".to_string(),
            endpoint: "https://test-workspace.ods.opinsights.azure.com".to_string(),
            batch_size: 100,
            flush_interval: Duration::from_secs(30),
            time_generated_field: "TimeGenerated".to_string(),
        };
        
        let client = SentinelClient::new(config);
        assert!(client.is_ok());
    }

    #[test]
    fn test_siem_event_creation() {
        let event = SiemEvent {
            event_id: "test-event".to_string(),
            timestamp: 1234567890,
            event_type: EventType::ThreatDetection,
            severity: SeverityLevel::High,
            source: "192.168.1.1".to_string(),
            destination: Some("192.168.1.100".to_string()),
            message: "Test threat detected".to_string(),
            details: HashMap::new(),
            raw_data: None,
            tags: vec!["test".to_string(), "threat".to_string()],
            correlation_id: Some("corr-123".to_string()),
        };
        
        assert_eq!(event.event_id, "test-event");
        assert_eq!(event.severity, SeverityLevel::High);
    }

    #[test]
    fn test_default_configurations() {
        let config = SiemConfig::default();
        assert!(!config.general_config.enabled_integrations.is_empty());
        assert_eq!(config.general_config.default_severity, SeverityLevel::Medium);
        assert!(config.general_config.metrics_collection);
    }

    #[test]
    fn test_siem_types() {
        let types = vec![
            SiemType::Splunk,
            SiemType::QRadar,
            SiemType::Sentinel,
            SiemType::Generic,
        ];
        
        for siem_type in types {
            assert!(matches!(siem_type, SiemType::Splunk | SiemType::QRadar | SiemType::Sentinel | SiemType::Generic));
        }
    }

    #[test]
    fn test_severity_levels() {
        assert_eq!(SeverityLevel::Critical as u32, 1);
        assert_eq!(SeverityLevel::High as u32, 2);
        assert_eq!(SeverityLevel::Medium as u32, 3);
        assert_eq!(SeverityLevel::Low as u32, 4);
        assert_eq!(SeverityLevel::Info as u32, 5);
    }

    #[test]
    fn test_metrics_default() {
        let metrics = SiemMetrics::default();
        assert_eq!(metrics.events_sent, 0);
        assert_eq!(metrics.events_failed, 0);
        assert_eq!(metrics.error_rate, 0.0);
    }
}
