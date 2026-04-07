//! Load Balancer Management
//!
//! This module provides comprehensive load balancing capabilities
//! for deployment systems, including various algorithms and health monitoring.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use uuid::Uuid;
use tracing::{info, warn, error, debug};

use crate::core::error::Result;

/// Type alias for backward compatibility
pub type LoadBalancer = LoadBalancerManager;

/// Load balancer manager
#[derive(Debug)]
pub struct LoadBalancerManager {
    /// Load balancer configuration
    config: LoadBalancerConfig,
    /// Backend servers
    backends: Arc<RwLock<HashMap<String, Backend>>>,
    /// Load balancing algorithm
    algorithm: Arc<RwLock<Box<dyn LoadBalancingAlgorithm + Send + Sync>>>,
    /// Health checker
    health_checker: Arc<RwLock<HealthChecker>>,
    /// Connection pool
    connection_pool: Arc<RwLock<ConnectionPool>>,
    /// Metrics collector
    metrics: Arc<RwLock<LoadBalancerMetrics>>,
}

/// Load balancer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadBalancerConfig {
    /// Load balancing strategy
    pub strategy: LoadBalancingStrategy,
    /// Health check configuration
    pub health_check: HealthCheckConfig,
    /// Connection configuration
    pub connection: ConnectionConfig,
    /// Timeout configuration
    pub timeout: TimeoutConfig,
    /// Retry configuration
    pub retry: RetryConfig,
    /// Circuit breaker configuration
    pub circuit_breaker: CircuitBreakerConfig,
    /// SSL/TLS configuration
    pub tls: Option<TlsConfig>,
    /// Session affinity configuration
    pub session_affinity: SessionAffinityConfig,
    /// Rate limiting configuration
    pub rate_limiting: RateLimitingConfig,
}

/// Load balancing strategies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LoadBalancingStrategy {
    RoundRobin,
    WeightedRoundRobin,
    LeastConnections,
    WeightedLeastConnections,
    IpHash,
    ConsistentHash,
    Random,
    WeightedRandom,
    LeastResponseTime,
    ResourceBased,
    Geographic,
    Custom(String),
}

/// Backend server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Backend {
    /// Backend ID
    pub id: String,
    /// Backend address
    pub address: String,
    /// Backend port
    pub port: u16,
    /// Backend weight
    pub weight: u32,
    /// Backend status
    pub status: BackendStatus,
    /// Backend metadata
    pub metadata: BackendMetadata,
    /// Health status
    pub health: HealthStatus,
    /// Connection statistics
    pub stats: ConnectionStats,
    /// Last health check
    pub last_health_check: SystemTime,
}

/// Backend status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BackendStatus {
    Active,
    Inactive,
    Draining,
    Maintenance,
    Failed,
}

/// Backend metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendMetadata {
    /// Backend name
    pub name: String,
    /// Backend version
    pub version: String,
    /// Backend region
    pub region: String,
    /// Backend zone
    pub zone: String,
    /// Backend tags
    pub tags: HashMap<String, String>,
    /// Backend capabilities
    pub capabilities: Vec<String>,
}

/// Health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    /// Is healthy
    pub healthy: bool,
    /// Health score (0.0 to 1.0)
    pub score: f64,
    /// Last check time
    pub last_check: SystemTime,
    /// Check count
    pub check_count: u64,
    /// Failure count
    pub failure_count: u64,
    /// Response time
    pub response_time: Duration,
    /// Error message
    pub error: Option<String>,
}

/// Connection statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionStats {
    /// Active connections
    pub active_connections: u32,
    /// Total connections
    pub total_connections: u64,
    /// Failed connections
    pub failed_connections: u64,
    /// Average response time
    pub avg_response_time: Duration,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_received: u64,
    /// Requests per second
    pub requests_per_second: f64,
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
    /// Health check path
    pub path: String,
    /// Expected status code
    pub expected_status: u16,
    /// Expected response body
    pub expected_body: Option<String>,
    /// Health check method
    pub method: HttpMethod,
    /// Health check headers
    pub headers: HashMap<String, String>,
    /// Healthy threshold
    pub healthy_threshold: u32,
    /// Unhealthy threshold
    pub unhealthy_threshold: u32,
}

/// HTTP methods
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HttpMethod {
    GET,
    POST,
    PUT,
    DELETE,
    HEAD,
    OPTIONS,
    PATCH,
}

/// Connection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionConfig {
    /// Maximum connections per backend
    pub max_connections_per_backend: u32,
    /// Connection pool size
    pub pool_size: u32,
    /// Connection timeout
    pub connect_timeout: Duration,
    /// Keep-alive timeout
    pub keep_alive_timeout: Duration,
    /// Idle timeout
    pub idle_timeout: Duration,
    /// Connection reuse
    pub reuse_connections: bool,
}

/// Timeout configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeoutConfig {
    /// Request timeout
    pub request_timeout: Duration,
    /// Response timeout
    pub response_timeout: Duration,
    /// Backend timeout
    pub backend_timeout: Duration,
    /// Total timeout
    pub total_timeout: Duration,
}

/// Retry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum retries
    pub max_retries: u32,
    /// Retry delay
    pub retry_delay: Duration,
    /// Retry backoff
    pub backoff: BackoffStrategy,
    /// Retry conditions
    pub retry_conditions: Vec<RetryCondition>,
}

/// Backoff strategies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BackoffStrategy {
    Fixed,
    Linear,
    Exponential,
    Custom(String),
}

/// Retry conditions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RetryCondition {
    ConnectionError,
    Timeout,
    ServerError,
    StatusCode(u16),
    Custom(String),
}

/// Circuit breaker configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    /// Enable circuit breaker
    pub enabled: bool,
    /// Failure threshold
    pub failure_threshold: u32,
    /// Success threshold
    pub success_threshold: u32,
    /// Timeout duration
    pub timeout: Duration,
    /// Half-open timeout
    pub half_open_timeout: Duration,
}

/// TLS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Enable TLS
    pub enabled: bool,
    /// Certificate path
    pub cert_path: String,
    /// Private key path
    pub key_path: String,
    /// CA certificate path
    pub ca_path: Option<String>,
    /// TLS version
    pub version: TlsVersion,
    /// Cipher suites
    pub cipher_suites: Vec<String>,
    /// Verify certificates
    pub verify_certs: bool,
}

/// TLS versions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TlsVersion {
    TLS1_0,
    TLS1_1,
    TLS1_2,
    TLS1_3,
}

/// Session affinity configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionAffinityConfig {
    /// Enable session affinity
    pub enabled: bool,
    /// Affinity type
    pub affinity_type: AffinityType,
    /// Cookie name
    pub cookie_name: String,
    /// Cookie duration
    pub cookie_duration: Duration,
    /// Sticky sessions
    pub sticky_sessions: bool,
}

/// Affinity types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AffinityType {
    Cookie,
    IpHash,
    Header(String),
    Custom(String),
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitingConfig {
    /// Enable rate limiting
    pub enabled: bool,
    /// Requests per second
    pub requests_per_second: u32,
    /// Burst size
    pub burst_size: u32,
    /// Rate limiting algorithm
    pub algorithm: RateLimitingAlgorithm,
    /// Rate limiting scope
    pub scope: RateLimitingScope,
}

/// Rate limiting algorithms
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RateLimitingAlgorithm {
    TokenBucket,
    LeakyBucket,
    FixedWindow,
    SlidingWindow,
    Custom(String),
}

/// Rate limiting scopes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RateLimitingScope {
    Global,
    PerBackend,
    PerClient,
    Custom(String),
}

/// Load balancing algorithm trait
pub trait LoadBalancingAlgorithm: std::fmt::Debug {
    /// Select a backend for the request
    fn select_backend(&self, backends: &[Backend], request: &LoadBalancerRequest) -> Option<String>;
    
    /// Get algorithm name
    fn name(&self) -> &str;
    
    /// Update algorithm state
    fn update_state(&mut self, backend_id: &str, response: &LoadBalancerResponse);
}

/// Load balancer request
#[derive(Debug, Clone)]
pub struct LoadBalancerRequest {
    /// Request ID
    pub id: String,
    /// Client IP
    pub client_ip: String,
    /// Request headers
    pub headers: HashMap<String, String>,
    /// Request path
    pub path: String,
    /// Request method
    pub method: HttpMethod,
    /// Request timestamp
    pub timestamp: SystemTime,
}

/// Load balancer response
#[derive(Debug, Clone)]
pub struct LoadBalancerResponse {
    /// Response status
    pub status: u16,
    /// Response time
    pub response_time: Duration,
    /// Response size
    pub size: u64,
    /// Backend ID
    pub backend_id: String,
    /// Error message
    pub error: Option<String>,
}

/// Health checker
#[derive(Debug)]
pub struct HealthChecker {
    /// Health check configuration
    config: HealthCheckConfig,
    /// HTTP client
    client: reqwest::Client,
}

/// Connection pool
#[derive(Debug)]
pub struct ConnectionPool {
    /// Pool configuration
    config: ConnectionConfig,
    /// Active connections
    connections: HashMap<String, Vec<Connection>>,
}

/// Connection
#[derive(Debug, Clone)]
pub struct Connection {
    /// Connection ID
    pub id: String,
    /// Backend ID
    pub backend_id: String,
    /// Connection status
    pub status: ConnectionStatus,
    /// Created timestamp
    pub created_at: SystemTime,
    /// Last used timestamp
    pub last_used: SystemTime,
    /// Request count
    pub request_count: u64,
}

/// Connection status
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ConnectionStatus {
    Active,
    Idle,
    Closed,
    Error,
}

/// Load balancer metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadBalancerMetrics {
    /// Total requests
    pub total_requests: u64,
    /// Successful requests
    pub successful_requests: u64,
    /// Failed requests
    pub failed_requests: u64,
    /// Average response time
    pub avg_response_time: Duration,
    /// Requests per second
    pub requests_per_second: f64,
    /// Backend distribution
    pub backend_distribution: HashMap<String, u64>,
    /// Error distribution
    pub error_distribution: HashMap<String, u64>,
}

// Algorithm implementations

/// Round robin algorithm
#[derive(Debug)]
pub struct RoundRobinAlgorithm {
    current_index: std::sync::atomic::AtomicUsize,
}

/// Weighted round robin algorithm
#[derive(Debug)]
pub struct WeightedRoundRobinAlgorithm {
    current_weights: Arc<RwLock<HashMap<String, u32>>>,
}

/// Least connections algorithm
#[derive(Debug)]
pub struct LeastConnectionsAlgorithm;

/// IP hash algorithm
#[derive(Debug)]
pub struct IpHashAlgorithm;

/// Random algorithm
#[derive(Debug)]
pub struct RandomAlgorithm;

// Default implementations
impl Default for LoadBalancerConfig {
    fn default() -> Self {
        Self {
            strategy: LoadBalancingStrategy::RoundRobin,
            health_check: HealthCheckConfig::default(),
            connection: ConnectionConfig::default(),
            timeout: TimeoutConfig::default(),
            retry: RetryConfig::default(),
            circuit_breaker: CircuitBreakerConfig::default(),
            tls: None,
            session_affinity: SessionAffinityConfig::default(),
            rate_limiting: RateLimitingConfig::default(),
        }
    }
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval: Duration::from_secs(30),
            timeout: Duration::from_secs(5),
            path: "/health".to_string(),
            expected_status: 200,
            expected_body: None,
            method: HttpMethod::GET,
            headers: HashMap::new(),
            healthy_threshold: 2,
            unhealthy_threshold: 3,
        }
    }
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            max_connections_per_backend: 100,
            pool_size: 10,
            connect_timeout: Duration::from_secs(5),
            keep_alive_timeout: Duration::from_secs(60),
            idle_timeout: Duration::from_secs(300),
            reuse_connections: true,
        }
    }
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(30),
            response_timeout: Duration::from_secs(30),
            backend_timeout: Duration::from_secs(60),
            total_timeout: Duration::from_secs(120),
        }
    }
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            retry_delay: Duration::from_millis(100),
            backoff: BackoffStrategy::Exponential,
            retry_conditions: vec![
                RetryCondition::ConnectionError,
                RetryCondition::Timeout,
                RetryCondition::ServerError,
            ],
        }
    }
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            failure_threshold: 5,
            success_threshold: 3,
            timeout: Duration::from_secs(60),
            half_open_timeout: Duration::from_secs(30),
        }
    }
}

impl Default for SessionAffinityConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            affinity_type: AffinityType::Cookie,
            cookie_name: "lb_session".to_string(),
            cookie_duration: Duration::from_secs(3600),
            sticky_sessions: false,
        }
    }
}

impl Default for RateLimitingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            requests_per_second: 1000,
            burst_size: 100,
            algorithm: RateLimitingAlgorithm::TokenBucket,
            scope: RateLimitingScope::Global,
        }
    }
}

impl Default for LoadBalancerMetrics {
    fn default() -> Self {
        Self {
            total_requests: 0,
            successful_requests: 0,
            failed_requests: 0,
            avg_response_time: Duration::from_millis(0),
            requests_per_second: 0.0,
            backend_distribution: HashMap::new(),
            error_distribution: HashMap::new(),
        }
    }
}

// Algorithm implementations
impl LoadBalancingAlgorithm for RoundRobinAlgorithm {
    fn select_backend(&self, backends: &[Backend], _request: &LoadBalancerRequest) -> Option<String> {
        let active_backends: Vec<&Backend> = backends
            .iter()
            .filter(|b| b.status == BackendStatus::Active && b.health.healthy)
            .collect();
        
        if active_backends.is_empty() {
            return None;
        }
        
        let index = self.current_index.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % active_backends.len();
        Some(active_backends[index].id.clone())
    }
    
    fn name(&self) -> &str {
        "round_robin"
    }
    
    fn update_state(&mut self, _backend_id: &str, _response: &LoadBalancerResponse) {
        // No state to update for round robin
    }
}

impl LoadBalancingAlgorithm for LeastConnectionsAlgorithm {
    fn select_backend(&self, backends: &[Backend], _request: &LoadBalancerRequest) -> Option<String> {
        backends
            .iter()
            .filter(|b| b.status == BackendStatus::Active && b.health.healthy)
            .min_by_key(|b| b.stats.active_connections)
            .map(|b| b.id.clone())
    }
    
    fn name(&self) -> &str {
        "least_connections"
    }
    
    fn update_state(&mut self, _backend_id: &str, _response: &LoadBalancerResponse) {
        // Connection counts are updated elsewhere
    }
}

impl LoadBalancingAlgorithm for IpHashAlgorithm {
    fn select_backend(&self, backends: &[Backend], request: &LoadBalancerRequest) -> Option<String> {
        let active_backends: Vec<&Backend> = backends
            .iter()
            .filter(|b| b.status == BackendStatus::Active && b.health.healthy)
            .collect();
        
        if active_backends.is_empty() {
            return None;
        }
        
        let hash = self.hash_ip(&request.client_ip);
        let index = hash % active_backends.len();
        Some(active_backends[index].id.clone())
    }
    
    fn name(&self) -> &str {
        "ip_hash"
    }
    
    fn update_state(&mut self, _backend_id: &str, _response: &LoadBalancerResponse) {
        // No state to update for IP hash
    }
}

impl IpHashAlgorithm {
    fn hash_ip(&self, ip: &str) -> usize {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        ip.hash(&mut hasher);
        hasher.finish() as usize
    }
}

impl LoadBalancingAlgorithm for RandomAlgorithm {
    fn select_backend(&self, backends: &[Backend], _request: &LoadBalancerRequest) -> Option<String> {
        let active_backends: Vec<&Backend> = backends
            .iter()
            .filter(|b| b.status == BackendStatus::Active && b.health.healthy)
            .collect();
        
        if active_backends.is_empty() {
            return None;
        }
        
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let index = rng.gen_range(0..active_backends.len());
        Some(active_backends[index].id.clone())
    }
    
    fn name(&self) -> &str {
        "random"
    }
    
    fn update_state(&mut self, _backend_id: &str, _response: &LoadBalancerResponse) {
        // No state to update for random
    }
}

// Implementation
impl LoadBalancerManager {
    /// Create a new load balancer manager
    pub async fn new(config: LoadBalancerConfig) -> Result<Self> {
        let algorithm: Box<dyn LoadBalancingAlgorithm + Send + Sync> = match config.strategy {
            LoadBalancingStrategy::RoundRobin => Box::new(RoundRobinAlgorithm {
                current_index: std::sync::atomic::AtomicUsize::new(0),
            }),
            LoadBalancingStrategy::LeastConnections => Box::new(LeastConnectionsAlgorithm),
            LoadBalancingStrategy::IpHash => Box::new(IpHashAlgorithm),
            LoadBalancingStrategy::Random => Box::new(RandomAlgorithm),
            _ => Box::new(RoundRobinAlgorithm {
                current_index: std::sync::atomic::AtomicUsize::new(0),
            }),
        };
        
        let health_checker = HealthChecker::new(config.health_check.clone())?;
        let connection_pool = ConnectionPool::new(config.connection.clone());
        
        Ok(Self {
            config,
            backends: Arc::new(RwLock::new(HashMap::new())),
            algorithm: Arc::new(RwLock::new(algorithm)),
            health_checker: Arc::new(RwLock::new(health_checker)),
            connection_pool: Arc::new(RwLock::new(connection_pool)),
            metrics: Arc::new(RwLock::new(LoadBalancerMetrics::default())),
        })
    }

    /// Add a backend server
    pub async fn add_backend(&self, backend: Backend) -> Result<()> {
        let mut backends = self.backends.write().await;
        backends.insert(backend.id.clone(), backend);
        info!("Added backend: {}", backends.len());
        Ok(())
    }

    /// Remove a backend server
    pub async fn remove_backend(&self, backend_id: &str) -> Result<()> {
        let mut backends = self.backends.write().await;
        backends.remove(backend_id);
        info!("Removed backend: {}", backend_id);
        Ok(())
    }

    /// Route a request to a backend
    pub async fn route_request(&self, request: LoadBalancerRequest) -> Result<String> {
        let backends = self.backends.read().await;
        let algorithm = self.algorithm.read().await;
        
        let backend_list: Vec<Backend> = backends.values().cloned().collect();
        
        if let Some(backend_id) = algorithm.select_backend(&backend_list, &request) {
            // Update metrics
            let mut metrics = self.metrics.write().await;
            metrics.total_requests += 1;
            *metrics.backend_distribution.entry(backend_id.clone()).or_insert(0) += 1;
            
            debug!("Routed request {} to backend {}", request.id, backend_id);
            Ok(backend_id)
        } else {
            error!("No healthy backends available for request {}", request.id);
            Err(crate::core::error::Error::LoadBalancerError("No healthy backends available".to_string()))
        }
    }

    /// Perform health checks on all backends
    pub async fn perform_health_checks(&self) -> Result<()> {
        let mut backends = self.backends.write().await;
        let health_checker = self.health_checker.read().await;
        
        for backend in backends.values_mut() {
            let health_result = health_checker.check_backend(backend).await;
            backend.health = health_result;
            backend.last_health_check = SystemTime::now();
            
            if !backend.health.healthy {
                warn!("Backend {} is unhealthy: {:?}", backend.id, backend.health.error);
            }
        }
        
        Ok(())
    }

    /// Get load balancer metrics
    pub async fn get_metrics(&self) -> LoadBalancerMetrics {
        let metrics = self.metrics.read().await;
        metrics.clone()
    }

    /// Update backend status
    pub async fn update_backend_status(&self, backend_id: &str, status: BackendStatus) -> Result<()> {
        let mut backends = self.backends.write().await;
        
        if let Some(backend) = backends.get_mut(backend_id) {
            backend.status = status;
            info!("Updated backend {} status to {:?}", backend_id, backend.status);
        }
        
        Ok(())
    }

    /// Get backend statistics
    pub async fn get_backend_stats(&self, backend_id: &str) -> Option<ConnectionStats> {
        let backends = self.backends.read().await;
        backends.get(backend_id).map(|b| b.stats.clone())
    }

    /// Update connection statistics
    pub async fn update_connection_stats(&self, backend_id: &str, response: LoadBalancerResponse) -> Result<()> {
        let mut backends = self.backends.write().await;
        let mut metrics = self.metrics.write().await;
        
        if let Some(backend) = backends.get_mut(backend_id) {
            // Update backend stats
            backend.stats.total_connections += 1;
            
            if response.status >= 200 && response.status < 400 {
                metrics.successful_requests += 1;
            } else {
                backend.stats.failed_connections += 1;
                metrics.failed_requests += 1;
                
                if let Some(error) = &response.error {
                    *metrics.error_distribution.entry(error.clone()).or_insert(0) += 1;
                }
            }
            
            // Update response time
            let current_avg = backend.stats.avg_response_time;
            let new_avg = Duration::from_nanos(
                (current_avg.as_nanos() as u64 + response.response_time.as_nanos() as u64) / 2
            );
            backend.stats.avg_response_time = new_avg;
            
            // Update global metrics
            metrics.avg_response_time = Duration::from_nanos(
                (metrics.avg_response_time.as_nanos() as u64 + response.response_time.as_nanos() as u64) / 2
            );
        }
        
        Ok(())
    }
}

impl HealthChecker {
    /// Create a new health checker
    pub fn new(config: HealthCheckConfig) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(config.timeout)
            .build()
            .map_err(|e| crate::core::error::Error::LoadBalancerError(format!("Failed to create HTTP client: {}", e)))?;
        
        Ok(Self { config, client })
    }

    /// Check backend health
    pub async fn check_backend(&self, backend: &Backend) -> HealthStatus {
        if !self.config.enabled {
            return HealthStatus {
                healthy: true,
                score: 1.0,
                last_check: SystemTime::now(),
                check_count: backend.health.check_count + 1,
                failure_count: backend.health.failure_count,
                response_time: Duration::from_millis(0),
                error: None,
            };
        }
        
        let start_time = SystemTime::now();
        let url = format!("http://{}:{}{}", backend.address, backend.port, self.config.path);
        
        let mut request = match self.config.method {
            HttpMethod::GET => self.client.get(&url),
            HttpMethod::POST => self.client.post(&url),
            HttpMethod::PUT => self.client.put(&url),
            HttpMethod::DELETE => self.client.delete(&url),
            HttpMethod::HEAD => self.client.head(&url),
            HttpMethod::OPTIONS => self.client.request(reqwest::Method::OPTIONS, &url),
            HttpMethod::PATCH => self.client.patch(&url),
        };
        
        // Add headers
        for (key, value) in &self.config.headers {
            request = request.header(key, value);
        }
        
        match request.send().await {
            Ok(response) => {
                let response_time = start_time.elapsed().unwrap_or(Duration::from_millis(0));
                let status = response.status().as_u16();
                
                let healthy = status == self.config.expected_status;
                let score = if healthy { 1.0 } else { 0.0 };
                
                let failure_count = if healthy {
                    0
                } else {
                    backend.health.failure_count + 1
                };
                
                HealthStatus {
                    healthy,
                    score,
                    last_check: SystemTime::now(),
                    check_count: backend.health.check_count + 1,
                    failure_count,
                    response_time,
                    error: if healthy { None } else { Some(format!("Unexpected status code: {}", status)) },
                }
            },
            Err(e) => {
                let response_time = start_time.elapsed().unwrap_or(Duration::from_millis(0));
                
                HealthStatus {
                    healthy: false,
                    score: 0.0,
                    last_check: SystemTime::now(),
                    check_count: backend.health.check_count + 1,
                    failure_count: backend.health.failure_count + 1,
                    response_time,
                    error: Some(format!("Health check failed: {}", e)),
                }
            }
        }
    }
}

impl ConnectionPool {
    /// Create a new connection pool
    pub fn new(config: ConnectionConfig) -> Self {
        Self {
            config,
            connections: HashMap::new(),
        }
    }

    /// Get a connection for a backend
    pub fn get_connection(&mut self, backend_id: &str) -> Option<Connection> {
        let connections = self.connections.entry(backend_id.to_string()).or_insert_with(Vec::new);
        
        // Find an idle connection
        for connection in connections.iter_mut() {
            if connection.status == ConnectionStatus::Idle {
                connection.status = ConnectionStatus::Active;
                connection.last_used = SystemTime::now();
                return Some(connection.clone());
            }
        }
        
        // Create a new connection if under limit
        if connections.len() < self.config.max_connections_per_backend as usize {
            let connection = Connection {
                id: Uuid::new_v4().to_string(),
                backend_id: backend_id.to_string(),
                status: ConnectionStatus::Active,
                created_at: SystemTime::now(),
                last_used: SystemTime::now(),
                request_count: 0,
            };
            
            connections.push(connection.clone());
            Some(connection)
        } else {
            None
        }
    }

    /// Return a connection to the pool
    pub fn return_connection(&mut self, connection: Connection) {
        if let Some(connections) = self.connections.get_mut(&connection.backend_id) {
            for conn in connections.iter_mut() {
                if conn.id == connection.id {
                    conn.status = ConnectionStatus::Idle;
                    conn.last_used = SystemTime::now();
                    conn.request_count += 1;
                    break;
                }
            }
        }
    }

    /// Clean up idle connections
    pub fn cleanup_idle_connections(&mut self) {
        let now = SystemTime::now();
        
        for connections in self.connections.values_mut() {
            connections.retain(|conn| {
                if conn.status == ConnectionStatus::Idle {
                    if let Ok(duration) = now.duration_since(conn.last_used) {
                        duration < self.config.idle_timeout
                    } else {
                        false
                    }
                } else {
                    true
                }
            });
        }
    }
}

/// Utility functions
pub fn create_default_load_balancer() -> LoadBalancerManager {
    LoadBalancerManager {
        config: LoadBalancerConfig::default(),
        backends: Arc::new(RwLock::new(HashMap::new())),
        algorithm: Arc::new(RwLock::new(Box::new(RoundRobinAlgorithm {
            current_index: std::sync::atomic::AtomicUsize::new(0),
        }))),
        health_checker: Arc::new(RwLock::new(HealthChecker {
            config: HealthCheckConfig::default(),
            client: reqwest::Client::new(),
        })),
        connection_pool: Arc::new(RwLock::new(ConnectionPool::new(ConnectionConfig::default()))),
        metrics: Arc::new(RwLock::new(LoadBalancerMetrics::default())),
    }
}

pub fn validate_load_balancer_config(config: &LoadBalancerConfig) -> bool {
    // Validate health check configuration
    if config.health_check.enabled {
        if config.health_check.interval.as_secs() == 0 {
            return false;
        }
        
        if config.health_check.timeout.as_secs() == 0 {
            return false;
        }
        
        if config.health_check.healthy_threshold == 0 {
            return false;
        }
        
        if config.health_check.unhealthy_threshold == 0 {
            return false;
        }
    }
    
    // Validate connection configuration
    if config.connection.max_connections_per_backend == 0 {
        return false;
    }
    
    if config.connection.pool_size == 0 {
        return false;
    }
    
    // Validate timeout configuration
    if config.timeout.request_timeout.as_secs() == 0 {
        return false;
    }
    
    if config.timeout.response_timeout.as_secs() == 0 {
        return false;
    }
    
    // Validate retry configuration
    if config.retry.max_retries == 0 {
        return false;
    }
    
    // Validate rate limiting configuration
    if config.rate_limiting.enabled {
        if config.rate_limiting.requests_per_second == 0 {
            return false;
        }
        
        if config.rate_limiting.burst_size == 0 {
            return false;
        }
    }
    
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_load_balancer_creation() {
        let config = LoadBalancerConfig::default();
        let lb = LoadBalancerManager::new(config).await;
        assert!(lb.is_ok());
    }
    
    #[tokio::test]
    async fn test_backend_management() {
        let config = LoadBalancerConfig::default();
        let lb = LoadBalancerManager::new(config).await.unwrap();
        
        let backend = Backend {
            id: "backend1".to_string(),
            address: "127.0.0.1".to_string(),
            port: 8080,
            weight: 1,
            status: BackendStatus::Active,
            metadata: BackendMetadata {
                name: "Test Backend".to_string(),
                version: "1.0.0".to_string(),
                region: "us-east-1".to_string(),
                zone: "us-east-1a".to_string(),
                tags: HashMap::new(),
                capabilities: vec![],
            },
            health: HealthStatus {
                healthy: true,
                score: 1.0,
                last_check: SystemTime::now(),
                check_count: 0,
                failure_count: 0,
                response_time: Duration::from_millis(0),
                error: None,
            },
            stats: ConnectionStats {
                active_connections: 0,
                total_connections: 0,
                failed_connections: 0,
                avg_response_time: Duration::from_millis(0),
                bytes_sent: 0,
                bytes_received: 0,
                requests_per_second: 0.0,
            },
            last_health_check: SystemTime::now(),
        };
        
        let result = lb.add_backend(backend).await;
        assert!(result.is_ok());
        
        let result = lb.remove_backend("backend1").await;
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_round_robin_algorithm() {
        let algorithm = RoundRobinAlgorithm {
            current_index: std::sync::atomic::AtomicUsize::new(0),
        };
        
        let backends = vec![
            Backend {
                id: "backend1".to_string(),
                address: "127.0.0.1".to_string(),
                port: 8080,
                weight: 1,
                status: BackendStatus::Active,
                metadata: BackendMetadata {
                    name: "Backend 1".to_string(),
                    version: "1.0.0".to_string(),
                    region: "us-east-1".to_string(),
                    zone: "us-east-1a".to_string(),
                    tags: HashMap::new(),
                    capabilities: vec![],
                },
                health: HealthStatus {
                    healthy: true,
                    score: 1.0,
                    last_check: SystemTime::now(),
                    check_count: 0,
                    failure_count: 0,
                    response_time: Duration::from_millis(0),
                    error: None,
                },
                stats: ConnectionStats {
                    active_connections: 0,
                    total_connections: 0,
                    failed_connections: 0,
                    avg_response_time: Duration::from_millis(0),
                    bytes_sent: 0,
                    bytes_received: 0,
                    requests_per_second: 0.0,
                },
                last_health_check: SystemTime::now(),
            },
            Backend {
                id: "backend2".to_string(),
                address: "127.0.0.1".to_string(),
                port: 8081,
                weight: 1,
                status: BackendStatus::Active,
                metadata: BackendMetadata {
                    name: "Backend 2".to_string(),
                    version: "1.0.0".to_string(),
                    region: "us-east-1".to_string(),
                    zone: "us-east-1a".to_string(),
                    tags: HashMap::new(),
                    capabilities: vec![],
                },
                health: HealthStatus {
                    healthy: true,
                    score: 1.0,
                    last_check: SystemTime::now(),
                    check_count: 0,
                    failure_count: 0,
                    response_time: Duration::from_millis(0),
                    error: None,
                },
                stats: ConnectionStats {
                    active_connections: 0,
                    total_connections: 0,
                    failed_connections: 0,
                    avg_response_time: Duration::from_millis(0),
                    bytes_sent: 0,
                    bytes_received: 0,
                    requests_per_second: 0.0,
                },
                last_health_check: SystemTime::now(),
            },
        ];
        
        let request = LoadBalancerRequest {
            id: "req1".to_string(),
            client_ip: "192.168.1.1".to_string(),
            headers: HashMap::new(),
            path: "/test".to_string(),
            method: HttpMethod::GET,
            timestamp: SystemTime::now(),
        };
        
        let backend1 = algorithm.select_backend(&backends, &request);
        let backend2 = algorithm.select_backend(&backends, &request);
        
        assert!(backend1.is_some());
        assert!(backend2.is_some());
        assert_ne!(backend1, backend2);
    }
    
    #[test]
    fn test_config_validation() {
        let valid_config = LoadBalancerConfig::default();
        assert!(validate_load_balancer_config(&valid_config));
        
        let mut invalid_config = valid_config.clone();
        invalid_config.connection.max_connections_per_backend = 0;
        assert!(!validate_load_balancer_config(&invalid_config));
    }
    
    #[test]
    fn test_default_configurations() {
        let config = LoadBalancerConfig::default();
        assert!(matches!(config.strategy, LoadBalancingStrategy::RoundRobin));
        assert!(config.health_check.enabled);
        assert_eq!(config.health_check.expected_status, 200);
        assert_eq!(config.connection.max_connections_per_backend, 100);
    }
    
    #[test]
    fn test_enum_serialization() {
        let strategy = LoadBalancingStrategy::RoundRobin;
        let serialized = serde_json::to_string(&strategy).unwrap();
        let deserialized: LoadBalancingStrategy = serde_json::from_str(&serialized).unwrap();
        assert!(matches!(deserialized, LoadBalancingStrategy::RoundRobin));
    }
    
    #[test]
    fn test_backend_status() {
        let status = BackendStatus::Active;
        assert_eq!(status, BackendStatus::Active);
        assert_ne!(status, BackendStatus::Inactive);
    }
    
    #[test]
    fn test_health_status() {
        let health = HealthStatus {
            healthy: true,
            score: 0.95,
            last_check: SystemTime::now(),
            check_count: 10,
            failure_count: 1,
            response_time: Duration::from_millis(50),
            error: None,
        };
        
        assert!(health.healthy);
        assert_eq!(health.score, 0.95);
        assert_eq!(health.check_count, 10);
        assert_eq!(health.failure_count, 1);
    }
}
