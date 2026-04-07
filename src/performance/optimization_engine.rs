//! Performance Optimization Engine for ERDPS
//!
//! This module provides comprehensive performance optimization capabilities including
//! memory management, connection pooling, caching mechanisms, and resource optimization.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};
use uuid::Uuid;
use crate::error::{AgentError, AgentResult, ErrorContext};

/// Performance metrics for monitoring optimization effectiveness
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationMetrics {
    pub memory_usage: u64,
    pub cache_hit_rate: f64,
    pub connection_pool_utilization: f64,
    pub average_response_time: Duration,
    pub throughput: f64,
    pub error_rate: f64,
    pub resource_utilization: ResourceUtilization,
}

/// Resource utilization metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUtilization {
    pub cpu_usage: f64,
    pub memory_usage: f64,
    pub disk_io: f64,
    pub network_io: f64,
    pub thread_count: u32,
    pub file_handles: u32,
}

/// Cache configuration and management
#[derive(Debug, Clone)]
pub struct CacheConfig {
    pub max_size: usize,
    pub ttl: Duration,
    pub eviction_policy: EvictionPolicy,
    pub compression_enabled: bool,
}

/// Cache eviction policies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EvictionPolicy {
    LRU,
    LFU,
    FIFO,
    TTL,
}

/// Connection pool configuration
#[derive(Debug, Clone)]
pub struct ConnectionPoolConfig {
    pub max_connections: u32,
    pub min_connections: u32,
    pub connection_timeout: Duration,
    pub idle_timeout: Duration,
    pub max_lifetime: Duration,
    pub health_check_interval: Duration,
}

/// Memory optimization configuration
#[derive(Debug, Clone)]
pub struct MemoryConfig {
    pub max_heap_size: u64,
    pub gc_threshold: f64,
    pub buffer_pool_size: usize,
    pub enable_memory_mapping: bool,
    pub compression_threshold: usize,
}

/// Performance optimization engine
pub struct OptimizationEngine {
    cache: Arc<RwLock<MultiLevelCache>>,
    connection_pool: Arc<ConnectionPool>,
    memory_manager: Arc<MemoryManager>,
    metrics: Arc<Mutex<OptimizationMetrics>>,
    config: OptimizationConfig,
}

/// Optimization configuration
#[derive(Debug, Clone)]
pub struct OptimizationConfig {
    pub cache_config: CacheConfig,
    pub connection_config: ConnectionPoolConfig,
    pub memory_config: MemoryConfig,
    pub enable_auto_tuning: bool,
    pub metrics_collection_interval: Duration,
}

/// Multi-level cache implementation
pub struct MultiLevelCache {
    l1_cache: HashMap<String, CacheEntry>,
    l2_cache: HashMap<String, CacheEntry>,
    l3_cache: HashMap<String, CacheEntry>,
    config: CacheConfig,
    stats: CacheStats,
}

/// Cache entry with metadata
#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub data: Vec<u8>,
    pub created_at: Instant,
    pub last_accessed: Instant,
    pub access_count: u64,
    pub size: usize,
    pub compressed: bool,
}

/// Cache statistics
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub total_size: usize,
    pub entry_count: usize,
}

/// Connection pool implementation
pub struct ConnectionPool {
    connections: Arc<Mutex<Vec<PooledConnection>>>,
    semaphore: Arc<Semaphore>,
    config: ConnectionPoolConfig,
    stats: Arc<Mutex<PoolStats>>,
}

/// Pooled connection wrapper
#[derive(Debug)]
pub struct PooledConnection {
    pub id: Uuid,
    pub created_at: Instant,
    pub last_used: Instant,
    pub is_healthy: bool,
    pub connection_data: Vec<u8>, // Placeholder for actual connection
}

/// Connection pool statistics
#[derive(Debug, Clone, Default)]
pub struct PoolStats {
    pub active_connections: u32,
    pub idle_connections: u32,
    pub total_connections: u32,
    pub connection_requests: u64,
    pub connection_timeouts: u64,
    pub health_check_failures: u64,
}

/// Memory manager for optimization
pub struct MemoryManager {
    buffer_pool: Arc<Mutex<Vec<Vec<u8>>>>,
    memory_stats: Arc<Mutex<MemoryStats>>,
    config: MemoryConfig,
}

/// Memory usage statistics
#[derive(Debug, Clone, Default)]
pub struct MemoryStats {
    pub allocated_bytes: u64,
    pub freed_bytes: u64,
    pub peak_usage: u64,
    pub buffer_pool_hits: u64,
    pub buffer_pool_misses: u64,
    pub gc_runs: u64,
}

impl OptimizationEngine {
    /// Create a new optimization engine
    pub fn new(config: OptimizationConfig) -> AgentResult<Self> {
        let cache = Arc::new(RwLock::new(MultiLevelCache::new(config.cache_config.clone())?));
        let connection_pool = Arc::new(ConnectionPool::new(config.connection_config.clone())?);
        let memory_manager = Arc::new(MemoryManager::new(config.memory_config.clone())?);
        
        let metrics = Arc::new(Mutex::new(OptimizationMetrics {
            memory_usage: 0,
            cache_hit_rate: 0.0,
            connection_pool_utilization: 0.0,
            average_response_time: Duration::from_millis(0),
            throughput: 0.0,
            error_rate: 0.0,
            resource_utilization: ResourceUtilization {
                cpu_usage: 0.0,
                memory_usage: 0.0,
                disk_io: 0.0,
                network_io: 0.0,
                thread_count: 0,
                file_handles: 0,
            },
        }));

        Ok(Self {
            cache,
            connection_pool,
            memory_manager,
            metrics,
            config,
        })
    }

    /// Start the optimization engine
    pub async fn start(&self) -> AgentResult<()> {
        info!("Starting performance optimization engine");
        
        // Start background tasks
        self.start_metrics_collection().await?;
        self.start_cache_maintenance().await?;
        self.start_connection_health_checks().await?;
        self.start_memory_management().await?;
        
        if self.config.enable_auto_tuning {
            self.start_auto_tuning().await?;
        }
        
        info!("Performance optimization engine started successfully");
        Ok(())
    }

    /// Get cached data
    pub async fn get_cached<T>(&self, key: &str) -> AgentResult<Option<T>>
    where
        T: serde::de::DeserializeOwned,
    {
        let cache = self.cache.read().map_err(|e| {
            AgentError::Resource {
                message: format!("Failed to acquire cache read lock: {}", e),
                resource_type: "cache_lock".to_string(),
                current_usage: None,
                limit: None,
                context: Some(ErrorContext::new("get_cached", "optimization_engine")),
            }
        })?;

        if let Some(entry) = cache.get_readonly(key) {
            let data: T = serde_json::from_slice(&entry.data).map_err(|e| {
                AgentError::Parse {
                    message: format!("Failed to deserialize cached data: {}", e),
                    input: None,
                    position: None,
                    context: Some(ErrorContext::new("get_cached", "optimization_engine")),
                }
            })?;
            Ok(Some(data))
        } else {
            Ok(None)
        }
    }

    /// Store data in cache
    pub async fn set_cached<T>(&self, key: &str, value: &T) -> AgentResult<()>
    where
        T: serde::Serialize,
    {
        let data = serde_json::to_vec(value).map_err(|e| {
            AgentError::Parse {
                message: format!("Failed to serialize data for caching: {}", e),
                input: None,
                position: None,
                context: Some(ErrorContext::new("set_cached", "optimization_engine")),
            }
        })?;

        let mut cache = self.cache.write().map_err(|e| {
            AgentError::Resource {
                message: format!("Failed to acquire cache write lock: {}", e),
                resource_type: "cache_lock".to_string(),
                current_usage: None,
                limit: None,
                context: Some(ErrorContext::new("set_cached", "optimization_engine")),
            }
        })?;

        cache.set(key.to_string(), data)?;
        Ok(())
    }

    /// Get a connection from the pool
    pub async fn get_connection(&self) -> AgentResult<PooledConnection> {
        self.connection_pool.get_connection().await
    }

    /// Return a connection to the pool
    pub async fn return_connection(&self, connection: PooledConnection) -> AgentResult<()> {
        self.connection_pool.return_connection(connection).await
    }

    /// Allocate optimized memory buffer
    pub async fn allocate_buffer(&self, size: usize) -> AgentResult<Vec<u8>> {
        self.memory_manager.allocate_buffer(size).await
    }

    /// Return buffer to pool
    pub async fn return_buffer(&self, buffer: Vec<u8>) -> AgentResult<()> {
        self.memory_manager.return_buffer(buffer).await
    }

    /// Get current performance metrics
    pub async fn get_metrics(&self) -> AgentResult<OptimizationMetrics> {
        let metrics = self.metrics.lock().map_err(|e| {
            AgentError::Resource {
                message: format!("Failed to acquire metrics lock: {}", e),
                resource_type: "metrics_lock".to_string(),
                current_usage: None,
                limit: None,
                context: Some(ErrorContext::new("get_metrics", "optimization_engine")),
            }
        })?;
        Ok(metrics.clone())
    }

    /// Start metrics collection background task
    async fn start_metrics_collection(&self) -> AgentResult<()> {
        let metrics = Arc::clone(&self.metrics);
        let cache = Arc::clone(&self.cache);
        let connection_pool = Arc::clone(&self.connection_pool);
        let memory_manager = Arc::clone(&self.memory_manager);
        let interval = self.config.metrics_collection_interval;

        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(interval);
            loop {
                interval_timer.tick().await;
                
                // Collect metrics outside the lock to avoid holding across await points
                let cache_hit_rate = if let Ok(cache_guard) = cache.read() {
                    cache_guard.get_hit_rate()
                } else {
                    0.0
                };
                
                let pool_utilization = if let Ok(pool_stats) = connection_pool.get_stats().await {
                    pool_stats.active_connections as f64 / pool_stats.total_connections as f64
                } else {
                    0.0
                };
                
                let memory_usage = if let Ok(memory_stats) = memory_manager.get_stats().await {
                    memory_stats.allocated_bytes
                } else {
                    0
                };
                
                // Update metrics with collected data
                if let Ok(mut metrics_guard) = metrics.lock() {
                    metrics_guard.cache_hit_rate = cache_hit_rate;
                    metrics_guard.connection_pool_utilization = pool_utilization;
                    metrics_guard.memory_usage = memory_usage;
                }
            }
        });

        Ok(())
    }

    /// Start cache maintenance background task
    async fn start_cache_maintenance(&self) -> AgentResult<()> {
        let cache = Arc::clone(&self.cache);
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                
                if let Ok(mut cache_guard) = cache.write() {
                    cache_guard.cleanup_expired();
                    cache_guard.optimize_storage();
                }
            }
        });

        Ok(())
    }

    /// Start connection health checks
    async fn start_connection_health_checks(&self) -> AgentResult<()> {
        let connection_pool = Arc::clone(&self.connection_pool);
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                interval.tick().await;
                
                if let Err(e) = connection_pool.health_check().await {
                    warn!("Connection pool health check failed: {}", e);
                }
            }
        });

        Ok(())
    }

    /// Start memory management background task
    async fn start_memory_management(&self) -> AgentResult<()> {
        let memory_manager = Arc::clone(&self.memory_manager);
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                interval.tick().await;
                
                if let Err(e) = memory_manager.garbage_collect().await {
                    warn!("Memory garbage collection failed: {}", e);
                }
            }
        });

        Ok(())
    }

    /// Start auto-tuning background task
    async fn start_auto_tuning(&self) -> AgentResult<()> {
        // Clone the Arc references for the spawned task
        let cache = Arc::clone(&self.cache);
        let connection_pool = Arc::clone(&self.connection_pool);
        let memory_manager = Arc::clone(&self.memory_manager);
        let metrics = Arc::clone(&self.metrics);
        let config = self.config.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300)); // 5 minutes
            loop {
                interval.tick().await;
                
                // Create a temporary engine instance for auto-tuning
                let temp_engine = OptimizationEngine {
                    cache: cache.clone(),
                    connection_pool: connection_pool.clone(),
                    memory_manager: memory_manager.clone(),
                    metrics: metrics.clone(),
                    config: config.clone(),
                };
                
                if let Err(e) = temp_engine.auto_tune().await {
                    warn!("Auto-tuning failed: {}", e);
                }
            }
        });
        
        Ok(())
    }

    /// Perform automatic performance tuning
    async fn auto_tune(&self) -> AgentResult<()> {
        let metrics = self.get_metrics().await?;
        
        // Tune cache based on hit rate
        if metrics.cache_hit_rate < 0.8 {
            self.tune_cache_size(1.2).await?;
        } else if metrics.cache_hit_rate > 0.95 {
            self.tune_cache_size(0.9).await?;
        }
        
        // Tune connection pool based on utilization
        if metrics.connection_pool_utilization > 0.9 {
            self.tune_connection_pool_size(1.5).await?;
        } else if metrics.connection_pool_utilization < 0.3 {
            self.tune_connection_pool_size(0.8).await?;
        }
        
        // Tune memory based on usage
        if metrics.memory_usage > (self.config.memory_config.max_heap_size as f64 * 0.9) as u64 {
            self.trigger_aggressive_gc().await?;
        }
        
        info!("Auto-tuning completed successfully");
        Ok(())
    }

    /// Tune cache size
    async fn tune_cache_size(&self, factor: f64) -> AgentResult<()> {
        debug!("Tuning cache size with factor: {}", factor);
        // Implementation would adjust cache size
        Ok(())
    }

    /// Tune connection pool size
    async fn tune_connection_pool_size(&self, factor: f64) -> AgentResult<()> {
        debug!("Tuning connection pool size with factor: {}", factor);
        // Implementation would adjust pool size
        Ok(())
    }

    /// Trigger aggressive garbage collection
    async fn trigger_aggressive_gc(&self) -> AgentResult<()> {
        debug!("Triggering aggressive garbage collection");
        self.memory_manager.aggressive_gc().await
    }
}

impl MultiLevelCache {
    pub fn new(config: CacheConfig) -> AgentResult<Self> {
        Ok(Self {
            l1_cache: HashMap::new(),
            l2_cache: HashMap::new(),
            l3_cache: HashMap::new(),
            config,
            stats: CacheStats::default(),
        })
    }

    pub fn get(&mut self, key: &str) -> Option<CacheEntry> {
        // Check L1 cache first
        if let Some(entry) = self.l1_cache.get_mut(key) {
            entry.last_accessed = Instant::now();
            entry.access_count += 1;
            self.stats.hits += 1;
            return Some(entry.clone());
        }

        // Check L2 cache
        if let Some(entry) = self.l2_cache.remove(key) {
            let cloned_entry = entry.clone();
            self.l1_cache.insert(key.to_string(), entry);
            self.stats.hits += 1;
            return Some(cloned_entry);
        }

        // Check L3 cache
        if let Some(entry) = self.l3_cache.remove(key) {
            let cloned_entry = entry.clone();
            self.l1_cache.insert(key.to_string(), entry);
            self.stats.hits += 1;
            return Some(cloned_entry);
        }

        self.stats.misses += 1;
        None
    }

    pub fn get_readonly(&self, key: &str) -> Option<CacheEntry> {
        // Check L1 cache first (read-only)
        if let Some(entry) = self.l1_cache.get(key) {
            return Some(entry.clone());
        }

        // Check L2 cache (read-only)
        if let Some(entry) = self.l2_cache.get(key) {
            return Some(entry.clone());
        }

        // Check L3 cache (read-only)
        if let Some(entry) = self.l3_cache.get(key) {
            return Some(entry.clone());
        }

        None
    }

    pub fn set(&mut self, key: String, data: Vec<u8>) -> AgentResult<()> {
        let entry_size = data.len();
        let entry = CacheEntry {
            size: entry_size,
            data,
            created_at: Instant::now(),
            last_accessed: Instant::now(),
            access_count: 1,
            compressed: false,
        };

        self.l1_cache.insert(key, entry);
        self.stats.entry_count += 1;
        self.stats.total_size += entry_size;

        // Evict if necessary
        self.evict_if_needed()?;
        
        Ok(())
    }

    pub fn get_hit_rate(&self) -> f64 {
        let total = self.stats.hits + self.stats.misses;
        if total == 0 {
            0.0
        } else {
            self.stats.hits as f64 / total as f64
        }
    }

    fn evict_if_needed(&mut self) -> AgentResult<()> {
        while self.stats.total_size > self.config.max_size {
            self.evict_one()?;
        }
        Ok(())
    }

    fn evict_one(&mut self) -> AgentResult<()> {
        match self.config.eviction_policy {
            EvictionPolicy::LRU => self.evict_lru(),
            EvictionPolicy::LFU => self.evict_lfu(),
            EvictionPolicy::FIFO => self.evict_fifo(),
            EvictionPolicy::TTL => self.evict_ttl(),
        }
    }

    fn evict_lru(&mut self) -> AgentResult<()> {
        let mut oldest_key = None;
        let mut oldest_time = Instant::now();

        for (key, entry) in &self.l1_cache {
            if entry.last_accessed < oldest_time {
                oldest_time = entry.last_accessed;
                oldest_key = Some(key.clone());
            }
        }

        if let Some(key) = oldest_key {
            if let Some(entry) = self.l1_cache.remove(&key) {
                self.stats.total_size -= entry.size;
                self.stats.entry_count -= 1;
                self.stats.evictions += 1;
            }
        }

        Ok(())
    }

    fn evict_lfu(&mut self) -> AgentResult<()> {
        let mut least_used_key = None;
        let mut least_count = u64::MAX;

        for (key, entry) in &self.l1_cache {
            if entry.access_count < least_count {
                least_count = entry.access_count;
                least_used_key = Some(key.clone());
            }
        }

        if let Some(key) = least_used_key {
            if let Some(entry) = self.l1_cache.remove(&key) {
                self.stats.total_size -= entry.size;
                self.stats.entry_count -= 1;
                self.stats.evictions += 1;
            }
        }

        Ok(())
    }

    fn evict_fifo(&mut self) -> AgentResult<()> {
        let mut oldest_key = None;
        let mut oldest_time = Instant::now();

        for (key, entry) in &self.l1_cache {
            if entry.created_at < oldest_time {
                oldest_time = entry.created_at;
                oldest_key = Some(key.clone());
            }
        }

        if let Some(key) = oldest_key {
            if let Some(entry) = self.l1_cache.remove(&key) {
                self.stats.total_size -= entry.size;
                self.stats.entry_count -= 1;
                self.stats.evictions += 1;
            }
        }

        Ok(())
    }

    fn evict_ttl(&mut self) -> AgentResult<()> {
        let now = Instant::now();
        let mut expired_keys = Vec::new();

        for (key, entry) in &self.l1_cache {
            if now.duration_since(entry.created_at) > self.config.ttl {
                expired_keys.push(key.clone());
            }
        }

        for key in expired_keys {
            if let Some(entry) = self.l1_cache.remove(&key) {
                self.stats.total_size -= entry.size;
                self.stats.entry_count -= 1;
                self.stats.evictions += 1;
            }
        }

        Ok(())
    }

    pub fn cleanup_expired(&mut self) {
        let _ = self.evict_ttl();
    }

    pub fn optimize_storage(&mut self) {
        // Move less frequently accessed items to lower cache levels
        let mut items_to_move = Vec::new();
        
        for (key, entry) in &self.l1_cache {
            if entry.access_count < 5 && entry.last_accessed.elapsed() > Duration::from_secs(300) {
                items_to_move.push(key.clone());
            }
        }

        for key in items_to_move {
            if let Some(entry) = self.l1_cache.remove(&key) {
                self.l2_cache.insert(key, entry);
            }
        }
    }
}

impl ConnectionPool {
    pub fn new(config: ConnectionPoolConfig) -> AgentResult<Self> {
        let semaphore = Arc::new(Semaphore::new(config.max_connections as usize));
        
        Ok(Self {
            connections: Arc::new(Mutex::new(Vec::new())),
            semaphore,
            config,
            stats: Arc::new(Mutex::new(PoolStats::default())),
        })
    }

    pub async fn get_connection(&self) -> AgentResult<PooledConnection> {
        let _permit = self.semaphore.acquire().await.map_err(|e| {
            AgentError::Resource {
                message: format!("Failed to acquire connection permit: {}", e),
                resource_type: "connection_permit".to_string(),
                current_usage: None,
                limit: Some(self.config.max_connections as u64),
                context: Some(ErrorContext::new("get_connection", "connection_pool")),
            }
        })?;

        let mut connections = self.connections.lock().map_err(|e| {
            AgentError::Resource {
                message: format!("Failed to acquire connections lock: {}", e),
                resource_type: "connections_lock".to_string(),
                current_usage: None,
                limit: None,
                context: Some(ErrorContext::new("get_connection", "connection_pool")),
            }
        })?;

        // Try to reuse an existing connection
        if let Some(connection) = connections.pop() {
            if connection.is_healthy && connection.last_used.elapsed() < self.config.idle_timeout {
                return Ok(connection);
            }
        }

        // Create a new connection
        let connection = PooledConnection {
            id: Uuid::new_v4(),
            created_at: Instant::now(),
            last_used: Instant::now(),
            is_healthy: true,
            connection_data: Vec::new(), // Placeholder
        };

        Ok(connection)
    }

    pub async fn return_connection(&self, mut connection: PooledConnection) -> AgentResult<()> {
        connection.last_used = Instant::now();
        
        let mut connections = self.connections.lock().map_err(|e| {
            AgentError::Resource {
                message: format!("Failed to acquire connections lock: {}", e),
                resource_type: "connections_lock".to_string(),
                current_usage: None,
                limit: None,
                context: Some(ErrorContext::new("return_connection", "connection_pool")),
            }
        })?;

        connections.push(connection);
        Ok(())
    }

    pub async fn get_stats(&self) -> AgentResult<PoolStats> {
        let stats = self.stats.lock().map_err(|e| {
            AgentError::Resource {
                message: format!("Failed to acquire stats lock: {}", e),
                resource_type: "stats_lock".to_string(),
                current_usage: None,
                limit: None,
                context: Some(ErrorContext::new("get_stats", "connection_pool")),
            }
        })?;
        Ok(stats.clone())
    }

    pub async fn health_check(&self) -> AgentResult<()> {
        let mut connections = self.connections.lock().map_err(|e| {
            AgentError::Resource {
                message: format!("Failed to acquire connections lock: {}", e),
                resource_type: "connections_lock".to_string(),
                current_usage: None,
                limit: None,
                context: Some(ErrorContext::new("health_check", "connection_pool")),
            }
        })?;

        connections.retain(|conn| {
            conn.is_healthy && conn.created_at.elapsed() < self.config.max_lifetime
        });

        Ok(())
    }
}

impl MemoryManager {
    pub fn new(config: MemoryConfig) -> AgentResult<Self> {
        Ok(Self {
            buffer_pool: Arc::new(Mutex::new(Vec::new())),
            memory_stats: Arc::new(Mutex::new(MemoryStats::default())),
            config,
        })
    }

    pub async fn allocate_buffer(&self, size: usize) -> AgentResult<Vec<u8>> {
        let mut buffer_pool = self.buffer_pool.lock().map_err(|e| {
            AgentError::Resource {
                message: format!("Failed to acquire buffer pool lock: {}", e),
                resource_type: "buffer_pool_lock".to_string(),
                current_usage: None,
                limit: None,
                context: Some(ErrorContext::new("allocate_buffer", "memory_manager")),
            }
        })?;

        // Try to reuse a buffer from the pool
        if let Some(mut buffer) = buffer_pool.pop() {
            if buffer.len() >= size {
                buffer.truncate(size);
                buffer.fill(0);
                
                if let Ok(mut stats) = self.memory_stats.lock() {
                    stats.buffer_pool_hits += 1;
                }
                
                return Ok(buffer);
            }
        }

        // Allocate a new buffer
        let buffer = vec![0u8; size];
        
        if let Ok(mut stats) = self.memory_stats.lock() {
            stats.allocated_bytes += size as u64;
            stats.buffer_pool_misses += 1;
            
            if stats.allocated_bytes > stats.peak_usage {
                stats.peak_usage = stats.allocated_bytes;
            }
        }

        Ok(buffer)
    }

    pub async fn return_buffer(&self, buffer: Vec<u8>) -> AgentResult<()> {
        let mut buffer_pool = self.buffer_pool.lock().map_err(|e| {
            AgentError::Resource {
                message: format!("Failed to acquire buffer pool lock: {}", e),
                resource_type: "buffer_pool_lock".to_string(),
                current_usage: None,
                limit: None,
                context: Some(ErrorContext::new("return_buffer", "memory_manager")),
            }
        })?;

        if buffer_pool.len() < self.config.buffer_pool_size {
            buffer_pool.push(buffer);
        }

        Ok(())
    }

    pub async fn get_stats(&self) -> AgentResult<MemoryStats> {
        let stats = self.memory_stats.lock().map_err(|e| {
            AgentError::Resource {
                message: format!("Failed to acquire memory stats lock: {}", e),
                resource_type: "memory_stats_lock".to_string(),
                current_usage: None,
                limit: None,
                context: Some(ErrorContext::new("get_stats", "memory_manager")),
            }
        })?;
        Ok(stats.clone())
    }

    pub async fn garbage_collect(&self) -> AgentResult<()> {
        let mut buffer_pool = self.buffer_pool.lock().map_err(|e| {
            AgentError::Resource {
                message: format!("Failed to acquire buffer pool lock: {}", e),
                resource_type: "buffer_pool_lock".to_string(),
                current_usage: None,
                limit: None,
                context: Some(ErrorContext::new("garbage_collect", "memory_manager")),
            }
        })?;

        // Remove excess buffers
        let target_size = self.config.buffer_pool_size / 2;
        if buffer_pool.len() > target_size {
            buffer_pool.truncate(target_size);
        }

        if let Ok(mut stats) = self.memory_stats.lock() {
            stats.gc_runs += 1;
        }

        Ok(())
    }

    pub async fn aggressive_gc(&self) -> AgentResult<()> {
        let mut buffer_pool = self.buffer_pool.lock().map_err(|e| {
            AgentError::Resource {
                message: format!("Failed to acquire buffer pool lock: {}", e),
                resource_type: "buffer_pool_lock".to_string(),
                current_usage: None,
                limit: None,
                context: Some(ErrorContext::new("aggressive_gc", "memory_manager")),
            }
        })?;

        // Clear most of the buffer pool
        buffer_pool.clear();

        if let Ok(mut stats) = self.memory_stats.lock() {
            stats.gc_runs += 1;
            stats.freed_bytes += stats.allocated_bytes / 2; // Estimate
        }

        info!("Aggressive garbage collection completed");
        Ok(())
    }
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_size: 100 * 1024 * 1024, // 100MB
            ttl: Duration::from_secs(3600), // 1 hour
            eviction_policy: EvictionPolicy::LRU,
            compression_enabled: true,
        }
    }
}

impl Default for ConnectionPoolConfig {
    fn default() -> Self {
        Self {
            max_connections: 100,
            min_connections: 10,
            connection_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(300),
            max_lifetime: Duration::from_secs(3600),
            health_check_interval: Duration::from_secs(60),
        }
    }
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            max_heap_size: 512 * 1024 * 1024, // 512MB
            gc_threshold: 0.8,
            buffer_pool_size: 1000,
            enable_memory_mapping: true,
            compression_threshold: 1024,
        }
    }
}

impl Default for OptimizationConfig {
    fn default() -> Self {
        Self {
            cache_config: CacheConfig::default(),
            connection_config: ConnectionPoolConfig::default(),
            memory_config: MemoryConfig::default(),
            enable_auto_tuning: true,
            metrics_collection_interval: Duration::from_secs(60),
        }
    }
}
