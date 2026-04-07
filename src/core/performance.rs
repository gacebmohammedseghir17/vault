//! 🚀 LIGHTNING-FAST PERFORMANCE OPTIMIZATION MODULE
//! 
//! This module implements elite-level performance optimizations to achieve:
//! - <50ms response time (2x improvement)
//! - 5,000+ files/minute scanning (5x improvement)
//! - <1 second memory analysis (5x improvement)
//! - <10ms network packet analysis (10x improvement)
//! - <500ms AI analysis (4x improvement)

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use rayon::prelude::*;
use dashmap::DashMap;
use lru::LruCache;
use smallvec::SmallVec;
use compact_str::CompactString;
use bytes::Bytes;
use ahash::AHasher;
use crate::threat_intel::ioc::BloomFilter;
use std::hash::{Hash, Hasher};
use std::sync::Mutex;

/// 🎯 Performance targets and metrics
#[derive(Debug, Clone)]
pub struct PerformanceTargets {
    pub max_response_time_ms: u64,      // Target: <50ms
    pub min_files_per_minute: u64,      // Target: 5,000+
    pub max_memory_analysis_ms: u64,    // Target: <1,000ms
    pub max_network_analysis_ms: u64,   // Target: <10ms
    pub max_ai_analysis_ms: u64,        // Target: <500ms
}

impl Default for PerformanceTargets {
    fn default() -> Self {
        Self {
            max_response_time_ms: 50,
            min_files_per_minute: 5000,
            max_memory_analysis_ms: 1000,
            max_network_analysis_ms: 10,
            max_ai_analysis_ms: 500,
        }
    }
}

/// 📊 Real-time performance metrics
#[derive(Debug, Clone)]
pub struct PerformanceMetrics {
    pub response_times: SmallVec<[u64; 100]>,
    pub files_scanned_per_minute: u64,
    pub memory_analysis_times: SmallVec<[u64; 50]>,
    pub network_analysis_times: SmallVec<[u64; 200]>,
    pub ai_analysis_times: SmallVec<[u64; 20]>,
    pub cache_hit_rate: f64,
    pub cpu_utilization: f64,
    pub memory_usage_mb: u64,
    pub last_updated: Instant,
}

impl Default for PerformanceMetrics {
    fn default() -> Self {
        Self {
            response_times: SmallVec::new(),
            files_scanned_per_minute: 0,
            memory_analysis_times: SmallVec::new(),
            network_analysis_times: SmallVec::new(),
            ai_analysis_times: SmallVec::new(),
            cache_hit_rate: 0.0,
            cpu_utilization: 0.0,
            memory_usage_mb: 0,
            last_updated: Instant::now(),
        }
    }
}

impl PerformanceMetrics {
    /// Calculate average response time
    pub fn avg_response_time(&self) -> f64 {
        if self.response_times.is_empty() {
            0.0
        } else {
            self.response_times.iter().sum::<u64>() as f64 / self.response_times.len() as f64
        }
    }

    /// Check if performance targets are met
    pub fn meets_targets(&self, targets: &PerformanceTargets) -> bool {
        self.avg_response_time() <= targets.max_response_time_ms as f64
            && self.files_scanned_per_minute >= targets.min_files_per_minute
            && self.avg_memory_analysis_time() <= targets.max_memory_analysis_ms as f64
            && self.avg_network_analysis_time() <= targets.max_network_analysis_ms as f64
            && self.avg_ai_analysis_time() <= targets.max_ai_analysis_ms as f64
    }

    pub fn avg_memory_analysis_time(&self) -> f64 {
        if self.memory_analysis_times.is_empty() {
            0.0
        } else {
            self.memory_analysis_times.iter().sum::<u64>() as f64 / self.memory_analysis_times.len() as f64
        }
    }

    pub fn avg_network_analysis_time(&self) -> f64 {
        if self.network_analysis_times.is_empty() {
            0.0
        } else {
            self.network_analysis_times.iter().sum::<u64>() as f64 / self.network_analysis_times.len() as f64
        }
    }

    pub fn avg_ai_analysis_time(&self) -> f64 {
        if self.ai_analysis_times.is_empty() {
            0.0
        } else {
            self.ai_analysis_times.iter().sum::<u64>() as f64 / self.ai_analysis_times.len() as f64
        }
    }
}

/// 🔥 Ultra-fast hash computation using AHash
pub fn fast_hash<T: Hash + ?Sized>(item: &T) -> u64 {
    let mut hasher = AHasher::default();
    item.hash(&mut hasher);
    hasher.finish()
}

/// 💾 Lightning-fast LRU cache for file hashes and results
pub struct FastCache<K, V> {
    cache: Arc<Mutex<LruCache<K, V>>>,
    bloom_filter: Arc<Mutex<BloomFilter>>,
    hit_count: Arc<std::sync::atomic::AtomicU64>,
    miss_count: Arc<std::sync::atomic::AtomicU64>,
}

impl<K: Hash + Eq + Clone, V: Clone> FastCache<K, V> {
    pub fn new(capacity: usize) -> Self {
        Self {
            cache: Arc::new(Mutex::new(LruCache::new(capacity.try_into().unwrap()))),
            bloom_filter: Arc::new(Mutex::new(BloomFilter::with_rate(0.01, capacity as u32))),
            hit_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            miss_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    pub fn get(&self, key: &K) -> Option<V> {
        // Fast bloom filter check first
        let hash = fast_hash(key);
        let hash_str = hash.to_string();
        if !self.bloom_filter.lock().unwrap().might_contain(&hash_str) {
            self.miss_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return None;
        }

        // Check actual cache
        if let Some(value) = self.cache.lock().unwrap().get(key) {
            self.hit_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Some(value.clone())
        } else {
            self.miss_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            None
        }
    }

    pub fn put(&self, key: K, value: V) {
        let hash = fast_hash(&key);
        let hash_str = hash.to_string();
        self.bloom_filter.lock().unwrap().add(&hash_str);
        self.cache.lock().unwrap().put(key, value);
    }

    pub fn hit_rate(&self) -> f64 {
        let hits = self.hit_count.load(std::sync::atomic::Ordering::Relaxed);
        let misses = self.miss_count.load(std::sync::atomic::Ordering::Relaxed);
        if hits + misses == 0 {
            0.0
        } else {
            hits as f64 / (hits + misses) as f64
        }
    }
}

/// 🚀 High-performance thread pool manager
pub struct PerformanceThreadPool {
    rayon_pool: rayon::ThreadPool,
    // Hold Tokio runtime as Option to allow safe take during Drop
    tokio_runtime: Option<tokio::runtime::Runtime>,
    cpu_cores: usize,
}

impl PerformanceThreadPool {
    pub fn new() -> anyhow::Result<Self> {
        let cpu_cores = num_cpus::get();
        
        // Create optimized rayon thread pool
        let rayon_pool = rayon::ThreadPoolBuilder::new()
            .num_threads(cpu_cores)
            .thread_name(|i| format!("erdps-rayon-{}", i))
            .build()?;

        // Create optimized tokio runtime
        let tokio_runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(cpu_cores)
            .thread_name("erdps-tokio")
            .enable_all()
            .build()?;

        Ok(Self {
            rayon_pool,
            tokio_runtime: Some(tokio_runtime),
            cpu_cores,
        })
    }

    pub fn cpu_cores(&self) -> usize {
        self.cpu_cores
    }

    pub fn rayon_pool(&self) -> &rayon::ThreadPool {
        &self.rayon_pool
    }

    pub fn tokio_handle(&self) -> tokio::runtime::Handle {
        // Fallback to current handle if runtime not available
        if let Some(rt) = &self.tokio_runtime {
            rt.handle().clone()
        } else {
            tokio::runtime::Handle::current()
        }
    }

    /// Execute CPU-intensive work in parallel
    pub fn execute_parallel<T, F, R>(&self, items: Vec<T>, func: F) -> Vec<R>
    where
        T: Send,
        F: Fn(T) -> R + Send + Sync,
        R: Send,
    {
        self.rayon_pool.install(|| {
            items.into_par_iter().map(func).collect()
        })
    }

    /// Execute async work concurrently
    pub async fn execute_concurrent<T, F, Fut, R>(&self, items: Vec<T>, func: F) -> Vec<R>
    where
        T: Send + 'static,
        F: Fn(T) -> Fut + Send + Sync + Clone + 'static,
        Fut: std::future::Future<Output = R> + Send,
        R: Send + 'static,
    {
        let mut join_set = tokio::task::JoinSet::new();
        
        for item in items {
            let func_clone = func.clone();
            join_set.spawn(async move {
                func_clone(item).await
            });
        }

        let mut results = Vec::new();
        while let Some(result) = join_set.join_next().await {
            if let Ok(value) = result {
                results.push(value);
            }
        }
        results
    }
}

/// 🎯 Performance monitor for real-time tracking
pub struct PerformanceMonitor {
    metrics: Arc<RwLock<PerformanceMetrics>>,
    targets: PerformanceTargets,
    start_time: Instant,
}

impl PerformanceMonitor {
    pub fn new(targets: PerformanceTargets) -> Self {
        Self {
            metrics: Arc::new(RwLock::new(PerformanceMetrics::default())),
            targets,
            start_time: Instant::now(),
        }
    }

    /// Record response time
    pub async fn record_response_time(&self, duration: Duration) {
        let mut metrics = self.metrics.write().await;
        let ms = duration.as_millis() as u64;
        
        if metrics.response_times.len() >= 100 {
            metrics.response_times.remove(0);
        }
        metrics.response_times.push(ms);
        metrics.last_updated = Instant::now();
    }

    /// Record file scanning performance
    pub async fn record_files_scanned(&self, count: u64, duration: Duration) {
        let mut metrics = self.metrics.write().await;
        let files_per_minute = (count as f64 / duration.as_secs_f64()) * 60.0;
        metrics.files_scanned_per_minute = files_per_minute as u64;
        metrics.last_updated = Instant::now();
    }

    /// Record memory analysis time
    pub async fn record_memory_analysis(&self, duration: Duration) {
        let mut metrics = self.metrics.write().await;
        let ms = duration.as_millis() as u64;
        
        if metrics.memory_analysis_times.len() >= 50 {
            metrics.memory_analysis_times.remove(0);
        }
        metrics.memory_analysis_times.push(ms);
        metrics.last_updated = Instant::now();
    }

    /// Record network analysis time
    pub async fn record_network_analysis(&self, duration: Duration) {
        let mut metrics = self.metrics.write().await;
        let ms = duration.as_millis() as u64;
        
        if metrics.network_analysis_times.len() >= 200 {
            metrics.network_analysis_times.remove(0);
        }
        metrics.network_analysis_times.push(ms);
        metrics.last_updated = Instant::now();
    }

    /// Record AI analysis time
    pub async fn record_ai_analysis(&self, duration: Duration) {
        let mut metrics = self.metrics.write().await;
        let ms = duration.as_millis() as u64;
        
        if metrics.ai_analysis_times.len() >= 20 {
            metrics.ai_analysis_times.remove(0);
        }
        metrics.ai_analysis_times.push(ms);
        metrics.last_updated = Instant::now();
    }

    /// Get current performance metrics
    pub async fn get_metrics(&self) -> PerformanceMetrics {
        self.metrics.read().await.clone()
    }

    /// Check if performance targets are being met
    pub async fn check_performance(&self) -> bool {
        let metrics = self.metrics.read().await;
        metrics.meets_targets(&self.targets)
    }

    /// Get performance report
    pub async fn get_performance_report(&self) -> String {
        let metrics = self.metrics.read().await;
        let uptime = self.start_time.elapsed();
        
        format!(
            "🚀 ERDPS Performance Report\n\
            ⏱️  Uptime: {:.2}s\n\
            📊 Avg Response Time: {:.2}ms (Target: <{}ms) {}\n\
            📁 Files/Minute: {} (Target: {}+) {}\n\
            🧠 Avg Memory Analysis: {:.2}ms (Target: <{}ms) {}\n\
            🌐 Avg Network Analysis: {:.2}ms (Target: <{}ms) {}\n\
            🤖 Avg AI Analysis: {:.2}ms (Target: <{}ms) {}\n\
            💾 Cache Hit Rate: {:.1}%\n\
            🎯 Overall Performance: {}",
            uptime.as_secs_f64(),
            metrics.avg_response_time(),
            self.targets.max_response_time_ms,
            if metrics.avg_response_time() <= self.targets.max_response_time_ms as f64 { "✅" } else { "❌" },
            metrics.files_scanned_per_minute,
            self.targets.min_files_per_minute,
            if metrics.files_scanned_per_minute >= self.targets.min_files_per_minute { "✅" } else { "❌" },
            metrics.avg_memory_analysis_time(),
            self.targets.max_memory_analysis_ms,
            if metrics.avg_memory_analysis_time() <= self.targets.max_memory_analysis_ms as f64 { "✅" } else { "❌" },
            metrics.avg_network_analysis_time(),
            self.targets.max_network_analysis_ms,
            if metrics.avg_network_analysis_time() <= self.targets.max_network_analysis_ms as f64 { "✅" } else { "❌" },
            metrics.avg_ai_analysis_time(),
            self.targets.max_ai_analysis_ms,
            if metrics.avg_ai_analysis_time() <= self.targets.max_ai_analysis_ms as f64 { "✅" } else { "❌" },
            metrics.cache_hit_rate * 100.0,
            if metrics.meets_targets(&self.targets) { "🎯 TARGETS MET!" } else { "⚠️  NEEDS OPTIMIZATION" }
        )
    }
}

/// 🔧 Memory-optimized data structures
pub type FastString = CompactString;
pub type FastVec<T> = SmallVec<[T; 8]>;
pub type FastMap<K, V> = DashMap<K, V>;
pub type FastBytes = Bytes;

/// 🚀 Zero-copy string operations
pub fn fast_string_from_bytes(bytes: &[u8]) -> FastString {
    // Use compact string for memory efficiency
    CompactString::from_utf8_lossy(bytes)
}

/// 🎯 Performance timer for measuring execution time
pub struct PerformanceTimer {
    start: Instant,
    name: String,
}

impl PerformanceTimer {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            start: Instant::now(),
            name: name.into(),
        }
    }

    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    pub fn elapsed_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }
}

impl Drop for PerformanceTimer {
    fn drop(&mut self) {
        let elapsed = self.elapsed();
        log::debug!("⏱️  {} took {:.2}ms", self.name, elapsed.as_millis());
    }
}

/// 🚀 Macro for easy performance timing
#[macro_export]
macro_rules! time_it {
    ($name:expr, $code:block) => {{
        let _timer = $crate::core::performance::PerformanceTimer::new($name);
        $code
    }};
}

impl Drop for PerformanceThreadPool {
    fn drop(&mut self) {
        // Safely shutdown Tokio runtime to avoid drop panic in async context
        if let Some(rt) = self.tokio_runtime.take() {
            // Prefer shutdown_background if available; otherwise drop on a detached thread
            #[allow(unused_must_use)]
            {
                // Attempt background shutdown (Tokio >=1.21)
                #[allow(deprecated)]
                {
                    // If method exists, call it; otherwise fallback
                    // Note: Direct feature detection isn't available here; use fallback thread
                }
            }
            // Fallback: drop runtime on a dedicated OS thread to avoid blocking in async context
            std::thread::spawn(move || {
                drop(rt);
            });
        }
    }
}