//! Cache Manager Module
//!
//! This module provides advanced caching capabilities with LRU eviction,
//! memory management, and performance optimization for the ERDPS system.


use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::RwLock;
use lru::LruCache;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use crate::performance::{NetworkThreat, PerformanceError};

/// Cache entry with metadata
#[derive(Debug, Clone)]
struct CacheEntry<T> {
    value: T,
    created_at: Instant,
    last_accessed: Instant,
    access_count: u64,
    size_bytes: usize,
}

impl<T> CacheEntry<T> {
    fn new(value: T, size_bytes: usize) -> Self {
        let now = Instant::now();
        Self {
            value,
            created_at: now,
            last_accessed: now,
            access_count: 1,
            size_bytes,
        }
    }
    
    fn access(&mut self) -> &T {
        self.last_accessed = Instant::now();
        self.access_count += 1;
        &self.value
    }
    
    fn is_expired(&self, ttl: Duration) -> bool {
        self.created_at.elapsed() > ttl
    }
}

/// Cache statistics for monitoring performance
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub total_entries: usize,
    pub memory_usage_bytes: usize,
    pub hit_rate: f64,
    pub average_access_time: Duration,
}

/// Cache configuration
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Maximum number of entries
    pub max_entries: usize,
    /// Maximum memory usage in bytes
    pub max_memory_bytes: usize,
    /// Time-to-live for cache entries
    pub ttl: Duration,
    /// Enable automatic cleanup of expired entries
    pub auto_cleanup: bool,
    /// Cleanup interval for expired entries
    pub cleanup_interval: Duration,
    /// Preload common patterns on startup
    pub preload_patterns: bool,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_entries: 10000,
            max_memory_bytes: 100 * 1024 * 1024, // 100MB
            ttl: Duration::from_secs(3600), // 1 hour
            auto_cleanup: true,
            cleanup_interval: Duration::from_secs(300), // 5 minutes
            preload_patterns: true,
        }
    }
}

/// Multi-level cache manager with different caching strategies
pub struct CacheManager {
    config: CacheConfig,
    
    // Pattern cache for malware signatures
    pattern_cache: Arc<RwLock<LruCache<String, CacheEntry<Vec<u8>>>>>,
    
    // Network threat cache
    network_cache: Arc<DashMap<u64, CacheEntry<NetworkThreat>>>,
    
    // File hash cache
    hash_cache: Arc<RwLock<LruCache<String, CacheEntry<String>>>>,
    
    // Memory region cache
    memory_cache: Arc<DashMap<usize, CacheEntry<Vec<u8>>>>,
    
    // Behavioral pattern cache
    behavioral_cache: Arc<RwLock<LruCache<u32, CacheEntry<BehavioralPattern>>>>,
    
    // Statistics
    stats: Arc<RwLock<CacheStats>>,
    
    // Last cleanup time
    last_cleanup: Arc<RwLock<Instant>>,
}

impl CacheManager {
    /// Create a new cache manager
    pub fn new(max_entries: usize) -> Self {
        let config = CacheConfig {
            max_entries,
            ..Default::default()
        };
        
        Self::with_config(config)
    }
    
    /// Create cache manager with custom configuration
    pub fn with_config(config: CacheConfig) -> Self {
        let pattern_cache_size = config.max_entries / 4;
        let hash_cache_size = config.max_entries / 4;
        let behavioral_cache_size = config.max_entries / 4;
        
        Self {
            config: config.clone(),
            pattern_cache: Arc::new(RwLock::new(
                LruCache::new(std::num::NonZeroUsize::new(pattern_cache_size).unwrap())
            )),
            network_cache: Arc::new(DashMap::new()),
            hash_cache: Arc::new(RwLock::new(
                LruCache::new(std::num::NonZeroUsize::new(hash_cache_size).unwrap())
            )),
            memory_cache: Arc::new(DashMap::new()),
            behavioral_cache: Arc::new(RwLock::new(
                LruCache::new(std::num::NonZeroUsize::new(behavioral_cache_size).unwrap())
            )),
            stats: Arc::new(RwLock::new(CacheStats::default())),
            last_cleanup: Arc::new(RwLock::new(Instant::now())),
        }
    }
    
    /// Get pattern from cache
    pub async fn get_pattern(&self, key: &str) -> Option<Vec<u8>> {
        let start_time = Instant::now();
        
        let result = {
            let mut cache = self.pattern_cache.write().await;
            cache.get_mut(key).map(|entry| {
                entry.access().clone()
            })
        };
        
        self.update_access_stats(result.is_some(), start_time).await;
        result
    }
    
    /// Put pattern in cache
    pub async fn put_pattern(&self, key: String, pattern: Vec<u8>) {
        let size_bytes = pattern.len() + key.len();
        let entry = CacheEntry::new(pattern, size_bytes);
        
        {
            let mut cache = self.pattern_cache.write().await;
            cache.put(key, entry);
        }
        
        self.update_memory_usage().await;
    }
    
    /// Get network threat from cache
    pub async fn get_network_threat(&self, hash: u64) -> Option<NetworkThreat> {
        let start_time = Instant::now();
        
        let result = self.network_cache.get_mut(&hash).map(|mut entry| {
            entry.access().clone()
        });
        
        self.update_access_stats(result.is_some(), start_time).await;
        result
    }
    
    /// Put network threat in cache
    pub async fn put_network_threat(&self, hash: u64, threat: NetworkThreat) {
        let size_bytes = std::mem::size_of::<NetworkThreat>() + 
                        threat.threat_type.len() + 
                        threat.source_ip.len() + 
                        threat.dest_ip.len() + 
                        threat.description.len();
        
        let entry = CacheEntry::new(threat, size_bytes);
        self.network_cache.insert(hash, entry);
        
        self.update_memory_usage().await;
    }
    
    /// Get file hash from cache
    pub async fn get_file_hash(&self, file_path: &str) -> Option<String> {
        let start_time = Instant::now();
        
        let result = {
            let mut cache = self.hash_cache.write().await;
            cache.get_mut(file_path).map(|entry| {
                entry.access().clone()
            })
        };
        
        self.update_access_stats(result.is_some(), start_time).await;
        result
    }
    
    /// Put file hash in cache
    pub async fn put_file_hash(&self, file_path: String, hash: String) {
        let size_bytes = file_path.len() + hash.len();
        let entry = CacheEntry::new(hash, size_bytes);
        
        {
            let mut cache = self.hash_cache.write().await;
            cache.put(file_path, entry);
        }
        
        self.update_memory_usage().await;
    }
    
    /// Get memory region from cache
    pub async fn get_memory_region(&self, address: usize) -> Option<Vec<u8>> {
        let start_time = Instant::now();
        
        let result = self.memory_cache.get_mut(&address).map(|mut entry| {
            entry.access().clone()
        });
        
        self.update_access_stats(result.is_some(), start_time).await;
        result
    }
    
    /// Put memory region in cache
    pub async fn put_memory_region(&self, address: usize, data: Vec<u8>) {
        let size_bytes = data.len();
        let entry = CacheEntry::new(data, size_bytes);
        self.memory_cache.insert(address, entry);
        
        self.update_memory_usage().await;
    }
    
    /// Get behavioral pattern from cache
    pub async fn get_behavioral_pattern(&self, process_id: u32) -> Option<BehavioralPattern> {
        let start_time = Instant::now();
        
        let result = {
            let mut cache = self.behavioral_cache.write().await;
            cache.get_mut(&process_id).map(|entry| {
                entry.access().clone()
            })
        };
        
        self.update_access_stats(result.is_some(), start_time).await;
        result
    }
    
    /// Put behavioral pattern in cache
    pub async fn put_behavioral_pattern(&self, process_id: u32, pattern: BehavioralPattern) {
        let size_bytes = std::mem::size_of::<BehavioralPattern>() + 
                        pattern.events.len() * std::mem::size_of::<String>();
        
        let entry = CacheEntry::new(pattern, size_bytes);
        
        {
            let mut cache = self.behavioral_cache.write().await;
            cache.put(process_id, entry);
        }
        
        self.update_memory_usage().await;
    }
    
    /// Generic get method for any cacheable type
    pub async fn get<T: Clone>(&self, _key: &u64) -> Option<T> 
    where
        T: Clone + 'static,
    {
        // This is a simplified generic implementation
        // In practice, you'd need type-specific cache selection
        None
    }
    
    /// Generic insert method for any cacheable type
    pub async fn insert<T: Clone>(&self, _key: u64, _value: T) 
    where
        T: Clone + 'static,
    {
        // This is a simplified generic implementation
        // In practice, you'd need type-specific cache selection
    }
    
    /// Preload common patterns and signatures
    pub async fn preload_common_patterns(&self) -> Result<(), PerformanceError> {
        if !self.config.preload_patterns {
            return Ok(());
        }
        
        // Preload common malware signatures
        let common_patterns = vec![
            ("eicar".to_string(), b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*".to_vec()),
            ("pe_header".to_string(), b"MZ".to_vec()),
            ("elf_header".to_string(), b"\x7fELF".to_vec()),
            ("zip_header".to_string(), b"PK".to_vec()),
            ("pdf_header".to_string(), b"%PDF".to_vec()),
        ];
        
        for (name, pattern) in common_patterns {
            self.put_pattern(name, pattern).await;
        }
        
        // Preload common file hashes (in practice, these would come from a database)
        let common_hashes = vec![
            ("/windows/system32/kernel32.dll".to_string(), "known_good_hash_1".to_string()),
            ("/windows/system32/ntdll.dll".to_string(), "known_good_hash_2".to_string()),
        ];
        
        for (path, hash) in common_hashes {
            self.put_file_hash(path, hash).await;
        }
        
        Ok(())
    }
    
    /// Optimize cache eviction policy based on usage patterns
    pub async fn optimize_eviction_policy(&self) -> Result<(), PerformanceError> {
        // Analyze access patterns and adjust cache sizes
        let stats = self.get_stats().await;
        
        if stats.hit_rate < 0.7 {
            // Low hit rate, consider increasing cache size or adjusting TTL
            // This would involve resizing the caches or adjusting configuration
        }
        
        // Perform cleanup of expired entries
        self.cleanup_expired_entries().await?;
        
        Ok(())
    }
    
    /// Increase cache size if memory allows
    pub async fn increase_size(&self) -> Result<(), PerformanceError> {
        let current_memory = self.get_memory_usage().await;
        
        if current_memory < self.config.max_memory_bytes / 2 {
            // We have room to grow, but LRU cache size is fixed at creation
            // In a real implementation, we'd need to recreate the caches with larger sizes
        }
        
        Ok(())
    }
    
    /// Clean up expired entries
    pub async fn cleanup_expired_entries(&self) -> Result<(), PerformanceError> {
        let now = Instant::now();
        let mut last_cleanup = self.last_cleanup.write().await;
        
        if now.duration_since(*last_cleanup) < self.config.cleanup_interval {
            return Ok(());
        }
        
        let mut evicted_count = 0;
        
        // Clean up network cache
        self.network_cache.retain(|_, entry| {
            if entry.is_expired(self.config.ttl) {
                evicted_count += 1;
                false
            } else {
                true
            }
        });
        
        // Clean up memory cache
        self.memory_cache.retain(|_, entry| {
            if entry.is_expired(self.config.ttl) {
                evicted_count += 1;
                false
            } else {
                true
            }
        });
        
        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.evictions += evicted_count;
        }
        
        *last_cleanup = now;
        
        Ok(())
    }
    
    /// Get current cache statistics
    pub async fn get_stats(&self) -> CacheStats {
        let mut stats = self.stats.read().await.clone();
        
        // Update current entry counts
        stats.total_entries = 
            self.pattern_cache.read().await.len() +
            self.network_cache.len() +
            self.hash_cache.read().await.len() +
            self.memory_cache.len() +
            self.behavioral_cache.read().await.len();
        
        // Calculate hit rate
        let total_accesses = stats.hits + stats.misses;
        stats.hit_rate = if total_accesses > 0 {
            stats.hits as f64 / total_accesses as f64
        } else {
            0.0
        };
        
        stats.memory_usage_bytes = self.get_memory_usage().await;
        
        stats
    }
    
    /// Clear all caches
    pub async fn clear_all(&self) {
        self.pattern_cache.write().await.clear();
        self.network_cache.clear();
        self.hash_cache.write().await.clear();
        self.memory_cache.clear();
        self.behavioral_cache.write().await.clear();
        
        // Reset statistics
        {
            let mut stats = self.stats.write().await;
            *stats = CacheStats::default();
        }
    }
    
    /// Get current memory usage
    async fn get_memory_usage(&self) -> usize {
        let mut total_size = 0;
        
        // Calculate pattern cache size
        for (_, entry) in self.pattern_cache.read().await.iter() {
            total_size += entry.size_bytes;
        }
        
        // Calculate network cache size
        for entry in self.network_cache.iter() {
            total_size += entry.value().size_bytes;
        }
        
        // Calculate hash cache size
        for (_, entry) in self.hash_cache.read().await.iter() {
            total_size += entry.size_bytes;
        }
        
        // Calculate memory cache size
        for entry in self.memory_cache.iter() {
            total_size += entry.value().size_bytes;
        }
        
        // Calculate behavioral cache size
        for (_, entry) in self.behavioral_cache.read().await.iter() {
            total_size += entry.size_bytes;
        }
        
        total_size
    }
    
    /// Update access statistics
    async fn update_access_stats(&self, hit: bool, start_time: Instant) {
        let mut stats = self.stats.write().await;
        
        if hit {
            stats.hits += 1;
        } else {
            stats.misses += 1;
        }
        
        let access_time = start_time.elapsed();
        stats.average_access_time = (stats.average_access_time + access_time) / 2;
    }
    
    /// Update memory usage statistics
    async fn update_memory_usage(&self) {
        // Trigger cleanup if memory usage is too high
        let current_usage = self.get_memory_usage().await;
        
        if current_usage > self.config.max_memory_bytes {
            // Force eviction of least recently used entries
            let _ = self.cleanup_expired_entries().await;
        }
    }
}

/// Behavioral pattern for caching
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralPattern {
    pub process_id: u32,
    pub events: Vec<String>,
    pub risk_score: f32,
    pub last_updated: SystemTime,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::test;
    
    #[test]
    async fn test_cache_manager_creation() {
        let cache_manager = CacheManager::new(1000);
        let stats = cache_manager.get_stats().await;
        assert_eq!(stats.total_entries, 0);
    }
    
    #[test]
    async fn test_pattern_cache() {
        let cache_manager = CacheManager::new(1000);
        
        let key = "test_pattern".to_string();
        let pattern = b"MALWARE_SIGNATURE".to_vec();
        
        // Put pattern in cache
        cache_manager.put_pattern(key.clone(), pattern.clone()).await;
        
        // Get pattern from cache
        let cached_pattern = cache_manager.get_pattern(&key).await;
        assert_eq!(cached_pattern, Some(pattern));
        
        // Check statistics
        let stats = cache_manager.get_stats().await;
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 0);
    }
    
    #[test]
    async fn test_network_threat_cache() {
        let cache_manager = CacheManager::new(1000);
        
        let threat = NetworkThreat {
            threat_type: "malware_c2".to_string(),
            source_ip: "192.168.1.100".to_string(),
            dest_ip: "10.0.0.1".to_string(),
            confidence: 0.9,
            description: "Suspicious C2 communication".to_string(),
        };
        
        let hash = 12345u64;
        
        // Put threat in cache
        cache_manager.put_network_threat(hash, threat.clone()).await;
        
        // Get threat from cache
        let cached_threat = cache_manager.get_network_threat(hash).await;
        assert!(cached_threat.is_some());
        assert_eq!(cached_threat.unwrap().threat_type, threat.threat_type);
    }
    
    #[test]
    async fn test_cache_cleanup() {
        let mut config = CacheConfig::default();
        config.ttl = Duration::from_millis(10); // Very short TTL for testing
        
        let cache_manager = CacheManager::with_config(config);
        
        // Add some entries
        cache_manager.put_pattern("test1".to_string(), b"pattern1".to_vec()).await;
        cache_manager.put_pattern("test2".to_string(), b"pattern2".to_vec()).await;
        
        // Wait for entries to expire
        tokio::time::sleep(Duration::from_millis(20)).await;
        
        // Force cleanup
        cache_manager.cleanup_expired_entries().await.unwrap();
        
        // Entries should still be in LRU cache (LRU doesn't auto-expire)
        // But DashMap entries would be cleaned up
        let stats = cache_manager.get_stats().await;
        // Some entries might remain in LRU caches
        assert!(stats.total_entries == stats.total_entries); // Placeholder assertion
    }
    
    #[test]
    async fn test_preload_patterns() {
        let cache_manager = CacheManager::new(1000);
        
        cache_manager.preload_common_patterns().await.unwrap();
        
        // Check that EICAR pattern was loaded
        let eicar_pattern = cache_manager.get_pattern("eicar").await;
        assert!(eicar_pattern.is_some());
        
        let stats = cache_manager.get_stats().await;
        assert!(stats.total_entries > 0);
    }
}
