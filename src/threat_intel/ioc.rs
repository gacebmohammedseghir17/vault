//! IOC (Indicators of Compromise) Processing Module
//!
//! This module handles IOC processing, matching, storage, and management
//! for the threat intelligence system.

use super::*;
use crate::error::{AgentResult, AgentError};
use async_trait::async_trait;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;
use tracing::{info, warn, debug};
use uuid::Uuid;
use regex::Regex;
use sha2::{Sha256, Digest};
use ipnetwork::IpNetwork;
use serde::{Serialize, Deserialize};
use serde_json;

/// IOC processing and matching engine
pub struct IocProcessor {
    config: IocConfig,
    storage: Arc<dyn IocStorage>,
    matchers: HashMap<IocType, Box<dyn IocMatcher>>,
    normalizers: HashMap<IocType, Box<dyn IocNormalizer>>,
    validators: HashMap<IocType, Box<dyn IocValidator>>,
    enrichers: HashMap<IocType, Box<dyn IocEnricher>>,
    cache: Arc<RwLock<IocCache>>,
    statistics: Arc<RwLock<IocStatistics>>,
    bloom_filter: Arc<RwLock<BloomFilter>>,
    whitelist: Arc<RwLock<HashSet<String>>>,
    blacklist: Arc<RwLock<HashSet<String>>>,
}

/// IOC storage trait
#[async_trait]
pub trait IocStorage: Send + Sync {
    /// Store IOC
    async fn store_ioc(&self, ioc: &ProcessedIoc) -> AgentResult<()>;
    
    /// Retrieve IOC by value
    async fn get_ioc(&self, ioc_value: &str, ioc_type: &IocType) -> AgentResult<Option<ProcessedIoc>>;
    
    /// Search IOCs by criteria
    async fn search_iocs(&self, criteria: &IocSearchCriteria) -> AgentResult<Vec<ProcessedIoc>>;
    
    /// Update IOC
    async fn update_ioc(&self, ioc: &ProcessedIoc) -> AgentResult<()>;
    
    /// Delete IOC
    async fn delete_ioc(&self, ioc_id: &str) -> AgentResult<()>;
    
    /// Bulk operations
    async fn bulk_store(&self, iocs: &[ProcessedIoc]) -> AgentResult<BulkOperationResult>;
    async fn bulk_delete(&self, ioc_ids: &[String]) -> AgentResult<BulkOperationResult>;
    
    /// Get storage statistics
    async fn get_statistics(&self) -> AgentResult<StorageStatistics>;
    
    /// Cleanup expired IOCs
    async fn cleanup_expired(&self, before: SystemTime) -> AgentResult<u64>;
}

/// IOC matcher trait
#[async_trait]
pub trait IocMatcher: Send + Sync {
    /// Match IOC against input
    async fn match_ioc(&self, input: &str, iocs: &[ProcessedIoc]) -> AgentResult<Vec<IocMatch>>;
    
    /// Get matcher type
    fn get_type(&self) -> IocType;
    
    /// Get match confidence
    fn get_confidence(&self, input: &str, ioc: &ProcessedIoc) -> f64;
}

/// IOC normalizer trait
#[async_trait]
pub trait IocNormalizer: Send + Sync {
    /// Normalize IOC value
    async fn normalize(&self, ioc_value: &str) -> AgentResult<String>;
    
    /// Get normalizer type
    fn get_type(&self) -> IocType;
}

/// IOC validator trait
#[async_trait]
pub trait IocValidator: Send + Sync {
    /// Validate IOC value
    async fn validate(&self, ioc_value: &str) -> AgentResult<ValidationResult>;
    
    /// Get validator type
    fn get_type(&self) -> IocType;
}

/// IOC enricher trait
#[async_trait]
pub trait IocEnricher: Send + Sync {
    /// Enrich IOC with additional data
    async fn enrich(&self, ioc: &ProcessedIoc) -> AgentResult<EnrichmentData>;
    
    /// Get enricher type
    fn get_type(&self) -> IocType;
}

/// IOC configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocConfig {
    pub enabled: bool,
    pub cache_size: usize,
    pub cache_ttl: Duration,
    pub bloom_filter_size: usize,
    pub bloom_filter_hash_functions: u32,
    pub batch_size: usize,
    pub max_concurrent_operations: usize,
    pub validation_enabled: bool,
    pub normalization_enabled: bool,
    pub enrichment_enabled: bool,
    pub whitelist_enabled: bool,
    pub blacklist_enabled: bool,
    pub fuzzy_matching: bool,
    pub case_sensitive: bool,
    pub regex_timeout: Duration,
    pub storage_backend: StorageBackend,
    pub retention_policy: RetentionPolicy,
}

/// Storage backend types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum StorageBackend {
    Memory,
    Sqlite,
    PostgreSQL,
    Redis,
    Custom(String),
}

/// Retention policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPolicy {
    pub default_ttl: Duration,
    pub max_age: Duration,
    pub cleanup_interval: Duration,
    pub type_specific_ttl: HashMap<IocType, Duration>,
    pub priority_based_retention: bool,
}

/// Processed IOC
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessedIoc {
    pub id: String,
    pub original_value: String,
    pub normalized_value: String,
    pub ioc_type: IocType,
    pub confidence: f64,
    pub severity: ThreatSeverity,
    pub tags: Vec<String>,
    pub source: String,
    pub first_seen: SystemTime,
    pub last_seen: SystemTime,
    pub created_at: SystemTime,
    pub updated_at: SystemTime,
    pub expires_at: Option<SystemTime>,
    pub context: ThreatContext,
    pub attribution: Option<ThreatAttribution>,
    pub enrichment: Option<EnrichmentData>,
    pub validation: ValidationResult,
    pub metadata: HashMap<String, serde_json::Value>,
    pub related_iocs: Vec<String>,
    pub false_positive: bool,
    pub active: bool,
}

/// IOC search criteria
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocSearchCriteria {
    pub ioc_types: Option<Vec<IocType>>,
    pub sources: Option<Vec<String>>,
    pub tags: Option<Vec<String>>,
    pub severity_min: Option<ThreatSeverity>,
    pub severity_max: Option<ThreatSeverity>,
    pub confidence_min: Option<f64>,
    pub confidence_max: Option<f64>,
    pub created_after: Option<SystemTime>,
    pub created_before: Option<SystemTime>,
    pub updated_after: Option<SystemTime>,
    pub updated_before: Option<SystemTime>,
    pub active_only: bool,
    pub exclude_false_positives: bool,
    pub text_search: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    pub sort_by: Option<String>,
    pub sort_order: Option<SortOrder>,
}

/// IOC match result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocMatch {
    pub match_id: Uuid,
    pub input: String,
    pub matched_ioc: ProcessedIoc,
    pub match_type: MatchType,
    pub confidence: f64,
    pub match_position: Option<(usize, usize)>, // start, end
    pub match_context: Option<String>,
    pub timestamp: SystemTime,
}

/// Match types
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MatchType {
    Exact,
    Partial,
    Fuzzy,
    Regex,
    Substring,
    Domain,
    Subdomain,
    Network,
    Hash,
}

/// Validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub is_valid: bool,
    pub confidence: f64,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub suggestions: Vec<String>,
    pub normalized_value: Option<String>,
    pub validation_rules: Vec<String>,
}

/// Enrichment data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichmentData {
    pub enrichment_id: Uuid,
    pub enrichment_type: String,
    pub data: HashMap<String, serde_json::Value>,
    pub sources: Vec<String>,
    pub confidence: f64,
    pub timestamp: SystemTime,
    pub ttl: Option<Duration>,
}

/// Bulk operation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkOperationResult {
    pub total_items: usize,
    pub successful_items: usize,
    pub failed_items: usize,
    pub errors: Vec<String>,
    pub duration: Duration,
}

/// Storage statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StorageStatistics {
    pub total_iocs: u64,
    pub active_iocs: u64,
    pub expired_iocs: u64,
    pub false_positives: u64,
    pub ioc_type_breakdown: HashMap<IocType, u64>,
    pub source_breakdown: HashMap<String, u64>,
    pub severity_breakdown: HashMap<ThreatSeverity, u64>,
    pub storage_size: u64, // bytes
    pub last_cleanup: Option<SystemTime>,
    pub average_query_time: Duration,
    pub cache_hit_rate: f64,
}

/// IOC statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IocStatistics {
    pub total_matches: u64,
    pub successful_matches: u64,
    pub false_positives: u64,
    pub match_type_breakdown: HashMap<MatchType, u64>,
    pub average_match_time: Duration,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub bloom_filter_hits: u64,
    pub bloom_filter_false_positives: u64,
    pub validation_stats: ValidationStatistics,
    pub enrichment_stats: EnrichmentStatistics,
}

/// Validation statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ValidationStatistics {
    pub total_validations: u64,
    pub valid_iocs: u64,
    pub invalid_iocs: u64,
    pub validation_errors: u64,
    pub validation_warnings: u64,
    pub average_validation_time: Duration,
}

/// Enrichment statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnrichmentStatistics {
    pub total_enrichments: u64,
    pub successful_enrichments: u64,
    pub failed_enrichments: u64,
    pub enrichment_sources: HashMap<String, u64>,
    pub average_enrichment_time: Duration,
}

/// IOC cache
#[derive(Debug, Clone, Default)]
pub struct IocCache {
    pub entries: HashMap<String, CachedIoc>,
    pub size: usize,
    pub max_size: usize,
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
}

/// Cached IOC
#[derive(Debug, Clone)]
pub struct CachedIoc {
    pub ioc: ProcessedIoc,
    pub created: SystemTime,
    pub accessed: SystemTime,
    pub access_count: u32,
    pub ttl: Duration,
}

/// Simple Bloom filter implementation
#[derive(Debug, Clone)]
pub struct BloomFilter {
    pub bits: Vec<bool>,
    pub size: usize,
    pub hash_functions: u32,
    pub items_count: u64,
    pub false_positive_rate: f64,
}

/// Specific IOC matchers
pub struct FileHashMatcher {
    supported_algorithms: HashSet<String>,
}

pub struct IpAddressMatcher {
    networks: Vec<IpNetwork>,
}

pub struct DomainMatcher {
    tld_list: HashSet<String>,
    domain_regex: Regex,
}

pub struct UrlMatcher {
    url_regex: Regex,
}

pub struct EmailMatcher {
    email_regex: Regex,
}

pub struct RegistryMatcher {
    registry_patterns: Vec<Regex>,
}

pub struct MutexMatcher;

pub struct CertificateMatcher {
    cert_patterns: Vec<Regex>,
}

pub struct UserAgentMatcher;

pub struct ProcessNameMatcher;

pub struct FilePathMatcher {
    path_patterns: Vec<Regex>,
}

pub struct NetworkSignatureMatcher {
    signature_patterns: Vec<Regex>,
}

pub struct YaraMatcher;

/// Memory-based IOC storage implementation
pub struct MemoryIocStorage {
    iocs: Arc<RwLock<HashMap<String, ProcessedIoc>>>,
    indices: Arc<RwLock<StorageIndices>>,
    statistics: Arc<RwLock<StorageStatistics>>,
}

/// Storage indices for fast lookups
#[derive(Debug, Default)]
struct StorageIndices {
    by_type: HashMap<IocType, HashSet<String>>,
    by_source: HashMap<String, HashSet<String>>,
    by_tag: HashMap<String, HashSet<String>>,
    by_severity: HashMap<ThreatSeverity, HashSet<String>>,
    by_normalized_value: HashMap<String, String>, // normalized -> id
}

/// Implementation for IocProcessor
impl IocProcessor {
    /// Create new IOC processor
    pub fn new(config: IocConfig) -> AgentResult<Self> {
        let storage: Arc<dyn IocStorage> = match config.storage_backend {
            StorageBackend::Memory => Arc::new(MemoryIocStorage::new()),
            _ => return Err(AgentError::Configuration { 
                message: "Unsupported storage backend".to_string(),
                field: Some("storage_backend".to_string()),
                context: None
            }),
        };

        let mut matchers: HashMap<IocType, Box<dyn IocMatcher>> = HashMap::new();
        matchers.insert(IocType::FileHash, Box::new(FileHashMatcher::new()));
        matchers.insert(IocType::IpAddress, Box::new(IpAddressMatcher::new()));
        matchers.insert(IocType::Domain, Box::new(DomainMatcher::new()?));
        matchers.insert(IocType::Url, Box::new(UrlMatcher::new()?));
        matchers.insert(IocType::Email, Box::new(EmailMatcher::new()?));
        matchers.insert(IocType::Registry, Box::new(RegistryMatcher::new()));
        matchers.insert(IocType::Mutex, Box::new(MutexMatcher::new()));
        matchers.insert(IocType::Certificate, Box::new(CertificateMatcher::new()));
        matchers.insert(IocType::UserAgent, Box::new(UserAgentMatcher::new()));
        matchers.insert(IocType::ProcessName, Box::new(ProcessNameMatcher::new()));
        matchers.insert(IocType::FilePath, Box::new(FilePathMatcher::new()));
        matchers.insert(IocType::NetworkSignature, Box::new(NetworkSignatureMatcher::new()));
        matchers.insert(IocType::Yara, Box::new(YaraMatcher::new()));

        let normalizers: HashMap<IocType, Box<dyn IocNormalizer>> = HashMap::new();
        let validators: HashMap<IocType, Box<dyn IocValidator>> = HashMap::new();
        let enrichers: HashMap<IocType, Box<dyn IocEnricher>> = HashMap::new();

        let bloom_filter = BloomFilter::new(config.bloom_filter_size, config.bloom_filter_hash_functions);
        let cache_size = config.cache_size;

        Ok(Self {
            config,
            storage,
            matchers,
            normalizers,
            validators,
            enrichers,
            cache: Arc::new(RwLock::new(IocCache {
                max_size: cache_size,
                ..Default::default()
            })),
            statistics: Arc::new(RwLock::new(IocStatistics::default())),
            bloom_filter: Arc::new(RwLock::new(bloom_filter)),
            whitelist: Arc::new(RwLock::new(HashSet::new())),
            blacklist: Arc::new(RwLock::new(HashSet::new())),
        })
    }

    /// Initialize IOC processor
    pub async fn initialize(&self) -> AgentResult<()> {
        info!("Initializing IOC processor");
        
        // Load existing IOCs into bloom filter
        self.rebuild_bloom_filter().await?;
        
        info!("IOC processor initialized successfully");
        Ok(())
    }

    /// Process and store IOC
    pub async fn process_ioc(&self, ioc_value: &str, ioc_type: IocType, context: Option<ThreatContext>) -> AgentResult<ProcessedIoc> {
        let start_time = SystemTime::now();
        
        // Normalize IOC if enabled
        let normalized_value = if self.config.normalization_enabled {
            if let Some(normalizer) = self.normalizers.get(&ioc_type) {
                normalizer.normalize(ioc_value).await?
            } else {
                ioc_value.to_string()
            }
        } else {
            ioc_value.to_string()
        };

        // Validate IOC if enabled
        let validation = if self.config.validation_enabled {
            if let Some(validator) = self.validators.get(&ioc_type) {
                validator.validate(&normalized_value).await?
            } else {
                ValidationResult {
                    is_valid: true,
                    confidence: 1.0,
                    errors: Vec::new(),
                    warnings: Vec::new(),
                    suggestions: Vec::new(),
                    normalized_value: Some(normalized_value.clone()),
                    validation_rules: Vec::new(),
                }
            }
        } else {
            ValidationResult {
                is_valid: true,
                confidence: 1.0,
                errors: Vec::new(),
                warnings: Vec::new(),
                suggestions: Vec::new(),
                normalized_value: Some(normalized_value.clone()),
                validation_rules: Vec::new(),
            }
        };

        if !validation.is_valid {
            return Err(AgentError::Validation {
                message: format!("Invalid IOC: {:?}", validation.errors),
                field: Some("ioc_value".to_string()),
                expected: None,
                actual: Some(ioc_value.to_string()),
                context: None,
            });
        }

        // Create processed IOC
        let mut processed_ioc = ProcessedIoc {
            id: Uuid::new_v4().to_string(),
            original_value: ioc_value.to_string(),
            normalized_value,
            ioc_type: ioc_type.clone(),
            confidence: validation.confidence,
            severity: ThreatSeverity::Medium,
            tags: Vec::new(),
            source: "manual".to_string(),
            first_seen: SystemTime::now(),
            last_seen: SystemTime::now(),
            created_at: SystemTime::now(),
            updated_at: SystemTime::now(),
            expires_at: None,
            context: context.unwrap_or_default(),
            attribution: None,
            enrichment: None,
            validation,
            metadata: HashMap::new(),
            related_iocs: Vec::new(),
            false_positive: false,
            active: true,
        };

        // Enrich IOC if enabled
        if self.config.enrichment_enabled {
            if let Some(enricher) = self.enrichers.get(&ioc_type) {
                match enricher.enrich(&processed_ioc).await {
                    Ok(enrichment) => processed_ioc.enrichment = Some(enrichment),
                    Err(e) => warn!("Failed to enrich IOC {}: {}", processed_ioc.id, e),
                }
            }
        }

        // Store IOC
        self.storage.store_ioc(&processed_ioc).await?;
        
        // Add to bloom filter
        self.bloom_filter.write().await.add(&processed_ioc.normalized_value);
        
        // Update cache
        self.cache_ioc(&processed_ioc).await;
        
        // Update statistics
        self.update_processing_statistics(start_time).await;
        
        debug!("Processed IOC: {} ({})", processed_ioc.normalized_value, processed_ioc.id);
        Ok(processed_ioc)
    }

    /// Match input against IOCs
    pub async fn match_input(&self, input: &str, ioc_types: Option<&[IocType]>) -> AgentResult<Vec<IocMatch>> {
        let start_time = SystemTime::now();
        let mut matches = Vec::new();
        
        // Check whitelist first
        if self.config.whitelist_enabled {
            let whitelist = self.whitelist.read().await;
            if whitelist.contains(input) {
                debug!("Input {} is whitelisted, skipping match", input);
                return Ok(matches);
            }
        }
        
        // Check blacklist
        if self.config.blacklist_enabled {
            let blacklist = self.blacklist.read().await;
            if blacklist.contains(input) {
                debug!("Input {} is blacklisted, treating as high-confidence match", input);
                // Create synthetic match for blacklisted item
                // This would be implemented based on requirements
            }
        }
        
        // Quick bloom filter check
        let bloom_filter = self.bloom_filter.read().await;
        if !bloom_filter.might_contain(input) {
            debug!("Bloom filter indicates no matches for input: {}", input);
            self.update_match_statistics(start_time, 0).await;
            return Ok(matches);
        }
        
        // Check cache first
        if let Some(cached_matches) = self.get_cached_matches(input).await {
            debug!("Using cached matches for input: {}", input);
            self.update_match_statistics(start_time, cached_matches.len()).await;
            return Ok(cached_matches);
        }
        
        // Determine which IOC types to check
        let types_to_check = if let Some(types) = ioc_types {
            types.to_vec()
        } else {
            self.matchers.keys().cloned().collect()
        };
        
        // Match against each IOC type
        for ioc_type in types_to_check {
            if let Some(matcher) = self.matchers.get(&ioc_type) {
                // Get IOCs of this type from storage
                let criteria = IocSearchCriteria {
                    ioc_types: Some(vec![ioc_type.clone()]),
                    active_only: true,
                    exclude_false_positives: true,
                    ..Default::default()
                };
                
                match self.storage.search_iocs(&criteria).await {
                    Ok(iocs) => {
                        match matcher.match_ioc(input, &iocs).await {
                            Ok(mut type_matches) => matches.append(&mut type_matches),
                            Err(e) => warn!("Failed to match IOCs of type {:?}: {}", ioc_type, e),
                        }
                    },
                    Err(e) => warn!("Failed to retrieve IOCs of type {:?}: {}", ioc_type, e),
                }
            }
        }
        
        // Cache results
        self.cache_matches(input, &matches).await;
        
        // Update statistics
        self.update_match_statistics(start_time, matches.len()).await;
        
        debug!("Found {} matches for input: {}", matches.len(), input);
        Ok(matches)
    }

    /// Bulk process IOCs
    pub async fn bulk_process_iocs(&self, iocs: &[(String, IocType, Option<ThreatContext>)]) -> AgentResult<BulkOperationResult> {
        let start_time = SystemTime::now();
        let mut successful = 0;
        let mut failed = 0;
        let mut errors = Vec::new();
        
        for (ioc_value, ioc_type, context) in iocs {
            match self.process_ioc(ioc_value, ioc_type.clone(), context.clone()).await {
                Ok(_) => successful += 1,
                Err(e) => {
                    failed += 1;
                    errors.push(format!("Failed to process IOC {}: {}", ioc_value, e));
                }
            }
        }
        
        Ok(BulkOperationResult {
            total_items: iocs.len(),
            successful_items: successful,
            failed_items: failed,
            errors,
            duration: start_time.elapsed().unwrap_or_default(),
        })
    }

    /// Get IOC statistics
    pub async fn get_statistics(&self) -> IocStatistics {
        self.statistics.read().await.clone()
    }

    /// Rebuild bloom filter from storage
    async fn rebuild_bloom_filter(&self) -> AgentResult<()> {
        let criteria = IocSearchCriteria {
            active_only: true,
            exclude_false_positives: true,
            ..Default::default()
        };
        
        let iocs = self.storage.search_iocs(&criteria).await?;
        let mut bloom_filter = self.bloom_filter.write().await;
        
        bloom_filter.clear();
        for ioc in iocs {
            bloom_filter.add(&ioc.normalized_value);
        }
        
        info!("Rebuilt bloom filter with {} IOCs", bloom_filter.items_count);
        Ok(())
    }

    /// Cache IOC
    async fn cache_ioc(&self, ioc: &ProcessedIoc) {
        let mut cache = self.cache.write().await;
        
        let cached_ioc = CachedIoc {
            ioc: ioc.clone(),
            created: SystemTime::now(),
            accessed: SystemTime::now(),
            access_count: 1,
            ttl: self.config.cache_ttl,
        };
        
        cache.entries.insert(ioc.normalized_value.clone(), cached_ioc);
        
        // Cleanup if cache is too large
        if cache.entries.len() > cache.max_size {
            self.cleanup_cache(&mut cache).await;
        }
    }

    /// Get cached matches
    async fn get_cached_matches(&self, _input: &str) -> Option<Vec<IocMatch>> {
        // This would implement match result caching
        // For now, return None to indicate no cached results
        None
    }

    /// Cache matches
    async fn cache_matches(&self, _input: &str, _matches: &[IocMatch]) {
        // This would implement match result caching
        // Implementation depends on caching strategy
    }

    /// Cleanup cache
    async fn cleanup_cache(&self, cache: &mut IocCache) {
        // Remove oldest entries until under size limit
        let mut entries: Vec<_> = cache.entries.iter().map(|(k, v)| (k.clone(), v.accessed)).collect();
        entries.sort_by_key(|(_, accessed)| accessed.clone());
        
        let target_size = cache.max_size * 80 / 100; // Remove 20% of entries
        while cache.entries.len() > target_size && !entries.is_empty() {
            let (key, _) = entries.remove(0);
            cache.entries.remove(key.as_str());
            cache.evictions += 1;
        }
    }

    /// Update processing statistics
    async fn update_processing_statistics(&self, start_time: SystemTime) {
        let mut stats = self.statistics.write().await;
        let duration = start_time.elapsed().unwrap_or_default();
        
        // Update average processing time
        let total_ops = stats.total_matches + 1;
        stats.average_match_time = Duration::from_nanos(
            (stats.average_match_time.as_nanos() as u64 * (total_ops - 1) + duration.as_nanos() as u64) / total_ops
        );
    }

    /// Update match statistics
    async fn update_match_statistics(&self, start_time: SystemTime, match_count: usize) {
        let mut stats = self.statistics.write().await;
        let duration = start_time.elapsed().unwrap_or_default();
        
        stats.total_matches += 1;
        if match_count > 0 {
            stats.successful_matches += 1;
        }
        
        // Update average match time
        stats.average_match_time = Duration::from_nanos(
            (stats.average_match_time.as_nanos() as u64 * (stats.total_matches - 1) + duration.as_nanos() as u64) / stats.total_matches
        );
    }
}

/// Implementation for BloomFilter
impl BloomFilter {
    /// Create new bloom filter
    pub fn new(size: usize, hash_functions: u32) -> Self {
        Self {
            bits: vec![false; size],
            size,
            hash_functions,
            items_count: 0,
            false_positive_rate: 0.0,
        }
    }

    /// Create new bloom filter with specified false positive rate and expected capacity
    pub fn with_rate(false_positive_rate: f64, expected_items: u32) -> Self {
        let size = Self::optimal_size(expected_items as usize, false_positive_rate);
        let hash_functions = Self::optimal_hash_functions(size, expected_items as usize);
        Self {
            bits: vec![false; size],
            size,
            hash_functions,
            items_count: 0,
            false_positive_rate,
        }
    }

    /// Calculate optimal size for bloom filter
    fn optimal_size(expected_items: usize, false_positive_rate: f64) -> usize {
        let ln2 = std::f64::consts::LN_2;
        (-(expected_items as f64 * false_positive_rate.ln()) / (ln2 * ln2)).ceil() as usize
    }

    /// Calculate optimal number of hash functions
    fn optimal_hash_functions(size: usize, expected_items: usize) -> u32 {
        let ln2 = std::f64::consts::LN_2;
        ((size as f64 / expected_items as f64) * ln2).ceil() as u32
    }

    /// Add item to bloom filter
    pub fn add(&mut self, item: &str) {
        for i in 0..self.hash_functions {
            let hash = self.hash(item, i) % self.size;
            self.bits[hash] = true;
        }
        self.items_count += 1;
        self.update_false_positive_rate();
    }

    /// Check if item might be in the set
    pub fn might_contain(&self, item: &str) -> bool {
        for i in 0..self.hash_functions {
            let hash = self.hash(item, i) % self.size;
            if !self.bits[hash] {
                return false;
            }
        }
        true
    }

    /// Clear bloom filter
    pub fn clear(&mut self) {
        self.bits.fill(false);
        self.items_count = 0;
        self.false_positive_rate = 0.0;
    }

    /// Simple hash function
    fn hash(&self, item: &str, seed: u32) -> usize {
        let mut hasher = Sha256::new();
        hasher.update(item.as_bytes());
        hasher.update(&seed.to_le_bytes());
        let result = hasher.finalize();
        
        // Convert first 8 bytes to usize
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&result[0..8]);
        usize::from_le_bytes(bytes)
    }

    /// Update false positive rate estimate
    fn update_false_positive_rate(&mut self) {
        if self.items_count > 0 {
            let k = self.hash_functions as f64;
            let m = self.size as f64;
            let n = self.items_count as f64;
            
            // Approximate false positive rate: (1 - e^(-kn/m))^k
            self.false_positive_rate = (1.0 - (-k * n / m).exp()).powf(k);
        }
    }
}

/// Implementation for MemoryIocStorage
impl MemoryIocStorage {
    pub fn new() -> Self {
        Self {
            iocs: Arc::new(RwLock::new(HashMap::new())),
            indices: Arc::new(RwLock::new(StorageIndices::default())),
            statistics: Arc::new(RwLock::new(StorageStatistics::default())),
        }
    }
}

#[async_trait]
impl IocStorage for MemoryIocStorage {
    async fn store_ioc(&self, ioc: &ProcessedIoc) -> AgentResult<()> {
        let mut iocs = self.iocs.write().await;
        let mut indices = self.indices.write().await;
        let mut stats = self.statistics.write().await;
        
        // Store IOC
        iocs.insert(ioc.id.clone(), ioc.clone());
        
        // Update indices
        indices.by_type.entry(ioc.ioc_type.clone()).or_insert_with(HashSet::new).insert(ioc.id.clone());
        indices.by_source.entry(ioc.source.clone()).or_insert_with(HashSet::new).insert(ioc.id.clone());
        indices.by_severity.entry(ioc.severity.clone()).or_insert_with(HashSet::new).insert(ioc.id.clone());
        indices.by_normalized_value.insert(ioc.normalized_value.clone(), ioc.id.clone());
        
        for tag in &ioc.tags {
            indices.by_tag.entry(tag.clone()).or_insert_with(HashSet::new).insert(ioc.id.clone());
        }
        
        // Update statistics
        stats.total_iocs += 1;
        if ioc.active {
            stats.active_iocs += 1;
        }
        *stats.ioc_type_breakdown.entry(ioc.ioc_type.clone()).or_insert(0) += 1;
        *stats.source_breakdown.entry(ioc.source.clone()).or_insert(0) += 1;
        *stats.severity_breakdown.entry(ioc.severity.clone()).or_insert(0) += 1;
        
        Ok(())
    }

    async fn get_ioc(&self, ioc_value: &str, ioc_type: &IocType) -> AgentResult<Option<ProcessedIoc>> {
        let iocs = self.iocs.read().await;
        let indices = self.indices.read().await;
        
        // Try to find by normalized value first
        if let Some(ioc_id) = indices.by_normalized_value.get(ioc_value) {
            if let Some(ioc) = iocs.get(ioc_id) {
                if &ioc.ioc_type == ioc_type {
                    return Ok(Some(ioc.clone()));
                }
            }
        }
        
        // Fallback to linear search
        for ioc in iocs.values() {
            if &ioc.ioc_type == ioc_type && (ioc.original_value == ioc_value || ioc.normalized_value == ioc_value) {
                return Ok(Some(ioc.clone()));
            }
        }
        
        Ok(None)
    }

    async fn search_iocs(&self, criteria: &IocSearchCriteria) -> AgentResult<Vec<ProcessedIoc>> {
        let iocs = self.iocs.read().await;
        let indices = self.indices.read().await;
        
        // Start with all IOCs or filter by type
        let mut candidate_ids: HashSet<String> = if let Some(types) = &criteria.ioc_types {
            let mut ids = HashSet::new();
            for ioc_type in types {
                if let Some(type_ids) = indices.by_type.get(ioc_type) {
                    ids.extend(type_ids.iter().cloned());
                }
            }
            ids
        } else {
            iocs.keys().cloned().collect()
        };
        
        // Apply other filters
        if let Some(sources) = &criteria.sources {
            let mut source_ids = HashSet::new();
            for source in sources {
                if let Some(ids) = indices.by_source.get(source) {
                    source_ids.extend(ids.iter().cloned());
                }
            }
            candidate_ids = candidate_ids.intersection(&source_ids).cloned().collect();
        }
        
        if let Some(tags) = &criteria.tags {
            for tag in tags {
                if let Some(tag_ids) = indices.by_tag.get(tag) {
                    candidate_ids = candidate_ids.intersection(tag_ids).cloned().collect();
                }
            }
        }
        
        // Filter by severity range
        if criteria.severity_min.is_some() || criteria.severity_max.is_some() {
            candidate_ids = candidate_ids.into_iter().filter(|id| {
                if let Some(ioc) = iocs.get(id) {
                    let severity_ok = if let Some(min_sev) = &criteria.severity_min {
                        ioc.severity >= *min_sev
                    } else {
                        true
                    } && if let Some(max_sev) = &criteria.severity_max {
                        ioc.severity <= *max_sev
                    } else {
                        true
                    };
                    severity_ok
                } else {
                    false
                }
            }).collect();
        }
        
        // Collect and filter results
        let mut results: Vec<ProcessedIoc> = candidate_ids.into_iter()
            .filter_map(|id| iocs.get(&id).cloned())
            .filter(|ioc| {
                // Apply additional filters
                if criteria.active_only && !ioc.active {
                    return false;
                }
                if criteria.exclude_false_positives && ioc.false_positive {
                    return false;
                }
                if let Some(min_conf) = criteria.confidence_min {
                    if ioc.confidence < min_conf {
                        return false;
                    }
                }
                if let Some(max_conf) = criteria.confidence_max {
                    if ioc.confidence > max_conf {
                        return false;
                    }
                }
                // Add time-based filters here
                true
            })
            .collect();
        
        // Apply sorting
        if let Some(sort_by) = &criteria.sort_by {
            match sort_by.as_str() {
                "created_at" => results.sort_by_key(|ioc| ioc.created_at),
                "updated_at" => results.sort_by_key(|ioc| ioc.updated_at),
                "confidence" => results.sort_by(|a, b| a.confidence.partial_cmp(&b.confidence).unwrap_or(std::cmp::Ordering::Equal)),
                "severity" => results.sort_by_key(|ioc| ioc.severity.clone()),
                _ => {}, // No sorting
            }
            
            if let Some(SortOrder::Descending) = criteria.sort_order {
                results.reverse();
            }
        }
        
        // Apply pagination
        if let Some(offset) = criteria.offset {
            if offset < results.len() {
                results = results.into_iter().skip(offset).collect();
            } else {
                results.clear();
            }
        }
        
        if let Some(limit) = criteria.limit {
            results.truncate(limit);
        }
        
        Ok(results)
    }

    async fn update_ioc(&self, ioc: &ProcessedIoc) -> AgentResult<()> {
        let mut iocs = self.iocs.write().await;
        if iocs.contains_key(&ioc.id) {
            iocs.insert(ioc.id.clone(), ioc.clone());
            Ok(())
        } else {
            Err(AgentError::Validation { 
                message: format!("IOC not found: {}", ioc.id), 
                field: None, 
                expected: None, 
                actual: None, 
                context: None 
            })
        }
    }

    async fn delete_ioc(&self, ioc_id: &str) -> AgentResult<()> {
        let mut iocs = self.iocs.write().await;
        let mut indices = self.indices.write().await;
        let mut stats = self.statistics.write().await;
        
        if let Some(ioc) = iocs.remove(ioc_id) {
            // Update indices
            if let Some(type_ids) = indices.by_type.get_mut(&ioc.ioc_type) {
                type_ids.remove(ioc_id);
            }
            if let Some(source_ids) = indices.by_source.get_mut(&ioc.source) {
                source_ids.remove(ioc_id);
            }
            if let Some(severity_ids) = indices.by_severity.get_mut(&ioc.severity) {
                severity_ids.remove(ioc_id);
            }
            indices.by_normalized_value.remove(&ioc.normalized_value);
            
            for tag in &ioc.tags {
                if let Some(tag_ids) = indices.by_tag.get_mut(tag) {
                    tag_ids.remove(ioc_id);
                }
            }
            
            // Update statistics
            stats.total_iocs -= 1;
            if ioc.active {
                stats.active_iocs -= 1;
            }
            
            Ok(())
        } else {
            Err(AgentError::Validation { 
                message: format!("IOC not found: {}", ioc_id), 
                field: None, 
                expected: None, 
                actual: None, 
                context: None 
            })
        }
    }

    async fn bulk_store(&self, iocs: &[ProcessedIoc]) -> AgentResult<BulkOperationResult> {
        let start_time = SystemTime::now();
        let mut successful = 0;
        let mut failed = 0;
        let mut errors = Vec::new();
        
        for ioc in iocs {
            match self.store_ioc(ioc).await {
                Ok(_) => successful += 1,
                Err(e) => {
                    failed += 1;
                    errors.push(format!("Failed to store IOC {}: {}", ioc.id, e));
                }
            }
        }
        
        Ok(BulkOperationResult {
            total_items: iocs.len(),
            successful_items: successful,
            failed_items: failed,
            errors,
            duration: start_time.elapsed().unwrap_or_default(),
        })
    }

    async fn bulk_delete(&self, ioc_ids: &[String]) -> AgentResult<BulkOperationResult> {
        let start_time = SystemTime::now();
        let mut successful = 0;
        let mut failed = 0;
        let mut errors = Vec::new();
        
        for ioc_id in ioc_ids {
            match self.delete_ioc(ioc_id).await {
                Ok(_) => successful += 1,
                Err(e) => {
                    failed += 1;
                    errors.push(format!("Failed to delete IOC {}: {}", ioc_id, e));
                }
            }
        }
        
        Ok(BulkOperationResult {
            total_items: ioc_ids.len(),
            successful_items: successful,
            failed_items: failed,
            errors,
            duration: start_time.elapsed().unwrap_or_default(),
        })
    }

    async fn get_statistics(&self) -> AgentResult<StorageStatistics> {
        Ok(self.statistics.read().await.clone())
    }

    async fn cleanup_expired(&self, before: SystemTime) -> AgentResult<u64> {
        let mut iocs = self.iocs.write().await;
        let mut indices = self.indices.write().await;
        let mut stats = self.statistics.write().await;
        
        let mut removed_count = 0;
        let expired_ids: Vec<String> = iocs.iter()
            .filter(|(_, ioc)| {
                if let Some(expires_at) = ioc.expires_at {
                    expires_at < before
                } else {
                    false
                }
            })
            .map(|(id, _)| id.clone())
            .collect();
        
        for ioc_id in expired_ids {
            if let Some(ioc) = iocs.remove(&ioc_id) {
                // Update indices (similar to delete_ioc)
                if let Some(type_ids) = indices.by_type.get_mut(&ioc.ioc_type) {
                    type_ids.remove(&ioc_id);
                }
                // ... (other index updates)
                
                removed_count += 1;
                stats.expired_iocs += 1;
            }
        }
        
        stats.last_cleanup = Some(SystemTime::now());
        Ok(removed_count)
    }
}

/// Matcher implementations (stubs)
impl FileHashMatcher {
    fn new() -> Self {
        let mut supported_algorithms = HashSet::new();
        supported_algorithms.insert("md5".to_string());
        supported_algorithms.insert("sha1".to_string());
        supported_algorithms.insert("sha256".to_string());
        supported_algorithms.insert("sha512".to_string());
        
        Self { supported_algorithms }
    }
}

#[async_trait]
impl IocMatcher for FileHashMatcher {
    async fn match_ioc(&self, input: &str, iocs: &[ProcessedIoc]) -> AgentResult<Vec<IocMatch>> {
        let mut matches = Vec::new();
        
        for ioc in iocs {
            if input.to_lowercase() == ioc.normalized_value.to_lowercase() {
                matches.push(IocMatch {
                    match_id: Uuid::new_v4(),
                    input: input.to_string(),
                    matched_ioc: ioc.clone(),
                    match_type: MatchType::Exact,
                    confidence: 1.0,
                    match_position: Some((0, input.len())),
                    match_context: None,
                    timestamp: SystemTime::now(),
                });
            }
        }
        
        Ok(matches)
    }
    
    fn get_type(&self) -> IocType {
        IocType::FileHash
    }
    
    fn get_confidence(&self, _input: &str, _ioc: &ProcessedIoc) -> f64 {
        1.0 // Exact hash matches have 100% confidence
    }
}

// Similar implementations for other matchers would go here...
// (IpAddressMatcher, DomainMatcher, etc.)

/// Stub implementations for other matchers
macro_rules! impl_stub_matcher {
    ($matcher:ident, $ioc_type:expr) => {
        impl $matcher {
            fn new() -> Self {
                Self {}
            }
        }
        
        #[async_trait]
        impl IocMatcher for $matcher {
            async fn match_ioc(&self, _input: &str, _iocs: &[ProcessedIoc]) -> AgentResult<Vec<IocMatch>> {
                // TODO: Implement specific matching logic
                Ok(Vec::new())
            }
            
            fn get_type(&self) -> IocType {
                $ioc_type
            }
            
            fn get_confidence(&self, _input: &str, _ioc: &ProcessedIoc) -> f64 {
                0.8 // Default confidence
            }
        }
    };
}

// Generate stub implementations
impl_stub_matcher!(MutexMatcher, IocType::Mutex);
impl_stub_matcher!(UserAgentMatcher, IocType::UserAgent);
impl_stub_matcher!(ProcessNameMatcher, IocType::ProcessName);
impl_stub_matcher!(YaraMatcher, IocType::Yara);

// Add missing matcher implementations
impl EmailMatcher {
    fn new() -> AgentResult<Self> {
        Ok(Self {
            email_regex: Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
                .map_err(|e| AgentError::Configuration {
                    message: format!("Failed to compile email regex: {}", e),
                    field: Some("email_regex".to_string()),
                    context: Some(crate::error::ErrorContext::new("EmailMatcher::new", "threat_intel")),
                })?,
        })
    }
}

#[async_trait]
impl IocMatcher for EmailMatcher {
    async fn match_ioc(&self, input: &str, iocs: &[ProcessedIoc]) -> AgentResult<Vec<IocMatch>> {
        let mut matches = Vec::new();
        for ioc in iocs {
            if self.email_regex.is_match(input) && input == ioc.normalized_value {
                matches.push(IocMatch {
                    match_id: Uuid::new_v4(),
                    input: input.to_string(),
                    matched_ioc: ioc.clone(),
                    match_type: MatchType::Exact,
                    confidence: self.get_confidence(input, ioc),
                    match_position: Some((0, input.len())),
                    match_context: None,
                    timestamp: SystemTime::now(),
                });
            }
        }
        Ok(matches)
    }

    fn get_type(&self) -> IocType {
        IocType::Email
    }

    fn get_confidence(&self, _input: &str, _ioc: &ProcessedIoc) -> f64 {
        0.9
    }
}

impl RegistryMatcher {
    fn new() -> Self {
        Self {
            registry_patterns: vec![
                Regex::new(r"^HKEY_[A-Z_]+\\.*").unwrap(),
                Regex::new(r"^HKLM\\.*").unwrap(),
                Regex::new(r"^HKCU\\.*").unwrap(),
            ],
        }
    }
}

#[async_trait]
impl IocMatcher for RegistryMatcher {
    async fn match_ioc(&self, input: &str, iocs: &[ProcessedIoc]) -> AgentResult<Vec<IocMatch>> {
        let mut matches = Vec::new();
        for ioc in iocs {
            for pattern in &self.registry_patterns {
                if pattern.is_match(input) && input == ioc.normalized_value {
                    matches.push(IocMatch {
                        match_id: Uuid::new_v4(),
                        input: input.to_string(),
                        matched_ioc: ioc.clone(),
                        match_type: MatchType::Regex,
                        confidence: self.get_confidence(input, ioc),
                        match_position: Some((0, input.len())),
                        match_context: None,
                        timestamp: SystemTime::now(),
                    });
                    break;
                }
            }
        }
        Ok(matches)
    }

    fn get_type(&self) -> IocType {
        IocType::Registry
    }

    fn get_confidence(&self, _input: &str, _ioc: &ProcessedIoc) -> f64 {
        0.8
    }
}

impl FilePathMatcher {
    fn new() -> Self {
        Self {
            path_patterns: vec![
                Regex::new(r"^[A-Za-z]:\\.*").unwrap(), // Windows paths
                Regex::new(r"^/.*").unwrap(),            // Unix paths
            ],
        }
    }
}

#[async_trait]
impl IocMatcher for FilePathMatcher {
    async fn match_ioc(&self, input: &str, iocs: &[ProcessedIoc]) -> AgentResult<Vec<IocMatch>> {
        let mut matches = Vec::new();
        for ioc in iocs {
            for pattern in &self.path_patterns {
                if pattern.is_match(input) && input == ioc.normalized_value {
                    matches.push(IocMatch {
                        match_id: Uuid::new_v4(),
                        input: input.to_string(),
                        matched_ioc: ioc.clone(),
                        match_type: MatchType::Regex,
                        confidence: self.get_confidence(input, ioc),
                        match_position: Some((0, input.len())),
                        match_context: None,
                        timestamp: SystemTime::now(),
                    });
                    break;
                }
            }
        }
        Ok(matches)
    }

    fn get_type(&self) -> IocType {
        IocType::FilePath
    }

    fn get_confidence(&self, _input: &str, _ioc: &ProcessedIoc) -> f64 {
        0.7
    }
}

impl NetworkSignatureMatcher {
    fn new() -> Self {
        Self {
            signature_patterns: vec![
                Regex::new(r"^[0-9a-fA-F]{32,}$").unwrap(), // Generic hex signatures
            ],
        }
    }
}

#[async_trait]
impl IocMatcher for NetworkSignatureMatcher {
    async fn match_ioc(&self, input: &str, iocs: &[ProcessedIoc]) -> AgentResult<Vec<IocMatch>> {
        let mut matches = Vec::new();
        for ioc in iocs {
            for pattern in &self.signature_patterns {
                if pattern.is_match(input) && input == ioc.normalized_value {
                    matches.push(IocMatch {
                        match_id: Uuid::new_v4(),
                        input: input.to_string(),
                        matched_ioc: ioc.clone(),
                        match_type: MatchType::Regex,
                        confidence: self.get_confidence(input, ioc),
                        match_position: Some((0, input.len())),
                        match_context: None,
                        timestamp: SystemTime::now(),
                    });
                    break;
                }
            }
        }
        Ok(matches)
    }

    fn get_type(&self) -> IocType {
        IocType::NetworkSignature
    }

    fn get_confidence(&self, _input: &str, _ioc: &ProcessedIoc) -> f64 {
        0.8
    }
}

impl IpAddressMatcher {
    fn new() -> Self {
        Self {
            networks: Vec::new(), // Initialize with empty networks, can be populated later
        }
    }
}

#[async_trait]
impl IocMatcher for IpAddressMatcher {
    async fn match_ioc(&self, input: &str, iocs: &[ProcessedIoc]) -> AgentResult<Vec<IocMatch>> {
        let mut matches = Vec::new();
        
        // Try to parse input as IP address
        if let Ok(input_ip) = input.parse::<std::net::IpAddr>() {
            for ioc in iocs {
                // Check exact IP match
                if let Ok(ioc_ip) = ioc.normalized_value.parse::<std::net::IpAddr>() {
                    if input_ip == ioc_ip {
                        matches.push(IocMatch {
                            match_id: Uuid::new_v4(),
                            input: input.to_string(),
                            matched_ioc: ioc.clone(),
                            match_type: MatchType::Exact,
                            confidence: self.get_confidence(input, ioc),
                            match_position: Some((0, input.len())),
                            match_context: None,
                            timestamp: SystemTime::now(),
                        });
                    }
                }
                
                // Check network matches
                for network in &self.networks {
                    if network.contains(input_ip) {
                        matches.push(IocMatch {
                            match_id: Uuid::new_v4(),
                            input: input.to_string(),
                            matched_ioc: ioc.clone(),
                            match_type: MatchType::Network,
                            confidence: self.get_confidence(input, ioc) * 0.9, // Slightly lower confidence for network matches
                            match_position: Some((0, input.len())),
                            match_context: Some(format!("Network: {}", network)),
                            timestamp: SystemTime::now(),
                        });
                    }
                }
            }
        }
        
        Ok(matches)
    }

    fn get_type(&self) -> IocType {
        IocType::IpAddress
    }

    fn get_confidence(&self, _input: &str, _ioc: &ProcessedIoc) -> f64 {
        0.95
    }
}

impl CertificateMatcher {
    fn new() -> Self {
        Self {
            cert_patterns: vec![
                Regex::new(r"^[A-Fa-f0-9]{40}$").unwrap(), // SHA-1 fingerprint
                Regex::new(r"^[A-Fa-f0-9]{64}$").unwrap(), // SHA-256 fingerprint
                Regex::new(r"^[A-Fa-f0-9:]{47,95}$").unwrap(), // Colon-separated fingerprint
            ],
        }
    }
}

#[async_trait]
impl IocMatcher for CertificateMatcher {
    async fn match_ioc(&self, input: &str, iocs: &[ProcessedIoc]) -> AgentResult<Vec<IocMatch>> {
        let mut matches = Vec::new();
        
        for ioc in iocs {
            // Check exact match first
            if input == ioc.normalized_value {
                matches.push(IocMatch {
                    match_id: Uuid::new_v4(),
                    input: input.to_string(),
                    matched_ioc: ioc.clone(),
                    match_type: MatchType::Exact,
                    confidence: self.get_confidence(input, ioc),
                    match_position: Some((0, input.len())),
                    match_context: None,
                    timestamp: SystemTime::now(),
                });
            } else {
                // Check pattern matches
                for pattern in &self.cert_patterns {
                    if pattern.is_match(input) && input == ioc.normalized_value {
                        matches.push(IocMatch {
                            match_id: Uuid::new_v4(),
                            input: input.to_string(),
                            matched_ioc: ioc.clone(),
                            match_type: MatchType::Regex,
                            confidence: self.get_confidence(input, ioc),
                            match_position: Some((0, input.len())),
                            match_context: None,
                            timestamp: SystemTime::now(),
                        });
                        break;
                    }
                }
            }
        }
        
        Ok(matches)
    }

    fn get_type(&self) -> IocType {
        IocType::Certificate
    }

    fn get_confidence(&self, _input: &str, _ioc: &ProcessedIoc) -> f64 {
        0.9
    }
}

impl UrlMatcher {
    fn new() -> AgentResult<Self> {
        Ok(Self {
            url_regex: Regex::new(r"^https?://[^\s/$.?#].[^\s]*$")
                .map_err(|e| AgentError::Configuration {
                    message: format!("Failed to compile URL regex: {}", e),
                    field: Some("url_regex".to_string()),
                    context: Some(crate::error::ErrorContext::new("UrlMatcher::new", "threat_intel")),
                })?,
        })
    }
}

#[async_trait]
impl IocMatcher for UrlMatcher {
    async fn match_ioc(&self, input: &str, iocs: &[ProcessedIoc]) -> AgentResult<Vec<IocMatch>> {
        let mut matches = Vec::new();
        for ioc in iocs {
            if self.url_regex.is_match(input) && input == ioc.normalized_value {
                matches.push(IocMatch {
                    match_id: Uuid::new_v4(),
                    input: input.to_string(),
                    matched_ioc: ioc.clone(),
                    match_type: MatchType::Exact,
                    confidence: self.get_confidence(input, ioc),
                    match_position: Some((0, input.len())),
                    match_context: None,
                    timestamp: SystemTime::now(),
                });
            }
        }
        Ok(matches)
    }

    fn get_type(&self) -> IocType {
        IocType::Url
    }

    fn get_confidence(&self, _input: &str, _ioc: &ProcessedIoc) -> f64 {
        0.9
    }
}

// Special implementations for regex-based matchers
impl DomainMatcher {
    fn new() -> AgentResult<Self> {
        let domain_regex = Regex::new(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.[a-zA-Z]{2,}$")
            .map_err(|e| AgentError::Configuration { 
                message: format!("Invalid domain regex: {}", e),
                field: Some("domain_regex".to_string()),
                context: None
            })?;
        
        Ok(Self {
            tld_list: HashSet::new(), // Would be populated with actual TLDs
            domain_regex,
        })
    }
}

#[async_trait]
impl IocMatcher for DomainMatcher {
    async fn match_ioc(&self, input: &str, iocs: &[ProcessedIoc]) -> AgentResult<Vec<IocMatch>> {
        let mut matches = Vec::new();
        
        for ioc in iocs {
            // Exact match
            if input.to_lowercase() == ioc.normalized_value.to_lowercase() {
                matches.push(IocMatch {
                    match_id: Uuid::new_v4(),
                    input: input.to_string(),
                    matched_ioc: ioc.clone(),
                    match_type: MatchType::Exact,
                    confidence: 1.0,
                    match_position: Some((0, input.len())),
                    match_context: None,
                    timestamp: SystemTime::now(),
                });
            }
            // Subdomain match
            else if input.to_lowercase().ends_with(&format!(".{}", ioc.normalized_value.to_lowercase())) {
                matches.push(IocMatch {
                    match_id: Uuid::new_v4(),
                    input: input.to_string(),
                    matched_ioc: ioc.clone(),
                    match_type: MatchType::Subdomain,
                    confidence: 0.9,
                    match_position: Some((input.len() - ioc.normalized_value.len() - 1, input.len())),
                    match_context: None,
                    timestamp: SystemTime::now(),
                });
            }
        }
        
        Ok(matches)
    }
    
    fn get_type(&self) -> IocType {
        IocType::Domain
    }
    
    fn get_confidence(&self, _input: &str, _ioc: &ProcessedIoc) -> f64 {
        0.9
    }
}

// Similar implementations for UrlMatcher, EmailMatcher, etc.

/// Default implementations
impl Default for IocConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cache_size: 10000,
            cache_ttl: Duration::from_secs(3600),
            bloom_filter_size: 1000000,
            bloom_filter_hash_functions: 3,
            batch_size: 1000,
            max_concurrent_operations: 10,
            validation_enabled: true,
            normalization_enabled: true,
            enrichment_enabled: false,
            whitelist_enabled: false,
            blacklist_enabled: false,
            fuzzy_matching: false,
            case_sensitive: false,
            regex_timeout: Duration::from_secs(5),
            storage_backend: StorageBackend::Memory,
            retention_policy: RetentionPolicy::default(),
        }
    }
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            default_ttl: Duration::from_secs(86400 * 30), // 30 days
            max_age: Duration::from_secs(86400 * 365), // 1 year
            cleanup_interval: Duration::from_secs(3600), // 1 hour
            type_specific_ttl: HashMap::new(),
            priority_based_retention: false,
        }
    }
}

impl Default for IocSearchCriteria {
    fn default() -> Self {
        Self {
            ioc_types: None,
            sources: None,
            tags: None,
            severity_min: None,
            severity_max: None,
            confidence_min: None,
            confidence_max: None,
            created_after: None,
            created_before: None,
            updated_after: None,
            updated_before: None,
            active_only: true,
            exclude_false_positives: true,
            text_search: None,
            limit: None,
            offset: None,
            sort_by: None,
            sort_order: None,
        }
    }
}
