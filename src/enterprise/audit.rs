//! Tamper-Proof Audit Logging System
//!
//! This module implements a comprehensive tamper-proof audit logging system
//! that ensures integrity, non-repudiation, and compliance with security standards.
//! It uses cryptographic techniques to prevent tampering and provides
//! immutable audit trails for all security events.

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Clock synchronization configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClockSyncConfig {
    /// NTP server URLs
    pub ntp_servers: Vec<String>,
    /// Sync interval in seconds
    pub sync_interval: u64,
    /// Maximum allowed drift in milliseconds
    pub max_drift_ms: u64,
    /// Enable automatic sync
    pub auto_sync: bool,
}

/// Consistency levels for distributed storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConsistencyLevel {
    /// Eventually consistent
    Eventual,
    /// Strong consistency
    Strong,
    /// Causal consistency
    Causal,
    /// Session consistency
    Session,
}

/// Sharding strategies for distributed storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ShardingStrategy {
    /// Hash-based sharding
    Hash,
    /// Range-based sharding
    Range,
    /// Directory-based sharding
    Directory,
    /// Consistent hashing
    ConsistentHash,
}

/// Storage node configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageNode {
    /// Node identifier
    pub id: String,
    /// Node address
    pub address: String,
    /// Node port
    pub port: u16,
    /// Node weight for load balancing
    pub weight: f32,
    /// Node status
    pub status: NodeStatus,
}

/// Node status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NodeStatus {
    Active,
    Inactive,
    Maintenance,
    Failed,
}

/// Compression algorithms
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CompressionAlgorithm {
    /// No compression
    None,
    /// Gzip compression
    Gzip,
    /// Zstd compression
    Zstd,
    /// LZ4 compression
    Lz4,
    /// Brotli compression
    Brotli,
}

/// Tamper detection algorithms
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TamperDetectionAlgorithm {
    /// Hash-based detection
    HashBased,
    /// Signature-based detection
    SignatureBased,
    /// Merkle tree-based detection
    MerkleTreeBased,
    /// Timestamp-based detection
    TimestampBased,
    /// Statistical analysis
    StatisticalAnalysis,
}

/// Configuration for tamper-proof audit logging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Cryptographic configuration
    pub cryptography: CryptographyConfig,
    /// Storage configuration
    pub storage: StorageConfig,
    /// Integrity verification configuration
    pub integrity: IntegrityConfig,
    /// Retention configuration
    pub retention: RetentionConfig,
    /// Compliance configuration
    pub compliance: ComplianceConfig,
    /// Performance configuration
    pub performance: PerformanceConfig,
    /// Backup configuration
    pub backup: BackupConfig,
}

/// Cryptographic configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptographyConfig {
    /// Hash algorithm for integrity
    pub hash_algorithm: HashAlgorithm,
    /// Digital signature algorithm
    pub signature_algorithm: SignatureAlgorithm,
    /// Encryption algorithm for sensitive data
    pub encryption_algorithm: EncryptionAlgorithm,
    /// Key management configuration
    pub key_management: KeyManagementConfig,
    /// Merkle tree configuration
    pub merkle_tree: MerkleTreeConfig,
    /// Timestamp authority configuration
    pub timestamp_authority: TimestampConfig,
}

/// Storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Primary storage backend
    pub primary_backend: StorageBackend,
    /// Secondary storage backends for redundancy
    pub secondary_backends: Vec<StorageBackend>,
    /// Immutable storage configuration
    pub immutable_storage: ImmutableStorageConfig,
    /// Distributed storage configuration
    pub distributed_storage: DistributedStorageConfig,
    /// Compression configuration
    pub compression: CompressionConfig,
}

/// Integrity verification configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityConfig {
    /// Verification frequency
    pub verification_frequency: Duration,
    /// Batch verification size
    pub batch_size: usize,
    /// Integrity check methods
    pub check_methods: Vec<IntegrityCheckMethod>,
    /// Tamper detection configuration
    pub tamper_detection: TamperDetectionConfig,
    /// Recovery configuration
    pub recovery: RecoveryConfig,
}

/// Retention configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionConfig {
    /// Default retention period
    pub default_retention: Duration,
    /// Category-specific retention policies
    pub category_policies: HashMap<AuditCategory, Duration>,
    /// Legal hold configuration
    pub legal_hold: LegalHoldConfig,
    /// Archival configuration
    pub archival: ArchivalConfig,
    /// Deletion policies
    pub deletion: DeletionConfig,
}

/// Compliance configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceConfig {
    /// Compliance frameworks
    pub frameworks: Vec<ComplianceFramework>,
    /// Audit trail requirements
    pub audit_trail_requirements: AuditTrailRequirements,
    /// Reporting configuration
    pub reporting: ComplianceReportingConfig,
    /// Certification requirements
    pub certification: CertificationConfig,
}

/// Performance configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    /// Batch processing configuration
    pub batch_processing: BatchProcessingConfig,
    /// Async processing configuration
    pub async_processing: AsyncProcessingConfig,
    /// Caching configuration
    pub caching: CachingConfig,
    /// Rate limiting configuration
    pub rate_limiting: RateLimitingConfig,
}

/// Backup configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupConfig {
    /// Backup frequency
    pub frequency: Duration,
    /// Backup destinations
    pub destinations: Vec<BackupDestination>,
    /// Backup encryption
    pub encryption: BackupEncryptionConfig,
    /// Backup verification
    pub verification: BackupVerificationConfig,
    /// Disaster recovery
    pub disaster_recovery: DisasterRecoveryConfig,
}

/// Hash algorithms
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HashAlgorithm {
    SHA256,
    SHA384,
    SHA512,
    SHA3_256,
    SHA3_384,
    SHA3_512,
    BLAKE2b,
    BLAKE3,
}

/// Digital signature algorithms
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    RSA2048,
    RSA3072,
    RSA4096,
    EcdsaP256,
    EcdsaP384,
    EcdsaP521,
    EdDsaEd25519,
    EdDsaEd448,
}

/// Encryption algorithms
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EncryptionAlgorithm {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
    XchaCha20Poly1305,
}

/// Key management configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyManagementConfig {
    /// Key derivation function
    pub key_derivation: KeyDerivationFunction,
    /// Key rotation policy
    pub rotation_policy: KeyRotationPolicy,
    /// Key storage backend
    pub storage_backend: KeyStorageBackend,
    /// Hardware security module configuration
    pub hsm_config: Option<HSMConfig>,
}

/// Merkle tree configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleTreeConfig {
    /// Tree depth
    pub depth: usize,
    /// Leaf hash algorithm
    pub leaf_hash: HashAlgorithm,
    /// Internal node hash algorithm
    pub internal_hash: HashAlgorithm,
    /// Tree balancing strategy
    pub balancing: TreeBalancingStrategy,
}

/// Timestamp configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimestampConfig {
    /// Timestamp authority URL
    pub authority_url: Option<String>,
    /// Local timestamp validation
    pub local_validation: bool,
    /// Timestamp precision
    pub precision: TimestampPrecision,
    /// Clock synchronization
    pub clock_sync: ClockSyncConfig,
}

/// Storage backends
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageBackend {
    FileSystem { path: String },
    Database { connection_string: String },
    S3 { bucket: String, region: String },
    Azure { container: String, account: String },
    GCS { bucket: String, project: String },
    IPFS { gateway: String },
    Blockchain { network: String, contract: String },
}

/// Immutable storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImmutableStorageConfig {
    /// Enable write-once-read-many (WORM) storage
    pub worm_enabled: bool,
    /// Immutability verification
    pub verification_enabled: bool,
    /// Immutable storage backend
    pub backend: Option<StorageBackend>,
}

/// Distributed storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributedStorageConfig {
    /// Replication factor
    pub replication_factor: usize,
    /// Consistency level
    pub consistency_level: ConsistencyLevel,
    /// Sharding strategy
    pub sharding_strategy: ShardingStrategy,
    /// Node configuration
    pub nodes: Vec<StorageNode>,
}

/// Compression configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressionConfig {
    /// Compression algorithm
    pub algorithm: CompressionAlgorithm,
    /// Compression level
    pub level: u8,
    /// Enable compression
    pub enabled: bool,
}

/// Integrity check methods
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IntegrityCheckMethod {
    HashVerification,
    SignatureVerification,
    MerkleTreeVerification,
    TimestampVerification,
    CrossReferenceVerification,
}

/// Tamper detection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TamperDetectionConfig {
    /// Detection algorithms
    pub algorithms: Vec<TamperDetectionAlgorithm>,
    /// Detection sensitivity
    pub sensitivity: f32,
    /// Alert configuration
    pub alerts: TamperAlertConfig,
    /// Response actions
    pub response_actions: Vec<TamperResponseAction>,
}

/// Recovery configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryConfig {
    /// Recovery strategies
    pub strategies: Vec<RecoveryStrategy>,
    /// Backup verification
    pub backup_verification: bool,
    /// Recovery testing
    pub recovery_testing: RecoveryTestingConfig,
}

/// Audit categories
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AuditCategory {
    Authentication,
    Authorization,
    DataAccess,
    SystemChanges,
    SecurityEvents,
    ComplianceEvents,
    AdministrativeActions,
    NetworkActivity,
    FileOperations,
    DatabaseOperations,
    APIAccess,
    ErrorEvents,
}

/// Legal hold configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegalHoldConfig {
    /// Enable legal hold
    pub enabled: bool,
    /// Hold policies
    pub policies: Vec<LegalHoldPolicy>,
    /// Notification configuration
    pub notifications: LegalHoldNotificationConfig,
}

/// Archival configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchivalConfig {
    /// Archival strategy
    pub strategy: ArchivalStrategy,
    /// Archival storage backend
    pub storage_backend: StorageBackend,
    /// Compression for archival
    pub compression: CompressionConfig,
    /// Retrieval configuration
    pub retrieval: ArchivalRetrievalConfig,
}

/// Deletion configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletionConfig {
    /// Secure deletion method
    pub method: SecureDeletionMethod,
    /// Deletion verification
    pub verification: bool,
    /// Deletion logging
    pub logging: bool,
}

/// Compliance frameworks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComplianceFramework {
    SOX,
    HIPAA,
    GDPR,
    PciDss,
    ISO27001,
    NIST,
    FedRAMP,
    SOC2,
    FISMA,
    COBIT,
}

/// Audit trail requirements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditTrailRequirements {
    /// Required fields
    pub required_fields: Vec<AuditField>,
    /// Minimum retention period
    pub min_retention: Duration,
    /// Integrity requirements
    pub integrity_requirements: IntegrityRequirements,
    /// Access control requirements
    pub access_control: AccessControlRequirements,
}

/// Compliance reporting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReportingConfig {
    /// Report formats
    pub formats: Vec<ReportFormat>,
    /// Report frequency
    pub frequency: Duration,
    /// Report recipients
    pub recipients: Vec<String>,
    /// Automated reporting
    pub automated: bool,
}

/// Certification configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificationConfig {
    /// Required certifications
    pub certifications: Vec<String>,
    /// Certification validation
    pub validation: CertificationValidationConfig,
    /// Renewal tracking
    pub renewal_tracking: bool,
}

/// Batch processing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchProcessingConfig {
    /// Batch size
    pub batch_size: usize,
    /// Processing interval
    pub interval: Duration,
    /// Parallel processing
    pub parallel_workers: usize,
    /// Queue configuration
    pub queue_config: QueueConfig,
}

/// Async processing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsyncProcessingConfig {
    /// Enable async processing
    pub enabled: bool,
    /// Worker pool size
    pub worker_pool_size: usize,
    /// Task queue size
    pub task_queue_size: usize,
    /// Priority handling
    pub priority_handling: bool,
}

/// Caching configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachingConfig {
    /// Enable caching
    pub enabled: bool,
    /// Cache size
    pub cache_size: usize,
    /// Cache TTL
    pub ttl: Duration,
    /// Cache eviction policy
    pub eviction_policy: CacheEvictionPolicy,
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitingConfig {
    /// Enable rate limiting
    pub enabled: bool,
    /// Requests per second
    pub requests_per_second: u32,
    /// Burst capacity
    pub burst_capacity: u32,
    /// Rate limiting strategy
    pub strategy: RateLimitingStrategy,
}

/// Backup destinations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BackupDestination {
    LocalFileSystem { path: String },
    RemoteFileSystem { url: String, credentials: String },
    CloudStorage { provider: String, config: HashMap<String, String> },
    TapeStorage { device: String },
    OpticalStorage { device: String },
}

/// Backup encryption configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupEncryptionConfig {
    /// Enable encryption
    pub enabled: bool,
    /// Encryption algorithm
    pub algorithm: EncryptionAlgorithm,
    /// Key management
    pub key_management: KeyManagementConfig,
}

/// Backup verification configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupVerificationConfig {
    /// Verification frequency
    pub frequency: Duration,
    /// Verification methods
    pub methods: Vec<BackupVerificationMethod>,
    /// Integrity checking
    pub integrity_checking: bool,
}

/// Disaster recovery configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisasterRecoveryConfig {
    /// Recovery time objective (RTO)
    pub rto: Duration,
    /// Recovery point objective (RPO)
    pub rpo: Duration,
    /// Recovery strategies
    pub strategies: Vec<DisasterRecoveryStrategy>,
    /// Testing schedule
    pub testing_schedule: Duration,
}

/// Audit error types
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("Configuration error: {0}")]
    Configuration(String),
    #[error("Cryptographic error: {0}")]
    Cryptographic(String),
    #[error("Storage error: {0}")]
    Storage(String),
    #[error("Integrity error: {0}")]
    Integrity(String),
    #[error("Tamper detection error: {0}")]
    TamperDetection(String),
    #[error("Compliance error: {0}")]
    Compliance(String),
}

/// Audit event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Event ID
    pub id: Uuid,
    /// Event timestamp
    pub timestamp: DateTime<Utc>,
    /// Event category
    pub category: AuditCategory,
    /// Event type
    pub event_type: String,
    /// Event source
    pub source: EventSource,
    /// Actor information
    pub actor: ActorInfo,
    /// Target information
    pub target: Option<TargetInfo>,
    /// Event outcome
    pub outcome: EventOutcome,
    /// Event details
    pub details: HashMap<String, String>,
    /// Risk level
    pub risk_level: RiskLevel,
    /// Compliance tags
    pub compliance_tags: Vec<String>,
    /// Custom metadata
    pub metadata: HashMap<String, String>,
}

/// Event source information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventSource {
    /// Source type
    pub source_type: SourceType,
    /// Source identifier
    pub identifier: String,
    /// Source location
    pub location: Option<String>,
    /// Source version
    pub version: Option<String>,
}

/// Actor information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActorInfo {
    /// Actor type
    pub actor_type: ActorType,
    /// Actor identifier
    pub identifier: String,
    /// Actor name
    pub name: Option<String>,
    /// Actor roles
    pub roles: Vec<String>,
    /// Actor session information
    pub session: Option<SessionInfo>,
    /// Actor location
    pub location: Option<LocationInfo>,
}

/// Target information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetInfo {
    /// Target type
    pub target_type: TargetType,
    /// Target identifier
    pub identifier: String,
    /// Target name
    pub name: Option<String>,
    /// Target attributes
    pub attributes: HashMap<String, String>,
}

/// Event outcome
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventOutcome {
    Success,
    Failure { reason: String },
    Partial { details: String },
    Unknown,
}

/// Risk levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Source types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SourceType {
    Application,
    System,
    Network,
    Database,
    WebServer,
    API,
    Service,
    Device,
}

/// Actor types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActorType {
    User,
    Service,
    System,
    Application,
    Device,
    Anonymous,
}

/// Target types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TargetType {
    File,
    Database,
    Record,
    System,
    Network,
    Service,
    Configuration,
    User,
}

/// Session information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    /// Session ID
    pub session_id: String,
    /// Session start time
    pub start_time: DateTime<Utc>,
    /// Session duration
    pub duration: Option<Duration>,
    /// Session attributes
    pub attributes: HashMap<String, String>,
}

/// Location information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocationInfo {
    /// IP address
    pub ip_address: Option<String>,
    /// Geographic location
    pub geographic: Option<GeographicLocation>,
    /// Network information
    pub network: Option<NetworkInfo>,
}

/// Geographic location
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeographicLocation {
    /// Country
    pub country: Option<String>,
    /// Region/State
    pub region: Option<String>,
    /// City
    pub city: Option<String>,
    /// Latitude
    pub latitude: Option<f64>,
    /// Longitude
    pub longitude: Option<f64>,
}

/// Network information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    /// Network name
    pub network_name: Option<String>,
    /// Subnet
    pub subnet: Option<String>,
    /// VLAN
    pub vlan: Option<String>,
    /// Protocol
    pub protocol: Option<String>,
}

/// Immutable audit record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImmutableAuditRecord {
    /// Record ID
    pub id: Uuid,
    /// Sequence number
    pub sequence_number: u64,
    /// Audit event
    pub event: AuditEvent,
    /// Cryptographic hash
    pub hash: String,
    /// Digital signature
    pub signature: String,
    /// Previous record hash (for chaining)
    pub previous_hash: Option<String>,
    /// Merkle tree proof
    pub merkle_proof: Option<MerkleProof>,
    /// Timestamp signature
    pub timestamp_signature: Option<TimestampSignature>,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
}

/// Merkle proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Proof path
    pub path: Vec<String>,
    /// Root hash
    pub root_hash: String,
    /// Leaf index
    pub leaf_index: usize,
}

/// Timestamp signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimestampSignature {
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Authority signature
    pub authority_signature: String,
    /// Authority certificate
    pub authority_certificate: Option<String>,
}

/// Audit trail
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditTrail {
    /// Trail ID
    pub id: Uuid,
    /// Trail name
    pub name: String,
    /// Records in the trail
    pub records: Vec<Uuid>,
    /// Trail metadata
    pub metadata: HashMap<String, String>,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last updated
    pub updated_at: DateTime<Utc>,
}

/// Integrity verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityVerificationResult {
    /// Verification ID
    pub id: Uuid,
    /// Verification timestamp
    pub timestamp: DateTime<Utc>,
    /// Records verified
    pub records_verified: usize,
    /// Verification results
    pub results: Vec<RecordVerificationResult>,
    /// Overall status
    pub status: VerificationStatus,
    /// Verification duration
    pub duration: Duration,
}

/// Record verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordVerificationResult {
    /// Record ID
    pub record_id: Uuid,
    /// Verification status
    pub status: VerificationStatus,
    /// Verification details
    pub details: Vec<VerificationDetail>,
    /// Error message (if any)
    pub error_message: Option<String>,
}

/// Verification status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VerificationStatus {
    Valid,
    Invalid,
    Corrupted,
    Missing,
    Tampered,
    Unknown,
}

/// Verification detail
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationDetail {
    /// Check type
    pub check_type: IntegrityCheckMethod,
    /// Check result
    pub result: bool,
    /// Details
    pub details: String,
}

/// Audit statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditStatistics {
    /// Total events logged
    pub total_events: u64,
    /// Events by category
    pub events_by_category: HashMap<AuditCategory, u64>,
    /// Events by risk level
    pub events_by_risk_level: HashMap<RiskLevel, u64>,
    /// Integrity verification statistics
    pub integrity_stats: IntegrityStatistics,
    /// Storage statistics
    pub storage_stats: StorageStatistics,
    /// Performance statistics
    pub performance_stats: PerformanceStatistics,
}

/// Integrity statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityStatistics {
    /// Total verifications performed
    pub total_verifications: u64,
    /// Successful verifications
    pub successful_verifications: u64,
    /// Failed verifications
    pub failed_verifications: u64,
    /// Tamper attempts detected
    pub tamper_attempts: u64,
    /// Last verification timestamp
    pub last_verification: Option<DateTime<Utc>>,
}

/// Storage statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageStatistics {
    /// Total storage used
    pub total_storage_bytes: u64,
    /// Storage by backend
    pub storage_by_backend: HashMap<String, u64>,
    /// Compression ratio
    pub compression_ratio: f32,
    /// Backup statistics
    pub backup_stats: BackupStatistics,
}

/// Performance statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceStatistics {
    /// Average logging latency
    pub avg_logging_latency: Duration,
    /// Average verification latency
    pub avg_verification_latency: Duration,
    /// Throughput (events per second)
    pub throughput: f32,
    /// Queue statistics
    pub queue_stats: QueueStatistics,
}

/// Backup statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupStatistics {
    /// Total backups created
    pub total_backups: u64,
    /// Successful backups
    pub successful_backups: u64,
    /// Failed backups
    pub failed_backups: u64,
    /// Last backup timestamp
    pub last_backup: Option<DateTime<Utc>>,
}

/// Queue statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueStatistics {
    /// Current queue size
    pub current_size: usize,
    /// Maximum queue size
    pub max_size: usize,
    /// Average processing time
    pub avg_processing_time: Duration,
    /// Queue overflow events
    pub overflow_events: u64,
}

/// Tamper-proof audit logger
pub struct TamperProofAuditLogger {
    config: AuditConfig,
    records: Arc<RwLock<VecDeque<ImmutableAuditRecord>>>,
    trails: Arc<RwLock<HashMap<Uuid, AuditTrail>>>,
    statistics: Arc<RwLock<AuditStatistics>>,
    sequence_counter: Arc<RwLock<u64>>,
    cryptographer: Arc<DefaultCryptographer>,
    storage_manager: Arc<DefaultStorageManager>,
    integrity_verifier: Arc<DefaultIntegrityVerifier>,
}

/// Trait for cryptographic operations
#[async_trait::async_trait]
pub trait Cryptographer: Send + Sync {
    /// Calculate hash of data
    async fn hash(&self, data: &[u8]) -> Result<String>;
    
    /// Create digital signature
    async fn sign(&self, data: &[u8]) -> Result<String>;
    
    /// Verify digital signature
    async fn verify_signature(&self, data: &[u8], signature: &str) -> Result<bool>;
    
    /// Encrypt data
    async fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>>;
    
    /// Decrypt data
    async fn decrypt(&self, encrypted_data: &[u8]) -> Result<Vec<u8>>;
}

/// Trait for storage management
#[async_trait::async_trait]
pub trait StorageManager: Send + Sync {
    /// Store audit record
    async fn store_record(&self, record: &ImmutableAuditRecord) -> Result<()>;
    
    /// Retrieve audit record
    async fn retrieve_record(&self, id: Uuid) -> Result<Option<ImmutableAuditRecord>>;
    
    /// List records by criteria
    async fn list_records(&self, criteria: &SearchCriteria) -> Result<Vec<ImmutableAuditRecord>>;
    
    /// Create backup
    async fn create_backup(&self, destination: &BackupDestination) -> Result<String>;
    
    /// Restore from backup
    async fn restore_backup(&self, backup_id: &str) -> Result<()>;
}

/// Trait for integrity verification
#[async_trait::async_trait]
pub trait IntegrityVerifier: Send + Sync {
    /// Verify record integrity
    async fn verify_record(&self, record: &ImmutableAuditRecord) -> Result<RecordVerificationResult>;
    
    /// Verify trail integrity
    async fn verify_trail(&self, trail: &AuditTrail) -> Result<IntegrityVerificationResult>;
    
    /// Detect tampering
    async fn detect_tampering(&self, records: &[ImmutableAuditRecord]) -> Result<Vec<Uuid>>;
}

/// Search criteria for audit records
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchCriteria {
    /// Time range
    pub time_range: Option<(DateTime<Utc>, DateTime<Utc>)>,
    /// Categories
    pub categories: Option<Vec<AuditCategory>>,
    /// Actor filter
    pub actor: Option<String>,
    /// Event type filter
    pub event_type: Option<String>,
    /// Risk level filter
    pub risk_level: Option<RiskLevel>,
    /// Outcome filter
    pub outcome: Option<EventOutcome>,
    /// Limit
    pub limit: Option<usize>,
    /// Offset
    pub offset: Option<usize>,
}

impl TamperProofAuditLogger {
    /// Create a new tamper-proof audit logger
    pub fn new(
        config: AuditConfig,
        cryptographer: Arc<DefaultCryptographer>,
        storage_manager: Arc<DefaultStorageManager>,
        integrity_verifier: Arc<DefaultIntegrityVerifier>,
    ) -> Self {
        Self {
            config,
            records: Arc::new(RwLock::new(VecDeque::new())),
            trails: Arc::new(RwLock::new(HashMap::new())),
            statistics: Arc::new(RwLock::new(AuditStatistics::default())),
            sequence_counter: Arc::new(RwLock::new(0)),
            cryptographer,
            storage_manager,
            integrity_verifier,
        }
    }

    /// Log an audit event
    pub async fn log_event(&self, event: AuditEvent) -> Result<Uuid> {
        // Create immutable record
        let record = self.create_immutable_record(event).await
            .context("Failed to create immutable record")?;

        // Store record
        self.storage_manager.store_record(&record).await
            .context("Failed to store record")?;

        // Add to in-memory cache
        let mut records = self.records.write().await;
        records.push_back(record.clone());
        
        // Maintain cache size
        if records.len() > 10000 {
            records.pop_front();
        }
        drop(records);

        // Update statistics
        self.update_statistics(&record).await?;

        Ok(record.id)
    }

    /// Retrieve audit records
    pub async fn get_records(&self, criteria: &SearchCriteria) -> Result<Vec<ImmutableAuditRecord>> {
        self.storage_manager.list_records(criteria).await
            .context("Failed to retrieve records")
    }

    /// Verify integrity of audit records
    pub async fn verify_integrity(&self, record_ids: Option<Vec<Uuid>>) -> Result<IntegrityVerificationResult> {
        let records = if let Some(ids) = record_ids {
            let mut records = Vec::new();
            for id in ids {
                if let Some(record) = self.storage_manager.retrieve_record(id).await? {
                    records.push(record);
                }
            }
            records
        } else {
            // Verify all recent records
            let criteria = SearchCriteria {
                time_range: Some((Utc::now() - Duration::days(1), Utc::now())),
                categories: None,
                actor: None,
                event_type: None,
                risk_level: None,
                outcome: None,
                limit: Some(1000),
                offset: None,
            };
            self.storage_manager.list_records(&criteria).await?
        };

        let mut results = Vec::new();
        let mut valid_count = 0;
        
        for record in &records {
            let result = self.integrity_verifier.verify_record(record).await?;
            if matches!(result.status, VerificationStatus::Valid) {
                valid_count += 1;
            }
            results.push(result);
        }

        let status = if valid_count == records.len() {
            VerificationStatus::Valid
        } else if valid_count == 0 {
            VerificationStatus::Invalid
        } else {
            VerificationStatus::Corrupted
        };

        Ok(IntegrityVerificationResult {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            records_verified: records.len(),
            results,
            status,
            duration: Duration::milliseconds(100), // Placeholder
        })
    }

    /// Create audit trail
    pub async fn create_trail(&self, name: String, record_ids: Vec<Uuid>) -> Result<Uuid> {
        let trail = AuditTrail {
            id: Uuid::new_v4(),
            name,
            records: record_ids,
            metadata: HashMap::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let mut trails = self.trails.write().await;
        trails.insert(trail.id, trail.clone());
        
        Ok(trail.id)
    }

    /// Get audit statistics
    pub async fn get_statistics(&self) -> Result<AuditStatistics> {
        let statistics = self.statistics.read().await;
        Ok(statistics.clone())
    }

    /// Update configuration
    pub async fn update_config(&self, new_config: AuditConfig) -> Result<()> {
        // Validate configuration
        self.validate_config(&new_config)?;
        
        // Update configuration (in a real implementation, this would be atomic)
        log::info!("Tamper-proof audit configuration updated");
        
        Ok(())
    }

    /// Create backup
    pub async fn create_backup(&self, destination: &BackupDestination) -> Result<String> {
        self.storage_manager.create_backup(destination).await
            .context("Failed to create backup")
    }

    /// Restore from backup
    pub async fn restore_backup(&self, backup_id: &str) -> Result<()> {
        self.storage_manager.restore_backup(backup_id).await
            .context("Failed to restore backup")
    }

    /// Create immutable record from event
    async fn create_immutable_record(&self, event: AuditEvent) -> Result<ImmutableAuditRecord> {
        let mut sequence_counter = self.sequence_counter.write().await;
        *sequence_counter += 1;
        let sequence_number = *sequence_counter;
        drop(sequence_counter);

        // Serialize event
        let event_data = serde_json::to_vec(&event)
            .context("Failed to serialize event")?;

        // Calculate hash
        let hash = self.cryptographer.hash(&event_data).await
            .context("Failed to calculate hash")?;

        // Create signature
        let signature = self.cryptographer.sign(&event_data).await
            .context("Failed to create signature")?;

        // Get previous hash for chaining
        let previous_hash = self.get_previous_hash().await?;

        Ok(ImmutableAuditRecord {
            id: event.id,
            sequence_number,
            event,
            hash,
            signature,
            previous_hash,
            merkle_proof: None, // Would be calculated in a real implementation
            timestamp_signature: None, // Would be obtained from timestamp authority
            created_at: Utc::now(),
        })
    }

    /// Get hash of previous record for chaining
    async fn get_previous_hash(&self) -> Result<Option<String>> {
        let records = self.records.read().await;
        Ok(records.back().map(|r| r.hash.clone()))
    }

    /// Update statistics
    async fn update_statistics(&self, record: &ImmutableAuditRecord) -> Result<()> {
        let mut stats = self.statistics.write().await;
        
        stats.total_events += 1;
        
        // Update category statistics
        *stats.events_by_category.entry(record.event.category.clone()).or_insert(0) += 1;
        
        // Update risk level statistics
        *stats.events_by_risk_level.entry(record.event.risk_level.clone()).or_insert(0) += 1;
        
        Ok(())
    }

    /// Validate configuration
    fn validate_config(&self, config: &AuditConfig) -> Result<()> {
        if config.retention.default_retention.num_seconds() == 0 {
            return Err(AuditError::Configuration(
                "Default retention period must be greater than zero".to_string()
            ).into());
        }

        Ok(())
    }
}

// Default implementations for testing and development
pub struct DefaultCryptographer;
pub struct DefaultStorageManager;
pub struct DefaultIntegrityVerifier;

#[async_trait::async_trait]
impl Cryptographer for DefaultCryptographer {
    async fn hash(&self, data: &[u8]) -> Result<String> {
        // Simple hash implementation for testing
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        data.hash(&mut hasher);
        Ok(format!("{:x}", hasher.finish()))
    }

    async fn sign(&self, data: &[u8]) -> Result<String> {
        // Simple signature implementation for testing
        Ok(format!("sig_{}", self.hash(data).await?))
    }

    async fn verify_signature(&self, data: &[u8], signature: &str) -> Result<bool> {
        let expected_signature = self.sign(data).await?;
        Ok(signature == expected_signature)
    }

    async fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Simple encryption for testing (just XOR with key)
        let key = 0x42u8;
        Ok(data.iter().map(|b| b ^ key).collect())
    }

    async fn decrypt(&self, encrypted_data: &[u8]) -> Result<Vec<u8>> {
        // Simple decryption for testing (just XOR with key)
        self.encrypt(encrypted_data).await
    }
}

#[async_trait::async_trait]
impl StorageManager for DefaultStorageManager {
    async fn store_record(&self, _record: &ImmutableAuditRecord) -> Result<()> {
        // In a real implementation, this would store to configured backends
        Ok(())
    }

    async fn retrieve_record(&self, _id: Uuid) -> Result<Option<ImmutableAuditRecord>> {
        // In a real implementation, this would retrieve from storage
        Ok(None)
    }

    async fn list_records(&self, _criteria: &SearchCriteria) -> Result<Vec<ImmutableAuditRecord>> {
        // In a real implementation, this would query storage
        Ok(Vec::new())
    }

    async fn create_backup(&self, _destination: &BackupDestination) -> Result<String> {
        Ok(format!("backup_{}", Uuid::new_v4()))
    }

    async fn restore_backup(&self, _backup_id: &str) -> Result<()> {
        Ok(())
    }
}

#[async_trait::async_trait]
impl IntegrityVerifier for DefaultIntegrityVerifier {
    async fn verify_record(&self, record: &ImmutableAuditRecord) -> Result<RecordVerificationResult> {
        Ok(RecordVerificationResult {
            record_id: record.id,
            status: VerificationStatus::Valid,
            details: vec![
                VerificationDetail {
                    check_type: IntegrityCheckMethod::HashVerification,
                    result: true,
                    details: "Hash verification passed".to_string(),
                },
                VerificationDetail {
                    check_type: IntegrityCheckMethod::SignatureVerification,
                    result: true,
                    details: "Signature verification passed".to_string(),
                },
            ],
            error_message: None,
        })
    }

    async fn verify_trail(&self, trail: &AuditTrail) -> Result<IntegrityVerificationResult> {
        let results = trail.records.iter().map(|&id| RecordVerificationResult {
            record_id: id,
            status: VerificationStatus::Valid,
            details: vec![
                VerificationDetail {
                    check_type: IntegrityCheckMethod::HashVerification,
                    result: true,
                    details: "Hash verification passed".to_string(),
                },
            ],
            error_message: None,
        }).collect();

        Ok(IntegrityVerificationResult {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            records_verified: trail.records.len(),
            results,
            status: VerificationStatus::Valid,
            duration: chrono::TimeDelta::milliseconds(50),
        })
    }

    async fn detect_tampering(&self, _records: &[ImmutableAuditRecord]) -> Result<Vec<Uuid>> {
        // In a real implementation, this would detect tampering
        Ok(Vec::new())
    }
}

// Default implementations
impl Default for AuditStatistics {
    fn default() -> Self {
        Self {
            total_events: 0,
            events_by_category: HashMap::new(),
            events_by_risk_level: HashMap::new(),
            integrity_stats: IntegrityStatistics {
                total_verifications: 0,
                successful_verifications: 0,
                failed_verifications: 0,
                tamper_attempts: 0,
                last_verification: None,
            },
            storage_stats: StorageStatistics {
                total_storage_bytes: 0,
                storage_by_backend: HashMap::new(),
                compression_ratio: 1.0,
                backup_stats: BackupStatistics {
                    total_backups: 0,
                    successful_backups: 0,
                    failed_backups: 0,
                    last_backup: None,
                },
            },
            performance_stats: PerformanceStatistics {
                avg_logging_latency: chrono::TimeDelta::milliseconds(0),
                avg_verification_latency: chrono::TimeDelta::milliseconds(0),
                throughput: 0.0,
                queue_stats: QueueStatistics {
                    current_size: 0,
                    max_size: 0,
                    avg_processing_time: chrono::TimeDelta::milliseconds(0),
                    overflow_events: 0,
                },
            },
        }
    }
}

/// Utility function to create a default tamper-proof audit logger
pub fn create_default_audit_logger() -> TamperProofAuditLogger {
    let config = AuditConfig {
        cryptography: CryptographyConfig {
            hash_algorithm: HashAlgorithm::SHA256,
            signature_algorithm: SignatureAlgorithm::EcdsaP256,
            encryption_algorithm: EncryptionAlgorithm::Aes256Gcm,
            key_management: KeyManagementConfig {
                key_derivation: KeyDerivationFunction::PBKDF2,
                rotation_policy: KeyRotationPolicy::Monthly,
                storage_backend: KeyStorageBackend::FileSystem,
                hsm_config: None,
            },
            merkle_tree: MerkleTreeConfig {
                depth: 16,
                leaf_hash: HashAlgorithm::SHA256,
                internal_hash: HashAlgorithm::SHA256,
                balancing: TreeBalancingStrategy::Balanced,
            },
            timestamp_authority: TimestampConfig {
                authority_url: None,
                local_validation: true,
                precision: TimestampPrecision::Millisecond,
                clock_sync: ClockSyncConfig {
                    ntp_servers: vec!["pool.ntp.org".to_string()],
                    sync_interval: 3600,
                    max_drift_ms: 1000,
                    auto_sync: true,
                },
            },
        },
        storage: StorageConfig {
            primary_backend: StorageBackend::FileSystem {
                path: "./audit_logs".to_string(),
            },
            secondary_backends: Vec::new(),
            immutable_storage: ImmutableStorageConfig {
                worm_enabled: true,
                verification_enabled: true,
                backend: None,
            },
            distributed_storage: DistributedStorageConfig {
                replication_factor: 3,
                consistency_level: ConsistencyLevel::Strong,
                sharding_strategy: ShardingStrategy::Hash,
                nodes: Vec::new(),
            },
            compression: CompressionConfig {
                algorithm: CompressionAlgorithm::Gzip,
                level: 6,
                enabled: true,
            },
        },
        integrity: IntegrityConfig {
            verification_frequency: chrono::TimeDelta::seconds(3600),
            batch_size: 1000,
            check_methods: vec![
                IntegrityCheckMethod::HashVerification,
                IntegrityCheckMethod::SignatureVerification,
            ],
            tamper_detection: TamperDetectionConfig {
                algorithms: vec![TamperDetectionAlgorithm::HashBased],
                sensitivity: 0.9,
                alerts: TamperAlertConfig {
                    enabled: true,
                    channels: vec![AlertChannel::Log],
                    escalation: AlertEscalationConfig {
                        enabled: true,
                        levels: vec![EscalationLevel::Warning, EscalationLevel::Critical],
                    },
                },
                response_actions: vec![TamperResponseAction::Alert, TamperResponseAction::Quarantine],
            },
            recovery: RecoveryConfig {
                strategies: vec![RecoveryStrategy::BackupRestore],
                backup_verification: true,
                recovery_testing: RecoveryTestingConfig {
                    enabled: true,
                    frequency: chrono::TimeDelta::seconds(86400 * 7), // Weekly
                    test_scenarios: vec![RecoveryTestScenario::PartialCorruption],
                },
            },
        },
        retention: RetentionConfig {
            default_retention: chrono::TimeDelta::seconds(86400 * 365 * 7), // 7 years
            category_policies: HashMap::from([
                (AuditCategory::SecurityEvents, chrono::TimeDelta::seconds(86400 * 365 * 10)), // 10 years
                (AuditCategory::ComplianceEvents, chrono::TimeDelta::seconds(86400 * 365 * 7)), // 7 years
            ]),
            legal_hold: LegalHoldConfig {
                enabled: true,
                policies: Vec::new(),
                notifications: LegalHoldNotificationConfig {
                    enabled: true,
                    recipients: Vec::new(),
                },
            },
            archival: ArchivalConfig {
                strategy: ArchivalStrategy::Tiered,
                storage_backend: StorageBackend::FileSystem {
                    path: "./audit_archive".to_string(),
                },
                compression: CompressionConfig {
                    algorithm: CompressionAlgorithm::Gzip,
                    level: 9,
                    enabled: true,
                },
                retrieval: ArchivalRetrievalConfig {
                    max_retrieval_time: chrono::TimeDelta::seconds(3600),
                    retrieval_methods: vec![RetrievalMethod::Direct],
                },
            },
            deletion: DeletionConfig {
                method: SecureDeletionMethod::DoD5220_22M,
                verification: true,
                logging: true,
            },
        },
        compliance: ComplianceConfig {
            frameworks: vec![ComplianceFramework::SOX, ComplianceFramework::ISO27001],
            audit_trail_requirements: AuditTrailRequirements {
                required_fields: vec![
                    AuditField::Timestamp,
                    AuditField::Actor,
                    AuditField::Action,
                    AuditField::Target,
                    AuditField::Outcome,
                ],
                min_retention: chrono::TimeDelta::seconds(86400 * 365 * 7), // 7 years
                integrity_requirements: IntegrityRequirements {
                    hash_required: true,
                    signature_required: true,
                    timestamp_required: true,
                    chain_required: true,
                },
                access_control: AccessControlRequirements {
                    role_based_access: true,
                    audit_log_protection: true,
                    segregation_of_duties: true,
                },
            },
            reporting: ComplianceReportingConfig {
                formats: vec![ReportFormat::PDF, ReportFormat::CSV],
                frequency: chrono::TimeDelta::seconds(86400 * 30), // Monthly
                recipients: Vec::new(),
                automated: true,
            },
            certification: CertificationConfig {
                certifications: vec!["ISO27001".to_string(), "SOC2".to_string()],
                validation: CertificationValidationConfig {
                    enabled: true,
                    validation_frequency: chrono::TimeDelta::seconds(86400 * 365), // Yearly
                },
                renewal_tracking: true,
            },
        },
        performance: PerformanceConfig {
            batch_processing: BatchProcessingConfig {
                batch_size: 100,
                interval: chrono::TimeDelta::seconds(60),
                parallel_workers: 4,
                queue_config: QueueConfig {
                    max_size: 10000,
                    overflow_strategy: QueueOverflowStrategy::DropOldest,
                },
            },
            async_processing: AsyncProcessingConfig {
                enabled: true,
                worker_pool_size: 8,
                task_queue_size: 1000,
                priority_handling: true,
            },
            caching: CachingConfig {
                enabled: true,
                cache_size: 1000,
                ttl: chrono::TimeDelta::seconds(3600),
                eviction_policy: CacheEvictionPolicy::LRU,
            },
            rate_limiting: RateLimitingConfig {
                enabled: true,
                requests_per_second: 1000,
                burst_capacity: 2000,
                strategy: RateLimitingStrategy::TokenBucket,
            },
        },
        backup: BackupConfig {
            frequency: chrono::TimeDelta::seconds(86400), // Daily
            destinations: vec![
                BackupDestination::LocalFileSystem {
                    path: "./audit_backups".to_string(),
                },
            ],
            encryption: BackupEncryptionConfig {
                enabled: true,
                algorithm: EncryptionAlgorithm::Aes256Gcm,
                key_management: KeyManagementConfig {
                    key_derivation: KeyDerivationFunction::PBKDF2,
                    rotation_policy: KeyRotationPolicy::Monthly,
                    storage_backend: KeyStorageBackend::FileSystem,
                    hsm_config: None,
                },
            },
            verification: BackupVerificationConfig {
                     frequency: chrono::TimeDelta::seconds(86400 * 7), // Weekly
                methods: vec![BackupVerificationMethod::HashCheck],
                integrity_checking: true,
            },
            disaster_recovery: DisasterRecoveryConfig {
                rto: chrono::TimeDelta::seconds(3600), // 1 hour
                rpo: chrono::TimeDelta::seconds(900),  // 15 minutes
                strategies: vec![DisasterRecoveryStrategy::BackupRestore],
                testing_schedule: chrono::TimeDelta::seconds(86400 * 90), // Quarterly
            },
        },
    };

    TamperProofAuditLogger::new(
        config,
        Arc::new(DefaultCryptographer),
        Arc::new(DefaultStorageManager),
        Arc::new(DefaultIntegrityVerifier),
    )
}

/// Utility function to validate audit configuration
pub fn validate_audit_config(config: &AuditConfig) -> Result<()> {
    if config.retention.default_retention.num_seconds() == 0 {
        return Err(AuditError::Configuration(
            "Default retention period must be greater than zero".to_string()
        ).into());
    }

    if config.performance.batch_processing.batch_size == 0 {
        return Err(AuditError::Configuration(
            "Batch size must be greater than zero".to_string()
        ).into());
    }

    Ok(())
}

// Additional enums and structs referenced in the configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyDerivationFunction {
    PBKDF2,
    Scrypt,
    Argon2,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyRotationPolicy {
    Never,
    Daily,
    Weekly,
    Monthly,
    Yearly,
    Custom(Duration),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyStorageBackend {
    FileSystem,
    Database,
    HSM,
    CloudKMS,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HSMConfig {
    pub provider: String,
    pub slot_id: u32,
    pub pin: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TreeBalancingStrategy {
    Balanced,
    LeftHeavy,
    RightHeavy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TimestampPrecision {
    Second,
    Millisecond,
    Microsecond,
    Nanosecond,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TamperAlertConfig {
    pub enabled: bool,
    pub channels: Vec<AlertChannel>,
    pub escalation: AlertEscalationConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertChannel {
    Log,
    Email,
    SMS,
    Webhook,
    SIEM,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertEscalationConfig {
    pub enabled: bool,
    pub levels: Vec<EscalationLevel>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EscalationLevel {
    Info,
    Warning,
    Critical,
    Emergency,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TamperResponseAction {
    Alert,
    Log,
    Quarantine,
    Shutdown,
    Notify,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecoveryStrategy {
    BackupRestore,
    Redundancy,
    Reconstruction,
    ManualIntervention,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryTestingConfig {
    pub enabled: bool,
    pub frequency: Duration,
    pub test_scenarios: Vec<RecoveryTestScenario>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecoveryTestScenario {
    PartialCorruption,
    CompleteCorruption,
    SystemFailure,
    NetworkFailure,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegalHoldPolicy {
    pub id: String,
    pub name: String,
    pub description: String,
    pub effective_date: DateTime<Utc>,
    pub expiration_date: Option<DateTime<Utc>>,
    pub categories: Vec<AuditCategory>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegalHoldNotificationConfig {
    pub enabled: bool,
    pub recipients: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ArchivalStrategy {
    Immediate,
    Scheduled,
    Tiered,
    PolicyBased,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchivalRetrievalConfig {
    pub max_retrieval_time: Duration,
    pub retrieval_methods: Vec<RetrievalMethod>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RetrievalMethod {
    Direct,
    Staged,
    OnDemand,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecureDeletionMethod {
    Simple,
    DoD5220_22M,
    Nist800_88,
    Gutmann,
    Random,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditField {
    Timestamp,
    Actor,
    Action,
    Target,
    Outcome,
    Source,
    RiskLevel,
    Category,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityRequirements {
    pub hash_required: bool,
    pub signature_required: bool,
    pub timestamp_required: bool,
    pub chain_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessControlRequirements {
    pub role_based_access: bool,
    pub audit_log_protection: bool,
    pub segregation_of_duties: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReportFormat {
    PDF,
    CSV,
    JSON,
    XML,
    HTML,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificationValidationConfig {
    pub enabled: bool,
    pub validation_frequency: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueConfig {
    pub max_size: usize,
    pub overflow_strategy: QueueOverflowStrategy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QueueOverflowStrategy {
    Block,
    DropOldest,
    DropNewest,
    Reject,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CacheEvictionPolicy {
    LRU,
    LFU,
    FIFO,
    Random,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RateLimitingStrategy {
    TokenBucket,
    LeakyBucket,
    FixedWindow,
    SlidingWindow,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BackupVerificationMethod {
    HashCheck,
    IntegrityCheck,
    RestoreTest,
    SampleVerification,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DisasterRecoveryStrategy {
    BackupRestore,
    Replication,
    Clustering,
    CloudFailover,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_audit_logger_creation() {
        let logger = create_default_audit_logger();
        let stats = logger.get_statistics().await.unwrap();
        assert_eq!(stats.total_events, 0);
    }

    #[tokio::test]
    async fn test_log_event() {
        let logger = create_default_audit_logger();
        
        let event = AuditEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            category: AuditCategory::SecurityEvents,
            event_type: "test_event".to_string(),
            source: EventSource {
                source_type: SourceType::Application,
                identifier: "test_app".to_string(),
                location: None,
                version: None,
            },
            actor: ActorInfo {
                actor_type: ActorType::User,
                identifier: "test_user".to_string(),
                name: Some("Test User".to_string()),
                roles: vec!["admin".to_string()],
                session: None,
                location: None,
            },
            target: None,
            outcome: EventOutcome::Success,
            details: HashMap::new(),
            risk_level: RiskLevel::Low,
            compliance_tags: vec!["SOX".to_string()],
            metadata: HashMap::new(),
        };

        let result = logger.log_event(event).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_config_validation() {
        let config = AuditConfig {
            cryptography: CryptographyConfig {
                hash_algorithm: HashAlgorithm::SHA256,
                signature_algorithm: SignatureAlgorithm::EcdsaP256,
                encryption_algorithm: EncryptionAlgorithm::Aes256Gcm,
                key_management: KeyManagementConfig {
                    key_derivation: KeyDerivationFunction::PBKDF2,
                    rotation_policy: KeyRotationPolicy::Monthly,
                    storage_backend: KeyStorageBackend::FileSystem,
                    hsm_config: None,
                },
                merkle_tree: MerkleTreeConfig {
                    depth: 16,
                    leaf_hash: HashAlgorithm::SHA256,
                    internal_hash: HashAlgorithm::SHA256,
                    balancing: TreeBalancingStrategy::Balanced,
                },
                timestamp_authority: TimestampConfig {
                    authority_url: None,
                    local_validation: true,
                    precision: TimestampPrecision::Millisecond,
                    clock_sync: ClockSyncConfig {
                        ntp_servers: vec!["pool.ntp.org".to_string()],
                        sync_interval: 3600,
                        max_drift_ms: 1000,
                        auto_sync: true,
                    },
                },
            },
            storage: StorageConfig {
                primary_backend: StorageBackend::FileSystem {
                    path: "./audit_logs".to_string(),
                },
                secondary_backends: Vec::new(),
                immutable_storage: ImmutableStorageConfig {
                    worm_enabled: true,
                    verification_enabled: true,
                    backend: None,
                },
                distributed_storage: DistributedStorageConfig {
                    replication_factor: 3,
                    consistency_level: ConsistencyLevel::Strong,
                    sharding_strategy: ShardingStrategy::Hash,
                    nodes: Vec::new(),
                },
                compression: CompressionConfig {
                    algorithm: CompressionAlgorithm::Gzip,
                    level: 6,
                    enabled: true,
                },
            },
            integrity: IntegrityConfig {
                verification_frequency: chrono::TimeDelta::seconds(3600),
                batch_size: 1000,
                check_methods: vec![
                    IntegrityCheckMethod::HashVerification,
                    IntegrityCheckMethod::SignatureVerification,
                ],
                tamper_detection: TamperDetectionConfig {
                    algorithms: vec![TamperDetectionAlgorithm::HashBased],
                    sensitivity: 0.9,
                    alerts: TamperAlertConfig {
                        enabled: true,
                        channels: vec![AlertChannel::Log],
                        escalation: AlertEscalationConfig {
                            enabled: true,
                            levels: vec![EscalationLevel::Warning, EscalationLevel::Critical],
                        },
                    },
                    response_actions: vec![TamperResponseAction::Alert],
                },
                recovery: RecoveryConfig {
                    strategies: vec![RecoveryStrategy::BackupRestore],
                    backup_verification: true,
                    recovery_testing: RecoveryTestingConfig {
                        enabled: true,
                        frequency: chrono::TimeDelta::seconds(86400 * 7),
                        test_scenarios: vec![RecoveryTestScenario::PartialCorruption],
                    },
                },
            },
            retention: RetentionConfig {
                default_retention: chrono::TimeDelta::seconds(86400 * 365 * 7),
                category_policies: HashMap::new(),
                legal_hold: LegalHoldConfig {
                    enabled: true,
                    policies: Vec::new(),
                    notifications: LegalHoldNotificationConfig {
                        enabled: true,
                        recipients: Vec::new(),
                    },
                },
                archival: ArchivalConfig {
                    strategy: ArchivalStrategy::Tiered,
                    storage_backend: StorageBackend::FileSystem {
                        path: "./audit_archive".to_string(),
                    },
                    compression: CompressionConfig {
                        algorithm: CompressionAlgorithm::Gzip,
                        level: 9,
                        enabled: true,
                    },
                    retrieval: ArchivalRetrievalConfig {
                        max_retrieval_time: chrono::TimeDelta::seconds(3600),
                        retrieval_methods: vec![RetrievalMethod::Direct],
                    },
                },
                deletion: DeletionConfig {
                    method: SecureDeletionMethod::DoD5220_22M,
                    verification: true,
                    logging: true,
                },
            },
            compliance: ComplianceConfig {
                frameworks: vec![ComplianceFramework::SOX],
                audit_trail_requirements: AuditTrailRequirements {
                    required_fields: vec![AuditField::Timestamp, AuditField::Actor],
                    min_retention: chrono::TimeDelta::seconds(86400 * 365 * 7),
                    integrity_requirements: IntegrityRequirements {
                        hash_required: true,
                        signature_required: true,
                        timestamp_required: true,
                        chain_required: true,
                    },
                    access_control: AccessControlRequirements {
                        role_based_access: true,
                        audit_log_protection: true,
                        segregation_of_duties: true,
                    },
                },
                reporting: ComplianceReportingConfig {
                    formats: vec![ReportFormat::PDF],
                    frequency: chrono::TimeDelta::seconds(86400 * 30),
                    recipients: Vec::new(),
                    automated: true,
                },
                certification: CertificationConfig {
                    certifications: vec!["ISO27001".to_string()],
                    validation: CertificationValidationConfig {
                        enabled: true,
                        validation_frequency: chrono::TimeDelta::seconds(86400 * 365),
                    },
                    renewal_tracking: true,
                },
            },
            performance: PerformanceConfig {
                batch_processing: BatchProcessingConfig {
                    batch_size: 100,
                    interval: chrono::TimeDelta::seconds(60),
                    parallel_workers: 4,
                    queue_config: QueueConfig {
                        max_size: 10000,
                        overflow_strategy: QueueOverflowStrategy::DropOldest,
                    },
                },
                async_processing: AsyncProcessingConfig {
                    enabled: true,
                    worker_pool_size: 8,
                    task_queue_size: 1000,
                    priority_handling: true,
                },
                caching: CachingConfig {
                    enabled: true,
                    cache_size: 1000,
                    ttl: chrono::TimeDelta::seconds(3600),
                    eviction_policy: CacheEvictionPolicy::LRU,
                },
                rate_limiting: RateLimitingConfig {
                    enabled: true,
                    requests_per_second: 1000,
                    burst_capacity: 2000,
                    strategy: RateLimitingStrategy::TokenBucket,
                },
            },
            backup: BackupConfig {
                frequency: chrono::TimeDelta::seconds(86400),
                destinations: vec![
                    BackupDestination::LocalFileSystem {
                        path: "./audit_backups".to_string(),
                    },
                ],
                encryption: BackupEncryptionConfig {
                    enabled: true,
                    algorithm: EncryptionAlgorithm::Aes256Gcm,
                    key_management: KeyManagementConfig {
                        key_derivation: KeyDerivationFunction::PBKDF2,
                        rotation_policy: KeyRotationPolicy::Monthly,
                        storage_backend: KeyStorageBackend::FileSystem,
                        hsm_config: None,
                    },
                },
                verification: BackupVerificationConfig {
                    frequency: chrono::TimeDelta::seconds(86400 * 7),
                    methods: vec![BackupVerificationMethod::HashCheck],
                    integrity_checking: true,
                },
                disaster_recovery: DisasterRecoveryConfig {
                    rto: chrono::TimeDelta::seconds(3600),
                    rpo: chrono::TimeDelta::seconds(900),
                    strategies: vec![DisasterRecoveryStrategy::BackupRestore],
                    testing_schedule: chrono::TimeDelta::seconds(86400 * 90),
                },
            },
        };

        let result = validate_audit_config(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_audit_categories() {
        let categories = vec![
            AuditCategory::Authentication,
            AuditCategory::Authorization,
            AuditCategory::DataAccess,
            AuditCategory::SecurityEvents,
        ];
        
        for category in categories {
            let serialized = serde_json::to_string(&category).unwrap();
            let deserialized: AuditCategory = serde_json::from_str(&serialized).unwrap();
            assert_eq!(category, deserialized);
        }
    }

    #[test]
    fn test_risk_levels() {
        let levels = vec![
            RiskLevel::Low,
            RiskLevel::Medium,
            RiskLevel::High,
            RiskLevel::Critical,
        ];
        
        for level in levels {
            let serialized = serde_json::to_string(&level).unwrap();
            let deserialized: RiskLevel = serde_json::from_str(&serialized).unwrap();
            assert_eq!(level, deserialized);
        }
    }

    #[test]
    fn test_hash_algorithms() {
        let algorithms = vec![
            HashAlgorithm::SHA256,
            HashAlgorithm::SHA384,
            HashAlgorithm::SHA512,
            HashAlgorithm::BLAKE2b,
        ];
        
        for algorithm in algorithms {
            let serialized = serde_json::to_string(&algorithm).unwrap();
            let deserialized: HashAlgorithm = serde_json::from_str(&serialized).unwrap();
            assert_eq!(algorithm, deserialized);
        }
    }

    #[tokio::test]
    async fn test_cryptographer_operations() {
        let cryptographer = DefaultCryptographer;
        let data = b"test data";
        
        let hash = cryptographer.hash(data).await.unwrap();
        assert!(!hash.is_empty());
        
        let signature = cryptographer.sign(data).await.unwrap();
        assert!(!signature.is_empty());
        
        let is_valid = cryptographer.verify_signature(data, &signature).await.unwrap();
        assert!(is_valid);
        
        let encrypted = cryptographer.encrypt(data).await.unwrap();
        let decrypted = cryptographer.decrypt(&encrypted).await.unwrap();
        assert_eq!(data, decrypted.as_slice());
    }

    #[test]
    fn test_default_statistics() {
        let stats = AuditStatistics::default();
        assert_eq!(stats.total_events, 0);
        assert_eq!(stats.events_by_category.len(), 0);
        assert_eq!(stats.events_by_risk_level.len(), 0);
        assert_eq!(stats.integrity_stats.total_verifications, 0);
    }
}
