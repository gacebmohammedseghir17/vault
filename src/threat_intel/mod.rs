//! Threat Intelligence Module for Enhanced ERDPS Agent
//!
//! This module provides comprehensive threat intelligence capabilities including:
//! - Multi-source threat feed integration
//! - IOC (Indicators of Compromise) processing and matching
//! - Threat attribution and campaign tracking
//! - Real-time threat intelligence updates
//! - Threat scoring and risk assessment
//! - Intelligence sharing and collaboration

use crate::error::AgentResult;
use crate::core::types::*;
use async_trait::async_trait;
use std::collections::HashMap;
use std::time::SystemTime;
use serde::{Serialize, Deserialize};
use uuid::Uuid;

pub mod feeds;
pub mod ioc;
pub mod attribution;
pub mod scoring;
pub mod sharing;
pub mod enrichment;

/// Main threat intelligence engine trait
#[async_trait]
pub trait ThreatIntelligenceEngine: Send + Sync {
    /// Initialize the threat intelligence engine
    async fn initialize(&self) -> AgentResult<()>;
    
    /// Start threat intelligence collection and processing
    async fn start(&self) -> AgentResult<()>;
    
    /// Stop threat intelligence operations
    async fn stop(&self) -> AgentResult<()>;
    
    /// Query threat intelligence for IOCs
    async fn query_ioc(&self, ioc: &str, ioc_type: IocType) -> AgentResult<Vec<ThreatIntelMatch>>;
    
    /// Bulk query multiple IOCs
    async fn bulk_query_iocs(&self, iocs: &[(String, IocType)]) -> AgentResult<HashMap<String, Vec<ThreatIntelMatch>>>;
    
    /// Submit new IOC for intelligence processing
    async fn submit_ioc(&self, ioc: &str, ioc_type: IocType, context: Option<ThreatContext>) -> AgentResult<()>;
    
    /// Get threat score for an entity
    async fn get_threat_score(&self, entity: &str, entity_type: EntityType) -> AgentResult<ThreatScore>;
    
    /// Update threat intelligence feeds
    async fn update_feeds(&self) -> AgentResult<FeedUpdateResult>;
    
    /// Get threat intelligence statistics
    async fn get_statistics(&self) -> AgentResult<ThreatIntelStatistics>;
    
    /// Search for threats by campaign or actor
    async fn search_threats(&self, query: &ThreatQuery) -> AgentResult<Vec<ThreatIntelligence>>;
    
    /// Get threat attribution information
    async fn get_attribution(&self, ioc: &str) -> AgentResult<Option<ThreatAttribution>>;
    
    /// Enrich threat data with additional context
    async fn enrich_threat(&self, threat_id: &ThreatId) -> AgentResult<EnrichedThreat>;
}

/// IOC (Indicator of Compromise) types
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IocType {
    FileHash,
    IpAddress,
    Domain,
    Url,
    Email,
    Registry,
    Mutex,
    Certificate,
    UserAgent,
    ProcessName,
    FilePath,
    NetworkSignature,
    Yara,
    Custom(String),
}

/// Entity types for threat scoring
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum EntityType {
    File,
    Process,
    Network,
    Registry,
    User,
    System,
}

/// Threat intelligence match result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelMatch {
    pub match_id: Uuid,
    pub ioc: String,
    pub ioc_type: IocType,
    pub threat_id: ThreatId,
    pub threat_name: String,
    pub threat_type: ThreatType,
    pub confidence: f64,
    pub severity: ThreatSeverity,
    pub first_seen: SystemTime,
    pub last_seen: SystemTime,
    pub source: String,
    pub tags: Vec<String>,
    pub context: Option<ThreatContext>,
    pub attribution: Option<ThreatAttribution>,
    pub related_iocs: Vec<String>,
}

/// Threat types
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThreatType {
    Malware,
    Ransomware,
    Trojan,
    Backdoor,
    Rootkit,
    Spyware,
    Adware,
    Worm,
    Virus,
    Botnet,
    C2,
    Phishing,
    Scam,
    Exploit,
    Vulnerability,
    Apt,
    Campaign,
    Unknown,
}

/// Threat severity levels
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ThreatSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Threat context information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatContext {
    pub campaign: Option<String>,
    pub actor: Option<String>,
    pub family: Option<String>,
    pub variant: Option<String>,
    pub target_sectors: Vec<String>,
    pub target_countries: Vec<String>,
    pub attack_vectors: Vec<String>,
    pub techniques: Vec<String>, // MITRE ATT&CK techniques
    pub tactics: Vec<String>,    // MITRE ATT&CK tactics
    pub kill_chain_phases: Vec<String>,
    pub metadata: HashMap<String, String>,
}

/// Threat attribution information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatAttribution {
    pub actor_id: Option<String>,
    pub actor_name: Option<String>,
    pub actor_aliases: Vec<String>,
    pub actor_type: ActorType,
    pub motivation: Vec<String>,
    pub sophistication: SophisticationLevel,
    pub origin_country: Option<String>,
    pub active_since: Option<SystemTime>,
    pub last_activity: Option<SystemTime>,
    pub confidence: f64,
    pub sources: Vec<String>,
}

/// Threat actor types
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ActorType {
    NationState,
    Cybercriminal,
    Hacktivist,
    Insider,
    ScriptKiddie,
    Unknown,
}

/// Sophistication levels
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SophisticationLevel {
    Minimal,
    Intermediate,
    Advanced,
    Expert,
    Innovator,
}

/// Threat score information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatScore {
    pub entity: String,
    pub entity_type: EntityType,
    pub score: f64, // 0.0 to 100.0
    pub confidence: f64, // 0.0 to 1.0
    pub risk_level: RiskLevel,
    pub contributing_factors: Vec<ScoreFactor>,
    pub last_updated: SystemTime,
    pub ttl: Option<SystemTime>,
}

/// Risk levels
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RiskLevel {
    Minimal,
    Low,
    Medium,
    High,
    Critical,
}

/// Score contributing factors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreFactor {
    pub factor_type: String,
    pub weight: f64,
    pub value: f64,
    pub description: String,
}

/// Feed update result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedUpdateResult {
    pub total_feeds: u32,
    pub successful_updates: u32,
    pub failed_updates: u32,
    pub new_iocs: u64,
    pub updated_iocs: u64,
    pub removed_iocs: u64,
    pub update_duration: std::time::Duration,
    pub errors: Vec<String>,
}

/// Threat intelligence statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ThreatIntelStatistics {
    pub total_iocs: u64,
    pub active_feeds: u32,
    pub total_queries: u64,
    pub successful_queries: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub average_query_time: std::time::Duration,
    pub last_feed_update: Option<SystemTime>,
    pub ioc_breakdown: HashMap<IocType, u64>,
    pub threat_breakdown: HashMap<ThreatType, u64>,
    pub severity_breakdown: HashMap<ThreatSeverity, u64>,
}

/// Threat query parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatQuery {
    pub query_type: ThreatQueryType,
    pub value: String,
    pub filters: HashMap<String, String>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
    pub sort_by: Option<String>,
    pub sort_order: Option<SortOrder>,
}

/// Threat query types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ThreatQueryType {
    Campaign,
    Actor,
    Family,
    Technique,
    Tactic,
    Sector,
    Country,
    Keyword,
}

/// Sort order
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SortOrder {
    Ascending,
    Descending,
}

/// Threat intelligence information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelligence {
    pub threat_id: ThreatId,
    pub name: String,
    pub description: String,
    pub threat_type: ThreatType,
    pub severity: ThreatSeverity,
    pub confidence: f64,
    pub first_seen: SystemTime,
    pub last_seen: SystemTime,
    pub iocs: Vec<String>,
    pub context: ThreatContext,
    pub attribution: Option<ThreatAttribution>,
    pub references: Vec<String>,
    pub tags: Vec<String>,
    pub source: String,
    pub ttps: Vec<String>,
}

impl Default for ThreatIntelligence {
    fn default() -> Self {
        Self {
            threat_id: Uuid::new_v4(),
            name: String::new(),
            description: String::new(),
            threat_type: ThreatType::Unknown,
            severity: ThreatSeverity::Info,
            confidence: 0.0,
            first_seen: SystemTime::now(),
            last_seen: SystemTime::now(),
            iocs: Vec::new(),
            context: ThreatContext::default(),
            attribution: None,
            references: Vec::new(),
            tags: Vec::new(),
            source: String::new(),
            ttps: Vec::new(),
        }
    }
}

/// Enriched threat information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichedThreat {
    pub base_threat: ThreatIntelligence,
    pub enrichment_data: HashMap<String, serde_json::Value>,
    pub related_threats: Vec<ThreatId>,
    pub timeline: Vec<ThreatEvent>,
    pub geolocation: Option<GeolocationInfo>,
    pub network_info: Option<NetworkInfo>,
    pub file_info: Option<FileInfo>,
    pub behavioral_patterns: Vec<BehavioralPattern>,
    pub enrichment_sources: Vec<String>,
    pub enrichment_timestamp: SystemTime,
}

/// Threat event for timeline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatEvent {
    pub event_id: Uuid,
    pub event_type: String,
    pub timestamp: SystemTime,
    pub description: String,
    pub source: String,
    pub confidence: f64,
    pub metadata: HashMap<String, String>,
}

/// Geolocation information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeolocationInfo {
    pub country: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub asn: Option<u32>,
    pub organization: Option<String>,
    pub isp: Option<String>,
}

/// Network information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    pub ip_addresses: Vec<String>,
    pub domains: Vec<String>,
    pub urls: Vec<String>,
    pub ports: Vec<u16>,
    pub protocols: Vec<String>,
    pub certificates: Vec<String>,
    pub dns_records: HashMap<String, Vec<String>>,
}

/// File information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    pub hashes: HashMap<String, String>, // hash_type -> hash_value
    pub file_size: Option<u64>,
    pub file_type: Option<String>,
    pub mime_type: Option<String>,
    pub pe_info: Option<PeInfo>,
    pub signatures: Vec<String>,
    pub imports: Vec<String>,
    pub exports: Vec<String>,
    pub strings: Vec<String>,
}

/// PE file information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeInfo {
    pub compile_time: Option<SystemTime>,
    pub entry_point: Option<u64>,
    pub sections: Vec<PeSection>,
    pub imports: Vec<String>,
    pub exports: Vec<String>,
    pub resources: Vec<String>,
    pub version_info: HashMap<String, String>,
}

/// PE section information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeSection {
    pub name: String,
    pub virtual_address: u64,
    pub virtual_size: u64,
    pub raw_size: u64,
    pub entropy: f64,
    pub characteristics: u32,
}

/// Behavioral pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralPattern {
    pub pattern_id: Uuid,
    pub pattern_type: String,
    pub description: String,
    pub indicators: Vec<String>,
    pub confidence: f64,
    pub frequency: u32,
    pub first_observed: SystemTime,
    pub last_observed: SystemTime,
}

/// Threat intelligence feed configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedConfig {
    pub feed_id: String,
    pub name: String,
    pub description: String,
    pub feed_type: FeedType,
    pub url: Option<String>,
    pub api_key: Option<String>,
    pub update_interval: std::time::Duration,
    pub enabled: bool,
    pub priority: u32,
    pub tags: Vec<String>,
    pub filters: HashMap<String, String>,
    pub last_update: Option<SystemTime>,
    pub next_update: Option<SystemTime>,
}

/// Feed types
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FeedType {
    Stix,
    Taxii,
    Json,
    Csv,
    Xml,
    Rss,
    Api,
    File,
    Custom,
}

/// Intelligence sharing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharingConfig {
    pub enabled: bool,
    pub sharing_level: SharingLevel,
    pub trusted_partners: Vec<String>,
    pub sharing_protocols: Vec<SharingProtocol>,
    pub anonymization: bool,
    pub retention_period: std::time::Duration,
    pub approval_required: bool,
}

/// Sharing levels
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SharingLevel {
    None,
    Internal,
    Partners,
    Community,
    Public,
}

/// Sharing protocols
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SharingProtocol {
    Stix,
    Taxii,
    Misp,
    Custom,
}

/// Default implementations
impl Default for ThreatContext {
    fn default() -> Self {
        Self {
            campaign: None,
            actor: None,
            family: None,
            variant: None,
            target_sectors: Vec::new(),
            target_countries: Vec::new(),
            attack_vectors: Vec::new(),
            techniques: Vec::new(),
            tactics: Vec::new(),
            kill_chain_phases: Vec::new(),
            metadata: HashMap::new(),
        }
    }
}

impl Default for ThreatScore {
    fn default() -> Self {
        Self {
            entity: String::new(),
            entity_type: EntityType::File,
            score: 0.0,
            confidence: 0.0,
            risk_level: RiskLevel::Minimal,
            contributing_factors: Vec::new(),
            last_updated: SystemTime::now(),
            ttl: None,
        }
    }
}

impl Default for FeedConfig {
    fn default() -> Self {
        Self {
            feed_id: String::new(),
            name: String::new(),
            description: String::new(),
            feed_type: FeedType::Json,
            url: None,
            api_key: None,
            update_interval: std::time::Duration::from_secs(3600), // 1 hour
            enabled: true,
            priority: 50,
            tags: Vec::new(),
            filters: HashMap::new(),
            last_update: None,
            next_update: None,
        }
    }
}

impl Default for SharingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            sharing_level: SharingLevel::None,
            trusted_partners: Vec::new(),
            sharing_protocols: Vec::new(),
            anonymization: true,
            retention_period: std::time::Duration::from_secs(86400 * 30), // 30 days
            approval_required: true,
        }
    }
}

/// Convert threat severity to numeric score
impl ThreatSeverity {
    pub fn to_score(&self) -> f64 {
        match self {
            ThreatSeverity::Info => 10.0,
            ThreatSeverity::Low => 25.0,
            ThreatSeverity::Medium => 50.0,
            ThreatSeverity::High => 75.0,
            ThreatSeverity::Critical => 100.0,
        }
    }
}

/// Convert risk level to numeric score
impl RiskLevel {
    pub fn to_score(&self) -> f64 {
        match self {
            RiskLevel::Minimal => 10.0,
            RiskLevel::Low => 25.0,
            RiskLevel::Medium => 50.0,
            RiskLevel::High => 75.0,
            RiskLevel::Critical => 100.0,
        }
    }
}

/// Display implementations
impl std::fmt::Display for IocType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IocType::FileHash => write!(f, "file_hash"),
            IocType::IpAddress => write!(f, "ip_address"),
            IocType::Domain => write!(f, "domain"),
            IocType::Url => write!(f, "url"),
            IocType::Email => write!(f, "email"),
            IocType::Registry => write!(f, "registry"),
            IocType::Mutex => write!(f, "mutex"),
            IocType::Certificate => write!(f, "certificate"),
            IocType::UserAgent => write!(f, "user_agent"),
            IocType::ProcessName => write!(f, "process_name"),
            IocType::FilePath => write!(f, "file_path"),
            IocType::NetworkSignature => write!(f, "network_signature"),
            IocType::Yara => write!(f, "yara"),
            IocType::Custom(s) => write!(f, "custom_{}", s),
        }
    }
}

impl std::fmt::Display for ThreatType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ThreatType::Malware => write!(f, "malware"),
            ThreatType::Ransomware => write!(f, "ransomware"),
            ThreatType::Trojan => write!(f, "trojan"),
            ThreatType::Backdoor => write!(f, "backdoor"),
            ThreatType::Rootkit => write!(f, "rootkit"),
            ThreatType::Spyware => write!(f, "spyware"),
            ThreatType::Adware => write!(f, "adware"),
            ThreatType::Worm => write!(f, "worm"),
            ThreatType::Virus => write!(f, "virus"),
            ThreatType::Botnet => write!(f, "botnet"),
            ThreatType::C2 => write!(f, "c2"),
            ThreatType::Phishing => write!(f, "phishing"),
            ThreatType::Scam => write!(f, "scam"),
            ThreatType::Exploit => write!(f, "exploit"),
            ThreatType::Vulnerability => write!(f, "vulnerability"),
            ThreatType::Apt => write!(f, "apt"),
            ThreatType::Campaign => write!(f, "campaign"),
            ThreatType::Unknown => write!(f, "unknown"),
        }
    }
}

impl std::fmt::Display for ThreatSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ThreatSeverity::Info => write!(f, "info"),
            ThreatSeverity::Low => write!(f, "low"),
            ThreatSeverity::Medium => write!(f, "medium"),
            ThreatSeverity::High => write!(f, "high"),
            ThreatSeverity::Critical => write!(f, "critical"),
        }
    }
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskLevel::Minimal => write!(f, "minimal"),
            RiskLevel::Low => write!(f, "low"),
            RiskLevel::Medium => write!(f, "medium"),
            RiskLevel::High => write!(f, "high"),
            RiskLevel::Critical => write!(f, "critical"),
        }
    }
}
