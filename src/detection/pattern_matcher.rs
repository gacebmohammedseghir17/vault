//! Advanced Pattern Matcher for ERDPS Phase 2
//!
//! This module provides sophisticated pattern matching capabilities for detecting
//! malware signatures, behavioral patterns, and known attack indicators using
//! YARA rules, custom signatures, and machine learning-enhanced pattern recognition.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, Instant};
use std::path::{Path, PathBuf};
use std::fs;
use tokio::sync::Semaphore;
use serde::{Deserialize, Serialize};
use anyhow::{Result, Context};
use crate::core::error::EnhancedAgentError;
use log::{debug, info, warn};
use uuid::Uuid;
use regex::Regex;
use yara_x::{Compiler, Rules, Scanner};
use rayon::prelude::*;
use sha2::{Sha256, Digest};
use md5;
use crc32fast::Hasher as Crc32Hasher;


/// Pattern matcher configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternMatcherConfig {
    /// Enable YARA rule matching
    pub enable_yara_matching: bool,
    /// Enable custom signature matching
    pub enable_custom_signatures: bool,
    /// Enable behavioral pattern matching
    pub enable_behavioral_patterns: bool,
    /// Enable hash-based detection
    pub enable_hash_detection: bool,
    /// Enable string pattern matching
    pub enable_string_patterns: bool,
    /// Maximum file size to scan (bytes)
    pub max_file_size: u64,
    /// Maximum concurrent scans
    pub max_concurrent_scans: usize,
    /// Scan timeout in seconds
    pub scan_timeout: u64,
    /// YARA rules directory
    pub yara_rules_path: PathBuf,
    /// Custom signatures file
    pub custom_signatures_path: PathBuf,
    /// Enable deep scanning
    pub enable_deep_scan: bool,
    /// Minimum pattern length
    pub min_pattern_length: usize,
    /// Maximum pattern length
    pub max_pattern_length: usize,
    /// Enable entropy-based pattern filtering
    pub enable_entropy_filtering: bool,
    /// Pattern confidence threshold
    pub confidence_threshold: f64,
}

/// Pattern match result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternMatch {
    pub match_id: Uuid,
    pub pattern_type: PatternType,
    pub pattern_name: String,
    pub pattern_description: String,
    pub confidence: f64,
    pub severity: MatchSeverity,
    pub file_path: Option<PathBuf>,
    pub offset: Option<u64>,
    pub length: Option<usize>,
    pub matched_data: Option<Vec<u8>>,
    pub context: MatchContext,
    pub metadata: HashMap<String, String>,
    pub timestamp: SystemTime,
    pub scan_duration: Duration,
}

/// Types of patterns
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PatternType {
    YaraRule,
    CustomSignature,
    BehavioralPattern,
    HashSignature,
    StringPattern,
    RegexPattern,
    ByteSequence,
    ApiSequence,
    NetworkPattern,
    RegistryPattern,
    FileSystemPattern,
    MemoryPattern,
}

/// Match severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum MatchSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Match context information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchContext {
    pub process_id: Option<u32>,
    pub process_name: Option<String>,
    pub parent_process_id: Option<u32>,
    pub user_context: Option<String>,
    pub file_attributes: Option<FileAttributes>,
    pub network_context: Option<NetworkContext>,
    pub registry_context: Option<RegistryContext>,
    pub memory_context: Option<MemoryContext>,
    pub behavioral_context: Option<BehavioralContext>,
}

/// File attributes for context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAttributes {
    pub size: u64,
    pub created: SystemTime,
    pub modified: SystemTime,
    pub accessed: SystemTime,
    pub permissions: String,
    pub file_type: String,
    pub entropy: f64,
    pub pe_info: Option<PeInfo>,
}

/// PE file information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeInfo {
    pub machine_type: String,
    pub timestamp: SystemTime,
    pub characteristics: Vec<String>,
    pub subsystem: String,
    pub entry_point: u64,
    pub image_base: u64,
    pub sections: Vec<PeSection>,
    pub imports: Vec<String>,
    pub exports: Vec<String>,
}

/// PE section information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeSection {
    pub name: String,
    pub virtual_address: u64,
    pub virtual_size: u64,
    pub raw_size: u64,
    pub characteristics: Vec<String>,
    pub entropy: f64,
}

/// Network context for matches
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkContext {
    pub source_ip: Option<String>,
    pub destination_ip: Option<String>,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub protocol: Option<String>,
    pub packet_size: Option<usize>,
}

/// Registry context for matches
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryContext {
    pub key_path: String,
    pub value_name: Option<String>,
    pub value_type: Option<String>,
    pub value_data: Option<String>,
    pub operation: String,
}

/// Memory context for matches
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryContext {
    pub base_address: u64,
    pub region_size: u64,
    pub protection: String,
    pub allocation_type: String,
    pub module_name: Option<String>,
}

/// Behavioral context for matches
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralContext {
    pub api_calls: Vec<String>,
    pub file_operations: Vec<String>,
    pub network_operations: Vec<String>,
    pub registry_operations: Vec<String>,
    pub process_operations: Vec<String>,
    pub timing_patterns: Vec<Duration>,
}

/// Custom signature definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomSignature {
    pub id: String,
    pub name: String,
    pub description: String,
    pub pattern: SignaturePattern,
    pub severity: MatchSeverity,
    pub confidence: f64,
    pub tags: Vec<String>,
    pub metadata: HashMap<String, String>,
    pub enabled: bool,
}

/// Signature pattern types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignaturePattern {
    ByteSequence(Vec<u8>),
    HexString(String),
    RegexPattern(String),
    StringLiteral(String),
    HashSignature {
        algorithm: HashAlgorithm,
        hash: String,
    },
    CompositePattern {
        patterns: Vec<SignaturePattern>,
        operator: LogicalOperator,
    },
}

/// Hash algorithms for signatures
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HashAlgorithm {
    Md5,
    Sha1,
    Sha256,
    Sha512,
    Crc32,
}

/// Logical operators for composite patterns
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LogicalOperator {
    And,
    Or,
    Not,
}

/// Behavioral pattern definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralPattern {
    pub id: String,
    pub name: String,
    pub description: String,
    pub api_sequence: Vec<String>,
    pub timing_constraints: Vec<TimingConstraint>,
    pub context_requirements: Vec<ContextRequirement>,
    pub confidence: f64,
    pub severity: MatchSeverity,
}

/// Timing constraint for behavioral patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingConstraint {
    pub min_interval: Duration,
    pub max_interval: Duration,
    pub sequence_timeout: Duration,
}

/// Context requirement for behavioral patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextRequirement {
    pub requirement_type: String,
    pub expected_value: String,
    pub operator: ComparisonOperator,
}

/// Comparison operators
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ComparisonOperator {
    Equals,
    NotEquals,
    Contains,
    StartsWith,
    EndsWith,
    GreaterThan,
    LessThan,
    Matches, // For regex
}

/// Pattern matching statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchingStatistics {
    pub total_scans: u64,
    pub total_matches: u64,
    pub yara_matches: u64,
    pub custom_signature_matches: u64,
    pub behavioral_matches: u64,
    pub hash_matches: u64,
    pub string_matches: u64,
    pub average_scan_time: Duration,
    pub total_scan_time: Duration,
    pub files_scanned: u64,
    pub bytes_scanned: u64,
    pub false_positives: u64,
    pub true_positives: u64,
}

/// Scan result summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub scan_id: Uuid,
    pub target: ScanTarget,
    pub start_time: SystemTime,
    pub end_time: SystemTime,
    pub duration: Duration,
    pub matches: Vec<PatternMatch>,
    pub statistics: MatchingStatistics,
    pub threat_level: ThreatLevel,
    pub recommendations: Vec<String>,
    pub errors: Vec<String>,
}

impl Default for ScanResult {
    fn default() -> Self {
        let now = SystemTime::now();
        Self {
            scan_id: Uuid::new_v4(),
            target: ScanTarget::File(PathBuf::new()),
            start_time: now,
            end_time: now,
            duration: Duration::from_secs(0),
            matches: Vec::new(),
            statistics: MatchingStatistics::default(),
            threat_level: ThreatLevel::Clean,
            recommendations: Vec::new(),
            errors: Vec::new(),
        }
    }
}

/// Scan target types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScanTarget {
    File(PathBuf),
    Directory(PathBuf),
    Memory(u32), // Process ID
    Network,
    Registry,
    Custom(String),
}

/// Threat level assessment
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum ThreatLevel {
    Clean,
    Suspicious,
    Malicious,
    Critical,
}

/// Main advanced pattern matcher
#[derive(Clone)]
pub struct AdvancedPatternMatcher {
    config: PatternMatcherConfig,
    yara_rules: Arc<RwLock<Option<Rules>>>,
    custom_signatures: Arc<RwLock<Vec<CustomSignature>>>,
    behavioral_patterns: Arc<RwLock<Vec<BehavioralPattern>>>,
    hash_database: Arc<RwLock<HashMap<String, CustomSignature>>>,
    string_patterns: Arc<RwLock<Vec<Regex>>>,
    scan_semaphore: Arc<Semaphore>,
    statistics: Arc<RwLock<MatchingStatistics>>,
    match_cache: Arc<RwLock<HashMap<String, Vec<PatternMatch>>>>,
    running: Arc<Mutex<bool>>,
    entropy_calculator: Arc<dyn Fn(&[u8]) -> f64 + Send + Sync>,
}

impl Default for PatternMatcherConfig {
    fn default() -> Self {
        Self {
            enable_yara_matching: true,
            enable_custom_signatures: true,
            enable_behavioral_patterns: true,
            enable_hash_detection: true,
            enable_string_patterns: true,
            max_file_size: 100 * 1024 * 1024, // 100MB
            max_concurrent_scans: 4,
            scan_timeout: 300, // 5 minutes
            yara_rules_path: PathBuf::from("rules/yara"),
            custom_signatures_path: PathBuf::from("signatures/custom.json"),
            enable_deep_scan: true,
            min_pattern_length: 4,
            max_pattern_length: 1024,
            enable_entropy_filtering: true,
            confidence_threshold: 0.7,
        }
    }
}

impl Default for MatchingStatistics {
    fn default() -> Self {
        Self {
            total_scans: 0,
            total_matches: 0,
            yara_matches: 0,
            custom_signature_matches: 0,
            behavioral_matches: 0,
            hash_matches: 0,
            string_matches: 0,
            average_scan_time: Duration::from_secs(0),
            total_scan_time: Duration::from_secs(0),
            files_scanned: 0,
            bytes_scanned: 0,
            false_positives: 0,
            true_positives: 0,
        }
    }
}

impl AdvancedPatternMatcher {
    /// Create a new advanced pattern matcher
    pub fn new(config: PatternMatcherConfig) -> Result<Self> {
        info!("Initializing Advanced Pattern Matcher");
        
        let scan_semaphore = Arc::new(Semaphore::new(config.max_concurrent_scans));
        
        // Default Shannon entropy calculator
        let entropy_calculator: Arc<dyn Fn(&[u8]) -> f64 + Send + Sync> = Arc::new(|data| {
            crate::utils::entropy::shannon_entropy(data) as f64
        });
        
        let matcher = Self {
            config,
            yara_rules: Arc::new(RwLock::new(None)),
            custom_signatures: Arc::new(RwLock::new(Vec::new())),
            behavioral_patterns: Arc::new(RwLock::new(Vec::new())),
            hash_database: Arc::new(RwLock::new(HashMap::new())),
            string_patterns: Arc::new(RwLock::new(Vec::new())),
            scan_semaphore,
            statistics: Arc::new(RwLock::new(MatchingStatistics::default())),
            match_cache: Arc::new(RwLock::new(HashMap::new())),
            running: Arc::new(Mutex::new(false)),
            entropy_calculator,
        };
        
        Ok(matcher)
    }
    
    /// Initialize the pattern matcher
    pub async fn initialize(&self) -> Result<()> {
        info!("Initializing pattern matcher components");
        
        // Load YARA rules
        if self.config.enable_yara_matching {
            self.load_yara_rules().await?;
        }
        
        // Load custom signatures
        if self.config.enable_custom_signatures {
            self.load_custom_signatures().await?;
        }
        
        // Load behavioral patterns
        if self.config.enable_behavioral_patterns {
            self.load_behavioral_patterns().await?;
        }
        
        // Initialize hash database
        if self.config.enable_hash_detection {
            self.initialize_hash_database().await?;
        }
        
        // Compile string patterns
        if self.config.enable_string_patterns {
            self.compile_string_patterns().await?;
        }
        
        {
            let mut running = self.running.lock().unwrap();
            *running = true;
        }
        
        info!("Pattern matcher initialization completed");
        Ok(())
    }
    
    /// Shutdown the pattern matcher
    pub async fn shutdown(&self) -> Result<()> {
        info!("Shutting down pattern matcher");
        
        {
            let mut running = self.running.lock().unwrap();
            *running = false;
        }
        
        Ok(())
    }
    
    /// Scan a file for patterns
    pub async fn scan_file(&self, file_path: &Path) -> Result<ScanResult> {
        let _permit = self.scan_semaphore.acquire().await?;
        let start_time = Instant::now();
        let scan_id = Uuid::new_v4();
        
        info!("Scanning file: {:?}", file_path);
        
        // Check file size
        let metadata = fs::metadata(file_path)
            .with_context(|| format!("Failed to get metadata for {:?}", file_path))?;
        
        if metadata.len() > self.config.max_file_size {
            return Err(anyhow::anyhow!(
                "File too large: {} bytes (max: {} bytes)",
                metadata.len(),
                self.config.max_file_size
            ));
        }
        
        // Read file content
        let content = fs::read(file_path)
            .with_context(|| format!("Failed to read file: {:?}", file_path))?;
        
        let mut matches = Vec::new();
        let mut errors = Vec::new();
        
        // YARA rule matching
        if self.config.enable_yara_matching {
            match self.scan_with_yara(&content, Some(file_path)).await {
                Ok(mut yara_matches) => matches.append(&mut yara_matches),
                Err(e) => errors.push(format!("YARA scan error: {}", e)),
            }
        }
        
        // Custom signature matching
        if self.config.enable_custom_signatures {
            match self.scan_with_custom_signatures(&content, Some(file_path)).await {
                Ok(mut sig_matches) => matches.append(&mut sig_matches),
                Err(e) => errors.push(format!("Custom signature scan error: {}", e)),
            }
        }
        
        // Hash-based detection
        if self.config.enable_hash_detection {
            match self.scan_with_hash_signatures(&content, Some(file_path)).await {
                Ok(mut hash_matches) => matches.append(&mut hash_matches),
                Err(e) => errors.push(format!("Hash scan error: {}", e)),
            }
        }
        
        // String pattern matching
        if self.config.enable_string_patterns {
            match self.scan_with_string_patterns(&content, Some(file_path)).await {
                Ok(mut string_matches) => matches.append(&mut string_matches),
                Err(e) => errors.push(format!("String pattern scan error: {}", e)),
            }
        }
        
        let end_time = Instant::now();
        let duration = end_time.duration_since(start_time);
        
        // Update statistics
        self.update_statistics(&matches, duration, content.len()).await;
        
        // Determine threat level
        let threat_level = self.calculate_threat_level(&matches);
        
        // Generate recommendations
        let recommendations = self.generate_recommendations(&matches, &threat_level);
        
        let result = ScanResult {
            scan_id,
            target: ScanTarget::File(file_path.to_path_buf()),
            start_time: SystemTime::now() - duration,
            end_time: SystemTime::now(),
            duration,
            matches,
            statistics: self.get_current_statistics().await,
            threat_level,
            recommendations,
            errors,
        };
        
        info!("File scan completed: {:?}, matches: {}, duration: {:?}", 
              file_path, result.matches.len(), duration);
        
        Ok(result)
    }
    
    /// Scan directory recursively
    pub async fn scan_directory(&self, dir_path: &Path) -> Result<ScanResult> {
        let start_time = Instant::now();
        let scan_id = Uuid::new_v4();
        
        info!("Scanning directory: {:?}", dir_path);
        
        let mut all_matches = Vec::new();
        let mut all_errors = Vec::new();
        let mut total_files = 0u64;
        let mut total_bytes = 0u64;
        
        // Collect all files to scan
        let files = self.collect_files_recursive(dir_path)?;
        
        // Scan files in parallel
        let results: Vec<Result<ScanResult>> = files
            .par_iter()
            .map(|file_path| {
                tokio::runtime::Handle::current().block_on(async {
                    self.scan_file(file_path).await
                })
            })
            .collect();
        
        // Aggregate results
        for result in results {
            match result {
                Ok(scan_result) => {
                    all_matches.extend(scan_result.matches);
                    all_errors.extend(scan_result.errors);
                    total_files += 1;
                    total_bytes += scan_result.statistics.bytes_scanned;
                }
                Err(e) => {
                    all_errors.push(format!("Scan error: {}", e));
                }
            }
        }
        
        let end_time = Instant::now();
        let duration = end_time.duration_since(start_time);
        
        // Create aggregated statistics
        let statistics = MatchingStatistics {
            total_scans: total_files,
            total_matches: all_matches.len() as u64,
            files_scanned: total_files,
            bytes_scanned: total_bytes,
            total_scan_time: duration,
            average_scan_time: if total_files > 0 { duration / total_files as u32 } else { Duration::from_secs(0) },
            ..Default::default()
        };
        
        let threat_level = self.calculate_threat_level(&all_matches);
        let recommendations = self.generate_recommendations(&all_matches, &threat_level);
        
        let result = ScanResult {
            scan_id,
            target: ScanTarget::Directory(dir_path.to_path_buf()),
            start_time: SystemTime::now() - duration,
            end_time: SystemTime::now(),
            duration,
            matches: all_matches,
            statistics,
            threat_level,
            recommendations,
            errors: all_errors,
        };
        
        info!("Directory scan completed: {:?}, files: {}, matches: {}, duration: {:?}", 
              dir_path, total_files, result.matches.len(), duration);
        
        Ok(result)
    }
    
    /// Scan memory of a process
    pub async fn scan_process_memory(&self, process_id: u32) -> Result<ScanResult> {
        let _permit = self.scan_semaphore.acquire().await?;
        let start_time = Instant::now();
        let scan_id = Uuid::new_v4();
        
        info!("Scanning process memory: PID {}", process_id);
        
        // This would integrate with the memory forensics engine
        // For now, return a placeholder result
        let matches = Vec::new();
        let errors = Vec::new();
        
        let end_time = Instant::now();
        let duration = end_time.duration_since(start_time);
        
        let threat_level = self.calculate_threat_level(&matches);
        let recommendations = self.generate_recommendations(&matches, &threat_level);
        
        let result = ScanResult {
            scan_id,
            target: ScanTarget::Memory(process_id),
            start_time: SystemTime::now() - duration,
            end_time: SystemTime::now(),
            duration,
            matches,
            statistics: MatchingStatistics::default(),
            threat_level,
            recommendations,
            errors,
        };
        
        Ok(result)
    }
    
    /// Load YARA rules from directory
    async fn load_yara_rules(&self) -> Result<()> {
        info!("Loading YARA rules from: {:?}", self.config.yara_rules_path);
        
        if !self.config.yara_rules_path.exists() {
            warn!("YARA rules directory does not exist: {:?}", self.config.yara_rules_path);
            return Ok(());
        }
        
        let mut compiler = Compiler::new();
        
        // Load all .yar and .yara files
        for entry in fs::read_dir(&self.config.yara_rules_path)? {
            let entry = entry?;
            let path = entry.path();
            
            if let Some(extension) = path.extension() {
                if extension == "yar" || extension == "yara" {
                    info!("Loading YARA rule file: {:?}", path);
                    match std::fs::read_to_string(&path) {
                        Ok(content) => {
                            match compiler.add_source(content.as_str()) {
                                Ok(_) => debug!("Successfully loaded YARA rules from: {:?}", path),
                                Err(e) => warn!("Failed to load YARA rules from {:?}: {}", path, e),
                            }
                        },
                         Err(e) => warn!("Failed to read YARA rules file {:?}: {}", path, e),
                     }
                }
            }
        }
        
        let rules = compiler.build();
        
        {
            let mut yara_rules = self.yara_rules.write().unwrap();
            *yara_rules = Some(rules);
        }
        
        info!("YARA rules loaded successfully");
        Ok(())
    }
    
    /// Load custom signatures from file
    async fn load_custom_signatures(&self) -> Result<()> {
        info!("Loading custom signatures from: {:?}", self.config.custom_signatures_path);
        
        if !self.config.custom_signatures_path.exists() {
            warn!("Custom signatures file does not exist: {:?}", self.config.custom_signatures_path);
            return Ok(());
        }
        
        let content = fs::read_to_string(&self.config.custom_signatures_path)
            .with_context(|| format!("Failed to read signatures file: {:?}", self.config.custom_signatures_path))?;
        
        let signatures: Vec<CustomSignature> = serde_json::from_str(&content)
            .with_context(|| "Failed to parse custom signatures JSON")?;
        
        {
            let mut custom_signatures = self.custom_signatures.write().unwrap();
            *custom_signatures = signatures;
        }
        
        info!("Custom signatures loaded successfully");
        Ok(())
    }
    
    /// Load behavioral patterns
    async fn load_behavioral_patterns(&self) -> Result<()> {
        info!("Loading behavioral patterns");
        
        // Load default behavioral patterns
        let default_patterns = vec![
            BehavioralPattern {
                id: "ransomware_file_encryption".to_string(),
                name: "Ransomware File Encryption Pattern".to_string(),
                description: "Detects rapid file encryption behavior typical of ransomware".to_string(),
                api_sequence: vec![
                    "CreateFileW".to_string(),
                    "ReadFile".to_string(),
                    "WriteFile".to_string(),
                    "DeleteFileW".to_string(),
                ],
                timing_constraints: vec![TimingConstraint {
                    min_interval: Duration::from_millis(1),
                    max_interval: Duration::from_millis(100),
                    sequence_timeout: Duration::from_secs(10),
                }],
                context_requirements: vec![ContextRequirement {
                    requirement_type: "file_extension".to_string(),
                    expected_value: "encrypted".to_string(),
                    operator: ComparisonOperator::Contains,
                }],
                confidence: 0.9,
                severity: MatchSeverity::Critical,
            },
            BehavioralPattern {
                id: "process_injection".to_string(),
                name: "Process Injection Pattern".to_string(),
                description: "Detects process injection techniques".to_string(),
                api_sequence: vec![
                    "OpenProcess".to_string(),
                    "VirtualAllocEx".to_string(),
                    "WriteProcessMemory".to_string(),
                    "CreateRemoteThread".to_string(),
                ],
                timing_constraints: vec![TimingConstraint {
                    min_interval: Duration::from_millis(10),
                    max_interval: Duration::from_secs(5),
                    sequence_timeout: Duration::from_secs(30),
                }],
                context_requirements: vec![],
                confidence: 0.85,
                severity: MatchSeverity::High,
            },
        ];
        
        {
            let mut behavioral_patterns = self.behavioral_patterns.write().unwrap();
            *behavioral_patterns = default_patterns;
        }
        
        info!("Behavioral patterns loaded successfully");
        Ok(())
    }
    
    /// Initialize hash database
    async fn initialize_hash_database(&self) -> Result<()> {
        info!("Initializing hash database");
        
        // Load known malicious hashes (would typically come from threat intelligence)
        let malicious_hashes = vec![
            ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(), CustomSignature {
                id: "empty_file_sha256".to_string(),
                name: "Empty File SHA256".to_string(),
                description: "SHA256 hash of empty file".to_string(),
                pattern: SignaturePattern::HashSignature {
                    algorithm: HashAlgorithm::Sha256,
                    hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
                },
                severity: MatchSeverity::Info,
                confidence: 1.0,
                tags: vec!["test".to_string()],
                metadata: HashMap::new(),
                enabled: true,
            }),
        ];
        
        {
            let mut hash_database = self.hash_database.write().unwrap();
            for (hash, signature) in malicious_hashes {
                hash_database.insert(hash, signature);
            }
        }
        
        info!("Hash database initialized");
        Ok(())
    }
    
    /// Compile string patterns
    async fn compile_string_patterns(&self) -> Result<()> {
        info!("Compiling string patterns");
        
        let pattern_strings = vec![
            r"(?i)wannacry",
            r"(?i)petya",
            r"(?i)notpetya",
            r"(?i)ryuk",
            r"(?i)maze",
            r"(?i)conti",
            r"(?i)lockbit",
            r"(?i)revil",
            r"(?i)sodinokibi",
            r"(?i)darkside",
            r"(?i)blackmatter",
            r"(?i)alphv",
            r"(?i)blackcat",
            r"[a-fA-F0-9]{32}\.(encrypted|locked|crypt|enc)",
            r"YOUR FILES ARE ENCRYPTED",
            r"DECRYPT_INSTRUCTIONS",
            r"RANSOM_NOTE",
            r"bitcoin",
            r"onion",
            r"\.onion",
        ];
        
        let mut compiled_patterns = Vec::new();
        
        for pattern_str in pattern_strings {
            match Regex::new(pattern_str) {
                Ok(regex) => compiled_patterns.push(regex),
                Err(e) => warn!("Failed to compile regex pattern '{}': {}", pattern_str, e),
            }
        }
        
        {
            let mut string_patterns = self.string_patterns.write().unwrap();
            *string_patterns = compiled_patterns;
        }
        
        info!("String patterns compiled successfully");
        Ok(())
    }
    
    /// Scan with YARA rules
    async fn scan_with_yara(&self, content: &[u8], file_path: Option<&Path>) -> Result<Vec<PatternMatch>> {
        let yara_rules = self.yara_rules.read().unwrap();
        let rules = match yara_rules.as_ref() {
            Some(rules) => rules,
            None => return Ok(Vec::new()),
        };
        
        let mut scanner = Scanner::new(rules);
        let scan_results = scanner.scan(content).map_err(|e| EnhancedAgentError::Detection(format!("YARA scan failed: {}", e)))?;
        
        let mut matches = Vec::new();
        
        for scan_result in scan_results.matching_rules() {
            let pattern_match = PatternMatch {
                match_id: Uuid::new_v4(),
                pattern_type: PatternType::YaraRule,
                pattern_name: scan_result.identifier().to_string(),
                pattern_description: format!("YARA rule match: {}", scan_result.identifier()),
                confidence: 0.9, // YARA rules are generally high confidence
                severity: MatchSeverity::High,
                file_path: file_path.map(|p| p.to_path_buf()),
                offset: None, // YARA-X doesn't provide string match details in the same way
                length: None,
                matched_data: None,
                context: MatchContext {
                    process_id: None,
                    process_name: None,
                    parent_process_id: None,
                    user_context: None,
                    file_attributes: None,
                    network_context: None,
                    registry_context: None,
                    memory_context: None,
                    behavioral_context: None,
                },
                metadata: HashMap::new(), // scan_result.metadata() returns different type
                timestamp: SystemTime::now(),
                scan_duration: Duration::from_millis(0), // Would be measured
            };
            
            matches.push(pattern_match);
        }
        
        Ok(matches)
    }
    
    /// Scan with custom signatures
    async fn scan_with_custom_signatures(&self, content: &[u8], file_path: Option<&Path>) -> Result<Vec<PatternMatch>> {
        let signatures = {
            let signatures_guard = self.custom_signatures.read().unwrap();
            signatures_guard.clone()
        };
        let mut matches = Vec::new();
        
        for signature in signatures.iter() {
            if !signature.enabled {
                continue;
            }
            
            if let Some(pattern_match) = self.match_signature_pattern(&signature.pattern, content, signature, file_path).await? {
                matches.push(pattern_match);
            }
        }
        
        Ok(matches)
    }
    
    /// Scan with hash signatures
    async fn scan_with_hash_signatures(&self, content: &[u8], file_path: Option<&Path>) -> Result<Vec<PatternMatch>> {
        let hash_database = {
            let hash_guard = self.hash_database.read().unwrap();
            hash_guard.clone()
        };
        let mut matches = Vec::new();
        
        // Calculate various hashes
        let md5_hash = format!("{:x}", md5::compute(content));
        let sha256_hash = format!("{:x}", Sha256::digest(content));
        
        let mut crc32_hasher = Crc32Hasher::new();
        crc32_hasher.update(content);
        let crc32_hash = format!("{:08x}", crc32_hasher.finalize());
        
        // Check against database
        for hash in [&md5_hash, &sha256_hash, &crc32_hash] {
            if let Some(signature) = hash_database.get(hash) {
                let pattern_match = PatternMatch {
                    match_id: Uuid::new_v4(),
                    pattern_type: PatternType::HashSignature,
                    pattern_name: signature.name.clone(),
                    pattern_description: signature.description.clone(),
                    confidence: signature.confidence,
                    severity: signature.severity.clone(),
                    file_path: file_path.map(|p| p.to_path_buf()),
                    offset: Some(0),
                    length: Some(content.len()),
                    matched_data: None, // Don't store entire file content
                    context: MatchContext {
                        process_id: None,
                        process_name: None,
                        parent_process_id: None,
                        user_context: None,
                        file_attributes: None,
                        network_context: None,
                        registry_context: None,
                        memory_context: None,
                        behavioral_context: None,
                    },
                    metadata: signature.metadata.clone(),
                    timestamp: SystemTime::now(),
                    scan_duration: Duration::from_millis(0),
                };
                
                matches.push(pattern_match);
            }
        }
        
        Ok(matches)
    }
    
    /// Scan with string patterns
    async fn scan_with_string_patterns(&self, content: &[u8], file_path: Option<&Path>) -> Result<Vec<PatternMatch>> {
        let string_patterns = {
            let patterns_guard = self.string_patterns.read().unwrap();
            patterns_guard.clone()
        };
        let mut matches = Vec::new();
        
        // Convert content to string for regex matching
        let content_str = String::from_utf8_lossy(content);
        
        for (i, pattern) in string_patterns.iter().enumerate() {
            for regex_match in pattern.find_iter(&content_str) {
                let pattern_match = PatternMatch {
                    match_id: Uuid::new_v4(),
                    pattern_type: PatternType::StringPattern,
                    pattern_name: format!("String Pattern {}", i),
                    pattern_description: format!("String pattern match: {}", pattern.as_str()),
                    confidence: 0.7,
                    severity: MatchSeverity::Medium,
                    file_path: file_path.map(|p| p.to_path_buf()),
                    offset: Some(regex_match.start() as u64),
                    length: Some(regex_match.len()),
                    matched_data: Some(regex_match.as_str().as_bytes().to_vec()),
                    context: MatchContext {
                        process_id: None,
                        process_name: None,
                        parent_process_id: None,
                        user_context: None,
                        file_attributes: None,
                        network_context: None,
                        registry_context: None,
                        memory_context: None,
                        behavioral_context: None,
                    },
                    metadata: HashMap::new(),
                    timestamp: SystemTime::now(),
                    scan_duration: Duration::from_millis(0),
                };
                
                matches.push(pattern_match);
            }
        }
        
        Ok(matches)
    }
    
    /// Match a signature pattern
    async fn match_signature_pattern(
        &self,
        pattern: &SignaturePattern,
        content: &[u8],
        signature: &CustomSignature,
        file_path: Option<&Path>
    ) -> Result<Option<PatternMatch>> {
        match pattern {
            SignaturePattern::ByteSequence(bytes) => {
                if let Some(offset) = self.find_byte_sequence(content, bytes) {
                    Ok(Some(PatternMatch {
                        match_id: Uuid::new_v4(),
                        pattern_type: PatternType::ByteSequence,
                        pattern_name: signature.name.clone(),
                        pattern_description: signature.description.clone(),
                        confidence: signature.confidence,
                        severity: signature.severity.clone(),
                        file_path: file_path.map(|p| p.to_path_buf()),
                        offset: Some(offset as u64),
                        length: Some(bytes.len()),
                        matched_data: Some(bytes.clone()),
                        context: MatchContext {
                            process_id: None,
                            process_name: None,
                            parent_process_id: None,
                            user_context: None,
                            file_attributes: None,
                            network_context: None,
                            registry_context: None,
                            memory_context: None,
                            behavioral_context: None,
                        },
                        metadata: signature.metadata.clone(),
                        timestamp: SystemTime::now(),
                        scan_duration: Duration::from_millis(0),
                    }))
                } else {
                    Ok(None)
                }
            }
            SignaturePattern::HexString(hex_str) => {
                if let Ok(bytes) = hex::decode(hex_str) {
                    if let Some(offset) = self.find_byte_sequence(content, &bytes) {
                        Ok(Some(PatternMatch {
                            match_id: Uuid::new_v4(),
                            pattern_type: PatternType::ByteSequence,
                            pattern_name: signature.name.clone(),
                            pattern_description: signature.description.clone(),
                            confidence: signature.confidence,
                            severity: signature.severity.clone(),
                            file_path: file_path.map(|p| p.to_path_buf()),
                            offset: Some(offset as u64),
                            length: Some(bytes.len()),
                            matched_data: Some(bytes),
                            context: MatchContext {
                                process_id: None,
                                process_name: None,
                                parent_process_id: None,
                                user_context: None,
                                file_attributes: None,
                                network_context: None,
                                registry_context: None,
                                memory_context: None,
                                behavioral_context: None,
                            },
                            metadata: signature.metadata.clone(),
                            timestamp: SystemTime::now(),
                            scan_duration: Duration::from_millis(0),
                        }))
                    } else {
                        Ok(None)
                    }
                } else {
                    Ok(None)
                }
            }
            SignaturePattern::RegexPattern(regex_str) => {
                if let Ok(regex) = Regex::new(regex_str) {
                    let content_str = String::from_utf8_lossy(content);
                    if let Some(regex_match) = regex.find(&content_str) {
                        Ok(Some(PatternMatch {
                            match_id: Uuid::new_v4(),
                            pattern_type: PatternType::RegexPattern,
                            pattern_name: signature.name.clone(),
                            pattern_description: signature.description.clone(),
                            confidence: signature.confidence,
                            severity: signature.severity.clone(),
                            file_path: file_path.map(|p| p.to_path_buf()),
                            offset: Some(regex_match.start() as u64),
                            length: Some(regex_match.len()),
                            matched_data: Some(regex_match.as_str().as_bytes().to_vec()),
                            context: MatchContext {
                                process_id: None,
                                process_name: None,
                                parent_process_id: None,
                                user_context: None,
                                file_attributes: None,
                                network_context: None,
                                registry_context: None,
                                memory_context: None,
                                behavioral_context: None,
                            },
                            metadata: signature.metadata.clone(),
                            timestamp: SystemTime::now(),
                            scan_duration: Duration::from_millis(0),
                        }))
                    } else {
                        Ok(None)
                    }
                } else {
                    Ok(None)
                }
            }
            SignaturePattern::StringLiteral(string) => {
                let content_str = String::from_utf8_lossy(content);
                if let Some(offset) = content_str.find(string) {
                    Ok(Some(PatternMatch {
                        match_id: Uuid::new_v4(),
                        pattern_type: PatternType::StringPattern,
                        pattern_name: signature.name.clone(),
                        pattern_description: signature.description.clone(),
                        confidence: signature.confidence,
                        severity: signature.severity.clone(),
                        file_path: file_path.map(|p| p.to_path_buf()),
                        offset: Some(offset as u64),
                        length: Some(string.len()),
                        matched_data: Some(string.as_bytes().to_vec()),
                        context: MatchContext {
                            process_id: None,
                            process_name: None,
                            parent_process_id: None,
                            user_context: None,
                            file_attributes: None,
                            network_context: None,
                            registry_context: None,
                            memory_context: None,
                            behavioral_context: None,
                        },
                        metadata: signature.metadata.clone(),
                        timestamp: SystemTime::now(),
                        scan_duration: Duration::from_millis(0),
                    }))
                } else {
                    Ok(None)
                }
            }
            _ => Ok(None), // Other pattern types not implemented yet
        }
    }
    
    /// Find byte sequence in content
    fn find_byte_sequence(&self, content: &[u8], pattern: &[u8]) -> Option<usize> {
        content.windows(pattern.len()).position(|window| window == pattern)
    }
    
    /// Collect files recursively from directory
    fn collect_files_recursive(&self, dir_path: &Path) -> Result<Vec<PathBuf>> {
        let mut files = Vec::new();
        
        for entry in fs::read_dir(dir_path)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.is_file() {
                files.push(path);
            } else if path.is_dir() {
                let mut sub_files = self.collect_files_recursive(&path)?;
                files.append(&mut sub_files);
            }
        }
        
        Ok(files)
    }
    
    /// Calculate threat level based on matches
    fn calculate_threat_level(&self, matches: &[PatternMatch]) -> ThreatLevel {
        if matches.is_empty() {
            return ThreatLevel::Clean;
        }
        
        let mut max_severity = MatchSeverity::Info;
        let mut total_confidence = 0.0;
        
        for pattern_match in matches {
            if pattern_match.severity > max_severity {
                max_severity = pattern_match.severity.clone();
            }
            total_confidence += pattern_match.confidence;
        }
        
        let avg_confidence = total_confidence / matches.len() as f64;
        
        match max_severity {
            MatchSeverity::Critical => ThreatLevel::Critical,
            MatchSeverity::High => {
                if avg_confidence > 0.8 {
                    ThreatLevel::Critical
                } else {
                    ThreatLevel::Malicious
                }
            }
            MatchSeverity::Medium => {
                if avg_confidence > 0.7 {
                    ThreatLevel::Malicious
                } else {
                    ThreatLevel::Suspicious
                }
            }
            _ => ThreatLevel::Suspicious,
        }
    }
    
    /// Generate recommendations based on matches and threat level
    fn generate_recommendations(&self, matches: &[PatternMatch], threat_level: &ThreatLevel) -> Vec<String> {
        let mut recommendations = Vec::new();
        
        match threat_level {
            ThreatLevel::Critical => {
                recommendations.push("IMMEDIATE ACTION REQUIRED: Quarantine the file/system immediately".to_string());
                recommendations.push("Disconnect from network to prevent lateral movement".to_string());
                recommendations.push("Initiate incident response procedures".to_string());
                recommendations.push("Perform full system scan and forensic analysis".to_string());
            }
            ThreatLevel::Malicious => {
                recommendations.push("Quarantine the detected file(s)".to_string());
                recommendations.push("Perform additional scanning of the system".to_string());
                recommendations.push("Review system logs for suspicious activity".to_string());
                recommendations.push("Consider network isolation if needed".to_string());
            }
            ThreatLevel::Suspicious => {
                recommendations.push("Monitor the file(s) for further activity".to_string());
                recommendations.push("Perform deeper analysis with additional tools".to_string());
                recommendations.push("Review file origins and execution context".to_string());
            }
            ThreatLevel::Clean => {
                recommendations.push("No immediate action required".to_string());
                recommendations.push("Continue regular monitoring".to_string());
            }
        }
        
        // Add specific recommendations based on match types
        let has_yara_matches = matches.iter().any(|m| m.pattern_type == PatternType::YaraRule);
        let has_hash_matches = matches.iter().any(|m| m.pattern_type == PatternType::HashSignature);
        let has_behavioral_matches = matches.iter().any(|m| m.pattern_type == PatternType::BehavioralPattern);
        
        if has_yara_matches {
            recommendations.push("YARA rule matches detected - review rule details for specific threats".to_string());
        }
        
        if has_hash_matches {
            recommendations.push("Known malicious hash detected - file is likely malware".to_string());
        }
        
        if has_behavioral_matches {
            recommendations.push("Suspicious behavioral patterns detected - monitor process activity".to_string());
        }
        
        recommendations
    }
    
    /// Update scanning statistics
    async fn update_statistics(&self, matches: &[PatternMatch], duration: Duration, bytes_scanned: usize) {
        let mut stats = self.statistics.write().unwrap();
        
        stats.total_scans += 1;
        stats.total_matches += matches.len() as u64;
        stats.files_scanned += 1;
        stats.bytes_scanned += bytes_scanned as u64;
        stats.total_scan_time += duration;
        
        // Update average scan time
        stats.average_scan_time = stats.total_scan_time / stats.total_scans as u32;
        
        // Count matches by type
        for pattern_match in matches {
            match pattern_match.pattern_type {
                PatternType::YaraRule => stats.yara_matches += 1,
                PatternType::CustomSignature => stats.custom_signature_matches += 1,
                PatternType::BehavioralPattern => stats.behavioral_matches += 1,
                PatternType::HashSignature => stats.hash_matches += 1,
                PatternType::StringPattern | PatternType::RegexPattern => stats.string_matches += 1,
                _ => {}
            }
        }
    }
    
    /// Get current statistics
    async fn get_current_statistics(&self) -> MatchingStatistics {
        let stats = self.statistics.read().unwrap();
        stats.clone()
    }
    
    /// Get recent scan results
    pub async fn get_recent_results(&self, _limit: usize) -> Result<Vec<ScanResult>> {
        // This would typically be stored in a database or persistent storage
        // For now, return empty vector
        Ok(Vec::new())
    }
    
    /// Add custom signature
    pub async fn add_custom_signature(&self, signature: CustomSignature) -> Result<()> {
        let mut signatures = self.custom_signatures.write().unwrap();
        signatures.push(signature);
        Ok(())
    }
    
    /// Remove custom signature
    pub async fn remove_custom_signature(&self, signature_id: &str) -> Result<bool> {
        let mut signatures = self.custom_signatures.write().unwrap();
        let initial_len = signatures.len();
        signatures.retain(|sig| sig.id != signature_id);
        Ok(signatures.len() < initial_len)
    }
    
    /// Update signature database from threat intelligence
    pub async fn update_signature_database(&self) -> Result<()> {
        info!("Updating signature database from threat intelligence");
        
        // This would typically fetch updates from threat intelligence feeds
        // For now, just log the operation
        
        info!("Signature database update completed");
        Ok(())
    }

    /// Scan raw data for patterns
    pub async fn scan_data(&self, data: &[u8]) -> Result<Vec<PatternMatch>, Box<dyn std::error::Error + Send + Sync>> {
        // Create a temporary file for YARA scanning
        let temp_dir = tempfile::TempDir::new()?;
        let temp_file = temp_dir.path().join("scan_data.tmp");
        std::fs::write(&temp_file, data)?;
        let result = self.scan_file(&temp_file).await?;
        
        Ok(result.matches)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;
    
    #[tokio::test]
    async fn test_pattern_matcher_creation() {
        let config = PatternMatcherConfig::default();
        let matcher = AdvancedPatternMatcher::new(config).unwrap();
        assert!(!*matcher.running.lock().unwrap());
    }
    
    #[test]
    fn test_byte_sequence_finding() {
        let config = PatternMatcherConfig::default();
        let matcher = AdvancedPatternMatcher::new(config).unwrap();
        
        let content = b"Hello, World! This is a test.";
        let pattern = b"World";
        
        let offset = matcher.find_byte_sequence(content, pattern);
        assert_eq!(offset, Some(7));
    }
    
    #[test]
    fn test_threat_level_calculation() {
        let config = PatternMatcherConfig::default();
        let matcher = AdvancedPatternMatcher::new(config).unwrap();
        
        let matches = vec![
            PatternMatch {
                match_id: Uuid::new_v4(),
                pattern_type: PatternType::YaraRule,
                pattern_name: "test".to_string(),
                pattern_description: "test".to_string(),
                confidence: 0.9,
                severity: MatchSeverity::Critical,
                file_path: None,
                offset: None,
                length: None,
                matched_data: None,
                context: MatchContext {
                    process_id: None,
                    process_name: None,
                    parent_process_id: None,
                    user_context: None,
                    file_attributes: None,
                    network_context: None,
                    registry_context: None,
                    memory_context: None,
                    behavioral_context: None,
                },
                metadata: HashMap::new(),
                timestamp: SystemTime::now(),
                scan_duration: Duration::from_secs(0),
            }
        ];
        
        let threat_level = matcher.calculate_threat_level(&matches);
        assert_eq!(threat_level, ThreatLevel::Critical);
    }
    
    #[tokio::test]
    async fn test_file_scanning() {
        let config = PatternMatcherConfig::default();
        let matcher = AdvancedPatternMatcher::new(config).unwrap();
        
        // Create a temporary file
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        fs::write(&file_path, b"This is a test file with some content").unwrap();
        
        // Initialize the matcher
        matcher.initialize().await.unwrap();
        
        // Scan the file
        let result = matcher.scan_file(&file_path).await.unwrap();
        
        assert_eq!(result.target, ScanTarget::File(file_path));
        assert!(result.duration > Duration::from_nanos(0));
    }
    
    #[tokio::test]
    async fn test_custom_signature_management() {
        let config = PatternMatcherConfig::default();
        let matcher = AdvancedPatternMatcher::new(config).unwrap();
        
        let signature = CustomSignature {
            id: "test_sig".to_string(),
            name: "Test Signature".to_string(),
            description: "A test signature".to_string(),
            pattern: SignaturePattern::StringLiteral("test_pattern".to_string()),
            severity: MatchSeverity::Medium,
            confidence: 0.8,
            tags: vec!["test".to_string()],
            metadata: HashMap::new(),
            enabled: true,
        };
        
        // Add signature
        matcher.add_custom_signature(signature).await.unwrap();
        
        // Check if signature was added
        let signatures = matcher.custom_signatures.read().unwrap();
        assert_eq!(signatures.len(), 1);
        assert_eq!(signatures[0].id, "test_sig");
        
        drop(signatures);
        
        // Remove signature
        let removed = matcher.remove_custom_signature("test_sig").await.unwrap();
        assert!(removed);
        
        // Check if signature was removed
        let signatures = matcher.custom_signatures.read().unwrap();
        assert_eq!(signatures.len(), 0);
    }
    
    #[test]
    fn test_hash_calculation() {
        let content = b"Hello, World!";
        
        let md5_hash = format!("{:x}", md5::compute(content));
        let sha256_hash = format!("{:x}", Sha256::digest(content));
        
        assert_eq!(md5_hash, "65a8e27d8879283831b664bd8b7f0ad4");
        assert_eq!(sha256_hash, "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f");
    }
    
    #[test]
    fn test_signature_pattern_matching() {
        let byte_pattern = SignaturePattern::ByteSequence(vec![0x48, 0x65, 0x6c, 0x6c, 0x6f]); // "Hello"
        let hex_pattern = SignaturePattern::HexString("48656c6c6f".to_string()); // "Hello"
        let string_pattern = SignaturePattern::StringLiteral("Hello".to_string());
        let regex_pattern = SignaturePattern::RegexPattern(r"H[e]+llo".to_string());
        
        // Test pattern creation
        match byte_pattern {
            SignaturePattern::ByteSequence(bytes) => assert_eq!(bytes, vec![0x48, 0x65, 0x6c, 0x6c, 0x6f]),
            _ => panic!("Wrong pattern type"),
        }
        
        match hex_pattern {
            SignaturePattern::HexString(hex) => assert_eq!(hex, "48656c6c6f"),
            _ => panic!("Wrong pattern type"),
        }
        
        match string_pattern {
            SignaturePattern::StringLiteral(s) => assert_eq!(s, "Hello"),
            _ => panic!("Wrong pattern type"),
        }
        
        match regex_pattern {
            SignaturePattern::RegexPattern(r) => assert_eq!(r, r"H[e]+llo"),
            _ => panic!("Wrong pattern type"),
        }
    }
    
    #[test]
    fn test_match_severity_ordering() {
        assert!(MatchSeverity::Critical > MatchSeverity::High);
        assert!(MatchSeverity::High > MatchSeverity::Medium);
        assert!(MatchSeverity::Medium > MatchSeverity::Low);
        assert!(MatchSeverity::Low > MatchSeverity::Info);
    }
    
    #[test]
    fn test_threat_level_ordering() {
        assert!(ThreatLevel::Critical > ThreatLevel::Malicious);
        assert!(ThreatLevel::Malicious > ThreatLevel::Suspicious);
        assert!(ThreatLevel::Suspicious > ThreatLevel::Clean);
    }
    
    #[tokio::test]
    async fn test_statistics_update() {
        let config = PatternMatcherConfig::default();
        let matcher = AdvancedPatternMatcher::new(config).unwrap();
        
        let matches = vec![
            PatternMatch {
                match_id: Uuid::new_v4(),
                pattern_type: PatternType::YaraRule,
                pattern_name: "test_yara".to_string(),
                pattern_description: "test".to_string(),
                confidence: 0.9,
                severity: MatchSeverity::High,
                file_path: None,
                offset: None,
                length: None,
                matched_data: None,
                context: MatchContext {
                    process_id: None,
                    process_name: None,
                    parent_process_id: None,
                    user_context: None,
                    file_attributes: None,
                    network_context: None,
                    registry_context: None,
                    memory_context: None,
                    behavioral_context: None,
                },
                metadata: HashMap::new(),
                timestamp: SystemTime::now(),
                scan_duration: Duration::from_secs(0),
            },
            PatternMatch {
                match_id: Uuid::new_v4(),
                pattern_type: PatternType::HashSignature,
                pattern_name: "test_hash".to_string(),
                pattern_description: "test".to_string(),
                confidence: 1.0,
                severity: MatchSeverity::Critical,
                file_path: None,
                offset: None,
                length: None,
                matched_data: None,
                context: MatchContext {
                    process_id: None,
                    process_name: None,
                    parent_process_id: None,
                    user_context: None,
                    file_attributes: None,
                    network_context: None,
                    registry_context: None,
                    memory_context: None,
                    behavioral_context: None,
                },
                metadata: HashMap::new(),
                timestamp: SystemTime::now(),
                scan_duration: Duration::from_secs(0),
            },
        ];
        
        let duration = Duration::from_millis(100);
        let bytes_scanned = 1024;
        
        matcher.update_statistics(&matches, duration, bytes_scanned).await;
        
        let stats = matcher.get_current_statistics().await;
        assert_eq!(stats.total_scans, 1);
        assert_eq!(stats.total_matches, 2);
        assert_eq!(stats.yara_matches, 1);
        assert_eq!(stats.hash_matches, 1);
        assert_eq!(stats.bytes_scanned, 1024);
        assert_eq!(stats.total_scan_time, duration);
    }
    
    #[test]
    fn test_behavioral_pattern_creation() {
        let pattern = BehavioralPattern {
            id: "test_behavior".to_string(),
            name: "Test Behavioral Pattern".to_string(),
            description: "A test behavioral pattern".to_string(),
            api_sequence: vec!["CreateFile".to_string(), "WriteFile".to_string()],
            timing_constraints: vec![TimingConstraint {
                min_interval: Duration::from_millis(1),
                max_interval: Duration::from_millis(100),
                sequence_timeout: Duration::from_secs(10),
            }],
            context_requirements: vec![ContextRequirement {
                requirement_type: "file_extension".to_string(),
                expected_value: ".exe".to_string(),
                operator: ComparisonOperator::EndsWith,
            }],
            confidence: 0.8,
            severity: MatchSeverity::Medium,
        };
        
        assert_eq!(pattern.id, "test_behavior");
        assert_eq!(pattern.api_sequence.len(), 2);
        assert_eq!(pattern.timing_constraints.len(), 1);
        assert_eq!(pattern.context_requirements.len(), 1);
    }
    
    #[test]
    fn test_pe_info_structure() {
        let pe_info = PeInfo {
            machine_type: "x64".to_string(),
            timestamp: SystemTime::now(),
            characteristics: vec!["EXECUTABLE_IMAGE".to_string()],
            subsystem: "WINDOWS_GUI".to_string(),
            entry_point: 0x1000,
            image_base: 0x400000,
            sections: vec![PeSection {
                name: ".text".to_string(),
                virtual_address: 0x1000,
                virtual_size: 0x2000,
                raw_size: 0x2000,
                characteristics: vec!["CODE".to_string(), "EXECUTE".to_string()],
                entropy: 6.5,
            }],
            imports: vec!["kernel32.dll".to_string()],
            exports: vec!["main".to_string()],
        };
        
        assert_eq!(pe_info.machine_type, "x64");
        assert_eq!(pe_info.sections.len(), 1);
        assert_eq!(pe_info.sections[0].name, ".text");
    }
}
