//! Cuckoo Sandbox Client Integration
//! Provides automatic sample submission, behavior report parsing, and IOC extraction

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{RwLock, Semaphore};
use serde::{Deserialize, Serialize};
use reqwest::{Client, multipart};
use tracing::info;
use uuid::Uuid;

use crate::error::AgentError;
use crate::metrics::MetricsCollector;

/// Cuckoo Sandbox client for automated malware analysis
pub struct CuckooSandboxClient {
    /// HTTP client for API communication
    client: Client,
    
    /// Cuckoo sandbox configuration
    config: CuckooConfig,
    
    /// Pending analysis tasks
    pending_tasks: Arc<RwLock<HashMap<String, AnalysisTask>>>,
    
    /// Completed analysis results
    completed_analyses: Arc<RwLock<HashMap<String, AnalysisResult>>>,
    
    /// IOC extraction engine
    ioc_extractor: Arc<IOCExtractor>,
    
    /// YARA rule generator
    yara_generator: Arc<YaraRuleGenerator>,
    
    /// Metrics collector
    metrics: Arc<MetricsCollector>,
    
    /// Rate limiting semaphore
    rate_limiter: Arc<Semaphore>,
    
    /// Analysis statistics
    stats: Arc<RwLock<AnalysisStatistics>>,
}

/// Cuckoo Sandbox configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CuckooConfig {
    /// Cuckoo API base URL
    pub api_url: String,
    
    /// API authentication token
    pub api_token: Option<String>,
    
    /// Analysis timeout (seconds)
    pub analysis_timeout: u64,
    
    /// Maximum concurrent submissions
    pub max_concurrent_submissions: usize,
    
    /// Polling interval for task status
    pub polling_interval: Duration,
    
    /// Enable automatic quarantine
    pub auto_quarantine: bool,
    
    /// Minimum confidence for quarantine
    pub quarantine_threshold: f64,
    
    /// Enable dynamic YARA rule generation
    pub enable_yara_generation: bool,
    
    /// Analysis machine tags
    pub machine_tags: Vec<String>,
    
    /// Analysis options
    pub analysis_options: HashMap<String, String>,
}

/// Analysis task information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisTask {
    /// Task ID from Cuckoo
    pub task_id: String,
    
    /// Local task UUID
    pub local_id: Uuid,
    
    /// Sample file path
    pub sample_path: PathBuf,
    
    /// Sample SHA256 hash
    pub sample_hash: String,
    
    /// Task status
    pub status: TaskStatus,
    
    /// Submission timestamp
    pub submitted_at: SystemTime,
    
    /// Analysis start timestamp
    pub started_at: Option<SystemTime>,
    
    /// Analysis completion timestamp
    pub completed_at: Option<SystemTime>,
    
    /// Analysis priority
    pub priority: AnalysisPriority,
    
    /// Analysis options
    pub options: HashMap<String, String>,
    
    /// Error message if failed
    pub error_message: Option<String>,
}

/// Task execution status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskStatus {
    /// Task is pending submission
    Pending,
    
    /// Task submitted to Cuckoo
    Submitted,
    
    /// Analysis is running
    Running,
    
    /// Analysis completed successfully
    Completed,
    
    /// Analysis failed
    Failed,
    
    /// Task was cancelled
    Cancelled,
    
    /// Results processed
    Processed,
}

/// Analysis priority levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AnalysisPriority {
    Low = 1,
    Normal = 2,
    High = 3,
    Critical = 4,
}

/// Complete analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    /// Task information
    pub task: AnalysisTask,
    
    /// Cuckoo analysis report
    pub cuckoo_report: CuckooReport,
    
    /// Extracted IOCs
    pub iocs: ExtractedIOCs,
    
    /// Generated YARA rules
    pub yara_rules: Vec<GeneratedYaraRule>,
    
    /// Threat assessment
    pub threat_assessment: ThreatAssessment,
    
    /// Quarantine decision
    pub quarantine_decision: QuarantineDecision,
    
    /// Processing timestamp
    pub processed_at: SystemTime,
}

/// Cuckoo analysis report structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CuckooReport {
    /// Analysis info
    pub info: AnalysisInfo,
    
    /// Target file information
    pub target: TargetInfo,
    
    /// Behavioral analysis
    pub behavior: BehaviorAnalysis,
    
    /// Network analysis
    pub network: NetworkAnalysis,
    
    /// Static analysis
    pub static_analysis: StaticAnalysis,
    
    /// Signatures triggered
    pub signatures: Vec<CuckooSignature>,
    
    /// Analysis score
    pub score: f64,
}

/// Analysis information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisInfo {
    pub id: u64,
    pub started: String,
    pub ended: String,
    pub duration: u64,
    pub machine: MachineInfo,
}

/// Machine information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineInfo {
    pub name: String,
    pub label: String,
    pub platform: String,
    pub tags: Vec<String>,
}

/// Target file information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetInfo {
    pub category: String,
    pub file: FileInfo,
}

/// File information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    pub name: String,
    pub path: String,
    pub size: u64,
    pub crc32: String,
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub ssdeep: Option<String>,
}

/// Behavioral analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorAnalysis {
    /// Process tree
    pub processes: Vec<ProcessInfo>,
    
    /// API calls summary
    pub apistats: HashMap<String, u64>,
    
    /// File system operations
    pub filesystem: Vec<FileOperation>,
    
    /// Registry operations
    pub registry: Vec<RegistryOperation>,
    
    /// Network operations
    pub network: Vec<NetworkOperation>,
    
    /// Mutex operations
    pub mutexes: Vec<String>,
    
    /// Services operations
    pub services: Vec<ServiceOperation>,
}

/// Process information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub command_line: String,
    pub first_seen: f64,
    pub calls: Vec<ApiCall>,
}

/// API call information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiCall {
    pub api: String,
    pub category: String,
    pub arguments: HashMap<String, String>,
    pub return_value: String,
    pub timestamp: f64,
}

/// File system operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileOperation {
    pub operation: String,
    pub path: String,
    pub timestamp: f64,
}

/// Registry operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryOperation {
    pub operation: String,
    pub key: String,
    pub value: Option<String>,
    pub data: Option<String>,
    pub timestamp: f64,
}

/// Network operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkOperation {
    pub operation: String,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub protocol: String,
    pub timestamp: f64,
}

/// Service operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceOperation {
    pub operation: String,
    pub service_name: String,
    pub timestamp: f64,
}

/// Network analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAnalysis {
    /// DNS requests
    pub dns: Vec<DnsRequest>,
    
    /// HTTP requests
    pub http: Vec<HttpRequest>,
    
    /// TCP connections
    pub tcp: Vec<TcpConnection>,
    
    /// UDP connections
    pub udp: Vec<UdpConnection>,
    
    /// Hosts contacted
    pub hosts: Vec<String>,
    
    /// Domains contacted
    pub domains: Vec<String>,
}

/// DNS request information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRequest {
    pub request: String,
    pub type_: String,
    pub answers: Vec<String>,
}

/// HTTP request information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequest {
    pub method: String,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub user_agent: String,
    pub body: String,
}

/// TCP connection information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpConnection {
    pub src: String,
    pub dst: String,
    pub sport: u16,
    pub dport: u16,
}

/// UDP connection information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpConnection {
    pub src: String,
    pub dst: String,
    pub sport: u16,
    pub dport: u16,
}

/// Static analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticAnalysis {
    /// PE analysis (if applicable)
    pub pe: Option<PeAnalysis>,
    
    /// Strings extracted
    pub strings: Vec<String>,
    
    /// Imports
    pub imports: Vec<ImportInfo>,
    
    /// Exports
    pub exports: Vec<String>,
    
    /// Resources
    pub resources: Vec<ResourceInfo>,
}

/// PE analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeAnalysis {
    pub machine: String,
    pub timestamp: String,
    pub entrypoint: String,
    pub sections: Vec<SectionInfo>,
}

/// PE section information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_address: String,
    pub virtual_size: u64,
    pub raw_size: u64,
    pub entropy: f64,
}

/// Import information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportInfo {
    pub dll: String,
    pub functions: Vec<String>,
}

/// Resource information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceInfo {
    pub name: String,
    pub offset: u64,
    pub size: u64,
}

/// Cuckoo signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CuckooSignature {
    pub name: String,
    pub description: String,
    pub severity: u8,
    pub confidence: u8,
    pub weight: u8,
    pub references: Vec<String>,
}

/// Extracted IOCs from analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedIOCs {
    /// File hashes
    pub file_hashes: HashSet<String>,
    
    /// IP addresses
    pub ip_addresses: HashSet<String>,
    
    /// Domain names
    pub domains: HashSet<String>,
    
    /// URLs
    pub urls: HashSet<String>,
    
    /// Registry keys
    pub registry_keys: HashSet<String>,
    
    /// File paths
    pub file_paths: HashSet<String>,
    
    /// Mutex names
    pub mutexes: HashSet<String>,
    
    /// Service names
    pub services: HashSet<String>,
    
    /// User agents
    pub user_agents: HashSet<String>,
    
    /// Email addresses
    pub email_addresses: HashSet<String>,
}

/// Generated YARA rule from analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratedYaraRule {
    /// Rule name
    pub name: String,
    
    /// Rule content
    pub content: String,
    
    /// Rule category
    pub category: String,
    
    /// Confidence score
    pub confidence: f64,
    
    /// Source analysis task
    pub source_task: String,
    
    /// Generation timestamp
    pub generated_at: SystemTime,
}

/// Threat assessment result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatAssessment {
    /// Overall threat score (0.0 - 1.0)
    pub threat_score: f64,
    
    /// Threat category
    pub threat_category: ThreatCategory,
    
    /// Confidence in assessment
    pub confidence: f64,
    
    /// Risk factors identified
    pub risk_factors: Vec<RiskFactor>,
    
    /// Behavioral indicators
    pub behavioral_indicators: Vec<String>,
    
    /// Recommendation
    pub recommendation: ThreatRecommendation,
}

/// Threat categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatCategory {
    Benign,
    Suspicious,
    Malicious,
    Ransomware,
    Trojan,
    Worm,
    Rootkit,
    Spyware,
    Adware,
    Unknown,
}

/// Risk factors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor {
    pub factor: String,
    pub severity: RiskSeverity,
    pub description: String,
    pub evidence: Vec<String>,
}

/// Risk severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RiskSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Threat recommendations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatRecommendation {
    Allow,
    Monitor,
    Quarantine,
    Block,
    Investigate,
}

/// Quarantine decision
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineDecision {
    /// Should quarantine the sample
    pub should_quarantine: bool,
    
    /// Decision confidence
    pub confidence: f64,
    
    /// Reasoning for decision
    pub reasoning: Vec<String>,
    
    /// Quarantine action taken
    pub action_taken: Option<QuarantineAction>,
    
    /// Decision timestamp
    pub decided_at: SystemTime,
}

/// Quarantine actions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum QuarantineAction {
    Isolated,
    Deleted,
    Moved,
    Encrypted,
    Blocked,
}

/// IOC extraction engine
pub struct IOCExtractor {
    /// Regex patterns for IOC extraction
    patterns: HashMap<String, regex::Regex>,
    
    /// IOC validation rules
    validation_rules: HashMap<String, Box<dyn Fn(&str) -> bool + Send + Sync>>,
}

/// YARA rule generator
pub struct YaraRuleGenerator {
    /// Rule templates
    templates: HashMap<String, String>,
    
    /// Generation statistics
    stats: Arc<RwLock<GenerationStats>>,
}

/// Generation statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GenerationStats {
    pub rules_generated: usize,
    pub successful_generations: usize,
    pub failed_generations: usize,
    pub avg_generation_time_ms: f64,
}

/// Analysis statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnalysisStatistics {
    /// Total analyses submitted
    pub total_submitted: usize,
    
    /// Completed analyses
    pub completed: usize,
    
    /// Failed analyses
    pub failed: usize,
    
    /// Average analysis time
    pub avg_analysis_time_seconds: f64,
    
    /// Quarantine rate
    pub quarantine_rate: f64,
    
    /// Threat detection rate
    pub threat_detection_rate: f64,
    
    /// IOCs extracted
    pub total_iocs_extracted: usize,
    
    /// YARA rules generated
    pub yara_rules_generated: usize,
}

impl Default for CuckooConfig {
    fn default() -> Self {
        Self {
            api_url: "http://localhost:8090".to_string(),
            api_token: None,
            analysis_timeout: 300, // 5 minutes
            max_concurrent_submissions: 5,
            polling_interval: Duration::from_secs(10),
            auto_quarantine: true,
            quarantine_threshold: 0.7,
            enable_yara_generation: true,
            machine_tags: vec!["windows10".to_string()],
            analysis_options: HashMap::new(),
        }
    }
}

impl CuckooSandboxClient {
    /// Create a new Cuckoo Sandbox client
    pub fn new(config: CuckooConfig, metrics: Arc<MetricsCollector>) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(config.analysis_timeout))
            .build()
            .expect("Failed to create HTTP client");
        
        let rate_limiter = Arc::new(Semaphore::new(config.max_concurrent_submissions));
        
        Self {
            client,
            config,
            pending_tasks: Arc::new(RwLock::new(HashMap::new())),
            completed_analyses: Arc::new(RwLock::new(HashMap::new())),
            ioc_extractor: Arc::new(IOCExtractor::new()),
            yara_generator: Arc::new(YaraRuleGenerator::new()),
            metrics,
            rate_limiter,
            stats: Arc::new(RwLock::new(AnalysisStatistics::default())),
        }
    }
    
    /// Initialize the Cuckoo client
    pub async fn initialize(&self) -> Result<(), AgentError> {
        info!("Initializing Cuckoo Sandbox client");
        
        // Test connection to Cuckoo API
        self.test_connection().await?;
        
        // Initialize IOC extractor
        self.ioc_extractor.initialize().await?;
        
        // Initialize YARA generator
        self.yara_generator.initialize().await?;
        
        info!("Cuckoo Sandbox client initialized successfully");
        Ok(())
    }
    
    /// Submit a sample for analysis
    pub async fn submit_sample<P: AsRef<Path>>(
        &self,
        sample_path: P,
        priority: AnalysisPriority,
        options: Option<HashMap<String, String>>,
    ) -> Result<Uuid, AgentError> {
        let sample_path = sample_path.as_ref().to_path_buf();
        let local_id = Uuid::new_v4();
        
        info!("Submitting sample for analysis: {:?}", sample_path);
        
        // Acquire rate limiting permit
        let _permit = self.rate_limiter.acquire().await
            .map_err(|e| AgentError::Resource {
                message: format!("Rate limit error: {}", e),
                resource_type: "rate_limiter".to_string(),
                current_usage: None,
                limit: None,
                context: None,
            })?;
        
        // Calculate sample hash
        let sample_hash = self.calculate_file_hash(&sample_path).await?;
        
        // Check if sample was already analyzed recently
        if let Some(existing_result) = self.check_existing_analysis(&sample_hash).await? {
            info!("Sample already analyzed, returning existing result");
            return Ok(existing_result);
        }
        
        // Create analysis task
        let mut task = AnalysisTask {
            task_id: String::new(), // Will be set after submission
            local_id,
            sample_path: sample_path.clone(),
            sample_hash,
            status: TaskStatus::Pending,
            submitted_at: SystemTime::now(),
            started_at: None,
            completed_at: None,
            priority,
            options: options.unwrap_or_default(),
            error_message: None,
        };
        
        // Submit to Cuckoo
        let task_id = self.submit_to_cuckoo(&sample_path, &task.options).await?;
        task.task_id = task_id;
        task.status = TaskStatus::Submitted;
        
        // Store pending task
        let mut pending = self.pending_tasks.write().await;
        pending.insert(local_id.to_string(), task);
        
        // Update statistics
        let mut stats = self.stats.write().await;
        stats.total_submitted += 1;
        
        info!("Sample submitted successfully with task ID: {}", local_id);
        Ok(local_id)
    }
    
    /// Get analysis result
    pub async fn get_analysis_result(&self, task_id: Uuid) -> Result<Option<AnalysisResult>, AgentError> {
        // Check completed analyses first
        let completed = self.completed_analyses.read().await;
        if let Some(result) = completed.get(&task_id.to_string()) {
            return Ok(Some(result.clone()));
        }
        drop(completed);
        
        // Check pending tasks
        let mut pending = self.pending_tasks.write().await;
        if let Some(task) = pending.get_mut(&task_id.to_string()) {
            // Poll Cuckoo for status update
            self.update_task_status(task).await?;
            
            if task.status == TaskStatus::Completed {
                // Process the completed analysis
                let result = self.process_completed_analysis(task).await?;
                
                // Move to completed analyses
                pending.remove(&task_id.to_string());
                let mut completed = self.completed_analyses.write().await;
                completed.insert(task_id.to_string(), result.clone());
                
                return Ok(Some(result));
            }
        }
        
        Ok(None)
    }
    
    /// Process completed analysis
    async fn process_completed_analysis(&self, task: &AnalysisTask) -> Result<AnalysisResult, AgentError> {
        info!("Processing completed analysis for task: {}", task.task_id);
        
        // Fetch Cuckoo report
        let cuckoo_report = self.fetch_cuckoo_report(&task.task_id).await?;
        
        // Extract IOCs
        let iocs = self.ioc_extractor.extract_iocs(&cuckoo_report).await?;
        
        // Generate YARA rules if enabled
        let yara_rules = if self.config.enable_yara_generation {
            self.yara_generator.generate_rules(&cuckoo_report, &iocs).await?
        } else {
            Vec::new()
        };
        
        // Perform threat assessment
        let threat_assessment = self.assess_threat(&cuckoo_report, &iocs).await?;
        
        // Make quarantine decision
        let quarantine_decision = self.make_quarantine_decision(&threat_assessment).await?;
        
        // Execute quarantine if needed
        if quarantine_decision.should_quarantine && self.config.auto_quarantine {
            self.execute_quarantine(&task.sample_path, &quarantine_decision).await?;
        }
        
        let result = AnalysisResult {
            task: task.clone(),
            cuckoo_report,
            iocs,
            yara_rules,
            threat_assessment,
            quarantine_decision,
            processed_at: SystemTime::now(),
        };
        
        // Update statistics
        let mut stats = self.stats.write().await;
        stats.completed += 1;
        stats.total_iocs_extracted += result.iocs.file_hashes.len() + 
                                     result.iocs.ip_addresses.len() + 
                                     result.iocs.domains.len();
        stats.yara_rules_generated += result.yara_rules.len();
        
        if result.quarantine_decision.should_quarantine {
            stats.quarantine_rate = (stats.quarantine_rate * (stats.completed - 1) as f64 + 1.0) / stats.completed as f64;
        }
        
        info!("Analysis processing completed for task: {}", task.task_id);
        Ok(result)
    }
    
    /// Test connection to Cuckoo API
    async fn test_connection(&self) -> Result<(), AgentError> {
        let url = format!("{}/cuckoo/status", self.config.api_url);
        
        let mut request = self.client.get(&url);
        if let Some(token) = &self.config.api_token {
            request = request.header("Authorization", format!("Bearer {}", token));
        }
        
        let response = request.send().await
            .map_err(|e| AgentError::Network { 
                message: format!("Failed to connect to Cuckoo: {}", e),
                endpoint: Some(self.config.api_url.clone()),
                retry_count: 0,
                context: None,
            })?;
        
        if !response.status().is_success() {
            return Err(AgentError::Network { message: format!("Cuckoo API returned status: {}", response.status()),
                endpoint: Some(self.config.api_url.clone()),
                retry_count: 0,
                context: None,
            });
        }
        
        info!("Successfully connected to Cuckoo Sandbox");
        Ok(())
    }
    
    /// Submit sample to Cuckoo
    async fn submit_to_cuckoo(
        &self,
        sample_path: &Path,
        options: &HashMap<String, String>,
    ) -> Result<String, AgentError> {
        let url = format!("{}/tasks/create/file", self.config.api_url);
        
        // Read file content
        let file_content = tokio::fs::read(sample_path).await
            .map_err(|e| AgentError::Io {
                message: format!("Failed to read sample file: {}", e),
                path: Some(sample_path.to_path_buf()),
                operation: Some("read".to_string()),
                context: None,
            })?;
        
        // Create multipart form
        let file_name = sample_path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("sample.bin");
        
        let file_part = multipart::Part::bytes(file_content)
            .file_name(file_name.to_string())
            .mime_str("application/octet-stream")
            .map_err(|e| AgentError::Configuration {
                message: format!("Failed to create file part: {}", e),
                field: Some("multipart_form".to_string()),
                context: None,
            })?;
        
        let mut form = multipart::Form::new().part("file", file_part);
        
        // Add analysis options
        for (key, value) in options {
            form = form.text(key.clone(), value.clone());
        }
        
        // Add machine tags
        if !self.config.machine_tags.is_empty() {
            form = form.text("tags", self.config.machine_tags.join(","));
        }
        
        // Send request
        let mut request = self.client.post(&url).multipart(form);
        if let Some(token) = &self.config.api_token {
            request = request.header("Authorization", format!("Bearer {}", token));
        }
        
        let response = request.send().await
            .map_err(|e| AgentError::Network { 
                message: format!("Failed to submit sample: {}", e),
                endpoint: Some(self.config.api_url.clone()),
                retry_count: 0,
                context: None
            })?;
        
        if !response.status().is_success() {
            return Err(AgentError::Network { 
                message: format!("Cuckoo submission failed with status: {}", response.status()),
                endpoint: Some(self.config.api_url.clone()),
                retry_count: 0,
                context: None
            });
        }
        
        let response_json: serde_json::Value = response.json().await
            .map_err(|e| AgentError::Parse {
                message: format!("Failed to parse submission response: {}", e),
                input: Some("cuckoo_response".to_string()),
                position: None,
                context: None,
            })?;

        let task_id = response_json["task_id"]
            .as_u64()
            .ok_or_else(|| AgentError::Parse {
                message: "Missing task_id in response".to_string(),
                input: Some("task_id".to_string()),
                position: None,
                context: None,
            })?;
        
        Ok(task_id.to_string())
    }
    
    /// Update task status from Cuckoo
    async fn update_task_status(&self, task: &mut AnalysisTask) -> Result<(), AgentError> {
        let url = format!("{}/tasks/view/{}", self.config.api_url, task.task_id);
        
        let mut request = self.client.get(&url);
        if let Some(token) = &self.config.api_token {
            request = request.header("Authorization", format!("Bearer {}", token));
        }
        
        let response = request.send().await
            .map_err(|e| AgentError::Network { 
                message: format!("Failed to get task status: {}", e),
                endpoint: Some(self.config.api_url.clone()),
                retry_count: 0,
                context: None
            })?;
        
        if !response.status().is_success() {
            return Err(AgentError::Network { 
                message: format!("Failed to get task status: {}", response.status()),
                endpoint: Some(self.config.api_url.clone()),
                retry_count: 0,
                context: None
            });
        }
        
        let task_info: serde_json::Value = response.json().await
            .map_err(|e| AgentError::Parse {
                message: format!("Failed to parse task status: {}", e),
                input: Some("task_status".to_string()),
                position: None,
                context: None,
            })?;
        
        let status = task_info["task"]["status"]
            .as_str()
            .unwrap_or("unknown");
        
        task.status = match status {
            "pending" => TaskStatus::Submitted,
            "running" => {
                if task.started_at.is_none() {
                    task.started_at = Some(SystemTime::now());
                }
                TaskStatus::Running
            }
            "completed" => {
                task.completed_at = Some(SystemTime::now());
                TaskStatus::Completed
            }
            "reported" => TaskStatus::Completed,
            _ => TaskStatus::Failed,
        };
        
        Ok(())
    }
    
    /// Fetch Cuckoo analysis report
    async fn fetch_cuckoo_report(&self, task_id: &str) -> Result<CuckooReport, AgentError> {
        let url = format!("{}/tasks/report/{}/json", self.config.api_url, task_id);
        
        let mut request = self.client.get(&url);
        if let Some(token) = &self.config.api_token {
            request = request.header("Authorization", format!("Bearer {}", token));
        }
        
        let response = request.send().await
            .map_err(|e| AgentError::Network { 
                message: format!("Failed to fetch report: {}", e),
                endpoint: Some(self.config.api_url.clone()),
                retry_count: 0,
                context: None
            })?;
        
        if !response.status().is_success() {
            return Err(AgentError::Network { 
                message: format!("Failed to fetch report: {}", response.status()),
                endpoint: Some(self.config.api_url.clone()),
                retry_count: 0,
                context: None
            });
        }
        
        let report: CuckooReport = response.json().await
            .map_err(|e| AgentError::Parse {
                message: format!("Failed to parse report: {}", e),
                input: Some("cuckoo_report".to_string()),
                position: None,
                context: None,
            })?;
        
        Ok(report)
    }
    
    /// Calculate file hash
    async fn calculate_file_hash(&self, path: &Path) -> Result<String, AgentError> {
        use sha2::{Sha256, Digest};
        
        let content = tokio::fs::read(path).await
            .map_err(|e| AgentError::Io {
                message: format!("Failed to read file: {}", e),
                path: Some(path.to_path_buf()),
                operation: Some("read".to_string()),
                context: None,
            })?;
        
        let mut hasher = Sha256::new();
        hasher.update(&content);
        let hash = hasher.finalize();
        
        Ok(format!("{:x}", hash))
    }
    
    /// Check for existing analysis
    async fn check_existing_analysis(&self, hash: &str) -> Result<Option<Uuid>, AgentError> {
        // Check completed analyses for matching hash
        let completed = self.completed_analyses.read().await;
        for (id, result) in completed.iter() {
            if result.task.sample_hash == hash {
                return Ok(Some(Uuid::parse_str(id).unwrap_or_default()));
            }
        }
        
        Ok(None)
    }
    
    /// Assess threat level
    async fn assess_threat(
        &self,
        report: &CuckooReport,
        iocs: &ExtractedIOCs,
    ) -> Result<ThreatAssessment, AgentError> {
        let mut threat_score = 0.0;
        let mut risk_factors = Vec::new();
        let mut behavioral_indicators = Vec::new();
        
        // Base score from Cuckoo
        threat_score += report.score / 10.0; // Normalize to 0-1
        
        // Signature-based scoring
        for signature in &report.signatures {
            let signature_score = (signature.severity as f64 * signature.confidence as f64) / 100.0;
            threat_score += signature_score * 0.1;
            
            risk_factors.push(RiskFactor {
                factor: signature.name.clone(),
                severity: match signature.severity {
                    1..=3 => RiskSeverity::Low,
                    4..=6 => RiskSeverity::Medium,
                    7..=8 => RiskSeverity::High,
                    _ => RiskSeverity::Critical,
                },
                description: signature.description.clone(),
                evidence: signature.references.clone(),
            });
        }
        
        // IOC-based scoring
        if !iocs.ip_addresses.is_empty() {
            threat_score += 0.2;
            behavioral_indicators.push("Network communication detected".to_string());
        }
        
        if !iocs.registry_keys.is_empty() {
            threat_score += 0.15;
            behavioral_indicators.push("Registry modifications detected".to_string());
        }
        
        if !iocs.file_paths.is_empty() {
            threat_score += 0.1;
            behavioral_indicators.push("File system modifications detected".to_string());
        }
        
        // Behavioral analysis scoring
        if !report.behavior.processes.is_empty() {
            threat_score += 0.1;
            behavioral_indicators.push("Process execution detected".to_string());
        }
        
        // Normalize threat score
        threat_score = threat_score.min(1.0);
        
        // Determine threat category
        let threat_category = match threat_score {
            s if s >= 0.8 => ThreatCategory::Malicious,
            s if s >= 0.6 => ThreatCategory::Suspicious,
            _ => ThreatCategory::Benign,
        };
        
        // Determine recommendation
        let recommendation = match threat_score {
            s if s >= 0.8 => ThreatRecommendation::Quarantine,
            s if s >= 0.6 => ThreatRecommendation::Monitor,
            s if s >= 0.4 => ThreatRecommendation::Investigate,
            _ => ThreatRecommendation::Allow,
        };
        
        Ok(ThreatAssessment {
            threat_score,
            threat_category,
            confidence: 0.85, // Base confidence
            risk_factors,
            behavioral_indicators,
            recommendation,
        })
    }
    
    /// Make quarantine decision
    async fn make_quarantine_decision(
        &self,
        assessment: &ThreatAssessment,
    ) -> Result<QuarantineDecision, AgentError> {
        let should_quarantine = assessment.threat_score >= self.config.quarantine_threshold;
        
        let mut reasoning = Vec::new();
        
        if should_quarantine {
            reasoning.push(format!("Threat score ({:.2}) exceeds threshold ({:.2})", 
                                 assessment.threat_score, self.config.quarantine_threshold));
            
            for factor in &assessment.risk_factors {
                if matches!(factor.severity, RiskSeverity::High | RiskSeverity::Critical) {
                    reasoning.push(format!("High-risk factor detected: {}", factor.factor));
                }
            }
        } else {
            reasoning.push(format!("Threat score ({:.2}) below threshold ({:.2})", 
                                 assessment.threat_score, self.config.quarantine_threshold));
        }
        
        Ok(QuarantineDecision {
            should_quarantine,
            confidence: assessment.confidence,
            reasoning,
            action_taken: None,
            decided_at: SystemTime::now(),
        })
    }
    
    /// Execute quarantine action
    async fn execute_quarantine(
        &self,
        sample_path: &Path,
        _decision: &QuarantineDecision,
    ) -> Result<(), AgentError> {
        info!("Executing quarantine for sample: {:?}", sample_path);
        
        // For now, just move to quarantine directory
        let quarantine_dir = Path::new("quarantine");
        tokio::fs::create_dir_all(quarantine_dir).await
            .map_err(|e| AgentError::Io {
                message: format!("Failed to create quarantine directory: {}", e),
                path: Some(quarantine_dir.to_path_buf()),
                operation: Some("create_dir_all".to_string()),
                context: None,
            })?;
        
        let quarantine_path = quarantine_dir.join(
            sample_path.file_name().unwrap_or_default()
        );
        
        tokio::fs::rename(sample_path, &quarantine_path).await
            .map_err(|e| AgentError::Io {
                message: format!("Failed to quarantine file: {}", e),
                path: Some(sample_path.to_path_buf()),
                operation: Some("rename".to_string()),
                context: None,
            })?;
        
        info!("Sample quarantined to: {:?}", quarantine_path);
        Ok(())
    }
    
    /// Get analysis statistics
    pub async fn get_statistics(&self) -> AnalysisStatistics {
        self.stats.read().await.clone()
    }
    
    /// Get pending tasks count
    pub async fn get_pending_count(&self) -> usize {
        self.pending_tasks.read().await.len()
    }
    
    /// Get completed analyses count
    pub async fn get_completed_count(&self) -> usize {
        self.completed_analyses.read().await.len()
    }
}

impl IOCExtractor {
    /// Create a new IOC extractor
    pub fn new() -> Self {
        Self {
            patterns: HashMap::new(),
            validation_rules: HashMap::new(),
        }
    }
    
    /// Initialize the IOC extractor
    pub async fn initialize(&self) -> Result<(), AgentError> {
        info!("Initializing IOC extractor");
        // Initialize regex patterns and validation rules
        Ok(())
    }
    
    /// Extract IOCs from Cuckoo report
    pub async fn extract_iocs(&self, report: &CuckooReport) -> Result<ExtractedIOCs, AgentError> {
        let mut iocs = ExtractedIOCs {
            file_hashes: HashSet::new(),
            ip_addresses: HashSet::new(),
            domains: HashSet::new(),
            urls: HashSet::new(),
            registry_keys: HashSet::new(),
            file_paths: HashSet::new(),
            mutexes: HashSet::new(),
            services: HashSet::new(),
            user_agents: HashSet::new(),
            email_addresses: HashSet::new(),
        };
        
        // Extract from network analysis
        for host in &report.network.hosts {
            if self.is_valid_ip(host) {
                iocs.ip_addresses.insert(host.clone());
            }
        }
        
        for domain in &report.network.domains {
            iocs.domains.insert(domain.clone());
        }
        
        for http_req in &report.network.http {
            let url = format!("http://{}:{}{}", http_req.host, http_req.port, http_req.path);
            iocs.urls.insert(url);
            
            if !http_req.user_agent.is_empty() {
                iocs.user_agents.insert(http_req.user_agent.clone());
            }
        }
        
        // Extract from behavioral analysis
        for reg_op in &report.behavior.registry {
            iocs.registry_keys.insert(reg_op.key.clone());
        }
        
        for file_op in &report.behavior.filesystem {
            iocs.file_paths.insert(file_op.path.clone());
        }
        
        for mutex in &report.behavior.mutexes {
            iocs.mutexes.insert(mutex.clone());
        }
        
        for service in &report.behavior.services {
            iocs.services.insert(service.service_name.clone());
        }
        
        // Extract file hashes
        iocs.file_hashes.insert(report.target.file.md5.clone());
        iocs.file_hashes.insert(report.target.file.sha1.clone());
        iocs.file_hashes.insert(report.target.file.sha256.clone());
        
        Ok(iocs)
    }
    
    /// Validate IP address
    fn is_valid_ip(&self, ip: &str) -> bool {
        ip.parse::<std::net::IpAddr>().is_ok()
    }
}

impl YaraRuleGenerator {
    /// Create a new YARA rule generator
    pub fn new() -> Self {
        Self {
            templates: HashMap::new(),
            stats: Arc::new(RwLock::new(GenerationStats::default())),
        }
    }
    
    /// Initialize the YARA rule generator
    pub async fn initialize(&self) -> Result<(), AgentError> {
        info!("Initializing YARA rule generator");
        // Load rule templates
        Ok(())
    }
    
    /// Generate YARA rules from analysis
    pub async fn generate_rules(
        &self,
        report: &CuckooReport,
        iocs: &ExtractedIOCs,
    ) -> Result<Vec<GeneratedYaraRule>, AgentError> {
        let mut rules = Vec::new();
        
        // Generate rule based on signatures
        if !report.signatures.is_empty() {
            let rule = self.generate_signature_rule(report).await?;
            rules.push(rule);
        }
        
        // Generate rule based on IOCs
        if !iocs.ip_addresses.is_empty() || !iocs.domains.is_empty() {
            let rule = self.generate_network_rule(iocs).await?;
            rules.push(rule);
        }
        
        // Update statistics
        let mut stats = self.stats.write().await;
        stats.rules_generated += rules.len();
        stats.successful_generations += 1;
        
        Ok(rules)
    }
    
    /// Generate rule from signatures
    async fn generate_signature_rule(&self, report: &CuckooReport) -> Result<GeneratedYaraRule, AgentError> {
        let rule_name = format!("cuckoo_signature_{}", report.info.id);
        
        let mut conditions = Vec::new();
        for signature in &report.signatures {
            if signature.confidence >= 80 {
                conditions.push(format!("// Signature: {}", signature.name));
            }
        }
        
        let rule_content = format!(
            r#"rule {} {{
    meta:
        author = "ERDPS Cuckoo Integration"
        description = "Generated from Cuckoo analysis"
        date = "{}"
        
    condition:
        true // Placeholder - implement actual conditions
}}
"#,
            rule_name,
            chrono::Utc::now().format("%Y-%m-%d")
        );
        
        Ok(GeneratedYaraRule {
            name: rule_name,
            content: rule_content,
            category: "behavioral".to_string(),
            confidence: 0.8,
            source_task: report.info.id.to_string(),
            generated_at: SystemTime::now(),
        })
    }
    
    /// Generate rule from network IOCs
    async fn generate_network_rule(&self, iocs: &ExtractedIOCs) -> Result<GeneratedYaraRule, AgentError> {
        let rule_name = format!("network_iocs_{}", 
                               SystemTime::now().duration_since(UNIX_EPOCH)
                                   .unwrap_or_default().as_secs());
        
        let mut strings = Vec::new();
        let mut conditions = Vec::new();
        
        // Add IP addresses
        for (i, ip) in iocs.ip_addresses.iter().enumerate().take(10) {
            strings.push(format!("        $ip{} = \"{}\" ascii", i, ip));
            conditions.push(format!("$ip{}", i));
        }
        
        // Add domains
        for (i, domain) in iocs.domains.iter().enumerate().take(10) {
            strings.push(format!("        $domain{} = \"{}\" ascii", i, domain));
            conditions.push(format!("$domain{}", i));
        }
        
        let rule_content = format!(
            r#"rule {} {{
    meta:
        author = "ERDPS Cuckoo Integration"
        description = "Network IOCs from dynamic analysis"
        date = "{}"
        
    strings:
{}
        
    condition:
        any of ({})
}}
"#,
            rule_name,
            chrono::Utc::now().format("%Y-%m-%d"),
            strings.join("\n"),
            conditions.join(", ")
        );
        
        Ok(GeneratedYaraRule {
            name: rule_name,
            content: rule_content,
            category: "network".to_string(),
            confidence: 0.75,
            source_task: "network_analysis".to_string(),
            generated_at: SystemTime::now(),
        })
    }
}
