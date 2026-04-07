//! Cuckoo Sandbox integration for automated malware analysis
//! Provides dynamic analysis capabilities and automatic YARA rule generation

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use reqwest::Client;
use tracing::{debug, info, warn};

use crate::error::AgentError;
use crate::metrics::MetricsCollector;

/// Cuckoo Sandbox analysis request
#[derive(Debug, Clone, Serialize)]
pub struct AnalysisRequest {
    pub file_path: PathBuf,
    pub file_hash: String,
    pub priority: AnalysisPriority,
    pub timeout: u32,
    pub options: AnalysisOptions,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AnalysisPriority {
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisOptions {
    pub enable_memory: bool,
    pub enable_network: bool,
    pub enable_screenshots: bool,
    pub enable_procmon: bool,
    pub custom_timeout: Option<u32>,
    pub machine: Option<String>,
    pub package: Option<String>,
}

impl Default for AnalysisOptions {
    fn default() -> Self {
        Self {
            enable_memory: true,
            enable_network: true,
            enable_screenshots: true,
            enable_procmon: true,
            custom_timeout: None,
            machine: None,
            package: None,
        }
    }
}

/// Cuckoo Sandbox analysis result
#[derive(Debug, Clone, Deserialize)]
pub struct AnalysisResult {
    pub task_id: u32,
    pub status: AnalysisStatus,
    pub score: f64,
    pub target: AnalysisTarget,
    pub behavior: BehaviorAnalysis,
    pub network: NetworkAnalysis,
    pub signatures: Vec<Signature>,
    pub dropped_files: Vec<DroppedFile>,
    pub registry_keys: Vec<RegistryKey>,
    pub mutexes: Vec<String>,
    pub yara_rules: Vec<YaraRule>,
    pub screenshots: Vec<String>,
    pub analysis_time: Duration,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub enum AnalysisStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Timeout,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AnalysisTarget {
    pub file_name: String,
    pub file_path: String,
    pub file_size: u64,
    pub file_type: String,
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub ssdeep: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BehaviorAnalysis {
    pub processes: Vec<ProcessBehavior>,
    pub api_calls: Vec<ApiCall>,
    pub file_operations: Vec<FileOperation>,
    pub registry_operations: Vec<RegistryOperation>,
    pub network_operations: Vec<NetworkOperation>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProcessBehavior {
    pub pid: u32,
    pub ppid: u32,
    pub process_name: String,
    pub command_line: String,
    pub first_seen: String,
    pub calls: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApiCall {
    pub api: String,
    pub status: bool,
    pub return_value: String,
    pub arguments: HashMap<String, String>,
    pub repeated: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FileOperation {
    pub operation: String,
    pub file_path: String,
    pub status: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RegistryOperation {
    pub operation: String,
    pub key: String,
    pub value: Option<String>,
    pub data: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NetworkOperation {
    pub protocol: String,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub data: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NetworkAnalysis {
    pub hosts: Vec<String>,
    pub domains: Vec<String>,
    pub http_requests: Vec<HttpRequest>,
    pub dns_requests: Vec<DnsRequest>,
    pub tcp_connections: Vec<TcpConnection>,
    pub udp_connections: Vec<UdpConnection>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HttpRequest {
    pub method: String,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub user_agent: Option<String>,
    pub body: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DnsRequest {
    pub request: String,
    pub type_: String,
    pub answers: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TcpConnection {
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UdpConnection {
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Signature {
    pub name: String,
    pub description: String,
    pub severity: u8,
    pub confidence: f64,
    pub references: Vec<String>,
    pub marks: Vec<SignatureMark>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SignatureMark {
    pub call: ApiCall,
    pub description: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DroppedFile {
    pub name: String,
    pub path: String,
    pub size: u64,
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub file_type: String,
    pub yara_matches: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RegistryKey {
    pub key: String,
    pub values: HashMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct YaraRule {
    pub name: String,
    pub meta: HashMap<String, String>,
    pub strings: Vec<YaraString>,
    pub condition: String,
    pub matches: Vec<YaraMatch>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct YaraString {
    pub identifier: String,
    pub value: String,
    pub type_: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct YaraMatch {
    pub rule: String,
    pub strings: Vec<String>,
    pub offset: u64,
}

/// Quarantine decision based on analysis
#[derive(Debug, Clone, PartialEq)]
pub enum QuarantineDecision {
    Allow,
    Quarantine,
    Block,
    Monitor,
}

/// Cuckoo Sandbox client
pub struct CuckooSandboxClient {
    base_url: String,
    api_key: Option<String>,
    client: Client,
    pending_analyses: Arc<RwLock<HashMap<u32, AnalysisRequest>>>,
    completed_analyses: Arc<RwLock<HashMap<u32, AnalysisResult>>>,
    metrics: Arc<MetricsCollector>,
    analysis_timeout: Duration,
    max_concurrent_analyses: usize,
}

impl CuckooSandboxClient {
    /// Create a new Cuckoo Sandbox client
    pub fn new(
        base_url: String,
        api_key: Option<String>,
        metrics: Arc<MetricsCollector>,
    ) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(300))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            base_url,
            api_key,
            client,
            pending_analyses: Arc::new(RwLock::new(HashMap::new())),
            completed_analyses: Arc::new(RwLock::new(HashMap::new())),
            metrics,
            analysis_timeout: Duration::from_secs(300), // 5 minutes default
            max_concurrent_analyses: 10,
        }
    }

    /// Create a new Cuckoo Sandbox client with lazy initialization (for performance)
    pub fn new_lazy(
        base_url: String,
        api_key: Option<String>,
        metrics: Arc<MetricsCollector>,
    ) -> Self {
        // Defer HTTP client creation to first use
        Self {
            base_url,
            api_key,
            client: Client::new(), // Use default client for faster initialization
            pending_analyses: Arc::new(RwLock::new(HashMap::new())),
            completed_analyses: Arc::new(RwLock::new(HashMap::new())),
            metrics,
            analysis_timeout: Duration::from_secs(300),
            max_concurrent_analyses: 10,
        }
    }

    /// Create stub Cuckoo Sandbox client for performance testing (no functionality)
    pub fn new_stub() -> Self {
        use crate::metrics::{MetricsCollector, MetricsDatabase};
        let stub_metrics = Arc::new(MetricsCollector::new(
            MetricsDatabase::new(":memory:").unwrap()
        ));
        
        Self {
            base_url: "http://localhost:8090".to_string(),
            api_key: None,
            client: Client::new(),
            pending_analyses: Arc::new(RwLock::new(HashMap::new())),
            completed_analyses: Arc::new(RwLock::new(HashMap::new())),
            metrics: stub_metrics,
            analysis_timeout: Duration::from_secs(300),
            max_concurrent_analyses: 10,
        }
    }

    /// Submit a file for analysis
    pub async fn submit_analysis(&self, request: AnalysisRequest) -> Result<u32, AgentError> {
        info!("Submitting file for Cuckoo analysis: {:?}", request.file_path);

        // Check if we're at the concurrent analysis limit
        let pending_count = self.pending_analyses.read().await.len();
        if pending_count >= self.max_concurrent_analyses {
            return Err(AgentError::SystemError(
                "Maximum concurrent analyses reached".to_string(),
            ));
        }

        // Simulate task submission (in real implementation, use Cuckoo REST API)
        let task_id = self.simulate_task_submission(&request).await?;

        // Store pending analysis
        self.pending_analyses.write().await.insert(task_id, request);

        // Start monitoring the analysis
        self.start_analysis_monitoring(task_id).await;

        self.metrics.record_counter("sandbox_submissions_total", 1.0);
        Ok(task_id)
    }

    /// Simulate task submission to Cuckoo Sandbox
    async fn simulate_task_submission(&self, _request: &AnalysisRequest) -> Result<u32, AgentError> {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        
        // Simulate API call delay
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        // Generate random task ID
        let task_id = rng.gen_range(1000..9999);
        
        info!("Simulated Cuckoo task submission: ID {}", task_id);
        Ok(task_id)
    }

    /// Start monitoring an analysis task
    async fn start_analysis_monitoring(&self, task_id: u32) {
        let pending_analyses = Arc::clone(&self.pending_analyses);
        let completed_analyses = Arc::clone(&self.completed_analyses);
        let metrics = Arc::clone(&self.metrics);
        let timeout = self.analysis_timeout;

        tokio::spawn(async move {
            let start_time = Instant::now();
            let mut interval = tokio::time::interval(Duration::from_secs(10));

            loop {
                interval.tick().await;

                // Check for timeout
                if start_time.elapsed() > timeout {
                    warn!("Analysis {} timed out", task_id);
                    pending_analyses.write().await.remove(&task_id);
                    metrics.record_counter("sandbox_timeouts_total", 1.0);
                    break;
                }

                // Simulate analysis completion
                if Self::simulate_analysis_completion().await {
                    info!("Analysis {} completed", task_id);
                    
                    if let Some(request) = pending_analyses.write().await.remove(&task_id) {
                        let result = Self::simulate_analysis_result(task_id, &request).await;
                        completed_analyses.write().await.insert(task_id, result);
                        metrics.record_counter("sandbox_completions_total", 1.0);
                    }
                    break;
                }
            }
        });
    }

    /// Simulate analysis completion
    async fn simulate_analysis_completion() -> bool {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        rng.gen::<f64>() < 0.3 // 30% chance per check
    }

    /// Simulate analysis result generation
    async fn simulate_analysis_result(task_id: u32, request: &AnalysisRequest) -> AnalysisResult {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        
        let score = rng.gen_range(0.0..10.0);
        let is_malicious = score > 7.0;
        
        AnalysisResult {
            task_id,
            status: AnalysisStatus::Completed,
            score,
            target: AnalysisTarget {
                file_name: request.file_path.file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string(),
                file_path: request.file_path.to_string_lossy().to_string(),
                file_size: 1024000,
                file_type: "PE32 executable".to_string(),
                md5: request.file_hash.clone(),
                sha1: format!("sha1_{}", request.file_hash),
                sha256: format!("sha256_{}", request.file_hash),
                ssdeep: Some(format!("ssdeep_{}", request.file_hash)),
            },
            behavior: BehaviorAnalysis {
                processes: vec![
                    ProcessBehavior {
                        pid: 1234,
                        ppid: 456,
                        process_name: "malware.exe".to_string(),
                        command_line: "malware.exe -encrypt".to_string(),
                        first_seen: "2024-01-01T12:00:00Z".to_string(),
                        calls: 150,
                    }
                ],
                api_calls: if is_malicious {
                    vec![
                        ApiCall {
                            api: "CryptAcquireContextW".to_string(),
                            status: true,
                            return_value: "0x1".to_string(),
                            arguments: HashMap::from([
                                ("dwProvType".to_string(), "PROV_RSA_FULL".to_string()),
                            ]),
                            repeated: 1,
                        },
                        ApiCall {
                            api: "CryptGenKey".to_string(),
                            status: true,
                            return_value: "0x1".to_string(),
                            arguments: HashMap::from([
                                ("Algid".to_string(), "CALG_AES_256".to_string()),
                            ]),
                            repeated: 1,
                        },
                    ]
                } else {
                    vec![]
                },
                file_operations: if is_malicious {
                    vec![
                        FileOperation {
                            operation: "CreateFileW".to_string(),
                            file_path: "C:\\Users\\victim\\Documents\\important.docx".to_string(),
                            status: true,
                        },
                        FileOperation {
                            operation: "WriteFile".to_string(),
                            file_path: "C:\\Users\\victim\\Documents\\important.docx.encrypted".to_string(),
                            status: true,
                        },
                    ]
                } else {
                    vec![]
                },
                registry_operations: vec![],
                network_operations: vec![],
            },
            network: NetworkAnalysis {
                hosts: if is_malicious {
                    vec!["malicious-c2.com".to_string()]
                } else {
                    vec![]
                },
                domains: vec![],
                http_requests: vec![],
                dns_requests: vec![],
                tcp_connections: vec![],
                udp_connections: vec![],
            },
            signatures: if is_malicious {
                vec![
                    Signature {
                        name: "ransomware_behavior".to_string(),
                        description: "Exhibits ransomware-like behavior".to_string(),
                        severity: 9,
                        confidence: 0.95,
                        references: vec!["https://attack.mitre.org/techniques/T1486/".to_string()],
                        marks: vec![],
                    }
                ]
            } else {
                vec![]
            },
            dropped_files: vec![],
            registry_keys: vec![],
            mutexes: if is_malicious {
                vec!["Global\\RansomwareMutex".to_string()]
            } else {
                vec![]
            },
            yara_rules: if is_malicious {
                vec![
                    YaraRule {
                        name: "ransomware_detection".to_string(),
                        meta: HashMap::from([
                            ("author".to_string(), "ERDPS".to_string()),
                            ("description".to_string(), "Detects ransomware patterns".to_string()),
                        ]),
                        strings: vec![
                            YaraString {
                                identifier: "$crypto1".to_string(),
                                value: "CryptAcquireContext".to_string(),
                                type_: "text".to_string(),
                            },
                            YaraString {
                                identifier: "$crypto2".to_string(),
                                value: "CryptGenKey".to_string(),
                                type_: "text".to_string(),
                            },
                        ],
                        condition: "$crypto1 and $crypto2".to_string(),
                        matches: vec![],
                    }
                ]
            } else {
                vec![]
            },
            screenshots: vec![],
            analysis_time: Duration::from_secs(120),
        }
    }

    /// Get analysis result by task ID
    pub async fn get_analysis_result(&self, task_id: u32) -> Option<AnalysisResult> {
        self.completed_analyses.read().await.get(&task_id).cloned()
    }

    /// Get all completed analyses
    pub async fn get_completed_analyses(&self) -> Vec<AnalysisResult> {
        self.completed_analyses.read().await.values().cloned().collect()
    }

    /// Make quarantine decision based on analysis result
    pub fn make_quarantine_decision(&self, result: &AnalysisResult) -> QuarantineDecision {
        // High-confidence malware detection
        if result.score >= 8.0 {
            return QuarantineDecision::Block;
        }
        
        // Medium-confidence detection
        if result.score >= 6.0 {
            return QuarantineDecision::Quarantine;
        }
        
        // Check for specific ransomware indicators
        let has_crypto_apis = result.behavior.api_calls.iter().any(|call| {
            call.api.contains("Crypt") || call.api.contains("Encrypt")
        });
        
        let has_file_encryption = result.behavior.file_operations.iter().any(|op| {
            op.file_path.contains(".encrypted") || op.file_path.contains(".locked")
        });
        
        let has_ransomware_signatures = result.signatures.iter().any(|sig| {
            sig.name.to_lowercase().contains("ransomware") && sig.confidence > 0.8
        });
        
        if has_crypto_apis && has_file_encryption {
            return QuarantineDecision::Quarantine;
        }
        
        if has_ransomware_signatures {
            return QuarantineDecision::Monitor;
        }
        
        // Low-confidence or suspicious behavior
        if result.score >= 4.0 {
            return QuarantineDecision::Monitor;
        }
        
        QuarantineDecision::Allow
    }

    /// Generate YARA rules from analysis results
    pub async fn generate_yara_rules(&self) -> Vec<String> {
        let mut generated_rules = Vec::new();
        let completed = self.completed_analyses.read().await;
        
        for result in completed.values() {
            if result.score >= 7.0 {
                let rule = self.create_yara_rule_from_analysis(result);
                generated_rules.push(rule);
            }
        }
        
        generated_rules
    }

    /// Create a YARA rule from analysis result
    fn create_yara_rule_from_analysis(&self, result: &AnalysisResult) -> String {
        let rule_name = format!("erdps_auto_generated_{}", result.task_id);
        let mut strings_section = Vec::new();
        let mut condition_parts = Vec::new();
        
        // Add API call patterns
        for (i, api_call) in result.behavior.api_calls.iter().enumerate() {
            if api_call.api.contains("Crypt") || api_call.api.contains("Encrypt") {
                strings_section.push(format!("        $api{} = \"{}\" ascii", i, api_call.api));
                condition_parts.push(format!("$api{}", i));
            }
        }
        
        // Add file operation patterns
        for (i, file_op) in result.behavior.file_operations.iter().enumerate() {
            if file_op.file_path.contains(".encrypted") || file_op.file_path.contains(".locked") {
                let extension = if file_op.file_path.contains(".encrypted") {
                    ".encrypted"
                } else {
                    ".locked"
                };
                strings_section.push(format!("        $ext{} = \"{}\" ascii", i, extension));
                condition_parts.push(format!("$ext{}", i));
            }
        }
        
        // Add mutex patterns
        for (i, mutex) in result.mutexes.iter().enumerate() {
            strings_section.push(format!("        $mutex{} = \"{}\" ascii", i, mutex));
            condition_parts.push(format!("$mutex{}", i));
        }
        
        let condition = if condition_parts.is_empty() {
            "any of them".to_string()
        } else {
            condition_parts.join(" and ")
        };
        
        format!(
            r#"rule {} {{
    meta:
        author = "ERDPS Auto-Generated"
        description = "Auto-generated rule from sandbox analysis"
        date = "{}"
        score = {:.1}
        task_id = {}
    
    strings:
{}
    
    condition:
        {}
}}
"#,
            rule_name,
            chrono::Utc::now().format("%Y-%m-%d"),
            result.score,
            result.task_id,
            strings_section.join("\n"),
            condition
        )
    }

    /// Get sandbox statistics
    pub async fn get_statistics(&self) -> HashMap<String, u64> {
        let mut stats = HashMap::new();
        
        stats.insert("pending_analyses".to_string(), self.pending_analyses.read().await.len() as u64);
        stats.insert("completed_analyses".to_string(), self.completed_analyses.read().await.len() as u64);
        
        let completed = self.completed_analyses.read().await;
        let malicious_count = completed.values().filter(|r| r.score >= 7.0).count();
        stats.insert("malicious_detected".to_string(), malicious_count as u64);
        
        stats
    }

    /// Clean up old analysis results
    pub async fn cleanup_old_results(&self) {
        let retention_period = Duration::from_secs(86400); // 24 hours
        let _cutoff_time = Instant::now() - retention_period;
        
        // In a real implementation, you would check the analysis timestamp
        // For now, we'll just limit the number of stored results
        let mut completed = self.completed_analyses.write().await;
        if completed.len() > 1000 {
            let keys_to_remove: Vec<u32> = completed.keys().take(completed.len() - 1000).cloned().collect();
            for key in keys_to_remove {
                completed.remove(&key);
            }
        }
        
        debug!("Cleaned up old sandbox analysis results");
    }
}
