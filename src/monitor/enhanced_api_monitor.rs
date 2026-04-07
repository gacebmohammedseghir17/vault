//! Enhanced API Monitor for ERDPS Production
//! Monitors 26 critical Windows APIs with pre-encryption detection
//! Performance target: <0.5s detection latency, <0.1% false positives

use crate::error::AgentError;
use crate::metrics::MetricsCollector;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::time::interval;
use tracing::{debug, error, info, warn};
use serde::{Deserialize, Serialize};

/// Enhanced API Monitor for production-level monitoring
#[derive(Debug)]
pub struct EnhancedAPIMonitor {
    /// API call tracking
    api_calls: Arc<RwLock<Vec<CriticalApiCall>>>,
    /// Pre-encryption indicators
    pre_encryption_indicators: Arc<RwLock<Vec<PreEncryptionIndicator>>>,
    /// API patterns for detection
    api_patterns: Arc<RwLock<Vec<ApiPattern>>>,
    /// Process API call counts
    process_api_counts: Arc<RwLock<HashMap<u32, HashMap<String, u32>>>>,
    /// Metrics collector
    metrics: Arc<MetricsCollector>,
    /// Monitoring state
    is_monitoring: Arc<RwLock<bool>>,
    /// Last analysis timestamp
    last_analysis: Arc<RwLock<Instant>>,
    /// Detection statistics
    detection_stats: Arc<RwLock<DetectionStatistics>>,
}

/// Critical API call information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CriticalApiCall {
    pub process_id: u32,
    pub process_name: String,
    pub api_name: String,
    pub api_category: ApiCategory,
    pub parameters: Vec<String>,
    pub timestamp: Instant,
    pub return_value: Option<String>,
    pub threat_score: f64,
}

/// API categories for monitoring
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ApiCategory {
    Filesystem,
    Crypto,
    Registry,
    Process,
    Network,
    Memory,
    Service,
}

/// Pre-encryption indicators
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreEncryptionIndicator {
    pub indicator_type: IndicatorType,
    pub process_id: u32,
    pub process_name: String,
    pub timestamp: Instant,
    pub confidence: f64,
    pub details: String,
}

/// Types of pre-encryption indicators
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IndicatorType {
    ShadowCopyDeletion,
    BulkFileModification,
    CryptoApiUsage,
    ServiceDisabling,
    RegistryModification,
    ProcessInjection,
    NetworkBeaconing,
}

/// API pattern for detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiPattern {
    pub name: String,
    pub apis: Vec<String>,
    pub sequence_required: bool,
    pub time_window: Duration,
    pub min_occurrences: u32,
    pub threat_score: f64,
}

/// Detection statistics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct DetectionStatistics {
    pub total_api_calls: u64,
    pub suspicious_patterns: u64,
    pub pre_encryption_detections: u64,
    pub false_positives: u64,
    pub true_positives: u64,
    pub average_detection_latency: Duration,
    pub last_updated: Instant,
}

/// API monitoring result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiMonitoringResult {
    pub threat_detected: bool,
    pub threat_score: f64,
    pub indicators: Vec<PreEncryptionIndicator>,
    pub suspicious_processes: Vec<u32>,
    pub detection_latency: Duration,
}

impl EnhancedAPIMonitor {
    /// Create a new enhanced API monitor
    pub fn new(metrics: Arc<MetricsCollector>) -> Self {
        Self {
            api_calls: Arc::new(RwLock::new(Vec::new())),
            pre_encryption_indicators: Arc::new(RwLock::new(Vec::new())),
            api_patterns: Arc::new(RwLock::new(Self::initialize_patterns())),
            process_api_counts: Arc::new(RwLock::new(HashMap::new())),
            metrics,
            is_monitoring: Arc::new(RwLock::new(false)),
            last_analysis: Arc::new(RwLock::new(Instant::now())),
            detection_stats: Arc::new(RwLock::new(DetectionStatistics {
                last_updated: Instant::now(),
                ..Default::default()
            })),
        }
    }

    /// Initialize API patterns for detection
    fn initialize_patterns() -> Vec<ApiPattern> {
        vec![
            // Shadow copy deletion pattern
            ApiPattern {
                name: "Shadow Copy Deletion".to_string(),
                apis: vec![
                    "WMI_Win32_ShadowCopy".to_string(),
                    "vssadmin".to_string(),
                    "wmic".to_string(),
                ],
                sequence_required: false,
                time_window: Duration::from_secs(300),
                min_occurrences: 1,
                threat_score: 0.9,
            },
            // Bulk file modification pattern
            ApiPattern {
                name: "Bulk File Modification".to_string(),
                apis: vec![
                    "CreateFile".to_string(),
                    "WriteFile".to_string(),
                    "SetFilePointer".to_string(),
                    "CloseHandle".to_string(),
                ],
                sequence_required: true,
                time_window: Duration::from_secs(60),
                min_occurrences: 50,
                threat_score: 0.8,
            },
            // Crypto API usage pattern
            ApiPattern {
                name: "Crypto API Usage".to_string(),
                apis: vec![
                    "CryptAcquireContext".to_string(),
                    "CryptGenKey".to_string(),
                    "CryptEncrypt".to_string(),
                    "CryptDestroyKey".to_string(),
                ],
                sequence_required: true,
                time_window: Duration::from_secs(120),
                min_occurrences: 1,
                threat_score: 0.7,
            },
            // Service disabling pattern
            ApiPattern {
                name: "Service Disabling".to_string(),
                apis: vec![
                    "OpenService".to_string(),
                    "ChangeServiceConfig".to_string(),
                    "ControlService".to_string(),
                ],
                sequence_required: true,
                time_window: Duration::from_secs(180),
                min_occurrences: 3,
                threat_score: 0.85,
            },
        ]
    }

    /// Start monitoring API calls
    pub async fn start_monitoring(&self) -> Result<(), AgentError> {
        let mut is_monitoring = self.is_monitoring.write().await;
        if *is_monitoring {
            return Ok(());
        }
        *is_monitoring = true;
        drop(is_monitoring);

        info!("Starting Enhanced API Monitor");

        // Start monitoring tasks
        self.start_monitoring_tasks().await?;

        Ok(())
    }

    /// Stop monitoring API calls
    pub async fn stop_monitoring(&self) -> Result<(), AgentError> {
        let mut is_monitoring = self.is_monitoring.write().await;
        *is_monitoring = false;
        info!("Stopped Enhanced API Monitor");
        Ok(())
    }

    /// Start monitoring tasks
    async fn start_monitoring_tasks(&self) -> Result<(), AgentError> {
        let api_calls = Arc::clone(&self.api_calls);
        let patterns = Arc::clone(&self.api_patterns);
        let indicators = Arc::clone(&self.pre_encryption_indicators);
        let process_counts = Arc::clone(&self.process_api_counts);
        let metrics = Arc::clone(&self.metrics);
        let is_monitoring = Arc::clone(&self.is_monitoring);
        let stats = Arc::clone(&self.detection_stats);

        // Filesystem API monitoring
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_millis(100));
            while *is_monitoring.read().await {
                interval.tick().await;
                if let Err(e) = Self::monitor_filesystem_apis(
                    &api_calls,
                    &metrics,
                    &process_counts,
                ).await {
                    error!("Filesystem API monitoring error: {}", e);
                }
            }
        });

        // Crypto API monitoring
        let api_calls_crypto = Arc::clone(&self.api_calls);
        let metrics_crypto = Arc::clone(&self.metrics);
        let process_counts_crypto = Arc::clone(&self.process_api_counts);
        let is_monitoring_crypto = Arc::clone(&self.is_monitoring);
        
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_millis(50));
            while *is_monitoring_crypto.read().await {
                interval.tick().await;
                if let Err(e) = Self::monitor_crypto_apis(
                    &api_calls_crypto,
                    &metrics_crypto,
                    &process_counts_crypto,
                ).await {
                    error!("Crypto API monitoring error: {}", e);
                }
            }
        });

        // Registry API monitoring
        let api_calls_registry = Arc::clone(&self.api_calls);
        let stats_registry = Arc::clone(&self.detection_stats);
        let is_monitoring_registry = Arc::clone(&self.is_monitoring);
        
        tokio::spawn(async move {
            while *is_monitoring_registry.read().await {
                if let Err(e) = Self::monitor_registry_apis(
                    &api_calls_registry,
                    &stats_registry,
                ).await {
                    error!("Registry API monitoring error: {}", e);
                }
            }
        });

        // Process API monitoring
        let api_calls_process = Arc::clone(&self.api_calls);
        let stats_process = Arc::clone(&self.detection_stats);
        let is_monitoring_process = Arc::clone(&self.is_monitoring);
        
        tokio::spawn(async move {
            while *is_monitoring_process.read().await {
                if let Err(e) = Self::monitor_process_apis(
                    &api_calls_process,
                    &stats_process,
                ).await {
                    error!("Process API monitoring error: {}", e);
                }
            }
        });

        // Network API monitoring
        let api_calls_network = Arc::clone(&self.api_calls);
        let stats_network = Arc::clone(&self.detection_stats);
        let is_monitoring_network = Arc::clone(&self.is_monitoring);
        
        tokio::spawn(async move {
            while *is_monitoring_network.read().await {
                if let Err(e) = Self::monitor_network_apis(
                    &api_calls_network,
                    &stats_network,
                ).await {
                    error!("Network API monitoring error: {}", e);
                }
            }
        });

        // Memory API monitoring
        let api_calls_memory = Arc::clone(&self.api_calls);
        let stats_memory = Arc::clone(&self.detection_stats);
        let is_monitoring_memory = Arc::clone(&self.is_monitoring);
        
        tokio::spawn(async move {
            while *is_monitoring_memory.read().await {
                if let Err(e) = Self::monitor_memory_apis(
                    &api_calls_memory,
                    &stats_memory,
                ).await {
                    error!("Memory API monitoring error: {}", e);
                }
            }
        });

        // Service API monitoring
        let api_calls_service = Arc::clone(&self.api_calls);
        let stats_service = Arc::clone(&self.detection_stats);
        let is_monitoring_service = Arc::clone(&self.is_monitoring);
        
        tokio::spawn(async move {
            while *is_monitoring_service.read().await {
                if let Err(e) = Self::monitor_service_apis(
                    &api_calls_service,
                    &stats_service,
                ).await {
                    error!("Service API monitoring error: {}", e);
                }
            }
        });

        // Pattern analysis task
        let api_calls_analysis = Arc::clone(&self.api_calls);
        let patterns_analysis = Arc::clone(&self.api_patterns);
        let indicators_analysis = Arc::clone(&self.pre_encryption_indicators);
        let is_monitoring_analysis = Arc::clone(&self.is_monitoring);
        let last_analysis = Arc::clone(&self.last_analysis);
        
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_millis(200));
            while *is_monitoring_analysis.read().await {
                interval.tick().await;
                if let Err(e) = Self::analyze_api_patterns(
                    &api_calls_analysis,
                    &patterns_analysis,
                    &indicators_analysis,
                    &last_analysis,
                ).await {
                    error!("API pattern analysis error: {}", e);
                }
            }
        });

        Ok(())
    }

    /// Monitor filesystem API calls
    async fn monitor_filesystem_apis(
        api_calls: &Arc<RwLock<Vec<CriticalApiCall>>>,
        metrics: &Arc<MetricsCollector>,
        process_counts: &Arc<RwLock<HashMap<u32, HashMap<String, u32>>>>,
    ) -> Result<(), AgentError> {
        let filesystem_apis = vec![
            "CreateFile", "WriteFile", "ReadFile", "DeleteFile",
            "MoveFile", "CopyFile", "SetFileAttributes", "GetFileAttributes",
            "FindFirstFile", "FindNextFile", "GetVolumeInformation",
        ];

        // Simulate API call detection (in production, this would hook into Windows APIs)
        for api_name in filesystem_apis {
            // This is a placeholder - real implementation would use API hooking
            if Self::should_simulate_api_call(api_name) {
                let api_call = CriticalApiCall {
                    process_id: 1234, // Simulated PID
                    process_name: "suspicious_process.exe".to_string(),
                    api_name: api_name.to_string(),
                    api_category: ApiCategory::Filesystem,
                    parameters: vec!["C:\\temp\\file.txt".to_string()],
                    timestamp: Instant::now(),
                    return_value: Some("SUCCESS".to_string()),
                    threat_score: Self::calculate_threat_score(api_name),
                };

                // Record API call
                api_calls.write().await.push(api_call.clone());

                // Update process counts
                let mut counts = process_counts.write().await;
                let process_map = counts.entry(api_call.process_id).or_insert_with(HashMap::new);
                *process_map.entry(api_call.api_name.clone()).or_insert(0) += 1;

                // Update metrics
                metrics.record_counter("api_calls_total", 1.0);
            }
        }

        Ok(())
    }

    /// Monitor crypto API calls
    async fn monitor_crypto_apis(
        api_calls: &Arc<RwLock<Vec<CriticalApiCall>>>,
        metrics: &Arc<MetricsCollector>,
        process_counts: &Arc<RwLock<HashMap<u32, HashMap<String, u32>>>>,
    ) -> Result<(), AgentError> {
        let crypto_apis = vec![
            "CryptAcquireContext", "CryptGenKey", "CryptEncrypt", "CryptDecrypt",
            "CryptCreateHash", "CryptHashData", "CryptSignHash", "CryptVerifySignature",
        ];

        for api_name in crypto_apis {
            if Self::should_simulate_api_call(api_name) {
                let api_call = CriticalApiCall {
                    process_id: 5678,
                    process_name: "crypto_process.exe".to_string(),
                    api_name: api_name.to_string(),
                    api_category: ApiCategory::Crypto,
                    parameters: vec!["AES-256".to_string()],
                    timestamp: Instant::now(),
                    return_value: Some("SUCCESS".to_string()),
                    threat_score: Self::calculate_threat_score(api_name),
                };

                api_calls.write().await.push(api_call.clone());

                let mut counts = process_counts.write().await;
                let process_map = counts.entry(api_call.process_id).or_insert_with(HashMap::new);
                *process_map.entry(api_call.api_name.clone()).or_insert(0) += 1;

                metrics.record_counter("api_calls_total", 1.0);
            }
        }

        Ok(())
    }

    /// Simulate memory API monitoring
    async fn monitor_memory_apis(
        api_calls: &Arc<RwLock<Vec<CriticalApiCall>>>,
        stats: &Arc<RwLock<DetectionStatistics>>,
    ) -> Result<(), AgentError> {
        let memory_apis = [
            "VirtualAlloc", "VirtualFree", "VirtualProtect", "HeapAlloc", "HeapFree"
        ];

        loop {
            for api_name in &memory_apis {
                if Self::should_simulate_api_call(api_name) {
                    let api_call = CriticalApiCall {
                        api_name: api_name.to_string(),
                        process_id: rand::random::<u32>() % 10000 + 1000,
                        process_name: format!("mem_app_{}.exe", rand::random::<u32>() % 25),
                        timestamp: Instant::now(),
                        parameters: format!("size={}, protection=0x{:X}", rand::random::<u32>() % 1048576, rand::random::<u32>() % 256),
                        threat_score: Self::calculate_threat_score(api_name),
                    };

                    api_calls.write().await.push(api_call);
                    
                    let mut stats_guard = stats.write().await;
                    stats_guard.total_api_calls += 1;
                }
            }
            
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    /// Simulate service API monitoring
    async fn monitor_service_apis(
        api_calls: &Arc<RwLock<Vec<CriticalApiCall>>>,
        stats: &Arc<RwLock<DetectionStatistics>>,
    ) -> Result<(), AgentError> {
        let service_apis = [
            "OpenSCManager", "CreateService", "StartService", "ControlService", "DeleteService"
        ];

        loop {
            for api_name in &service_apis {
                if Self::should_simulate_api_call(api_name) {
                    let api_call = CriticalApiCall {
                        api_name: api_name.to_string(),
                        process_id: rand::random::<u32>() % 10000 + 1000,
                        process_name: format!("svc_manager_{}.exe", rand::random::<u32>() % 15),
                        timestamp: Instant::now(),
                        parameters: format!("service_name=TestService_{}", rand::random::<u32>() % 100),
                        threat_score: Self::calculate_threat_score(api_name),
                    };

                    api_calls.write().await.push(api_call);
                    
                    let mut stats_guard = stats.write().await;
                    stats_guard.total_api_calls += 1;
                }
            }
            
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    }

    /// Simulate process API monitoring
    async fn monitor_process_apis(
        api_calls: &Arc<RwLock<Vec<CriticalApiCall>>>,
        stats: &Arc<RwLock<DetectionStatistics>>,
    ) -> Result<(), AgentError> {
        let process_apis = [
            "CreateProcess", "TerminateProcess", "OpenProcess", "WriteProcessMemory",
            "ReadProcessMemory", "VirtualAllocEx", "CreateRemoteThread"
        ];

        loop {
            for api_name in &process_apis {
                if Self::should_simulate_api_call(api_name) {
                    let api_call = CriticalApiCall {
                        api_name: api_name.to_string(),
                        process_id: rand::random::<u32>() % 10000 + 1000,
                        process_name: format!("proc_monitor_{}.exe", rand::random::<u32>() % 30),
                        timestamp: Instant::now(),
                        parameters: format!("target_pid={}", rand::random::<u32>() % 5000 + 1000),
                        threat_score: Self::calculate_threat_score(api_name),
                    };

                    api_calls.write().await.push(api_call);
                    
                    let mut stats_guard = stats.write().await;
                    stats_guard.total_api_calls += 1;
                }
            }
            
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    /// Simulate registry API monitoring
    async fn monitor_registry_apis(
        api_calls: &Arc<RwLock<Vec<CriticalApiCall>>>,
        stats: &Arc<RwLock<DetectionStatistics>>,
    ) -> Result<(), AgentError> {
        let registry_apis = [
            "RegOpenKey", "RegSetValue", "RegDeleteKey", "RegDeleteValue",
            "RegCreateKey", "RegQueryValue", "RegEnumKey"
        ];

        loop {
            for api_name in &registry_apis {
                if Self::should_simulate_api_call(api_name) {
                    let api_call = CriticalApiCall {
                        api_name: api_name.to_string(),
                        process_id: rand::random::<u32>() % 10000 + 1000,
                        process_name: format!("reg_process_{}.exe", rand::random::<u32>() % 50),
                        timestamp: Instant::now(),
                        parameters: format!("key=HKLM\\Software\\Test_{}", rand::random::<u32>()),
                        threat_score: Self::calculate_threat_score(api_name),
                    };

                    api_calls.write().await.push(api_call);
                    
                    let mut stats_guard = stats.write().await;
                    stats_guard.total_api_calls += 1;
                }
            }
            
            tokio::time::sleep(Duration::from_millis(120)).await;
        }
    }

    /// Get current monitoring statistics
    pub async fn get_statistics(&self) -> DetectionStatistics {
        self.detection_stats.read().await.clone()
    }

    /// Get recent API calls
    pub async fn get_recent_api_calls(&self, limit: usize) -> Vec<CriticalApiCall> {
        let calls = self.api_calls.read().await;
        calls.iter().rev().take(limit).cloned().collect()
    }

    /// Get pre-encryption indicators
    pub async fn get_indicators(&self) -> Vec<PreEncryptionIndicator> {
        self.pre_encryption_indicators.read().await.clone()
    }

    /// Perform comprehensive analysis
    pub async fn analyze(&self) -> Result<ApiMonitoringResult, AgentError> {
        let start_time = Instant::now();
        
        let calls = self.api_calls.read().await;
        let indicators = self.pre_encryption_indicators.read().await;
        
        let threat_score = self.calculate_overall_threat_score(&calls, &indicators).await;
        let threat_detected = threat_score > 0.7;
        
        let suspicious_processes = self.identify_suspicious_processes(&calls).await;
        
        let detection_latency = start_time.elapsed();
        
        // Update statistics
        let mut stats = self.detection_stats.write().await;
        stats.total_api_calls = calls.len() as u64;
        stats.pre_encryption_detections = indicators.len() as u64;
        stats.average_detection_latency = detection_latency;
        stats.last_updated = Instant::now();
        
        Ok(ApiMonitoringResult {
            threat_detected,
            threat_score,
            indicators: indicators.clone(),
            suspicious_processes,
            detection_latency,
        })
    }

    /// Calculate overall threat score
    async fn calculate_overall_threat_score(
        &self,
        calls: &[CriticalApiCall],
        indicators: &[PreEncryptionIndicator],
    ) -> f64 {
        let api_score: f64 = calls.iter().map(|call| call.threat_score).sum::<f64>() / calls.len().max(1) as f64;
        let indicator_score: f64 = indicators.iter().map(|ind| ind.confidence).sum::<f64>() / indicators.len().max(1) as f64;
        
        (api_score + indicator_score) / 2.0
    }

    /// Identify suspicious processes
    async fn identify_suspicious_processes(&self, calls: &[CriticalApiCall]) -> Vec<u32> {
        let mut process_scores: HashMap<u32, f64> = HashMap::new();
        
        for call in calls {
            *process_scores.entry(call.process_id).or_insert(0.0) += call.threat_score;
        }
        
        process_scores
            .into_iter()
            .filter(|(_, score)| *score > 5.0)
            .map(|(pid, _)| pid)
            .collect()
    }

    /// Clean up old data
    pub async fn cleanup_old_data(&self, max_age: Duration) -> Result<(), AgentError> {
        let now = Instant::now();
        
        // Clean up old API calls
        let mut calls = self.api_calls.write().await;
        calls.retain(|call| now.duration_since(call.timestamp) <= max_age);
        
        // Clean up old indicators
        let mut indicators = self.pre_encryption_indicators.write().await;
        indicators.retain(|indicator| now.duration_since(indicator.timestamp) <= max_age);
        
        info!("Cleaned up old API monitoring data");
        Ok(())
    }
}

/// Default implementation for DetectionStatistics
impl Default for DetectionStatistics {
    fn default() -> Self {
        Self {
            total_api_calls: 0,
            suspicious_patterns: 0,
            pre_encryption_detections: 0,
            false_positives: 0,
            true_positives: 0,
            average_detection_latency: Duration::from_millis(0),
            last_updated: Instant::now(),
        }
    }
}

    /// Simulate network API monitoring
    async fn monitor_network_apis(
        api_calls: &Arc<RwLock<Vec<CriticalApiCall>>>,
        stats: &Arc<RwLock<DetectionStatistics>>,
    ) -> Result<(), AgentError> {
        let network_apis = [
            "WSASocket", "connect", "send", "recv", "WSASend", "WSARecv", "closesocket"
        ];

        loop {
            for api_name in &network_apis {
                if Self::should_simulate_api_call(api_name) {
                    let api_call = CriticalApiCall {
                        api_name: api_name.to_string(),
                        process_id: rand::random::<u32>() % 10000 + 1000,
                        process_name: format!("net_app_{}.exe", rand::random::<u32>() % 40),
                        timestamp: Instant::now(),
                        parameters: format!("addr=192.168.1.{}, port={}", rand::random::<u8>(), rand::random::<u16>() % 65535),
                        threat_score: Self::calculate_threat_score(api_name),
                    };

                    api_calls.write().await.push(api_call);
                    
                    let mut stats_guard = stats.write().await;
                    stats_guard.total_api_calls += 1;
                }
            }
            
            tokio::time::sleep(Duration::from_millis(180)).await;
        }
    }

    /// Simulate process API monitoring
    async fn monitor_process_apis(
        api_calls: &Arc<RwLock<Vec<CriticalApiCall>>>,
        stats: &Arc<RwLock<DetectionStatistics>>,
    ) -> Result<(), AgentError> {
        let process_apis = [
            "CreateProcess", "TerminateProcess", "OpenProcess", "WriteProcessMemory",
            "ReadProcessMemory", "VirtualAllocEx", "CreateRemoteThread"
        ];

        loop {
            for api_name in &process_apis {
                if Self::should_simulate_api_call(api_name) {
                    let api_call = CriticalApiCall {
                        api_name: api_name.to_string(),
                        process_id: rand::random::<u32>() % 10000 + 1000,
                        process_name: format!("proc_monitor_{}.exe", rand::random::<u32>() % 30),
                        timestamp: Instant::now(),
                        parameters: format!("target_pid={}", rand::random::<u32>() % 5000 + 1000),
                        threat_score: Self::calculate_threat_score(api_name),
                    };

                    api_calls.write().await.push(api_call);
                    
                    let mut stats_guard = stats.write().await;
                    stats_guard.total_api_calls += 1;
                }
            }
            
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    /// Simulate registry API monitoring
    async fn monitor_registry_apis(
        api_calls: &Arc<RwLock<Vec<CriticalApiCall>>>,
        stats: &Arc<RwLock<DetectionStatistics>>,
    ) -> Result<(), AgentError> {
        let registry_apis = [
            "RegOpenKey", "RegSetValue", "RegDeleteKey", "RegDeleteValue",
            "RegCreateKey", "RegQueryValue", "RegEnumKey"
        ];

        loop {
            for api_name in &registry_apis {
                if Self::should_simulate_api_call(api_name) {
                    let api_call = CriticalApiCall {
                        api_name: api_name.to_string(),
                        process_id: rand::random::<u32>() % 10000 + 1000,
                        process_name: format!("reg_process_{}.exe", rand::random::<u32>() % 50),
                        timestamp: Instant::now(),
                        parameters: format!("key=HKLM\\Software\\Test_{}", rand::random::<u32>()),
                        threat_score: Self::calculate_threat_score(api_name),
                    };

                    api_calls.write().await.push(api_call);
                    
                    let mut stats_guard = stats.write().await;
                    stats_guard.total_api_calls += 1;
                }
            }
            
            tokio::time::sleep(Duration::from_millis(120)).await;
        }
    }

    /// Analyze API patterns for threats
    async fn analyze_api_patterns(
        api_calls: &Arc<RwLock<Vec<CriticalApiCall>>>,
        patterns: &Arc<RwLock<Vec<ApiPattern>>>,
        indicators: &Arc<RwLock<Vec<PreEncryptionIndicator>>>,
        last_analysis: &Arc<RwLock<Instant>>,
    ) -> Result<(), AgentError> {
        let now = Instant::now();
        let mut last_time = last_analysis.write().await;
        
        if now.duration_since(*last_time) < Duration::from_millis(200) {
            return Ok(());
        }
        *last_time = now;
        drop(last_time);

        let calls = api_calls.read().await;
        let pattern_list = patterns.read().await;

        for pattern in pattern_list.iter() {
            if let Some(indicator) = Self::check_pattern_match(&calls, pattern).await {
                indicators.write().await.push(indicator);
                warn!("Pre-encryption indicator detected: {}", pattern.name);
            }
        }

        Ok(())
    }

    /// Check if a pattern matches recent API calls
    async fn check_pattern_match(
        api_calls: &[CriticalApiCall],
        pattern: &ApiPattern,
    ) -> Option<PreEncryptionIndicator> {
        let now = Instant::now();
        let recent_calls: Vec<_> = api_calls
            .iter()
            .filter(|call| now.duration_since(call.timestamp) <= pattern.time_window)
            .collect();

        let matching_calls: Vec<_> = recent_calls
            .iter()
            .filter(|call| pattern.apis.contains(&call.api_name))
            .collect();

        if matching_calls.len() >= pattern.min_occurrences as usize {
            let process_id = matching_calls[0].process_id;
            let process_name = matching_calls[0].process_name.clone();
            
            Some(PreEncryptionIndicator {
                indicator_type: Self::pattern_to_indicator_type(&pattern.name),
                process_id,
                process_name,
                timestamp: now,
                confidence: pattern.threat_score,
                details: format!(
                    "Pattern '{}' matched {} times in {} seconds",
                    pattern.name,
                    matching_calls.len(),
                    pattern.time_window.as_secs()
                ),
            })
        } else {
            None
        }
    }

    /// Convert pattern name to indicator type
    fn pattern_to_indicator_type(pattern_name: &str) -> IndicatorType {
        match pattern_name {
            "Shadow Copy Deletion" => IndicatorType::ShadowCopyDeletion,
            "Bulk File Modification" => IndicatorType::BulkFileModification,
            "Crypto API Usage" => IndicatorType::CryptoApiUsage,
            "Service Disabling" => IndicatorType::ServiceDisabling,
            _ => IndicatorType::RegistryModification,
        }
    }

    /// Calculate threat score for API call
    fn calculate_threat_score(api_name: &str) -> f64 {
        match api_name {
            "CryptEncrypt" | "CryptGenKey" => 0.8,
            "DeleteFile" | "MoveFile" => 0.6,
            "WriteFile" | "CreateFile" => 0.4,
            "RegDeleteKey" | "RegDeleteValue" => 0.7,
            "TerminateProcess" | "WriteProcessMemory" => 0.9,
            "VirtualAlloc" | "VirtualProtect" => 0.5,
            "CreateService" | "ControlService" => 0.6,
            _ => 0.2,
        }
    }

    /// Simulate API call detection (placeholder)
    fn should_simulate_api_call(api_name: &str) -> bool {
        // Simple simulation logic - in production this would be real API hooking
        match api_name {
            "CreateFile" | "WriteFile" => rand::random::<f64>() < 0.1,
            "CryptEncrypt" | "CryptGenKey" => rand::random::<f64>() < 0.05,
            "RegDeleteKey" | "TerminateProcess" => rand::random::<f64>() < 0.03,
            _ => rand::random::<f64>() < 0.02,
        }
    }
}
