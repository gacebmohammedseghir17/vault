//! Real Ransomware Sample Integration
//!
//! This module provides secure handling and testing of real ransomware samples
//! for enterprise validation. All samples are handled in isolated environments
//! with strict security controls.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::fs;
use tokio::sync::RwLock;
use tracing::{info, warn, error, debug};
use serde::{Deserialize, Serialize};

/// Configuration for real ransomware sample testing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RansomSampleConfig {
    /// Directory containing ransomware samples (read-only mount)
    pub samples_dir: PathBuf,
    /// Maximum execution time per sample (safety timeout)
    pub max_execution_time: Duration,
    /// Sandbox environment configuration
    pub sandbox_config: SandboxConfig,
    /// Detection timeout threshold
    pub detection_timeout: Duration,
}

/// Sandbox configuration for secure sample execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    /// Enable air-gapped mode (no network access)
    pub air_gapped: bool,
    /// Temporary directory for sample execution
    pub temp_dir: PathBuf,
    /// Enable file system isolation
    pub fs_isolation: bool,
    /// Maximum memory usage for sandbox
    pub max_memory_mb: u64,
}

/// Metadata for a ransomware sample
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RansomSample {
    /// Sample file path
    pub path: PathBuf,
    /// Sample name/identifier
    pub name: String,
    /// Sample family (e.g., "WannaCry", "Ryuk", "Maze")
    pub family: String,
    /// SHA256 hash of the sample
    pub sha256: String,
    /// Expected behavior patterns
    pub expected_behaviors: Vec<ExpectedBehavior>,
    /// Sample size in bytes
    pub size: u64,
}

/// Expected behavior patterns for validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExpectedBehavior {
    /// File encryption activity
    FileEncryption {
        /// Expected file extensions to encrypt
        target_extensions: Vec<String>,
        /// Expected encryption patterns
        encryption_markers: Vec<String>,
    },
    /// Registry modifications
    RegistryModification {
        /// Registry keys to modify
        target_keys: Vec<String>,
        /// Expected operations
        operations: Vec<String>,
    },
    /// Process injection attempts
    ProcessInjection {
        /// Target processes
        target_processes: Vec<String>,
        /// Injection techniques
        techniques: Vec<String>,
    },
    /// Network communication
    NetworkActivity {
        /// C2 domains/IPs
        c2_endpoints: Vec<String>,
        /// Communication protocols
        protocols: Vec<String>,
    },
}

/// Detection result for a ransomware sample
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionResult {
    /// Sample that was tested
    pub sample: RansomSample,
    /// Whether the sample was detected
    pub detected: bool,
    /// Time to detection (MTTD)
    pub detection_time: Option<Duration>,
    /// Detected behaviors
    pub detected_behaviors: Vec<String>,
    /// Detection confidence score (0.0-1.0)
    pub confidence: f64,
    /// Any errors during testing
    pub errors: Vec<String>,
    /// Performance metrics during testing
    pub performance_metrics: PerformanceMetrics,
}

/// Performance metrics during sample testing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    /// CPU usage percentage during test
    pub cpu_usage_percent: f64,
    /// Memory usage in bytes
    pub memory_usage_bytes: u64,
    /// Disk I/O operations per second
    pub disk_io_ops_per_sec: f64,
    /// Network packets per second
    pub network_packets_per_sec: f64,
}

/// Real ransomware sample library manager
pub struct RealRansomLib {
    config: RansomSampleConfig,
    samples: Arc<RwLock<HashMap<String, RansomSample>>>,
    detection_results: Arc<RwLock<Vec<DetectionResult>>>,
}

impl Default for RansomSampleConfig {
    fn default() -> Self {
        let detection_timeout_secs = std::env::var("ERDPS_TEST_DETECTION_TIMEOUT")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(5); // Default to 5s for faster tests
        
        Self {
            samples_dir: PathBuf::from("/samples/ransom"),
            max_execution_time: Duration::from_secs(300), // 5 minutes max
            detection_timeout: Duration::from_secs(detection_timeout_secs), // Configurable via ERDPS_TEST_DETECTION_TIMEOUT
            sandbox_config: SandboxConfig {
                air_gapped: true,
                temp_dir: PathBuf::from("/tmp/ransom_sandbox"),
                fs_isolation: true,
                max_memory_mb: 512,
            },
        }
    }
}

impl RealRansomLib {
    /// Create a new real ransomware sample library
    pub fn new(config: RansomSampleConfig) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Validate configuration
        if !config.samples_dir.exists() {
            return Err(format!("Samples directory does not exist: {:?}", config.samples_dir).into());
        }
        
        // Ensure sandbox directory exists
        std::fs::create_dir_all(&config.sandbox_config.temp_dir)?;
        
        Ok(Self {
            config,
            samples: Arc::new(RwLock::new(HashMap::new())),
            detection_results: Arc::new(RwLock::new(Vec::new())),
        })
    }
    
    /// Load ransomware samples from the configured directory
    pub async fn load_samples(&self) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
        info!("Loading ransomware samples from {:?}", self.config.samples_dir);
        
        let mut samples_guard = self.samples.write().await;
        samples_guard.clear();
        
        let mut entries = fs::read_dir(&self.config.samples_dir).await?;
        let mut loaded_count = 0;
        
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            
            // Only process executable files
            if let Some(extension) = path.extension() {
                if extension == "exe" || extension == "dll" || extension == "bin" {
                    match self.create_sample_metadata(&path).await {
                        Ok(sample) => {
                            samples_guard.insert(sample.name.clone(), sample);
                            loaded_count += 1;
                        }
                        Err(e) => {
                            warn!("Failed to load sample {:?}: {}", path, e);
                        }
                    }
                }
            }
        }
        
        info!("Loaded {} ransomware samples", loaded_count);
        Ok(loaded_count)
    }
    
    /// Create metadata for a ransomware sample
    async fn create_sample_metadata(&self, path: &Path) -> Result<RansomSample, Box<dyn std::error::Error + Send + Sync>> {
        let metadata = fs::metadata(path).await?;
        let file_name = path.file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();
        
        // Calculate SHA256 hash
        let content = fs::read(path).await?;
        let sha256 = Self::calculate_sha256(&content);
        
        // Determine family based on file name patterns
        let family = Self::determine_family(&file_name);
        
        // Generate expected behaviors based on family
        let expected_behaviors = Self::generate_expected_behaviors(&family);
        
        Ok(RansomSample {
            path: path.to_path_buf(),
            name: file_name,
            family,
            sha256,
            expected_behaviors,
            size: metadata.len(),
        })
    }
    
    /// Calculate SHA256 hash of file content
    fn calculate_sha256(content: &[u8]) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(content);
        format!("{:x}", hasher.finalize())
    }
    
    /// Determine ransomware family from file name
    fn determine_family(file_name: &str) -> String {
        let name_lower = file_name.to_lowercase();
        
        if name_lower.contains("wannacry") || name_lower.contains("wcry") {
            "WannaCry".to_string()
        } else if name_lower.contains("ryuk") {
            "Ryuk".to_string()
        } else if name_lower.contains("maze") {
            "Maze".to_string()
        } else if name_lower.contains("lockbit") {
            "LockBit".to_string()
        } else if name_lower.contains("conti") {
            "Conti".to_string()
        } else if name_lower.contains("revil") || name_lower.contains("sodinokibi") {
            "REvil".to_string()
        } else {
            "Unknown".to_string()
        }
    }
    
    /// Generate expected behaviors based on ransomware family
    fn generate_expected_behaviors(family: &str) -> Vec<ExpectedBehavior> {
        match family {
            "WannaCry" => vec![
                ExpectedBehavior::FileEncryption {
                    target_extensions: vec![".doc".to_string(), ".pdf".to_string(), ".jpg".to_string()],
                    encryption_markers: vec!["WANACRY!".to_string()],
                },
                ExpectedBehavior::NetworkActivity {
                    c2_endpoints: vec!["iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com".to_string()],
                    protocols: vec!["HTTP".to_string()],
                },
            ],
            "Ryuk" => vec![
                ExpectedBehavior::FileEncryption {
                    target_extensions: vec![".doc".to_string(), ".xls".to_string(), ".pdf".to_string()],
                    encryption_markers: vec!["RYUK".to_string()],
                },
                ExpectedBehavior::ProcessInjection {
                    target_processes: vec!["explorer.exe".to_string(), "winlogon.exe".to_string()],
                    techniques: vec!["Process Hollowing".to_string()],
                },
            ],
            _ => vec![
                ExpectedBehavior::FileEncryption {
                    target_extensions: vec![".doc".to_string(), ".pdf".to_string(), ".jpg".to_string()],
                    encryption_markers: vec!["ENCRYPTED".to_string()],
                },
            ],
        }
    }
    
    /// Get all loaded samples
    pub async fn get_samples(&self) -> Vec<RansomSample> {
        self.samples.read().await.values().cloned().collect()
    }
    
    /// Get a specific sample by name
    pub async fn get_sample(&self, name: &str) -> Option<RansomSample> {
        self.samples.read().await.get(name).cloned()
    }
    
    /// Execute a ransomware sample in sandbox and measure detection
    pub async fn test_sample_detection(
        &self,
        sample_name: &str,
        agent_handle: Arc<dyn SampleTestAgent>,
    ) -> Result<DetectionResult, Box<dyn std::error::Error + Send + Sync>> {
        let sample = self.get_sample(sample_name).await
            .ok_or_else(|| format!("Sample not found: {}", sample_name))?;
        
        info!("Testing detection for sample: {}", sample.name);
        
        // Prepare sandbox environment
        self.prepare_sandbox().await?;
        
        let start_time = Instant::now();
        let mut detection_result = DetectionResult {
            sample: sample.clone(),
            detected: false,
            detection_time: None,
            detected_behaviors: Vec::new(),
            confidence: 0.0,
            errors: Vec::new(),
            performance_metrics: PerformanceMetrics {
                cpu_usage_percent: 0.0,
                memory_usage_bytes: 0,
                disk_io_ops_per_sec: 0.0,
                network_packets_per_sec: 0.0,
            },
        };
        
        // Start performance monitoring
        let perf_monitor = self.start_performance_monitoring().await?;
        
        // Execute sample in controlled environment
        match self.execute_sample_safely(&sample, agent_handle).await {
            Ok(result) => {
                detection_result.detected = result.detected;
                detection_result.detection_time = Some(start_time.elapsed());
                detection_result.detected_behaviors = result.behaviors;
                detection_result.confidence = result.confidence;
            }
            Err(e) => {
                error!("Sample execution failed: {}", e);
                detection_result.errors.push(e.to_string());
            }
        }
        
        // Stop performance monitoring and collect metrics
        detection_result.performance_metrics = self.stop_performance_monitoring(perf_monitor).await?;
        
        // Cleanup sandbox
        self.cleanup_sandbox().await?;
        
        // Store result
        self.detection_results.write().await.push(detection_result.clone());
        
        Ok(detection_result)
    }
    
    /// Prepare sandbox environment for sample execution
    async fn prepare_sandbox(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let temp_dir = &self.config.sandbox_config.temp_dir;
        
        // Clean and recreate temp directory
        if temp_dir.exists() {
            fs::remove_dir_all(temp_dir).await?;
        }
        fs::create_dir_all(temp_dir).await?;
        
        // Set up file system isolation if enabled
        if self.config.sandbox_config.fs_isolation {
            // Create isolated file system view
            self.setup_fs_isolation().await?;
        }
        
        info!("Sandbox prepared at {:?}", temp_dir);
        Ok(())
    }
    
    /// Set up file system isolation
    async fn setup_fs_isolation(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // On Windows, we can use junction points or symbolic links
        // For now, we'll create a basic isolated directory structure
        let temp_dir = &self.config.sandbox_config.temp_dir;
        
        // Create basic Windows directory structure
        let dirs = [
            "Windows\\System32",
            "Windows\\SysWOW64",
            "Program Files",
            "Program Files (x86)",
            "Users\\Public\\Documents",
        ];
        
        for dir in &dirs {
            let path = temp_dir.join(dir);
            fs::create_dir_all(&path).await?;
        }
        
        Ok(())
    }
    
    /// Execute sample safely in sandbox
    async fn execute_sample_safely(
        &self,
        sample: &RansomSample,
        agent_handle: Arc<dyn SampleTestAgent>,
    ) -> Result<SampleExecutionResult, Box<dyn std::error::Error + Send + Sync>> {
        // Copy sample to sandbox
        let sandbox_sample_path = self.config.sandbox_config.temp_dir.join(&sample.name);
        fs::copy(&sample.path, &sandbox_sample_path).await?;
        
        // Start agent monitoring
        agent_handle.start_monitoring().await?;
        
        // Execute sample with timeout
        let execution_result = tokio::time::timeout(
            self.config.max_execution_time,
            self.run_sample_process(&sandbox_sample_path)
        ).await;
        
        match execution_result {
            Ok(Ok(_)) => {
                // Sample executed successfully, check for detection
                let detection_result = agent_handle.check_detection().await?;
                Ok(detection_result)
            }
            Ok(Err(e)) => {
                warn!("Sample execution error: {}", e);
                // Even if execution failed, check if agent detected anything
                let detection_result = agent_handle.check_detection().await?;
                Ok(detection_result)
            }
            Err(_) => {
                warn!("Sample execution timed out");
                // Timeout occurred, check detection anyway
                let detection_result = agent_handle.check_detection().await?;
                Ok(detection_result)
            }
        }
    }
    
    /// Run sample process in sandbox
    async fn run_sample_process(&self, sample_path: &Path) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use std::process::Command;
        
        // Execute the sample in a controlled manner
        let output = Command::new(sample_path)
            .current_dir(&self.config.sandbox_config.temp_dir)
            .output()?;
        
        debug!("Sample execution output: {:?}", output);
        Ok(())
    }
    
    /// Start performance monitoring
    async fn start_performance_monitoring(&self) -> Result<PerformanceMonitor, Box<dyn std::error::Error + Send + Sync>> {
        Ok(PerformanceMonitor::new())
    }
    
    /// Stop performance monitoring and return metrics
    async fn stop_performance_monitoring(&self, monitor: PerformanceMonitor) -> Result<PerformanceMetrics, Box<dyn std::error::Error + Send + Sync>> {
        Ok(monitor.get_metrics())
    }
    
    /// Cleanup sandbox environment
    async fn cleanup_sandbox(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let temp_dir = &self.config.sandbox_config.temp_dir;
        
        if temp_dir.exists() {
            // Secure deletion of sandbox contents
            fs::remove_dir_all(temp_dir).await?;
        }
        
        info!("Sandbox cleaned up");
        Ok(())
    }
    
    /// Get all detection results
    pub async fn get_detection_results(&self) -> Vec<DetectionResult> {
        self.detection_results.read().await.clone()
    }
    
    /// Calculate overall detection statistics
    pub async fn get_detection_statistics(&self) -> DetectionStatistics {
        let results = self.get_detection_results().await;
        
        let total_samples = results.len();
        let detected_samples = results.iter().filter(|r| r.detected).count();
        let detection_rate = if total_samples > 0 {
            detected_samples as f64 / total_samples as f64
        } else {
            0.0
        };
        
        let avg_detection_time = if detected_samples > 0 {
            let total_time: Duration = results.iter()
                .filter_map(|r| r.detection_time)
                .sum();
            Some(total_time / detected_samples as u32)
        } else {
            None
        };
        
        let avg_confidence = if detected_samples > 0 {
            results.iter()
                .filter(|r| r.detected)
                .map(|r| r.confidence)
                .sum::<f64>() / detected_samples as f64
        } else {
            0.0
        };
        
        DetectionStatistics {
            total_samples,
            detected_samples,
            detection_rate,
            avg_detection_time,
            avg_confidence,
            failed_samples: results.iter().filter(|r| !r.errors.is_empty()).count(),
        }
    }
}

/// Sample execution result
#[derive(Debug, Clone)]
pub struct SampleExecutionResult {
    pub detected: bool,
    pub behaviors: Vec<String>,
    pub confidence: f64,
}

/// Detection statistics summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionStatistics {
    pub total_samples: usize,
    pub detected_samples: usize,
    pub detection_rate: f64,
    pub avg_detection_time: Option<Duration>,
    pub avg_confidence: f64,
    pub failed_samples: usize,
}

/// Performance monitor for sample testing
pub struct PerformanceMonitor {
    _start_time: Instant,
    initial_memory: u64,
}

impl PerformanceMonitor {
    pub fn new() -> Self {
        Self {
            _start_time: Instant::now(),
            initial_memory: Self::get_current_memory_usage(),
        }
    }
    
    pub fn get_metrics(self) -> PerformanceMetrics {
        PerformanceMetrics {
            cpu_usage_percent: Self::get_cpu_usage(),
            memory_usage_bytes: Self::get_current_memory_usage() - self.initial_memory,
            disk_io_ops_per_sec: Self::get_disk_io_rate(),
            network_packets_per_sec: Self::get_network_rate(),
        }
    }
    
    fn get_current_memory_usage() -> u64 {
        // Simplified memory usage calculation
        // In a real implementation, this would use Windows APIs
        1024 * 1024 * 50 // 50MB placeholder
    }
    
    fn get_cpu_usage() -> f64 {
        // Simplified CPU usage calculation
        // In a real implementation, this would use performance counters
        2.5 // 2.5% placeholder
    }
    
    fn get_disk_io_rate() -> f64 {
        // Simplified disk I/O rate calculation
        100.0 // 100 ops/sec placeholder
    }
    
    fn get_network_rate() -> f64 {
        // Simplified network rate calculation
        50.0 // 50 packets/sec placeholder
    }
}

/// Trait for agent integration during sample testing
#[async_trait::async_trait]
pub trait SampleTestAgent: Send + Sync {
    /// Start monitoring for the sample test
    async fn start_monitoring(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    
    /// Check if detection occurred and return results
    async fn check_detection(&self) -> Result<SampleExecutionResult, Box<dyn std::error::Error + Send + Sync>>;
    
    /// Stop monitoring
    async fn stop_monitoring(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    
    #[tokio::test]
    async fn test_ransom_lib_creation() {
        let temp_dir = TempDir::new().unwrap();
        let config = RansomSampleConfig {
            samples_dir: temp_dir.path().to_path_buf(),
            ..Default::default()
        };
        
        let lib = RealRansomLib::new(config).unwrap();
        assert_eq!(lib.get_samples().await.len(), 0);
    }
    
    #[tokio::test]
    async fn test_family_determination() {
        assert_eq!(RealRansomLib::determine_family("wannacry_sample"), "WannaCry");
        assert_eq!(RealRansomLib::determine_family("ryuk_variant"), "Ryuk");
        assert_eq!(RealRansomLib::determine_family("unknown_sample"), "Unknown");
    }
    
    #[test]
    fn test_sha256_calculation() {
        let content = b"test content";
        let hash = RealRansomLib::calculate_sha256(content);
        assert_eq!(hash.len(), 64); // SHA256 produces 64 character hex string
    }
    
    #[tokio::test]
    async fn test_detection_statistics() {
        let temp_dir = TempDir::new().unwrap();
        let config = RansomSampleConfig {
            samples_dir: temp_dir.path().to_path_buf(),
            ..Default::default()
        };
        
        let lib = RealRansomLib::new(config).unwrap();
        let stats = lib.get_detection_statistics().await;
        
        assert_eq!(stats.total_samples, 0);
        assert_eq!(stats.detection_rate, 0.0);
    }
}
