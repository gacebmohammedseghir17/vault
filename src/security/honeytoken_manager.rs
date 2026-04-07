//! HoneytokenManager - Decoy file monitoring for early ransomware detection
//!
//! This module implements a sophisticated honeytoken system that creates and monitors
//! decoy files to detect ransomware activity before it can cause significant damage.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use std::fs;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::{RwLock, mpsc};
use tokio::time::interval;
use uuid::Uuid;
use sha2::{Sha256, Digest};
use rand::{Rng, thread_rng};
use rand::distributions::Alphanumeric;


use crate::core::error::{EnhancedAgentError, Result};

/// Configuration for the honeytoken system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoneytokenConfig {
    /// Number of honeytokens to deploy per directory
    pub tokens_per_directory: usize,
    /// Directories to monitor with honeytokens
    pub monitored_directories: Vec<PathBuf>,
    /// File extensions to mimic
    pub target_extensions: Vec<String>,
    /// Check interval for honeytoken integrity
    pub check_interval: Duration,
    /// Maximum file size for honeytokens
    pub max_file_size: usize,
    /// Enable advanced entropy monitoring
    pub enable_entropy_monitoring: bool,
    /// Quarantine suspicious processes immediately
    pub auto_quarantine: bool,
}

impl Default for HoneytokenConfig {
    fn default() -> Self {
        Self {
            tokens_per_directory: 5,
            monitored_directories: vec![
                PathBuf::from("C:\\Users\\Public\\Documents"),
                PathBuf::from("C:\\Users\\Public\\Pictures"),
                PathBuf::from("C:\\temp"),
            ],
            target_extensions: vec![
                ".docx".to_string(), ".xlsx".to_string(), ".pdf".to_string(),
                ".jpg".to_string(), ".png".to_string(), ".txt".to_string(),
                ".pptx".to_string(), ".zip".to_string(),
            ],
            check_interval: Duration::from_secs(30),
            max_file_size: 1024 * 1024, // 1MB
            enable_entropy_monitoring: true,
            auto_quarantine: true,
        }
    }
}

/// Represents a deployed honeytoken
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Honeytoken {
    /// Unique identifier for the token
    pub id: Uuid,
    /// File path of the honeytoken
    pub path: PathBuf,
    /// Original file hash for integrity checking
    pub original_hash: String,
    /// File size in bytes
    pub size: usize,
    /// Creation timestamp
    pub created_at: SystemTime,
    /// Last verification timestamp
    pub last_verified: SystemTime,
    /// File extension
    pub extension: String,
    /// Expected entropy range
    pub entropy_range: (f64, f64),
    /// Access count (should remain 0)
    pub access_count: u32,
}

/// Detection event from honeytoken monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoneytokenEvent {
    /// Event unique identifier
    pub id: Uuid,
    /// Affected honeytoken
    pub token: Honeytoken,
    /// Type of detected activity
    pub event_type: HoneytokenEventType,
    /// Process that triggered the event
    pub process_info: ProcessInfo,
    /// Detection timestamp
    pub timestamp: SystemTime,
    /// Threat severity level
    pub severity: ThreatSeverity,
    /// Additional context information
    pub context: HashMap<String, String>,
}

/// Types of honeytoken events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HoneytokenEventType {
    /// File was accessed/opened
    FileAccessed,
    /// File was modified
    FileModified,
    /// File was encrypted
    FileEncrypted,
    /// File was deleted
    FileDeleted,
    /// File was moved/renamed
    FileMoved,
    /// Suspicious entropy change detected
    EntropyAnomaly,
    /// Multiple honeytokens affected simultaneously
    MassModification,
}

/// Process information for event attribution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub path: PathBuf,
    pub command_line: String,
    pub parent_pid: u32,
    pub user: String,
    pub start_time: SystemTime,
}

/// Threat severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ThreatSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Statistics for honeytoken deployment and monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoneytokenStatistics {
    pub total_deployed: usize,
    pub active_tokens: usize,
    pub compromised_tokens: usize,
    pub total_events: usize,
    pub events_by_type: HashMap<String, usize>,
    pub average_detection_time: Duration,
    pub false_positive_rate: f64,
    pub last_update: SystemTime,
}

/// Main honeytoken management system
pub struct HoneytokenManager {
    config: HoneytokenConfig,
    deployed_tokens: Arc<RwLock<HashMap<Uuid, Honeytoken>>>,
    event_history: RwLock<Vec<HoneytokenEvent>>,
    statistics: RwLock<HoneytokenStatistics>,
    event_sender: mpsc::UnboundedSender<HoneytokenEvent>,
    shutdown_signal: RwLock<Option<mpsc::Sender<()>>>,
}

impl HoneytokenManager {
    /// Create a new HoneytokenManager instance
    pub fn new(config: HoneytokenConfig) -> Result<(Self, mpsc::UnboundedReceiver<HoneytokenEvent>)> {
        let (event_sender, event_receiver) = mpsc::unbounded_channel();
        
        let manager = Self {
            config,
            deployed_tokens: Arc::new(RwLock::new(HashMap::new())),
            event_history: RwLock::new(Vec::new()),
            statistics: RwLock::new(HoneytokenStatistics {
                total_deployed: 0,
                active_tokens: 0,
                compromised_tokens: 0,
                total_events: 0,
                events_by_type: HashMap::new(),
                average_detection_time: Duration::from_secs(0),
                false_positive_rate: 0.0,
                last_update: SystemTime::now(),
            }),
            event_sender,
            shutdown_signal: RwLock::new(None),
        };
        
        Ok((manager, event_receiver))
    }
    
    /// Initialize and deploy honeytokens
    pub async fn initialize(&self) -> Result<()> {
        log::info!("Initializing HoneytokenManager with {} monitored directories", 
                  self.config.monitored_directories.len());
        
        // Deploy honeytokens in each monitored directory
        for directory in &self.config.monitored_directories {
            if let Err(e) = self.deploy_tokens_in_directory(directory).await {
                log::warn!("Failed to deploy tokens in {:?}: {}", directory, e);
            }
        }
        
        // Start monitoring task
        self.start_monitoring().await?;
        
        log::info!("HoneytokenManager initialized successfully");
        Ok(())
    }
    
    /// Deploy honeytokens in a specific directory
    async fn deploy_tokens_in_directory(&self, directory: &Path) -> Result<()> {
        if !directory.exists() {
            fs::create_dir_all(directory)
                .map_err(|e| EnhancedAgentError::Io(e.to_string()))?;
        }
        
        let mut deployed_count = 0;
        let mut tokens = self.deployed_tokens.write().await;
        
        for _ in 0..self.config.tokens_per_directory {
            if let Ok(token) = self.create_honeytoken(directory).await {
                tokens.insert(token.id, token);
                deployed_count += 1;
            }
        }
        
        log::info!("Deployed {} honeytokens in {:?}", deployed_count, directory);
        Ok(())
    }
    
    /// Create a single honeytoken file
    async fn create_honeytoken(&self, directory: &Path) -> Result<Honeytoken> {
        let extension = self.config.target_extensions
            .get(thread_rng().gen_range(0..self.config.target_extensions.len()))
            .unwrap()
            .clone();
        
        let filename = format!("{}{}", self.generate_realistic_filename(&extension), extension);
        let path = directory.join(filename);
        
        // Generate realistic file content
        let content = self.generate_file_content(&extension)?;
        
        // Write the file
        fs::write(&path, &content)
            .map_err(|e| EnhancedAgentError::Io(e.to_string()))?;
        
        // Calculate hash and entropy
        let hash = self.calculate_file_hash(&content);
        let entropy = self.calculate_entropy(&content);
        
        let token = Honeytoken {
            id: Uuid::new_v4(),
            path,
            original_hash: hash,
            size: content.len(),
            created_at: SystemTime::now(),
            last_verified: SystemTime::now(),
            extension,
            entropy_range: (entropy - 0.1, entropy + 0.1),
            access_count: 0,
        };
        
        Ok(token)
    }
    
    /// Generate realistic filename based on extension
    fn generate_realistic_filename(&self, extension: &str) -> String {
        let prefixes = match extension {
            ".docx" => vec!["Report", "Document", "Proposal", "Meeting_Notes", "Project"],
            ".xlsx" => vec!["Budget", "Data", "Analysis", "Spreadsheet", "Financial"],
            ".pdf" => vec!["Manual", "Guide", "Specification", "Contract", "Invoice"],
            ".jpg" | ".png" => vec!["Image", "Photo", "Screenshot", "Diagram", "Chart"],
            ".txt" => vec!["Notes", "Log", "Config", "Readme", "Info"],
            _ => vec!["File", "Data", "Backup", "Archive", "Document"],
        };
        
        let prefix = prefixes[thread_rng().gen_range(0..prefixes.len())];
        let suffix: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(6)
            .map(char::from)
            .collect();
        
        format!("{}_{}", prefix, suffix)
    }
    
    /// Generate realistic file content
    fn generate_file_content(&self, extension: &str) -> Result<Vec<u8>> {
        let size = thread_rng().gen_range(1024..self.config.max_file_size);
        
        match extension {
            ".txt" => {
                let content = "This is a test document for security monitoring.\n"
                    .repeat(size / 50);
                Ok(content.into_bytes())
            },
            ".docx" | ".xlsx" | ".pdf" => {
                // Generate binary-like content with realistic entropy
                let mut content = vec![0u8; size];
                thread_rng().fill(&mut content[..]);
                
                // Add some structure to make it look more realistic
                for i in (0..size).step_by(256) {
                    if i + 4 < size {
                        content[i..i+4].copy_from_slice(b"\x50\x4B\x03\x04"); // ZIP header
                    }
                }
                Ok(content)
            },
            ".jpg" | ".png" => {
                // Generate image-like content
                let mut content = vec![0u8; size];
                thread_rng().fill(&mut content[..]);
                
                // Add JPEG/PNG headers
                if extension == ".jpg" && size > 10 {
                    content[0..2].copy_from_slice(b"\xFF\xD8");
                    content[size-2..].copy_from_slice(b"\xFF\xD9");
                } else if extension == ".png" && size > 8 {
                    content[0..8].copy_from_slice(b"\x89PNG\r\n\x1A\n");
                }
                Ok(content)
            },
            _ => {
                let mut content = vec![0u8; size];
                thread_rng().fill(&mut content[..]);
                Ok(content)
            }
        }
    }
    
    /// Calculate SHA256 hash of content
    fn calculate_file_hash(&self, content: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content);
        format!("{:x}", hasher.finalize())
    }
    
    /// Calculate entropy of file content
    fn calculate_entropy(&self, data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        
        let mut counts = [0u32; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }
        
        let len = data.len() as f64;
        let mut entropy = 0.0;
        
        for &count in &counts {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }
        
        entropy
    }
    
    /// Start the monitoring task
    async fn start_monitoring(&self) -> Result<()> {
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);
        *self.shutdown_signal.write().await = Some(shutdown_tx);
        
        let config = self.config.clone();
        let deployed_tokens = Arc::clone(&self.deployed_tokens);
        let event_sender = self.event_sender.clone();
        
        tokio::spawn(async move {
            let mut interval = interval(config.check_interval);
            
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        if let Err(e) = Self::check_tokens(&deployed_tokens, &event_sender).await {
                            log::error!("Error checking tokens: {}", e);
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        log::info!("Honeytoken monitoring task shutting down");
                        break;
                    }
                }
            }
        });
        
        Ok(())
    }
    
    /// Check all deployed tokens for integrity
    async fn check_tokens(
        deployed_tokens: &RwLock<HashMap<Uuid, Honeytoken>>,
        event_sender: &mpsc::UnboundedSender<HoneytokenEvent>,
    ) -> Result<()> {
        let tokens = deployed_tokens.read().await;
        
        for token in tokens.values() {
            if let Err(e) = Self::verify_token_integrity(token, event_sender).await {
                log::warn!("Failed to verify token {:?}: {}", token.path, e);
            }
        }
        
        Ok(())
    }
    
    /// Verify integrity of a single token
    async fn verify_token_integrity(
        token: &Honeytoken,
        event_sender: &mpsc::UnboundedSender<HoneytokenEvent>,
    ) -> Result<()> {
        if !token.path.exists() {
            // File was deleted
            let event = HoneytokenEvent {
                id: Uuid::new_v4(),
                token: token.clone(),
                event_type: HoneytokenEventType::FileDeleted,
                process_info: Self::get_current_process_info(),
                timestamp: SystemTime::now(),
                severity: ThreatSeverity::High,
                context: HashMap::new(),
            };
            
            let _ = event_sender.send(event);
            return Ok(());
        }
        
        // Read current file content
        let current_content = fs::read(&token.path)
            .map_err(|e| EnhancedAgentError::Io(e.to_string()))?;
        
        // Check hash
        let current_hash = {
            let mut hasher = Sha256::new();
            hasher.update(&current_content);
            format!("{:x}", hasher.finalize())
        };
        
        if current_hash != token.original_hash {
            // File was modified
            let mut context = HashMap::new();
            context.insert("original_hash".to_string(), token.original_hash.clone());
            context.insert("current_hash".to_string(), current_hash);
            context.insert("size_change".to_string(), 
                          (current_content.len() as i64 - token.size as i64).to_string());
            
            let event_type = if Self::is_likely_encrypted(&current_content) {
                HoneytokenEventType::FileEncrypted
            } else {
                HoneytokenEventType::FileModified
            };
            
            let event = HoneytokenEvent {
                id: Uuid::new_v4(),
                token: token.clone(),
                event_type,
                process_info: Self::get_current_process_info(),
                timestamp: SystemTime::now(),
                severity: ThreatSeverity::Critical,
                context,
            };
            
            let _ = event_sender.send(event);
        }
        
        Ok(())
    }
    
    /// Check if content appears to be encrypted
    fn is_likely_encrypted(content: &[u8]) -> bool {
        if content.len() < 100 {
            return false;
        }
        
        // Calculate entropy
        let mut counts = [0u32; 256];
        for &byte in content {
            counts[byte as usize] += 1;
        }
        
        let len = content.len() as f64;
        let mut entropy = 0.0;
        
        for &count in &counts {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }
        
        // High entropy suggests encryption
        entropy > 7.5
    }
    
    /// Get current process information (placeholder)
    fn get_current_process_info() -> ProcessInfo {
        ProcessInfo {
            pid: std::process::id(),
            name: "unknown".to_string(),
            path: PathBuf::from("unknown"),
            command_line: "unknown".to_string(),
            parent_pid: 0,
            user: "unknown".to_string(),
            start_time: SystemTime::now(),
        }
    }
    
    /// Get current statistics
    pub async fn get_statistics(&self) -> HoneytokenStatistics {
        self.statistics.read().await.clone()
    }
    
    /// Get all deployed tokens
    pub async fn get_deployed_tokens(&self) -> Vec<Honeytoken> {
        self.deployed_tokens.read().await.values().cloned().collect()
    }
    
    /// Clean up and remove all honeytokens
    pub async fn cleanup(&self) -> Result<()> {
        log::info!("Cleaning up honeytokens");
        
        // Signal shutdown
        if let Some(shutdown_tx) = self.shutdown_signal.write().await.take() {
            let _ = shutdown_tx.send(()).await;
        }
        
        // Remove all deployed tokens
        let tokens = self.deployed_tokens.read().await;
        for token in tokens.values() {
            if token.path.exists() {
                if let Err(e) = fs::remove_file(&token.path) {
                    log::warn!("Failed to remove honeytoken {:?}: {}", token.path, e);
                }
            }
        }
        
        log::info!("Honeytoken cleanup completed");
        Ok(())
    }
}

impl Drop for HoneytokenManager {
    fn drop(&mut self) {
        // Best effort cleanup
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            rt.spawn(async {
                // Cleanup logic here if needed
            });
        }
    }
}
