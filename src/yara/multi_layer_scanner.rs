//! Multi-Layer Detection Engine for ERDPS Agent
//!
//! This module provides a comprehensive multi-layer scanning system that orchestrates
//! parallel scanning across file, memory, behavior, and network layers with weighted
//! risk scoring and database integration.

use anyhow::Result;
use rayon::prelude::*;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use super::file_scanner::YaraFileScanner;
use crate::error::AgentError;

/// Scan target types for multi-layer detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScanTarget {
    /// Single file target
    File(PathBuf),
    /// Directory target for recursive scanning
    Directory(PathBuf),
}

/// Layered scan result containing matches from all scanning layers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayeredScanResult {
    /// File layer matches
    pub file_matches: Vec<RuleMatch>,
    /// Memory layer matches
    pub memory_matches: Vec<RuleMatch>,
    /// Behavior layer matches
    pub behavior_matches: Vec<RuleMatch>,
    /// Network layer matches
    pub network_matches: Vec<RuleMatch>,
    /// Computed risk score (0.0 to 1.0)
    pub risk_score: f32,
    /// Scan timestamp
    pub timestamp: u64,
    /// Target information
    pub target: String,
    /// Scan duration in milliseconds
    pub scan_duration_ms: u64,
}

/// Rule match information compatible with existing YARA structures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMatch {
    /// Rule name
    pub rule_name: String,
    /// Rule namespace
    pub namespace: Option<String>,
    /// Rule tags
    pub tags: Vec<String>,
    /// Rule metadata
    pub metadata: HashMap<String, String>,
    /// Match confidence (0.0 to 1.0)
    pub confidence: f32,
    /// Match severity level
    pub severity: String,
}

/// File scanner wrapper for multi-layer integration
#[derive(Debug)]
pub struct FileScanner {
    inner: Arc<RwLock<YaraFileScanner>>,
}

/// Memory scanner for process memory analysis
#[derive(Debug)]
pub struct MemoryScanner {
    enabled: bool,
}

/// Behavior scanner for behavioral analysis
#[derive(Debug)]
pub struct BehaviorScanner {
    enabled: bool,
}

/// Network scanner for network traffic analysis
#[derive(Debug)]
pub struct NetworkScanner {
    enabled: bool,
}

/// Multi-layer detection engine
#[derive(Debug)]
pub struct MultiLayerScanner {
    file_scanner: FileScanner,
    memory_scanner: MemoryScanner,
    behavior_scanner: BehaviorScanner,
    network_scanner: NetworkScanner,
    database_path: PathBuf,
}

impl FileScanner {
    /// Create a new file scanner
    pub fn new(yara_scanner: Arc<RwLock<YaraFileScanner>>) -> Self {
        Self {
            inner: yara_scanner,
        }
    }

    /// Scan a file for YARA matches
    pub async fn scan(&self, path: &Path) -> Result<Vec<RuleMatch>, AgentError> {
        info!("Starting file scan for: {:?}", path);

        let scanner = self.inner.read().await;
        let scan_result = scanner
            .scan_file(path)
            .await
            .map_err(|e| AgentError::SystemError(format!("File scan failed: {}", e)))?;

        let matches: Vec<RuleMatch> = scan_result
            .matches
            .into_iter()
            .map(|yara_match| RuleMatch {
                rule_name: yara_match.rule_name,
                namespace: yara_match.namespace,
                tags: yara_match.tags,
                metadata: yara_match.metadata,
                confidence: 0.8, // Default confidence for file matches
                severity: "medium".to_string(),
            })
            .collect();

        debug!("File scan completed with {} matches", matches.len());
        Ok(matches)
    }
}

impl MemoryScanner {
    /// Create a new memory scanner
    pub fn new() -> Self {
        Self { enabled: true }
    }

    /// Scan process memory (mock implementation)
    pub async fn scan(&self, _target: &Path) -> Result<Vec<RuleMatch>, AgentError> {
        info!("Starting memory scan");

        if !self.enabled {
            debug!("Memory scanner disabled, returning empty results");
            return Ok(vec![]);
        }

        // Mock memory scanning - in production this would analyze process memory
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let matches = vec![];
        debug!("Memory scan completed with {} matches", matches.len());
        Ok(matches)
    }
}

impl BehaviorScanner {
    /// Create a new behavior scanner
    pub fn new() -> Self {
        Self { enabled: true }
    }

    /// Scan for behavioral indicators (mock implementation)
    pub async fn scan(&self, _target: &Path) -> Result<Vec<RuleMatch>, AgentError> {
        info!("Starting behavior scan");

        if !self.enabled {
            debug!("Behavior scanner disabled, returning empty results");
            return Ok(vec![]);
        }

        // Mock behavior scanning - in production this would analyze system behavior
        tokio::time::sleep(tokio::time::Duration::from_millis(150)).await;

        let matches = vec![];
        debug!("Behavior scan completed with {} matches", matches.len());
        Ok(matches)
    }
}

impl NetworkScanner {
    /// Create a new network scanner
    pub fn new() -> Self {
        Self { enabled: true }
    }

    /// Scan for network indicators (mock implementation)
    pub async fn scan(&self, _target: &Path) -> Result<Vec<RuleMatch>, AgentError> {
        info!("Starting network scan");

        if !self.enabled {
            debug!("Network scanner disabled, returning empty results");
            return Ok(vec![]);
        }

        // Mock network scanning - in production this would analyze network traffic
        tokio::time::sleep(tokio::time::Duration::from_millis(80)).await;

        let matches = vec![];
        debug!("Network scan completed with {} matches", matches.len());
        Ok(matches)
    }
}

impl MultiLayerScanner {
    /// Create a new multi-layer scanner
    pub fn new(file_scanner: Arc<RwLock<YaraFileScanner>>, database_path: PathBuf) -> Self {
        Self {
            file_scanner: FileScanner::new(file_scanner),
            memory_scanner: MemoryScanner::new(),
            behavior_scanner: BehaviorScanner::new(),
            network_scanner: NetworkScanner::new(),
            database_path,
        }
    }

    /// Perform multi-layer scan on target
    pub async fn scan(&self, target: ScanTarget) -> Result<LayeredScanResult, AgentError> {
        let start_time = std::time::Instant::now();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        info!("Starting multi-layer scan for target: {:?}", target);

        let _target_string = match &target {
            ScanTarget::File(path) => path.to_string_lossy().to_string(),
            ScanTarget::Directory(path) => path.to_string_lossy().to_string(),
        };

        match target {
            ScanTarget::File(path) => self.scan_single_file(&path, timestamp, start_time).await,
            ScanTarget::Directory(path) => self.scan_directory(&path, timestamp, start_time).await,
        }
    }

    /// Scan a single file with all layers
    async fn scan_single_file(
        &self,
        path: &Path,
        timestamp: u64,
        start_time: std::time::Instant,
    ) -> Result<LayeredScanResult, AgentError> {
        info!("Scanning single file: {:?}", path);

        // Spawn concurrent tasks for each scanning layer
        let file_task = {
            let scanner = &self.file_scanner;
            let path = path.to_path_buf();
            async move {
                info!("File layer scan started");
                let result = scanner.scan(&path).await;
                info!("File layer scan finished");
                result
            }
        };

        let memory_task = {
            let scanner = &self.memory_scanner;
            let path = path.to_path_buf();
            async move {
                info!("Memory layer scan started");
                let result = scanner.scan(&path).await;
                info!("Memory layer scan finished");
                result
            }
        };

        let behavior_task = {
            let scanner = &self.behavior_scanner;
            let path = path.to_path_buf();
            async move {
                info!("Behavior layer scan started");
                let result = scanner.scan(&path).await;
                info!("Behavior layer scan finished");
                result
            }
        };

        let network_task = {
            let scanner = &self.network_scanner;
            let path = path.to_path_buf();
            async move {
                info!("Network layer scan started");
                let result = scanner.scan(&path).await;
                info!("Network layer scan finished");
                result
            }
        };

        // Execute all scans concurrently
        let (file_result, memory_result, behavior_result, network_result) =
            tokio::join!(file_task, memory_task, behavior_task, network_task);

        // Collect results
        let file_matches = file_result.unwrap_or_else(|e| {
            error!("File scan failed: {}", e);
            vec![]
        });
        let memory_matches = memory_result.unwrap_or_else(|e| {
            error!("Memory scan failed: {}", e);
            vec![]
        });
        let behavior_matches = behavior_result.unwrap_or_else(|e| {
            error!("Behavior scan failed: {}", e);
            vec![]
        });
        let network_matches = network_result.unwrap_or_else(|e| {
            error!("Network scan failed: {}", e);
            vec![]
        });

        debug!("File matches: {}", file_matches.len());
        debug!("Memory matches: {}", memory_matches.len());
        debug!("Behavior matches: {}", behavior_matches.len());
        debug!("Network matches: {}", network_matches.len());

        // Calculate risk score
        let risk_score = self.calculate_risk_score(
            &file_matches,
            &memory_matches,
            &behavior_matches,
            &network_matches,
        );

        let scan_duration_ms = start_time.elapsed().as_millis() as u64;
        let target_string = path.to_string_lossy().to_string();

        let result = LayeredScanResult {
            file_matches,
            memory_matches,
            behavior_matches,
            network_matches,
            risk_score,
            timestamp,
            target: target_string.clone(),
            scan_duration_ms,
        };

        // Store results in database
        if let Err(e) = self.store_scan_result(&result).await {
            warn!("Failed to store scan result in database: {}", e);
        }

        info!(
            "Multi-layer scan completed with risk score: {:.2}",
            risk_score
        );
        Ok(result)
    }

    /// Scan a directory recursively
    async fn scan_directory(
        &self,
        path: &Path,
        timestamp: u64,
        start_time: std::time::Instant,
    ) -> Result<LayeredScanResult, AgentError> {
        info!("Scanning directory: {:?}", path);

        // Collect all files in directory recursively
        let files = self.collect_files_recursive(path).await?;
        info!("Found {} files to scan", files.len());

        // Process files in parallel using Rayon
        let all_results: Vec<LayeredScanResult> = files
            .par_iter()
            .map(|file_path| {
                // Use tokio runtime for async operations in parallel context
                let rt = tokio::runtime::Handle::current();
                rt.block_on(async {
                    self.scan_single_file(file_path, timestamp, std::time::Instant::now())
                        .await
                        .unwrap_or_else(|e| {
                            error!("Failed to scan file {:?}: {}", file_path, e);
                            LayeredScanResult {
                                file_matches: vec![],
                                memory_matches: vec![],
                                behavior_matches: vec![],
                                network_matches: vec![],
                                risk_score: 0.0,
                                timestamp,
                                target: file_path.to_string_lossy().to_string(),
                                scan_duration_ms: 0,
                            }
                        })
                })
            })
            .collect();

        // Aggregate results
        let mut aggregated_file_matches = Vec::new();
        let mut aggregated_memory_matches = Vec::new();
        let mut aggregated_behavior_matches = Vec::new();
        let mut aggregated_network_matches = Vec::new();
        let mut total_risk_score = 0.0;

        for result in all_results {
            aggregated_file_matches.extend(result.file_matches);
            aggregated_memory_matches.extend(result.memory_matches);
            aggregated_behavior_matches.extend(result.behavior_matches);
            aggregated_network_matches.extend(result.network_matches);
            total_risk_score += result.risk_score;
        }

        // Normalize risk score
        let normalized_risk_score = if files.is_empty() {
            0.0
        } else {
            (total_risk_score / files.len() as f32).min(1.0)
        };

        let scan_duration_ms = start_time.elapsed().as_millis() as u64;
        let target_string = path.to_string_lossy().to_string();

        let result = LayeredScanResult {
            file_matches: aggregated_file_matches,
            memory_matches: aggregated_memory_matches,
            behavior_matches: aggregated_behavior_matches,
            network_matches: aggregated_network_matches,
            risk_score: normalized_risk_score,
            timestamp,
            target: target_string,
            scan_duration_ms,
        };

        // Store aggregated results in database
        if let Err(e) = self.store_scan_result(&result).await {
            warn!("Failed to store directory scan result in database: {}", e);
        }

        info!(
            "Directory scan completed with {} total matches and risk score: {:.2}",
            result.file_matches.len()
                + result.memory_matches.len()
                + result.behavior_matches.len()
                + result.network_matches.len(),
            normalized_risk_score
        );

        Ok(result)
    }

    /// Collect all files in directory recursively
    fn collect_files_recursive<'a>(
        &'a self,
        dir: &'a Path,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<PathBuf>, AgentError>> + Send + 'a>,
    > {
        Box::pin(async move {
            let mut files = Vec::new();
            let mut entries = fs::read_dir(dir).await.map_err(|e| AgentError::Io {
                message: format!("Failed to read directory: {}", e),
                path: Some(dir.to_path_buf()),
                operation: Some("read_directory".to_string()),
                context: None,
            })?;

            while let Some(entry) = entries.next_entry().await.map_err(|e| AgentError::Io {
                message: format!("Failed to read directory entry: {}", e),
                path: Some(dir.to_path_buf()),
                operation: Some("read_directory_entry".to_string()),
                context: None,
            })? {
                let path = entry.path();
                if path.is_file() {
                    files.push(path);
                } else if path.is_dir() {
                    let mut sub_files = self.collect_files_recursive(&path).await?;
                    files.append(&mut sub_files);
                }
            }

            Ok(files)
        })
    }

    /// Calculate weighted risk score
    fn calculate_risk_score(
        &self,
        file_matches: &[RuleMatch],
        memory_matches: &[RuleMatch],
        behavior_matches: &[RuleMatch],
        network_matches: &[RuleMatch],
    ) -> f32 {
        // Weights: 0.4*file + 0.3*behavior + 0.2*memory + 0.1*network
        let file_score = (file_matches.len() as f32).min(10.0) / 10.0;
        let memory_score = (memory_matches.len() as f32).min(10.0) / 10.0;
        let behavior_score = (behavior_matches.len() as f32).min(10.0) / 10.0;
        let network_score = (network_matches.len() as f32).min(10.0) / 10.0;

        let weighted_score =
            0.4 * file_score + 0.3 * behavior_score + 0.2 * memory_score + 0.1 * network_score;
        weighted_score.min(1.0)
    }

    /// Store scan result in database
    async fn store_scan_result(&self, result: &LayeredScanResult) -> Result<(), AgentError> {
        let conn = Connection::open(&self.database_path).map_err(|e| AgentError::Database {
            message: format!("Failed to open database: {}", e),
            operation: Some("open".to_string()),
            transaction_id: None,
            context: None,
        })?;

        // Create table if it doesn't exist
        conn.execute(
            "CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                risk_score REAL NOT NULL,
                timestamp INTEGER NOT NULL,
                scan_duration_ms INTEGER NOT NULL,
                file_matches INTEGER NOT NULL,
                memory_matches INTEGER NOT NULL,
                behavior_matches INTEGER NOT NULL,
                network_matches INTEGER NOT NULL
            )",
            [],
        )
        .map_err(|e| AgentError::Database {
            message: format!("Failed to create scan_results table: {}", e),
            operation: Some("create_table".to_string()),
            transaction_id: None,
            context: None,
        })?;

        // Insert scan result
        conn.execute(
            "INSERT INTO scan_results (
                target, risk_score, timestamp, scan_duration_ms,
                file_matches, memory_matches, behavior_matches, network_matches
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                result.target,
                result.risk_score,
                result.timestamp as i64,
                result.scan_duration_ms as i64,
                result.file_matches.len() as i64,
                result.memory_matches.len() as i64,
                result.behavior_matches.len() as i64,
                result.network_matches.len() as i64,
            ],
        )
        .map_err(|e| AgentError::Database {
            message: format!("Failed to insert scan result: {}", e),
            operation: Some("insert".to_string()),
            transaction_id: None,
            context: None,
        })?;

        debug!("Scan result stored in database successfully");
        Ok(())
    }
}

/// Default implementations
impl Default for MemoryScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for BehaviorScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for NetworkScanner {
    fn default() -> Self {
        Self::new()
    }
}
