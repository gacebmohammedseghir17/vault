//!
//! Enhanced YARA Integration Module with Production-Ready Error Handling
//!
//! This module provides a production-ready YARA integration with comprehensive
//! error handling, recovery mechanisms, and performance monitoring.

use crate::config::AgentConfig;
use crate::error::{
    YaraError, YaraErrorHandler, create_error_context,
    FileSystemErrorKind, ScanErrorKind,
    RecoveryStrategy
};
// Scanning module imports (temporarily disabled)
// use crate::scanning::yara_scanner::{ProductionYaraScanner, ScanConfig, ScanStatistics};
// use crate::scanning::yara_scanner_production::{ThreatLevel, ProductionScanResult};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Mutex};
use tracing::{debug, error, info, warn, instrument};

/// Enhanced YARA scan result with additional metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedYaraScanResult {
    /// Original scan result
    pub result: ProductionScanResult,
    /// Processing timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Scan context information
    pub context: ScanContext,
    /// Error information (if any)
    pub error: Option<String>,
}

/// Context information for scan operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanContext {
    /// Scan session ID
    pub session_id: String,
    /// Scanner configuration used
    pub config_hash: String,
    /// System resource usage at scan time
    pub resource_usage: ResourceUsage,
    /// Scan performance metrics
    pub performance: PerformanceMetrics,
}

/// System resource usage information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsage {
    /// Memory usage in bytes
    pub memory_usage: u64,
    /// CPU usage percentage
    pub cpu_usage: f32,
    /// Disk I/O operations per second
    pub disk_iops: u32,
    /// Network usage in bytes per second
    pub network_usage: u64,
}

/// Performance metrics for scan operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    /// Total scan duration
    pub total_duration: Duration,
    /// Time spent on file I/O
    pub io_duration: Duration,
    /// Time spent on actual scanning
    pub scan_duration: Duration,
    /// Files processed per second
    pub throughput: f32,
    /// Average file processing time
    pub avg_file_time: Duration,
}

/// Enhanced statistics with error tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedYaraScanStats {
    /// Basic scan statistics
    pub basic_stats: ScanStatistics,
    /// Error statistics
    pub error_count: u64,
    /// Recovery success rate
    pub recovery_success_rate: f32,
    /// Performance trends
    pub performance_trend: Vec<PerformanceDataPoint>,
    /// Resource usage history
    pub resource_history: Vec<ResourceUsage>,
}

/// Performance data point for trending
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceDataPoint {
    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Throughput (files/second)
    pub throughput: f32,
    /// Error rate
    pub error_rate: f32,
    /// Average response time
    pub avg_response_time: Duration,
}

/// Enhanced YARA integration with production-ready features
pub struct EnhancedYaraIntegration {
    /// Configuration
    config: Arc<RwLock<AgentConfig>>,
    /// Production scanner
    scanner: Arc<Mutex<Option<ProductionYaraScanner>>>,
    /// Error handler
    error_handler: Arc<YaraErrorHandler>,
    /// Enhanced statistics
    stats: Arc<RwLock<EnhancedYaraScanStats>>,
    /// Running state
    is_running: Arc<RwLock<bool>>,
    /// Current session ID
    session_id: Arc<RwLock<String>>,
    /// Performance monitor
    performance_monitor: Arc<Mutex<PerformanceMonitor>>,
}

/// Performance monitoring component
struct PerformanceMonitor {
    /// Recent performance data
    recent_data: std::collections::VecDeque<PerformanceDataPoint>,
    /// Maximum data points to keep
    max_data_points: usize,
    /// Performance thresholds
    thresholds: PerformanceThresholds,
}

/// Performance thresholds for alerting
#[derive(Debug, Clone)]
struct PerformanceThresholds {
    /// Minimum acceptable throughput (files/second)
    min_throughput: f32,
    /// Maximum acceptable error rate
    max_error_rate: f32,
    /// Maximum acceptable response time
    max_response_time: Duration,
    /// Maximum memory usage (bytes)
    max_memory_usage: u64,
}

impl EnhancedYaraIntegration {
    /// Create a new enhanced YARA integration instance
    pub fn new(config: Arc<RwLock<AgentConfig>>) -> Self {
        let error_handler = Arc::new(YaraErrorHandler::new());
        let session_id = Arc::new(RwLock::new(uuid::Uuid::new_v4().to_string()));
        
        let performance_monitor = Arc::new(Mutex::new(PerformanceMonitor {
            recent_data: std::collections::VecDeque::new(),
            max_data_points: 1000,
            thresholds: PerformanceThresholds {
                min_throughput: 10.0, // 10 files/second minimum
                max_error_rate: 0.05,  // 5% maximum error rate
                max_response_time: Duration::from_secs(30),
                max_memory_usage: 1024 * 1024 * 1024, // 1GB maximum
            },
        }));

        Self {
            config,
            scanner: Arc::new(Mutex::new(None)),
            error_handler,
            stats: Arc::new(RwLock::new(EnhancedYaraScanStats {
                basic_stats: ScanStatistics::default(),
                error_count: 0,
                recovery_success_rate: 1.0,
                performance_trend: Vec::new(),
                resource_history: Vec::new(),
            })),
            is_running: Arc::new(RwLock::new(false)),
            session_id,
            performance_monitor,
        }
    }

    /// Initialize the scanner with current configuration
    #[instrument(skip(self))]
    pub async fn initialize(&self) -> Result<(), YaraError> {
        let config_guard = self.config.read().await;
        let yara_config = &config_guard.yara;
        
        if !yara_config.enabled {
            info!("YARA scanning is disabled in configuration");
            return Ok(());
        }

        let scan_config = ScanConfig {
            max_file_size: 100 * 1024 * 1024, // 100MB
            max_memory_usage: 512 * 1024 * 1024, // 512MB
            scan_timeout: Duration::from_secs(30),
            max_concurrent_scans: 4,
            ignore_system_files: true,
            ignore_readonly_files: false,
            ignore_locked_files: true,
            ignored_extensions: vec![
                ".tmp".to_string(),
                ".log".to_string(),
                ".bak".to_string(),
            ],
            ignored_directories: vec![
                "System Volume Information".to_string(),
                "$Recycle.Bin".to_string(),
                "Windows\\System32".to_string(),
            ],
        };

        let rules_dir = PathBuf::from(&yara_config.rules_path);
        
        match ProductionYaraScanner::new(rules_dir, scan_config).await {
            Ok(scanner) => {
                let mut scanner_guard = self.scanner.lock().await;
                *scanner_guard = Some(scanner);
                info!("YARA scanner initialized successfully");
                Ok(())
            }
            Err(e) => {
                let error = YaraError::InitializationError {
                    message: format!("Failed to initialize YARA scanner: {}", e),
                    source: Some(Box::new(e)),
                };
                
                let context = create_error_context("scanner_initialization");
                self.error_handler.handle_error(&error, context).await?;
                
                Err(error)
            }
        }
    }

    /// Start periodic YARA scanning with enhanced error handling
    #[instrument(skip(self))]
    pub async fn start_periodic_scanning(&self) -> Result<(), YaraError> {
        let mut is_running = self.is_running.write().await;
        if *is_running {
            warn!("YARA periodic scanning is already running");
            return Ok(());
        }
        *is_running = true;
        drop(is_running);

        // Initialize scanner if not already done
        self.initialize().await?;

        let config = self.config.clone();
        let scanner = self.scanner.clone();
        let error_handler = self.error_handler.clone();
        let stats = self.stats.clone();
        let is_running = self.is_running.clone();
        let session_id = self.session_id.clone();
        let performance_monitor = self.performance_monitor.clone();

        tokio::spawn(async move {
            let mut retry_count = 0;
            const MAX_RETRIES: u32 = 3;
            
            loop {
                // Check if we should continue running
                {
                    let running = is_running.read().await;
                    if !*running {
                        break;
                    }
                }

                // Get current configuration
                let config_guard = config.read().await;
                let yara_config = &config_guard.yara;
                let scan_enabled = yara_config.enabled;
                // Use target processes as scan paths for now (this may need adjustment based on actual requirements)
        let scan_paths = vec!["/".to_string()]; // Default scan path
        let interval_seconds = yara_config.directory_scan_interval_secs;
                drop(config_guard);

                if !scan_enabled {
                    debug!("YARA scanning is disabled, waiting for next interval");
                    tokio::time::sleep(Duration::from_secs(interval_seconds as u64)).await;
                    continue;
                }

                // Generate new session ID for this scan
                {
                    let mut session_guard = session_id.write().await;
                    *session_guard = uuid::Uuid::new_v4().to_string();
                }

                // Perform scan with error handling and recovery
                let scan_start = Instant::now();
                match Self::run_enhanced_scan_internal(
                    &scanner,
                    &scan_paths,
                    &error_handler,
                    &stats,
                    &session_id,
                    &performance_monitor,
                ).await {
                    Ok(results) => {
                        retry_count = 0; // Reset retry count on success
                        
                        if !results.is_empty() {
                            info!(
                                "YARA scan completed with {} detections in {:?}",
                                results.len(),
                                scan_start.elapsed()
                            );
                            
                            // Process high-severity detections
                            for result in &results {
                                if matches!(result.result.threat_level, ThreatLevel::High | ThreatLevel::Critical) {
                                    warn!(
                                        "High-severity threat detected: {} in {}",
                                        result.result.rule_name,
                                        result.result.file_path.display()
                                    );
                                }
                            }
                        } else {
                            debug!("YARA scan completed with no detections");
                        }
                    }
                    Err(e) => {
                        retry_count += 1;
                        error!(
                            "YARA scan failed (attempt {}/{}): {}",
                            retry_count, MAX_RETRIES, e
                        );
                        
                        if retry_count >= MAX_RETRIES {
                            error!("Maximum retry attempts reached, stopping periodic scanning");
                            let mut running = is_running.write().await;
                            *running = false;
                            break;
                        }
                        
                        // Exponential backoff for retries
                        let backoff_duration = Duration::from_secs(2_u64.pow(retry_count));
                        tokio::time::sleep(backoff_duration).await;
                        continue;
                    }
                }

                // Wait for next scan interval
                tokio::time::sleep(Duration::from_secs(interval_seconds as u64)).await;
            }

            info!("YARA periodic scanning stopped");
        });

        info!("YARA periodic scanning started");
        Ok(())
    }

    /// Run enhanced scan with comprehensive error handling
    #[instrument(skip_all)]
    async fn run_enhanced_scan_internal(
        scanner: &Arc<Mutex<Option<ProductionYaraScanner>>>,
        scan_paths: &[String],
        error_handler: &Arc<YaraErrorHandler>,
        stats: &Arc<RwLock<EnhancedYaraScanStats>>,
        session_id: &Arc<RwLock<String>>,
        performance_monitor: &Arc<Mutex<PerformanceMonitor>>,
    ) -> Result<Vec<EnhancedYaraScanResult>, YaraError> {
        let scan_start = Instant::now();
        let mut all_results = Vec::new();
        let mut total_errors = 0u64;
        let mut total_files = 0u64;
        
        let current_session_id = session_id.read().await.clone();
        
        // Get scanner instance
        let scanner_guard = scanner.lock().await;
        let scanner_ref = match scanner_guard.as_ref() {
            Some(s) => s,
            None => {
                let error = YaraError::InitializationError {
                    message: "Scanner not initialized".to_string(),
                    source: None,
                };
                let context = create_error_context("scan_execution");
                error_handler.handle_error(&error, context).await?;
                return Err(error);
            }
        };

        // Scan each path with individual error handling
        for path_str in scan_paths {
            let path = PathBuf::from(path_str);
            
            if !path.exists() {
                let error = YaraError::FileSystemError {
                    path: path.clone(),
                    kind: FileSystemErrorKind::NotFound,
                    source: None,
                };
                
                let mut context = create_error_context("path_validation");
                context.metadata.insert("scan_session".to_string(), current_session_id.clone());
                
                match error_handler.handle_error(&error, context).await? {
                    RecoveryStrategy::Skip => {
                        warn!("Skipping non-existent path: {}", path_str);
                        continue;
                    }
                    _ => continue,
                }
            }

            debug!("Scanning path: {}", path_str);
            
            match scanner_ref.scan_directory(&path).await {
                Ok(results) => {
                    total_files += results.len() as u64;
                    
                    // Convert to enhanced results
                    for result in results {
                        let enhanced_result = EnhancedYaraScanResult {
                            result,
                            timestamp: chrono::Utc::now(),
                            context: ScanContext {
                                session_id: current_session_id.clone(),
                                config_hash: "config_hash_placeholder".to_string(),
                                resource_usage: Self::get_current_resource_usage(),
                                performance: PerformanceMetrics {
                                    total_duration: scan_start.elapsed(),
                                    io_duration: Duration::from_millis(0), // Would be measured
                                    scan_duration: Duration::from_millis(0), // Would be measured
                                    throughput: 0.0, // Would be calculated
                                    avg_file_time: Duration::from_millis(0), // Would be calculated
                                },
                            },
                            error: None,
                        };
                        all_results.push(enhanced_result);
                    }
                }
                Err(e) => {
                    total_errors += 1;
                    
                    let yara_error = YaraError::ScanError {
                        target: path.clone(),
                        kind: ScanErrorKind::EngineError(e.to_string()),
                        duration: Some(scan_start.elapsed()),
                    };
                    
                    let mut context = create_error_context("directory_scan");
                    context.metadata.insert("scan_session".to_string(), current_session_id.clone());
                    context.metadata.insert("path".to_string(), path_str.clone());
                    
                    match error_handler.handle_error(&yara_error, context).await? {
                        RecoveryStrategy::Skip => {
                            warn!("Skipping failed path after error: {}", path_str);
                            continue;
                        }
                        RecoveryStrategy::Retry { max_attempts, delay, .. } => {
                            // Implement retry logic here if needed
                            warn!("Retry not implemented for path: {}", path_str);
                            continue;
                        }
                        _ => continue,
                    }
                }
            }
        }

        let total_duration = scan_start.elapsed();
        let throughput = if total_duration.as_secs_f32() > 0.0 {
            total_files as f32 / total_duration.as_secs_f32()
        } else {
            0.0
        };
        
        let error_rate = if total_files > 0 {
            total_errors as f32 / total_files as f32
        } else {
            0.0
        };

        // Update statistics
        {
            let mut stats_guard = stats.write().await;
            stats_guard.basic_stats.files_scanned += total_files;
            stats_guard.basic_stats.threats_detected += all_results.len() as u64;
            stats_guard.error_count += total_errors;
            
            // Update performance trend
            let data_point = PerformanceDataPoint {
                timestamp: chrono::Utc::now(),
                throughput,
                error_rate,
                avg_response_time: if total_files > 0 {
                    total_duration / total_files as u32
                } else {
                    Duration::from_millis(0)
                },
            };
            
            stats_guard.performance_trend.push(data_point.clone());
            
            // Keep only recent data points
            if stats_guard.performance_trend.len() > 1000 {
                stats_guard.performance_trend.drain(0..stats_guard.performance_trend.len() - 1000);
            }
            
            // Update resource history
            stats_guard.resource_history.push(Self::get_current_resource_usage());
            if stats_guard.resource_history.len() > 100 {
                stats_guard.resource_history.drain(0..stats_guard.resource_history.len() - 100);
            }
        }

        // Update performance monitor
        {
            let mut monitor = performance_monitor.lock().await;
            let data_point = PerformanceDataPoint {
                timestamp: chrono::Utc::now(),
                throughput,
                error_rate,
                avg_response_time: if total_files > 0 {
                    total_duration / total_files as u32
                } else {
                    Duration::from_millis(0)
                },
            };
            
            monitor.recent_data.push_back(data_point);
            if monitor.recent_data.len() > monitor.max_data_points {
                monitor.recent_data.pop_front();
            }
            
            // Check performance thresholds
            if throughput < monitor.thresholds.min_throughput {
                warn!("Performance alert: Throughput below threshold ({} < {})", 
                      throughput, monitor.thresholds.min_throughput);
            }
            
            if error_rate > monitor.thresholds.max_error_rate {
                warn!("Performance alert: Error rate above threshold ({} > {})", 
                      error_rate, monitor.thresholds.max_error_rate);
            }
        }

        info!(
            "Enhanced YARA scan completed: {} files, {} detections, {} errors, {:.2} files/sec",
            total_files, all_results.len(), total_errors, throughput
        );

        Ok(all_results)
    }

    /// Get current system resource usage
    fn get_current_resource_usage() -> ResourceUsage {
        // This would integrate with system monitoring APIs
        // For now, return placeholder values
        ResourceUsage {
            memory_usage: 256 * 1024 * 1024, // 256MB placeholder
            cpu_usage: 25.0, // 25% placeholder
            disk_iops: 100,   // 100 IOPS placeholder
            network_usage: 1024, // 1KB/s placeholder
        }
    }

    /// Stop periodic scanning
    #[instrument(skip(self))]
    pub async fn stop_periodic_scanning(&self) -> Result<(), YaraError> {
        let mut is_running = self.is_running.write().await;
        *is_running = false;
        info!("YARA periodic scanning stop requested");
        Ok(())
    }

    /// Run a single enhanced scan
    #[instrument(skip(self))]
    pub async fn run_enhanced_scan(&self) -> Result<Vec<EnhancedYaraScanResult>, YaraError> {
        let config_guard = self.config.read().await;
        // Use default scan paths since scan_paths field was removed
        let scan_paths = vec!["/".to_string()]; // Default scan path
        drop(config_guard);

        // Generate session ID for this scan
        {
            let mut session_guard = self.session_id.write().await;
            *session_guard = uuid::Uuid::new_v4().to_string();
        }

        Self::run_enhanced_scan_internal(
            &self.scanner,
            &scan_paths,
            &self.error_handler,
            &self.stats,
            &self.session_id,
            &self.performance_monitor,
        ).await
    }

    /// Get enhanced statistics
    pub async fn get_enhanced_stats(&self) -> EnhancedYaraScanStats {
        self.stats.read().await.clone()
    }

    /// Get error statistics
    pub async fn get_error_stats(&self) -> crate::error::ErrorStatistics {
        self.error_handler.get_statistics().await
    }

    /// Check if scanning is currently running
    pub async fn is_running(&self) -> bool {
        *self.is_running.read().await
    }

    /// Get current session ID
    pub async fn get_session_id(&self) -> String {
        self.session_id.read().await.clone()
    }

    /// Reset all statistics
    pub async fn reset_statistics(&self) {
        let mut stats_guard = self.stats.write().await;
        *stats_guard = EnhancedYaraScanStats {
            basic_stats: ScanStatistics::default(),
            error_count: 0,
            recovery_success_rate: 1.0,
            performance_trend: Vec::new(),
            resource_history: Vec::new(),
        };
        
        self.error_handler.reset_statistics().await;
        
        let mut monitor = self.performance_monitor.lock().await;
        monitor.recent_data.clear();
    }
}

impl Drop for EnhancedYaraIntegration {
    fn drop(&mut self) {
        // Stop the background scanning task
        let is_running = self.is_running.clone();
        tokio::spawn(async move {
            let mut running = is_running.write().await;
            *running = false;
            info!("EnhancedYaraIntegration background scanning stopped during drop");
        });
    }
}

#[cfg(all(test, feature = "yara"))]
mod tests {
    use super::*;
    use crate::config::YaraConfig;
    use crate::yara_updater::YaraUpdaterConfig;

    fn create_test_config() -> Arc<RwLock<AgentConfig>> {
        let config = AgentConfig {
            yara: YaraConfig {
                enabled: true,
                rules_path: "./rules/ransomware".to_string(),
                process_scan_interval_secs: 300,
                directory_scan_interval_secs: 60,
                target_processes: vec!["explorer.exe".to_string(), "svchost.exe".to_string()],
                memory_chunk_size: 4096,
            },
            yara_updater: YaraUpdaterConfig::default(),
            ..Default::default()
        };
        Arc::new(RwLock::new(config))
    }

    #[tokio::test]
    async fn test_enhanced_integration_creation() {
        let config = create_test_config();
        let integration = EnhancedYaraIntegration::new(config);
        assert!(!integration.is_running().await);
    }

    #[tokio::test]
    async fn test_session_id_generation() {
        let config = create_test_config();
        let integration = EnhancedYaraIntegration::new(config);
        
        let session1 = integration.get_session_id().await;
        let session2 = integration.get_session_id().await;
        
        assert_eq!(session1, session2); // Same until regenerated
    }

    #[tokio::test]
    async fn test_statistics_reset() {
        let config = create_test_config();
        let integration = EnhancedYaraIntegration::new(config);
        
        integration.reset_statistics().await;
        let stats = integration.get_enhanced_stats().await;
        
        assert_eq!(stats.error_count, 0);
        assert_eq!(stats.basic_stats.files_scanned, 0);
    }
}
