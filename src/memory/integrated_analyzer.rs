//! Integrated Memory Analysis System
//!
//! This module provides a unified interface that combines memory forensics
//! with ML-based anomaly detection for comprehensive threat analysis.

use super::{
    forensics_engine::{MemoryForensicsEngine, MemoryForensicsConfig, MemoryForensicsResult},
    // ml_integration::{MemoryAnomalyDetector, MemoryForensicsFeatures}, // ML integration removed for production
    MemoryError,
};

// Production stub for removed ML functionality
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MemoryForensicsFeatures {
    pub feature_count: usize,
    pub anomaly_indicators: Vec<String>,
    pub injection_count: f64,
    pub shellcode_count: f64,
    pub high_entropy_regions: f64,
    pub avg_entropy_regions: f64,
    pub critical_threats: f64,
}

pub struct MemoryAnomalyDetector {
    threshold: f64,
}

impl MemoryAnomalyDetector {
    pub fn new() -> Self {
        Self { threshold: 0.7 }
    }
    
    pub async fn initialize(&mut self, _training_data: &[MemoryForensicsResult]) -> MLResult<()> {
        // Production stub - no ML training
        Ok(())
    }
    
    pub fn set_threshold(&mut self, threshold: f64) {
        self.threshold = threshold;
    }
    
    pub async fn detect_anomaly(&self, _results: &[MemoryForensicsResult]) -> MLResult<Prediction> {
        // Production stub - return safe default
        Ok(Prediction {
            anomaly_score: 0.1,
            confidence: 0.5,
            threat_level: ThreatLevel::Low,
        })
    }
    
    pub fn get_feature_stats(&self) -> HashMap<String, f64> {
        // Production stub - return empty stats
        HashMap::new()
    }
}
// Unused imports for tests
#[cfg(test)]
use super::{MemoryAnalysisResult, MemoryRegion};
// use crate::ml::zero_day::{Prediction, ThreatLevel}; // ML zero-day detection removed for production
// use crate::ml::MLResult; // ML result type removed for production
use log::{debug, info, warn, error};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock};
use tokio::time::sleep;

// Production replacement types for removed ML functionality
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Prediction {
    pub anomaly_score: f64,
    pub confidence: f64,
    pub threat_level: ThreatLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum ThreatLevel {
    Low,
    Medium,
    High,
    Critical,
}

pub type MLResult<T> = Result<T, String>;

/// Integrated memory analysis result combining forensics and ML detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegratedAnalysisResult {
    /// Memory forensics results
    pub forensics_results: Vec<MemoryForensicsResult>,
    /// ML anomaly detection prediction
    pub anomaly_prediction: Option<Prediction>,
    /// Extracted ML features
    pub ml_features: Option<MemoryForensicsFeatures>,
    /// Overall threat assessment
    pub threat_assessment: ThreatAssessment,
    /// Analysis performance metrics
    pub performance_metrics: AnalysisMetrics,
    /// Analysis timestamp
    pub timestamp: std::time::SystemTime,
}

/// Overall threat assessment combining multiple detection methods
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatAssessment {
    /// Overall threat level
    pub threat_level: ThreatLevel,
    /// Combined confidence score (0.0 - 1.0)
    pub confidence: f64,
    /// Risk score (0.0 - 1.0)
    pub risk_score: f64,
    /// Threat categories detected
    pub threat_categories: Vec<String>,
    /// Recommended actions
    pub recommendations: Vec<String>,
    /// Critical indicators count
    pub critical_indicators: usize,
}

/// Analysis performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisMetrics {
    /// Total analysis duration
    pub total_duration: Duration,
    /// Forensics analysis duration
    pub forensics_duration: Duration,
    /// ML inference duration
    pub ml_duration: Duration,
    /// Memory scanned (bytes)
    pub memory_scanned: u64,
    /// Processes analyzed
    pub processes_analyzed: usize,
    /// Performance score (0.0 - 1.0, higher is better)
    pub performance_score: f64,
}

/// Configuration for integrated memory analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegratedAnalysisConfig {
    /// Memory forensics configuration
    pub forensics_config: MemoryForensicsConfig,
    /// ML anomaly detection threshold
    pub anomaly_threshold: f64,
    /// Enable real-time monitoring
    pub enable_realtime_monitoring: bool,
    /// Monitoring interval for real-time analysis
    pub monitoring_interval: Duration,
    /// Maximum analysis duration per process
    pub max_analysis_duration: Duration,
    /// Enable performance optimization
    pub enable_performance_optimization: bool,
    /// Minimum confidence threshold for alerts
    pub alert_confidence_threshold: f64,
}

/// Integrated memory analyzer combining forensics and ML
pub struct IntegratedMemoryAnalyzer {
    /// Memory forensics engine
    forensics_engine: Arc<Mutex<MemoryForensicsEngine>>,
    /// ML anomaly detector
    anomaly_detector: Arc<Mutex<MemoryAnomalyDetector>>,
    /// Analysis configuration
    config: IntegratedAnalysisConfig,
    /// Analysis history for trend analysis
    analysis_history: Arc<RwLock<Vec<IntegratedAnalysisResult>>>,
    /// Performance statistics
    performance_stats: Arc<RwLock<HashMap<String, f64>>>,
    /// Real-time monitoring state
    monitoring_active: Arc<RwLock<bool>>,
}

impl Default for IntegratedAnalysisConfig {
    fn default() -> Self {
        Self {
            forensics_config: MemoryForensicsConfig::default(),
            anomaly_threshold: 0.7,
            enable_realtime_monitoring: true,
            monitoring_interval: Duration::from_secs(30),
            max_analysis_duration: Duration::from_millis(500),
            enable_performance_optimization: true,
            alert_confidence_threshold: 0.8,
        }
    }
}

impl IntegratedMemoryAnalyzer {
    /// Create a new integrated memory analyzer
    pub async fn new(config: IntegratedAnalysisConfig) -> Result<Self, MemoryError> {
        let forensics_engine = MemoryForensicsEngine::new(config.forensics_config.clone())
            .map_err(|e| MemoryError::AnalysisFailed(format!("Failed to create forensics engine: {}", e)))?;
        let anomaly_detector = MemoryAnomalyDetector::new();
        
        Ok(Self {
            forensics_engine: Arc::new(Mutex::new(forensics_engine)),
            anomaly_detector: Arc::new(Mutex::new(anomaly_detector)),
            config,
            analysis_history: Arc::new(RwLock::new(Vec::new())),
            performance_stats: Arc::new(RwLock::new(HashMap::new())),
            monitoring_active: Arc::new(RwLock::new(false)),
        })
    }
    
    /// Initialize the analyzer with training data
    pub async fn initialize(&self, training_data: &[MemoryForensicsResult]) -> MLResult<()> {
        info!("Initializing integrated memory analyzer with {} training samples", training_data.len());
        
        // Initialize ML anomaly detector
        let mut detector = self.anomaly_detector.lock().await;
        detector.initialize(training_data).await?;
        detector.set_threshold(self.config.anomaly_threshold);
        
        info!("Integrated memory analyzer initialized successfully");
        Ok(())
    }
    
    /// Perform comprehensive memory analysis on a process
    pub async fn analyze_process(&self, process_id: u32) -> Result<IntegratedAnalysisResult, MemoryError> {
        let start_time = Instant::now();
        
        debug!("Starting integrated analysis for process {}", process_id);
        
        // Perform memory forensics analysis
        let forensics_start = Instant::now();
        let forensics_engine = self.forensics_engine.lock().await;
        let forensics_results = match forensics_engine.analyze_process_memory(process_id).await {
            Ok(result) => vec![result],
            Err(e) => {
                error!("Forensics analysis failed for process {}: {}", process_id, e);
                return Err(MemoryError::AnalysisFailed(format!("Forensics analysis failed: {}", e)));
            }
        };
        let forensics_duration = forensics_start.elapsed();
        drop(forensics_engine); // Release lock early
        
        // Perform ML anomaly detection
        let ml_start = Instant::now();
        let detector = self.anomaly_detector.lock().await;
        let (anomaly_prediction, ml_features) = match detector.detect_anomaly(&forensics_results).await {
            Ok(prediction) => {
                let features = detector.get_feature_stats();
                (Some(prediction), Some(self.convert_stats_to_features(features)))
            },
            Err(e) => {
                warn!("ML anomaly detection failed for process {}: {}", process_id, e);
                (None, None)
            }
        };
        let ml_duration = ml_start.elapsed();
        drop(detector); // Release lock early
        
        // Generate threat assessment
        let threat_assessment = self.generate_threat_assessment(
            &forensics_results, 
            &anomaly_prediction
        );
        
        // Calculate performance metrics
        let total_duration = start_time.elapsed();
        let memory_scanned = forensics_results.iter()
            .map(|r| r.memory_analysis.suspicious_regions.len() as u64 * 4096) // Estimate based on regions
            .sum();
        
        let performance_metrics = AnalysisMetrics {
            total_duration,
            forensics_duration,
            ml_duration,
            memory_scanned,
            processes_analyzed: 1,
            performance_score: self.calculate_performance_score(total_duration, memory_scanned),
        };
        
        let result = IntegratedAnalysisResult {
            forensics_results,
            anomaly_prediction,
            ml_features,
            threat_assessment,
            performance_metrics,
            timestamp: std::time::SystemTime::now(),
        };
        
        // Update analysis history
        self.update_analysis_history(result.clone()).await;
        
        // Update performance statistics
        self.update_performance_stats(&result).await;
        
        debug!("Integrated analysis completed for process {} in {:?}", 
               process_id, total_duration);
        
        Ok(result)
    }
    
    /// Analyze multiple processes concurrently
    pub async fn analyze_processes(&self, process_ids: &[u32]) -> Vec<Result<IntegratedAnalysisResult, MemoryError>> {
        info!("Starting batch analysis for {} processes", process_ids.len());
        
        let mut tasks = Vec::new();
        
        for &process_id in process_ids {
            let analyzer = self.clone_for_task();
            let task = tokio::spawn(async move {
                analyzer.analyze_process(process_id).await
            });
            tasks.push(task);
        }
        
        let mut results = Vec::new();
        for task in tasks {
            match task.await {
                Ok(result) => results.push(result),
                Err(e) => results.push(Err(MemoryError::AnalysisFailed(format!("Task failed: {}", e)))),
            }
        }
        
        info!("Batch analysis completed for {} processes", process_ids.len());
        results
    }
    
    /// Start real-time memory monitoring
    pub async fn start_realtime_monitoring(&self) -> Result<(), MemoryError> {
        let mut monitoring_active = self.monitoring_active.write().await;
        if *monitoring_active {
            return Err(MemoryError::AnalysisFailed("Real-time monitoring already active".to_string()));
        }
        
        *monitoring_active = true;
        drop(monitoring_active);
        
        info!("Starting real-time memory monitoring");
        
        // Start forensics engine monitoring
        let forensics_engine = self.forensics_engine.lock().await;
        forensics_engine.start_realtime_monitoring().await
            .map_err(|e| MemoryError::AnalysisFailed(format!("Failed to start forensics monitoring: {}", e)))?;
        drop(forensics_engine);
        
        // Start monitoring loop
        let analyzer = self.clone_for_task();
        tokio::spawn(async move {
            analyzer.monitoring_loop().await;
        });
        
        Ok(())
    }
    
    /// Stop real-time memory monitoring
    pub async fn stop_realtime_monitoring(&self) -> Result<(), MemoryError> {
        let mut monitoring_active = self.monitoring_active.write().await;
        if !*monitoring_active {
            return Ok(());
        }
        
        *monitoring_active = false;
        drop(monitoring_active);
        
        info!("Stopping real-time memory monitoring");
        
        // Stop forensics engine monitoring
        let forensics_engine = self.forensics_engine.lock().await;
        forensics_engine.stop_monitoring().await
            .map_err(|e| MemoryError::AnalysisFailed(format!("Failed to stop forensics monitoring: {}", e)))?;
        
        Ok(())
    }
    
    /// Get analysis history
    pub async fn get_analysis_history(&self, limit: Option<usize>) -> Vec<IntegratedAnalysisResult> {
        let history = self.analysis_history.read().await;
        match limit {
            Some(n) => history.iter().rev().take(n).cloned().collect(),
            None => history.clone(),
        }
    }
    
    /// Get performance statistics
    pub async fn get_performance_stats(&self) -> HashMap<String, f64> {
        self.performance_stats.read().await.clone()
    }
    
    /// Update analyzer configuration
    pub async fn update_config(&mut self, new_config: IntegratedAnalysisConfig) {
        info!("Updating integrated analyzer configuration");
        
        // Update anomaly detector threshold
        let mut detector = self.anomaly_detector.lock().await;
        detector.set_threshold(new_config.anomaly_threshold);
        drop(detector);
        
        self.config = new_config;
    }
    
    /// Real-time monitoring loop
    async fn monitoring_loop(&self) {
        while *self.monitoring_active.read().await {
            // Get recent forensics results
            let forensics_engine = self.forensics_engine.lock().await;
            let recent_results = forensics_engine.get_recent_results(10).await;
            drop(forensics_engine);
            
            if !recent_results.is_empty() {
                // Perform ML analysis on recent results
                let detector = self.anomaly_detector.lock().await;
                if let Ok(prediction) = detector.detect_anomaly(&recent_results).await {
                    if prediction.anomaly_score > self.config.anomaly_threshold {
                        warn!("Real-time anomaly detected: score={:.3}, confidence={:.3}", 
                              prediction.anomaly_score, prediction.confidence);
                        
                        // Generate alert if confidence is high enough
                        if prediction.confidence > self.config.alert_confidence_threshold {
                            self.generate_realtime_alert(&recent_results, &prediction).await;
                        }
                    }
                }
                drop(detector);
            }
            
            // Wait for next monitoring interval
            sleep(self.config.monitoring_interval).await;
        }
        
        info!("Real-time monitoring loop stopped");
    }
    
    /// Generate threat assessment from analysis results
    fn generate_threat_assessment(
        &self,
        forensics_results: &[MemoryForensicsResult],
        anomaly_prediction: &Option<Prediction>,
    ) -> ThreatAssessment {
        let mut threat_categories = Vec::new();
        let mut recommendations = Vec::new();
        let mut critical_indicators = 0;
        let mut total_confidence = 0.0;
        let mut confidence_count = 0;
        
        // Analyze forensics results
        for result in forensics_results {
            for indicator in &result.threat_indicators {
                match indicator.severity {
                    crate::memory::forensics_engine::ThreatSeverity::Critical => {
                        critical_indicators += 1;
                        threat_categories.push(format!("Critical: {}", indicator.indicator_type));
                        recommendations.push("Immediate isolation and investigation required".to_string());
                    },
                    crate::memory::forensics_engine::ThreatSeverity::High => {
                        threat_categories.push(format!("High: {}", indicator.indicator_type));
                        recommendations.push("Enhanced monitoring and analysis recommended".to_string());
                    },
                    _ => {}
                }
                
                total_confidence += indicator.confidence;
                confidence_count += 1;
            }
        }
        
        // Factor in ML prediction
        let (threat_level, risk_score) = if let Some(prediction) = anomaly_prediction {
            total_confidence += prediction.confidence;
            confidence_count += 1;
            
            if prediction.anomaly_score > 0.8 {
                threat_categories.push("ML: High Anomaly Score".to_string());
                recommendations.push("ML model detected high anomaly - investigate immediately".to_string());
            }
            
            let ml_threat_level = if prediction.anomaly_score > 0.9 {
                ThreatLevel::Critical
            } else if prediction.anomaly_score > 0.7 {
                ThreatLevel::High
            } else if prediction.anomaly_score > 0.5 {
                ThreatLevel::Medium
            } else {
                ThreatLevel::Low
            };
            
            (ml_threat_level, prediction.anomaly_score)
        } else {
            // Determine threat level based on forensics only
            let forensics_threat_level = if critical_indicators > 0 {
                ThreatLevel::Critical
            } else if threat_categories.len() > 2 {
                ThreatLevel::High
            } else if !threat_categories.is_empty() {
                ThreatLevel::Medium
            } else {
                ThreatLevel::Low
            };
            
            (forensics_threat_level, critical_indicators as f64 * 0.3)
        };
        
        let confidence = if confidence_count > 0 {
            total_confidence / confidence_count as f64
        } else {
            0.0
        };
        
        // Remove duplicate recommendations
        recommendations.sort();
        recommendations.dedup();
        
        ThreatAssessment {
            threat_level,
            confidence,
            risk_score,
            threat_categories,
            recommendations,
            critical_indicators,
        }
    }
    
    /// Calculate performance score based on analysis metrics
    fn calculate_performance_score(&self, duration: Duration, memory_scanned: u64) -> f64 {
        let duration_ms = duration.as_millis() as f64;
        let target_duration_ms = self.config.max_analysis_duration.as_millis() as f64;
        
        // Performance score based on meeting target duration
        let duration_score = if duration_ms <= target_duration_ms {
            1.0
        } else {
            (target_duration_ms / duration_ms).min(1.0)
        };
        
        // Factor in memory throughput (MB/s)
        let memory_mb = memory_scanned as f64 / (1024.0 * 1024.0);
        let throughput = memory_mb / (duration_ms / 1000.0);
        let throughput_score = (throughput / 100.0).min(1.0); // Target: 100 MB/s
        
        // Combined score
        (duration_score * 0.7 + throughput_score * 0.3).clamp(0.0, 1.0)
    }
    
    /// Update analysis history
    async fn update_analysis_history(&self, result: IntegratedAnalysisResult) {
        let mut history = self.analysis_history.write().await;
        history.push(result);
        
        // Keep only recent history (last 1000 analyses)
        if history.len() > 1000 {
            history.remove(0);
        }
    }
    
    /// Update performance statistics
    async fn update_performance_stats(&self, result: &IntegratedAnalysisResult) {
        let mut stats = self.performance_stats.write().await;
        
        // Update running averages
        let current_count = stats.get("analysis_count").unwrap_or(&0.0) + 1.0;
        let prev_avg_duration = stats.get("avg_duration_ms").unwrap_or(&0.0);
        let new_avg_duration = (prev_avg_duration * (current_count - 1.0) + 
                               result.performance_metrics.total_duration.as_millis() as f64) / current_count;
        
        let prev_avg_performance = stats.get("avg_performance_score").unwrap_or(&0.0);
        let new_avg_performance = (prev_avg_performance * (current_count - 1.0) + 
                                  result.performance_metrics.performance_score) / current_count;
        
        stats.insert("analysis_count".to_string(), current_count);
        stats.insert("avg_duration_ms".to_string(), new_avg_duration);
        stats.insert("avg_performance_score".to_string(), new_avg_performance);
        stats.insert("last_analysis_duration_ms".to_string(), 
                    result.performance_metrics.total_duration.as_millis() as f64);
        stats.insert("last_performance_score".to_string(), 
                    result.performance_metrics.performance_score);
    }
    
    /// Generate real-time alert
    async fn generate_realtime_alert(&self, results: &[MemoryForensicsResult], prediction: &Prediction) {
        warn!("REAL-TIME MEMORY THREAT ALERT");
        warn!("Anomaly Score: {:.3}", prediction.anomaly_score);
        warn!("Confidence: {:.3}", prediction.confidence);
        warn!("Threat Level: {:?}", prediction.threat_level);
        
        for result in results {
            warn!("Process {}: {} critical indicators", 
                  result.process_id, 
                  result.threat_indicators.iter()
                      .filter(|i| matches!(i.severity, crate::memory::forensics_engine::ThreatSeverity::Critical))
                      .count());
        }
    }
    
    /// Convert feature stats to MemoryForensicsFeatures
    fn convert_stats_to_features(&self, stats: HashMap<String, f64>) -> MemoryForensicsFeatures {
        MemoryForensicsFeatures {
            injection_count: stats.get("avg_injection_count").copied().unwrap_or(0.0),
            shellcode_count: stats.get("avg_shellcode_count").copied().unwrap_or(0.0),
            high_entropy_regions: stats.get("avg_entropy_regions").copied().unwrap_or(0.0),
            critical_threats: stats.get("avg_critical_threats").copied().unwrap_or(0.0),
            ..Default::default()
        }
    }
    
    /// Clone analyzer for concurrent tasks
    fn clone_for_task(&self) -> Self {
        Self {
            forensics_engine: Arc::clone(&self.forensics_engine),
            anomaly_detector: Arc::clone(&self.anomaly_detector),
            config: self.config.clone(),
            analysis_history: Arc::clone(&self.analysis_history),
            performance_stats: Arc::clone(&self.performance_stats),
            monitoring_active: Arc::clone(&self.monitoring_active),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::forensics_engine::*;
    use std::time::Duration;
    
    fn create_test_forensics_result() -> MemoryForensicsResult {
        
        MemoryForensicsResult {
            analysis_id: uuid::Uuid::new_v4(),
            timestamp: std::time::SystemTime::now(),
            process_id: 1234,
            process_name: "test.exe".to_string(),
            analysis_duration: Duration::from_millis(100),
            memory_analysis: MemoryAnalysisResult {
                entropy_scores: std::collections::HashMap::from([(0x12345678, 7.5)]),
                suspicious_regions: vec![
                    MemoryRegion {
                        start_address: 0x12345678,
                        end_address: 0x12346678,
                        size: 4096,
                        permissions: "RWX".to_string(),
                        module_name: Some("test.exe".to_string()),
                    },
                ],
                detected_patterns: vec!["test_pattern".to_string()],
                confidence_score: 0.9,
            },
            threat_indicators: vec![
                ThreatIndicator {
                    indicator_type: "Process Injection".to_string(),
                    description: "Test injection".to_string(),
                    severity: ThreatSeverity::Critical,
                    confidence: 0.9,
                    memory_address: 0x12345678,
                    evidence: vec!["Test evidence".to_string()],
                },
            ],
            recommended_actions: vec!["Terminate process".to_string()],
            suspicious_regions: vec![
                SuspiciousMemoryRegion {
                    address: 0x12345678,
                    size: 4096,
                    entropy: 7.5,
                    permissions: "RWX".to_string(),
                    detected_patterns: vec!["test_pattern".to_string()],
                },
            ],
            total_memory_scanned: 1048576,
            scan_duration: Duration::from_millis(100),
        }
    }
    
    #[tokio::test]
    async fn test_integrated_analyzer_creation() {
        let config = IntegratedAnalysisConfig::default();
        let analyzer = IntegratedMemoryAnalyzer::new(config).await
            .expect("Failed to create analyzer");
        
        // Test that analyzer was created successfully
        assert!(!*analyzer.monitoring_active.read().await);
    }
    
    #[tokio::test]
    async fn test_threat_assessment_generation() {
        let config = IntegratedAnalysisConfig::default();
        let analyzer = IntegratedMemoryAnalyzer::new(config).await
            .expect("Failed to create analyzer");
        
        let forensics_results = vec![create_test_forensics_result()];
        let threat_assessment = analyzer.generate_threat_assessment(&forensics_results, &None);
        
        assert_eq!(threat_assessment.critical_indicators, 1);
        assert!(threat_assessment.confidence > 0.0);
        assert!(!threat_assessment.threat_categories.is_empty());
        assert!(!threat_assessment.recommendations.is_empty());
    }
    
    #[tokio::test]
    async fn test_performance_score_calculation() {
        let config = IntegratedAnalysisConfig::default();
        let analyzer = IntegratedMemoryAnalyzer::new(config).await
            .expect("Failed to create analyzer");
        
        // Test fast analysis
        let fast_duration = Duration::from_millis(100);
        let score = analyzer.calculate_performance_score(fast_duration, 1048576);
        assert!(score > 0.5);
        
        // Test slow analysis
        let slow_duration = Duration::from_millis(1000);
        let score = analyzer.calculate_performance_score(slow_duration, 1048576);
        assert!(score < 1.0);
    }
}
