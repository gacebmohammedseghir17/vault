//! Detection Engine Integration Module
//!
//! This module provides integration between all Phase 2 detection engines
//! and the existing entropy analysis system for comprehensive threat detection.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::{mpsc, RwLock};
use uuid::Uuid;

// Import Phase 2 detection engines
#[cfg(feature = "behavioral-analysis")]
use crate::detection::behavioral::BehavioralAnalysisEngine;
// use crate::core::config::BehavioralAnalysisConfig;  // Currently unused

#[cfg(feature = "memory-forensics")]
use crate::memory::forensics_engine::{MemoryForensicsConfig, MemoryForensicsEngine};

#[cfg(feature = "network-monitoring")]
use crate::network::traffic_analyzer::{NetworkTrafficAnalyzer, NetworkTrafficConfig};

#[cfg(feature = "api-hooking")]
use crate::api::hooking_engine::{ApiHookingConfig, ApiHookingEngine};

// #[cfg(feature = "ml-engine")]
// use crate::ml::anomaly_detector::{AnomalyDetectorConfig, MLAnomalyDetector}; // ML engine removed for production

#[cfg(feature = "behavioral-analysis")]
use crate::core::agent::BehavioralEngine;
use crate::core::types::{ThreatSeverity, ThreatType};
use crate::detection::pattern_matcher::{AdvancedPatternMatcher, PatternMatcherConfig};
#[cfg(feature = "behavioral-analysis")]
use crate::entropy_analyzer::{EntropyAnalyzer, EntropyResult};

/// Configuration for the integrated detection system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegratedDetectionConfig {
    /// Enable behavioral analysis engine
    pub enable_behavioral_analysis: bool,
    /// Enable memory forensics engine
    pub enable_memory_forensics: bool,
    /// Enable network traffic analysis
    pub enable_network_analysis: bool,
    /// Enable API hooking monitoring
    pub enable_api_hooking: bool,
    /// Enable ML anomaly detection
    pub enable_ml_detection: bool,
    /// Enable pattern matching
    pub enable_pattern_matching: bool,
    /// Correlation window for threat events
    pub correlation_window: Duration,
    /// Minimum confidence threshold for alerts
    pub min_confidence_threshold: f32,
    /// Maximum events to buffer per engine
    pub max_events_per_engine: usize,
    /// Enable cross-engine correlation
    pub enable_correlation: bool,
    /// Threat escalation threshold
    pub escalation_threshold: f32,
}

impl Default for IntegratedDetectionConfig {
    fn default() -> Self {
        Self {
            enable_behavioral_analysis: true,
            enable_memory_forensics: true,
            enable_network_analysis: true,
            enable_api_hooking: true,
            enable_ml_detection: true,
            enable_pattern_matching: true,
            correlation_window: Duration::from_secs(300), // 5 minutes
            min_confidence_threshold: 0.7,
            max_events_per_engine: 1000,
            enable_correlation: true,
            escalation_threshold: 0.9,
        }
    }
}

/// Unified threat event from any detection engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedThreatEvent {
    /// Event identifier
    pub event_id: Uuid,
    /// Source detection engine
    pub source_engine: DetectionEngineType,
    /// Threat type detected
    pub threat_type: ThreatType,
    /// Threat severity
    pub severity: ThreatSeverity,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f32,
    /// Event timestamp
    pub timestamp: SystemTime,
    /// Process ID associated with the threat
    pub process_id: Option<u32>,
    /// File path associated with the threat
    pub file_path: Option<String>,
    /// Network endpoint associated with the threat
    pub network_endpoint: Option<String>,
    /// Detailed event data
    pub event_data: serde_json::Value,
    /// Entropy analysis result (if available)
    #[cfg(feature = "behavioral-analysis")]
    pub entropy_result: Option<EntropyResult>,
    /// Correlation score with other events
    pub correlation_score: f32,
    /// Recommended actions
    pub recommended_actions: Vec<String>,
}

/// Types of detection engines
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DetectionEngineType {
    BehavioralAnalysis,
    MemoryForensics,
    NetworkTraffic,
    ApiHooking,
    MachineLearning,
    PatternMatching,
    EntropyAnalysis,
}

/// Correlated threat detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelatedThreatResult {
    /// Correlation identifier
    pub correlation_id: Uuid,
    /// Primary threat event
    pub primary_event: UnifiedThreatEvent,
    /// Related threat events
    pub related_events: Vec<UnifiedThreatEvent>,
    /// Overall confidence score
    pub overall_confidence: f32,
    /// Threat campaign identifier (if part of larger attack)
    pub campaign_id: Option<String>,
    /// Attack timeline
    pub timeline: Vec<(SystemTime, String)>,
    /// Risk assessment
    pub risk_level: RiskLevel,
    /// Mitigation recommendations
    pub mitigation_steps: Vec<String>,
}

/// Risk assessment levels
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
    Emergency,
}

/// Statistics for the integrated detection system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationStats {
    /// Events processed by engine type
    pub events_by_engine: HashMap<DetectionEngineType, u64>,
    /// Total correlations found
    pub total_correlations: u64,
    /// High-confidence detections
    pub high_confidence_detections: u64,
    /// False positive rate estimate
    pub estimated_false_positive_rate: f32,
    /// Average processing time per event
    pub avg_processing_time: Duration,
    /// System start time
    pub start_time: SystemTime,
    /// Last update time
    pub last_update: SystemTime,
}

/// Main integrated detection system
pub struct IntegratedDetectionSystem {
    config: IntegratedDetectionConfig,

    // Detection engines
    #[cfg(feature = "behavioral-analysis")]
    behavioral_engine: Option<Arc<RwLock<BehavioralAnalysisEngine>>>,

    #[cfg(feature = "memory-forensics")]
    memory_engine: Option<Arc<RwLock<MemoryForensicsEngine>>>,

    #[cfg(feature = "network-monitoring")]
    network_engine: Option<Arc<RwLock<NetworkTrafficAnalyzer>>>,

    #[cfg(feature = "api-hooking")]
    api_engine: Option<Arc<RwLock<ApiHookingEngine>>>,

    // #[cfg(feature = "ml-engine")]
    // ml_engine: Option<Arc<RwLock<MLAnomalyDetector>>>, // ML engine removed for production

    pattern_matcher: Arc<RwLock<AdvancedPatternMatcher>>,
    #[cfg(feature = "behavioral-analysis")]
    entropy_analyzer: Arc<RwLock<EntropyAnalyzer>>,

    // Event processing
    event_buffer: Arc<RwLock<Vec<UnifiedThreatEvent>>>,
    correlation_results: Arc<RwLock<Vec<CorrelatedThreatResult>>>,
    stats: Arc<RwLock<IntegrationStats>>,

    // Communication channels
    event_sender: Option<mpsc::UnboundedSender<UnifiedThreatEvent>>,
    correlation_sender: Option<mpsc::UnboundedSender<CorrelatedThreatResult>>,

    // Processing control
    is_running: Arc<RwLock<bool>>,
}

impl IntegratedDetectionSystem {
    /// Create a new integrated detection system
    pub async fn new(
        config: IntegratedDetectionConfig,
        #[cfg(feature = "behavioral-analysis")] entropy_analyzer: Arc<RwLock<EntropyAnalyzer>>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let pattern_matcher = Arc::new(RwLock::new(AdvancedPatternMatcher::new(
            PatternMatcherConfig::default(),
        )?));

        let stats = IntegrationStats {
            events_by_engine: HashMap::new(),
            total_correlations: 0,
            high_confidence_detections: 0,
            estimated_false_positive_rate: 0.05, // 5% initial estimate
            avg_processing_time: Duration::from_millis(10),
            start_time: SystemTime::now(),
            last_update: SystemTime::now(),
        };

        Ok(Self {
            config,

            #[cfg(feature = "behavioral-analysis")]
            behavioral_engine: None,

            #[cfg(feature = "memory-forensics")]
            memory_engine: None,

            #[cfg(feature = "network-monitoring")]
            network_engine: None,

            #[cfg(feature = "api-hooking")]
            api_engine: None,

            // ML engine removed for production

            pattern_matcher,
            #[cfg(feature = "behavioral-analysis")]
            entropy_analyzer,

            event_buffer: Arc::new(RwLock::new(Vec::new())),
            correlation_results: Arc::new(RwLock::new(Vec::new())),
            stats: Arc::new(RwLock::new(stats)),

            event_sender: None,
            correlation_sender: None,

            is_running: Arc::new(RwLock::new(false)),
        })
    }

    /// Initialize all detection engines
    pub async fn initialize_engines(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Initialize behavioral analysis engine
        #[cfg(feature = "behavioral-analysis")]
        if self.config.enable_behavioral_analysis {
            let engine = BehavioralAnalysisEngine::new();
            self.behavioral_engine = Some(Arc::new(RwLock::new(engine)));
        }

        // Initialize memory forensics engine
        #[cfg(feature = "memory-forensics")]
        if self.config.enable_memory_forensics {
            let engine = MemoryForensicsEngine::new(MemoryForensicsConfig::default())?;
            self.memory_engine = Some(Arc::new(RwLock::new(engine)));
        }

        // Initialize network traffic analyzer
        #[cfg(feature = "network-monitoring")]
        if self.config.enable_network_analysis {
            let engine = NetworkTrafficAnalyzer::new(NetworkTrafficConfig::default())?;
            self.network_engine = Some(Arc::new(RwLock::new(engine)));
        }

        // Initialize API hooking engine
        #[cfg(feature = "api-hooking")]
        if self.config.enable_api_hooking {
            let engine = ApiHookingEngine::new(ApiHookingConfig::default());
            self.api_engine = Some(Arc::new(RwLock::new(engine)));
        }

        // // Initialize ML anomaly detector - removed for production
        // #[cfg(feature = "ml-engine")]
        // if self.config.enable_ml_detection {
        //     let engine = MLAnomalyDetector::new(AnomalyDetectorConfig::default())?;
        //     self.ml_engine = Some(Arc::new(RwLock::new(engine)));
        // }

        Ok(())
    }

    /// Start the integrated detection system
    pub async fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        *self.is_running.write().await = true;

        let (event_sender, mut event_receiver) = mpsc::unbounded_channel();
        let (correlation_sender, mut correlation_receiver) = mpsc::unbounded_channel();

        self.event_sender = Some(event_sender.clone());
        self.correlation_sender = Some(correlation_sender.clone());

        // Start event processing loop
        let event_buffer = Arc::clone(&self.event_buffer);
        let correlation_results = Arc::clone(&self.correlation_results);
        let stats = Arc::clone(&self.stats);
        let config = self.config.clone();
        let is_running = Arc::clone(&self.is_running);
        let is_running_correlation = Arc::clone(&self.is_running);

        tokio::spawn(async move {
            while let Some(event) = event_receiver.recv().await {
                if !*is_running.read().await {
                    break;
                }

                // Process the event
                Self::process_threat_event(
                    event,
                    &event_buffer,
                    &correlation_results,
                    &stats,
                    &config,
                    &correlation_sender,
                )
                .await;
            }
        });

        // Start correlation processing loop
        tokio::spawn(async move {
            while let Some(correlation) = correlation_receiver.recv().await {
                if !*is_running_correlation.read().await {
                    break;
                }

                // Handle correlated threat result
                println!(
                    "Correlated threat detected: {:?}",
                    correlation.correlation_id
                );
                // Here you would typically send alerts, trigger responses, etc.
            }
        });

        // Start individual detection engines
        self.start_detection_engines().await?;

        Ok(())
    }

    /// Stop the integrated detection system
    pub async fn stop(&mut self) {
        *self.is_running.write().await = false;

        // Stop individual detection engines
        self.stop_detection_engines().await;

        self.event_sender = None;
        self.correlation_sender = None;
    }

    /// Process a threat event and perform correlation
    async fn process_threat_event(
        event: UnifiedThreatEvent,
        event_buffer: &Arc<RwLock<Vec<UnifiedThreatEvent>>>,
        correlation_results: &Arc<RwLock<Vec<CorrelatedThreatResult>>>,
        stats: &Arc<RwLock<IntegrationStats>>,
        config: &IntegratedDetectionConfig,
        correlation_sender: &mpsc::UnboundedSender<CorrelatedThreatResult>,
    ) {
        let start_time = SystemTime::now();

        // Add event to buffer
        {
            let mut buffer = event_buffer.write().await;
            buffer.push(event.clone());

            // Maintain buffer size
            while buffer.len() > config.max_events_per_engine {
                buffer.remove(0);
            }
        }

        // Update statistics
        {
            let mut stats_guard = stats.write().await;
            *stats_guard
                .events_by_engine
                .entry(event.source_engine.clone())
                .or_insert(0) += 1;

            if event.confidence >= config.min_confidence_threshold {
                stats_guard.high_confidence_detections += 1;
            }

            stats_guard.last_update = SystemTime::now();
        }

        // Perform correlation if enabled
        if config.enable_correlation {
            if let Some(correlation) = Self::correlate_events(&event, event_buffer, config).await {
                {
                    let mut correlations = correlation_results.write().await;
                    correlations.push(correlation.clone());

                    // Maintain correlation results size
                    while correlations.len() > 1000 {
                        correlations.remove(0);
                    }
                }

                // Update correlation statistics
                {
                    let mut stats_guard = stats.write().await;
                    stats_guard.total_correlations += 1;
                }

                // Send correlation result
                let _ = correlation_sender.send(correlation);
            }
        }

        // Update processing time statistics
        if let Ok(duration) = start_time.elapsed() {
            let mut stats_guard = stats.write().await;
            stats_guard.avg_processing_time = (stats_guard.avg_processing_time + duration) / 2;
        }
    }

    /// Correlate events to detect complex attack patterns
    async fn correlate_events(
        new_event: &UnifiedThreatEvent,
        event_buffer: &Arc<RwLock<Vec<UnifiedThreatEvent>>>,
        config: &IntegratedDetectionConfig,
    ) -> Option<CorrelatedThreatResult> {
        let buffer = event_buffer.read().await;

        // Find related events within the correlation window
        let cutoff_time = new_event.timestamp - config.correlation_window;
        let related_events: Vec<UnifiedThreatEvent> = buffer
            .iter()
            .filter(|event| {
                event.timestamp >= cutoff_time
                    && event.event_id != new_event.event_id
                    && Self::events_are_related(new_event, event)
            })
            .cloned()
            .collect();

        if related_events.is_empty() {
            return None;
        }

        // Calculate overall confidence
        let mut total_confidence = new_event.confidence;
        for event in &related_events {
            total_confidence += event.confidence * 0.5; // Weight related events less
        }
        let overall_confidence =
            (total_confidence / (1.0 + related_events.len() as f32 * 0.5)).min(1.0_f32);

        // Determine risk level
        let risk_level = match overall_confidence {
            c if c >= 0.95 => RiskLevel::Emergency,
            c if c >= 0.85 => RiskLevel::Critical,
            c if c >= 0.70 => RiskLevel::High,
            c if c >= 0.50 => RiskLevel::Medium,
            _ => RiskLevel::Low,
        };

        // Build timeline
        let mut timeline = vec![(
            new_event.timestamp,
            format!("Primary event: {:?}", new_event.threat_type),
        )];
        for event in &related_events {
            timeline.push((
                event.timestamp,
                format!("Related event: {:?}", event.threat_type),
            ));
        }
        timeline.sort_by_key(|(time, _)| *time);

        // Generate mitigation recommendations
        let mitigation_steps =
            Self::generate_mitigation_steps(new_event, &related_events, &risk_level);

        Some(CorrelatedThreatResult {
            correlation_id: Uuid::new_v4(),
            primary_event: new_event.clone(),
            related_events,
            overall_confidence,
            campaign_id: None, // Could be enhanced with campaign detection
            timeline,
            risk_level,
            mitigation_steps,
        })
    }

    /// Check if two events are related
    fn events_are_related(event1: &UnifiedThreatEvent, event2: &UnifiedThreatEvent) -> bool {
        // Same process ID
        if let (Some(pid1), Some(pid2)) = (event1.process_id, event2.process_id) {
            if pid1 == pid2 {
                return true;
            }
        }

        // Same file path
        if let (Some(path1), Some(path2)) = (&event1.file_path, &event2.file_path) {
            if path1 == path2 {
                return true;
            }
        }

        // Same network endpoint
        if let (Some(endpoint1), Some(endpoint2)) =
            (&event1.network_endpoint, &event2.network_endpoint)
        {
            if endpoint1 == endpoint2 {
                return true;
            }
        }

        // Similar threat types
        match (&event1.threat_type, &event2.threat_type) {
            (ThreatType::Ransomware, ThreatType::Ransomware) => true,
            (ThreatType::Trojan, ThreatType::Trojan) => true,
            _ => false,
        }
    }

    /// Generate mitigation steps based on threat correlation
    fn generate_mitigation_steps(
        primary_event: &UnifiedThreatEvent,
        _related_events: &[UnifiedThreatEvent],
        risk_level: &RiskLevel,
    ) -> Vec<String> {
        let mut steps = Vec::new();

        match risk_level {
            RiskLevel::Emergency | RiskLevel::Critical => {
                steps.push("IMMEDIATE: Isolate affected systems from network".to_string());
                steps.push("IMMEDIATE: Terminate suspicious processes".to_string());
                steps.push("IMMEDIATE: Contact incident response team".to_string());
            }
            RiskLevel::High => {
                steps.push("HIGH: Monitor affected systems closely".to_string());
                steps.push("HIGH: Prepare for potential isolation".to_string());
            }
            _ => {
                steps.push("MEDIUM: Increase monitoring on affected systems".to_string());
            }
        }

        // Add specific steps based on threat type
        match primary_event.threat_type {
            ThreatType::Ransomware => {
                steps.push("Block file encryption operations".to_string());
                steps.push("Backup critical data immediately".to_string());
            }
            ThreatType::Trojan => {
                steps.push("Run full system scan".to_string());
                steps.push("Update antivirus signatures".to_string());
            }
            _ => {}
        }

        // Add process-specific steps
        if let Some(pid) = primary_event.process_id {
            steps.push(format!(
                "Monitor process ID {} for suspicious activity",
                pid
            ));
        }

        steps
    }

    /// Start all detection engines
    async fn start_detection_engines(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Start behavioral analysis engine
        #[cfg(feature = "behavioral-analysis")]
        if let Some(engine) = &self.behavioral_engine {
            let engine_guard = engine.write().await;
            engine_guard.start_monitoring().await?;
        }

        // Start memory forensics engine
        #[cfg(feature = "memory-forensics")]
        if let Some(engine) = &self.memory_engine {
            let engine_guard = engine.write().await;
            engine_guard.start_monitoring().await?;
        }

        // Start network traffic analyzer
        #[cfg(feature = "network-monitoring")]
        if let Some(engine) = &self.network_engine {
            let engine_guard = engine.write().await;
            engine_guard.start_analysis().await?;
        }

        // Start API hooking engine
        #[cfg(feature = "api-hooking")]
        if let Some(engine) = &self.api_engine {
            let mut engine_guard = engine.write().await;
            engine_guard.start_monitoring().await?;
        }

        // // Start ML anomaly detector - removed for production
        // #[cfg(feature = "ml-engine")]
        // if let Some(engine) = &self.ml_engine {
        //     let _engine_guard = engine.read().await;
        //     // ML engine is typically passive, no explicit start needed
        // }

        Ok(())
    }

    /// Stop all detection engines
    async fn stop_detection_engines(&mut self) {
        // Stop behavioral analysis engine
        #[cfg(feature = "behavioral-analysis")]
        if let Some(engine) = &self.behavioral_engine {
            let engine_guard = engine.write().await;
            let _ = (*engine_guard).stop_monitoring().await;
        }

        // Stop memory forensics engine
        #[cfg(feature = "memory-forensics")]
        if let Some(engine) = &self.memory_engine {
            let engine_guard = engine.write().await;
            let _ = engine_guard.stop_monitoring().await;
        }

        // Stop network traffic analyzer
        #[cfg(feature = "network-monitoring")]
        if let Some(engine) = &self.network_engine {
            let engine_guard = engine.write().await;
            engine_guard.stop_analysis().await;
        }

        // Stop API hooking engine
        #[cfg(feature = "api-hooking")]
        if let Some(engine) = &self.api_engine {
            let mut engine_guard = engine.write().await;
            engine_guard.stop_monitoring().await;
        }
    }

    /// Get current system statistics
    pub async fn get_statistics(&self) -> IntegrationStats {
        self.stats.read().await.clone()
    }

    /// Get recent threat events
    pub async fn get_recent_events(&self, limit: usize) -> Vec<UnifiedThreatEvent> {
        let buffer = self.event_buffer.read().await;
        buffer.iter().rev().take(limit).cloned().collect()
    }

    /// Get correlation results
    pub async fn get_correlations(&self, limit: usize) -> Vec<CorrelatedThreatResult> {
        let correlations = self.correlation_results.read().await;
        correlations.iter().rev().take(limit).cloned().collect()
    }

    /// Submit a threat event for processing
    pub async fn submit_threat_event(
        &self,
        event: UnifiedThreatEvent,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(sender) = &self.event_sender {
            sender.send(event)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[cfg(feature = "behavioral-analysis")]
    async fn test_integrated_detection_system_creation() {
        let config = IntegratedDetectionConfig::default();
        let db = crate::metrics::MetricsDatabase::new(":memory:").unwrap();
        db.initialize_schema().unwrap();
        let metrics = Arc::new(crate::metrics::MetricsCollector::new(db));
        let entropy_analyzer = Arc::new(RwLock::new(EntropyAnalyzer::new(
            crate::entropy_analyzer::EntropyConfig::default(),
            metrics,
        )));

        let system = IntegratedDetectionSystem::new(config, entropy_analyzer).await;
        assert!(system.is_ok());
    }

    #[tokio::test]
    #[cfg(not(feature = "behavioral-analysis"))]
    async fn test_integrated_detection_system_creation() {
        let config = IntegratedDetectionConfig::default();

        let system = IntegratedDetectionSystem::new(config).await;
        assert!(system.is_ok());
    }

    #[test]
    fn test_unified_threat_event_creation() {
        let event = UnifiedThreatEvent {
            event_id: Uuid::new_v4(),
            source_engine: DetectionEngineType::BehavioralAnalysis,
            threat_type: ThreatType::Ransomware,
            severity: ThreatSeverity::High,
            confidence: 0.85,
            timestamp: SystemTime::now(),
            process_id: Some(1234),
            file_path: Some("/path/to/suspicious/file".to_string()),
            network_endpoint: None,
            event_data: serde_json::json!({"test": "data"}),
            #[cfg(feature = "behavioral-analysis")]
            entropy_result: None,
            correlation_score: 0.0,
            recommended_actions: vec!["Monitor process".to_string()],
        };

        assert_eq!(event.source_engine, DetectionEngineType::BehavioralAnalysis);
        assert_eq!(event.confidence, 0.85);
    }

    #[test]
    fn test_events_are_related() {
        let event1 = UnifiedThreatEvent {
            event_id: Uuid::new_v4(),
            source_engine: DetectionEngineType::BehavioralAnalysis,
            threat_type: ThreatType::Ransomware,
            severity: ThreatSeverity::High,
            confidence: 0.85,
            timestamp: SystemTime::now(),
            process_id: Some(1234),
            file_path: None,
            network_endpoint: None,
            event_data: serde_json::json!({}),
            #[cfg(feature = "behavioral-analysis")]
            entropy_result: None,
            correlation_score: 0.0,
            recommended_actions: vec![],
        };

        let event2 = UnifiedThreatEvent {
            event_id: Uuid::new_v4(),
            source_engine: DetectionEngineType::MemoryForensics,
            threat_type: ThreatType::Ransomware,
            severity: ThreatSeverity::Medium,
            confidence: 0.75,
            timestamp: SystemTime::now(),
            process_id: Some(1234), // Same process ID
            file_path: None,
            network_endpoint: None,
            event_data: serde_json::json!({}),
            #[cfg(feature = "behavioral-analysis")]
            entropy_result: None,
            correlation_score: 0.0,
            recommended_actions: vec![],
        };

        assert!(IntegratedDetectionSystem::events_are_related(
            &event1, &event2
        ));
    }

    #[test]
    fn test_risk_level_determination() {
        let levels = vec![
            (0.96, RiskLevel::Emergency),
            (0.90, RiskLevel::Critical),
            (0.75, RiskLevel::High),
            (0.60, RiskLevel::Medium),
            (0.30, RiskLevel::Low),
        ];

        for (confidence, expected_level) in levels {
            let actual_level = match confidence {
                c if c >= 0.95 => RiskLevel::Emergency,
                c if c >= 0.85 => RiskLevel::Critical,
                c if c >= 0.70 => RiskLevel::High,
                c if c >= 0.50 => RiskLevel::Medium,
                _ => RiskLevel::Low,
            };

            assert_eq!(actual_level, expected_level);
        }
    }
}
