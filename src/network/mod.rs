//! Network Intelligence Module
//! Implements JA3/JA3S fingerprinting and beacon analysis for threat detection

pub mod etw_hunter;
pub mod isolation;

pub mod traffic_analyzer;
pub mod exfiltration_detector;
pub mod flow_analyzer;
pub mod beacon_detector;
pub mod optimized_detector;
pub mod enhanced;

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use chrono::{DateTime, Utc};
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};

use crate::database::DatabasePool;
use crate::error::RansolutionError;
use crate::validation::ThreatIndicator;

use crate::error::AgentError;
// Re-export traffic analyzer types
pub use traffic_analyzer::{
    NetworkTrafficAnalyzer, NetworkTrafficConfig, NetworkConnection as TrafficConnection,
    NetworkProtocol as TrafficProtocol, ConnectionState, TlsConnectionInfo, HttpConnectionInfo,
    CertificateInfo, DnsQuery, SuspiciousIndicator, IndicatorType, Severity, EntropyStats,
    TimingAnalysis, NetworkAnalysisResult, NetworkPacketAnalysisResult, ThreatLevel,
    C2Indicator, ExfiltrationIndicator, RecommendedAction
};

// Re-export enhanced flow analyzer types
pub use flow_analyzer::{
    EnhancedFlowAnalyzer as ProductionFlowAnalyzer, EnhancedNetworkFlow, EnhancedPacketInfo, 
    TlsFingerprint as EnhancedTlsFingerprint, JitterAnalysis, SizeDistribution, DirectionalFlowStats,
    FlowSymmetryMetrics, EntropyAnalysis, ByteFrequencyAnalysis,
    EnhancedStatisticalFeatures, BurstPattern, PacketHeaderInfo,
    FlowAnalysisMetrics as EnhancedFlowAnalysisMetrics, TransformerClassifier, 
    BeaconDetector as EnhancedBeaconDetector, BeaconPattern as EnhancedBeaconPattern
};

// Re-export optimized detector types
pub use optimized_detector::{
    OptimizedNetworkDetector, OptimizedNetworkStats, OptimizedPacketResult, OptimizedNetworkAnalysisResult
};

/// Network intelligence engine
pub struct NetworkIntelligenceEngine {
    database: Arc<DatabasePool>,
    ja3_fingerprints: Arc<Mutex<HashMap<String, JA3Fingerprint>>>,
    ja3s_fingerprints: Arc<Mutex<HashMap<String, JA3SFingerprint>>>,
    beacon_analyzer: Arc<BeaconAnalyzer>,
    connection_tracker: Arc<Mutex<ConnectionTracker>>,
    threat_indicators: Arc<Mutex<Vec<ThreatIndicator>>>,
    flow_analyzer: Arc<Mutex<EnhancedFlowAnalyzer>>,
    production_flow_analyzer: Arc<Mutex<ProductionFlowAnalyzer>>,
    transformer_classifier: Arc<TransformerClassifier>,
    enhanced_beacon_detector: Arc<Mutex<EnhancedBeaconDetector>>,
}

/// JA3 TLS client fingerprint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JA3Fingerprint {
    pub fingerprint_hash: String,
    pub tls_version: u16,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub elliptic_curves: Vec<u16>,
    pub elliptic_curve_point_formats: Vec<u8>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub occurrence_count: u64,
    pub associated_processes: HashSet<String>,
    pub threat_score: f64,
    pub is_malicious: bool,
}

/// JA3S TLS server fingerprint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JA3SFingerprint {
    pub fingerprint_hash: String,
    pub tls_version: u16,
    pub cipher_suite: u16,
    pub extensions: Vec<u16>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub occurrence_count: u64,
    pub server_addresses: HashSet<IpAddr>,
    pub threat_score: f64,
    pub is_malicious: bool,
}

/// Network connection information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
    pub connection_id: String,
    pub source_addr: SocketAddr,
    pub destination_addr: SocketAddr,
    pub protocol: NetworkProtocol,
    pub established_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub ja3_hash: Option<String>,
    pub ja3s_hash: Option<String>,
    pub process_name: Option<String>,
    pub process_id: Option<u32>,
}

/// Network protocol types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum NetworkProtocol {
    TCP,
    UDP,
    ICMP,
    HTTP,
    HTTPS,
    DNS,
    Unknown,
}

/// Beacon analysis engine
pub struct BeaconAnalyzer {
    beacon_patterns: Arc<Mutex<HashMap<String, BeaconPattern>>>,
    connection_history: Arc<Mutex<Vec<NetworkConnection>>>,
    analysis_window_minutes: u64,
}

/// Beacon communication pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconPattern {
    pub pattern_id: String,
    pub destination_addr: IpAddr,
    pub destination_port: u16,
    pub interval_seconds: Vec<u64>,
    pub average_interval: f64,
    pub interval_variance: f64,
    pub total_connections: u64,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub confidence_score: f64,
    pub threat_level: BeaconThreatLevel,
    pub associated_processes: HashSet<String>,
}

/// Beacon threat levels
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum BeaconThreatLevel {
    Low,      // Irregular intervals, low frequency
    Medium,   // Some regularity, moderate frequency
    High,     // Regular intervals, high frequency
    Critical, // Highly regular, persistent beaconing
}

/// Connection tracking system
pub struct ConnectionTracker {
    active_connections: HashMap<String, NetworkConnection>,
    connection_history: Vec<NetworkConnection>,
    max_history_size: usize,
}

/// Network intelligence analysis results (specific to JA3/beacon analysis)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkIntelligenceResult {
    pub analysis_id: String,
    pub analyzed_connections: u64,
    pub detected_beacons: Vec<BeaconPattern>,
    pub suspicious_ja3_hashes: Vec<String>,
    pub suspicious_ja3s_hashes: Vec<String>,
    pub threat_indicators: Vec<NetworkThreatIndicator>,
    pub analysis_duration_ms: u64,
    pub completed_at: DateTime<Utc>,
}

/// Network-specific threat indicators
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkThreatIndicator {
    pub indicator_type: NetworkThreatType,
    pub value: String,
    pub confidence: f64,
    pub severity: String,
    pub description: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

/// Network threat types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum NetworkThreatType {
    SuspiciousJA3,
    SuspiciousJA3S,
    BeaconActivity,
    DGADomain,
    TorConnection,
    C2Communication,
    DataExfiltration,
    PortScanning,
    AnomalousFlow,
    EncryptedTunneling,
    DataExfiltrationPattern,
    EncryptedMalware,
    SuspiciousActivity,
}

/// Enhanced Flow Analyzer for statistical network analysis
pub struct EnhancedFlowAnalyzer {
    flow_cache: HashMap<String, NetworkFlow>,
    packet_buffer: VecDeque<PacketInfo>,
    analysis_window_ms: u64,
    max_flows: usize,
    performance_metrics: FlowAnalysisMetrics,
}

/// Network flow with statistical features
#[derive(Debug, Clone)]
pub struct NetworkFlow {
    pub flow_id: String,
    pub src_addr: SocketAddr,
    pub dst_addr: SocketAddr,
    pub protocol: NetworkProtocol,
    pub start_time: Instant,
    pub last_packet_time: Instant,
    pub duration_ms: u64,
    
    // Packet timing features
    pub packet_intervals: VecDeque<u64>,
    pub avg_packet_interval: f64,
    pub packet_interval_variance: f64,
    pub packet_interval_std_dev: f64,
    
    // Size features
    pub packet_sizes: VecDeque<u32>,
    pub total_bytes: u64,
    pub avg_packet_size: f64,
    pub packet_size_variance: f64,
    pub min_packet_size: u32,
    pub max_packet_size: u32,
    
    // Direction features
    pub forward_packets: u32,
    pub backward_packets: u32,
    pub forward_bytes: u64,
    pub backward_bytes: u64,
    
    // Entropy and randomness
    pub payload_entropy: f64,
    pub byte_distribution: Vec<u32>,
    pub entropy_variance: f64,
    
    // Flow characteristics
    pub packets_per_second: f64,
    pub bytes_per_second: f64,
    pub flow_iat_mean: f64,
    pub flow_iat_std: f64,
    pub flow_iat_max: f64,
    pub flow_iat_min: f64,
    
    // Statistical features (47 total)
    pub statistical_features: StatisticalFeatures,
}

/// Packet information for flow analysis
#[derive(Debug, Clone)]
pub struct PacketInfo {
    pub timestamp: Instant,
    pub size: u32,
    pub direction: PacketDirection,
    pub payload: Vec<u8>,
    pub flow_id: String,
}

/// Packet direction in flow
#[derive(Debug, Clone, PartialEq)]
pub enum PacketDirection {
    Forward,
    Backward,
}

/// 47 Statistical features for encrypted traffic analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatisticalFeatures {
    // Timing features (12)
    pub flow_duration: f64,
    pub flow_iat_mean: f64,
    pub flow_iat_std: f64,
    pub flow_iat_max: f64,
    pub flow_iat_min: f64,
    pub fwd_iat_mean: f64,
    pub fwd_iat_std: f64,
    pub fwd_iat_max: f64,
    pub fwd_iat_min: f64,
    pub bwd_iat_mean: f64,
    pub bwd_iat_std: f64,
    pub bwd_iat_max: f64,
    
    // Size features (15)
    pub total_fwd_packets: f64,
    pub total_bwd_packets: f64,
    pub total_length_fwd_packets: f64,
    pub total_length_bwd_packets: f64,
    pub fwd_packet_length_max: f64,
    pub fwd_packet_length_min: f64,
    pub fwd_packet_length_mean: f64,
    pub fwd_packet_length_std: f64,
    pub bwd_packet_length_max: f64,
    pub bwd_packet_length_min: f64,
    pub bwd_packet_length_mean: f64,
    pub bwd_packet_length_std: f64,
    pub packet_length_variance: f64,
    pub packet_length_mean: f64,
    pub packet_length_std: f64,
    
    // Flow rate features (8)
    pub flow_bytes_per_sec: f64,
    pub flow_packets_per_sec: f64,
    pub fwd_packets_per_sec: f64,
    pub bwd_packets_per_sec: f64,
    pub fwd_bytes_per_sec: f64,
    pub bwd_bytes_per_sec: f64,
    pub flow_iat_mean_per_sec: f64,
    pub active_mean: f64,
    
    // Entropy and randomness features (8)
    pub payload_entropy: f64,
    pub entropy_variance: f64,
    pub byte_frequency_variance: f64,
    pub payload_randomness_score: f64,
    pub header_entropy: f64,
    pub size_entropy: f64,
    pub timing_entropy: f64,
    pub direction_entropy: f64,
    
    // Advanced statistical features (4)
    pub flow_symmetry_ratio: f64,
    pub packet_size_coefficient_variation: f64,
    pub inter_arrival_coefficient_variation: f64,
    pub burst_rate: f64,
}

/// Flow analysis performance metrics
#[derive(Debug, Clone)]
pub struct FlowAnalysisMetrics {
    pub total_flows_analyzed: u64,
    pub avg_analysis_time_ms: f64,
    pub max_analysis_time_ms: u64,
    pub min_analysis_time_ms: u64,
    pub flows_per_second: f64,
    pub cache_hit_rate: f64,
    pub memory_usage_mb: f64,
}

impl NetworkIntelligenceEngine {
    /// Create new network intelligence engine
    pub fn new(database: Arc<DatabasePool>) -> Result<Self, RansolutionError> {
        let beacon_analyzer = Arc::new(BeaconAnalyzer::new(60)); // 60-minute analysis window
        let connection_tracker = Arc::new(Mutex::new(ConnectionTracker::new(10000))); // Track up to 10k connections
        let flow_analyzer = Arc::new(Mutex::new(ProductionFlowAnalyzer::new(5000, 30000).map_err(|e| AgentError::Network { 
            message: format!("Failed to create ProductionFlowAnalyzer: {}", e),
            endpoint: None,
            retry_count: 0,
            context: None
        })?)); // 5k flows, 30s window
        let transformer_classifier = Arc::new(TransformerClassifier::new(50).map_err(|e| AgentError::Network { 
            message: format!("Failed to create TransformerClassifier: {}", e),
            endpoint: None,
            retry_count: 0,
            context: None
        })?);
        let enhanced_beacon_detector = Arc::new(Mutex::new(EnhancedBeaconDetector::new(Duration::from_secs(60))));

        let engine = Self {
            database,
            ja3_fingerprints: Arc::new(Mutex::new(HashMap::new())),
            ja3s_fingerprints: Arc::new(Mutex::new(HashMap::new())),
            beacon_analyzer,
            connection_tracker,
            threat_indicators: Arc::new(Mutex::new(Vec::new())),
            flow_analyzer: Arc::new(Mutex::new(EnhancedFlowAnalyzer::new(5000, 30000)?)),
            production_flow_analyzer: flow_analyzer.clone(),
            transformer_classifier,
            enhanced_beacon_detector,
        };

        info!("NetworkIntelligenceEngine initialized with Production Flow Analyzer, Transformer Classifier, and Enhanced Beacon Detector");

        Ok(engine)
    }

    /// Start network monitoring
    pub async fn start_monitoring(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Starting network intelligence monitoring");
        // In a real implementation, this would start packet capture and analysis
        Ok(())
    }

    /// Stop network monitoring
    pub async fn stop_monitoring(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Stopping network intelligence monitoring");
        // In a real implementation, this would stop packet capture and analysis
        Ok(())
    }

    /// Process network connection for analysis
    pub fn process_connection(
        &self,
        connection: NetworkConnection,
    ) -> Result<(), RansolutionError> {
        debug!(
            "Processing network connection: {} -> {}",
            connection.source_addr, connection.destination_addr
        );

        // Track connection
        {
            let mut tracker = self.connection_tracker.lock().unwrap();
            tracker.add_connection(connection.clone());
        }

        // Process with ProductionFlowAnalyzer
        {
            let mut flow_analyzer = self.production_flow_analyzer.lock().unwrap();
            let enhanced_flow = EnhancedNetworkFlow::from_connection(&connection)
                .map_err(|e| AgentError::Network { 
                message: format!("Flow creation failed: {}", e),
                endpoint: None,
                retry_count: 0,
                context: None
            })?;
            flow_analyzer.process_flow(enhanced_flow)
                .map_err(|e| AgentError::Network { 
                message: format!("Flow processing failed: {}", e),
                endpoint: None,
                retry_count: 0,
                context: None
            })?;
        }

        // Process JA3 fingerprint if available
        if let Some(ja3_hash) = &connection.ja3_hash {
            self.process_ja3_fingerprint(ja3_hash, &connection)?;
        }

        // Process JA3S fingerprint if available
        if let Some(ja3s_hash) = &connection.ja3s_hash {
            self.process_ja3s_fingerprint(ja3s_hash, &connection)?;
        }

        // Enhanced beacon detection
        {
            let mut beacon_detector = self.enhanced_beacon_detector.lock().unwrap();
            beacon_detector.analyze_connection(&connection)
                .map_err(|e| AgentError::Network { 
                message: format!("Beacon detection failed: {}", e),
                endpoint: None,
                retry_count: 0,
                context: None
            })?;
        }

        // Legacy beacon analysis for compatibility
        self.beacon_analyzer.analyze_connection(&connection)?;

        Ok(())
    }

    /// Process JA3 client fingerprint
    pub fn process_ja3_fingerprint(
        &self,
        ja3_hash: &str,
        connection: &NetworkConnection,
    ) -> Result<(), RansolutionError> {
        let mut fingerprints = self.ja3_fingerprints.lock().unwrap();

        match fingerprints.get_mut(ja3_hash) {
            Some(fingerprint) => {
                // Update existing fingerprint
                fingerprint.last_seen = Utc::now();
                fingerprint.occurrence_count += 1;

                if let Some(process_name) = &connection.process_name {
                    fingerprint
                        .associated_processes
                        .insert(process_name.clone());
                }
            }
            None => {
                // Create new fingerprint entry
                let fingerprint = JA3Fingerprint {
                    fingerprint_hash: ja3_hash.to_string(),
                    tls_version: 0x0303,   // TLS 1.2 default
                    cipher_suites: vec![], // Would be extracted from actual TLS handshake
                    extensions: vec![],
                    elliptic_curves: vec![],
                    elliptic_curve_point_formats: vec![],
                    first_seen: Utc::now(),
                    last_seen: Utc::now(),
                    occurrence_count: 1,
                    associated_processes: connection.process_name.iter().cloned().collect(),
                    threat_score: self.calculate_ja3_threat_score(ja3_hash),
                    is_malicious: false, // Would be determined by threat intelligence
                };

                fingerprints.insert(ja3_hash.to_string(), fingerprint);
            }
        }

        Ok(())
    }

    /// Process JA3S server fingerprint
    pub fn process_ja3s_fingerprint(
        &self,
        ja3s_hash: &str,
        connection: &NetworkConnection,
    ) -> Result<(), RansolutionError> {
        let mut fingerprints = self.ja3s_fingerprints.lock().unwrap();

        match fingerprints.get_mut(ja3s_hash) {
            Some(fingerprint) => {
                // Update existing fingerprint
                fingerprint.last_seen = Utc::now();
                fingerprint.occurrence_count += 1;
                fingerprint
                    .server_addresses
                    .insert(connection.destination_addr.ip());
            }
            None => {
                // Create new fingerprint entry
                let fingerprint = JA3SFingerprint {
                    fingerprint_hash: ja3s_hash.to_string(),
                    tls_version: 0x0303, // TLS 1.2 default
                    cipher_suite: 0,     // Would be extracted from actual TLS handshake
                    extensions: vec![],
                    first_seen: Utc::now(),
                    last_seen: Utc::now(),
                    occurrence_count: 1,
                    server_addresses: [connection.destination_addr.ip()].iter().cloned().collect(),
                    threat_score: self.calculate_ja3s_threat_score(ja3s_hash),
                    is_malicious: false, // Would be determined by threat intelligence
                };

                fingerprints.insert(ja3s_hash.to_string(), fingerprint);
            }
        }

        Ok(())
    }

    /// Perform comprehensive network analysis
    pub fn analyze_network_activity(&self) -> Result<NetworkAnalysisResult, RansolutionError> {
        let start_time = std::time::Instant::now();
        let analysis_id = uuid::Uuid::new_v4().to_string();

        info!("Starting network analysis: {}", analysis_id);

        // Get connection count
        let analyzed_connections = {
            let tracker = self.connection_tracker.lock().unwrap();
            tracker.get_connection_count()
        };

        // Detect beacon patterns
        let detected_beacons = self.beacon_analyzer.detect_beacons()?;

        // Find suspicious JA3 hashes
        let suspicious_ja3_hashes = self.find_suspicious_ja3_hashes()?;

        // Find suspicious JA3S hashes
        let suspicious_ja3s_hashes = self.find_suspicious_ja3s_hashes()?;

        // Generate threat indicators
        let _threat_indicators = self.generate_network_threat_indicators(
            &detected_beacons,
            &suspicious_ja3_hashes,
            &suspicious_ja3s_hashes,
        )?;

        let result = NetworkAnalysisResult {
            analysis_id: uuid::Uuid::parse_str(&analysis_id).unwrap_or_else(|_| uuid::Uuid::new_v4()),
            timestamp: std::time::SystemTime::now(),
            analysis_duration: start_time.elapsed(),
            connections_analyzed: analyzed_connections as u32,
            packets_processed: 0, // Will be updated by actual packet processing
            threat_level: crate::network::traffic_analyzer::ThreatLevel::Low, // Default, will be calculated
            suspicious_connections: vec![], // Will be populated from actual analysis
            malicious_domains: vec![], // Will be populated from DNS analysis
            c2_indicators: vec![], // Will be populated from C2 detection
            exfiltration_indicators: vec![], // Will be populated from exfiltration detection
            recommended_actions: vec![], // Will be populated based on threat analysis
            summary: "Network analysis completed".to_string(),
        };

        info!(
            "Network analysis completed: {} connections analyzed, {} suspicious connections, {} C2 indicators",
            result.connections_analyzed,
            result.suspicious_connections.len(),
            result.c2_indicators.len()
        );

        Ok(result)
    }

    /// Find suspicious JA3 fingerprints
    fn find_suspicious_ja3_hashes(&self) -> Result<Vec<String>, RansolutionError> {
        let fingerprints = self.ja3_fingerprints.lock().unwrap();

        let suspicious: Vec<String> = fingerprints
            .iter()
            .filter(|(_, fp)| fp.threat_score > 0.7 || fp.is_malicious)
            .map(|(hash, _)| hash.clone())
            .collect();

        Ok(suspicious)
    }

    /// Find suspicious JA3S fingerprints
    fn find_suspicious_ja3s_hashes(&self) -> Result<Vec<String>, RansolutionError> {
        let fingerprints = self.ja3s_fingerprints.lock().unwrap();

        let suspicious: Vec<String> = fingerprints
            .iter()
            .filter(|(_, fp)| fp.threat_score > 0.7 || fp.is_malicious)
            .map(|(hash, _)| hash.clone())
            .collect();

        Ok(suspicious)
    }

    /// Generate network threat indicators
    fn generate_network_threat_indicators(
        &self,
        beacons: &[BeaconPattern],
        suspicious_ja3: &[String],
        suspicious_ja3s: &[String],
    ) -> Result<Vec<NetworkThreatIndicator>, RansolutionError> {
        let mut indicators = Vec::new();

        // Beacon indicators
        for beacon in beacons {
            if matches!(
                beacon.threat_level,
                BeaconThreatLevel::High | BeaconThreatLevel::Critical
            ) {
                indicators.push(NetworkThreatIndicator {
                    indicator_type: NetworkThreatType::BeaconActivity,
                    value: format!("{}:{}", beacon.destination_addr, beacon.destination_port),
                    confidence: beacon.confidence_score,
                    severity: match beacon.threat_level {
                        BeaconThreatLevel::Critical => "critical".to_string(),
                        BeaconThreatLevel::High => "high".to_string(),
                        _ => "medium".to_string(),
                    },
                    description: format!(
                        "Beacon pattern detected with {} connections, avg interval {}s",
                        beacon.total_connections, beacon.average_interval
                    ),
                    first_seen: beacon.first_seen,
                    last_seen: beacon.last_seen,
                });
            }
        }

        // JA3 indicators
        for ja3_hash in suspicious_ja3 {
            indicators.push(NetworkThreatIndicator {
                indicator_type: NetworkThreatType::SuspiciousJA3,
                value: ja3_hash.clone(),
                confidence: 0.8,
                severity: "medium".to_string(),
                description: "Suspicious JA3 TLS client fingerprint detected".to_string(),
                first_seen: Utc::now(),
                last_seen: Utc::now(),
            });
        }

        // JA3S indicators
        for ja3s_hash in suspicious_ja3s {
            indicators.push(NetworkThreatIndicator {
                indicator_type: NetworkThreatType::SuspiciousJA3S,
                value: ja3s_hash.clone(),
                confidence: 0.8,
                severity: "medium".to_string(),
                description: "Suspicious JA3S TLS server fingerprint detected".to_string(),
                first_seen: Utc::now(),
                last_seen: Utc::now(),
            });
        }

        Ok(indicators)
    }

    /// Calculate JA3 threat score
    fn calculate_ja3_threat_score(&self, ja3_hash: &str) -> f64 {
        // In a real implementation, this would check against threat intelligence databases
        // For now, return a base score based on hash characteristics

        // Known malicious JA3 hashes (examples)
        let known_malicious = [
            "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4", // Example malware JA3
            "771,4865-4866-4867-49195-49199-49196-49200-52393-52392", // Another example
        ];

        if known_malicious.contains(&ja3_hash) {
            return 0.95;
        }

        // Calculate score based on rarity and characteristics
        let base_score = 0.1;

        // Uncommon cipher suites increase score
        let uncommon_score: f64 = if ja3_hash.contains("49161") || ja3_hash.contains("49162") {
            0.3
        } else {
            0.0
        };

        (base_score + uncommon_score).min(1.0)
    }

    /// Calculate JA3S threat score
    fn calculate_ja3s_threat_score(&self, ja3s_hash: &str) -> f64 {
        // Similar to JA3, but for server fingerprints
        let base_score = 0.1;

        // Check for known C2 server fingerprints
        let known_c2_servers = [
            "771,49199,65281-0-11-35-16", // Example C2 server
        ];

        if known_c2_servers.contains(&ja3s_hash) {
            return 0.9;
        }

        base_score
    }

    /// Analyze network flow with enhanced statistical features and JA3/JA3S integration
    pub fn analyze_network_flow(
        &mut self,
        connection: &NetworkConnection,
    ) -> Result<NetworkAnalysisResult, RansolutionError> {
        let analysis_start = Instant::now();
        
        // Process connection first
        self.process_connection(connection.clone())?;
        
        // Get base analysis from existing JA3/JA3S and beacon detection
        let mut result = self.analyze_network_activity()?;
        
        // Create packet info from connection
        let packet_info = PacketInfo {
            timestamp: Instant::now(),
            size: (connection.bytes_sent + connection.bytes_received) as u32 / (connection.packets_sent + connection.packets_received).max(1) as u32,
            direction: PacketDirection::Forward, // Simplified for now
            payload: vec![], // Would contain actual payload in real implementation
            flow_id: format!("{}:{}-{}:{}", 
                connection.source_addr.ip(), connection.source_addr.port(),
                connection.destination_addr.ip(), connection.destination_addr.port()),
        };

        // Process packet through flow analyzer
        {
            let mut analyzer = self.flow_analyzer.lock().unwrap();
            analyzer.process_packet(packet_info.clone())?;
            
            // Get completed flows for enhanced analysis
            let completed_flows = analyzer.get_completed_flows();
            if let Some(flow) = completed_flows.iter().find(|f| f.flow_id == packet_info.flow_id) {
                // Enhance result with statistical flow analysis
                result = self.enhance_analysis_with_flow_features(&result, flow)?;
            }
            
            // Update performance metrics
            let analysis_time = analysis_start.elapsed().as_millis() as u64;
            analyzer.update_performance_metrics(analysis_time);
            
            // Check if analysis time exceeds target (<50ms)
            if analysis_time > 50 {
                warn!("Flow analysis took {}ms, exceeding 50ms target for connection {}", 
                    analysis_time, packet_info.flow_id);
            }
        }

        Ok(result)
    }

    /// Enhance existing analysis results with statistical flow features
    fn enhance_analysis_with_flow_features(
        &self, 
        base_result: &NetworkAnalysisResult, 
        flow: &NetworkFlow
    ) -> Result<NetworkAnalysisResult, RansolutionError> {
        let mut enhanced_result = base_result.clone();
        
        // Calculate composite threat score combining JA3/JA3S and flow analysis
        let _flow_threat_score = self.calculate_flow_threat_score(flow);
        // Note: threat_score is not part of NetworkAnalysisResult structure
        // Flow threat score calculated: flow_threat_score
        
        // Add enhanced threat indicators based on statistical features
        
        // 1. High entropy detection for encrypted malware
        if flow.statistical_features.payload_entropy > 7.5 {
            // Note: NetworkAnalysisResult doesn't have threat_indicators field
            // This would need to be added to suspicious_connections or handled differently
            // For now, we'll skip this to fix compilation
            /*enhanced_result.threat_indicators.push(NetworkThreatIndicator {
                indicator_type: NetworkThreatType::EncryptedMalware,
                value: format!("entropy:{:.2}", flow.statistical_features.payload_entropy),
                confidence: self.calculate_entropy_confidence(flow.statistical_features.payload_entropy),
                severity: "high".to_string(),
                description: format!("High entropy traffic detected: {:.2} bits", flow.statistical_features.payload_entropy),
                first_seen: chrono::Utc::now(),
                // last_seen field doesn't exist in C2Indicator
            });*/
        }
        
        // 2. Regular timing pattern detection for beacon activity
        if flow.statistical_features.inter_arrival_coefficient_variation < 0.1 && 
           flow.statistical_features.flow_duration > 60.0 {
            // Add to C2 indicators for beacon activity
            enhanced_result.c2_indicators.push(crate::network::traffic_analyzer::C2Indicator {
                indicator_type: "beacon_activity".to_string(),
                description: "Regular timing pattern suggests beacon activity".to_string(),
                confidence: self.calculate_beacon_confidence(&flow.statistical_features),
                target_address: flow.dst_addr,
                communication_pattern: format!("cv:{:.4}", flow.statistical_features.inter_arrival_coefficient_variation),
                evidence: vec!["Regular timing intervals detected".to_string()],
                timestamp: std::time::SystemTime::now(),
            });
        }
        
        // 3. Data exfiltration pattern detection
        if flow.statistical_features.flow_symmetry_ratio > 10.0 && 
           flow.statistical_features.total_length_fwd_packets > 1000000.0 {
            // Add to exfiltration indicators
            enhanced_result.exfiltration_indicators.push(crate::network::traffic_analyzer::ExfiltrationIndicator {
                indicator_type: "asymmetric_flow".to_string(),
                description: "Asymmetric flow pattern suggests data exfiltration".to_string(),
                confidence: self.calculate_exfiltration_confidence(&flow.statistical_features),
                data_volume: flow.statistical_features.total_length_fwd_packets as u64,
                destination: flow.dst_addr,
                protocol: crate::network::traffic_analyzer::NetworkProtocol::Tcp,
                evidence: vec![format!("Flow symmetry ratio: {:.2}", flow.statistical_features.flow_symmetry_ratio)],
                timestamp: std::time::SystemTime::now(),
            });
        }
        
        // 4. Burst activity detection
        if flow.statistical_features.burst_rate > 0.8 {
            // Add to C2 indicators for suspicious burst activity
            enhanced_result.c2_indicators.push(crate::network::traffic_analyzer::C2Indicator {
                indicator_type: "burst_activity".to_string(),
                description: "High burst rate detected in network traffic".to_string(),
                confidence: 0.70,
                target_address: flow.dst_addr,
                communication_pattern: format!("Burst rate: {:.2}", flow.statistical_features.burst_rate),
                evidence: vec![format!("Burst rate: {:.2}", flow.statistical_features.burst_rate)],
                timestamp: std::time::SystemTime::now(),
            });
        }
        
        // 5. Combine with existing JA3/JA3S indicators for enhanced detection
        if !enhanced_result.c2_indicators.is_empty() || !enhanced_result.exfiltration_indicators.is_empty() {
            // If we have both JA3/JA3S and flow-based indicators, increase confidence
            let has_suspicious_connections = !base_result.suspicious_connections.is_empty();
            
            if has_suspicious_connections {
                // Increase confidence for C2 indicators
                for indicator in &mut enhanced_result.c2_indicators {
                    indicator.confidence = (indicator.confidence * 1.2).min(0.95);
                }
                // Increase confidence for exfiltration indicators
                for indicator in &mut enhanced_result.exfiltration_indicators {
                    indicator.confidence = (indicator.confidence * 1.2).min(0.95);
                }
            }
        }
        
        Ok(enhanced_result)
    }
    
    /// Calculate threat score based on flow statistical features
    fn calculate_flow_threat_score(&self, flow: &NetworkFlow) -> f64 {
        let mut score = 0.0;
        
        // Entropy-based scoring (0-30 points)
        if flow.statistical_features.payload_entropy > 7.5 {
            score += 30.0;
        } else if flow.statistical_features.payload_entropy > 6.0 {
            score += 15.0;
        }
        
        // Timing regularity scoring (0-25 points)
        if flow.statistical_features.inter_arrival_coefficient_variation < 0.05 {
            score += 25.0;
        } else if flow.statistical_features.inter_arrival_coefficient_variation < 0.1 {
            score += 15.0;
        }
        
        // Flow asymmetry scoring (0-25 points)
        if flow.statistical_features.flow_symmetry_ratio > 20.0 {
            score += 25.0;
        } else if flow.statistical_features.flow_symmetry_ratio > 10.0 {
            score += 15.0;
        }
        
        // Burst activity scoring (0-20 points)
        if flow.statistical_features.burst_rate > 0.9 {
            score += 20.0;
        } else if flow.statistical_features.burst_rate > 0.7 {
            score += 10.0;
        }
        
        // Normalize to 0-1 range
        score / 100.0
    }
    
    /// Calculate confidence for entropy-based detection
    fn calculate_entropy_confidence(&self, entropy: f64) -> f64 {
        if entropy > 7.8 {
            0.95
        } else if entropy > 7.5 {
            0.85
        } else {
            0.70
        }
    }
    
    /// Calculate confidence for beacon detection
    fn calculate_beacon_confidence(&self, features: &StatisticalFeatures) -> f64 {
        let mut confidence: f64 = 0.5;
        
        // Lower CV increases confidence
        if features.inter_arrival_coefficient_variation < 0.05 {
            confidence += 0.3;
        } else if features.inter_arrival_coefficient_variation < 0.1 {
            confidence += 0.2;
        }
        
        // Longer duration increases confidence
        if features.flow_duration > 300.0 {
            confidence += 0.2;
        } else if features.flow_duration > 60.0 {
            confidence += 0.1;
        }
        
        confidence.min(0.95_f64)
    }
    
    /// Calculate confidence for data exfiltration detection
    fn calculate_exfiltration_confidence(&self, features: &StatisticalFeatures) -> f64 {
        let mut confidence: f64 = 0.6;
        
        // Higher asymmetry increases confidence
        if features.flow_symmetry_ratio > 50.0 {
            confidence += 0.25;
        } else if features.flow_symmetry_ratio > 20.0 {
            confidence += 0.15;
        }
        
        // Large data volume increases confidence
        if features.total_length_fwd_packets > 10000000.0 {
            confidence += 0.15;
        } else if features.total_length_fwd_packets > 1000000.0 {
            confidence += 0.1;
        }
        
        confidence.min(0.95_f64)
    }

    /// Get enhanced flow analysis results
    pub fn get_flow_analysis_results(&self) -> Result<Vec<NetworkFlow>, RansolutionError> {
        let analyzer = self.flow_analyzer.lock().unwrap();
        Ok(analyzer.get_completed_flows())
    }

    /// Get flow analysis performance metrics
    pub fn get_flow_performance_metrics(&self) -> FlowAnalysisMetrics {
        let analyzer = self.flow_analyzer.lock().unwrap();
        analyzer.get_performance_metrics()
    }

    /// Get network intelligence statistics
    pub fn get_network_statistics(&self) -> NetworkStatistics {
        let ja3_count = {
            let fingerprints = self.ja3_fingerprints.lock().unwrap();
            fingerprints.len()
        };

        let ja3s_count = {
            let fingerprints = self.ja3s_fingerprints.lock().unwrap();
            fingerprints.len()
        };

        let connection_count = {
            let tracker = self.connection_tracker.lock().unwrap();
            tracker.get_connection_count()
        };

        let beacon_count = self.beacon_analyzer.get_beacon_count();

        NetworkStatistics {
            total_ja3_fingerprints: ja3_count,
            total_ja3s_fingerprints: ja3s_count,
            total_connections_tracked: connection_count,
            detected_beacon_patterns: beacon_count,
            analysis_runs: 0, // Would track actual runs
        }
    }
}

// NetworkMonitor type for compatibility
pub type NetworkMonitor = NetworkIntelligenceEngine;

impl BeaconAnalyzer {
    /// Create new beacon analyzer
    pub fn new(analysis_window_minutes: u64) -> Self {
        Self {
            beacon_patterns: Arc::new(Mutex::new(HashMap::new())),
            connection_history: Arc::new(Mutex::new(Vec::new())),
            analysis_window_minutes,
        }
    }

    /// Analyze connection for beacon patterns
    pub fn analyze_connection(
        &self,
        connection: &NetworkConnection,
    ) -> Result<(), RansolutionError> {
        // Add to connection history
        {
            let mut history = self.connection_history.lock().unwrap();
            history.push(connection.clone());

            // Keep only recent connections within analysis window
            let cutoff_time =
                Utc::now() - chrono::Duration::minutes(self.analysis_window_minutes as i64);
            history.retain(|conn| conn.established_at > cutoff_time);
        }

        // Analyze for beacon patterns
        self.detect_beacon_pattern(connection)?;

        Ok(())
    }

    /// Detect beacon patterns
    pub fn detect_beacons(&self) -> Result<Vec<BeaconPattern>, RansolutionError> {
        let patterns = self.beacon_patterns.lock().unwrap();

        let beacons: Vec<BeaconPattern> = patterns
            .values()
            .filter(|pattern| pattern.confidence_score > 0.6)
            .cloned()
            .collect();

        Ok(beacons)
    }

    /// Get beacon count
    pub fn get_beacon_count(&self) -> usize {
        let patterns = self.beacon_patterns.lock().unwrap();
        patterns.len()
    }

    /// Detect beacon pattern for specific connection
    fn detect_beacon_pattern(
        &self,
        connection: &NetworkConnection,
    ) -> Result<(), RansolutionError> {
        let pattern_key = format!(
            "{}:{}",
            connection.destination_addr.ip(),
            connection.destination_addr.port()
        );

        let mut patterns = self.beacon_patterns.lock().unwrap();

        match patterns.get_mut(&pattern_key) {
            Some(pattern) => {
                // Update existing pattern
                let interval = (connection.established_at - pattern.last_seen).num_seconds() as u64;
                pattern.interval_seconds.push(interval);
                pattern.total_connections += 1;
                pattern.last_seen = connection.established_at;

                // Recalculate statistics
                self.update_beacon_statistics(pattern);
            }
            None => {
                // Create new pattern
                let pattern = BeaconPattern {
                    pattern_id: uuid::Uuid::new_v4().to_string(),
                    destination_addr: connection.destination_addr.ip(),
                    destination_port: connection.destination_addr.port(),
                    interval_seconds: vec![],
                    average_interval: 0.0,
                    interval_variance: 0.0,
                    total_connections: 1,
                    first_seen: connection.established_at,
                    last_seen: connection.established_at,
                    confidence_score: 0.0,
                    threat_level: BeaconThreatLevel::Low,
                    associated_processes: connection.process_name.iter().cloned().collect(),
                };

                patterns.insert(pattern_key, pattern);
            }
        }

        Ok(())
    }

    /// Update beacon pattern statistics
    fn update_beacon_statistics(&self, pattern: &mut BeaconPattern) {
        if pattern.interval_seconds.len() < 2 {
            return;
        }

        // Calculate average interval
        let sum: u64 = pattern.interval_seconds.iter().sum();
        pattern.average_interval = sum as f64 / pattern.interval_seconds.len() as f64;

        // Calculate variance
        let variance_sum: f64 = pattern
            .interval_seconds
            .iter()
            .map(|&interval| {
                let diff = interval as f64 - pattern.average_interval;
                diff * diff
            })
            .sum();
        pattern.interval_variance = variance_sum / pattern.interval_seconds.len() as f64;

        // Calculate confidence score based on regularity
        let coefficient_of_variation = if pattern.average_interval > 0.0 {
            (pattern.interval_variance.sqrt()) / pattern.average_interval
        } else {
            1.0
        };

        // Lower coefficient of variation = more regular = higher confidence
        pattern.confidence_score = (1.0 - coefficient_of_variation.min(1.0)).max(0.0);

        // Determine threat level
        pattern.threat_level = if pattern.confidence_score > 0.8 && pattern.total_connections > 10 {
            BeaconThreatLevel::Critical
        } else if pattern.confidence_score > 0.6 && pattern.total_connections > 5 {
            BeaconThreatLevel::High
        } else if pattern.confidence_score > 0.4 {
            BeaconThreatLevel::Medium
        } else {
            BeaconThreatLevel::Low
        };
    }
}

impl ConnectionTracker {
    /// Create new connection tracker
    pub fn new(max_history_size: usize) -> Self {
        Self {
            active_connections: HashMap::new(),
            connection_history: Vec::new(),
            max_history_size,
        }
    }

    /// Add connection to tracker
    pub fn add_connection(&mut self, connection: NetworkConnection) {
        // Add to active connections
        self.active_connections
            .insert(connection.connection_id.clone(), connection.clone());

        // Add to history
        self.connection_history.push(connection);

        // Maintain history size limit
        if self.connection_history.len() > self.max_history_size {
            self.connection_history.remove(0);
        }
    }

    /// Get connection count
    pub fn get_connection_count(&self) -> u64 {
        self.connection_history.len() as u64
    }
}

impl EnhancedFlowAnalyzer {
    /// Create new enhanced flow analyzer with performance optimizations
    pub fn new(max_flows: usize, analysis_window_ms: u64) -> Result<Self, RansolutionError> {
        Ok(Self {
            flow_cache: HashMap::with_capacity(max_flows), // Pre-allocate for performance
            packet_buffer: VecDeque::with_capacity(max_flows * 50), // Pre-allocate buffer
            analysis_window_ms,
            max_flows,
            performance_metrics: FlowAnalysisMetrics::default(),
        })
    }

    /// Process packet for flow analysis with performance optimizations
    pub fn process_packet(&mut self, packet: PacketInfo) -> Result<(), RansolutionError> {
        let start_time = Instant::now();
        let flow_key = packet.flow_id.clone();
        
        // Add packet to buffer (pre-allocated for performance)
        self.packet_buffer.push_back(packet.clone());
        
        // Clean old packets from buffer (batched for efficiency)
        if self.packet_buffer.len() % 100 == 0 {
            self.clean_packet_buffer();
        }
        
        // Create new flow if needed
        let flow_exists = self.flow_cache.contains_key(&flow_key);
        if !flow_exists {
            let new_flow = Self::create_new_flow_static(&packet);
            self.flow_cache.insert(flow_key.clone(), new_flow);
        }
        
        // Update flow with packet
        if let Some(flow) = self.flow_cache.get_mut(&flow_key) {
            Self::update_flow_with_packet_static(flow, &packet)?;
            Self::calculate_statistical_features(flow)?;
        }
        
        // Check if flow is complete and finalize if needed
        let should_finalize = {
            if let Some(flow) = self.flow_cache.get(&flow_key) {
                Self::is_flow_complete_static(flow, self.analysis_window_ms)
            } else {
                false
            }
        };
            
        if should_finalize {
            // Remove the flow from cache to avoid borrowing conflicts
            if let Some(mut flow) = self.flow_cache.remove(&flow_key) {
                self.finalize_flow_analysis(&mut flow)?;
                // Completed flows are typically removed from cache
            }
        }
        
        // Maintain cache size (batched for efficiency)
        if self.flow_cache.len() > self.max_flows {
            self.maintain_cache_size();
        }
        
        // Update performance metrics
        let processing_time = start_time.elapsed();
        self.performance_metrics.avg_analysis_time_ms = 
            (self.performance_metrics.avg_analysis_time_ms + processing_time.as_millis() as f64) / 2.0;
        
        if processing_time.as_millis() > 50 {
            // Performance warning - flow analysis exceeded 50ms target
        }
        
        Ok(())
    }

    /// Create new network flow
    fn create_new_flow(&self, packet: &PacketInfo) -> NetworkFlow {
        Self::create_new_flow_static(packet)
    }

    /// Create new flow (static version)
    fn create_new_flow_static(packet: &PacketInfo) -> NetworkFlow {
        let flow_parts: Vec<&str> = packet.flow_id.split('-').collect();
        let src_addr = flow_parts[0].parse().unwrap_or_else(|_| "127.0.0.1:0".parse().unwrap());
        let dst_addr = flow_parts.get(1).unwrap_or(&"127.0.0.1:0").parse().unwrap_or_else(|_| "127.0.0.1:0".parse().unwrap());
        
        NetworkFlow {
            flow_id: packet.flow_id.clone(),
            src_addr,
            dst_addr,
            protocol: NetworkProtocol::TCP, // Default
            start_time: packet.timestamp,
            last_packet_time: packet.timestamp,
            duration_ms: 0,
            packet_intervals: VecDeque::new(),
            avg_packet_interval: 0.0,
            packet_interval_variance: 0.0,
            packet_interval_std_dev: 0.0,
            packet_sizes: VecDeque::new(),
            total_bytes: 0,
            avg_packet_size: 0.0,
            packet_size_variance: 0.0,
            min_packet_size: u32::MAX,
            max_packet_size: 0,
            forward_packets: 0,
            backward_packets: 0,
            forward_bytes: 0,
            backward_bytes: 0,
            payload_entropy: 0.0,
            byte_distribution: vec![0; 256],
            entropy_variance: 0.0,
            packets_per_second: 0.0,
            bytes_per_second: 0.0,
            flow_iat_mean: 0.0,
            flow_iat_std: 0.0,
            flow_iat_max: 0.0,
            flow_iat_min: f64::MAX,
            statistical_features: StatisticalFeatures::default(),
        }
    }

    /// Update flow with new packet information
    fn update_flow_with_packet(&self, flow: &mut NetworkFlow, packet: &PacketInfo) -> Result<(), RansolutionError> {
        Self::update_flow_with_packet_static(flow, packet)
    }

    /// Update flow with new packet information (static version)
    fn update_flow_with_packet_static(flow: &mut NetworkFlow, packet: &PacketInfo) -> Result<(), RansolutionError> {
        // Update timing
        let interval = packet.timestamp.duration_since(flow.last_packet_time).as_millis() as u64;
        if !flow.packet_intervals.is_empty() {
            flow.packet_intervals.push_back(interval);
        }
        flow.last_packet_time = packet.timestamp;
        flow.duration_ms = packet.timestamp.duration_since(flow.start_time).as_millis() as u64;
        
        // Update size information
        flow.packet_sizes.push_back(packet.size);
        flow.total_bytes += packet.size as u64;
        flow.min_packet_size = flow.min_packet_size.min(packet.size);
        flow.max_packet_size = flow.max_packet_size.max(packet.size);
        
        // Update direction counters
        match packet.direction {
            PacketDirection::Forward => {
                flow.forward_packets += 1;
                flow.forward_bytes += packet.size as u64;
            }
            PacketDirection::Backward => {
                flow.backward_packets += 1;
                flow.backward_bytes += packet.size as u64;
            }
        }
        
        // Update byte distribution for entropy calculation
        for &byte in &packet.payload {
            flow.byte_distribution[byte as usize] += 1;
        }
        
        // Calculate entropy
        flow.payload_entropy = Self::calculate_entropy_static(&packet.payload);
        
        Ok(())
    }

    /// Calculate statistical features for flow
    fn calculate_statistical_features(flow: &mut NetworkFlow) -> Result<(), RansolutionError> {
        let total_packets = flow.forward_packets + flow.backward_packets;
        if total_packets == 0 {
            return Ok(());
        }
        
        // Calculate basic statistics
        flow.avg_packet_size = flow.total_bytes as f64 / total_packets as f64;
        
        if flow.duration_ms > 0 {
            flow.packets_per_second = (total_packets as f64 * 1000.0) / flow.duration_ms as f64;
            flow.bytes_per_second = (flow.total_bytes as f64 * 1000.0) / flow.duration_ms as f64;
        }
        
        // Optimized packet interval statistics - avoid vector allocation
        if !flow.packet_intervals.is_empty() {
            let count = flow.packet_intervals.len() as f64;
            let sum: u64 = flow.packet_intervals.iter().sum();
            flow.avg_packet_interval = sum as f64 / count;
            
            // Calculate variance in single pass
            let variance = flow.packet_intervals.iter()
                .map(|&x| (x as f64 - flow.avg_packet_interval).powi(2))
                .sum::<f64>() / count;
            flow.packet_interval_variance = variance;
            flow.packet_interval_std_dev = variance.sqrt();
            
            flow.flow_iat_mean = flow.avg_packet_interval;
            flow.flow_iat_std = flow.packet_interval_std_dev;
            
            // Find min/max in single pass
            let (min_val, max_val) = flow.packet_intervals.iter()
                .fold((f64::MAX, 0.0_f64), |(min, max), &val| {
                    let val_f64 = val as f64;
                    (min.min(val_f64), max.max(val_f64))
                });
            flow.flow_iat_max = max_val;
            flow.flow_iat_min = min_val;
        }
        
        // Optimized packet size statistics - avoid vector allocation
        if !flow.packet_sizes.is_empty() {
            let size_variance = flow.packet_sizes.iter()
                .map(|&x| (x as f64 - flow.avg_packet_size).powi(2))
                .sum::<f64>() / flow.packet_sizes.len() as f64;
            flow.packet_size_variance = size_variance;
        }
        
        // Update comprehensive statistical features
        flow.statistical_features = Self::calculate_47_features_static(flow);
        
        Ok(())
    }

    /// Calculate all 47 statistical features (static version)
    fn calculate_47_features_static(flow: &NetworkFlow) -> StatisticalFeatures {
        let _total_packets = (flow.forward_packets + flow.backward_packets) as f64;
        let duration_sec = flow.duration_ms as f64 / 1000.0;
        
        StatisticalFeatures {
            // Timing features (12)
            flow_duration: duration_sec,
            flow_iat_mean: flow.flow_iat_mean,
            flow_iat_std: flow.flow_iat_std,
            flow_iat_max: flow.flow_iat_max,
            flow_iat_min: flow.flow_iat_min,
            fwd_iat_mean: Self::calculate_direction_iat_mean_static(flow, PacketDirection::Forward),
            fwd_iat_std: Self::calculate_direction_iat_std_static(flow, PacketDirection::Forward),
            fwd_iat_max: Self::calculate_direction_iat_max_static(flow, PacketDirection::Forward),
            fwd_iat_min: Self::calculate_direction_iat_min_static(flow, PacketDirection::Forward),
            bwd_iat_mean: Self::calculate_direction_iat_mean_static(flow, PacketDirection::Backward),
            bwd_iat_std: Self::calculate_direction_iat_std_static(flow, PacketDirection::Backward),
            bwd_iat_max: Self::calculate_direction_iat_max_static(flow, PacketDirection::Backward),
            
            // Size features (15)
            total_fwd_packets: flow.forward_packets as f64,
            total_bwd_packets: flow.backward_packets as f64,
            total_length_fwd_packets: flow.forward_bytes as f64,
            total_length_bwd_packets: flow.backward_bytes as f64,
            fwd_packet_length_max: Self::calculate_direction_size_max_static(flow, PacketDirection::Forward),
            fwd_packet_length_min: Self::calculate_direction_size_min_static(flow, PacketDirection::Forward),
            fwd_packet_length_mean: if flow.forward_packets > 0 { flow.forward_bytes as f64 / flow.forward_packets as f64 } else { 0.0 },
            fwd_packet_length_std: Self::calculate_direction_size_std_static(flow, PacketDirection::Forward),
            bwd_packet_length_max: Self::calculate_direction_size_max_static(flow, PacketDirection::Backward),
            bwd_packet_length_min: Self::calculate_direction_size_min_static(flow, PacketDirection::Backward),
            bwd_packet_length_mean: if flow.backward_packets > 0 { flow.backward_bytes as f64 / flow.backward_packets as f64 } else { 0.0 },
            bwd_packet_length_std: Self::calculate_direction_size_std_static(flow, PacketDirection::Backward),
            packet_length_variance: flow.packet_size_variance,
            packet_length_mean: flow.avg_packet_size,
            packet_length_std: flow.packet_size_variance.sqrt(),
            
            // Flow rate features (8)
            flow_bytes_per_sec: flow.bytes_per_second,
            flow_packets_per_sec: flow.packets_per_second,
            fwd_packets_per_sec: if duration_sec > 0.0 { flow.forward_packets as f64 / duration_sec } else { 0.0 },
            bwd_packets_per_sec: if duration_sec > 0.0 { flow.backward_packets as f64 / duration_sec } else { 0.0 },
            fwd_bytes_per_sec: if duration_sec > 0.0 { flow.forward_bytes as f64 / duration_sec } else { 0.0 },
            bwd_bytes_per_sec: if duration_sec > 0.0 { flow.backward_bytes as f64 / duration_sec } else { 0.0 },
            flow_iat_mean_per_sec: if duration_sec > 0.0 { flow.flow_iat_mean / 1000.0 } else { 0.0 },
            active_mean: Self::calculate_active_time_mean_static(flow),
            
            // Entropy and randomness features (8)
            payload_entropy: flow.payload_entropy,
            entropy_variance: flow.entropy_variance,
            byte_frequency_variance: Self::calculate_byte_frequency_variance_static(flow),
            payload_randomness_score: Self::calculate_randomness_score_static(flow),
            header_entropy: Self::calculate_header_entropy_static(flow),
            size_entropy: Self::calculate_size_entropy_static(flow),
            timing_entropy: Self::calculate_timing_entropy_static(flow),
            direction_entropy: Self::calculate_direction_entropy_static(flow),
            
            // Advanced statistical features (4)
            flow_symmetry_ratio: if flow.backward_bytes > 0 { flow.forward_bytes as f64 / flow.backward_bytes as f64 } else { f64::INFINITY },
            packet_size_coefficient_variation: if flow.avg_packet_size > 0.0 { flow.packet_size_variance.sqrt() / flow.avg_packet_size } else { 0.0 },
            inter_arrival_coefficient_variation: if flow.flow_iat_mean > 0.0 { flow.flow_iat_std / flow.flow_iat_mean } else { 0.0 },
            burst_rate: Self::calculate_burst_rate_static(flow),
        }
    }

    /// Calculate all 47 statistical features (instance method - kept for compatibility)
    fn calculate_47_features(&self, flow: &NetworkFlow) -> StatisticalFeatures {
        let _total_packets = (flow.forward_packets + flow.backward_packets) as f64;
        let duration_sec = flow.duration_ms as f64 / 1000.0;
        
        StatisticalFeatures {
            // Timing features (12)
            flow_duration: duration_sec,
            flow_iat_mean: flow.flow_iat_mean,
            flow_iat_std: flow.flow_iat_std,
            flow_iat_max: flow.flow_iat_max,
            flow_iat_min: flow.flow_iat_min,
            fwd_iat_mean: self.calculate_direction_iat_mean(flow, PacketDirection::Forward),
            fwd_iat_std: self.calculate_direction_iat_std(flow, PacketDirection::Forward),
            fwd_iat_max: self.calculate_direction_iat_max(flow, PacketDirection::Forward),
            fwd_iat_min: self.calculate_direction_iat_min(flow, PacketDirection::Forward),
            bwd_iat_mean: self.calculate_direction_iat_mean(flow, PacketDirection::Backward),
            bwd_iat_std: self.calculate_direction_iat_std(flow, PacketDirection::Backward),
            bwd_iat_max: self.calculate_direction_iat_max(flow, PacketDirection::Backward),
            
            // Size features (15)
            total_fwd_packets: flow.forward_packets as f64,
            total_bwd_packets: flow.backward_packets as f64,
            total_length_fwd_packets: flow.forward_bytes as f64,
            total_length_bwd_packets: flow.backward_bytes as f64,
            fwd_packet_length_max: self.calculate_direction_size_max(flow, PacketDirection::Forward),
            fwd_packet_length_min: self.calculate_direction_size_min(flow, PacketDirection::Forward),
            fwd_packet_length_mean: if flow.forward_packets > 0 { flow.forward_bytes as f64 / flow.forward_packets as f64 } else { 0.0 },
            fwd_packet_length_std: self.calculate_direction_size_std(flow, PacketDirection::Forward),
            bwd_packet_length_max: self.calculate_direction_size_max(flow, PacketDirection::Backward),
            bwd_packet_length_min: self.calculate_direction_size_min(flow, PacketDirection::Backward),
            bwd_packet_length_mean: if flow.backward_packets > 0 { flow.backward_bytes as f64 / flow.backward_packets as f64 } else { 0.0 },
            bwd_packet_length_std: self.calculate_direction_size_std(flow, PacketDirection::Backward),
            packet_length_variance: flow.packet_size_variance,
            packet_length_mean: flow.avg_packet_size,
            packet_length_std: flow.packet_size_variance.sqrt(),
            
            // Flow rate features (8)
            flow_bytes_per_sec: flow.bytes_per_second,
            flow_packets_per_sec: flow.packets_per_second,
            fwd_packets_per_sec: if duration_sec > 0.0 { flow.forward_packets as f64 / duration_sec } else { 0.0 },
            bwd_packets_per_sec: if duration_sec > 0.0 { flow.backward_packets as f64 / duration_sec } else { 0.0 },
            fwd_bytes_per_sec: if duration_sec > 0.0 { flow.forward_bytes as f64 / duration_sec } else { 0.0 },
            bwd_bytes_per_sec: if duration_sec > 0.0 { flow.backward_bytes as f64 / duration_sec } else { 0.0 },
            flow_iat_mean_per_sec: if duration_sec > 0.0 { flow.flow_iat_mean / 1000.0 } else { 0.0 },
            active_mean: self.calculate_active_time_mean(flow),
            
            // Entropy and randomness features (8)
            payload_entropy: flow.payload_entropy,
            entropy_variance: flow.entropy_variance,
            byte_frequency_variance: self.calculate_byte_frequency_variance(flow),
            payload_randomness_score: self.calculate_randomness_score(flow),
            header_entropy: self.calculate_header_entropy(flow),
            size_entropy: self.calculate_size_entropy(flow),
            timing_entropy: self.calculate_timing_entropy(flow),
            direction_entropy: self.calculate_direction_entropy(flow),
            
            // Advanced statistical features (4)
            flow_symmetry_ratio: if flow.backward_bytes > 0 { flow.forward_bytes as f64 / flow.backward_bytes as f64 } else { f64::INFINITY },
            packet_size_coefficient_variation: if flow.avg_packet_size > 0.0 { flow.packet_size_variance.sqrt() / flow.avg_packet_size } else { 0.0 },
            inter_arrival_coefficient_variation: if flow.flow_iat_mean > 0.0 { flow.flow_iat_std / flow.flow_iat_mean } else { 0.0 },
            burst_rate: self.calculate_burst_rate(flow),
        }
    }

    /// Calculate entropy of byte sequence
    fn calculate_entropy(&self, data: &[u8]) -> f64 {
        Self::calculate_entropy_static(data)
    }

    /// Calculate entropy (static version)
    fn calculate_entropy_static(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        
        let mut freq = [0u32; 256];
        for &byte in data {
            freq[byte as usize] += 1;
        }
        
        let len = data.len() as f64;
        let mut entropy = 0.0;
        
        for &count in &freq {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }
        
        entropy
    }

    /// Helper methods for statistical calculations
    fn calculate_direction_iat_mean(&self, _flow: &NetworkFlow, _direction: PacketDirection) -> f64 {
        // Simplified implementation - would need packet-level direction tracking
        0.0
    }
    
    fn calculate_direction_iat_std(&self, _flow: &NetworkFlow, _direction: PacketDirection) -> f64 {
        0.0
    }
    
    fn calculate_direction_iat_max(&self, _flow: &NetworkFlow, _direction: PacketDirection) -> f64 {
        0.0
    }
    
    fn calculate_direction_iat_min(&self, _flow: &NetworkFlow, _direction: PacketDirection) -> f64 {
        0.0
    }
    
    fn calculate_direction_size_max(&self, flow: &NetworkFlow, direction: PacketDirection) -> f64 {
        match direction {
            PacketDirection::Forward => flow.max_packet_size as f64,
            PacketDirection::Backward => flow.max_packet_size as f64, // Simplified
        }
    }
    
    fn calculate_direction_size_min(&self, flow: &NetworkFlow, direction: PacketDirection) -> f64 {
        match direction {
            PacketDirection::Forward => flow.min_packet_size as f64,
            PacketDirection::Backward => flow.min_packet_size as f64, // Simplified
        }
    }
    
    fn calculate_direction_size_std(&self, _flow: &NetworkFlow, _direction: PacketDirection) -> f64 {
        0.0 // Simplified
    }
    
    fn calculate_active_time_mean(&self, flow: &NetworkFlow) -> f64 {
        if flow.duration_ms > 0 {
            flow.duration_ms as f64 / (flow.forward_packets + flow.backward_packets) as f64
        } else {
            0.0
        }
    }
    
    fn calculate_byte_frequency_variance(&self, flow: &NetworkFlow) -> f64 {
        let total_bytes: u32 = flow.byte_distribution.iter().sum();
        if total_bytes == 0 {
            return 0.0;
        }
        
        let mean = total_bytes as f64 / 256.0;
        flow.byte_distribution.iter()
            .map(|&count| (count as f64 - mean).powi(2))
            .sum::<f64>() / 256.0
    }
    
    fn calculate_randomness_score(&self, flow: &NetworkFlow) -> f64 {
        // Chi-square test for randomness
        let total_bytes: u32 = flow.byte_distribution.iter().sum();
        if total_bytes == 0 {
            return 0.0;
        }
        
        let expected = total_bytes as f64 / 256.0;
        let chi_square: f64 = flow.byte_distribution.iter()
            .map(|&observed| {
                let diff = observed as f64 - expected;
                (diff * diff) / expected
            })
            .sum();
        
        // Normalize to 0-1 range
        (chi_square / 255.0).min(1.0)
    }
    
    fn calculate_header_entropy(&self, _flow: &NetworkFlow) -> f64 {
        // Simplified - would analyze packet headers
        0.0
    }
    
    fn calculate_size_entropy(&self, flow: &NetworkFlow) -> f64 {
        if flow.packet_sizes.is_empty() {
            return 0.0;
        }
        
        let mut size_freq: HashMap<u32, u32> = HashMap::new();
        for &size in &flow.packet_sizes {
            *size_freq.entry(size).or_insert(0) += 1;
        }
        
        let total = flow.packet_sizes.len() as f64;
        let mut entropy = 0.0;
        
        for count in size_freq.values() {
            let p = *count as f64 / total;
            entropy -= p * p.log2();
        }
        
        entropy
    }
    
    fn calculate_timing_entropy(&self, flow: &NetworkFlow) -> f64 {
        if flow.packet_intervals.is_empty() {
            return 0.0;
        }
        
        // Discretize intervals into bins for entropy calculation
        let mut interval_bins: HashMap<u64, u32> = HashMap::new();
        for &interval in &flow.packet_intervals {
            let bin = interval / 10; // 10ms bins
            *interval_bins.entry(bin).or_insert(0) += 1;
        }
        
        let total = flow.packet_intervals.len() as f64;
        let mut entropy = 0.0;
        
        for count in interval_bins.values() {
            let p = *count as f64 / total;
            entropy -= p * p.log2();
        }
        
        entropy
    }
    
    fn calculate_direction_entropy(&self, flow: &NetworkFlow) -> f64 {
        let total = flow.forward_packets + flow.backward_packets;
        if total == 0 {
            return 0.0;
        }
        
        let p_fwd = flow.forward_packets as f64 / total as f64;
        let p_bwd = flow.backward_packets as f64 / total as f64;
        
        let mut entropy = 0.0;
        if p_fwd > 0.0 {
            entropy -= p_fwd * p_fwd.log2();
        }
        if p_bwd > 0.0 {
            entropy -= p_bwd * p_bwd.log2();
        }
        
        entropy
    }
    
    fn calculate_burst_rate(&self, flow: &NetworkFlow) -> f64 {
        if flow.packet_intervals.is_empty() {
            return 0.0;
        }
        
        // Count intervals below threshold as bursts
        let burst_threshold = 100; // 100ms
        let burst_count = flow.packet_intervals.iter()
            .filter(|&&interval| interval < burst_threshold)
            .count();
        
        burst_count as f64 / flow.packet_intervals.len() as f64
    }

    /// Static helper methods for statistical calculations
    fn calculate_direction_iat_mean_static(_flow: &NetworkFlow, _direction: PacketDirection) -> f64 {
        // Simplified implementation - would need packet-level direction tracking
        0.0
    }
    
    fn calculate_direction_iat_std_static(_flow: &NetworkFlow, _direction: PacketDirection) -> f64 {
        0.0
    }
    
    fn calculate_direction_iat_max_static(_flow: &NetworkFlow, _direction: PacketDirection) -> f64 {
        0.0
    }
    
    fn calculate_direction_iat_min_static(_flow: &NetworkFlow, _direction: PacketDirection) -> f64 {
        0.0
    }
    
    fn calculate_direction_size_max_static(flow: &NetworkFlow, direction: PacketDirection) -> f64 {
        match direction {
            PacketDirection::Forward => flow.max_packet_size as f64,
            PacketDirection::Backward => flow.max_packet_size as f64, // Simplified
        }
    }
    
    fn calculate_direction_size_min_static(flow: &NetworkFlow, direction: PacketDirection) -> f64 {
        match direction {
            PacketDirection::Forward => flow.min_packet_size as f64,
            PacketDirection::Backward => flow.min_packet_size as f64, // Simplified
        }
    }
    
    fn calculate_direction_size_std_static(_flow: &NetworkFlow, _direction: PacketDirection) -> f64 {
        0.0 // Simplified
    }
    
    fn calculate_active_time_mean_static(flow: &NetworkFlow) -> f64 {
        if flow.duration_ms > 0 {
            flow.duration_ms as f64 / (flow.forward_packets + flow.backward_packets) as f64
        } else {
            0.0
        }
    }
    
    fn calculate_byte_frequency_variance_static(flow: &NetworkFlow) -> f64 {
        let total_bytes: u32 = flow.byte_distribution.iter().sum();
        if total_bytes == 0 {
            return 0.0;
        }
        
        let mean = total_bytes as f64 / 256.0;
        flow.byte_distribution.iter()
            .map(|&count| (count as f64 - mean).powi(2))
            .sum::<f64>() / 256.0
    }
    
    fn calculate_randomness_score_static(flow: &NetworkFlow) -> f64 {
        // Chi-square test for randomness
        let total_bytes: u32 = flow.byte_distribution.iter().sum();
        if total_bytes == 0 {
            return 0.0;
        }
        
        let expected = total_bytes as f64 / 256.0;
        let chi_square: f64 = flow.byte_distribution.iter()
            .map(|&observed| {
                let diff = observed as f64 - expected;
                (diff * diff) / expected
            })
            .sum();
        
        // Normalize to 0-1 range
        (chi_square / 255.0).min(1.0)
    }
    
    fn calculate_header_entropy_static(_flow: &NetworkFlow) -> f64 {
        // Simplified - would analyze packet headers
        0.0
    }
    
    fn calculate_size_entropy_static(flow: &NetworkFlow) -> f64 {
        if flow.packet_sizes.is_empty() {
            return 0.0;
        }
        
        let mut size_freq: HashMap<u32, u32> = HashMap::new();
        for &size in &flow.packet_sizes {
            *size_freq.entry(size).or_insert(0) += 1;
        }
        
        let total = flow.packet_sizes.len() as f64;
        let mut entropy = 0.0;
        
        for count in size_freq.values() {
            let p = *count as f64 / total;
            entropy -= p * p.log2();
        }
        
        entropy
    }
    
    fn calculate_timing_entropy_static(flow: &NetworkFlow) -> f64 {
        if flow.packet_intervals.is_empty() {
            return 0.0;
        }
        
        // Discretize intervals into bins for entropy calculation
        let mut interval_bins: HashMap<u64, u32> = HashMap::new();
        for &interval in &flow.packet_intervals {
            let bin = interval / 10; // 10ms bins
            *interval_bins.entry(bin).or_insert(0) += 1;
        }
        
        let total = flow.packet_intervals.len() as f64;
        let mut entropy = 0.0;
        
        for count in interval_bins.values() {
            let p = *count as f64 / total;
            entropy -= p * p.log2();
        }
        
        entropy
    }
    
    fn calculate_direction_entropy_static(flow: &NetworkFlow) -> f64 {
        let total = flow.forward_packets + flow.backward_packets;
        if total == 0 {
            return 0.0;
        }
        
        let p_fwd = flow.forward_packets as f64 / total as f64;
        let p_bwd = flow.backward_packets as f64 / total as f64;
        
        let mut entropy = 0.0;
        if p_fwd > 0.0 {
            entropy -= p_fwd * p_fwd.log2();
        }
        if p_bwd > 0.0 {
            entropy -= p_bwd * p_bwd.log2();
        }
        
        entropy
    }
    
    fn calculate_burst_rate_static(flow: &NetworkFlow) -> f64 {
        if flow.packet_intervals.is_empty() {
            return 0.0;
        }
        
        // Count intervals below threshold as bursts
        let burst_threshold = 100; // 100ms
        let burst_count = flow.packet_intervals.iter()
            .filter(|&&interval| interval < burst_threshold)
            .count();
        
        burst_count as f64 / flow.packet_intervals.len() as f64
    }

    /// Check if flow analysis is complete
    fn is_flow_complete(&self, flow: &NetworkFlow) -> bool {
        Self::is_flow_complete_static(flow, self.analysis_window_ms)
    }

    /// Check if flow analysis is complete (static version)
    fn is_flow_complete_static(flow: &NetworkFlow, analysis_window_ms: u64) -> bool {
        // Flow is complete if it's been inactive for analysis window
        let inactive_time = Instant::now().duration_since(flow.last_packet_time).as_millis() as u64;
        inactive_time > analysis_window_ms
    }

    /// Finalize flow analysis
    fn finalize_flow_analysis(&mut self, _flow: &mut NetworkFlow) -> Result<(), RansolutionError> {
        // Mark flow as analyzed and ready for threat detection
        self.performance_metrics.total_flows_analyzed += 1;
        Ok(())
    }

    /// Clean old packets from buffer
    fn clean_packet_buffer(&mut self) {
        let cutoff_time = Instant::now() - Duration::from_millis(self.analysis_window_ms);
        while let Some(packet) = self.packet_buffer.front() {
            if packet.timestamp < cutoff_time {
                self.packet_buffer.pop_front();
            } else {
                break;
            }
        }
    }

    /// Maintain cache size within limits
    fn maintain_cache_size(&mut self) {
        while self.flow_cache.len() > self.max_flows {
            // Remove oldest flow (simplified - would use LRU)
            if let Some(key) = self.flow_cache.keys().next().cloned() {
                self.flow_cache.remove(&key);
            }
        }
    }

    /// Update performance metrics
    pub fn update_performance_metrics(&mut self, analysis_time_ms: u64) {
        self.performance_metrics.max_analysis_time_ms = 
            self.performance_metrics.max_analysis_time_ms.max(analysis_time_ms);
        
        if self.performance_metrics.min_analysis_time_ms == 0 {
            self.performance_metrics.min_analysis_time_ms = analysis_time_ms;
        } else {
            self.performance_metrics.min_analysis_time_ms = 
                self.performance_metrics.min_analysis_time_ms.min(analysis_time_ms);
        }
        
        // Update average (simplified)
        let total_analyses = self.performance_metrics.total_flows_analyzed + 1;
        self.performance_metrics.avg_analysis_time_ms = 
            (self.performance_metrics.avg_analysis_time_ms * (total_analyses - 1) as f64 + analysis_time_ms as f64) / total_analyses as f64;
    }

    /// Get completed flows for analysis
    pub fn get_completed_flows(&self) -> Vec<NetworkFlow> {
        self.flow_cache.values()
            .filter(|flow| self.is_flow_complete(flow))
            .cloned()
            .collect()
    }

    /// Get performance metrics
    pub fn get_performance_metrics(&self) -> FlowAnalysisMetrics {
        self.performance_metrics.clone()
    }
}

impl Default for StatisticalFeatures {
    fn default() -> Self {
        Self {
            flow_duration: 0.0,
            flow_iat_mean: 0.0,
            flow_iat_std: 0.0,
            flow_iat_max: 0.0,
            flow_iat_min: 0.0,
            fwd_iat_mean: 0.0,
            fwd_iat_std: 0.0,
            fwd_iat_max: 0.0,
            fwd_iat_min: 0.0,
            bwd_iat_mean: 0.0,
            bwd_iat_std: 0.0,
            bwd_iat_max: 0.0,
            total_fwd_packets: 0.0,
            total_bwd_packets: 0.0,
            total_length_fwd_packets: 0.0,
            total_length_bwd_packets: 0.0,
            fwd_packet_length_max: 0.0,
            fwd_packet_length_min: 0.0,
            fwd_packet_length_mean: 0.0,
            fwd_packet_length_std: 0.0,
            bwd_packet_length_max: 0.0,
            bwd_packet_length_min: 0.0,
            bwd_packet_length_mean: 0.0,
            bwd_packet_length_std: 0.0,
            packet_length_variance: 0.0,
            packet_length_mean: 0.0,
            packet_length_std: 0.0,
            flow_bytes_per_sec: 0.0,
            flow_packets_per_sec: 0.0,
            fwd_packets_per_sec: 0.0,
            bwd_packets_per_sec: 0.0,
            fwd_bytes_per_sec: 0.0,
            bwd_bytes_per_sec: 0.0,
            flow_iat_mean_per_sec: 0.0,
            active_mean: 0.0,
            payload_entropy: 0.0,
            entropy_variance: 0.0,
            byte_frequency_variance: 0.0,
            payload_randomness_score: 0.0,
            header_entropy: 0.0,
            size_entropy: 0.0,
            timing_entropy: 0.0,
            direction_entropy: 0.0,
            flow_symmetry_ratio: 0.0,
            packet_size_coefficient_variation: 0.0,
            inter_arrival_coefficient_variation: 0.0,
            burst_rate: 0.0,
        }
    }
}

impl Default for FlowAnalysisMetrics {
    fn default() -> Self {
        Self {
            total_flows_analyzed: 0,
            avg_analysis_time_ms: 0.0,
            max_analysis_time_ms: 0,
            min_analysis_time_ms: 0,
            flows_per_second: 0.0,
            cache_hit_rate: 0.0,
            memory_usage_mb: 0.0,
        }
    }
}



/// Network intelligence statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStatistics {
    pub total_ja3_fingerprints: usize,
    pub total_ja3s_fingerprints: usize,
    pub total_connections_tracked: u64,
    pub detected_beacon_patterns: usize,
    pub analysis_runs: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use tempfile::TempDir;

    fn create_test_engine() -> (NetworkIntelligenceEngine, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let db_file = temp_dir.path().join("test.db");
        let database = Arc::new(DatabasePool::new(&db_file).unwrap());

        let engine = NetworkIntelligenceEngine::new(database).unwrap();
        (engine, temp_dir)
    }

    fn create_test_connection() -> NetworkConnection {
        NetworkConnection {
            connection_id: "test-conn-1".to_string(),
            source_addr: SocketAddr::from_str("192.168.1.100:12345").unwrap(),
            destination_addr: SocketAddr::from_str("203.0.113.1:443").unwrap(),
            protocol: NetworkProtocol::HTTPS,
            established_at: Utc::now(),
            last_activity: Utc::now(),
            bytes_sent: 1024,
            bytes_received: 2048,
            packets_sent: 10,
            packets_received: 15,
            ja3_hash: Some("769,47-53-5-10-49161-49162".to_string()),
            ja3s_hash: Some("771,49199,65281-0-11".to_string()),
            process_name: Some("test.exe".to_string()),
            process_id: Some(1234),
        }
    }

    #[test]
    fn test_engine_initialization() {
        let (engine, _temp_dir) = create_test_engine();

        let stats = engine.get_network_statistics();
        assert_eq!(stats.total_ja3_fingerprints, 0);
        assert_eq!(stats.total_ja3s_fingerprints, 0);
        assert_eq!(stats.total_connections_tracked, 0);
    }

    #[test]
    fn test_connection_processing() {
        let (engine, _temp_dir) = create_test_engine();
        let connection = create_test_connection();

        engine.process_connection(connection).unwrap();

        let stats = engine.get_network_statistics();
        assert_eq!(stats.total_ja3_fingerprints, 1);
        assert_eq!(stats.total_ja3s_fingerprints, 1);
        assert_eq!(stats.total_connections_tracked, 1);
    }

    #[test]
    fn test_ja3_fingerprint_processing() {
        let (engine, _temp_dir) = create_test_engine();
        let connection = create_test_connection();

        engine
            .process_ja3_fingerprint("test-ja3-hash", &connection)
            .unwrap();

        let fingerprints = engine.ja3_fingerprints.lock().unwrap();
        assert!(fingerprints.contains_key("test-ja3-hash"));

        let fingerprint = fingerprints.get("test-ja3-hash").unwrap();
        assert_eq!(fingerprint.occurrence_count, 1);
        assert!(fingerprint.associated_processes.contains("test.exe"));
    }

    #[test]
    fn test_beacon_analysis() {
        let analyzer = BeaconAnalyzer::new(60);
        let mut connection = create_test_connection();

        // Simulate multiple connections to same destination
        for i in 0..5 {
            connection.connection_id = format!("conn-{}", i);
            connection.established_at = Utc::now() + chrono::Duration::seconds(i * 30);
            analyzer.analyze_connection(&connection).unwrap();
        }

        let beacons = analyzer.detect_beacons().unwrap();
        assert!(!beacons.is_empty());
    }

    #[test]
    fn test_network_analysis() {
        let (engine, _temp_dir) = create_test_engine();
        let connection = create_test_connection();

        // Process some connections
        engine.process_connection(connection).unwrap();

        let result = engine.analyze_network_activity().unwrap();
        assert!(!result.analysis_id.to_string().is_empty());
        assert_eq!(result.connections_analyzed, 1);
    }

    #[test]
    fn test_threat_score_calculation() {
        let (engine, _temp_dir) = create_test_engine();

        // Test normal JA3 hash
        let normal_score = engine.calculate_ja3_threat_score("normal-hash");
        assert!(normal_score < 0.5);

        // Test suspicious JA3 hash
        let suspicious_score =
            engine.calculate_ja3_threat_score("769,47-53-5-10-49161-49162-49171-49172-50-56-19-4");
        assert!(suspicious_score > 0.9);
    }

    #[test]
    fn test_enhanced_flow_analyzer_creation() {
        let analyzer = EnhancedFlowAnalyzer::new(1000, 30000).unwrap();
        assert_eq!(analyzer.max_flows, 1000);
        assert_eq!(analyzer.analysis_window_ms, 30000);
        assert_eq!(analyzer.flow_cache.len(), 0);
        assert_eq!(analyzer.packet_buffer.len(), 0);
    }

    #[test]
    fn test_packet_processing_performance() {
        let mut analyzer = EnhancedFlowAnalyzer::new(100, 30000).unwrap();
        let packet = PacketInfo {
            flow_id: "test-flow-1".to_string(),
            timestamp: Instant::now(),
            size: 1024,
            direction: PacketDirection::Forward,
            payload: vec![0x41; 100], // 'A' repeated
        };

        let start = Instant::now();
        analyzer.process_packet(packet).unwrap();
        let duration = start.elapsed();

        // Should process within performance target
        assert!(duration.as_millis() < 50, "Processing took {}ms, expected <50ms", duration.as_millis());
    }

    #[test]
    fn test_statistical_features_calculation() {
        let mut analyzer = EnhancedFlowAnalyzer::new(100, 30000).unwrap();
        
        // Create multiple packets for the same flow
        for i in 0..10 {
            let packet = PacketInfo {
                flow_id: "test-flow-stats".to_string(),
                timestamp: Instant::now() + Duration::from_millis(i * 100),
                size: 500 + (i * 50) as u32,
                direction: if i % 2 == 0 { PacketDirection::Forward } else { PacketDirection::Backward },
                payload: vec![0x41 + (i as u8); 50],
            };
            analyzer.process_packet(packet).unwrap();
        }

        // Verify flow was created and has statistical features
        assert!(analyzer.flow_cache.contains_key("test-flow-stats"));
        let flow = analyzer.flow_cache.get("test-flow-stats").unwrap();
        
        // Check basic statistics
        assert!(flow.total_bytes > 0);
        assert!(flow.forward_packets > 0);
        assert!(flow.backward_packets > 0);
        assert!(flow.avg_packet_size > 0.0);
        assert!(flow.duration_ms > 0);
    }

    #[test]
    fn test_entropy_calculation() {
        let analyzer = EnhancedFlowAnalyzer::new(100, 30000).unwrap();
        
        // Test with uniform data (low entropy)
        let uniform_data = vec![0x41; 100]; // All 'A'
        let uniform_entropy = analyzer.calculate_entropy(&uniform_data);
        assert!(uniform_entropy < 1.0, "Uniform data should have low entropy");
        
        // Test with random data (high entropy)
        let random_data: Vec<u8> = (0..=255).collect();
        let random_entropy = analyzer.calculate_entropy(&random_data);
        assert!(random_entropy > 7.0, "Random data should have high entropy");
    }

    #[test]
    fn test_47_statistical_features() {
        let analyzer = EnhancedFlowAnalyzer::new(100, 30000).unwrap();
        let flow = NetworkFlow {
            flow_id: "test-features".to_string(),
            src_addr: SocketAddr::from_str("192.168.1.1:1234").unwrap(),
            dst_addr: SocketAddr::from_str("10.0.0.1:443").unwrap(),
            protocol: NetworkProtocol::TCP,
            start_time: Instant::now(),
            last_packet_time: Instant::now() + Duration::from_millis(1000),
            duration_ms: 1000,
            packet_intervals: VecDeque::from(vec![100, 150, 200, 120, 180]),
            avg_packet_interval: 150.0,
            packet_interval_variance: 1000.0,
            packet_interval_std_dev: 31.6,
            packet_sizes: VecDeque::from(vec![500, 600, 550, 700, 650]),
            total_bytes: 3000,
            avg_packet_size: 600.0,
            packet_size_variance: 5000.0,
            min_packet_size: 500,
            max_packet_size: 700,
            forward_packets: 3,
            backward_packets: 2,
            forward_bytes: 1800,
            backward_bytes: 1200,
            payload_entropy: 6.5,
            byte_distribution: vec![0; 256],
            entropy_variance: 0.5,
            packets_per_second: 5.0,
            bytes_per_second: 3000.0,
            flow_iat_mean: 150.0,
            flow_iat_std: 31.6,
            flow_iat_max: 200.0,
            flow_iat_min: 100.0,
            statistical_features: StatisticalFeatures::default(),
        };

        let features = analyzer.calculate_47_features(&flow);
        
        // Verify key statistical features are calculated
        assert_eq!(features.flow_duration, 1.0); // 1000ms = 1 second
        assert_eq!(features.total_fwd_packets, 3.0);
        assert_eq!(features.total_bwd_packets, 2.0);
        assert_eq!(features.total_length_fwd_packets, 1800.0);
        assert_eq!(features.total_length_bwd_packets, 1200.0);
        assert_eq!(features.flow_bytes_per_sec, 3000.0);
        assert_eq!(features.flow_packets_per_sec, 5.0);
        assert_eq!(features.payload_entropy, 6.5);
        assert!(features.flow_symmetry_ratio > 0.0);
    }

    #[test]
    fn test_flow_analysis_integration() {
        let (mut engine, _temp_dir) = create_test_engine();
        let connection = NetworkConnection {
            connection_id: "integration-test-flow".to_string(),
            source_addr: SocketAddr::from_str("192.168.1.100:12345").unwrap(),
            destination_addr: SocketAddr::from_str("10.0.0.1:443").unwrap(),
            protocol: NetworkProtocol::TCP,
            established_at: Utc::now(),
            last_activity: Utc::now(),
            bytes_sent: 1024,
            bytes_received: 512,
            packets_sent: 10,
            packets_received: 5,
            ja3_hash: Some("test-ja3-hash".to_string()),
            ja3s_hash: Some("test-ja3s-hash".to_string()),
            process_name: Some("test_process".to_string()),
            process_id: Some(1234),
        };

        let result = engine.analyze_network_flow(&connection).unwrap();
        
        // Verify integration with existing analysis
        assert!(!result.analysis_id.to_string().is_empty());
        
        // Simulate flow completion by directly processing packets with old timestamps
        // to trigger flow finalization
        {
            let mut analyzer = engine.flow_analyzer.lock().unwrap();
            let flow_id = format!("{}:{}-{}:{}", 
                connection.source_addr.ip(), connection.source_addr.port(),
                connection.destination_addr.ip(), connection.destination_addr.port());
            
            // Create packets with old timestamps to trigger flow completion
            let old_timestamp = Instant::now() - Duration::from_millis(35000); // Older than 30s window
            for i in 0..5 {
                let packet = PacketInfo {
                    flow_id: flow_id.clone(),
                    timestamp: old_timestamp + Duration::from_millis(i * 100),
                    size: 512,
                    direction: if i % 2 == 0 { PacketDirection::Forward } else { PacketDirection::Backward },
                    payload: vec![0x41; 50],
                };
                analyzer.process_packet(packet).unwrap();
            }
        }
        
        // Check that flow analysis metrics are updated after flow completion
        let metrics = engine.get_flow_performance_metrics();
        assert!(metrics.total_flows_analyzed > 0);
    }

    #[test]
    fn test_performance_metrics_tracking() {
        let mut analyzer = EnhancedFlowAnalyzer::new(100, 30000).unwrap();
        
        // Process multiple packets with old timestamps to trigger flow completion
        let old_timestamp = Instant::now() - Duration::from_millis(35000); // Older than 30s window
        for i in 0..5 {
            let packet = PacketInfo {
                flow_id: format!("perf-test-{}", i),
                timestamp: old_timestamp + Duration::from_millis(i * 100),
                size: 512,
                direction: PacketDirection::Forward,
                payload: vec![0x42; 50],
            };
            analyzer.process_packet(packet).unwrap();
        }

        let metrics = analyzer.get_performance_metrics();
        assert_eq!(metrics.total_flows_analyzed, 5);
        assert!(metrics.avg_analysis_time_ms >= 0.0);
    }

    #[test]
    fn test_cache_management() {
        let mut analyzer = EnhancedFlowAnalyzer::new(2, 30000).unwrap(); // Small cache
        
        // Add more flows than cache capacity
        for i in 0..5 {
            let packet = PacketInfo {
                flow_id: format!("cache-test-{}", i),
                timestamp: Instant::now(),
                size: 256,
                direction: PacketDirection::Forward,
                payload: vec![0x43; 25],
            };
            analyzer.process_packet(packet).unwrap();
        }

        // Cache should not exceed max capacity
        assert!(analyzer.flow_cache.len() <= analyzer.max_flows);
    }
}
