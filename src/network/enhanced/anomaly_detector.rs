//! Network anomaly detection engine
//! Provides statistical and ML-based anomaly detection for network traffic

use super::*;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;
use tracing::info;

/// Anomaly detection methods
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DetectionMethod {
    /// Statistical threshold-based detection
    Statistical,
    /// Time-series based detection
    TimeSeries,
    /// Behavioral baseline deviation
    Behavioral,
    /// Machine learning based
    MachineLearning,
    /// Rule-based detection
    RuleBased,
}

/// Anomaly detection configuration
#[derive(Debug, Clone)]
pub struct AnomalyDetectionConfig {
    /// Detection methods to use
    pub methods: Vec<DetectionMethod>,
    /// Statistical thresholds
    pub statistical_thresholds: HashMap<String, f64>,
    /// Time window for analysis
    pub time_window: Duration,
    /// Minimum confidence for anomaly reporting
    pub min_confidence: f32,
    /// Maximum anomalies to track
    pub max_anomalies: usize,
    /// Baseline learning period
    pub baseline_period: Duration,
}

/// Network baseline metrics
#[derive(Debug, Clone)]
pub struct NetworkBaseline {
    /// Baseline timestamp
    pub timestamp: SystemTime,
    /// Average packet rate
    pub avg_packet_rate: f64,
    /// Average byte rate
    pub avg_byte_rate: f64,
    /// Protocol distribution
    pub protocol_distribution: HashMap<String, f64>,
    /// Port usage patterns
    pub port_patterns: HashMap<u16, f64>,
    /// Connection patterns
    pub connection_patterns: HashMap<String, f64>,
    /// Payload entropy distribution
    pub entropy_distribution: Vec<f64>,
    /// Inter-arrival time patterns
    pub inter_arrival_patterns: Vec<Duration>,
}

/// Anomaly detection result
#[derive(Debug, Clone)]
pub struct AnomalyDetectionResult {
    /// Detected anomalies
    pub anomalies: Vec<NetworkAnomaly>,
    /// Detection confidence
    pub overall_confidence: f32,
    /// Analysis timestamp
    pub timestamp: SystemTime,
    /// Detection method used
    pub detection_method: DetectionMethod,
    /// Baseline comparison
    pub baseline_deviation: HashMap<String, f64>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Time series data point
#[derive(Debug, Clone)]
pub struct TimeSeriesPoint {
    /// Timestamp
    pub timestamp: SystemTime,
    /// Metric value
    pub value: f64,
    /// Associated metadata
    pub metadata: HashMap<String, String>,
}

/// Anomaly detector engine
pub struct AnomalyDetector {
    /// Detection configuration
    config: AnomalyDetectionConfig,
    /// Network baseline
    baseline: Arc<RwLock<Option<NetworkBaseline>>>,
    /// Time series data
    time_series: Arc<RwLock<HashMap<String, VecDeque<TimeSeriesPoint>>>>,
    /// Detected anomalies
    anomalies: Arc<RwLock<VecDeque<NetworkAnomaly>>>,
    /// Detection statistics
    stats: Arc<RwLock<AnomalyDetectionStats>>,
    /// Behavioral patterns
    behavioral_patterns: Arc<RwLock<HashMap<String, Vec<f64>>>>,
}

/// Anomaly detection statistics
#[derive(Debug, Clone, Default)]
pub struct AnomalyDetectionStats {
    /// Total detections performed
    pub total_detections: u64,
    /// Total anomalies detected
    pub total_anomalies: u64,
    /// False positive rate (if known)
    pub false_positive_rate: Option<f64>,
    /// Detection method effectiveness
    pub method_effectiveness: HashMap<DetectionMethod, f64>,
    /// Average detection time
    pub avg_detection_time: Duration,
    /// Anomaly type distribution
    pub anomaly_distribution: HashMap<AnomalyType, u64>,
}

impl AnomalyDetector {
    /// Create new anomaly detector
    pub fn new(config: AnomalyDetectionConfig) -> Self {
        Self {
            config,
            baseline: Arc::new(RwLock::new(None)),
            time_series: Arc::new(RwLock::new(HashMap::new())),
            anomalies: Arc::new(RwLock::new(VecDeque::new())),
            stats: Arc::new(RwLock::new(AnomalyDetectionStats::default())),
            behavioral_patterns: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Detect anomalies in network traffic
    pub async fn detect_anomalies(&self, flows: &[NetworkFlow], packets: &[PacketInfo]) -> AnomalyDetectionResult {
        let start_time = SystemTime::now();
        let mut detected_anomalies = Vec::new();
        let mut baseline_deviation = HashMap::new();
        let mut overall_confidence = 0.0;
        let mut detection_method = DetectionMethod::Statistical;

        // Update time series data
        self.update_time_series(flows, packets).await;

        // Run detection methods
        for method in &self.config.methods {
            let method_result = match method {
                DetectionMethod::Statistical => self.statistical_detection(flows, packets).await,
                DetectionMethod::TimeSeries => self.time_series_detection().await,
                DetectionMethod::Behavioral => self.behavioral_detection(flows, packets).await,
                DetectionMethod::MachineLearning => self.ml_detection(flows, packets).await,
                DetectionMethod::RuleBased => self.rule_based_detection(flows, packets).await,
            };

            if let Ok(result) = method_result {
                detected_anomalies.extend(result.anomalies);
                
                // Update overall confidence (weighted average)
                if result.overall_confidence > overall_confidence {
                    overall_confidence = result.overall_confidence;
                    detection_method = method.clone();
                }
                
                // Merge baseline deviations
                for (key, value) in result.baseline_deviation {
                    baseline_deviation.insert(key, value);
                }
            }
        }

        // Deduplicate and rank anomalies
        detected_anomalies = self.deduplicate_anomalies(detected_anomalies).await;
        detected_anomalies.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));

        // Filter by minimum confidence
        detected_anomalies.retain(|anomaly| anomaly.confidence >= self.config.min_confidence);

        // Store detected anomalies
        self.store_anomalies(&detected_anomalies).await;

        // Update statistics
        self.update_detection_stats(&detected_anomalies, &detection_method, start_time.elapsed().unwrap_or_default()).await;

        let mut metadata = HashMap::new();
        metadata.insert("total_flows".to_string(), flows.len().to_string());
        metadata.insert("total_packets".to_string(), packets.len().to_string());
        metadata.insert("detection_time_ms".to_string(), 
                       start_time.elapsed().unwrap_or_default().as_millis().to_string());

        info!("Detected {} anomalies using {:?} method", detected_anomalies.len(), detection_method);

        AnomalyDetectionResult {
            anomalies: detected_anomalies,
            overall_confidence,
            timestamp: SystemTime::now(),
            detection_method,
            baseline_deviation,
            metadata,
        }
    }

    /// Statistical anomaly detection
    async fn statistical_detection(&self, flows: &[NetworkFlow], packets: &[PacketInfo]) -> Result<AnomalyDetectionResult, NetworkAnalysisError> {
        let mut anomalies = Vec::new();
        let mut baseline_deviation = HashMap::new();

        // Calculate current metrics
        let current_metrics = self.calculate_current_metrics(flows, packets).await;
        
        // Compare against baseline if available
        if let Some(baseline) = self.baseline.read().await.as_ref() {
            // Check packet rate anomaly
            let packet_rate_deviation = (current_metrics.packet_rate - baseline.avg_packet_rate).abs() / baseline.avg_packet_rate;
            baseline_deviation.insert("packet_rate_deviation".to_string(), packet_rate_deviation);
            
            if packet_rate_deviation > *self.config.statistical_thresholds.get("packet_rate").unwrap_or(&2.0) {
                anomalies.push(NetworkAnomaly {
                    anomaly_type: AnomalyType::TrafficAnomaly,
                    severity: if packet_rate_deviation > 5.0 { AnomalySeverity::High } else { AnomalySeverity::Medium },
                    description: format!("Unusual packet rate: {:.2} packets/sec (baseline: {:.2})", 
                                       current_metrics.packet_rate, baseline.avg_packet_rate),
                    affected_flows: flows.iter().map(|f| f.flow_id.clone()).collect(),
                    confidence: (packet_rate_deviation / 10.0).min(1.0) as f32,
                    detected_at: SystemTime::now(),
                    metadata: HashMap::new(),
                });
            }

            // Check byte rate anomaly
            let byte_rate_deviation = (current_metrics.byte_rate - baseline.avg_byte_rate).abs() / baseline.avg_byte_rate;
            baseline_deviation.insert("byte_rate_deviation".to_string(), byte_rate_deviation);
            
            if byte_rate_deviation > *self.config.statistical_thresholds.get("byte_rate").unwrap_or(&2.0) {
                anomalies.push(NetworkAnomaly {
                    anomaly_type: AnomalyType::TrafficAnomaly,
                    severity: if byte_rate_deviation > 5.0 { AnomalySeverity::High } else { AnomalySeverity::Medium },
                    description: format!("Unusual byte rate: {:.2} bytes/sec (baseline: {:.2})", 
                                       current_metrics.byte_rate, baseline.avg_byte_rate),
                    affected_flows: flows.iter().map(|f| f.flow_id.clone()).collect(),
                    confidence: (byte_rate_deviation / 10.0).min(1.0) as f32,
                    detected_at: SystemTime::now(),
                    metadata: HashMap::new(),
                });
            }
        }

        // Check for port scanning
        let unique_ports: std::collections::HashSet<u16> = packets.iter()
            .filter_map(|p| p.dst_port)
            .collect();
        
        if unique_ports.len() > *self.config.statistical_thresholds.get("max_unique_ports").unwrap_or(&100.0) as usize {
            anomalies.push(NetworkAnomaly {
                anomaly_type: AnomalyType::PortAnomaly,
                severity: AnomalySeverity::High,
                description: format!("Potential port scan detected: {} unique ports accessed", unique_ports.len()),
                affected_flows: flows.iter().map(|f| f.flow_id.clone()).collect(),
                confidence: 0.8,
                detected_at: SystemTime::now(),
                metadata: HashMap::new(),
            });
        }

        // Check for DDoS patterns
        let connection_rate = flows.len() as f64 / self.config.time_window.as_secs_f64();
        if connection_rate > *self.config.statistical_thresholds.get("max_connection_rate").unwrap_or(&1000.0) {
            anomalies.push(NetworkAnomaly {
                anomaly_type: AnomalyType::TrafficAnomaly,
                severity: AnomalySeverity::Critical,
                description: format!("Potential DDoS attack: {:.2} connections/sec", connection_rate),
                affected_flows: flows.iter().map(|f| f.flow_id.clone()).collect(),
                confidence: 0.9,
                detected_at: SystemTime::now(),
                metadata: HashMap::new(),
            });
        }

        let overall_confidence = if anomalies.is_empty() { 0.0 } else { 0.7 };
        
        Ok(AnomalyDetectionResult {
            anomalies,
            overall_confidence,
            timestamp: SystemTime::now(),
            detection_method: DetectionMethod::Statistical,
            baseline_deviation,
            metadata: HashMap::new(),
        })
    }

    /// Time series anomaly detection
    async fn time_series_detection(&self) -> Result<AnomalyDetectionResult, NetworkAnalysisError> {
        let mut anomalies = Vec::new();
        let time_series = self.time_series.read().await;

        for (metric_name, data_points) in time_series.iter() {
            if data_points.len() < 10 {
                continue; // Need sufficient data points
            }

            // Simple moving average anomaly detection
            let window_size = 5;
            let values: Vec<f64> = data_points.iter().map(|p| p.value).collect();
            
            for i in window_size..values.len() {
                let window_avg: f64 = values[i-window_size..i].iter().sum::<f64>() / window_size as f64;
                let current_value = values[i];
                let deviation = (current_value - window_avg).abs() / window_avg;
                
                if deviation > 3.0 { // 3-sigma rule
                    anomalies.push(NetworkAnomaly {
                        anomaly_type: AnomalyType::TrafficAnomaly,
                        severity: if deviation > 5.0 { AnomalySeverity::High } else { AnomalySeverity::Medium },
                        description: format!("Time series anomaly in {}: current={:.2}, expected={:.2}", 
                                           metric_name, current_value, window_avg),
                        affected_flows: Vec::new(),
                        confidence: (deviation / 10.0).min(1.0) as f32,
                        detected_at: data_points[i].timestamp,
                        metadata: HashMap::new(),
                    });
                }
            }
        }

        let overall_confidence = if anomalies.is_empty() { 0.0 } else { 0.6 };
        
        Ok(AnomalyDetectionResult {
            anomalies,
            overall_confidence,
            timestamp: SystemTime::now(),
            detection_method: DetectionMethod::TimeSeries,
            baseline_deviation: HashMap::new(),
            metadata: HashMap::new(),
        })
    }

    /// Behavioral anomaly detection
    async fn behavioral_detection(&self, flows: &[NetworkFlow], _packets: &[PacketInfo]) -> Result<AnomalyDetectionResult, NetworkAnalysisError> {
        let mut anomalies = Vec::new();
        
        // Detect unusual connection patterns
        let mut connection_patterns: HashMap<String, u32> = HashMap::new();
        for flow in flows {
            let pattern = format!("{}:{:?}", flow.dst_endpoint.ip, flow.dst_endpoint.port);
            *connection_patterns.entry(pattern).or_insert(0) += 1;
        }

        // Check for beaconing behavior (regular intervals)
        let mut flow_intervals: HashMap<String, Vec<Duration>> = HashMap::new();
        for flow in flows {
            if let (Some(start), Some(_end)) = (flow.start_time.elapsed().ok(), flow.end_time.and_then(|t| t.elapsed().ok())) {
                flow_intervals.entry(flow.dst_endpoint.ip.to_string())
                    .or_insert_with(Vec::new)
                    .push(start);
            }
        }

        for (ip, intervals) in flow_intervals {
            if intervals.len() > 5 {
                // Check for regular intervals (potential beaconing)
                let mut interval_diffs = Vec::new();
                for i in 1..intervals.len() {
                    let curr = intervals[i].as_secs();
                    let prev = intervals[i-1].as_secs();
                    interval_diffs.push((curr as i64 - prev as i64).abs());
                }
                
                if !interval_diffs.is_empty() {
                    let avg_diff = interval_diffs.iter().sum::<i64>() as f64 / interval_diffs.len() as f64;
                    let variance: f64 = interval_diffs.iter()
                        .map(|&x| (x as f64 - avg_diff).powi(2))
                        .sum::<f64>() / interval_diffs.len() as f64;
                    
                    // Low variance indicates regular intervals
                    if variance < avg_diff * 0.1 && avg_diff > 10.0 {
                        anomalies.push(NetworkAnomaly {
                            anomaly_type: AnomalyType::BehavioralAnomaly,
                            severity: AnomalySeverity::Medium,
                            description: format!("Potential beaconing behavior to {}: regular intervals of {:.1}s", ip, avg_diff),
                            affected_flows: flows.iter()
                                .filter(|f| f.dst_endpoint.ip.to_string() == ip)
                                .map(|f| f.flow_id.clone())
                                .collect(),
                            confidence: 0.7,
                            detected_at: SystemTime::now(),
                            metadata: HashMap::new(),
                        });
                    }
                }
            }
        }

        let overall_confidence = if anomalies.is_empty() { 0.0 } else { 0.6 };
        
        Ok(AnomalyDetectionResult {
            anomalies,
            overall_confidence,
            timestamp: SystemTime::now(),
            detection_method: DetectionMethod::Behavioral,
            baseline_deviation: HashMap::new(),
            metadata: HashMap::new(),
        })
    }

    /// Machine learning anomaly detection (simplified)
    async fn ml_detection(&self, _flows: &[NetworkFlow], _packets: &[PacketInfo]) -> Result<AnomalyDetectionResult, NetworkAnalysisError> {
        // Placeholder for ML-based detection
        // In a real implementation, this would use trained models
        Ok(AnomalyDetectionResult {
            anomalies: Vec::new(),
            overall_confidence: 0.0,
            timestamp: SystemTime::now(),
            detection_method: DetectionMethod::MachineLearning,
            baseline_deviation: HashMap::new(),
            metadata: HashMap::new(),
        })
    }

    /// Rule-based anomaly detection
    async fn rule_based_detection(&self, flows: &[NetworkFlow], packets: &[PacketInfo]) -> Result<AnomalyDetectionResult, NetworkAnalysisError> {
        let mut anomalies = Vec::new();

        // Rule: Detect connections to suspicious ports
        let suspicious_ports = vec![1337, 31337, 4444, 5555, 6666, 7777, 8888, 9999];
        for flow in flows {
            if let Some(dst_port) = flow.dst_endpoint.port {
                if suspicious_ports.contains(&dst_port) {
                    anomalies.push(NetworkAnomaly {
                        anomaly_type: AnomalyType::PortAnomaly,
                        severity: AnomalySeverity::Medium,
                        description: format!("Connection to suspicious port {}", dst_port),
                        affected_flows: vec![flow.flow_id.clone()],
                        confidence: 0.6,
                        detected_at: SystemTime::now(),
                        metadata: HashMap::new(),
                    });
                }
            }
        }

        // Rule: Detect high entropy payloads (potential encryption/obfuscation)
        for packet in packets {
            if let Some(payload) = &packet.payload {
                let entropy = utils::calculate_payload_entropy(payload);
                if entropy > 7.5 && payload.len() > 100 {
                    anomalies.push(NetworkAnomaly {
                        anomaly_type: AnomalyType::PayloadAnomaly,
                        severity: AnomalySeverity::Medium,
                        description: format!("High entropy payload detected: {:.2}", entropy),
                        affected_flows: Vec::new(),
                        confidence: 0.5,
                        detected_at: SystemTime::now(),
                        metadata: HashMap::new(),
                    });
                }
            }
        }

        let overall_confidence = if anomalies.is_empty() { 0.0 } else { 0.5 };
        
        Ok(AnomalyDetectionResult {
            anomalies,
            overall_confidence,
            timestamp: SystemTime::now(),
            detection_method: DetectionMethod::RuleBased,
            baseline_deviation: HashMap::new(),
            metadata: HashMap::new(),
        })
    }

    /// Calculate current network metrics
    async fn calculate_current_metrics(&self, flows: &[NetworkFlow], packets: &[PacketInfo]) -> CurrentMetrics {
        let time_window_secs = self.config.time_window.as_secs_f64();
        
        CurrentMetrics {
            packet_rate: packets.len() as f64 / time_window_secs,
            byte_rate: packets.iter().map(|p| p.size as u64).sum::<u64>() as f64 / time_window_secs,
            flow_rate: flows.len() as f64 / time_window_secs,
            avg_packet_size: if packets.is_empty() { 0.0 } else { 
                packets.iter().map(|p| p.size).sum::<usize>() as f64 / packets.len() as f64 
            },
        }
    }

    /// Update time series data
    async fn update_time_series(&self, _flows: &[NetworkFlow], packets: &[PacketInfo]) {
        let mut time_series = self.time_series.write().await;
        let _now = SystemTime::now();
        
        // Add packet rate data point
        let packet_rate = packets.len() as f64 / self.config.time_window.as_secs_f64();
        time_series.entry("packet_rate".to_string())
            .or_insert_with(VecDeque::new)
            .push_back(TimeSeriesPoint {
                timestamp: _now,
                value: packet_rate,
                metadata: HashMap::new(),
            });

        // Add byte rate data point
        let byte_rate = packets.iter().map(|p| p.size as u64).sum::<u64>() as f64 / self.config.time_window.as_secs_f64();
        time_series.entry("byte_rate".to_string())
            .or_insert_with(VecDeque::new)
            .push_back(TimeSeriesPoint {
                timestamp: _now,
                value: byte_rate,
                metadata: HashMap::new(),
            });

        // Limit time series data size
        for data_points in time_series.values_mut() {
            while data_points.len() > 1000 {
                data_points.pop_front();
            }
        }
    }

    /// Deduplicate similar anomalies
    async fn deduplicate_anomalies(&self, anomalies: Vec<NetworkAnomaly>) -> Vec<NetworkAnomaly> {
        // Simple deduplication based on type and description similarity
        let mut deduplicated = Vec::new();
        
        for anomaly in anomalies {
            let is_duplicate = deduplicated.iter().any(|existing: &NetworkAnomaly| {
                existing.anomaly_type == anomaly.anomaly_type &&
                existing.description.contains(&anomaly.description[..anomaly.description.len().min(20)])
            });
            
            if !is_duplicate {
                deduplicated.push(anomaly);
            }
        }
        
        deduplicated
    }

    /// Store detected anomalies
    async fn store_anomalies(&self, anomalies: &[NetworkAnomaly]) {
        let mut stored_anomalies = self.anomalies.write().await;
        
        for anomaly in anomalies {
            stored_anomalies.push_back(anomaly.clone());
        }
        
        // Limit stored anomalies
        while stored_anomalies.len() > self.config.max_anomalies {
            stored_anomalies.pop_front();
        }
    }

    /// Update detection statistics
    async fn update_detection_stats(&self, anomalies: &[NetworkAnomaly], method: &DetectionMethod, processing_time: Duration) {
        let mut stats = self.stats.write().await;
        
        stats.total_detections += 1;
        stats.total_anomalies += anomalies.len() as u64;
        
        // Update method effectiveness (simplified)
        let effectiveness = if anomalies.is_empty() { 0.0 } else { 1.0 };
        stats.method_effectiveness.insert(method.clone(), effectiveness);
        
        // Update anomaly distribution
        for anomaly in anomalies {
            *stats.anomaly_distribution.entry(anomaly.anomaly_type.clone()).or_insert(0) += 1;
        }
        
        // Update average detection time
        let total_time = stats.avg_detection_time.as_nanos() as u64 * (stats.total_detections - 1) + processing_time.as_nanos() as u64;
        stats.avg_detection_time = Duration::from_nanos(total_time / stats.total_detections);
    }

    /// Learn baseline from network traffic
    pub async fn learn_baseline(&self, flows: &[NetworkFlow], packets: &[PacketInfo]) {
        let current_metrics = self.calculate_current_metrics(flows, packets).await;
        
        // Calculate protocol distribution
        let mut protocol_distribution = HashMap::new();
        for packet in packets {
            let protocol_name = format!("{:?}", packet.protocol);
            *protocol_distribution.entry(protocol_name).or_insert(0.0) += 1.0;
        }
        
        // Normalize protocol distribution
        let total_packets = packets.len() as f64;
        for count in protocol_distribution.values_mut() {
            *count /= total_packets;
        }

        // Calculate port patterns
        let mut port_patterns = HashMap::new();
        for packet in packets {
            if let Some(dst_port) = packet.dst_port {
                *port_patterns.entry(dst_port).or_insert(0.0) += 1.0;
            }
        }
        
        // Normalize port patterns
        for count in port_patterns.values_mut() {
            *count /= total_packets;
        }

        let baseline = NetworkBaseline {
            timestamp: SystemTime::now(),
            avg_packet_rate: current_metrics.packet_rate,
            avg_byte_rate: current_metrics.byte_rate,
            protocol_distribution,
            port_patterns,
            connection_patterns: HashMap::new(),
            entropy_distribution: Vec::new(),
            inter_arrival_patterns: Vec::new(),
        };

        let mut baseline_lock = self.baseline.write().await;
        *baseline_lock = Some(baseline);
        
        info!("Learned network baseline from {} flows and {} packets", flows.len(), packets.len());
    }

    /// Get detected anomalies
    pub async fn get_anomalies(&self) -> Vec<NetworkAnomaly> {
        let anomalies = self.anomalies.read().await;
        anomalies.iter().cloned().collect()
    }

    /// Get detection statistics
    pub async fn get_statistics(&self) -> AnomalyDetectionStats {
        let stats = self.stats.read().await;
        stats.clone()
    }

    /// Clear anomaly history
    pub async fn clear_anomalies(&self) {
        let mut anomalies = self.anomalies.write().await;
        anomalies.clear();
        info!("Cleared anomaly history");
    }
}

/// Current network metrics
#[derive(Debug, Clone)]
struct CurrentMetrics {
    packet_rate: f64,
    byte_rate: f64,
    flow_rate: f64,
    avg_packet_size: f64,
}

impl Default for AnomalyDetectionConfig {
    fn default() -> Self {
        let mut statistical_thresholds = HashMap::new();
        statistical_thresholds.insert("packet_rate".to_string(), 2.0);
        statistical_thresholds.insert("byte_rate".to_string(), 2.0);
        statistical_thresholds.insert("max_unique_ports".to_string(), 100.0);
        statistical_thresholds.insert("max_connection_rate".to_string(), 1000.0);

        Self {
            methods: vec![DetectionMethod::Statistical, DetectionMethod::RuleBased],
            statistical_thresholds,
            time_window: Duration::from_secs(60),
            min_confidence: 0.5,
            max_anomalies: 1000,
            baseline_period: Duration::from_secs(3600),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_anomaly_detector_creation() {
        let config = AnomalyDetectionConfig::default();
        let detector = AnomalyDetector::new(config);
        
        let stats = detector.get_statistics().await;
        assert_eq!(stats.total_detections, 0);
    }

    #[tokio::test]
    async fn test_port_scan_detection() {
        let config = AnomalyDetectionConfig::default();
        let detector = AnomalyDetector::new(config);
        
        // Create packets that simulate port scanning
        let mut packets = Vec::new();
        for port in 1..150 {
            packets.push(PacketInfo {
                timestamp: SystemTime::now(),
                src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                src_port: Some(12345),
                dst_port: Some(port),
                protocol: ProtocolType::Tcp,
                size: 64,
                payload: None,
                flags: PacketFlags::default(),
                ttl: Some(64),
                direction: PacketDirection::Outbound,
            });
        }
        
        let flows = Vec::new();
        let result = detector.detect_anomalies(&flows, &packets).await;
        
        assert!(!result.anomalies.is_empty());
        assert!(result.anomalies.iter().any(|a| a.anomaly_type == AnomalyType::PortAnomaly));
    }

    #[tokio::test]
    async fn test_baseline_learning() {
        let config = AnomalyDetectionConfig::default();
        let detector = AnomalyDetector::new(config);
        
        let flows = vec![
            NetworkFlow {
                flow_id: "flow1".to_string(),
                src_endpoint: NetworkEndpoint {
                    ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                    port: Some(12345),
                    hostname: None,
                    geolocation: None,
                    reputation: None,
                },
                dst_endpoint: NetworkEndpoint {
                    ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                    port: Some(80),
                    hostname: None,
                    geolocation: None,
                    reputation: None,
                },
                protocol: ProtocolType::Http,
                start_time: SystemTime::now(),
                end_time: None,
                total_bytes: 1024,
                total_packets: 10,
                duration: Some(Duration::from_secs(5)),
                state: FlowState::Active,
                application_protocol: Some("HTTP".to_string()),
                metadata: HashMap::new(),
            }
        ];
        
        let packets = vec![
            PacketInfo {
                timestamp: SystemTime::now(),
                src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                src_port: Some(12345),
                dst_port: Some(80),
                protocol: ProtocolType::Http,
                size: 100,
                payload: None,
                flags: PacketFlags::default(),
                ttl: Some(64),
                direction: PacketDirection::Outbound,
            }
        ];
        
        detector.learn_baseline(&flows, &packets).await;
        
        let baseline = detector.baseline.read().await;
        assert!(baseline.is_some());
        
        let baseline = baseline.as_ref().unwrap();
        assert!(baseline.avg_packet_rate > 0.0);
        assert!(baseline.avg_byte_rate > 0.0);
    }
}
