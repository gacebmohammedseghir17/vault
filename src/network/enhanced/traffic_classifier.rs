//! Traffic classifier for network behavior analysis
//! Provides ML-based traffic classification and behavioral analysis

use super::*;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;
use tracing::{debug, info};

/// Traffic classification categories
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TrafficCategory {
    /// Normal web browsing
    WebBrowsing,
    /// File transfer
    FileTransfer,
    /// Video streaming
    VideoStreaming,
    /// Gaming traffic
    Gaming,
    /// Email communication
    Email,
    /// Voice over IP
    VoIP,
    /// Peer-to-peer traffic
    P2P,
    /// Malicious traffic
    Malicious,
    /// Suspicious activity
    Suspicious,
    /// Unknown/unclassified
    Unknown,
}

/// Traffic classification result
#[derive(Debug, Clone)]
pub struct TrafficClassificationResult {
    /// Classified category
    pub category: TrafficCategory,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f32,
    /// Classification features used
    pub features: HashMap<String, f64>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
    /// Classification timestamp
    pub timestamp: SystemTime,
}

/// Traffic flow features for classification
#[derive(Debug, Clone)]
pub struct FlowFeatures {
    /// Flow duration
    pub duration: Duration,
    /// Total bytes transferred
    pub total_bytes: u64,
    /// Total packets
    pub total_packets: u64,
    /// Average packet size
    pub avg_packet_size: f64,
    /// Packet size variance
    pub packet_size_variance: f64,
    /// Inter-arrival time statistics
    pub inter_arrival_mean: Duration,
    /// Inter-arrival time variance
    pub inter_arrival_variance: Duration,
    /// Bytes per second
    pub bytes_per_second: f64,
    /// Packets per second
    pub packets_per_second: f64,
    /// Protocol distribution
    pub protocol_distribution: HashMap<String, u32>,
    /// Port usage patterns
    pub port_patterns: HashMap<u16, u32>,
    /// Payload entropy
    pub payload_entropy: f64,
    /// Connection patterns
    pub connection_patterns: HashMap<String, u32>,
}

/// Traffic classifier engine
#[derive(Clone)]
pub struct TrafficClassifier {
    /// Classification rules
    rules: Arc<RwLock<Vec<ClassificationRule>>>,
    /// Feature extractors
    feature_extractors: Arc<RwLock<Vec<FeatureExtractor>>>,
    /// Classification cache
    cache: Arc<RwLock<HashMap<String, TrafficClassificationResult>>>,
    /// Classification statistics
    stats: Arc<RwLock<ClassificationStats>>,
    /// Behavioral baselines
    baselines: Arc<RwLock<HashMap<TrafficCategory, FlowFeatures>>>,
}

/// Classification rule
#[derive(Debug, Clone)]
pub struct ClassificationRule {
    /// Rule name
    pub name: String,
    /// Target category
    pub category: TrafficCategory,
    /// Rule conditions
    pub conditions: Vec<RuleCondition>,
    /// Rule weight
    pub weight: f32,
    /// Minimum confidence threshold
    pub min_confidence: f32,
}

/// Rule condition
#[derive(Debug, Clone)]
pub enum RuleCondition {
    /// Port-based condition
    PortEquals(u16),
    PortRange(u16, u16),
    /// Protocol-based condition
    ProtocolEquals(ProtocolType),
    /// Feature-based condition
    FeatureGreaterThan(String, f64),
    FeatureLessThan(String, f64),
    FeatureEquals(String, f64),
    /// Pattern-based condition
    PayloadContains(Vec<u8>),
    /// Behavioral condition
    BehaviorMatches(String),
}

/// Feature extractor
#[derive(Debug, Clone)]
pub struct FeatureExtractor {
    /// Extractor name
    pub name: String,
    /// Feature type
    pub feature_type: FeatureType,
    /// Extraction function identifier
    pub extractor_id: String,
}

/// Feature types
#[derive(Debug, Clone)]
pub enum FeatureType {
    /// Statistical features
    Statistical,
    /// Temporal features
    Temporal,
    /// Protocol features
    Protocol,
    /// Payload features
    Payload,
    /// Behavioral features
    Behavioral,
}

/// Classification statistics
#[derive(Debug, Clone, Default)]
pub struct ClassificationStats {
    /// Total classifications performed
    pub total_classifications: u64,
    /// Category distribution
    pub category_distribution: HashMap<TrafficCategory, u64>,
    /// Average confidence scores
    pub average_confidence: HashMap<TrafficCategory, f64>,
    /// Classification accuracy (if ground truth available)
    pub accuracy: Option<f64>,
    /// Feature importance scores
    pub feature_importance: HashMap<String, f64>,
    /// Processing time statistics
    pub avg_processing_time: Duration,
}

impl TrafficClassifier {
    /// Create new traffic classifier
    pub fn new() -> Self {
        let classifier = Self {
            rules: Arc::new(RwLock::new(Vec::new())),
            feature_extractors: Arc::new(RwLock::new(Vec::new())),
            cache: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(ClassificationStats::default())),
            baselines: Arc::new(RwLock::new(HashMap::new())),
        };
        
        // Initialize with default rules and extractors
        let classifier_clone = classifier.clone();
        tokio::spawn(async move {
            classifier_clone.initialize_default_rules().await;
            classifier_clone.initialize_feature_extractors().await;
        });
        
        classifier
    }

    /// Initialize default classification rules
    async fn initialize_default_rules(&self) {
        let mut rules = self.rules.write().await;
        
        // Web browsing rules
        rules.push(ClassificationRule {
            name: "HTTP_Web_Browsing".to_string(),
            category: TrafficCategory::WebBrowsing,
            conditions: vec![
                RuleCondition::PortEquals(80),
                RuleCondition::ProtocolEquals(ProtocolType::Http),
            ],
            weight: 0.8,
            min_confidence: 0.7,
        });

        rules.push(ClassificationRule {
            name: "HTTPS_Web_Browsing".to_string(),
            category: TrafficCategory::WebBrowsing,
            conditions: vec![
                RuleCondition::PortEquals(443),
                RuleCondition::ProtocolEquals(ProtocolType::Https),
            ],
            weight: 0.8,
            min_confidence: 0.7,
        });

        // File transfer rules
        rules.push(ClassificationRule {
            name: "FTP_File_Transfer".to_string(),
            category: TrafficCategory::FileTransfer,
            conditions: vec![
                RuleCondition::PortEquals(21),
                RuleCondition::ProtocolEquals(ProtocolType::Ftp),
            ],
            weight: 0.9,
            min_confidence: 0.8,
        });

        // Email rules
        rules.push(ClassificationRule {
            name: "SMTP_Email".to_string(),
            category: TrafficCategory::Email,
            conditions: vec![
                RuleCondition::PortEquals(25),
                RuleCondition::ProtocolEquals(ProtocolType::Smtp),
            ],
            weight: 0.9,
            min_confidence: 0.8,
        });

        // P2P rules
        rules.push(ClassificationRule {
            name: "BitTorrent_P2P".to_string(),
            category: TrafficCategory::P2P,
            conditions: vec![
                RuleCondition::PortRange(6881, 6889),
                RuleCondition::FeatureGreaterThan("connection_diversity".to_string(), 10.0),
            ],
            weight: 0.8,
            min_confidence: 0.6,
        });

        // Malicious traffic rules
        rules.push(ClassificationRule {
            name: "Suspicious_Port_Scan".to_string(),
            category: TrafficCategory::Suspicious,
            conditions: vec![
                RuleCondition::FeatureGreaterThan("unique_ports".to_string(), 100.0),
                RuleCondition::FeatureLessThan("avg_packet_size".to_string(), 64.0),
            ],
            weight: 0.9,
            min_confidence: 0.7,
        });

        rules.push(ClassificationRule {
            name: "High_Entropy_Payload".to_string(),
            category: TrafficCategory::Suspicious,
            conditions: vec![
                RuleCondition::FeatureGreaterThan("payload_entropy".to_string(), 7.5),
                RuleCondition::FeatureGreaterThan("bytes_per_second".to_string(), 1000000.0),
            ],
            weight: 0.7,
            min_confidence: 0.6,
        });

        info!("Initialized {} classification rules", rules.len());
    }

    /// Initialize feature extractors
    async fn initialize_feature_extractors(&self) {
        let mut extractors = self.feature_extractors.write().await;
        
        // Statistical extractors
        extractors.push(FeatureExtractor {
            name: "packet_size_stats".to_string(),
            feature_type: FeatureType::Statistical,
            extractor_id: "extract_packet_size_stats".to_string(),
        });

        extractors.push(FeatureExtractor {
            name: "flow_duration_stats".to_string(),
            feature_type: FeatureType::Temporal,
            extractor_id: "extract_flow_duration_stats".to_string(),
        });

        // Protocol extractors
        extractors.push(FeatureExtractor {
            name: "protocol_distribution".to_string(),
            feature_type: FeatureType::Protocol,
            extractor_id: "extract_protocol_distribution".to_string(),
        });

        // Payload extractors
        extractors.push(FeatureExtractor {
            name: "payload_entropy".to_string(),
            feature_type: FeatureType::Payload,
            extractor_id: "extract_payload_entropy".to_string(),
        });

        // Behavioral extractors
        extractors.push(FeatureExtractor {
            name: "connection_patterns".to_string(),
            feature_type: FeatureType::Behavioral,
            extractor_id: "extract_connection_patterns".to_string(),
        });

        info!("Initialized {} feature extractors", extractors.len());
    }

    /// Classify network flow
    pub async fn classify_flow(&self, flow: &NetworkFlow, packets: &[PacketInfo]) -> TrafficClassificationResult {
        let start_time = SystemTime::now();
        
        // Check cache first
        if let Some(cached_result) = self.check_cache(&flow.flow_id).await {
            return cached_result;
        }

        // Extract features from flow
        let features = self.extract_flow_features(flow, packets).await;
        
        // Apply classification rules
        let mut classification_scores: HashMap<TrafficCategory, f32> = HashMap::new();
        let rules = self.rules.read().await;
        
        for rule in rules.iter() {
            if self.evaluate_rule_conditions(&rule.conditions, &features, flow, packets).await {
                let current_score = classification_scores.get(&rule.category).unwrap_or(&0.0);
                classification_scores.insert(rule.category.clone(), current_score + rule.weight);
            }
        }

        // Determine best classification
        let (category, confidence) = if classification_scores.is_empty() {
            (TrafficCategory::Unknown, 0.1)
        } else {
            let max_entry = classification_scores.iter()
                .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
                .unwrap();
            
            let total_score: f32 = classification_scores.values().sum();
            let confidence = if total_score > 0.0 { max_entry.1 / total_score } else { 0.0 };
            
            (max_entry.0.clone(), confidence)
        };

        // Create classification result
        let mut metadata = HashMap::new();
        metadata.insert("flow_id".to_string(), flow.flow_id.clone());
        metadata.insert("total_packets".to_string(), packets.len().to_string());
        metadata.insert("classification_time".to_string(), 
                       start_time.elapsed().unwrap_or_default().as_millis().to_string());

        let result = TrafficClassificationResult {
            category,
            confidence,
            features: self.features_to_map(&features),
            metadata,
            timestamp: SystemTime::now(),
        };

        // Cache result
        self.cache_result(flow.flow_id.clone(), result.clone()).await;
        
        // Update statistics
        self.update_classification_stats(&result, start_time.elapsed().unwrap_or_default()).await;
        
        debug!("Classified flow {} as {:?} with confidence {:.2}", 
               flow.flow_id, result.category, result.confidence);
        
        result
    }

    /// Extract features from network flow
    async fn extract_flow_features(&self, flow: &NetworkFlow, packets: &[PacketInfo]) -> FlowFeatures {
        let mut features = FlowFeatures {
            duration: flow.duration.unwrap_or_default(),
            total_bytes: flow.total_bytes,
            total_packets: flow.total_packets,
            avg_packet_size: 0.0,
            packet_size_variance: 0.0,
            inter_arrival_mean: Duration::default(),
            inter_arrival_variance: Duration::default(),
            bytes_per_second: 0.0,
            packets_per_second: 0.0,
            protocol_distribution: HashMap::new(),
            port_patterns: HashMap::new(),
            payload_entropy: 0.0,
            connection_patterns: HashMap::new(),
        };

        if packets.is_empty() {
            return features;
        }

        // Calculate packet size statistics
        let packet_sizes: Vec<usize> = packets.iter().map(|p| p.size).collect();
        features.avg_packet_size = packet_sizes.iter().sum::<usize>() as f64 / packet_sizes.len() as f64;
        
        let variance_sum: f64 = packet_sizes.iter()
            .map(|&size| (size as f64 - features.avg_packet_size).powi(2))
            .sum();
        features.packet_size_variance = variance_sum / packet_sizes.len() as f64;

        // Calculate temporal features
        if packets.len() > 1 {
            let mut inter_arrivals = Vec::new();
            for i in 1..packets.len() {
                if let Ok(duration) = packets[i].timestamp.duration_since(packets[i-1].timestamp) {
                    inter_arrivals.push(duration);
                }
            }
            
            if !inter_arrivals.is_empty() {
                let total_nanos: u64 = inter_arrivals.iter().map(|d| d.as_nanos() as u64).sum();
                features.inter_arrival_mean = Duration::from_nanos(total_nanos / inter_arrivals.len() as u64);
            }
        }

        // Calculate throughput
        if let Some(duration) = flow.duration {
            let duration_secs = duration.as_secs_f64();
            if duration_secs > 0.0 {
                features.bytes_per_second = flow.total_bytes as f64 / duration_secs;
                features.packets_per_second = flow.total_packets as f64 / duration_secs;
            }
        }

        // Extract protocol distribution
        for packet in packets {
            let protocol_name = format!("{:?}", packet.protocol);
            *features.protocol_distribution.entry(protocol_name).or_insert(0) += 1;
        }

        // Extract port patterns
        for packet in packets {
            if let Some(dst_port) = packet.dst_port {
                *features.port_patterns.entry(dst_port).or_insert(0) += 1;
            }
            if let Some(src_port) = packet.src_port {
                *features.port_patterns.entry(src_port).or_insert(0) += 1;
            }
        }

        // Calculate payload entropy (simplified)
        let mut total_entropy = 0.0;
        let mut entropy_count = 0;
        for packet in packets {
            if let Some(payload) = &packet.payload {
                total_entropy += utils::calculate_payload_entropy(payload);
                entropy_count += 1;
            }
        }
        if entropy_count > 0 {
            features.payload_entropy = total_entropy / entropy_count as f64;
        }

        features
    }

    /// Evaluate rule conditions
    async fn evaluate_rule_conditions(&self, conditions: &[RuleCondition], features: &FlowFeatures, flow: &NetworkFlow, packets: &[PacketInfo]) -> bool {
        for condition in conditions {
            if !self.evaluate_single_condition(condition, features, flow, packets).await {
                return false;
            }
        }
        true
    }

    /// Evaluate single rule condition
    async fn evaluate_single_condition(&self, condition: &RuleCondition, features: &FlowFeatures, flow: &NetworkFlow, packets: &[PacketInfo]) -> bool {
        match condition {
            RuleCondition::PortEquals(port) => {
                flow.src_endpoint.port == Some(*port) || flow.dst_endpoint.port == Some(*port)
            }
            RuleCondition::PortRange(min_port, max_port) => {
                let src_in_range = flow.src_endpoint.port.map_or(false, |p| p >= *min_port && p <= *max_port);
                let dst_in_range = flow.dst_endpoint.port.map_or(false, |p| p >= *min_port && p <= *max_port);
                src_in_range || dst_in_range
            }
            RuleCondition::ProtocolEquals(protocol) => {
                flow.protocol == *protocol
            }
            RuleCondition::FeatureGreaterThan(feature_name, threshold) => {
                self.get_feature_value(feature_name, features) > *threshold
            }
            RuleCondition::FeatureLessThan(feature_name, threshold) => {
                self.get_feature_value(feature_name, features) < *threshold
            }
            RuleCondition::FeatureEquals(feature_name, value) => {
                (self.get_feature_value(feature_name, features) - value).abs() < 0.001
            }
            RuleCondition::PayloadContains(pattern) => {
                packets.iter().any(|packet| {
                    if let Some(payload) = &packet.payload {
                        payload.windows(pattern.len()).any(|window| window == pattern)
                    } else {
                        false
                    }
                })
            }
            RuleCondition::BehaviorMatches(_behavior_pattern) => {
                // Simplified behavior matching
                true
            }
        }
    }

    /// Get feature value by name
    fn get_feature_value(&self, feature_name: &str, features: &FlowFeatures) -> f64 {
        match feature_name {
            "avg_packet_size" => features.avg_packet_size,
            "packet_size_variance" => features.packet_size_variance,
            "bytes_per_second" => features.bytes_per_second,
            "packets_per_second" => features.packets_per_second,
            "payload_entropy" => features.payload_entropy,
            "total_bytes" => features.total_bytes as f64,
            "total_packets" => features.total_packets as f64,
            "unique_ports" => features.port_patterns.len() as f64,
            "connection_diversity" => features.protocol_distribution.len() as f64,
            _ => 0.0,
        }
    }

    /// Convert features to hashmap
    fn features_to_map(&self, features: &FlowFeatures) -> HashMap<String, f64> {
        let mut feature_map = HashMap::new();
        
        feature_map.insert("avg_packet_size".to_string(), features.avg_packet_size);
        feature_map.insert("packet_size_variance".to_string(), features.packet_size_variance);
        feature_map.insert("bytes_per_second".to_string(), features.bytes_per_second);
        feature_map.insert("packets_per_second".to_string(), features.packets_per_second);
        feature_map.insert("payload_entropy".to_string(), features.payload_entropy);
        feature_map.insert("total_bytes".to_string(), features.total_bytes as f64);
        feature_map.insert("total_packets".to_string(), features.total_packets as f64);
        feature_map.insert("unique_ports".to_string(), features.port_patterns.len() as f64);
        feature_map.insert("protocol_diversity".to_string(), features.protocol_distribution.len() as f64);
        
        feature_map
    }

    /// Check classification cache
    async fn check_cache(&self, flow_id: &str) -> Option<TrafficClassificationResult> {
        let cache = self.cache.read().await;
        cache.get(flow_id).cloned()
    }

    /// Cache classification result
    async fn cache_result(&self, flow_id: String, result: TrafficClassificationResult) {
        let mut cache = self.cache.write().await;
        
        // Limit cache size
        if cache.len() > 1000 {
            cache.clear();
        }
        
        cache.insert(flow_id, result);
    }

    /// Update classification statistics
    async fn update_classification_stats(&self, result: &TrafficClassificationResult, processing_time: Duration) {
        let mut stats = self.stats.write().await;
        
        stats.total_classifications += 1;
        
        // Update category distribution
        *stats.category_distribution.entry(result.category.clone()).or_insert(0) += 1;
        
        // Update average confidence
        let current_avg = stats.average_confidence.get(&result.category).unwrap_or(&0.0);
        let count = stats.category_distribution.get(&result.category).unwrap_or(&1);
        let new_avg = (current_avg * (*count - 1) as f64 + result.confidence as f64) / *count as f64;
        stats.average_confidence.insert(result.category.clone(), new_avg);
        
        // Update processing time
        let total_time = stats.avg_processing_time.as_nanos() as u64 * (stats.total_classifications - 1) + processing_time.as_nanos() as u64;
        stats.avg_processing_time = Duration::from_nanos(total_time / stats.total_classifications);
    }

    /// Batch classify multiple flows
    pub async fn classify_flows_batch(&self, flows_with_packets: Vec<(&NetworkFlow, &[PacketInfo])>) -> Vec<TrafficClassificationResult> {
        let mut results = Vec::new();
        
        for (flow, packets) in flows_with_packets {
            let result = self.classify_flow(flow, packets).await;
            results.push(result);
        }
        
        info!("Performed batch classification on {} flows", results.len());
        results
    }

    /// Add custom classification rule
    pub async fn add_rule(&self, rule: ClassificationRule) {
        let mut rules = self.rules.write().await;
        rules.push(rule);
        info!("Added custom classification rule");
    }

    /// Get classification statistics
    pub async fn get_statistics(&self) -> ClassificationStats {
        let stats = self.stats.read().await;
        stats.clone()
    }

    /// Update behavioral baselines
    pub async fn update_baselines(&self, category: TrafficCategory, baseline_features: FlowFeatures) {
        let mut baselines = self.baselines.write().await;
        baselines.insert(category, baseline_features);
        info!("Updated behavioral baseline");
    }

    /// Clear classification cache
    pub async fn clear_cache(&self) {
        let mut cache = self.cache.write().await;
        cache.clear();
        info!("Cleared traffic classification cache");
    }
}

impl Default for TrafficClassifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_traffic_classifier_creation() {
        let classifier = TrafficClassifier::new();
        
        // Wait for initialization
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        let rules = classifier.rules.read().await;
        assert!(!rules.is_empty());
    }

    #[tokio::test]
    async fn test_web_traffic_classification() {
        let classifier = TrafficClassifier::new();
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        let flow = NetworkFlow {
            flow_id: "test_flow".to_string(),
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
        };
        
        let packets = vec![
            PacketInfo {
                timestamp: SystemTime::now(),
                src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                src_port: Some(12345),
                dst_port: Some(80),
                protocol: ProtocolType::Http,
                size: 100,
                payload: Some(b"GET /index.html HTTP/1.1\r\n\r\n".to_vec()),
                flags: PacketFlags::default(),
                ttl: Some(64),
                direction: PacketDirection::Outbound,
            }
        ];
        
        let result = classifier.classify_flow(&flow, &packets).await;
        
        assert_eq!(result.category, TrafficCategory::WebBrowsing);
        assert!(result.confidence > 0.5);
    }

    #[tokio::test]
    async fn test_feature_extraction() {
        let classifier = TrafficClassifier::new();
        
        let flow = NetworkFlow {
            flow_id: "test_flow".to_string(),
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
            total_bytes: 2048,
            total_packets: 20,
            duration: Some(Duration::from_secs(10)),
            state: FlowState::Active,
            application_protocol: Some("HTTP".to_string()),
            metadata: HashMap::new(),
        };
        
        let packets = vec![
            PacketInfo {
                timestamp: SystemTime::now(),
                src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                src_port: Some(12345),
                dst_port: Some(80),
                protocol: ProtocolType::Http,
                size: 100,
                payload: Some(b"test payload".to_vec()),
                flags: PacketFlags::default(),
                ttl: Some(64),
                direction: PacketDirection::Outbound,
            },
            PacketInfo {
                timestamp: SystemTime::now(),
                src_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                src_port: Some(80),
                dst_port: Some(12345),
                protocol: ProtocolType::Http,
                size: 200,
                payload: Some(b"response payload".to_vec()),
                flags: PacketFlags::default(),
                ttl: Some(64),
                direction: PacketDirection::Inbound,
            }
        ];
        
        let features = classifier.extract_flow_features(&flow, &packets).await;
        
        assert_eq!(features.total_bytes, 2048);
        assert_eq!(features.total_packets, 20);
        assert_eq!(features.avg_packet_size, 150.0); // (100 + 200) / 2
        assert!(features.bytes_per_second > 0.0);
        assert!(!features.port_patterns.is_empty());
    }
}
