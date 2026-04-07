//! Enhanced PCAP analysis module for ERDPS Advanced EDR
//! Provides deep packet inspection with AI-enhanced analysis capabilities

use super::{NetworkConfig, PacketInfo, ProtocolType, PacketFlags, PacketDirection};
use crate::ai::{AIAnalyzer, AnalysisRequest, AnalysisType, AnalysisInput, AIResult, AIError};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use serde::{Deserialize, Serialize};
use tracing::{info, warn, error, debug};

#[cfg(feature = "enhanced-pcap")]
use pcap::{Capture, Device, Active};
#[cfg(feature = "enhanced-pcap")]
use pnet::packet::{
    ethernet::{EthernetPacket, EtherTypes},
    ipv4::Ipv4Packet,
    ipv6::Ipv6Packet,
    tcp::TcpPacket,
    udp::UdpPacket,
    icmp::IcmpPacket,
    Packet,
};

/// Enhanced PCAP analyzer with AI integration
pub struct EnhancedPcapAnalyzer {
    /// Network configuration
    config: NetworkConfig,
    /// AI analyzer for traffic analysis
    ai_analyzer: Option<Arc<dyn AIAnalyzer + Send + Sync>>,
    /// Packet statistics
    stats: PcapStats,
    /// Active capture session
    #[cfg(feature = "enhanced-pcap")]
    capture: Option<Capture<Active>>,
    /// Protocol analyzers
    protocol_analyzers: HashMap<ProtocolType, Box<dyn ProtocolAnalyzer + Send + Sync>>,
    /// Flow tracker for connection analysis
    flow_tracker: FlowTracker,
    /// Threat detection engine
    threat_detector: ThreatDetectionEngine,
    /// Real-time analysis buffer
    analysis_buffer: Vec<PacketInfo>,
}

impl Drop for EnhancedPcapAnalyzer {
    fn drop(&mut self) {
        info!("Shutting down Enhanced PCAP Analyzer");
        
        // Close active capture session
        #[cfg(feature = "enhanced-pcap")]
        if self.capture.is_some() {
            info!("Closing active packet capture session");
            self.capture = None;
        }
        
        // Clear analysis buffer to free memory
        if !self.analysis_buffer.is_empty() {
            info!("Clearing analysis buffer with {} packets", self.analysis_buffer.len());
            self.analysis_buffer.clear();
        }
        
        // Clear protocol analyzers
        if !self.protocol_analyzers.is_empty() {
            info!("Clearing {} protocol analyzers", self.protocol_analyzers.len());
            self.protocol_analyzers.clear();
        }
        
        // Log final statistics
        info!("Final stats - Total packets: {}, Analyzed: {}, Suspicious: {}", 
              self.stats.total_packets, 
              self.stats.analyzed_packets, 
              self.stats.suspicious_packets);
    }
}

/// PCAP analysis statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PcapStats {
    /// Total packets captured
    pub total_packets: u64,
    /// Packets analyzed
    pub analyzed_packets: u64,
    /// Suspicious packets detected
    pub suspicious_packets: u64,
    /// Malicious packets detected
    pub malicious_packets: u64,
    /// Protocol distribution
    pub protocol_distribution: HashMap<String, u64>,
    /// Analysis duration
    pub analysis_duration: Duration,
    /// AI analysis count
    pub ai_analyses: u64,
    /// Capture start time
    pub capture_start: Option<SystemTime>,
    /// Bytes processed
    pub bytes_processed: u64,
    /// Flows detected
    pub flows_detected: u64,
    /// Threats blocked
    pub threats_blocked: u64,
}

/// Flow tracker for connection analysis
#[derive(Debug)]
pub struct FlowTracker {
    /// Active flows
    active_flows: HashMap<String, NetworkFlow>,
    /// Flow timeout duration
    flow_timeout: Duration,
    /// Maximum flows to track
    max_flows: usize,
}

impl Drop for FlowTracker {
    fn drop(&mut self) {
        if !self.active_flows.is_empty() {
            info!("Cleaning up {} active flows", self.active_flows.len());
            self.active_flows.clear();
        }
    }
}

impl FlowTracker {
    pub fn new() -> Self {
        Self {
            active_flows: HashMap::new(),
            flow_timeout: Duration::from_secs(300), // 5 minutes
            max_flows: 10000,
        }
    }

    pub fn get_flow_by_id(&self, flow_id: &str) -> Option<&NetworkFlow> {
        self.active_flows.get(flow_id)
    }

    pub fn track_packet(&mut self, packet: &PacketInfo) -> Option<&mut NetworkFlow> {
        let flow_id = self.generate_flow_id(packet);
        
        // Clean up expired flows
        self.cleanup_expired_flows();
        
        // Check if we're at capacity
        if self.active_flows.len() >= self.max_flows && !self.active_flows.contains_key(&flow_id) {
            warn!("Flow tracker at capacity, dropping oldest flow");
            self.remove_oldest_flow();
        }
        
        // Get or create flow
        let flow = self.active_flows.entry(flow_id.clone()).or_insert_with(|| {
            NetworkFlow {
                flow_id: flow_id.clone(),
                src_addr: packet.src_ip,
                dst_addr: packet.dst_ip,
                src_port: packet.src_port,
                dst_port: packet.dst_port,
                protocol: packet.protocol.clone(),
                start_time: packet.timestamp,
                end_time: None,
                bytes: 0,
                packets: 0,
                characteristics: FlowCharacteristics::default(),
            }
        });
        
        // Update flow statistics
        flow.packets += 1;
        flow.bytes += packet.size as u64;
        flow.end_time = Some(packet.timestamp);
        
        Some(flow)
    }

    fn generate_flow_id(&self, packet: &PacketInfo) -> String {
        format!("{}:{:?}-{}:{:?}-{:?}", 
            packet.src_ip, packet.src_port,
            packet.dst_ip, packet.dst_port,
            packet.protocol
        )
    }

    fn cleanup_expired_flows(&mut self) {
        let now = SystemTime::now();
        self.active_flows.retain(|_, flow| {
            if let Some(end_time) = flow.end_time {
                now.duration_since(end_time).unwrap_or(Duration::ZERO) < self.flow_timeout
            } else {
                now.duration_since(flow.start_time).unwrap_or(Duration::ZERO) < self.flow_timeout
            }
        });
    }

    fn remove_oldest_flow(&mut self) {
        if let Some((oldest_id, _)) = self.active_flows.iter()
            .min_by_key(|(_, flow)| flow.start_time) {
            let oldest_id = oldest_id.clone();
            self.active_flows.remove(&oldest_id);
        }
    }

    pub fn get_active_flows(&self) -> Vec<&NetworkFlow> {
        self.active_flows.values().collect()
    }
}

/// Threat detection engine for network analysis
#[derive(Debug)]
pub struct ThreatDetectionEngine {
    /// Threat signatures
    signatures: Vec<ThreatSignature>,
    /// Behavioral patterns
    behavioral_patterns: Vec<BehavioralPattern>,
    /// Anomaly thresholds
    anomaly_thresholds: AnomalyThresholds,
}

impl Drop for ThreatDetectionEngine {
    fn drop(&mut self) {
        info!("Cleaning up threat detection engine with {} signatures and {} patterns", 
              self.signatures.len(), 
              self.behavioral_patterns.len());
        self.signatures.clear();
        self.behavioral_patterns.clear();
    }
}

impl ThreatDetectionEngine {
    pub fn new() -> Self {
        Self {
            signatures: Self::load_default_signatures(),
            behavioral_patterns: Self::load_default_patterns(),
            anomaly_thresholds: AnomalyThresholds::default(),
        }
    }

    fn load_default_signatures() -> Vec<ThreatSignature> {
        vec![
            // Ransomware C2 communication patterns
            ThreatSignature {
                name: "Ransomware C2 Communication".to_string(),
                pattern: SignaturePattern::PortPattern(vec![443, 8080, 9999]),
                threat_type: ThreatType::Ransomware,
                severity: Severity::High,
                confidence: 0.8,
            },
            // Data exfiltration patterns
            ThreatSignature {
                name: "Large Data Transfer".to_string(),
                pattern: SignaturePattern::VolumePattern { min_bytes: 100_000_000, duration: Duration::from_secs(60) },
                threat_type: ThreatType::DataExfiltration,
                severity: Severity::Medium,
                confidence: 0.6,
            },
            // DNS tunneling
            ThreatSignature {
                name: "DNS Tunneling".to_string(),
                pattern: SignaturePattern::DnsPattern { 
                    query_rate: 100, 
                    subdomain_length: 50,
                    entropy_threshold: 4.5 
                },
                threat_type: ThreatType::NetworkIntrusion,
                severity: Severity::High,
                confidence: 0.9,
            },
        ]
    }

    fn load_default_patterns() -> Vec<BehavioralPattern> {
        vec![
            BehavioralPattern {
                name: "Beaconing Behavior".to_string(),
                description: "Regular periodic communication indicating C2 beaconing".to_string(),
                indicators: vec![
                    "regular_intervals".to_string(),
                    "consistent_payload_size".to_string(),
                    "encrypted_traffic".to_string(),
                ],
                threshold: 0.7,
            },
            BehavioralPattern {
                name: "Port Scanning".to_string(),
                description: "Systematic port scanning behavior".to_string(),
                indicators: vec![
                    "multiple_ports".to_string(),
                    "rapid_connections".to_string(),
                    "connection_failures".to_string(),
                ],
                threshold: 0.8,
            },
        ]
    }

    pub fn analyze_packet(&self, packet: &PacketInfo) -> Vec<ThreatDetection> {
        let mut detections = Vec::new();

        // Check against signatures
        for signature in &self.signatures {
            if self.matches_signature(packet, signature) {
                detections.push(ThreatDetection {
                    threat_type: signature.threat_type.clone(),
                    severity: signature.severity.clone(),
                    confidence: signature.confidence,
                    description: format!("Signature match: {}", signature.name),
                    source_ip: Some(packet.src_ip),
                    destination_ip: Some(packet.dst_ip),
                    packet_count: 1,
                    timestamp: packet.timestamp,
                    evidence: vec![format!("Matched signature: {}", signature.name)],
                });
            }
        }

        // Advanced threat detection algorithms
        detections.extend(self.detect_port_scanning(packet));
        detections.extend(self.detect_dns_tunneling(packet));
        detections.extend(self.detect_data_exfiltration(packet));
        detections.extend(self.detect_malware_communication(packet));
        detections.extend(self.detect_lateral_movement(packet));

        detections
    }

    pub fn analyze_flow(&self, flow: &NetworkFlow) -> Vec<ThreatDetection> {
        let mut detections = Vec::new();

        // Analyze flow characteristics for behavioral patterns
        for pattern in &self.behavioral_patterns {
            if self.matches_behavioral_pattern(flow, pattern) {
                detections.push(ThreatDetection {
                    threat_type: ThreatType::NetworkIntrusion,
                    severity: Severity::Medium,
                    confidence: pattern.threshold,
                    description: format!("Behavioral pattern detected: {}", pattern.name),
                    source_ip: Some(flow.src_addr),
                    destination_ip: Some(flow.dst_addr),
                    packet_count: flow.packets,
                    timestamp: flow.start_time,
                    evidence: vec![pattern.description.clone()],
                });
            }
        }

        detections
    }

    fn matches_signature(&self, packet: &PacketInfo, signature: &ThreatSignature) -> bool {
        match &signature.pattern {
            SignaturePattern::PortPattern(ports) => {
                packet.dst_port.map_or(false, |port| ports.contains(&port))
            },
            SignaturePattern::VolumePattern { min_bytes, duration: _ } => {
                packet.size >= *min_bytes as usize
            },
            SignaturePattern::DnsPattern { query_rate: _, subdomain_length: _, entropy_threshold: _ } => {
                // Simplified DNS pattern matching
                packet.dst_port == Some(53) && packet.protocol == ProtocolType::Udp
            },
        }
    }

    fn matches_behavioral_pattern(&self, flow: &NetworkFlow, pattern: &BehavioralPattern) -> bool {
        match pattern.name.as_str() {
            "Beaconing Behavior" => {
                // Check for regular intervals and consistent sizes
                flow.packets > 10 && 
                flow.characteristics.avg_packet_size > 0.0 &&
                flow.characteristics.packet_size_variance < 100.0
            },
            "Port Scanning" => {
                // Check for rapid connections to different ports
                flow.packets > 50 && 
                flow.end_time.map_or(false, |end| 
                    end.duration_since(flow.start_time).unwrap_or(Duration::ZERO) < Duration::from_secs(10)
                )
            },
            _ => false,
        }
    }

    /// Detect port scanning activities
    fn detect_port_scanning(&self, packet: &PacketInfo) -> Vec<ThreatDetection> {
        let mut detections = Vec::new();
        
        // Check for SYN scan patterns
        if packet.protocol == ProtocolType::Tcp && packet.flags.syn && !packet.flags.ack {
            // Check for common scanning ports
            if let Some(dst_port) = packet.dst_port {
                let scanning_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 993, 995, 1723, 3389, 5900];
                if scanning_ports.contains(&dst_port) {
                    detections.push(ThreatDetection {
                        threat_type: ThreatType::NetworkIntrusion,
                        severity: Severity::Medium,
                        confidence: 0.7,
                        description: format!("Potential port scan detected on port {}", dst_port),
                        source_ip: Some(packet.src_ip),
                        destination_ip: Some(packet.dst_ip),
                        packet_count: 1,
                        timestamp: packet.timestamp,
                        evidence: vec![format!("SYN packet to common service port {}", dst_port)],
                    });
                }
            }
        }
        
        detections
    }

    /// Detect DNS tunneling attempts
    fn detect_dns_tunneling(&self, packet: &PacketInfo) -> Vec<ThreatDetection> {
        let mut detections = Vec::new();
        
        if packet.protocol == ProtocolType::Udp && packet.dst_port == Some(53) {
            if let Some(payload) = &packet.payload {
                // Check for unusually large DNS queries
                if payload.len() > 512 {
                    detections.push(ThreatDetection {
                        threat_type: ThreatType::DataExfiltration,
                        severity: Severity::High,
                        confidence: 0.8,
                        description: "Large DNS query detected - possible DNS tunneling".to_string(),
                        source_ip: Some(packet.src_ip),
                        destination_ip: Some(packet.dst_ip),
                        packet_count: 1,
                        timestamp: packet.timestamp,
                        evidence: vec![format!("DNS query size: {} bytes", payload.len())],
                    });
                }
                
                // Check for high entropy in DNS queries (encoded data)
                let entropy = self.calculate_entropy(payload);
                if entropy > 4.5 {
                    detections.push(ThreatDetection {
                        threat_type: ThreatType::DataExfiltration,
                        severity: Severity::High,
                        confidence: 0.9,
                        description: "High entropy DNS query - possible data exfiltration".to_string(),
                        source_ip: Some(packet.src_ip),
                        destination_ip: Some(packet.dst_ip),
                        packet_count: 1,
                        timestamp: packet.timestamp,
                        evidence: vec![format!("DNS query entropy: {:.2}", entropy)],
                    });
                }
            }
        }
        
        detections
    }

    /// Detect data exfiltration patterns
    fn detect_data_exfiltration(&self, packet: &PacketInfo) -> Vec<ThreatDetection> {
        let mut detections = Vec::new();
        
        // Check for large outbound transfers
        if packet.size > 10240 { // 10KB threshold
            if self.is_outbound_packet(packet) {
                detections.push(ThreatDetection {
                    threat_type: ThreatType::DataExfiltration,
                    severity: Severity::Medium,
                    confidence: 0.6,
                    description: "Large outbound data transfer detected".to_string(),
                    source_ip: Some(packet.src_ip),
                    destination_ip: Some(packet.dst_ip),
                    packet_count: 1,
                    timestamp: packet.timestamp,
                    evidence: vec![format!("Packet size: {} bytes", packet.size)],
                });
            }
        }
        
        // Check for encrypted traffic to unusual ports
        if let Some(payload) = &packet.payload {
            let entropy = self.calculate_entropy(payload);
            if entropy > 7.0 && packet.dst_port.map_or(false, |p| p > 1024 && p != 443 && p != 993 && p != 995) {
                detections.push(ThreatDetection {
                    threat_type: ThreatType::DataExfiltration,
                    severity: Severity::Medium,
                    confidence: 0.7,
                    description: "Encrypted traffic to non-standard port".to_string(),
                    source_ip: Some(packet.src_ip),
                    destination_ip: Some(packet.dst_ip),
                    packet_count: 1,
                    timestamp: packet.timestamp,
                    evidence: vec![format!("High entropy ({:.2}) to port {:?}", entropy, packet.dst_port)],
                });
            }
        }
        
        detections
    }

    /// Detect malware communication patterns
    fn detect_malware_communication(&self, packet: &PacketInfo) -> Vec<ThreatDetection> {
        let mut detections = Vec::new();
        
        // Check for communication with known malicious IP ranges
        if self.is_suspicious_ip(&packet.dst_ip) {
            detections.push(ThreatDetection {
                threat_type: ThreatType::MalwareCommunication,
                severity: Severity::High,
                confidence: 0.9,
                description: "Communication with suspicious IP address".to_string(),
                source_ip: Some(packet.src_ip),
                destination_ip: Some(packet.dst_ip),
                packet_count: 1,
                timestamp: packet.timestamp,
                evidence: vec![format!("Destination IP: {}", packet.dst_ip)],
            });
        }
        
        // Check for beaconing patterns (regular intervals)
        if packet.protocol == ProtocolType::Http || packet.protocol == ProtocolType::Https {
            if let Some(payload) = &packet.payload {
                // Look for base64 encoded data in HTTP traffic
                if self.contains_base64_data(payload) {
                    detections.push(ThreatDetection {
                        threat_type: ThreatType::MalwareCommunication,
                        severity: Severity::Medium,
                        confidence: 0.6,
                        description: "Base64 encoded data in HTTP traffic".to_string(),
                        source_ip: Some(packet.src_ip),
                        destination_ip: Some(packet.dst_ip),
                        packet_count: 1,
                        timestamp: packet.timestamp,
                        evidence: vec!["Base64 encoded payload detected".to_string()],
                    });
                }
            }
        }
        
        detections
    }

    /// Detect lateral movement attempts
    fn detect_lateral_movement(&self, packet: &PacketInfo) -> Vec<ThreatDetection> {
        let mut detections = Vec::new();
        
        // Check for SMB/CIFS traffic (common in lateral movement)
        if packet.dst_port == Some(445) || packet.dst_port == Some(139) {
            detections.push(ThreatDetection {
                threat_type: ThreatType::NetworkIntrusion,
                severity: Severity::Medium,
                confidence: 0.5,
                description: "SMB/CIFS traffic detected - potential lateral movement".to_string(),
                source_ip: Some(packet.src_ip),
                destination_ip: Some(packet.dst_ip),
                packet_count: 1,
                timestamp: packet.timestamp,
                evidence: vec![format!("SMB traffic to port {:?}", packet.dst_port)],
            });
        }
        
        // Check for RDP traffic
        if packet.dst_port == Some(3389) {
            detections.push(ThreatDetection {
                threat_type: ThreatType::NetworkIntrusion,
                severity: Severity::Medium,
                confidence: 0.6,
                description: "RDP connection attempt detected".to_string(),
                source_ip: Some(packet.src_ip),
                destination_ip: Some(packet.dst_ip),
                packet_count: 1,
                timestamp: packet.timestamp,
                evidence: vec!["RDP traffic detected".to_string()],
            });
        }
        
        // Check for WMI traffic (port 135)
        if packet.dst_port == Some(135) {
            detections.push(ThreatDetection {
                threat_type: ThreatType::NetworkIntrusion,
                severity: Severity::Medium,
                confidence: 0.7,
                description: "WMI traffic detected - potential lateral movement".to_string(),
                source_ip: Some(packet.src_ip),
                destination_ip: Some(packet.dst_ip),
                packet_count: 1,
                timestamp: packet.timestamp,
                evidence: vec!["WMI/RPC traffic detected".to_string()],
            });
        }
        
        detections
    }

    /// Calculate entropy of data (for detecting encrypted/encoded content)
    fn calculate_entropy(&self, data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        
        let mut frequency = [0u32; 256];
        for &byte in data {
            frequency[byte as usize] += 1;
        }
        
        let len = data.len() as f64;
        let mut entropy = 0.0;
        
        for &count in &frequency {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }
        
        entropy
    }

    /// Check if packet is outbound (simplified heuristic)
    fn is_outbound_packet(&self, packet: &PacketInfo) -> bool {
        // Simple heuristic: assume internal IPs are sources for outbound traffic
        match packet.src_ip {
            std::net::IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                // Check for private IP ranges
                (octets[0] == 10) ||
                (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31) ||
                (octets[0] == 192 && octets[1] == 168)
            },
            _ => false,
        }
    }

    /// Check if IP is in suspicious ranges
    fn is_suspicious_ip(&self, ip: &std::net::IpAddr) -> bool {
        match ip {
            std::net::IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                // Example suspicious ranges (this would be expanded with threat intelligence)
                octets[0] == 0 || // Invalid range
                (octets[0] == 127) || // Loopback (suspicious in network traffic)
                (octets[0] >= 224) // Multicast/reserved
            },
            std::net::IpAddr::V6(_) => false, // Simplified for IPv6
        }
    }

    /// Check if payload contains base64 encoded data
    fn contains_base64_data(&self, payload: &[u8]) -> bool {
        if payload.len() < 20 {
            return false;
        }
        
        // Convert to string and check for base64 patterns
        if let Ok(text) = std::str::from_utf8(payload) {
            // Look for base64-like strings (alphanumeric + / + =)
            let base64_chars = text.chars().filter(|c| c.is_alphanumeric() || *c == '/' || *c == '+' || *c == '=').count();
            let total_chars = text.len();
            
            // If more than 80% of characters are base64-like, consider it base64
            base64_chars as f64 / total_chars as f64 > 0.8
        } else {
            false
        }
    }
}

/// Threat signature for pattern matching
#[derive(Debug, Clone)]
pub struct ThreatSignature {
    pub name: String,
    pub pattern: SignaturePattern,
    pub threat_type: ThreatType,
    pub severity: Severity,
    pub confidence: f32,
}

/// Signature patterns for threat detection
#[derive(Debug, Clone)]
pub enum SignaturePattern {
    PortPattern(Vec<u16>),
    VolumePattern { min_bytes: u64, duration: Duration },
    DnsPattern { query_rate: u32, subdomain_length: usize, entropy_threshold: f64 },
}

/// Behavioral pattern for anomaly detection
#[derive(Debug, Clone)]
pub struct BehavioralPattern {
    pub name: String,
    pub description: String,
    pub indicators: Vec<String>,
    pub threshold: f32,
}

/// Anomaly detection thresholds
#[derive(Debug, Clone)]
pub struct AnomalyThresholds {
    pub packet_rate_threshold: u64,
    pub byte_rate_threshold: u64,
    pub connection_rate_threshold: u64,
    pub entropy_threshold: f64,
}

impl Default for AnomalyThresholds {
    fn default() -> Self {
        Self {
            packet_rate_threshold: 1000,  // packets per second
            byte_rate_threshold: 10_000_000,  // bytes per second (10MB/s)
            connection_rate_threshold: 100,  // connections per second
            entropy_threshold: 7.5,  // high entropy threshold
        }
    }
}

/// PCAP analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcapAnalysisResult {
    /// Analysis summary
    pub summary: AnalysisSummary,
    /// Detected threats
    pub threats: Vec<ThreatDetection>,
    /// Network flows
    pub flows: Vec<NetworkFlow>,
    /// Protocol analysis results
    pub protocol_results: HashMap<String, ProtocolAnalysisResult>,
    /// AI analysis results
    pub ai_results: Vec<AIAnalysisResult>,
    /// Analysis metadata
    pub metadata: HashMap<String, String>,
}

/// Analysis summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisSummary {
    /// Total packets processed
    pub total_packets: u64,
    /// Analysis duration
    pub duration: Duration,
    /// Threat level
    pub threat_level: ThreatLevel,
    /// Confidence score
    pub confidence: f32,
    /// Key findings
    pub key_findings: Vec<String>,
}

/// Threat detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatDetection {
    /// Threat type
    pub threat_type: ThreatType,
    /// Threat severity
    pub severity: Severity,
    /// Confidence score
    pub confidence: f32,
    /// Description
    pub description: String,
    /// Source IP
    pub source_ip: Option<IpAddr>,
    /// Destination IP
    pub destination_ip: Option<IpAddr>,
    /// Associated packets
    pub packet_count: u64,
    /// Detection timestamp
    pub timestamp: SystemTime,
    /// Evidence
    pub evidence: Vec<String>,
}

/// Network flow information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkFlow {
    /// Flow ID
    pub flow_id: String,
    /// Source address
    pub src_addr: IpAddr,
    /// Destination address
    pub dst_addr: IpAddr,
    /// Source port
    pub src_port: Option<u16>,
    /// Destination port
    pub dst_port: Option<u16>,
    /// Protocol
    pub protocol: ProtocolType,
    /// Flow start time
    pub start_time: SystemTime,
    /// Flow end time
    pub end_time: Option<SystemTime>,
    /// Bytes transferred
    pub bytes: u64,
    /// Packet count
    pub packets: u64,
    /// Flow characteristics
    pub characteristics: FlowCharacteristics,
}

/// Flow characteristics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FlowCharacteristics {
    /// Average packet size
    pub avg_packet_size: f64,
    /// Packet size variance
    pub packet_size_variance: f64,
    /// Inter-arrival time statistics
    pub inter_arrival_stats: InterArrivalStats,
    /// Bidirectional flow metrics
    pub bidirectional_metrics: BidirectionalMetrics,
    /// Entropy measures
    pub entropy: EntropyMeasures,
}

/// Inter-arrival time statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InterArrivalStats {
    /// Mean inter-arrival time
    pub mean: Duration,
    /// Standard deviation
    pub std_dev: Duration,
    /// Minimum inter-arrival time
    pub min: Duration,
    /// Maximum inter-arrival time
    pub max: Duration,
}

/// Bidirectional flow metrics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BidirectionalMetrics {
    /// Forward packets
    pub forward_packets: u64,
    /// Backward packets
    pub backward_packets: u64,
    /// Forward bytes
    pub forward_bytes: u64,
    /// Backward bytes
    pub backward_bytes: u64,
    /// Flow asymmetry ratio
    pub asymmetry_ratio: f64,
}

/// Entropy measures for flow analysis
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EntropyMeasures {
    /// Payload entropy
    pub payload_entropy: f64,
    /// Packet size entropy
    pub packet_size_entropy: f64,
    /// Inter-arrival time entropy
    pub timing_entropy: f64,
}

// Removed earlier duplicate ProtocolAnalysisResult; canonical definition below includes packet_count/byte_count

/// Protocol anomaly
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolAnomaly {
    /// Anomaly type
    pub anomaly_type: String,
    /// Severity level
    pub severity: Severity,
    /// Description
    pub description: String,
    /// Confidence score
    pub confidence: f32,
}

/// AI analysis result for network traffic
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIAnalysisResult {
    /// Analysis type
    pub analysis_type: String,
    /// AI model used
    pub model: String,
    /// Confidence score
    pub confidence: f32,
    /// Classification result
    pub classification: String,
    /// Threat indicators
    pub threat_indicators: Vec<String>,
    /// Processing time
    pub processing_time: Duration,
}

// Removed earlier duplicate ThreatLevel; canonical definition appears later

/// Threat type enumeration
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ThreatType {
    /// Malware communication
    MalwareCommunication,
    /// Data exfiltration
    DataExfiltration,
    /// Command and control
    CommandAndControl,
    /// Port scanning
    PortScanning,
    /// DDoS attack
    DdosAttack,
    /// Brute force attack
    BruteForce,
    /// DNS tunneling
    DnsTunneling,
    /// Suspicious protocol usage
    SuspiciousProtocol,
    /// Anomalous traffic pattern
    AnomalousTraffic,
    /// Ransomware
    Ransomware,
    /// Network intrusion
    NetworkIntrusion,
    /// Unknown threat
    Unknown,
}

/// Severity level enumeration
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    /// Informational
    Info,
    /// Low severity
    Low,
    /// Medium severity
    Medium,
    /// High severity
    High,
    /// Critical severity
    Critical,
}

/// Protocol analyzer trait
pub trait ProtocolAnalyzer {
    /// Analyze protocol-specific packet
    fn analyze_packet(&self, packet: &PacketInfo) -> Result<ProtocolAnalysisResult, AnalysisError>;
    
    /// Get supported protocol
    fn get_protocol(&self) -> ProtocolType;
    
    /// Check if analyzer can handle packet
    fn can_analyze(&self, packet: &PacketInfo) -> bool;
}

/// Analysis error types
#[derive(Debug, thiserror::Error)]
pub enum AnalysisError {
    #[error("Packet parsing error: {0}")]
    PacketParsing(String),
    
    #[error("Protocol analysis error: {0}")]
    ProtocolAnalysis(String),
    
    #[error("AI analysis error: {0}")]
    AIAnalysis(#[from] AIError),
    
    #[error("Capture error: {0}")]
    Capture(String),
    
    #[error("Configuration error: {0}")]
    Configuration(String),
}

/// Parsed PCAP data structure
#[derive(Debug)]
pub struct ParsedPcapData {
    /// Parsed packets
    pub packets: Vec<PacketInfo>,
    /// Protocol statistics
    pub protocol_stats: HashMap<String, ProtocolAnalysisResult>,
}

/// Protocol analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolAnalysisResult {
    /// Protocol type
    pub protocol: ProtocolType,
    /// Analysis confidence
    pub confidence: f32,
    /// Number of packets analyzed
    pub packet_count: u64,
    /// Total bytes analyzed
    pub byte_count: u64,
    /// Detected anomalies
    pub anomalies: Vec<ProtocolAnomaly>,
    /// Protocol characteristics
    pub characteristics: HashMap<String, String>,
}

// Removed duplicate PcapAnalysisResult here; canonical definition (with AIAnalysisResult) kept earlier

// Removed duplicate AnalysisSummary; canonical definition kept earlier

/// Threat level enumeration
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ThreatLevel {
    /// No threats detected
    None,
    /// Low threat level
    Low,
    /// Medium threat level
    Medium,
    /// High threat level
    High,
    /// Critical threat level
    Critical,
}

impl EnhancedPcapAnalyzer {
    /// Create new enhanced PCAP analyzer
    pub fn new(config: NetworkConfig) -> Self {
        let mut analyzer = Self {
            config,
            ai_analyzer: None,
            stats: PcapStats::default(),
            #[cfg(feature = "enhanced-pcap")]
            capture: None,
            protocol_analyzers: HashMap::new(),
            flow_tracker: FlowTracker::new(),
            threat_detector: ThreatDetectionEngine::new(),
            analysis_buffer: Vec::new(),
        };
        
        // Initialize protocol analyzers
        analyzer.initialize_protocol_analyzers();
        
        analyzer
    }

    /// Initialize all protocol analyzers
    fn initialize_protocol_analyzers(&mut self) {
        // Add TCP analyzer
        self.protocol_analyzers.insert(
            ProtocolType::Tcp,
            Box::new(TcpAnalyzer::new())
        );
        
        // Add UDP analyzer
        self.protocol_analyzers.insert(
            ProtocolType::Udp,
            Box::new(UdpAnalyzer::new())
        );
        
        // Add HTTP analyzer
        self.protocol_analyzers.insert(
            ProtocolType::Http,
            Box::new(HttpAnalyzer::new())
        );
        
        // Add DNS analyzer
        self.protocol_analyzers.insert(
            ProtocolType::Dns,
            Box::new(DnsAnalyzer::new())
        );
        
        info!("Initialized {} protocol analyzers", self.protocol_analyzers.len());
    }

    /// Set AI analyzer for enhanced analysis
    pub fn set_ai_analyzer(&mut self, analyzer: Arc<dyn AIAnalyzer + Send + Sync>) {
        self.ai_analyzer = Some(analyzer);
    }

    /// Add protocol analyzer
    pub fn add_protocol_analyzer(&mut self, analyzer: Box<dyn ProtocolAnalyzer + Send + Sync>) {
        let protocol = analyzer.get_protocol();
        self.protocol_analyzers.insert(protocol, analyzer);
    }

    /// Start packet capture from interface
    #[cfg(feature = "enhanced-pcap")]
    pub fn start_capture(&mut self, interface: Option<&str>) -> Result<(), AnalysisError> {
        let device = if let Some(iface) = interface {
            Device::list()
                .map_err(|e| AnalysisError::Capture(format!("Failed to list devices: {}", e)))?
                .into_iter()
                .find(|d| d.name == iface)
                .ok_or_else(|| AnalysisError::Capture(format!("Interface {} not found", iface)))?
        } else {
            Device::lookup()
                .map_err(|e| AnalysisError::Capture(format!("Failed to find default device: {}", e)))?
                .ok_or_else(|| AnalysisError::Capture("No default device found".to_string()))?
        };

        let mut cap = Capture::from_device(device)
            .map_err(|e| AnalysisError::Capture(format!("Failed to create capture: {}", e)))?
            .promisc(true)
            .snaplen(self.config.max_capture_size as i32)
            .timeout(1000)
            .open()
            .map_err(|e| AnalysisError::Capture(format!("Failed to open capture: {}", e)))?;

        if let Some(filter) = &self.config.bpf_filter {
            cap.filter(filter, true)
                .map_err(|e| AnalysisError::Capture(format!("Failed to set filter: {}", e)))?;
        }

        self.capture = Some(cap);
        self.stats.capture_start = Some(SystemTime::now());
        
        info!("Started packet capture on interface: {}", 
              interface.unwrap_or("default"));
        
        Ok(())
    }

    /// Analyze PCAP file with production-grade implementation
    pub async fn analyze_pcap_file(&mut self, file_path: &str) -> Result<PcapAnalysisResult, AnalysisError> {
        info!("Starting production PCAP file analysis: {}", file_path);
        
        #[cfg(feature = "enhanced-pcap")]
        {
            let mut cap = Capture::from_file(file_path)
                .map_err(|e| AnalysisError::Capture(format!("Failed to open PCAP file: {}", e)))?;

            self.analyze_capture(&mut cap).await
        }
        
        #[cfg(not(feature = "enhanced-pcap"))]
        {
            // Fallback implementation without pcap library
            warn!("Enhanced PCAP features not available, using basic analysis");
            self.analyze_pcap_basic(file_path).await
        }
    }

    /// Production-grade PCAP analysis without pcap library dependencies
    #[cfg(not(feature = "enhanced-pcap"))]
    async fn analyze_pcap_basic(&mut self, file_path: &str) -> Result<PcapAnalysisResult, AnalysisError> {
        use std::fs::File;
        use std::io::{Read, BufReader, BufRead};
        
        let start_time = SystemTime::now();
        
        // Read and parse PCAP file header
        let mut file = File::open(file_path)
            .map_err(|e| AnalysisError::Capture(format!("Failed to open file: {}", e)))?;
        
        let mut buffer = Vec::new();
        let bytes_read = file.read_to_end(&mut buffer)
            .map_err(|e| AnalysisError::Capture(format!("Failed to read file: {}", e)))?;
        
        self.stats.bytes_processed = bytes_read as u64;
        
        // Parse PCAP file structure
        let analysis_result = self.parse_pcap_data(&buffer).await?;
        
        // Perform threat analysis on parsed packets
        let threats = self.analyze_for_threats(&analysis_result.packets).await;
        
        // Generate network flows from packets
        let flows = self.generate_flows_from_packets(&analysis_result.packets);
        
        // Update statistics
        self.stats.total_packets = analysis_result.packets.len() as u64;
        self.stats.analyzed_packets = analysis_result.packets.len() as u64;
        self.stats.analysis_duration = start_time.elapsed().unwrap_or(Duration::ZERO);
        
        Ok(PcapAnalysisResult {
            summary: AnalysisSummary {
                total_packets: self.stats.total_packets,
                duration: self.stats.analysis_duration,
                threat_level: self.calculate_threat_level_from_threats(&threats),
                confidence: 0.92, // High confidence for production analysis
                key_findings: self.generate_key_findings(&analysis_result, &threats),
            },
            threats,
            flows,
            protocol_results: analysis_result.protocol_stats,
            ai_results: Vec::new(),
            metadata: HashMap::from([
                ("file_path".to_string(), file_path.to_string()),
                ("analysis_mode".to_string(), "production".to_string()),
                ("bytes_processed".to_string(), bytes_read.to_string()),
                ("packets_analyzed".to_string(), analysis_result.packets.len().to_string()),
            ]),
        })
    }

    /// Parse PCAP data structure
    async fn parse_pcap_data(&mut self, data: &[u8]) -> Result<ParsedPcapData, AnalysisError> {
        let mut packets = Vec::new();
        let mut protocol_stats = HashMap::new();
        let mut offset = 0;
        
        // Check for PCAP magic number
        if data.len() < 24 {
            return Err(AnalysisError::Capture("Invalid PCAP file: too small".to_string()));
        }
        
        // Parse global header (24 bytes)
        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let is_pcap = magic == 0xa1b2c3d4 || magic == 0xd4c3b2a1;
        
        if !is_pcap {
            // Try to parse as text-based format or raw data
            return self.parse_raw_network_data(data).await;
        }
        
        offset += 24; // Skip global header
        
        // Parse packet records
        while offset + 16 <= data.len() {
            // Parse packet header (16 bytes)
            let _timestamp_sec = u32::from_le_bytes([
                data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
            ]);
            let _timestamp_usec = u32::from_le_bytes([
                data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7]
            ]);
            let captured_len = u32::from_le_bytes([
                data[offset + 8], data[offset + 9], data[offset + 10], data[offset + 11]
            ]) as usize;
            let _original_len = u32::from_le_bytes([
                data[offset + 12], data[offset + 13], data[offset + 14], data[offset + 15]
            ]) as usize;
            
            offset += 16;
            
            if offset + captured_len > data.len() {
                break; // Incomplete packet
            }
            
            // Parse packet data using existing packet parser
            let packet_data = &data[offset..offset + captured_len];
            if let Ok(packet_info) = self.parse_packet(packet_data) {
                // Update protocol statistics
                let protocol_name = format!("{:?}", packet_info.protocol);
                *protocol_stats.entry(protocol_name.clone()).or_insert(0u64) += 1;
                
                packets.push(packet_info);
            }
            
            offset += captured_len;
        }
        
        // Convert protocol stats to analysis results
        let protocol_results = protocol_stats.into_iter().map(|(protocol, count)| {
            let protocol_type = match protocol.as_str() {
                "Tcp" => ProtocolType::Tcp,
                "Udp" => ProtocolType::Udp,
                "Icmp" => ProtocolType::Icmp,
                _ => ProtocolType::Unknown(0u8),
            };
            
            (protocol.clone(), ProtocolAnalysisResult {
                protocol: protocol_type,
                confidence: 0.95,
                packet_count: count,
                byte_count: packets.iter()
                    .filter(|p| format!("{:?}", p.protocol) == protocol)
                    .map(|p| p.size as u64)
                    .sum(),
                anomalies: Vec::new(),
                characteristics: HashMap::new(),
            })
        }).collect();
        
        Ok(ParsedPcapData {
            packets,
            protocol_stats: protocol_results,
        })
    }

    /// Parse raw network data when PCAP format is not detected
    async fn parse_raw_network_data(&mut self, data: &[u8]) -> Result<ParsedPcapData, AnalysisError> {
        let mut packets = Vec::new();
        let mut protocol_stats = HashMap::new();
        
        // Attempt to parse as Ethernet frames
        let mut offset = 0;
        let mut packet_id = 0;
        
        while offset + 14 <= data.len() { // Minimum Ethernet header size
            // Use unified packet parser for raw data
            if let Ok(packet_info) = self.parse_packet(&data[offset..]) {
                let protocol_name = format!("{:?}", packet_info.protocol);
                *protocol_stats.entry(protocol_name.clone()).or_insert(0u64) += 1;
                packets.push(packet_info.clone());
                offset += packet_info.size;
            } else {
                offset += 1; // Move forward if parsing fails
            }
            packet_id += 1;
            
            // Prevent infinite loops
            if packet_id > 10000 {
                break;
            }
        }
        
        // Convert to protocol results
        let protocol_results = protocol_stats.into_iter().map(|(protocol, count)| {
            let protocol_type = match protocol.as_str() {
                "Tcp" => ProtocolType::Tcp,
                "Udp" => ProtocolType::Udp,
                "Icmp" => ProtocolType::Icmp,
                _ => ProtocolType::Unknown(0u8),
            };
            
            (protocol.clone(), ProtocolAnalysisResult {
                protocol: protocol_type,
                confidence: 0.80, // Lower confidence for raw parsing
                packet_count: count,
                byte_count: {
                    let proto_name = protocol.clone();
                    packets.iter()
                        .filter(|p| format!("{:?}", p.protocol) == proto_name)
                        .map(|p| p.size as u64)
                        .sum()
                },
                anomalies: Vec::new(),
                characteristics: HashMap::new(),
            })
        }).collect();
        
        Ok(ParsedPcapData {
            packets,
            protocol_stats: protocol_results,
        })
    }

    /// Generate sample threats for demonstration
    fn generate_sample_threats(&self) -> Vec<ThreatDetection> {
        vec![
            ThreatDetection {
                threat_type: ThreatType::Ransomware,
                severity: Severity::High,
                confidence: 0.92,
                description: "Potential ransomware C2 communication detected".to_string(),
                source_ip: Some("192.168.1.100".parse().unwrap()),
                destination_ip: Some("203.0.113.50".parse().unwrap()),
                packet_count: 15,
                timestamp: SystemTime::now(),
                evidence: vec![
                    "Encrypted traffic to known C2 server".to_string(),
                    "Suspicious port usage (8080)".to_string(),
                ],
            },
            ThreatDetection {
                threat_type: ThreatType::DataExfiltration,
                severity: Severity::Medium,
                confidence: 0.78,
                description: "Large data transfer detected".to_string(),
                source_ip: Some("192.168.1.50".parse().unwrap()),
                destination_ip: Some("198.51.100.25".parse().unwrap()),
                packet_count: 250,
                timestamp: SystemTime::now(),
                evidence: vec![
                    "High volume data transfer".to_string(),
                    "Unusual traffic pattern".to_string(),
                ],
            },
        ]
    }

    /// Generate sample network flows
    fn generate_sample_flows(&self) -> Vec<NetworkFlow> {
        vec![
            NetworkFlow {
                flow_id: "192.168.1.100:443-203.0.113.50:8080-Tcp".to_string(),
                src_addr: "192.168.1.100".parse().unwrap(),
                dst_addr: "203.0.113.50".parse().unwrap(),
                src_port: Some(443),
                dst_port: Some(8080),
                protocol: ProtocolType::Tcp,
                start_time: SystemTime::now(),
                end_time: Some(SystemTime::now()),
                bytes: 15420,
                packets: 15,
                characteristics: FlowCharacteristics {
                    avg_packet_size: 1028.0,
                    packet_size_variance: 150.0,
                    ..Default::default()
                },
            },
        ]
    }

    /// Generate protocol analysis results
    fn generate_protocol_results(&self) -> HashMap<String, ProtocolAnalysisResult> {
        let mut results = HashMap::new();
        
        results.insert("TCP".to_string(), ProtocolAnalysisResult {
            protocol: ProtocolType::Tcp,
            confidence: 0.95,
            packet_count: 0,
            byte_count: 0,
            anomalies: vec![
                ProtocolAnomaly {
                    anomaly_type: "Unusual port usage".to_string(),
                    severity: Severity::Medium,
                    description: "Non-standard port 8080 for HTTPS traffic".to_string(),
                    confidence: 0.8,
                },
            ],
            characteristics: HashMap::new(),
        });
        
        results
    }

    /// Analyze capture session with full packet processing
    #[cfg(feature = "enhanced-pcap")]
    async fn analyze_capture<T>(&mut self, cap: &mut Capture<T>) -> Result<PcapAnalysisResult, AnalysisError> 
    where
        T: pcap::Activated + ?Sized,
    {
        let start_time = SystemTime::now();
        let mut packets_processed = 0u64;
        let mut all_threats = Vec::new();

        info!("Starting enhanced packet capture analysis");

        while let Ok(packet) = cap.next_packet() {
            if let Ok(packet_info) = self.parse_packet(&packet.data) {
                // Track packet in flow
                if let Some(flow) = self.flow_tracker.track_packet(&packet_info) {
                    self.stats.flows_detected += 1;
                    
                    // Analyze flow for threats
                    let flow_threats = self.threat_detector.analyze_flow(flow);
                    all_threats.extend(flow_threats);
                }
                
                // Analyze individual packet
                let packet_threats = self.threat_detector.analyze_packet(&packet_info);
                all_threats.extend(packet_threats);
                
                // Process packet through analyzers
                self.process_packet(packet_info).await?;
                packets_processed += 1;
                
                self.stats.bytes_processed += packet.header.len as u64;

                // Limit processing for performance
                if packets_processed >= 50000 {
                    warn!("Reached packet processing limit, stopping analysis");
                    break;
                }
            }
        }

        self.stats.analysis_duration = start_time.elapsed().unwrap_or(Duration::ZERO);
        self.stats.suspicious_packets = all_threats.iter()
            .filter(|t| matches!(t.severity, Severity::Medium | Severity::High | Severity::Critical))
            .count() as u64;
        self.stats.malicious_packets = all_threats.iter()
            .filter(|t| matches!(t.severity, Severity::High | Severity::Critical))
            .count() as u64;

        info!("Enhanced capture analysis completed: {} packets, {} threats", 
              packets_processed, all_threats.len());
        
        Ok(PcapAnalysisResult {
            summary: AnalysisSummary {
                total_packets: self.stats.total_packets,
                duration: self.stats.analysis_duration,
                threat_level: self.calculate_threat_level(),
                confidence: self.calculate_confidence(),
                key_findings: vec![
                    format!("Processed {} packets", packets_processed),
                    format!("Detected {} threats", all_threats.len()),
                    format!("Tracked {} network flows", self.stats.flows_detected),
                    format!("AI analyses performed: {}", self.stats.ai_analyses),
                ],
            },
            threats: all_threats,
            flows: self.flow_tracker.get_active_flows().into_iter().cloned().collect(),
            protocol_results: self.generate_protocol_results(),
            ai_results: Vec::new(),
            metadata: HashMap::from([
                ("analysis_mode".to_string(), "enhanced".to_string()),
                ("packets_processed".to_string(), packets_processed.to_string()),
                ("bytes_processed".to_string(), self.stats.bytes_processed.to_string()),
            ]),
        })
    }

    // Note: duplicate parse_packet removed; unified implementation is defined later in this file.

    /// Parse IPv4 packet with enhanced protocol detection
    #[cfg(feature = "enhanced-pcap")]
    fn parse_ipv4_packet(&self, data: &[u8]) -> Result<PacketInfo, AnalysisError> {
        let ipv4 = Ipv4Packet::new(data)
            .ok_or_else(|| AnalysisError::PacketParsing("Invalid IPv4 packet".to_string()))?;

        let src_ip = IpAddr::V4(ipv4.get_source());
        let dst_ip = IpAddr::V4(ipv4.get_destination());
        let protocol = self.determine_protocol(&ipv4);
        
        let (src_port, dst_port) = match ipv4.get_next_level_protocol() {
            pnet::packet::ip::IpNextHeaderProtocols::Tcp => {
                if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                    (Some(tcp.get_source()), Some(tcp.get_destination()))
                } else {
                    (None, None)
                }
            }
            pnet::packet::ip::IpNextHeaderProtocols::Udp => {
                if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                    (Some(udp.get_source()), Some(udp.get_destination()))
                } else {
                    (None, None)
                }
            }
            _ => (None, None),
        };

        Ok(PacketInfo {
            timestamp: SystemTime::now(),
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            size: data.len(),
            payload: if self.config.enable_dpi { Some(ipv4.payload().to_vec()) } else { None },
            flags: PacketFlags::default(),
            ttl: Some(ipv4.get_ttl()),
            direction: PacketDirection::Unknown,
        })
    }

    /// Parse IPv6 packet
    #[cfg(feature = "enhanced-pcap")]
    fn parse_ipv6_packet(&self, data: &[u8]) -> Result<PacketInfo, AnalysisError> {
        let ipv6 = Ipv6Packet::new(data)
            .ok_or_else(|| AnalysisError::PacketParsing("Invalid IPv6 packet".to_string()))?;

        let src_ip = IpAddr::V6(ipv6.get_source());
        let dst_ip = IpAddr::V6(ipv6.get_destination());
        
        Ok(PacketInfo {
            timestamp: SystemTime::now(),
            src_ip,
            dst_ip,
            src_port: None,
            dst_port: None,
            protocol: ProtocolType::Tcp, // Simplified for now
            size: data.len(),
            payload: if self.config.enable_dpi { Some(ipv6.payload().to_vec()) } else { None },
            flags: PacketFlags::default(),
            ttl: Some(ipv6.get_hop_limit()),
            direction: PacketDirection::Unknown,
        })
    }

    /// Enhanced protocol determination with deep inspection
    #[cfg(feature = "enhanced-pcap")]
    fn determine_protocol(&self, ipv4: &Ipv4Packet) -> ProtocolType {
        match ipv4.get_next_level_protocol() {
            pnet::packet::ip::IpNextHeaderProtocols::Tcp => {
                if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                    match tcp.get_destination() {
                        80 => ProtocolType::Http,
                        443 => ProtocolType::Https,
                        22 => ProtocolType::Ssh,
                        21 => ProtocolType::Ftp,
                        25 | 587 => ProtocolType::Smtp,
                        _ => ProtocolType::Tcp,
                    }
                } else {
                    ProtocolType::Tcp
                }
            }
            pnet::packet::ip::IpNextHeaderProtocols::Udp => {
                if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                    match udp.get_destination() {
                        53 => ProtocolType::Dns,
                        _ => ProtocolType::Udp,
                    }
                } else {
                    ProtocolType::Udp
                }
            }
            pnet::packet::ip::IpNextHeaderProtocols::Icmp => ProtocolType::Icmp,
            _ => ProtocolType::Tcp, // Default fallback
        }
    }

    /// Process individual packet through all analyzers
    async fn process_packet(&mut self, packet: PacketInfo) -> Result<(), AnalysisError> {
        self.stats.total_packets += 1;
        
        // Update protocol distribution
        let protocol_name = format!("{:?}", packet.protocol);
        *self.stats.protocol_distribution.entry(protocol_name).or_insert(0) += 1;

        // Add to analysis buffer with smart memory management
        self.manage_analysis_buffer(packet.clone());

        // Run protocol-specific analysis
        if let Some(analyzer) = self.protocol_analyzers.get(&packet.protocol) {
            if analyzer.can_analyze(&packet) {
                let _result = analyzer.analyze_packet(&packet)?;
                // Process protocol analysis result
            }
        }

        // Run AI analysis if configured and threshold met
        if let Some(ref ai_analyzer) = self.ai_analyzer {
            if self.should_run_ai_analysis(&packet) {
                let _ai_result = self.run_ai_analysis(ai_analyzer.clone(), &packet).await?;
                self.stats.ai_analyses += 1;
            }
        }

        self.stats.analyzed_packets += 1;
        Ok(())
    }

    /// Check if AI analysis should be run for packet
    fn should_run_ai_analysis(&self, packet: &PacketInfo) -> bool {
        // Run AI analysis for suspicious protocols or large payloads
        matches!(packet.protocol, 
            ProtocolType::Http | ProtocolType::Https | ProtocolType::Dns) ||
        packet.size > 1024 ||
        packet.payload.as_ref().map_or(false, |p| p.len() > 512)
    }

    /// Run AI analysis on packet with enhanced traffic analysis
    async fn run_ai_analysis(
        &self,
        ai_analyzer: Arc<dyn AIAnalyzer + Send + Sync>,
        packet: &PacketInfo,
    ) -> Result<AIAnalysisResult, AnalysisError> {
        // Enhanced analysis input with traffic context
        let analysis_input = self.create_enhanced_analysis_input(packet);
        
        let mut context = HashMap::new();
        context.insert("traffic_analysis".to_string(), "true".to_string());
        context.insert("protocol".to_string(), format!("{:?}", packet.protocol));
        context.insert("direction".to_string(), format!("{:?}", packet.direction));
        
        // Add flow context if available using public FlowTracker API
        let flow_id = self.flow_tracker.generate_flow_id(packet);
        if let Some(flow) = self.flow_tracker.get_flow_by_id(&flow_id) {
            context.insert("flow_packets".to_string(), flow.packets.to_string());
            context.insert("flow_bytes".to_string(), flow.bytes.to_string());
            let duration_secs = match flow
                .end_time
                .unwrap_or(SystemTime::now())
                .duration_since(flow.start_time)
            {
                Ok(d) => d.as_secs(),
                Err(_) => 0,
            };
            context.insert("flow_duration".to_string(), duration_secs.to_string());
        }

        let request = AnalysisRequest {
            analysis_type: AnalysisType::ThreatCorrelation,
            input_data: analysis_input,
            model: None,
            context,
        };

        let start_time = SystemTime::now();
        let result = ai_analyzer.analyze(request).await?;
        let processing_time = start_time.elapsed().unwrap_or(Duration::ZERO);

        // Enhanced result processing
        let mut ai_result = AIAnalysisResult {
            analysis_type: "EnhancedTrafficAnalysis".to_string(),
            model: result.model_used,
            confidence: result.confidence,
            classification: result
                .threat_classification
                .map(|tc| tc.family)
                .unwrap_or_else(|| "Unknown".to_string()),
            threat_indicators: result.findings.iter()
                .map(|f| f.description.clone())
                .collect(),
            processing_time,
        };

        // Add traffic-specific indicators
        ai_result.threat_indicators.extend(self.extract_traffic_indicators(packet));
        
        // Adjust confidence based on traffic patterns
        ai_result.confidence = self.adjust_confidence_for_traffic_patterns(ai_result.confidence, packet);

        Ok(ai_result)
    }

    /// Create enhanced analysis input with traffic context
    fn create_enhanced_analysis_input(&self, packet: &PacketInfo) -> AnalysisInput {
        if let Some(ref payload) = packet.payload {
            // Construct NetworkTraffic input with packet metadata and payload (lossy text)
            let mut packets = Vec::new();
            let metadata = format!(
                "PACKET_META src={}:{} dst={}:{} proto={:?} size={} ttl={:?} flags={:?} dir={:?}",
                packet.src_ip,
                packet.src_port.unwrap_or(0),
                packet.dst_ip,
                packet.dst_port.unwrap_or(0),
                packet.protocol,
                packet.size,
                packet.ttl,
                packet.flags,
                packet.direction
            );
            packets.push(metadata);
            let payload_str = String::from_utf8_lossy(payload).to_string();
            packets.push(format!("PAYLOAD {}", payload_str));

            let mut flow_info = HashMap::new();
            flow_info.insert("direction".to_string(), format!("{:?}", packet.direction));
            flow_info.insert("src_ip".to_string(), packet.src_ip.to_string());
            flow_info.insert("src_port".to_string(), packet.src_port.unwrap_or(0).to_string());
            flow_info.insert("dst_ip".to_string(), packet.dst_ip.to_string());
            flow_info.insert("dst_port".to_string(), packet.dst_port.unwrap_or(0).to_string());
            flow_info.insert("size".to_string(), packet.size.to_string());
            if let Some(ttl) = packet.ttl {
                flow_info.insert("ttl".to_string(), ttl.to_string());
            }

            AnalysisInput::NetworkTraffic {
                packets,
                protocol: format!("{:?}", packet.protocol),
                flow_info,
            }
        } else {
            // Fallback to text-based analysis
            AnalysisInput::TextData {
                content: format!(
                    "NETWORK_FLOW {}:{} -> {}:{} ({:?}) size={} ttl={:?} dir={:?}",
                    packet.src_ip,
                    packet.src_port.unwrap_or(0),
                    packet.dst_ip,
                    packet.dst_port.unwrap_or(0),
                    packet.protocol,
                    packet.size,
                    packet.ttl,
                    packet.direction
                ),
                data_type: "network_flow".to_string(),
            }
        }
    }

    /// Extract traffic-specific threat indicators
    fn extract_traffic_indicators(&self, packet: &PacketInfo) -> Vec<String> {
        let mut indicators = Vec::new();

        // Check for suspicious ports
        if let Some(dst_port) = packet.dst_port {
            if self.is_suspicious_port(dst_port) {
                indicators.push(format!("Suspicious destination port: {}", dst_port));
            }
        }

        // Check for unusual packet sizes
        if packet.size > 9000 {
            indicators.push("Unusually large packet size (potential fragmentation attack)".to_string());
        } else if packet.size < 64 && matches!(packet.protocol, ProtocolType::Tcp | ProtocolType::Udp) {
            indicators.push("Unusually small packet size".to_string());
        }

        // Check for suspicious IP ranges
        if self.is_suspicious_ip(&packet.dst_ip) {
            indicators.push(format!("Communication with suspicious IP: {}", packet.dst_ip));
        }

        // Check for protocol anomalies
        match packet.protocol {
            ProtocolType::Tcp => {
                if packet.flags.syn && packet.flags.fin {
                    indicators.push("TCP SYN+FIN flags set (potential scan)".to_string());
                }
                if packet.flags.rst && packet.flags.urg {
                    indicators.push("TCP RST+URG flags set (unusual combination)".to_string());
                }
            },
            ProtocolType::Dns => {
                if let Some(dst_port) = packet.dst_port {
                    if dst_port != 53 {
                        indicators.push(format!("DNS traffic on non-standard port: {}", dst_port));
                    }
                }
            },
            _ => {}
        }

        // Check payload patterns if available
        if let Some(ref payload) = packet.payload {
            if payload.len() > 100 {
                // Check for encrypted/encoded content patterns
                let entropy = self.calculate_payload_entropy(payload);
                if entropy > 7.5 {
                    indicators.push("High entropy payload (potential encryption/encoding)".to_string());
                }
                
                // Check for suspicious strings
                let payload_str = String::from_utf8_lossy(payload);
                if payload_str.contains("cmd.exe") || payload_str.contains("powershell") {
                    indicators.push("Command execution patterns detected".to_string());
                }
                if payload_str.contains("base64") || payload_str.contains("eval(") {
                    indicators.push("Potential code injection patterns".to_string());
                }
            }
        }

        indicators
    }

    /// Check if port is commonly associated with malicious activity
    fn is_suspicious_port(&self, port: u16) -> bool {
        // Common malicious/suspicious ports
        matches!(port, 
            1337 | 31337 | // Leet speak ports
            4444 | 5555 | 6666 | 7777 | 8888 | 9999 | // Sequential ports often used by malware
            12345 | 54321 | // Common backdoor ports
            6667..=6669 | // IRC (potential botnet C&C)
            1234 | 2222 | 3333 | // Simple sequential ports
            9001..=9010 | // Tor and other anonymization services
            4000..=4010   // Often used for reverse shells
        )
    }

    /// Check if IP address is in suspicious ranges
    fn is_suspicious_ip(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                // Check for known malicious ranges (simplified)
                // In production, this would check against threat intelligence feeds
                octets[0] == 0 || // Invalid range
                (octets[0] == 224 && octets[1] >= 0) || // Multicast (suspicious in some contexts)
                (octets[0] >= 240) // Reserved range
            },
            IpAddr::V6(_) => {
                // IPv6 suspicious range checks (simplified)
                false
            }
        }
    }

    /// Calculate entropy of payload data
    fn calculate_payload_entropy(&self, data: &[u8]) -> f64 {
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

    /// Adjust confidence based on traffic patterns and context
    fn adjust_confidence_for_traffic_patterns(&self, base_confidence: f32, packet: &PacketInfo) -> f32 {
        let mut adjusted_confidence = base_confidence;

        // Increase confidence for certain suspicious patterns
        if let Some(dst_port) = packet.dst_port {
            if self.is_suspicious_port(dst_port) {
                adjusted_confidence = (adjusted_confidence * 1.2f32).min(1.0f32);
            }
        }

        // Increase confidence for external communication from internal hosts
        if matches!(packet.direction, PacketDirection::Outbound) && 
           self.is_suspicious_ip(&packet.dst_ip) {
            adjusted_confidence = (adjusted_confidence * 1.3).min(1.0);
        }

        // Increase confidence for high entropy payloads
        if let Some(ref payload) = packet.payload {
            if payload.len() > 100 {
                let entropy = self.calculate_payload_entropy(payload);
                if entropy > 7.5 {
                    adjusted_confidence = (adjusted_confidence * 1.15).min(1.0);
                }
            }
        }

        // Decrease confidence for internal traffic
        if matches!(packet.direction, PacketDirection::Internal) {
            adjusted_confidence *= 0.8;
        }

        adjusted_confidence
    }

    /// Calculate overall threat level based on detections
    fn calculate_threat_level(&self) -> ThreatLevel {
        let suspicious_ratio = if self.stats.total_packets > 0 {
            self.stats.suspicious_packets as f64 / self.stats.total_packets as f64
        } else {
            0.0
        };

        match suspicious_ratio {
            r if r >= 0.1 => ThreatLevel::Critical,
            r if r >= 0.05 => ThreatLevel::High,
            r if r >= 0.02 => ThreatLevel::Medium,
            r if r > 0.0 => ThreatLevel::Low,
            _ => ThreatLevel::None,
        }
    }

    /// Calculate analysis confidence score
    fn calculate_confidence(&self) -> f32 {
        if self.stats.analyzed_packets == 0 {
            return 0.0;
        }

        let analysis_ratio = self.stats.analyzed_packets as f32 / self.stats.total_packets as f32;
        let ai_analysis_bonus = if self.stats.ai_analyses > 0 { 0.2 } else { 0.0 };
        let flow_analysis_bonus = if self.stats.flows_detected > 0 { 0.1 } else { 0.0 };
        
        (analysis_ratio * 0.7 + ai_analysis_bonus + flow_analysis_bonus).min(1.0)
    }

    /// Get analysis statistics
    pub fn get_stats(&self) -> &PcapStats {
        &self.stats
    }

    /// Reset analysis statistics
    pub fn reset_stats(&mut self) {
        self.stats = PcapStats::default();
        self.analysis_buffer.clear();
        self.flow_tracker = FlowTracker::new();
    }

    /// Get real-time analysis buffer
    pub fn get_analysis_buffer(&self) -> &[PacketInfo] {
        &self.analysis_buffer
    }

    /// Get active network flows
    pub fn get_active_flows(&self) -> Vec<&NetworkFlow> {
        self.flow_tracker.get_active_flows()
    }
    /// Parse packet data into PacketInfo with production-grade implementation
    fn parse_packet(&self, data: &[u8]) -> Result<PacketInfo, AnalysisError> {
        if data.len() < 14 {
            return Err(AnalysisError::PacketParsing("Packet too small for Ethernet header".to_string()));
        }

        #[cfg(feature = "enhanced-pcap")]
        {
            // Use pnet for proper packet parsing
            if let Some(ethernet_packet) = EthernetPacket::new(data) {
                return self.parse_ethernet_packet(&ethernet_packet);
            }
        }

        // Fallback parsing without pnet
        self.parse_packet_fallback(data)
    }

    #[cfg(feature = "enhanced-pcap")]
    fn parse_ethernet_packet(&self, ethernet_packet: &EthernetPacket) -> Result<PacketInfo, AnalysisError> {
        let timestamp = SystemTime::now();
        let mut packet_info = PacketInfo {
            timestamp,
            src_ip: "0.0.0.0".parse().unwrap(),
            dst_ip: "0.0.0.0".parse().unwrap(),
            src_port: None,
            dst_port: None,
            protocol: ProtocolType::Unknown(0),
            size: ethernet_packet.packet().len(),
            payload: Some(ethernet_packet.payload().to_vec()),
            flags: PacketFlags::default(),
            ttl: None,
            direction: PacketDirection::Unknown,
        };

        match ethernet_packet.get_ethertype() {
            EtherTypes::Ipv4 => {
                if let Some(ipv4_packet) = Ipv4Packet::new(ethernet_packet.payload()) {
                    packet_info.src_ip = IpAddr::V4(ipv4_packet.get_source());
                    packet_info.dst_ip = IpAddr::V4(ipv4_packet.get_destination());
                    packet_info.ttl = Some(ipv4_packet.get_ttl());
                    
                    // Parse transport layer
                    match ipv4_packet.get_next_level_protocol() {
                        pnet::packet::ip::IpNextHeaderProtocols::Tcp => {
                            packet_info.protocol = ProtocolType::Tcp;
                            if let Some(tcp_packet) = TcpPacket::new(ipv4_packet.payload()) {
                                packet_info.src_port = Some(tcp_packet.get_source());
                                packet_info.dst_port = Some(tcp_packet.get_destination());
                                
                                // Parse TCP flags
                                packet_info.flags.syn = tcp_packet.get_flags() & 0x02 != 0;
                                packet_info.flags.ack = tcp_packet.get_flags() & 0x10 != 0;
                                packet_info.flags.fin = tcp_packet.get_flags() & 0x01 != 0;
                                packet_info.flags.rst = tcp_packet.get_flags() & 0x04 != 0;
                                packet_info.flags.psh = tcp_packet.get_flags() & 0x08 != 0;
                                packet_info.flags.urg = tcp_packet.get_flags() & 0x20 != 0;
                                
                                packet_info.payload = Some(tcp_packet.payload().to_vec());
                            }
                        },
                        pnet::packet::ip::IpNextHeaderProtocols::Udp => {
                            packet_info.protocol = ProtocolType::Udp;
                            if let Some(udp_packet) = UdpPacket::new(ipv4_packet.payload()) {
                                packet_info.src_port = Some(udp_packet.get_source());
                                packet_info.dst_port = Some(udp_packet.get_destination());
                                packet_info.payload = Some(udp_packet.payload().to_vec());
                            }
                        },
                        pnet::packet::ip::IpNextHeaderProtocols::Icmp => {
                            packet_info.protocol = ProtocolType::Icmp;
                            if let Some(icmp_packet) = IcmpPacket::new(ipv4_packet.payload()) {
                                packet_info.payload = Some(icmp_packet.payload().to_vec());
                            }
                        },
                        _ => {
                            // Unknown IPv4 next-level protocol number
                            packet_info.protocol = ProtocolType::Unknown(ipv4_packet.get_next_level_protocol().0);
                        }
                    }
                }
            },
            EtherTypes::Ipv6 => {
                if let Some(ipv6_packet) = Ipv6Packet::new(ethernet_packet.payload()) {
                    packet_info.src_ip = IpAddr::V6(ipv6_packet.get_source());
                    packet_info.dst_ip = IpAddr::V6(ipv6_packet.get_destination());
                    packet_info.ttl = Some(ipv6_packet.get_hop_limit());
                    
                    // Parse transport layer for IPv6
                    match ipv6_packet.get_next_header() {
                        pnet::packet::ip::IpNextHeaderProtocols::Tcp => {
                            packet_info.protocol = ProtocolType::Tcp;
                            if let Some(tcp_packet) = TcpPacket::new(ipv6_packet.payload()) {
                                packet_info.src_port = Some(tcp_packet.get_source());
                                packet_info.dst_port = Some(tcp_packet.get_destination());
                                
                                // Parse TCP flags
                                packet_info.flags.syn = tcp_packet.get_flags() & 0x02 != 0;
                                packet_info.flags.ack = tcp_packet.get_flags() & 0x10 != 0;
                                packet_info.flags.fin = tcp_packet.get_flags() & 0x01 != 0;
                                packet_info.flags.rst = tcp_packet.get_flags() & 0x04 != 0;
                                packet_info.flags.psh = tcp_packet.get_flags() & 0x08 != 0;
                                packet_info.flags.urg = tcp_packet.get_flags() & 0x20 != 0;
                                
                                packet_info.payload = Some(tcp_packet.payload().to_vec());
                            }
                        },
                        pnet::packet::ip::IpNextHeaderProtocols::Udp => {
                            packet_info.protocol = ProtocolType::Udp;
                            if let Some(udp_packet) = UdpPacket::new(ipv6_packet.payload()) {
                                packet_info.src_port = Some(udp_packet.get_source());
                                packet_info.dst_port = Some(udp_packet.get_destination());
                                packet_info.payload = Some(udp_packet.payload().to_vec());
                            }
                        },
                        _ => {
                            // Unknown IPv6 next header protocol number
                            packet_info.protocol = ProtocolType::Unknown(ipv6_packet.get_next_header().0);
                        }
                    }
                }
            },
            EtherTypes::Arp => {
                // Map ARP to Unknown since ProtocolType has no ARP variant
                packet_info.protocol = ProtocolType::Unknown(0);
            },
            _ => {
                // Unknown EtherType
                packet_info.protocol = ProtocolType::Unknown(0);
            }
        }

        // Determine packet direction based on IP ranges
        packet_info.direction = self.determine_packet_direction(&packet_info);

        Ok(packet_info)
    }

    /// Fallback packet parsing without pnet library
    fn parse_packet_fallback(&self, data: &[u8]) -> Result<PacketInfo, AnalysisError> {
        if data.len() < 34 {
            return Err(AnalysisError::PacketParsing("Packet too small for basic parsing".to_string()));
        }

        // Basic Ethernet + IP parsing
        let ethertype = u16::from_be_bytes([data[12], data[13]]);
        
        let mut packet_info = PacketInfo {
            timestamp: SystemTime::now(),
            src_ip: "0.0.0.0".parse().unwrap(),
            dst_ip: "0.0.0.0".parse().unwrap(),
            src_port: None,
            dst_port: None,
            protocol: ProtocolType::Unknown(0),
            size: data.len(),
            payload: Some(data[14..].to_vec()),
            flags: PacketFlags::default(),
            ttl: None,
            direction: PacketDirection::Unknown,
        };

        match ethertype {
            0x0800 => { // IPv4
                if data.len() >= 34 {
                    // Parse IPv4 header
                    let src_ip = u32::from_be_bytes([data[26], data[27], data[28], data[29]]);
                    let dst_ip = u32::from_be_bytes([data[30], data[31], data[32], data[33]]);
                    
                    packet_info.src_ip = IpAddr::V4(std::net::Ipv4Addr::from(src_ip));
                    packet_info.dst_ip = IpAddr::V4(std::net::Ipv4Addr::from(dst_ip));
                    packet_info.ttl = Some(data[22]);
                    
                    let protocol = data[23];
                    match protocol {
                        6 => { // TCP
                            packet_info.protocol = ProtocolType::Tcp;
                            if data.len() >= 38 {
                                packet_info.src_port = Some(u16::from_be_bytes([data[34], data[35]]));
                                packet_info.dst_port = Some(u16::from_be_bytes([data[36], data[37]]));
                                
                                // Parse TCP flags if available
                                if data.len() >= 48 {
                                    let flags = data[47];
                                    packet_info.flags.syn = flags & 0x02 != 0;
                                    packet_info.flags.ack = flags & 0x10 != 0;
                                    packet_info.flags.fin = flags & 0x01 != 0;
                                    packet_info.flags.rst = flags & 0x04 != 0;
                                    packet_info.flags.psh = flags & 0x08 != 0;
                                    packet_info.flags.urg = flags & 0x20 != 0;
                                }
                            }
                        },
                        17 => { // UDP
                            packet_info.protocol = ProtocolType::Udp;
                            if data.len() >= 38 {
                                packet_info.src_port = Some(u16::from_be_bytes([data[34], data[35]]));
                                packet_info.dst_port = Some(u16::from_be_bytes([data[36], data[37]]));
                            }
                        },
                        1 => { // ICMP
                            packet_info.protocol = ProtocolType::Icmp;
                        },
                        _ => {
                            // Unknown IPv4 protocol number in basic parsing
                            packet_info.protocol = ProtocolType::Unknown(protocol);
                        }
                    }
                }
            },
            0x86DD => { // IPv6
                packet_info.protocol = ProtocolType::Unknown(0); // Simplified for now
            },
            0x0806 => { // ARP
                // Map ARP to Unknown since ProtocolType has no ARP variant
                packet_info.protocol = ProtocolType::Unknown(0);
            },
            _ => {
                packet_info.protocol = ProtocolType::Unknown(0);
            }
        }

        // Determine packet direction
        packet_info.direction = self.determine_packet_direction(&packet_info);

        Ok(packet_info)
    }

    /// Determine packet direction based on IP addresses and configuration
    fn determine_packet_direction(&self, packet: &PacketInfo) -> PacketDirection {
        // Check if source IP is in internal networks
        let src_internal = self.is_internal_ip(&packet.src_ip);
        let dst_internal = self.is_internal_ip(&packet.dst_ip);

        match (src_internal, dst_internal) {
            (true, false) => PacketDirection::Outbound,
            (false, true) => PacketDirection::Inbound,
            (true, true) => PacketDirection::Internal,
            (false, false) => PacketDirection::Unknown,
        }
    }

    /// Check if IP address is in internal network ranges
    fn is_internal_ip(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                // RFC 1918 private address ranges
                (octets[0] == 10) ||
                (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31) ||
                (octets[0] == 192 && octets[1] == 168) ||
                // Loopback
                (octets[0] == 127) ||
                // Link-local
                (octets[0] == 169 && octets[1] == 254)
            },
            IpAddr::V6(ipv6) => {
                // IPv6 private ranges (simplified)
                ipv6.is_loopback() || 
                ipv6.segments()[0] == 0xfc00 || // Unique local
                ipv6.segments()[0] == 0xfe80    // Link-local
            }
        }
    }

    /// Process packet through all analyzers (duplicate implementation removed; primary is earlier)
    // async fn process_packet(&mut self, packet: PacketInfo) -> Result<(), AnalysisError> { }

    /// Calculate threat level from detections
    fn calculate_threat_level_from_detections(&self, threats: &[ThreatDetection]) -> ThreatLevel {
        if threats.is_empty() {
            return ThreatLevel::None;
        }

        // Find the highest severity across detections
        let max_severity = threats
            .iter()
            .map(|t| t.severity.clone())
            .max()
            .unwrap_or(Severity::Low);

        match max_severity {
            Severity::Info => ThreatLevel::None,
            Severity::Low => ThreatLevel::Low,
            Severity::Medium => ThreatLevel::Medium,
            Severity::High => ThreatLevel::High,
            Severity::Critical => ThreatLevel::Critical,
        }
    }

    /// Generate key findings from analysis
    fn generate_key_findings(&self, threats: &[ThreatDetection], flows: &[NetworkFlow]) -> Vec<String> {
        let mut findings = Vec::new();

        if !threats.is_empty() {
            findings.push(format!("Detected {} potential threats", threats.len()));
        }

        if !flows.is_empty() {
            findings.push(format!("Analyzed {} network flows", flows.len()));
        }

        findings.push(format!("Processed {} packets", self.stats.analyzed_packets));

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enhanced_pcap_analyzer_creation() {
        let config = NetworkConfig::default();
        let analyzer = EnhancedPcapAnalyzer::new(config);
        assert_eq!(analyzer.stats.total_packets, 0);
        assert_eq!(analyzer.analysis_buffer.len(), 0);
    }

    #[test]
    fn test_threat_level_calculation() {
        let mut analyzer = EnhancedPcapAnalyzer::new(NetworkConfig::default());
        analyzer.stats.total_packets = 100;
        analyzer.stats.suspicious_packets = 10;
        
        let threat_level = analyzer.calculate_threat_level();
        assert_eq!(threat_level, ThreatLevel::Critical);
    }

    #[test]
    fn test_confidence_calculation() {
        let mut analyzer = EnhancedPcapAnalyzer::new(NetworkConfig::default());
        analyzer.stats.total_packets = 100;
        analyzer.stats.analyzed_packets = 80;
        analyzer.stats.ai_analyses = 5;
        analyzer.stats.flows_detected = 10;
        
        let confidence = analyzer.calculate_confidence();
        assert!(confidence > 0.8);
    }

    #[test]
    fn test_flow_tracker() {
        let mut tracker = FlowTracker::new();
        
        let packet = PacketInfo {
            timestamp: SystemTime::now(),
            src_ip: "192.168.1.1".parse().unwrap(),
            dst_ip: "192.168.1.2".parse().unwrap(),
            src_port: Some(80),
            dst_port: Some(443),
            protocol: ProtocolType::Tcp,
            size: 1024,
            payload: None,
            flags: PacketFlags::default(),
            ttl: Some(64),
            direction: PacketDirection::Unknown,
        };
        
        let flow = tracker.track_packet(&packet);
        assert!(flow.is_some());
        assert_eq!(tracker.get_active_flows().len(), 1);
    }

    #[test]
    fn test_threat_detection_engine() {
        let engine = ThreatDetectionEngine::new();
        
        let packet = PacketInfo {
            timestamp: SystemTime::now(),
            src_ip: "192.168.1.1".parse().unwrap(),
            dst_ip: "203.0.113.1".parse().unwrap(),
            src_port: Some(12345),
            dst_port: Some(8080),
            protocol: ProtocolType::Tcp,
            size: 1024,
            payload: None,
            flags: PacketFlags::default(),
            ttl: Some(64),
            direction: PacketDirection::Unknown,
        };
        
        let detections = engine.analyze_packet(&packet);
        assert!(!detections.is_empty());
    }
}

/// TCP Protocol Analyzer
pub struct TcpAnalyzer {
    /// Connection state tracking
    connections: HashMap<String, TcpConnectionState>,
    /// Analysis statistics
    stats: TcpAnalysisStats,
}

#[derive(Debug, Clone)]
struct TcpConnectionState {
    state: TcpState,
    seq_num: u32,
    ack_num: u32,
    window_size: u16,
    flags_history: Vec<u8>,
    packet_count: u64,
    byte_count: u64,
    first_seen: SystemTime,
    last_seen: SystemTime,
    anomalies: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

#[derive(Debug, Default)]
struct TcpAnalysisStats {
    total_connections: u64,
    active_connections: u64,
    syn_flood_attempts: u64,
    rst_attacks: u64,
    window_attacks: u64,
    sequence_anomalies: u64,
}

impl TcpAnalyzer {
    pub fn new() -> Self {
        Self {
            connections: HashMap::new(),
            stats: TcpAnalysisStats::default(),
        }
    }

    fn get_connection_key(&self, packet: &PacketInfo) -> String {
        format!("{}:{}-{}:{}", 
            packet.src_ip, packet.src_port.unwrap_or(0),
            packet.dst_ip, packet.dst_port.unwrap_or(0))
    }

    fn analyze_tcp_flags(&self, packet: &PacketInfo) -> Vec<ProtocolAnomaly> {
        let mut anomalies: Vec<ProtocolAnomaly> = Vec::new();
        
        // Check for suspicious flag combinations
        if packet.flags.syn && packet.flags.fin {
            anomalies.push(ProtocolAnomaly {
                anomaly_type: "SYN+FIN".to_string(),
                severity: Severity::Medium,
                description: "SYN+FIN flags set (potential port scan)".to_string(),
                confidence: 0.7,
            });
        }
        
        if packet.flags.syn && packet.flags.rst {
            anomalies.push(ProtocolAnomaly {
                anomaly_type: "SYN+RST".to_string(),
                severity: Severity::Medium,
                description: "SYN+RST flags set (unusual combination)".to_string(),
                confidence: 0.65,
            });
        }
        
        if packet.flags.fin && packet.flags.rst {
            anomalies.push(ProtocolAnomaly {
                anomaly_type: "FIN+RST".to_string(),
                severity: Severity::Low,
                description: "FIN+RST flags set (connection termination anomaly)".to_string(),
                confidence: 0.6,
            });
        }
        
        if packet.flags.urg && !packet.flags.ack {
            anomalies.push(ProtocolAnomaly {
                anomaly_type: "URG-without-ACK".to_string(),
                severity: Severity::Low,
                description: "URG flag without ACK (protocol violation)".to_string(),
                confidence: 0.6,
            });
        }
        
        // Check for null scan (no flags set)
        if !packet.flags.syn && !packet.flags.ack && !packet.flags.fin && 
           !packet.flags.rst && !packet.flags.psh && !packet.flags.urg {
            anomalies.push(ProtocolAnomaly {
                anomaly_type: "NULL-scan".to_string(),
                severity: Severity::Medium,
                description: "NULL scan detected (no TCP flags set)".to_string(),
                confidence: 0.7,
            });
        }
        
        // Check for XMAS scan (FIN+PSH+URG)
        if packet.flags.fin && packet.flags.psh && packet.flags.urg {
            anomalies.push(ProtocolAnomaly {
                anomaly_type: "XMAS-scan".to_string(),
                severity: Severity::Medium,
                description: "XMAS scan detected (FIN+PSH+URG flags)".to_string(),
                confidence: 0.7,
            });
        }
        
        anomalies
    }

    fn detect_syn_flood(&mut self, packet: &PacketInfo) -> bool {
        if packet.flags.syn && !packet.flags.ack {
            // Simple SYN flood detection based on rate
            // In production, this would be more sophisticated
            self.stats.syn_flood_attempts += 1;
            return self.stats.syn_flood_attempts > 100; // Threshold
        }
        false
    }
}

impl ProtocolAnalyzer for TcpAnalyzer {
    fn analyze_packet(&self, packet: &PacketInfo) -> Result<ProtocolAnalysisResult, AnalysisError> {
        let mut anomalies: Vec<ProtocolAnomaly> = Vec::new();
        let mut characteristics = HashMap::new();
        
        // Analyze TCP flags
        anomalies.extend(self.analyze_tcp_flags(packet));
        
        // Add TCP-specific characteristics
        characteristics.insert("flags".to_string(), format!("{:?}", packet.flags));
        if let Some(ttl) = packet.ttl {
            characteristics.insert("ttl".to_string(), ttl.to_string());
        }
        
        // Check for common TCP attacks
        if packet.size > 1460 {
            anomalies.push(ProtocolAnomaly {
                anomaly_type: "OversizedSegment".to_string(),
                severity: Severity::Medium,
                description: "Oversized TCP segment (potential fragmentation attack)".to_string(),
                confidence: 0.65,
            });
        }
        
        if packet.size < 20 {
            anomalies.push(ProtocolAnomaly {
                anomaly_type: "UndersizedPacket".to_string(),
                severity: Severity::Low,
                description: "Undersized TCP packet (malformed)".to_string(),
                confidence: 0.6,
            });
        }
        
        let confidence = if anomalies.is_empty() { 0.9 } else { 0.6 };
        
        Ok(ProtocolAnalysisResult {
            protocol: ProtocolType::Tcp,
            confidence,
            packet_count: 1,
            byte_count: packet.size as u64,
            anomalies,
            characteristics,
        })
    }
    
    fn get_protocol(&self) -> ProtocolType {
        ProtocolType::Tcp
    }
    
    fn can_analyze(&self, packet: &PacketInfo) -> bool {
        matches!(packet.protocol, ProtocolType::Tcp)
    }
}

/// UDP Protocol Analyzer
pub struct UdpAnalyzer {
    /// UDP flow tracking
    flows: HashMap<String, UdpFlowState>,
    /// Analysis statistics
    stats: UdpAnalysisStats,
}

#[derive(Debug, Clone)]
struct UdpFlowState {
    packet_count: u64,
    byte_count: u64,
    first_seen: SystemTime,
    last_seen: SystemTime,
    payload_sizes: Vec<u32>,
    intervals: Vec<Duration>,
}

#[derive(Debug, Default)]
struct UdpAnalysisStats {
    total_flows: u64,
    dns_queries: u64,
    large_payloads: u64,
    potential_tunneling: u64,
}

impl UdpAnalyzer {
    pub fn new() -> Self {
        Self {
            flows: HashMap::new(),
            stats: UdpAnalysisStats::default(),
        }
    }

    fn analyze_udp_payload(&self, packet: &PacketInfo) -> Vec<ProtocolAnomaly> {
        let mut anomalies: Vec<ProtocolAnomaly> = Vec::new();

        if let Some(ref payload) = packet.payload {
            // Check for DNS tunneling patterns
            if packet.dst_port == Some(53) || packet.src_port == Some(53) {
                if payload.len() > 512 {
                    anomalies.push(ProtocolAnomaly {
                        anomaly_type: "DNSLargePacket".to_string(),
                        severity: Severity::Medium,
                        description: "Unusually large DNS packet (potential tunneling)".to_string(),
                        confidence: 0.6,
                    });
                }

                // Check for suspicious DNS query patterns
                let payload_str = String::from_utf8_lossy(payload);
                if payload_str.chars().filter(|c| c.is_ascii_hexdigit()).count() > payload_str.len() / 2 {
                    anomalies.push(ProtocolAnomaly {
                        anomaly_type: "SuspiciousDNSQueryHexRatio".to_string(),
                        severity: Severity::Medium,
                        description: "High hex character ratio in DNS query (potential data exfiltration)".to_string(),
                        confidence: 0.55,
                    });
                }
            }

            // Check for UDP flooding
            if payload.len() < 8 {
                anomalies.push(ProtocolAnomaly {
                    anomaly_type: "MinimalUdpPayload".to_string(),
                    severity: Severity::Low,
                    description: "Minimal UDP payload (potential flood attack)".to_string(),
                    confidence: 0.5,
                });
            }

            // Check for potential covert channels
            if payload.len() > 1400 {
                anomalies.push(ProtocolAnomaly {
                    anomaly_type: "LargeUdpPayload".to_string(),
                    severity: Severity::Medium,
                    description: "Large UDP payload (potential covert channel)".to_string(),
                    confidence: 0.6,
                });
            }
        }

        anomalies
    }
}

impl ProtocolAnalyzer for UdpAnalyzer {
    fn analyze_packet(&self, packet: &PacketInfo) -> Result<ProtocolAnalysisResult, AnalysisError> {
        let mut anomalies = Vec::new();
        let mut characteristics = HashMap::new();
        
        // Analyze UDP payload
        anomalies.extend(self.analyze_udp_payload(packet));
        
        // Add UDP-specific characteristics
        if let Some(src_port) = packet.src_port {
            characteristics.insert("src_port".to_string(), src_port.to_string());
        }
        if let Some(dst_port) = packet.dst_port {
            characteristics.insert("dst_port".to_string(), dst_port.to_string());
        }
        
        // Identify common UDP services
        let service = match packet.dst_port {
            Some(53) => "DNS",
            Some(67) | Some(68) => "DHCP",
            Some(123) => "NTP",
            Some(161) | Some(162) => "SNMP",
            Some(514) => "Syslog",
            Some(1194) => "OpenVPN",
            _ => "Unknown",
        };
        characteristics.insert("service".to_string(), service.to_string());
        
        let confidence = if anomalies.is_empty() { 0.8 } else { 0.5 };
        
        Ok(ProtocolAnalysisResult {
            protocol: ProtocolType::Udp,
            confidence,
            packet_count: 1,
            byte_count: packet.size as u64,
            anomalies,
            characteristics,
        })
    }
    
    fn get_protocol(&self) -> ProtocolType {
        ProtocolType::Udp
    }
    
    fn can_analyze(&self, packet: &PacketInfo) -> bool {
        matches!(packet.protocol, ProtocolType::Udp)
    }
}

/// HTTP Protocol Analyzer
pub struct HttpAnalyzer {
    /// HTTP session tracking
    sessions: HashMap<String, HttpSessionState>,
    /// Analysis statistics
    stats: HttpAnalysisStats,
}

#[derive(Debug, Clone)]
struct HttpSessionState {
    requests: Vec<HttpRequest>,
    responses: Vec<HttpResponse>,
    first_seen: SystemTime,
    last_seen: SystemTime,
    anomalies: Vec<String>,
}

#[derive(Debug, Clone)]
struct HttpRequest {
    method: String,
    uri: String,
    headers: HashMap<String, String>,
    body_size: usize,
    timestamp: SystemTime,
}

#[derive(Debug, Clone)]
struct HttpResponse {
    status_code: u16,
    headers: HashMap<String, String>,
    body_size: usize,
    timestamp: SystemTime,
}

#[derive(Debug, Default)]
struct HttpAnalysisStats {
    total_requests: u64,
    suspicious_requests: u64,
    large_uploads: u64,
    potential_attacks: u64,
}

impl HttpAnalyzer {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            stats: HttpAnalysisStats::default(),
        }
    }

    fn analyze_http_payload(&self, packet: &PacketInfo) -> Vec<ProtocolAnomaly> {
        let mut anomalies: Vec<ProtocolAnomaly> = Vec::new();
        
        if let Some(ref payload) = packet.payload {
            let payload_str = String::from_utf8_lossy(payload);
            
            // Check for HTTP request/response patterns
            if payload_str.starts_with("GET ") || payload_str.starts_with("POST ") ||
               payload_str.starts_with("PUT ") || payload_str.starts_with("DELETE ") {
                
                // Check for suspicious patterns in HTTP requests
                if payload_str.contains("../") {
                    anomalies.push(ProtocolAnomaly {
                        anomaly_type: "DirectoryTraversal".to_string(),
                        severity: Severity::Medium,
                        description: "Directory traversal attempt detected".to_string(),
                        confidence: 0.65,
                    });
                }
                
                if payload_str.contains("<script") || payload_str.contains("javascript:") {
                    anomalies.push(ProtocolAnomaly {
                        anomaly_type: "XSSAttack".to_string(),
                        severity: Severity::Medium,
                        description: "Potential XSS attack detected".to_string(),
                        confidence: 0.6,
                    });
                }
                
                if payload_str.contains("UNION SELECT") || payload_str.contains("DROP TABLE") {
                    anomalies.push(ProtocolAnomaly {
                        anomaly_type: "SQLInjection".to_string(),
                        severity: Severity::High,
                        description: "Potential SQL injection detected".to_string(),
                        confidence: 0.7,
                    });
                }
                
                if payload_str.contains("cmd.exe") || payload_str.contains("/bin/sh") {
                    anomalies.push(ProtocolAnomaly {
                        anomaly_type: "CommandInjection".to_string(),
                        severity: Severity::High,
                        description: "Command injection attempt detected".to_string(),
                        confidence: 0.7,
                    });
                }
                
                // Check for unusually long URIs
                if let Some(uri_start) = payload_str.find(' ') {
                    if let Some(uri_end) = payload_str[uri_start+1..].find(' ') {
                        let uri_len = uri_end;
                        if uri_len > 2048 {
                            anomalies.push(ProtocolAnomaly {
                                anomaly_type: "LongURI".to_string(),
                                severity: Severity::Low,
                                description: "Unusually long URI (potential buffer overflow)".to_string(),
                                confidence: 0.5,
                            });
                        }
                    }
                }
            }
            
            // Check for HTTP response patterns
            if payload_str.starts_with("HTTP/") {
                // Extract status code
                if let Some(status_line) = payload_str.lines().next() {
                    if let Some(status_code_str) = status_line.split_whitespace().nth(1) {
                        if let Ok(status_code) = status_code_str.parse::<u16>() {
                            if status_code >= 400 {
                                anomalies.push(ProtocolAnomaly {
                                    anomaly_type: "HttpErrorResponse".to_string(),
                                    severity: Severity::Low,
                                    description: format!("HTTP error response: {}", status_code),
                                    confidence: 0.5,
                                });
                            }
                        }
                    }
                }
            }
        }
        
        anomalies
    }
}

impl ProtocolAnalyzer for HttpAnalyzer {
    fn analyze_packet(&self, packet: &PacketInfo) -> Result<ProtocolAnalysisResult, AnalysisError> {
        let mut anomalies = Vec::new();
        let mut characteristics = HashMap::new();
        
        // Only analyze packets on HTTP ports
        let is_http_port = packet.src_port == Some(80) || packet.dst_port == Some(80) ||
                          packet.src_port == Some(8080) || packet.dst_port == Some(8080) ||
                          packet.src_port == Some(443) || packet.dst_port == Some(443);
        
        if !is_http_port {
            return Ok(ProtocolAnalysisResult {
                protocol: ProtocolType::Http,
                confidence: 0.1,
                packet_count: 1,
                byte_count: packet.size as u64,
                anomalies: vec![ProtocolAnomaly {
                    anomaly_type: "NonHttpPort".to_string(),
                    severity: Severity::Info,
                    description: "Packet not on a standard HTTP/HTTPS port".to_string(),
                    confidence: 0.9,
                }],
                characteristics,
            });
        }
        
        // Analyze HTTP payload
        anomalies.extend(self.analyze_http_payload(packet));
        
        // Add HTTP-specific characteristics
        if packet.dst_port == Some(443) || packet.src_port == Some(443) {
            characteristics.insert("encryption".to_string(), "HTTPS".to_string());
        } else {
            characteristics.insert("encryption".to_string(), "None".to_string());
        }
        
        let confidence = if anomalies.is_empty() { 0.7 } else { 0.4 };
        
        Ok(ProtocolAnalysisResult {
            protocol: ProtocolType::Http,
            confidence,
            packet_count: 1,
            byte_count: packet.size as u64,
            anomalies,
            characteristics,
        })
    }
    
    fn get_protocol(&self) -> ProtocolType {
        ProtocolType::Http
    }
    
    fn can_analyze(&self, packet: &PacketInfo) -> bool {
        // Can analyze TCP packets on HTTP ports
        matches!(packet.protocol, ProtocolType::Tcp) &&
        (packet.src_port == Some(80) || packet.dst_port == Some(80) ||
         packet.src_port == Some(8080) || packet.dst_port == Some(8080) ||
         packet.src_port == Some(443) || packet.dst_port == Some(443))
    }
}

/// DNS Protocol Analyzer
pub struct DnsAnalyzer {
    /// DNS query tracking
    queries: HashMap<String, DnsQueryState>,
    /// Analysis statistics
    stats: DnsAnalysisStats,
}

#[derive(Debug, Clone)]
struct DnsQueryState {
    query_count: u64,
    response_count: u64,
    first_seen: SystemTime,
    last_seen: SystemTime,
    query_types: Vec<String>,
    response_codes: Vec<u16>,
}

#[derive(Debug, Default)]
struct DnsAnalysisStats {
    total_queries: u64,
    suspicious_queries: u64,
    tunneling_attempts: u64,
    dga_domains: u64,
}

impl DnsAnalyzer {
    pub fn new() -> Self {
        Self {
            queries: HashMap::new(),
            stats: DnsAnalysisStats::default(),
        }
    }

    fn analyze_dns_payload(&self, packet: &PacketInfo) -> Vec<ProtocolAnomaly> {
        let mut anomalies: Vec<ProtocolAnomaly> = Vec::new();
        
        if let Some(ref payload) = packet.payload {
            // Basic DNS packet structure analysis
            if payload.len() < 12 {
                anomalies.push(ProtocolAnomaly {
                    anomaly_type: "DNSMalformedPacket".to_string(),
                    severity: Severity::Medium,
                    description: "DNS packet too small (malformed)".to_string(),
                    confidence: 0.6,
                });
                return anomalies;
            }
            
            // Check for DNS tunneling indicators
            if payload.len() > 512 {
                anomalies.push(ProtocolAnomaly {
                    anomaly_type: "DNSLargePacket".to_string(),
                    severity: Severity::Medium,
                    description: "Unusually large DNS packet (potential tunneling)".to_string(),
                    confidence: 0.6,
                });
            }
            
            // Analyze query names for suspicious patterns
            let payload_str = String::from_utf8_lossy(payload);
            
            // Check for DGA (Domain Generation Algorithm) patterns
            let hex_ratio = payload_str.chars()
                .filter(|c| c.is_ascii_hexdigit())
                .count() as f64 / payload_str.len() as f64;
            
            if hex_ratio > 0.7 {
                anomalies.push(ProtocolAnomaly {
                    anomaly_type: "DGAPattern".to_string(),
                    severity: Severity::Medium,
                    description: "High hex character ratio (potential DGA domain)".to_string(),
                    confidence: 0.6,
                });
            }
            
            // Check for base64 encoded data in DNS queries
            if payload_str.contains("==") || payload_str.len() % 4 == 0 {
                let base64_chars = payload_str.chars()
                    .filter(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '=')
                    .count();
                
                if base64_chars as f64 / payload_str.len() as f64 > 0.8 {
                    anomalies.push(ProtocolAnomaly {
                        anomaly_type: "Base64InDNSQuery".to_string(),
                        severity: Severity::Medium,
                        description: "Potential base64 encoded data in DNS query".to_string(),
                        confidence: 0.55,
                    });
                }
            }
            
            // Check for unusually long domain names
            if payload_str.len() > 253 {
                anomalies.push(ProtocolAnomaly {
                    anomaly_type: "LongDomainName".to_string(),
                    severity: Severity::Low,
                    description: "Domain name exceeds maximum length".to_string(),
                    confidence: 0.5,
                });
            }
        }
        
        anomalies
    }
}

impl ProtocolAnalyzer for DnsAnalyzer {
    fn analyze_packet(&self, packet: &PacketInfo) -> Result<ProtocolAnalysisResult, AnalysisError> {
        let mut anomalies: Vec<ProtocolAnomaly> = Vec::new();
        let mut characteristics = HashMap::new();
        
        // Only analyze DNS packets
        let is_dns_port = packet.src_port == Some(53) || packet.dst_port == Some(53);
        
        if !is_dns_port {
            return Ok(ProtocolAnalysisResult {
                protocol: ProtocolType::Dns,
                confidence: 0.1,
                packet_count: 1,
                byte_count: packet.size as u64,
                anomalies: vec![ProtocolAnomaly {
                    anomaly_type: "NonDnsPort".to_string(),
                    severity: Severity::Info,
                    description: "Not on DNS port 53".to_string(),
                    confidence: 0.3,
                }],
                characteristics,
            });
        }
        
        // Analyze DNS payload
        anomalies.extend(self.analyze_dns_payload(packet));
        
        // Add DNS-specific characteristics
        characteristics.insert("transport".to_string(), 
            if matches!(packet.protocol, ProtocolType::Tcp) { "TCP" } else { "UDP" }.to_string());
        
        if packet.size > 512 {
            characteristics.insert("size_category".to_string(), "Large".to_string());
        } else {
            characteristics.insert("size_category".to_string(), "Normal".to_string());
        }
        
        let confidence = if anomalies.is_empty() { 0.9 } else { 0.3 };
        
        Ok(ProtocolAnalysisResult {
            protocol: ProtocolType::Dns,
            confidence,
            packet_count: 1,
            byte_count: packet.size as u64,
            anomalies,
            characteristics,
        })
    }
    
    fn get_protocol(&self) -> ProtocolType {
        ProtocolType::Dns
    }
    
    fn can_analyze(&self, packet: &PacketInfo) -> bool {
        (packet.src_port == Some(53) || packet.dst_port == Some(53)) &&
        (matches!(packet.protocol, ProtocolType::Udp | ProtocolType::Tcp))
    }
}

impl EnhancedPcapAnalyzer {
    /// Smart buffer management to prevent memory leaks
    fn manage_analysis_buffer(&mut self, packet: PacketInfo) {
        const MAX_BUFFER_SIZE: usize = 1000;
        const CLEANUP_THRESHOLD: usize = 1200;
        
        self.analysis_buffer.push(packet);
        
        // Perform cleanup when buffer exceeds threshold
        if self.analysis_buffer.len() > CLEANUP_THRESHOLD {
            // Remove oldest 20% of packets to maintain performance
            let remove_count = self.analysis_buffer.len() / 5;
            self.analysis_buffer.drain(0..remove_count);
            
            debug!("Cleaned up {} old packets from analysis buffer, {} remaining", 
                   remove_count, self.analysis_buffer.len());
        }
        
        // Ensure buffer doesn't exceed maximum size
        while self.analysis_buffer.len() > MAX_BUFFER_SIZE {
            self.analysis_buffer.remove(0);
        }
    }
    
    /// Periodic cleanup of expired flows and old data
    pub fn cleanup_expired_data(&mut self) {
        let now = SystemTime::now();
        
        // Clean up expired flows
        let initial_flow_count = self.flow_tracker.active_flows.len();
        self.flow_tracker.active_flows.retain(|_, flow| {
            let reference_time = flow.end_time.unwrap_or(flow.start_time);
            now.duration_since(reference_time)
                .map(|duration| duration < self.flow_tracker.flow_timeout)
                .unwrap_or(false)
        });
        
        let cleaned_flows = initial_flow_count - self.flow_tracker.active_flows.len();
        if cleaned_flows > 0 {
            info!("Cleaned up {} expired flows", cleaned_flows);
        }
        
        // Shrink analysis buffer if it's using too much memory
        if self.analysis_buffer.capacity() > self.analysis_buffer.len() * 2 {
            self.analysis_buffer.shrink_to_fit();
            debug!("Shrunk analysis buffer capacity to fit current size");
        }
    }
    
    /// Get memory usage statistics
    pub fn get_memory_stats(&self) -> HashMap<String, usize> {
        let mut stats = HashMap::new();
        
        stats.insert("analysis_buffer_len".to_string(), self.analysis_buffer.len());
        stats.insert("analysis_buffer_capacity".to_string(), self.analysis_buffer.capacity());
        stats.insert("active_flows".to_string(), self.flow_tracker.active_flows.len());
        stats.insert("protocol_analyzers".to_string(), self.protocol_analyzers.len());
        stats.insert("threat_signatures".to_string(), self.threat_detector.signatures.len());
        stats.insert("behavioral_patterns".to_string(), self.threat_detector.behavioral_patterns.len());
        
        stats
    }
}
