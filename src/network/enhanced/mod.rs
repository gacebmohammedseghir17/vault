//! Enhanced network analysis module for ERDPS Advanced EDR
//! Provides deep packet inspection and AI-enhanced network traffic analysis

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};
use serde::{Deserialize, Serialize};

pub mod packet_analyzer;
pub mod protocol_detector;
pub mod traffic_classifier;
pub mod anomaly_detector;

// Re-export enhanced PCAP analyzer
#[cfg(feature = "enhanced-pcap")]
pub mod pcap_analyzer;
#[cfg(feature = "enhanced-pcap")]
pub use pcap_analyzer::*;

/// Enhanced network analysis configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Enable deep packet inspection
    pub enable_dpi: bool,
    /// Maximum packet capture size
    pub max_capture_size: usize,
    /// Analysis timeout
    pub analysis_timeout: Duration,
    /// Enable protocol detection
    pub enable_protocol_detection: bool,
    /// Enable traffic classification
    pub enable_traffic_classification: bool,
    /// Enable anomaly detection
    pub enable_anomaly_detection: bool,
    /// Capture interface
    pub capture_interface: Option<String>,
    /// BPF filter for packet capture
    pub bpf_filter: Option<String>,
    /// AI analysis threshold
    pub ai_analysis_threshold: f32,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            enable_dpi: true,
            max_capture_size: 65536,
            analysis_timeout: Duration::from_secs(30),
            enable_protocol_detection: true,
            enable_traffic_classification: true,
            enable_anomaly_detection: true,
            capture_interface: None,
            bpf_filter: None,
            ai_analysis_threshold: 0.7,
        }
    }
}

/// Network packet information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketInfo {
    /// Packet timestamp
    pub timestamp: SystemTime,
    /// Source IP address
    pub src_ip: IpAddr,
    /// Destination IP address
    pub dst_ip: IpAddr,
    /// Source port
    pub src_port: Option<u16>,
    /// Destination port
    pub dst_port: Option<u16>,
    /// Protocol type
    pub protocol: ProtocolType,
    /// Packet size
    pub size: usize,
    /// Packet payload (if captured)
    pub payload: Option<Vec<u8>>,
    /// Packet flags
    pub flags: PacketFlags,
    /// TTL/Hop limit
    pub ttl: Option<u8>,
    /// Packet direction
    pub direction: PacketDirection,
}

/// Network protocol types
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProtocolType {
    /// TCP protocol
    Tcp,
    /// UDP protocol
    Udp,
    /// ICMP protocol
    Icmp,
    /// HTTP protocol
    Http,
    /// HTTPS protocol
    Https,
    /// DNS protocol
    Dns,
    /// FTP protocol
    Ftp,
    /// SSH protocol
    Ssh,
    /// SMTP protocol
    Smtp,
    /// Unknown protocol
    Unknown(u8),
}

/// Packet flags
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PacketFlags {
    /// SYN flag
    pub syn: bool,
    /// ACK flag
    pub ack: bool,
    /// FIN flag
    pub fin: bool,
    /// RST flag
    pub rst: bool,
    /// PSH flag
    pub psh: bool,
    /// URG flag
    pub urg: bool,
    /// Fragmented packet
    pub fragmented: bool,
}

/// Packet direction
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub enum PacketDirection {
    /// Inbound traffic
    Inbound,
    /// Outbound traffic
    Outbound,
    /// Internal traffic
    Internal,
    /// Unknown direction
    #[default]
    Unknown,
}

/// Network flow information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkFlow {
    /// Flow identifier
    pub flow_id: String,
    /// Source endpoint
    pub src_endpoint: NetworkEndpoint,
    /// Destination endpoint
    pub dst_endpoint: NetworkEndpoint,
    /// Protocol used
    pub protocol: ProtocolType,
    /// Flow start time
    pub start_time: SystemTime,
    /// Flow end time
    pub end_time: Option<SystemTime>,
    /// Total bytes transferred
    pub total_bytes: u64,
    /// Total packets
    pub total_packets: u64,
    /// Flow duration
    pub duration: Option<Duration>,
    /// Flow state
    pub state: FlowState,
    /// Application layer protocol
    pub application_protocol: Option<String>,
    /// Flow metadata
    pub metadata: HashMap<String, String>,
}

/// Network endpoint information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEndpoint {
    /// IP address
    pub ip: IpAddr,
    /// Port number
    pub port: Option<u16>,
    /// Hostname (if resolved)
    pub hostname: Option<String>,
    /// Geolocation information
    pub geolocation: Option<GeolocationInfo>,
    /// Reputation score
    pub reputation: Option<f32>,
}

/// Geolocation information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeolocationInfo {
    /// Country code
    pub country: String,
    /// Country name
    pub country_name: String,
    /// Region/State
    pub region: Option<String>,
    /// City
    pub city: Option<String>,
    /// Latitude
    pub latitude: Option<f64>,
    /// Longitude
    pub longitude: Option<f64>,
    /// ISP information
    pub isp: Option<String>,
    /// Organization
    pub organization: Option<String>,
}

/// Network flow state
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FlowState {
    /// Flow is active
    Active,
    /// Flow completed normally
    Completed,
    /// Flow was reset
    Reset,
    /// Flow timed out
    TimedOut,
    /// Flow is suspicious
    Suspicious,
}

/// Network analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAnalysisResult {
    /// Analysis timestamp
    pub timestamp: SystemTime,
    /// Analyzed flows
    pub flows: Vec<NetworkFlow>,
    /// Detected protocols
    pub protocols: HashMap<ProtocolType, u64>,
    /// Traffic statistics
    pub statistics: TrafficStatistics,
    /// Detected anomalies
    pub anomalies: Vec<NetworkAnomaly>,
    /// Threat indicators
    pub threat_indicators: Vec<ThreatIndicator>,
    /// Analysis confidence
    pub confidence: f32,
    /// Processing time
    pub processing_time: Duration,
}

/// Traffic statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrafficStatistics {
    /// Total packets analyzed
    pub total_packets: u64,
    /// Total bytes analyzed
    pub total_bytes: u64,
    /// Unique source IPs
    pub unique_src_ips: u64,
    /// Unique destination IPs
    pub unique_dst_ips: u64,
    /// Protocol distribution
    pub protocol_distribution: HashMap<String, u64>,
    /// Port distribution
    pub port_distribution: HashMap<u16, u64>,
    /// Average packet size
    pub average_packet_size: f64,
    /// Peak bandwidth
    pub peak_bandwidth: f64,
    /// Analysis duration
    pub analysis_duration: Duration,
}

/// Network anomaly detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAnomaly {
    /// Anomaly type
    pub anomaly_type: AnomalyType,
    /// Severity level
    pub severity: AnomalySeverity,
    /// Description
    pub description: String,
    /// Affected flows
    pub affected_flows: Vec<String>,
    /// Detection confidence
    pub confidence: f32,
    /// Detection timestamp
    pub detected_at: SystemTime,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Types of network anomalies
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AnomalyType {
    /// Unusual traffic volume
    VolumeAnomaly,
    /// Suspicious port usage
    PortAnomaly,
    /// Unusual protocol usage
    ProtocolAnomaly,
    /// Geographic anomaly
    GeographicAnomaly,
    /// Timing anomaly
    TimingAnomaly,
    /// Payload anomaly
    PayloadAnomaly,
    /// Connection pattern anomaly
    ConnectionAnomaly,
    /// DNS anomaly
    DnsAnomaly,
    /// Behavioral anomaly
    BehavioralAnomaly,
    /// Traffic anomaly
    TrafficAnomaly,
}

/// Anomaly severity levels
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AnomalySeverity {
    /// Low severity
    Low,
    /// Medium severity
    Medium,
    /// High severity
    High,
    /// Critical severity
    Critical,
}

/// Network threat indicator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIndicator {
    /// Indicator type
    pub indicator_type: ThreatIndicatorType,
    /// Indicator value
    pub value: String,
    /// Threat level
    pub threat_level: ThreatLevel,
    /// Confidence score
    pub confidence: f32,
    /// Source of indicator
    pub source: String,
    /// First seen timestamp
    pub first_seen: SystemTime,
    /// Last seen timestamp
    pub last_seen: SystemTime,
    /// Associated flows
    pub associated_flows: Vec<String>,
    /// Additional context
    pub context: HashMap<String, String>,
}

/// Types of threat indicators
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ThreatIndicatorType {
    /// Malicious IP address
    MaliciousIp,
    /// Suspicious domain
    SuspiciousDomain,
    /// Command and control server
    C2Server,
    /// Data exfiltration
    DataExfiltration,
    /// Botnet communication
    BotnetCommunication,
    /// Malware download
    MalwareDownload,
    /// Phishing site
    PhishingSite,
    /// Cryptocurrency mining
    CryptoMining,
}

/// Threat levels
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ThreatLevel {
    /// Informational
    Info,
    /// Low threat
    Low,
    /// Medium threat
    Medium,
    /// High threat
    High,
    /// Critical threat
    Critical,
}

/// Network analysis error types
#[derive(Debug, thiserror::Error)]
pub enum NetworkAnalysisError {
    /// Packet capture error
    #[error("Packet capture error: {0}")]
    CaptureError(String),
    
    /// Protocol parsing error
    #[error("Protocol parsing error: {0}")]
    ProtocolError(String),
    
    /// Analysis timeout
    #[error("Analysis timeout after {0:?}")]
    Timeout(Duration),
    
    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigError(String),
    
    /// IO error
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    /// Generic analysis error
    #[error("Analysis error: {0}")]
    AnalysisError(String),
}

/// Result type for network analysis operations
pub type NetworkResult<T> = Result<T, NetworkAnalysisError>;

/// Enhanced network analyzer trait
#[async_trait::async_trait]
pub trait NetworkAnalyzer: Send + Sync {
    /// Start packet capture and analysis
    async fn start_analysis(&mut self, config: NetworkConfig) -> NetworkResult<()>;
    
    /// Stop analysis
    async fn stop_analysis(&mut self) -> NetworkResult<()>;
    
    /// Analyze captured packets
    async fn analyze_packets(&self, packets: &[PacketInfo]) -> NetworkResult<NetworkAnalysisResult>;
    
    /// Get current analysis results
    async fn get_results(&self) -> NetworkResult<NetworkAnalysisResult>;
    
    /// Add custom threat indicators
    async fn add_threat_indicators(&mut self, indicators: Vec<ThreatIndicator>) -> NetworkResult<()>;
    
    /// Get analysis statistics
    fn get_statistics(&self) -> TrafficStatistics;
}

/// Utility functions for network analysis
pub mod utils {
    use super::*;
    
    /// Check if IP address is private
    pub fn is_private_ip(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => {
                ipv4.is_private() || ipv4.is_loopback() || ipv4.is_link_local()
            }
            IpAddr::V6(ipv6) => {
                ipv6.is_loopback() || ipv6.is_multicast()
            }
        }
    }
    
    /// Generate flow ID from endpoints
    pub fn generate_flow_id(src: &NetworkEndpoint, dst: &NetworkEndpoint, protocol: &ProtocolType) -> String {
        format!("{}:{:?}-{}:{:?}-{:?}", 
                src.ip, src.port.unwrap_or(0),
                dst.ip, dst.port.unwrap_or(0),
                protocol)
    }
    
    /// Calculate entropy of payload data
    pub fn calculate_payload_entropy(payload: &[u8]) -> f64 {
        if payload.is_empty() {
            return 0.0;
        }
        
        let mut counts = [0u32; 256];
        for &byte in payload {
            counts[byte as usize] += 1;
        }
        
        let len = payload.len() as f64;
        let mut entropy = 0.0;
        
        for &count in &counts {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }
        
        entropy
    }
    
    /// Extract domain from hostname
    pub fn extract_domain(hostname: &str) -> Option<String> {
        let parts: Vec<&str> = hostname.split('.').collect();
        if parts.len() >= 2 {
            Some(format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]))
        } else {
            None
        }
    }
    
    /// Check if port is commonly used for malware
    pub fn is_suspicious_port(port: u16) -> bool {
        // Common malware ports (this would be more comprehensive in practice)
        matches!(port, 
            1337 | 31337 | 4444 | 5555 | 6666 | 7777 | 8888 | 9999 |
            1234 | 12345 | 54321 | 65535 | 4321 | 8080
        )
    }
    
    /// Classify traffic type based on port and protocol
    pub fn classify_traffic(protocol: &ProtocolType, port: Option<u16>) -> String {
        match (protocol, port) {
            (ProtocolType::Tcp, Some(80)) => "HTTP".to_string(),
            (ProtocolType::Tcp, Some(443)) => "HTTPS".to_string(),
            (ProtocolType::Tcp, Some(22)) => "SSH".to_string(),
            (ProtocolType::Tcp, Some(21)) => "FTP".to_string(),
            (ProtocolType::Tcp, Some(25)) => "SMTP".to_string(),
            (ProtocolType::Udp, Some(53)) => "DNS".to_string(),
            (ProtocolType::Udp, Some(67)) => "DHCP".to_string(),
            (ProtocolType::Udp, Some(123)) => "NTP".to_string(),
            _ => "Unknown".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::utils::*;
    use std::net::Ipv4Addr;
    
    #[test]
    fn test_private_ip_detection() {
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }
    
    #[test]
    fn test_flow_id_generation() {
        let src = NetworkEndpoint {
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            port: Some(12345),
            hostname: None,
            geolocation: None,
            reputation: None,
        };
        
        let dst = NetworkEndpoint {
            ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            port: Some(80),
            hostname: None,
            geolocation: None,
            reputation: None,
        };
        
        let flow_id = generate_flow_id(&src, &dst, &ProtocolType::Tcp);
        assert!(flow_id.contains("192.168.1.1"));
        assert!(flow_id.contains("8.8.8.8"));
    }
    
    #[test]
    fn test_payload_entropy() {
        let uniform_payload = vec![0u8; 100];
        let entropy = calculate_payload_entropy(&uniform_payload);
        assert_eq!(entropy, 0.0);
        
        let random_payload: Vec<u8> = (0..256).map(|i| i as u8).collect();
        let entropy = calculate_payload_entropy(&random_payload);
        assert!(entropy > 7.0);
    }
    
    #[test]
    fn test_suspicious_port_detection() {
        assert!(is_suspicious_port(1337));
        assert!(is_suspicious_port(31337));
        assert!(!is_suspicious_port(80));
        assert!(!is_suspicious_port(443));
    }
    
    #[test]
    fn test_traffic_classification() {
        assert_eq!(classify_traffic(&ProtocolType::Tcp, Some(80)), "HTTP");
        assert_eq!(classify_traffic(&ProtocolType::Tcp, Some(443)), "HTTPS");
        assert_eq!(classify_traffic(&ProtocolType::Udp, Some(53)), "DNS");
        assert_eq!(classify_traffic(&ProtocolType::Tcp, Some(9999)), "Unknown");
    }
}
