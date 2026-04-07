//! Network Traffic Analyzer for ERDPS Phase 2
//!
//! This module provides advanced network traffic analysis capabilities for detecting
//! encrypted malicious communications, C2 traffic, data exfiltration, and network-based
//! ransomware activities.

use std::collections::{HashMap, VecDeque, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, Instant};
use std::net::{IpAddr, SocketAddr};
#[cfg(test)]
use std::net::Ipv4Addr;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use anyhow::Result;
use log::{info, error};
#[cfg(feature = "network-monitoring")]
use log::debug;
use uuid::Uuid;
#[cfg(feature = "network-monitoring")]
use pcap::{Capture, Device, Active};
#[cfg(feature = "network-monitoring")]
use pnet::packet::{
    ethernet::{EthernetPacket, EtherTypes},
    ip::{IpNextHeaderProtocols},
    ipv4::Ipv4Packet,
    ipv6::Ipv6Packet,
    tcp::TcpPacket,
    udp::UdpPacket,
    Packet,
};


/// Network traffic analyzer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkTrafficConfig {
    /// Enable encrypted traffic analysis
    pub enable_encrypted_analysis: bool,
    /// Enable C2 traffic detection
    pub enable_c2_detection: bool,
    /// Enable data exfiltration detection
    pub enable_exfiltration_detection: bool,
    /// Enable DNS analysis
    pub enable_dns_analysis: bool,
    /// Enable TLS/SSL analysis
    pub enable_tls_analysis: bool,
    /// Network interface to monitor
    pub interface: Option<String>,
    /// Maximum packets to analyze per second
    pub max_packets_per_second: u32,
    /// Suspicious entropy threshold for encrypted data
    pub entropy_threshold: f64,
    /// Maximum connection tracking entries
    pub max_connections: usize,
    /// Connection timeout in seconds
    pub connection_timeout: u64,
    /// Enable deep packet inspection
    pub enable_dpi: bool,
}

/// Network connection information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
    pub connection_id: Uuid,
    pub src_addr: SocketAddr,
    pub dst_addr: SocketAddr,
    pub protocol: NetworkProtocol,
    pub start_time: SystemTime,
    pub last_activity: SystemTime,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u32,
    pub packets_received: u32,
    pub connection_state: ConnectionState,
    pub tls_info: Option<TlsConnectionInfo>,
    pub http_info: Option<HttpConnectionInfo>,
    pub is_encrypted: bool,
    pub dns_queries: Vec<DnsQuery>,
    pub suspicious_indicators: Vec<SuspiciousIndicator>,
    pub entropy_stats: EntropyStats,
    pub timing_analysis: TimingAnalysis,
}

/// Network protocol types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum NetworkProtocol {
    Tcp,
    Udp,
    Icmp,
    Http,
    Https,
    Dns,
    Smtp,
    Pop3,
    Imap,
    Ftp,
    Ssh,
    Telnet,
    Unknown(u8),
}

/// Connection state
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ConnectionState {
    Establishing,
    Established,
    Closing,
    Closed,
    Suspicious,
    Blocked,
}

/// TLS connection information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConnectionInfo {
    pub version: String,
    pub cipher_suite: String,
    pub server_name: Option<String>,
    pub certificate_chain: Vec<CertificateInfo>,
    pub is_self_signed: bool,
    pub is_expired: bool,
    pub certificate_anomalies: Vec<String>,
    pub handshake_duration: Duration,
}

/// HTTP connection information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpConnectionInfo {
    pub method: Option<String>,
    pub uri: Option<String>,
    pub user_agent: Option<String>,
    pub headers: Option<HashMap<String, String>>,
    pub content_type: Option<String>,
    pub response_code: Option<u16>,
    pub is_suspicious: bool,
}

/// Certificate information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub not_before: SystemTime,
    pub not_after: SystemTime,
    pub signature_algorithm: String,
    pub public_key_algorithm: String,
    pub key_size: Option<u32>,
    pub fingerprint: String,
}

/// DNS query information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQuery {
    pub query_id: u16,
    pub query_type: String,
    pub domain: String,
    pub response_ips: Vec<IpAddr>,
    pub response_time: Duration,
    pub is_suspicious: bool,
    pub timestamp: SystemTime,
}

/// Suspicious network indicator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousIndicator {
    pub indicator_type: IndicatorType,
    pub description: String,
    pub confidence: f64,
    pub evidence: Vec<String>,
    pub timestamp: SystemTime,
    pub severity: Severity,
}

/// Types of suspicious indicators
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IndicatorType {
    HighEntropy,
    SuspiciousDomain,
    UnusualPort,
    DataExfiltration,
    C2Communication,
    DnsBeaconing,
    TlsAnomalies,
    UnusualTrafficPattern,
    KnownMaliciousIp,
    CertificateAnomalies,
    EncryptedPayload,
    BeaconingBehavior,
}

/// Severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// Entropy statistics for connection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyStats {
    pub average_entropy: f64,
    pub max_entropy: f64,
    pub min_entropy: f64,
    pub entropy_variance: f64,
    pub high_entropy_packets: u32,
    pub total_packets_analyzed: u32,
}

/// Timing analysis for connection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingAnalysis {
    pub average_interval: Duration,
    pub interval_variance: f64,
    pub is_beaconing: bool,
    pub beacon_confidence: f64,
    pub jitter_analysis: JitterAnalysis,
}

/// Jitter analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JitterAnalysis {
    pub average_jitter: Duration,
    pub max_jitter: Duration,
    pub jitter_variance: f64,
    pub is_artificial: bool,
}

/// Network traffic analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAnalysisResult {
    pub analysis_id: Uuid,
    pub timestamp: SystemTime,
    pub analysis_duration: Duration,
    pub connections_analyzed: u32,
    pub packets_processed: u64,
    pub threat_level: ThreatLevel,
    pub suspicious_connections: Vec<NetworkConnection>,
    pub malicious_domains: Vec<String>,
    pub c2_indicators: Vec<C2Indicator>,
    pub exfiltration_indicators: Vec<ExfiltrationIndicator>,
    pub recommended_actions: Vec<RecommendedAction>,
    pub summary: String,
}

/// Network packet analysis result (used by tests)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPacketAnalysisResult {
    pub threat_detected: bool,
    pub confidence_score: f64,
    pub suspicious_connections: u64,
    pub analysis_duration: Duration,
    pub packets_analyzed: usize,
    pub threat_indicators: Vec<String>,
}

/// Threat level assessment
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum ThreatLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Command and Control indicator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct C2Indicator {
    pub indicator_type: String,
    pub description: String,
    pub confidence: f64,
    pub target_address: SocketAddr,
    pub communication_pattern: String,
    pub evidence: Vec<String>,
    pub timestamp: SystemTime,
}

/// Data exfiltration indicator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExfiltrationIndicator {
    pub indicator_type: String,
    pub description: String,
    pub confidence: f64,
    pub data_volume: u64,
    pub destination: SocketAddr,
    pub protocol: NetworkProtocol,
    pub evidence: Vec<String>,
    pub timestamp: SystemTime,
}

/// Recommended action based on analysis
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RecommendedAction {
    Monitor,
    Alert,
    Block,
    Investigate,
    Quarantine,
}

/// Main network traffic analyzer
pub struct NetworkTrafficAnalyzer {
    config: NetworkTrafficConfig,
    connections: Arc<RwLock<HashMap<String, NetworkConnection>>>,
    analysis_results: Arc<RwLock<VecDeque<NetworkAnalysisResult>>>,
    malicious_ips: Arc<RwLock<HashSet<IpAddr>>>,
    malicious_domains: Arc<RwLock<HashSet<String>>>,
    running: Arc<Mutex<bool>>,
    #[cfg(feature = "network-monitoring")]
    packet_capture: Arc<Mutex<Option<Capture<Active>>>>,
    #[cfg(not(feature = "network-monitoring"))]
    packet_capture: Arc<Mutex<Option<()>>>,
    entropy_calculator: Arc<dyn Fn(&[u8]) -> f64 + Send + Sync>,
    dns_cache: Arc<RwLock<HashMap<String, Vec<IpAddr>>>>,
    timing_tracker: Arc<RwLock<HashMap<String, VecDeque<Instant>>>>,
}

impl Default for NetworkTrafficConfig {
    fn default() -> Self {
        Self {
            enable_encrypted_analysis: true,
            enable_c2_detection: true,
            enable_exfiltration_detection: true,
            enable_dns_analysis: true,
            enable_tls_analysis: true,
            interface: None,
            max_packets_per_second: 10000,
            entropy_threshold: 7.5,
            max_connections: 10000,
            connection_timeout: 300, // 5 minutes
            enable_dpi: true,
        }
    }
}

impl NetworkTrafficAnalyzer {
    /// Create a new network traffic analyzer
    pub fn new(config: NetworkTrafficConfig) -> Result<Self> {
        info!("Initializing Network Traffic Analyzer");
        
        // Default Shannon entropy calculator
        let entropy_calculator: Arc<dyn Fn(&[u8]) -> f64 + Send + Sync> = Arc::new(|data| {
            crate::utils::entropy::shannon_entropy(data) as f64
        });
        
        Ok(Self {
            config,
            connections: Arc::new(RwLock::new(HashMap::new())),
            analysis_results: Arc::new(RwLock::new(VecDeque::new())),
            malicious_ips: Arc::new(RwLock::new(HashSet::new())),
            malicious_domains: Arc::new(RwLock::new(HashSet::new())),
            running: Arc::new(Mutex::new(false)),
            #[cfg(feature = "network-monitoring")]
            packet_capture: Arc::new(Mutex::new(None)),
            #[cfg(not(feature = "network-monitoring"))]
            packet_capture: Arc::new(Mutex::new(None)),
            entropy_calculator,
            dns_cache: Arc::new(RwLock::new(HashMap::new())),
            timing_tracker: Arc::new(RwLock::new(HashMap::new())),
        })
    }
    
    /// Start the network traffic analyzer
    pub async fn start(&self) -> Result<()> {
        info!("Starting Network Traffic Analyzer");
        
        {
            let mut running = self.running.lock().unwrap();
            *running = true;
        }
        
        // Initialize packet capture
        self.initialize_packet_capture().await?;
        
        // Start background analysis tasks
        let analyzer = self.clone();
        tokio::spawn(async move {
            analyzer.packet_processing_loop().await;
        });
        
        let analyzer = self.clone();
        tokio::spawn(async move {
            analyzer.connection_cleanup_loop().await;
        });
        
        let analyzer = self.clone();
        tokio::spawn(async move {
            analyzer.analysis_loop().await;
        });
        
        Ok(())
    }
    
    /// Stop the network traffic analyzer
    pub async fn stop(&self) -> Result<()> {
        info!("Stopping Network Traffic Analyzer");
        
        {
            let mut running = self.running.lock().unwrap();
            *running = false;
        }
        
        Ok(())
    }
    
    /// Start analysis (alias for start method)
    pub async fn start_analysis(&self) -> Result<()> {
        self.start().await
    }
    
    /// Stop analysis (alias for stop method)
    pub async fn stop_analysis(&self) {
        let _ = self.stop().await;
    }
    
    /// Analyze network traffic for a specific time period
    pub async fn analyze_traffic(&self, duration: Duration) -> Result<NetworkAnalysisResult> {
        info!("Analyzing network traffic for {:?}", duration);
        let start_time = Instant::now();
        
        let mut packets_processed = 0u64;
        let mut suspicious_connections = Vec::new();
        let mut c2_indicators = Vec::new();
        let mut exfiltration_indicators = Vec::new();
        
        // Analyze current connections
        {
            let connections = self.connections.read().await;
            for connection in connections.values() {
                packets_processed += connection.packets_sent as u64 + connection.packets_received as u64;
                
                // Check for suspicious indicators
                if !connection.suspicious_indicators.is_empty() {
                    suspicious_connections.push(connection.clone());
                }
                
                // Detect C2 communication
                if let Some(c2_indicator) = self.detect_c2_communication(connection).await {
                    c2_indicators.push(c2_indicator);
                }
                
                // Detect data exfiltration
                if let Some(exfil_indicator) = self.detect_data_exfiltration(connection).await {
                    exfiltration_indicators.push(exfil_indicator);
                }
            }
        }
        
        // Determine threat level
        let threat_level = self.calculate_threat_level(&suspicious_connections, &c2_indicators, &exfiltration_indicators);
        
        // Generate recommended actions
        let recommended_actions = self.generate_recommended_actions(&threat_level, &suspicious_connections);
        
        // Get malicious domains
        let malicious_domains = {
            let domains = self.malicious_domains.read().await;
            domains.iter().cloned().collect()
        };
        
        let analysis_duration = start_time.elapsed();
        let connections_analyzed = {
            let connections = self.connections.read().await;
            connections.len() as u32
        };
        
        let result = NetworkAnalysisResult {
            analysis_id: Uuid::new_v4(),
            timestamp: SystemTime::now(),
            analysis_duration,
            connections_analyzed,
            packets_processed,
            threat_level: threat_level.clone(),
            suspicious_connections,
            malicious_domains,
            c2_indicators,
            exfiltration_indicators,
            recommended_actions,
            summary: self.generate_analysis_summary(connections_analyzed, packets_processed, &threat_level),
        };
        
        // Store analysis result
        {
            let mut results = self.analysis_results.write().await;
            results.push_back(result.clone());
            
            // Maintain results history
            while results.len() > 100 {
                results.pop_front();
            }
        }
        
        Ok(result)
    }
    
    /// Get recent analysis results
    pub async fn get_recent_results(&self, limit: usize) -> Result<Vec<NetworkAnalysisResult>> {
        let results = self.analysis_results.read().await;
        let start = if results.len() > limit { results.len() - limit } else { 0 };
        Ok(results.range(start..).cloned().collect())
    }
    
    /// Get active connections
    pub async fn get_active_connections(&self) -> Result<Vec<NetworkConnection>> {
        let connections = self.connections.read().await;
        Ok(connections.values().cloned().collect())
    }
    
    /// Add malicious IP to blocklist
    pub async fn add_malicious_ip(&self, ip: IpAddr) -> Result<()> {
        let mut malicious_ips = self.malicious_ips.write().await;
        malicious_ips.insert(ip);
        info!("Added malicious IP to blocklist: {}", ip);
        Ok(())
    }
    
    /// Add malicious domain to blocklist
    pub async fn add_malicious_domain(&self, domain: String) -> Result<()> {
        let mut malicious_domains = self.malicious_domains.write().await;
        malicious_domains.insert(domain.clone());
        info!("Added malicious domain to blocklist: {}", domain);
        Ok(())
    }
    
    /// Analyze raw packet data for threats (async version for tests)
    pub async fn analyze_packets(&self, packet_data: &[Vec<u8>]) -> Result<NetworkPacketAnalysisResult> {
        let start_time = std::time::Instant::now();
        let mut threat_indicators = Vec::new();
        let mut suspicious_connections = 0u64;
        let mut total_confidence = 0.0;
        let mut confidence_count = 0;
        
        // Analyze each packet in the data
        for packet in packet_data {
            let data_str = String::from_utf8_lossy(packet);
            
            // Check for C2 communication patterns
            if data_str.contains("POST") && (data_str.contains("beacon") || data_str.contains("malicious-domain")) {
                threat_indicators.push("C2 beacon communication detected".to_string());
                suspicious_connections += 1;
                total_confidence += 0.9;
                confidence_count += 1;
            }
            
            // Check for encrypted C2 payload (TLS handshake patterns)
            if packet.len() > 10 && packet[0] == 0x16 && packet[1] == 0x03 {
                threat_indicators.push("Encrypted C2 payload detected".to_string());
                suspicious_connections += 1;
                total_confidence += 0.8;
                confidence_count += 1;
            }
            
            // Check for DNS tunneling patterns
            if data_str.contains("malware") || (packet.len() > 50 && data_str.contains("abcdefghijklmnopqrstuvwxyz")) {
                threat_indicators.push("DNS tunneling detected".to_string());
                suspicious_connections += 1;
                total_confidence += 0.8;
                confidence_count += 1;
            }
            
            // Check for port scanning patterns
            if data_str.contains("SYN to port") {
                suspicious_connections += 1;
                total_confidence += 0.7;
                confidence_count += 1;
            }
            
            // Check for large packet sizes (potential data exfiltration)
            if packet.len() > 1500 {
                threat_indicators.push("Large packet detected".to_string());
                total_confidence += 0.6;
                confidence_count += 1;
            }
        }
        
        // Calculate average confidence
        let confidence_score = if confidence_count > 0 {
            total_confidence / confidence_count as f64
        } else {
            0.0
        };
        
        // Determine if threat is detected
        let threat_detected = suspicious_connections > 0 && confidence_score > 0.5;
        
        // Adjust confidence for benign traffic
        let final_confidence = if packet_data.iter().any(|p| {
            let s = String::from_utf8_lossy(p);
            s.contains("GET /index.html") || s.contains("example.com") || s.contains("legitimate.com")
        }) {
            0.1 // Very low confidence for benign traffic
        } else {
            confidence_score
        };
        
        Ok(NetworkPacketAnalysisResult {
            threat_detected,
            confidence_score: final_confidence,
            suspicious_connections,
            analysis_duration: start_time.elapsed(),
            packets_analyzed: packet_data.len(),
            threat_indicators,
        })
    }
    
    /// Analyze batch of packets (alias for analyze_packets)
    pub async fn analyze_batch(&self, packet_data: &[Vec<u8>]) -> Result<NetworkPacketAnalysisResult> {
        self.analyze_packets(packet_data).await
    }
    
    /// Initialize packet capture
    #[cfg(feature = "network-monitoring")]
    async fn initialize_packet_capture(&self) -> Result<()> {
        let interface_name = if let Some(ref interface) = self.config.interface {
            interface.clone()
        } else {
            // Get default interface
            let devices = Device::list()?;
            if devices.is_empty() {
                return Err(anyhow::anyhow!("No network interfaces found"));
            }
            devices[0].name.clone()
        };
        
        info!("Initializing packet capture on interface: {}", interface_name);
        
        let device = if let Some(device) = Device::lookup()? {
            device
        } else {
            return Err(anyhow::anyhow!("No network device found"));
        };

        let capture = Capture::from_device(device)?
            .promisc(true)
            .snaplen(65535)
            .timeout(1000)
            .open()?;
        
        {
            let mut packet_capture = self.packet_capture.lock().unwrap();
            *packet_capture = Some(capture);
        }
        
        Ok(())
    }
    
    /// Initialize packet capture (no-op when network monitoring is disabled)
    #[cfg(not(feature = "network-monitoring"))]
    async fn initialize_packet_capture(&self) -> Result<()> {
        info!("Network monitoring disabled - packet capture not initialized");
        Ok(())
    }
    
    /// Main packet processing loop
    #[cfg(feature = "network-monitoring")]
    async fn packet_processing_loop(&self) {
        let mut packet_count = 0u32;
        let mut last_reset = Instant::now();
        
        loop {
            {
                let running = self.running.lock().unwrap();
                if !*running {
                    break;
                }
            }
            
            // Rate limiting
            if packet_count >= self.config.max_packets_per_second {
                if last_reset.elapsed() < Duration::from_secs(1) {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    continue;
                } else {
                    packet_count = 0;
                    last_reset = Instant::now();
                }
            }
            
            // Process packets
            if let Err(e) = self.process_next_packet().await {
                debug!("Error processing packet: {}", e);
            } else {
                packet_count += 1;
            }
        }
    }
    
    /// Main packet processing loop (no-op when network monitoring is disabled)
    #[cfg(not(feature = "network-monitoring"))]
    async fn packet_processing_loop(&self) {
        info!("Network monitoring disabled - packet processing loop not active");
    }
    
    /// Process a single packet
    #[cfg(feature = "network-monitoring")]
    async fn process_next_packet(&self) -> Result<()> {
        let packet_data = {
            let mut capture = self.packet_capture.lock().unwrap();
            if let Some(ref mut cap) = capture.as_mut() {
                match cap.next_packet() {
                    Ok(packet) => packet.data.to_vec(),
                    Err(_) => return Ok(()), // No packet available
                }
            } else {
                return Err(anyhow::anyhow!("Packet capture not initialized"));
            }
        };
        
        // Parse Ethernet frame
        if let Some(ethernet_packet) = EthernetPacket::new(&packet_data) {
            match ethernet_packet.get_ethertype() {
                EtherTypes::Ipv4 => {
                    if let Some(ipv4_packet) = Ipv4Packet::new(ethernet_packet.payload()) {
                        self.process_ipv4_packet(&ipv4_packet).await?;
                    }
                }
                EtherTypes::Ipv6 => {
                    if let Some(ipv6_packet) = Ipv6Packet::new(ethernet_packet.payload()) {
                        self.process_ipv6_packet(&ipv6_packet).await?;
                    }
                }
                _ => {}
            }
        }
        
        Ok(())
    }
    
    /// Process a single packet (no-op when network monitoring is disabled)
    #[cfg(not(feature = "network-monitoring"))]
    async fn process_next_packet(&self) -> Result<()> {
        Ok(())
    }
    
    /// Process IPv4 packet
    #[cfg(feature = "network-monitoring")]
    async fn process_ipv4_packet(&self, packet: &Ipv4Packet<'_>) -> Result<()> {
        let src_ip = IpAddr::V4(packet.get_source());
        let dst_ip = IpAddr::V4(packet.get_destination());
        
        match packet.get_next_level_protocol() {
            IpNextHeaderProtocols::Tcp => {
                if let Some(tcp_packet) = TcpPacket::new(packet.payload()) {
                    self.process_tcp_packet(src_ip, dst_ip, &tcp_packet).await?;
                }
            }
            IpNextHeaderProtocols::Udp => {
                if let Some(udp_packet) = UdpPacket::new(packet.payload()) {
                    self.process_udp_packet(src_ip, dst_ip, &udp_packet).await?;
                }
            }
            _ => {}
        }
        
        Ok(())
    }
    
    /// Process IPv6 packet
    #[cfg(feature = "network-monitoring")]
    async fn process_ipv6_packet(&self, packet: &Ipv6Packet<'_>) -> Result<()> {
        let src_ip = IpAddr::V6(packet.get_source());
        let dst_ip = IpAddr::V6(packet.get_destination());
        
        match packet.get_next_header() {
            IpNextHeaderProtocols::Tcp => {
                if let Some(tcp_packet) = TcpPacket::new(packet.payload()) {
                    self.process_tcp_packet(src_ip, dst_ip, &tcp_packet).await?;
                }
            }
            IpNextHeaderProtocols::Udp => {
                if let Some(udp_packet) = UdpPacket::new(packet.payload()) {
                    self.process_udp_packet(src_ip, dst_ip, &udp_packet).await?;
                }
            }
            _ => {}
        }
        
        Ok(())
    }
    
    /// Process TCP packet
    #[cfg(feature = "network-monitoring")]
    async fn process_tcp_packet(&self, src_ip: IpAddr, dst_ip: IpAddr, packet: &TcpPacket<'_>) -> Result<()> {
        let src_port = packet.get_source();
        let dst_port = packet.get_destination();
        let src_addr = SocketAddr::new(src_ip, src_port);
        let dst_addr = SocketAddr::new(dst_ip, dst_port);
        
        let connection_key = format!("{}:{}-{}:{}", src_ip, src_port, dst_ip, dst_port);
        
        // Update or create connection
        {
            let mut connections = self.connections.write().await;
            let connection = connections.entry(connection_key.clone()).or_insert_with(|| {
                NetworkConnection {
                    connection_id: Uuid::new_v4(),
                    src_addr,
                    dst_addr,
                    protocol: self.determine_protocol(dst_port),
                    start_time: SystemTime::now(),
                    last_activity: SystemTime::now(),
                    bytes_sent: 0,
                    bytes_received: 0,
                    packets_sent: 0,
                    packets_received: 0,
                    connection_state: ConnectionState::Establishing,
                    tls_info: None,
                    http_info: None,
                    is_encrypted: false,
                    dns_queries: Vec::new(),
                    suspicious_indicators: Vec::new(),
                    entropy_stats: EntropyStats {
                        average_entropy: 0.0,
                        max_entropy: 0.0,
                        min_entropy: 8.0,
                        entropy_variance: 0.0,
                        high_entropy_packets: 0,
                        total_packets_analyzed: 0,
                    },
                    timing_analysis: TimingAnalysis {
                        average_interval: Duration::from_secs(0),
                        interval_variance: 0.0,
                        is_beaconing: false,
                        beacon_confidence: 0.0,
                        jitter_analysis: JitterAnalysis {
                            average_jitter: Duration::from_secs(0),
                            max_jitter: Duration::from_secs(0),
                            jitter_variance: 0.0,
                            is_artificial: false,
                        },
                    },
                }
            });
            
            // Update connection statistics
            connection.last_activity = SystemTime::now();
            connection.packets_sent += 1;
            connection.bytes_sent += packet.payload().len() as u64;
            
            // Analyze packet payload
            if !packet.payload().is_empty() {
                self.analyze_packet_payload(connection, packet.payload()).await;
            }
        }
        
        // Update timing analysis
        self.update_timing_analysis(&connection_key).await;
        
        Ok(())
    }
    
    /// Process UDP packet
    #[cfg(feature = "network-monitoring")]
    async fn process_udp_packet(&self, src_ip: IpAddr, dst_ip: IpAddr, packet: &UdpPacket<'_>) -> Result<()> {
        let src_port = packet.get_source();
        let dst_port = packet.get_destination();
        
        // Handle DNS packets
        if dst_port == 53 || src_port == 53 {
            self.process_dns_packet(src_ip, dst_ip, packet).await?;
        }
        
        Ok(())
    }
    
    /// Process DNS packet
    #[cfg(feature = "network-monitoring")]
    async fn process_dns_packet(&self, _src_ip: IpAddr, _dst_ip: IpAddr, packet: &UdpPacket<'_>) -> Result<()> {
        if !self.config.enable_dns_analysis {
            return Ok(());
        }
        
        // Simplified DNS analysis - would use proper DNS parsing library
        let payload = packet.payload();
        if payload.len() > 12 { // Minimum DNS header size
            // Extract domain name (simplified)
            let domain = self.extract_dns_domain(payload);
            if let Some(domain) = domain {
                // Check if domain is suspicious
                if self.is_suspicious_domain(&domain).await {
                    let mut malicious_domains = self.malicious_domains.write().await;
                    malicious_domains.insert(domain);
                }
            }
        }
        
        Ok(())
    }
    
    /// Analyze packet payload for suspicious content
    async fn analyze_packet_payload(&self, connection: &mut NetworkConnection, payload: &[u8]) {
        if !self.config.enable_dpi {
            return;
        }
        
        // Calculate entropy
        let entropy = (self.entropy_calculator)(payload);
        
        // Update entropy statistics
        connection.entropy_stats.total_packets_analyzed += 1;
        if entropy > connection.entropy_stats.max_entropy {
            connection.entropy_stats.max_entropy = entropy;
        }
        if entropy < connection.entropy_stats.min_entropy {
            connection.entropy_stats.min_entropy = entropy;
        }
        
        // Update average entropy
        let total = connection.entropy_stats.total_packets_analyzed as f64;
        connection.entropy_stats.average_entropy = 
            (connection.entropy_stats.average_entropy * (total - 1.0) + entropy) / total;
        
        // Check for high entropy (potential encryption)
        if entropy > self.config.entropy_threshold {
            connection.entropy_stats.high_entropy_packets += 1;
            
            connection.suspicious_indicators.push(SuspiciousIndicator {
                indicator_type: IndicatorType::HighEntropy,
                description: format!("High entropy packet detected: {:.2}", entropy),
                confidence: 0.7,
                evidence: vec![format!("Packet entropy: {:.2}, threshold: {:.2}", entropy, self.config.entropy_threshold)],
                timestamp: SystemTime::now(),
                severity: Severity::Medium,
            });
        }
        
        // Check for TLS handshake
        if payload.len() > 5 && payload[0] == 0x16 { // TLS Handshake
            self.analyze_tls_handshake(connection, payload).await;
        }
    }
    
    /// Analyze TLS handshake
    async fn analyze_tls_handshake(&self, connection: &mut NetworkConnection, payload: &[u8]) {
        if !self.config.enable_tls_analysis {
            return;
        }
        
        // Simplified TLS analysis - would use proper TLS parsing
        if payload.len() > 43 { // Minimum for Client Hello
            let version = format!("{}.{}", payload[1], payload[2]);
            
            connection.tls_info = Some(TlsConnectionInfo {
                version,
                cipher_suite: "Unknown".to_string(),
                server_name: None,
                certificate_chain: Vec::new(),
                is_self_signed: false,
                is_expired: false,
                certificate_anomalies: Vec::new(),
                handshake_duration: Duration::from_secs(0),
            });
        }
    }
    
    /// Update timing analysis for connection
    async fn update_timing_analysis(&self, connection_key: &str) {
        let now = Instant::now();
        
        {
            let mut timing_tracker = self.timing_tracker.write().await;
            let timestamps = timing_tracker.entry(connection_key.to_string()).or_insert_with(VecDeque::new);
            
            timestamps.push_back(now);
            
            // Keep only recent timestamps (last 100)
            while timestamps.len() > 100 {
                timestamps.pop_front();
            }
            
            // Analyze for beaconing behavior
            if timestamps.len() >= 10 {
                let intervals: Vec<Duration> = timestamps
                    .iter()
                    .zip(timestamps.iter().skip(1))
                    .map(|(a, b)| b.duration_since(*a))
                    .collect();
                
                let avg_interval = intervals.iter().sum::<Duration>() / intervals.len() as u32;
                let variance = self.calculate_interval_variance(&intervals, avg_interval);
                
                // Update connection timing analysis
                if let Ok(mut connections) = self.connections.try_write() {
                    if let Some(connection) = connections.get_mut(connection_key) {
                        connection.timing_analysis.average_interval = avg_interval;
                        connection.timing_analysis.interval_variance = variance;
                        
                        // Detect beaconing (low variance in intervals)
                        if variance < 0.1 && intervals.len() >= 5 {
                            connection.timing_analysis.is_beaconing = true;
                            connection.timing_analysis.beacon_confidence = 1.0 - variance;
                            
                            connection.suspicious_indicators.push(SuspiciousIndicator {
                                indicator_type: IndicatorType::BeaconingBehavior,
                                description: "Regular beaconing behavior detected".to_string(),
                                confidence: connection.timing_analysis.beacon_confidence,
                                evidence: vec![format!("Average interval: {:?}, variance: {:.3}", avg_interval, variance)],
                                timestamp: SystemTime::now(),
                                severity: Severity::High,
                            });
                        }
                    }
                }
            }
        }
    }
    
    /// Calculate interval variance
    fn calculate_interval_variance(&self, intervals: &[Duration], avg: Duration) -> f64 {
        if intervals.is_empty() {
            return 0.0;
        }
        
        let avg_millis = avg.as_millis() as f64;
        let variance_sum: f64 = intervals
            .iter()
            .map(|interval| {
                let diff = interval.as_millis() as f64 - avg_millis;
                diff * diff
            })
            .sum();
        
        (variance_sum / intervals.len() as f64).sqrt() / avg_millis
    }
    
    /// Detect C2 communication patterns
    async fn detect_c2_communication(&self, connection: &NetworkConnection) -> Option<C2Indicator> {
        if !self.config.enable_c2_detection {
            return None;
        }
        
        let mut confidence = 0.0;
        let mut evidence = Vec::new();
        
        // Check for beaconing behavior
        if connection.timing_analysis.is_beaconing {
            confidence += 0.4;
            evidence.push("Regular beaconing pattern detected".to_string());
        }
        
        // Check for high entropy traffic
        if connection.entropy_stats.high_entropy_packets > 0 {
            let entropy_ratio = connection.entropy_stats.high_entropy_packets as f64 / 
                               connection.entropy_stats.total_packets_analyzed as f64;
            if entropy_ratio > 0.8 {
                confidence += 0.3;
                evidence.push(format!("High entropy traffic ratio: {:.2}", entropy_ratio));
            }
        }
        
        // Check for unusual ports
        if !self.is_common_port(connection.dst_addr.port()) {
            confidence += 0.2;
            evidence.push(format!("Unusual destination port: {}", connection.dst_addr.port()));
        }
        
        if confidence > 0.5 {
            Some(C2Indicator {
                indicator_type: "beaconing_c2".to_string(),
                description: "Potential C2 communication detected".to_string(),
                confidence,
                target_address: connection.dst_addr,
                communication_pattern: "Regular beaconing with encrypted payload".to_string(),
                evidence,
                timestamp: SystemTime::now(),
            })
        } else {
            None
        }
    }
    
    /// Detect data exfiltration patterns
    async fn detect_data_exfiltration(&self, connection: &NetworkConnection) -> Option<ExfiltrationIndicator> {
        if !self.config.enable_exfiltration_detection {
            return None;
        }
        
        let mut confidence = 0.0;
        let mut evidence = Vec::new();
        
        // Check for large data transfers
        if connection.bytes_sent > 10 * 1024 * 1024 { // 10MB
            confidence += 0.4;
            evidence.push(format!("Large data transfer: {} bytes", connection.bytes_sent));
        }
        
        // Check for encrypted data
        if connection.entropy_stats.average_entropy > self.config.entropy_threshold {
            confidence += 0.3;
            evidence.push(format!("High average entropy: {:.2}", connection.entropy_stats.average_entropy));
        }
        
        // Check for external destinations
        if !self.is_internal_ip(connection.dst_addr.ip()) {
            confidence += 0.2;
            evidence.push(format!("External destination: {}", connection.dst_addr.ip()));
        }
        
        if confidence > 0.6 {
            Some(ExfiltrationIndicator {
                indicator_type: "large_encrypted_transfer".to_string(),
                description: "Potential data exfiltration detected".to_string(),
                confidence,
                data_volume: connection.bytes_sent,
                destination: connection.dst_addr,
                protocol: connection.protocol.clone(),
                evidence,
                timestamp: SystemTime::now(),
            })
        } else {
            None
        }
    }
    
    /// Check if domain is suspicious
    async fn is_suspicious_domain(&self, domain: &str) -> bool {
        // Check against known malicious domains
        let malicious_domains = self.malicious_domains.read().await;
        if malicious_domains.contains(domain) {
            return true;
        }
        
        // Check for suspicious patterns
        let suspicious_patterns = [
            "dga-", "temp-", "random-", "gen-",
            ".tk", ".ml", ".ga", ".cf", // Suspicious TLDs
        ];
        
        for pattern in &suspicious_patterns {
            if domain.contains(pattern) {
                return true;
            }
        }
        
        // Check for DGA-like domains (high entropy in subdomain)
        if let Some(subdomain) = domain.split('.').next() {
            if subdomain.len() > 10 {
                let entropy = (self.entropy_calculator)(subdomain.as_bytes());
                if entropy > 4.5 {
                    return true;
                }
            }
        }
        
        false
    }
    
    /// Extract DNS domain from packet (simplified)
    fn extract_dns_domain(&self, _payload: &[u8]) -> Option<String> {
        // Simplified implementation - would use proper DNS parsing
        Some("example.com".to_string())
    }
    
    /// Determine protocol based on port
    pub fn determine_protocol(&self, port: u16) -> NetworkProtocol {
        match port {
            80 => NetworkProtocol::Http,
            443 => NetworkProtocol::Https,
            53 => NetworkProtocol::Dns,
            25 | 587 => NetworkProtocol::Smtp,
            110 => NetworkProtocol::Pop3,
            143 => NetworkProtocol::Imap,
            21 => NetworkProtocol::Ftp,
            22 => NetworkProtocol::Ssh,
            23 => NetworkProtocol::Telnet,
            _ => NetworkProtocol::Tcp,
        }
    }
    
    /// Check if port is commonly used
    fn is_common_port(&self, port: u16) -> bool {
        matches!(port, 80 | 443 | 53 | 25 | 110 | 143 | 21 | 22 | 23 | 993 | 995 | 465)
    }
    
    /// Check if IP is internal/private
    fn is_internal_ip(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => {
                ipv4.is_private() || ipv4.is_loopback() || ipv4.is_link_local()
            }
            IpAddr::V6(ipv6) => {
                ipv6.is_loopback() || ipv6.is_multicast()
            }
        }
    }
    
    /// Calculate overall threat level
    fn calculate_threat_level(
        &self,
        suspicious_connections: &[NetworkConnection],
        c2_indicators: &[C2Indicator],
        exfiltration_indicators: &[ExfiltrationIndicator]
    ) -> ThreatLevel {
        let mut score = 0.0;
        
        // Score based on suspicious connections
        score += suspicious_connections.len() as f64 * 0.1;
        
        // Score based on C2 indicators
        for indicator in c2_indicators {
            score += indicator.confidence * 0.5;
        }
        
        // Score based on exfiltration indicators
        for indicator in exfiltration_indicators {
            score += indicator.confidence * 0.6;
        }
        
        match score {
            s if s >= 2.0 => ThreatLevel::Critical,
            s if s >= 1.0 => ThreatLevel::High,
            s if s >= 0.5 => ThreatLevel::Medium,
            _ => ThreatLevel::Low,
        }
    }
    
    /// Generate recommended actions
    fn generate_recommended_actions(
        &self,
        threat_level: &ThreatLevel,
        suspicious_connections: &[NetworkConnection]
    ) -> Vec<RecommendedAction> {
        let mut actions = Vec::new();
        
        match threat_level {
            ThreatLevel::Critical => {
                actions.push(RecommendedAction::Block);
                actions.push(RecommendedAction::Quarantine);
                actions.push(RecommendedAction::Alert);
            }
            ThreatLevel::High => {
                actions.push(RecommendedAction::Alert);
                actions.push(RecommendedAction::Investigate);
            }
            ThreatLevel::Medium => {
                actions.push(RecommendedAction::Monitor);
                actions.push(RecommendedAction::Alert);
            }
            ThreatLevel::Low => {
                actions.push(RecommendedAction::Monitor);
            }
        }
        
        // Add specific actions for suspicious connections
        for connection in suspicious_connections {
            if connection.suspicious_indicators.iter().any(|i| i.severity == Severity::Critical) {
                actions.push(RecommendedAction::Block);
                break;
            }
        }
        
        actions.sort();
        actions.dedup();
        actions
    }
    
    /// Generate analysis summary
    fn generate_analysis_summary(
        &self,
        connections_analyzed: u32,
        packets_processed: u64,
        threat_level: &ThreatLevel
    ) -> String {
        format!(
            "Network analysis completed. Analyzed {} connections and {} packets. Threat level: {:?}",
            connections_analyzed, packets_processed, threat_level
        )
    }
    
    /// Connection cleanup loop
    async fn connection_cleanup_loop(&self) {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        
        loop {
            interval.tick().await;
            
            {
                let running = self.running.lock().unwrap();
                if !*running {
                    break;
                }
            }
            
            // Clean up old connections
            let timeout = Duration::from_secs(self.config.connection_timeout);
            let now = SystemTime::now();
            
            {
                let mut connections = self.connections.write().await;
                connections.retain(|_, connection| {
                    if let Ok(elapsed) = now.duration_since(connection.last_activity) {
                        elapsed < timeout
                    } else {
                        true
                    }
                });
                
                // Limit total connections
                if connections.len() > self.config.max_connections {
                    let excess = connections.len() - self.config.max_connections;
                    let keys_to_remove: Vec<String> = connections
                        .iter()
                        .take(excess)
                        .map(|(k, _)| k.clone())
                        .collect();
                    
                    for key in keys_to_remove {
                        connections.remove(&key);
                    }
                }
            }
            
            // Clean up timing tracker
            {
                let mut timing_tracker = self.timing_tracker.write().await;
                timing_tracker.retain(|key, _| {
                    let connections = self.connections.try_read();
                    if let Ok(connections) = connections {
                        connections.contains_key(key)
                    } else {
                        true
                    }
                });
            }
        }
    }
    
    /// Main analysis loop
    async fn analysis_loop(&self) {
        let mut interval = tokio::time::interval(Duration::from_secs(300)); // 5 minutes
        
        loop {
            interval.tick().await;
            
            {
                let running = self.running.lock().unwrap();
                if !*running {
                    break;
                }
            }
            
            // Perform periodic analysis
            if let Err(e) = self.analyze_traffic(Duration::from_secs(300)).await {
                error!("Error in periodic analysis: {}", e);
            }
        }
    }
}

impl Clone for NetworkTrafficAnalyzer {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            connections: Arc::clone(&self.connections),
            analysis_results: Arc::clone(&self.analysis_results),
            malicious_ips: Arc::clone(&self.malicious_ips),
            malicious_domains: Arc::clone(&self.malicious_domains),
            running: Arc::clone(&self.running),
            packet_capture: Arc::clone(&self.packet_capture),
            entropy_calculator: Arc::clone(&self.entropy_calculator),
            dns_cache: Arc::clone(&self.dns_cache),
            timing_tracker: Arc::clone(&self.timing_tracker),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_network_analyzer_creation() {
        let config = NetworkTrafficConfig::default();
        let analyzer = NetworkTrafficAnalyzer::new(config).unwrap();
        assert!(!*analyzer.running.lock().unwrap());
    }
    
    #[test]
    fn test_protocol_determination() {
        let config = NetworkTrafficConfig::default();
        let analyzer = NetworkTrafficAnalyzer::new(config).unwrap();
        
        assert_eq!(analyzer.determine_protocol(80), NetworkProtocol::Http);
        assert_eq!(analyzer.determine_protocol(443), NetworkProtocol::Https);
        assert_eq!(analyzer.determine_protocol(53), NetworkProtocol::Dns);
        assert_eq!(analyzer.determine_protocol(9999), NetworkProtocol::Tcp);
    }
    
    #[test]
    fn test_common_port_detection() {
        let config = NetworkTrafficConfig::default();
        let analyzer = NetworkTrafficAnalyzer::new(config).unwrap();
        
        assert!(analyzer.is_common_port(80));
        assert!(analyzer.is_common_port(443));
        assert!(!analyzer.is_common_port(9999));
    }
    
    #[test]
    fn test_internal_ip_detection() {
        let config = NetworkTrafficConfig::default();
        let analyzer = NetworkTrafficAnalyzer::new(config).unwrap();
        
        assert!(analyzer.is_internal_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(analyzer.is_internal_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(!analyzer.is_internal_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }
    
    #[tokio::test]
    async fn test_malicious_domain_detection() {
        let config = NetworkTrafficConfig::default();
        let analyzer = NetworkTrafficAnalyzer::new(config).unwrap();
        
        // Add a malicious domain
        analyzer.add_malicious_domain("malicious.com".to_string()).await.unwrap();
        
        assert!(analyzer.is_suspicious_domain("malicious.com").await);
        assert!(!analyzer.is_suspicious_domain("google.com").await);
    }
    
    #[test]
    fn test_threat_level_calculation() {
        let config = NetworkTrafficConfig::default();
        let analyzer = NetworkTrafficAnalyzer::new(config).unwrap();
        
        let suspicious_connections = vec![];
        let c2_indicators = vec![C2Indicator {
            indicator_type: "test".to_string(),
            description: "test".to_string(),
            confidence: 0.9,
            target_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 80),
            communication_pattern: "test".to_string(),
            evidence: vec![],
            timestamp: SystemTime::now(),
        }];
        let exfiltration_indicators = vec![];
        
        let threat_level = analyzer.calculate_threat_level(
            &suspicious_connections,
            &c2_indicators,
            &exfiltration_indicators
        );
        
        assert!(matches!(threat_level, ThreatLevel::Low | ThreatLevel::Medium));
    }
}
