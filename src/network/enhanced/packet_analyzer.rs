//! Enhanced packet analyzer for deep packet inspection
//! Provides comprehensive packet analysis and protocol detection

use super::*;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use std::net::{IpAddr, Ipv4Addr};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

#[cfg(feature = "enhanced-pcap")]
use etherparse::{SlicedPacket, TransportSlice, InternetSlice};

// Import AI integration types

/// Enhanced packet analyzer
pub struct PacketAnalyzer {
    /// Configuration
    config: NetworkConfig,
    /// Packet statistics
    stats: Arc<RwLock<TrafficStatistics>>,
    /// Flow tracking
    flows: Arc<RwLock<HashMap<String, NetworkFlow>>>,
    /// Threat indicators
    threat_indicators: Arc<RwLock<Vec<ThreatIndicator>>>,
    /// Analysis cache
    analysis_cache: Arc<RwLock<HashMap<String, NetworkAnalysisResult>>>,
}

impl PacketAnalyzer {
    /// Create new packet analyzer
    pub fn new(config: NetworkConfig) -> Self {
        Self {
            config,
            stats: Arc::new(RwLock::new(TrafficStatistics::default())),
            flows: Arc::new(RwLock::new(HashMap::new())),
            threat_indicators: Arc::new(RwLock::new(Vec::new())),
            analysis_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Analyze a single packet
    #[cfg(feature = "enhanced-pcap")]
    pub async fn analyze_packet(&self, packet_data: &[u8], timestamp: SystemTime) -> NetworkResult<PacketInfo> {
        let packet = SlicedPacket::from_ethernet(packet_data)
            .map_err(|e| NetworkAnalysisError::ProtocolError(format!("Failed to parse packet: {}", e)))?;

        let mut packet_info = PacketInfo {
            timestamp,
            src_ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            src_port: None,
            dst_port: None,
            protocol: ProtocolType::Unknown(0),
            size: packet_data.len(),
            payload: None,
            flags: PacketFlags::default(),
            ttl: None,
            direction: PacketDirection::Unknown,
        };

        // Extract IP information (etherparse 0.14+ uses `net` instead of `ip`)
        if let Some(net_slice) = &packet.net {
            match net_slice {
                InternetSlice::Ipv4(ipv4) => {
                    // Ipv4Slice exposes addresses via header slice
                    let src = ipv4.header().source_addr();
                    let dst = ipv4.header().destination_addr();
                    packet_info.src_ip = IpAddr::V4(src);
                    packet_info.dst_ip = IpAddr::V4(dst);
                }
                InternetSlice::Ipv6(ipv6) => {
                    // Ipv6Slice exposes addresses via header slice
                    let src = ipv6.header().source_addr();
                    let dst = ipv6.header().destination_addr();
                    packet_info.src_ip = IpAddr::V6(src);
                    packet_info.dst_ip = IpAddr::V6(dst);
                }
                // Older etherparse versions may not include ARP in InternetSlice
            }
        }

        // Extract transport layer information
        if let Some(transport) = &packet.transport {
            match transport {
                TransportSlice::Tcp(tcp_header) => {
                    packet_info.src_port = Some(tcp_header.source_port());
                    packet_info.dst_port = Some(tcp_header.destination_port());
                    packet_info.protocol = ProtocolType::Tcp;

                    // Extract TCP flags
                    packet_info.flags = PacketFlags {
                        syn: tcp_header.syn(),
                        ack: tcp_header.ack(),
                        fin: tcp_header.fin(),
                        rst: tcp_header.rst(),
                        psh: tcp_header.psh(),
                        urg: tcp_header.urg(),
                        fragmented: false,
                    };
                }
                TransportSlice::Udp(udp_header) => {
                    packet_info.src_port = Some(udp_header.source_port());
                    packet_info.dst_port = Some(udp_header.destination_port());
                    packet_info.protocol = ProtocolType::Udp;
                }
                TransportSlice::Icmpv4(_) | TransportSlice::Icmpv6(_) => {
                    // ICMP has no ports; mark protocol and proceed
                    packet_info.src_port = None;
                    packet_info.dst_port = None;
                    packet_info.protocol = ProtocolType::Icmp;
                }
            }
        }

        // Determine packet direction
        packet_info.direction = self.determine_packet_direction(&packet_info.src_ip, &packet_info.dst_ip);

        // Extract payload if enabled (use layer payloads in etherparse 0.14+)
        if self.config.enable_dpi {
            // Prefer transport payload, else fall back to net/ip payload slice
            let payload_opt: Option<&[u8]> = if let Some(transport) = &packet.transport {
                match transport {
                    TransportSlice::Tcp(tcp) => Some(tcp.payload()),
                    TransportSlice::Udp(udp) => Some(udp.payload()),
                    TransportSlice::Icmpv4(icmp4) => Some(icmp4.payload()),
                    TransportSlice::Icmpv6(icmp6) => Some(icmp6.payload()),
                }
            } else if let Some(net_slice) = &packet.net {
                // NetSlice can return an IpPayloadSlice; extract its raw slice
                match net_slice.ip_payload_ref() {
                    Some(ip_payload) => Some(ip_payload.payload),
                    None => None,
                }
            } else if let Some(link) = &packet.link {
                // As a last resort, extract the link layer payload
                let ether_payload = link.payload();
                Some(ether_payload.payload)
            } else {
                None
            };

            if let Some(payload) = payload_opt {
                if !payload.is_empty() {
                    let payload_size = payload.len().min(self.config.max_capture_size);
                    packet_info.payload = Some(payload[..payload_size].to_vec());
                }
            }

            // Detect application protocol from payload
            if let Some(app_protocol) = self.detect_application_protocol(&packet_info).await {
                match app_protocol.as_str() {
                    "HTTP" => packet_info.protocol = ProtocolType::Http,
                    "HTTPS" => packet_info.protocol = ProtocolType::Https,
                    "DNS" => packet_info.protocol = ProtocolType::Dns,
                    "FTP" => packet_info.protocol = ProtocolType::Ftp,
                    "SSH" => packet_info.protocol = ProtocolType::Ssh,
                    "SMTP" => packet_info.protocol = ProtocolType::Smtp,
                    _ => {}
                }
            }
        }

        // Update statistics
        self.update_packet_statistics(&packet_info).await;

        // Update or create flow
        self.update_flow_tracking(&packet_info).await?;

        debug!("Analyzed packet: {}:{:?} -> {}:{:?} ({})", 
               packet_info.src_ip, packet_info.src_port,
               packet_info.dst_ip, packet_info.dst_port,
               format!("{:?}", packet_info.protocol));

        Ok(packet_info)
    }

    /// Analyze packet without enhanced-pcap feature
    #[cfg(not(feature = "enhanced-pcap"))]
    pub async fn analyze_packet(&self, packet_data: &[u8], timestamp: SystemTime) -> NetworkResult<PacketInfo> {
        warn!("Enhanced PCAP feature not enabled, returning basic packet info");
        
        Ok(PacketInfo {
            timestamp,
            src_ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            src_port: None,
            dst_port: None,
            protocol: ProtocolType::Unknown(0),
            size: packet_data.len(),
            payload: None,
            flags: PacketFlags::default(),
            ttl: None,
            direction: PacketDirection::Unknown,
        })
    }

    /// Map protocol number to protocol type
    fn map_protocol(&self, protocol: u8) -> ProtocolType {
        match protocol {
            1 => ProtocolType::Icmp,
            6 => ProtocolType::Tcp,
            17 => ProtocolType::Udp,
            _ => ProtocolType::Unknown(protocol),
        }
    }

    /// Determine packet direction based on IP addresses
    fn determine_packet_direction(&self, src_ip: &IpAddr, dst_ip: &IpAddr) -> PacketDirection {
        let src_private = utils::is_private_ip(src_ip);
        let dst_private = utils::is_private_ip(dst_ip);

        match (src_private, dst_private) {
            (true, true) => PacketDirection::Internal,
            (true, false) => PacketDirection::Outbound,
            (false, true) => PacketDirection::Inbound,
            (false, false) => PacketDirection::Unknown,
        }
    }

    /// Detect application protocol from packet payload
    async fn detect_application_protocol(&self, packet_info: &PacketInfo) -> Option<String> {
        if let Some(payload) = &packet_info.payload {
            if payload.is_empty() {
                return None;
            }

            // HTTP detection
            if payload.starts_with(b"GET ") || payload.starts_with(b"POST ") || 
               payload.starts_with(b"PUT ") || payload.starts_with(b"DELETE ") ||
               payload.starts_with(b"HTTP/") {
                return Some("HTTP".to_string());
            }

            // HTTPS/TLS detection
            if payload.len() >= 6 && payload[0] == 0x16 && payload[1] == 0x03 {
                return Some("HTTPS".to_string());
            }

            // DNS detection
            if packet_info.protocol == ProtocolType::Udp && 
               (packet_info.src_port == Some(53) || packet_info.dst_port == Some(53)) {
                return Some("DNS".to_string());
            }

            // SSH detection
            if payload.starts_with(b"SSH-") {
                return Some("SSH".to_string());
            }

            // FTP detection
            if payload.starts_with(b"220 ") || payload.starts_with(b"USER ") || 
               payload.starts_with(b"PASS ") {
                return Some("FTP".to_string());
            }

            // SMTP detection
            if payload.starts_with(b"220 ") || payload.starts_with(b"HELO ") || 
               payload.starts_with(b"EHLO ") || payload.starts_with(b"MAIL FROM:") {
                return Some("SMTP".to_string());
            }
        }

        None
    }

    /// Update packet statistics
    async fn update_packet_statistics(&self, packet_info: &PacketInfo) {
        let mut stats = self.stats.write().await;
        
        stats.total_packets += 1;
        stats.total_bytes += packet_info.size as u64;
        
        // Update protocol distribution
        let protocol_name = format!("{:?}", packet_info.protocol);
        *stats.protocol_distribution.entry(protocol_name).or_insert(0) += 1;
        
        // Update port distribution
        if let Some(port) = packet_info.dst_port {
            *stats.port_distribution.entry(port).or_insert(0) += 1;
        }
        
        // Update average packet size
        stats.average_packet_size = stats.total_bytes as f64 / stats.total_packets as f64;
    }

    /// Update flow tracking
    async fn update_flow_tracking(&self, packet_info: &PacketInfo) -> NetworkResult<()> {
        let src_endpoint = NetworkEndpoint {
            ip: packet_info.src_ip,
            port: packet_info.src_port,
            hostname: None,
            geolocation: None,
            reputation: None,
        };

        let dst_endpoint = NetworkEndpoint {
            ip: packet_info.dst_ip,
            port: packet_info.dst_port,
            hostname: None,
            geolocation: None,
            reputation: None,
        };

        let flow_id = utils::generate_flow_id(&src_endpoint, &dst_endpoint, &packet_info.protocol);
        
        let mut flows = self.flows.write().await;
        
        if let Some(flow) = flows.get_mut(&flow_id) {
            // Update existing flow
            flow.total_bytes += packet_info.size as u64;
            flow.total_packets += 1;
            flow.end_time = Some(packet_info.timestamp);
            
            if let Some(start_time) = flow.start_time.elapsed().ok() {
                flow.duration = Some(start_time);
            }
        } else {
            // Create new flow
            let new_flow = NetworkFlow {
                flow_id: flow_id.clone(),
                src_endpoint,
                dst_endpoint,
                protocol: packet_info.protocol.clone(),
                start_time: packet_info.timestamp,
                end_time: None,
                total_bytes: packet_info.size as u64,
                total_packets: 1,
                duration: None,
                state: FlowState::Active,
                application_protocol: self.detect_application_protocol(packet_info).await,
                metadata: HashMap::new(),
            };
            
            flows.insert(flow_id, new_flow);
        }

        Ok(())
    }

    /// Analyze multiple packets in batch
    pub async fn analyze_packets_batch(&self, packets: Vec<(Vec<u8>, SystemTime)>) -> NetworkResult<Vec<PacketInfo>> {
        let mut results = Vec::new();
        
        for (packet_data, timestamp) in packets {
            match self.analyze_packet(&packet_data, timestamp).await {
                Ok(packet_info) => results.push(packet_info),
                Err(e) => {
                    warn!("Failed to analyze packet: {}", e);
                    continue;
                }
            }
        }
        
        info!("Analyzed {} packets in batch", results.len());
        Ok(results)
    }

    /// Get current flows
    pub async fn get_flows(&self) -> Vec<NetworkFlow> {
        let flows = self.flows.read().await;
        flows.values().cloned().collect()
    }

    /// Get traffic statistics
    pub async fn get_statistics(&self) -> TrafficStatistics {
        let stats = self.stats.read().await;
        stats.clone()
    }

    /// Add threat indicators
    pub async fn add_threat_indicators(&self, indicators: Vec<ThreatIndicator>) {
        let mut threat_indicators = self.threat_indicators.write().await;
        threat_indicators.extend(indicators);
        info!("Added {} threat indicators", threat_indicators.len());
    }

    /// Check packet against threat indicators
    pub async fn check_threat_indicators(&self, packet_info: &PacketInfo) -> Vec<ThreatIndicator> {
        let threat_indicators = self.threat_indicators.read().await;
        let mut matches = Vec::new();

        for indicator in threat_indicators.iter() {
            match indicator.indicator_type {
                ThreatIndicatorType::MaliciousIp => {
                    if packet_info.src_ip.to_string() == indicator.value || 
                       packet_info.dst_ip.to_string() == indicator.value {
                        matches.push(indicator.clone());
                    }
                }
                ThreatIndicatorType::SuspiciousDomain => {
                    // Would need DNS resolution for domain matching
                    // This is a simplified check
                }
                _ => {
                    // Other indicator types would be checked here
                }
            }
        }

        matches
    }

    /// Cleanup old flows
    pub async fn cleanup_old_flows(&self, max_age: Duration) {
        let mut flows = self.flows.write().await;
        let _now = SystemTime::now();
        
        flows.retain(|_, flow| {
            if let Ok(elapsed) = flow.start_time.elapsed() {
                elapsed < max_age
            } else {
                false
            }
        });
        
        debug!("Cleaned up old flows, {} flows remaining", flows.len());
    }

    /// Generate analysis summary
    pub async fn generate_analysis_summary(&self) -> NetworkAnalysisResult {
        let stats = self.get_statistics().await;
        let flows = self.get_flows().await;
        let threat_indicators = self.threat_indicators.read().await;
        
        // Detect anomalies (simplified)
        let mut anomalies = Vec::new();
        
        // Check for unusual port usage
        for (port, count) in &stats.port_distribution {
            if utils::is_suspicious_port(*port) && *count > 10 {
                anomalies.push(NetworkAnomaly {
                    anomaly_type: AnomalyType::PortAnomaly,
                    severity: AnomalySeverity::Medium,
                    description: format!("Suspicious port {} used {} times", port, count),
                    affected_flows: Vec::new(),
                    confidence: 0.7,
                    detected_at: SystemTime::now(),
                    metadata: HashMap::new(),
                });
            }
        }

        NetworkAnalysisResult {
            timestamp: SystemTime::now(),
            flows,
            protocols: HashMap::new(), // Would be populated from stats
            statistics: stats,
            anomalies,
            threat_indicators: threat_indicators.clone(),
            confidence: 0.8,
            processing_time: Duration::from_millis(0), // Would be measured
        }
    }
}

#[async_trait::async_trait]
impl NetworkAnalyzer for PacketAnalyzer {
    async fn start_analysis(&mut self, config: NetworkConfig) -> NetworkResult<()> {
        self.config = config;
        info!("Started packet analysis with DPI: {}", self.config.enable_dpi);
        Ok(())
    }

    async fn stop_analysis(&mut self) -> NetworkResult<()> {
        info!("Stopped packet analysis");
        Ok(())
    }

    async fn analyze_packets(&self, _packets: &[PacketInfo]) -> NetworkResult<NetworkAnalysisResult> {
        // This would process already parsed packets
        let stats = self.get_statistics().await;
        
        Ok(NetworkAnalysisResult {
            timestamp: SystemTime::now(),
            flows: Vec::new(),
            protocols: HashMap::new(),
            statistics: stats,
            anomalies: Vec::new(),
            threat_indicators: Vec::new(),
            confidence: 0.8,
            processing_time: Duration::from_millis(0),
        })
    }

    async fn get_results(&self) -> NetworkResult<NetworkAnalysisResult> {
        Ok(self.generate_analysis_summary().await)
    }

    async fn add_threat_indicators(&mut self, indicators: Vec<ThreatIndicator>) -> NetworkResult<()> {
        PacketAnalyzer::add_threat_indicators(self, indicators).await;
        Ok(())
    }

    fn get_statistics(&self) -> TrafficStatistics {
        // Synchronous version - would need to be implemented differently
        TrafficStatistics::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_packet_analyzer_creation() {
        let config = NetworkConfig::default();
        let analyzer = PacketAnalyzer::new(config);
        
        let stats = analyzer.get_statistics().await;
        assert_eq!(stats.total_packets, 0);
    }

    #[tokio::test]
    async fn test_flow_tracking() {
        let config = NetworkConfig::default();
        let analyzer = PacketAnalyzer::new(config);
        
        let packet_info = PacketInfo {
            timestamp: SystemTime::now(),
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            src_port: Some(12345),
            dst_port: Some(80),
            protocol: ProtocolType::Tcp,
            size: 1024,
            payload: None,
            flags: PacketFlags::default(),
            ttl: Some(64),
            direction: PacketDirection::Outbound,
        };
        
        analyzer.update_flow_tracking(&packet_info).await.unwrap();
        
        let flows = analyzer.get_flows().await;
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].total_packets, 1);
        assert_eq!(flows[0].total_bytes, 1024);
    }

    #[test]
    fn test_protocol_mapping() {
        let config = NetworkConfig::default();
        let analyzer = PacketAnalyzer::new(config);
        
        assert_eq!(analyzer.map_protocol(1), ProtocolType::Icmp);
        assert_eq!(analyzer.map_protocol(6), ProtocolType::Tcp);
        assert_eq!(analyzer.map_protocol(17), ProtocolType::Udp);
        assert_eq!(analyzer.map_protocol(255), ProtocolType::Unknown(255));
    }

    #[test]
    fn test_packet_direction_determination() {
        let config = NetworkConfig::default();
        let analyzer = PacketAnalyzer::new(config);
        
        let private_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let public_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        
        assert_eq!(analyzer.determine_packet_direction(&private_ip, &public_ip), PacketDirection::Outbound);
        assert_eq!(analyzer.determine_packet_direction(&public_ip, &private_ip), PacketDirection::Inbound);
        assert_eq!(analyzer.determine_packet_direction(&private_ip, &private_ip), PacketDirection::Internal);
    }
}
