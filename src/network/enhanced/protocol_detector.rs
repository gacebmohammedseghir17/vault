//! Protocol detection engine for network traffic analysis
//! Provides deep protocol inspection and classification

use super::*;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;
use tracing::{debug, info};

/// Protocol detection patterns
#[derive(Debug, Clone)]
pub struct ProtocolPattern {
    /// Pattern name
    pub name: String,
    /// Protocol type
    pub protocol: ProtocolType,
    /// Byte pattern to match
    pub pattern: Vec<u8>,
    /// Pattern offset in packet
    pub offset: usize,
    /// Pattern mask (for partial matching)
    pub mask: Option<Vec<u8>>,
    /// Minimum packet size required
    pub min_size: usize,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f32,
}

/// Protocol detection result
#[derive(Debug, Clone)]
pub struct ProtocolDetectionResult {
    /// Detected protocol
    pub protocol: ProtocolType,
    /// Confidence score
    pub confidence: f32,
    /// Matched patterns
    pub matched_patterns: Vec<String>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Protocol detector engine
#[derive(Clone)]
pub struct ProtocolDetector {
    /// Detection patterns
    patterns: Arc<RwLock<Vec<ProtocolPattern>>>,
    /// Detection cache
    cache: Arc<RwLock<HashMap<Vec<u8>, ProtocolDetectionResult>>>,
    /// Detection statistics
    stats: Arc<RwLock<ProtocolDetectionStats>>,
}

/// Protocol detection statistics
#[derive(Debug, Clone, Default)]
pub struct ProtocolDetectionStats {
    /// Total detections performed
    pub total_detections: u64,
    /// Cache hits
    pub cache_hits: u64,
    /// Protocol distribution
    pub protocol_distribution: HashMap<String, u64>,
    /// Average detection time
    pub average_detection_time: Duration,
    /// Pattern match statistics
    pub pattern_matches: HashMap<String, u64>,
}

impl ProtocolDetector {
    /// Create new protocol detector
    pub fn new() -> Self {
        let detector = Self {
            patterns: Arc::new(RwLock::new(Vec::new())),
            cache: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(ProtocolDetectionStats::default())),
        };
        
        // Initialize with default patterns
        let detector_clone = detector.clone();
        tokio::spawn(async move {
            detector_clone.initialize_default_patterns().await;
        });
        
        detector
    }

    /// Initialize default protocol patterns
    async fn initialize_default_patterns(&self) {
        let mut patterns = self.patterns.write().await;
        
        // HTTP patterns
        patterns.push(ProtocolPattern {
            name: "HTTP_GET".to_string(),
            protocol: ProtocolType::Http,
            pattern: b"GET ".to_vec(),
            offset: 0,
            mask: None,
            min_size: 4,
            confidence: 0.95,
        });
        
        patterns.push(ProtocolPattern {
            name: "HTTP_POST".to_string(),
            protocol: ProtocolType::Http,
            pattern: b"POST ".to_vec(),
            offset: 0,
            mask: None,
            min_size: 5,
            confidence: 0.95,
        });
        
        patterns.push(ProtocolPattern {
            name: "HTTP_RESPONSE".to_string(),
            protocol: ProtocolType::Http,
            pattern: b"HTTP/".to_vec(),
            offset: 0,
            mask: None,
            min_size: 5,
            confidence: 0.90,
        });

        // HTTPS/TLS patterns
        patterns.push(ProtocolPattern {
            name: "TLS_HANDSHAKE".to_string(),
            protocol: ProtocolType::Https,
            pattern: vec![0x16, 0x03],
            offset: 0,
            mask: Some(vec![0xFF, 0xFF]),
            min_size: 5,
            confidence: 0.92,
        });

        patterns.push(ProtocolPattern {
            name: "TLS_APPLICATION_DATA".to_string(),
            protocol: ProtocolType::Https,
            pattern: vec![0x17, 0x03],
            offset: 0,
            mask: Some(vec![0xFF, 0xFF]),
            min_size: 6,
            confidence: 0.85,
        });

        // SSH patterns
        patterns.push(ProtocolPattern {
            name: "SSH_VERSION".to_string(),
            protocol: ProtocolType::Ssh,
            pattern: b"SSH-".to_vec(),
            offset: 0,
            mask: None,
            min_size: 4,
            confidence: 0.95,
        });

        // FTP patterns
        patterns.push(ProtocolPattern {
            name: "FTP_WELCOME".to_string(),
            protocol: ProtocolType::Ftp,
            pattern: b"220 ".to_vec(),
            offset: 0,
            mask: None,
            min_size: 4,
            confidence: 0.80,
        });

        patterns.push(ProtocolPattern {
            name: "FTP_USER".to_string(),
            protocol: ProtocolType::Ftp,
            pattern: b"USER ".to_vec(),
            offset: 0,
            mask: None,
            min_size: 5,
            confidence: 0.85,
        });

        // SMTP patterns
        patterns.push(ProtocolPattern {
            name: "SMTP_WELCOME".to_string(),
            protocol: ProtocolType::Smtp,
            pattern: b"220 ".to_vec(),
            offset: 0,
            mask: None,
            min_size: 4,
            confidence: 0.75, // Lower confidence due to overlap with FTP
        });

        patterns.push(ProtocolPattern {
            name: "SMTP_HELO".to_string(),
            protocol: ProtocolType::Smtp,
            pattern: b"HELO ".to_vec(),
            offset: 0,
            mask: None,
            min_size: 5,
            confidence: 0.90,
        });

        patterns.push(ProtocolPattern {
            name: "SMTP_EHLO".to_string(),
            protocol: ProtocolType::Smtp,
            pattern: b"EHLO ".to_vec(),
            offset: 0,
            mask: None,
            min_size: 5,
            confidence: 0.90,
        });

        // DNS patterns
        patterns.push(ProtocolPattern {
            name: "DNS_QUERY".to_string(),
            protocol: ProtocolType::Dns,
            pattern: vec![0x00, 0x00, 0x01, 0x00], // Standard query flags
            offset: 2,
            mask: Some(vec![0x00, 0x00, 0xFF, 0xFF]),
            min_size: 12,
            confidence: 0.80,
        });

        // DHCP patterns
        patterns.push(ProtocolPattern {
            name: "DHCP_REQUEST".to_string(),
            protocol: ProtocolType::Unknown(67), // DHCP
            pattern: vec![0x01], // Boot request
            offset: 0,
            mask: None,
            min_size: 236,
            confidence: 0.70,
        });

        // BitTorrent patterns
        patterns.push(ProtocolPattern {
            name: "BITTORRENT_HANDSHAKE".to_string(),
            protocol: ProtocolType::Tcp, // BitTorrent typically runs over TCP (e.g., port 6881)
            pattern: vec![0x13], // Protocol string length
            offset: 0,
            mask: None,
            min_size: 68,
            confidence: 0.85,
        });

        info!("Initialized {} protocol detection patterns", patterns.len());
    }

    /// Detect protocol from packet payload
    pub async fn detect_protocol(&self, payload: &[u8], packet_info: &PacketInfo) -> ProtocolDetectionResult {
        let start_time = SystemTime::now();
        
        // Check cache first
        if let Some(cached_result) = self.check_cache(payload).await {
            self.update_cache_hit_stats().await;
            return cached_result;
        }

        let mut best_match = ProtocolDetectionResult {
            protocol: ProtocolType::Unknown(0),
            confidence: 0.0,
            matched_patterns: Vec::new(),
            metadata: HashMap::new(),
        };

        let patterns = self.patterns.read().await;
        
        // Try to match against all patterns
        for pattern in patterns.iter() {
            if let Some(detection_result) = self.match_pattern(pattern, payload, packet_info).await {
                if detection_result.confidence > best_match.confidence {
                    best_match = detection_result;
                }
            }
        }

        // If no pattern matched, try heuristic detection
        if best_match.confidence == 0.0 {
            best_match = self.heuristic_detection(payload, packet_info).await;
        }

        // Cache the result
        self.cache_result(payload.to_vec(), best_match.clone()).await;
        
        // Update statistics
        self.update_detection_stats(&best_match, start_time.elapsed().unwrap_or_default()).await;
        
        debug!("Detected protocol: {:?} with confidence: {:.2}", 
               best_match.protocol, best_match.confidence);
        
        best_match
    }

    /// Match a specific pattern against payload
    async fn match_pattern(&self, pattern: &ProtocolPattern, payload: &[u8], packet_info: &PacketInfo) -> Option<ProtocolDetectionResult> {
        // Check minimum size requirement
        if payload.len() < pattern.min_size {
            return None;
        }

        // Check if pattern fits within payload
        if pattern.offset + pattern.pattern.len() > payload.len() {
            return None;
        }

        // Extract the relevant portion of payload
        let payload_slice = &payload[pattern.offset..pattern.offset + pattern.pattern.len()];
        
        // Perform pattern matching
        let matches = if let Some(mask) = &pattern.mask {
            self.masked_pattern_match(payload_slice, &pattern.pattern, mask)
        } else {
            payload_slice == pattern.pattern.as_slice()
        };

        if matches {
            let mut metadata = HashMap::new();
            metadata.insert("pattern_name".to_string(), pattern.name.clone());
            metadata.insert("pattern_offset".to_string(), pattern.offset.to_string());
            
            // Add protocol-specific metadata
            self.add_protocol_metadata(&mut metadata, &pattern.protocol, payload, packet_info).await;
            
            Some(ProtocolDetectionResult {
                protocol: pattern.protocol.clone(),
                confidence: pattern.confidence,
                matched_patterns: vec![pattern.name.clone()],
                metadata,
            })
        } else {
            None
        }
    }

    /// Perform masked pattern matching
    fn masked_pattern_match(&self, payload: &[u8], pattern: &[u8], mask: &[u8]) -> bool {
        if payload.len() != pattern.len() || pattern.len() != mask.len() {
            return false;
        }

        for i in 0..payload.len() {
            if (payload[i] & mask[i]) != (pattern[i] & mask[i]) {
                return false;
            }
        }

        true
    }

    /// Add protocol-specific metadata
    async fn add_protocol_metadata(&self, metadata: &mut HashMap<String, String>, protocol: &ProtocolType, payload: &[u8], packet_info: &PacketInfo) {
        match protocol {
            ProtocolType::Http => {
                if let Ok(http_data) = std::str::from_utf8(payload) {
                    // Extract HTTP method and path
                    if let Some(first_line) = http_data.lines().next() {
                        let parts: Vec<&str> = first_line.split_whitespace().collect();
                        if parts.len() >= 3 {
                            metadata.insert("http_method".to_string(), parts[0].to_string());
                            metadata.insert("http_path".to_string(), parts[1].to_string());
                            metadata.insert("http_version".to_string(), parts[2].to_string());
                        }
                    }
                    
                    // Extract User-Agent if present
                    for line in http_data.lines() {
                        if line.to_lowercase().starts_with("user-agent:") {
                            metadata.insert("user_agent".to_string(), line[11..].trim().to_string());
                            break;
                        }
                    }
                }
            }
            ProtocolType::Https => {
                if payload.len() >= 6 {
                    metadata.insert("tls_version".to_string(), format!("{}.{}", payload[1], payload[2]));
                    metadata.insert("tls_length".to_string(), 
                                  ((payload[3] as u16) << 8 | payload[4] as u16).to_string());
                }
            }
            ProtocolType::Dns => {
                if payload.len() >= 12 {
                    let transaction_id = (payload[0] as u16) << 8 | payload[1] as u16;
                    let flags = (payload[2] as u16) << 8 | payload[3] as u16;
                    let questions = (payload[4] as u16) << 8 | payload[5] as u16;
                    
                    metadata.insert("dns_transaction_id".to_string(), transaction_id.to_string());
                    metadata.insert("dns_flags".to_string(), format!("0x{:04x}", flags));
                    metadata.insert("dns_questions".to_string(), questions.to_string());
                    metadata.insert("dns_query_type".to_string(), 
                                  if flags & 0x8000 == 0 { "query" } else { "response" }.to_string());
                }
            }
            _ => {}
        }

        // Add common metadata
        metadata.insert("payload_size".to_string(), payload.len().to_string());
        metadata.insert("src_port".to_string(), packet_info.src_port.map_or("unknown".to_string(), |p| p.to_string()));
        metadata.insert("dst_port".to_string(), packet_info.dst_port.map_or("unknown".to_string(), |p| p.to_string()));
    }

    /// Heuristic protocol detection when patterns don't match
    async fn heuristic_detection(&self, payload: &[u8], packet_info: &PacketInfo) -> ProtocolDetectionResult {
        let mut metadata = HashMap::new();
        metadata.insert("detection_method".to_string(), "heuristic".to_string());

        // Port-based detection
        if let Some(dst_port) = packet_info.dst_port {
            let (protocol, confidence) = match dst_port {
                80 => (ProtocolType::Http, 0.6),
                443 => (ProtocolType::Https, 0.6),
                22 => (ProtocolType::Ssh, 0.7),
                21 => (ProtocolType::Ftp, 0.7),
                25 | 587 => (ProtocolType::Smtp, 0.6),
                53 => (ProtocolType::Dns, 0.7),
                _ => (ProtocolType::Unknown(dst_port as u8), 0.3),
            };

            metadata.insert("port_based_detection".to_string(), "true".to_string());
            metadata.insert("detected_port".to_string(), dst_port.to_string());

            return ProtocolDetectionResult {
                protocol,
                confidence,
                matched_patterns: vec!["port_heuristic".to_string()],
                metadata,
            };
        }

        // Payload entropy analysis
        let entropy = utils::calculate_payload_entropy(payload);
        metadata.insert("payload_entropy".to_string(), format!("{:.2}", entropy));

        // High entropy might indicate encrypted traffic
        if entropy > 7.5 {
            return ProtocolDetectionResult {
                protocol: ProtocolType::Https,
                confidence: 0.4,
                matched_patterns: vec!["entropy_heuristic".to_string()],
                metadata,
            };
        }

        // Default unknown protocol
        ProtocolDetectionResult {
            protocol: ProtocolType::Unknown(0),
            confidence: 0.1,
            matched_patterns: vec!["default_unknown".to_string()],
            metadata,
        }
    }

    /// Check detection cache
    async fn check_cache(&self, payload: &[u8]) -> Option<ProtocolDetectionResult> {
        let cache = self.cache.read().await;
        
        // Use first 64 bytes as cache key to avoid memory issues
        let cache_key = payload.iter().take(64).cloned().collect::<Vec<u8>>();
        cache.get(&cache_key).cloned()
    }

    /// Cache detection result
    async fn cache_result(&self, payload: Vec<u8>, result: ProtocolDetectionResult) {
        let mut cache = self.cache.write().await;
        
        // Limit cache size
        if cache.len() > 1000 {
            cache.clear();
        }
        
        // Use first 64 bytes as cache key
        let cache_key = payload.into_iter().take(64).collect::<Vec<u8>>();
        cache.insert(cache_key, result);
    }

    /// Update cache hit statistics
    async fn update_cache_hit_stats(&self) {
        let mut stats = self.stats.write().await;
        stats.cache_hits += 1;
    }

    /// Update detection statistics
    async fn update_detection_stats(&self, result: &ProtocolDetectionResult, detection_time: Duration) {
        let mut stats = self.stats.write().await;
        
        stats.total_detections += 1;
        
        // Update protocol distribution
        let protocol_name = format!("{:?}", result.protocol);
        *stats.protocol_distribution.entry(protocol_name).or_insert(0) += 1;
        
        // Update pattern match statistics
        for pattern in &result.matched_patterns {
            *stats.pattern_matches.entry(pattern.clone()).or_insert(0) += 1;
        }
        
        // Update average detection time
        let total_time = stats.average_detection_time.as_nanos() as u64 * (stats.total_detections - 1) + detection_time.as_nanos() as u64;
        stats.average_detection_time = Duration::from_nanos(total_time / stats.total_detections);
    }

    /// Add custom protocol pattern
    pub async fn add_pattern(&self, pattern: ProtocolPattern) {
        let mut patterns = self.patterns.write().await;
        patterns.push(pattern);
        info!("Added custom protocol pattern");
    }

    /// Get detection statistics
    pub async fn get_statistics(&self) -> ProtocolDetectionStats {
        let stats = self.stats.read().await;
        stats.clone()
    }

    /// Clear detection cache
    pub async fn clear_cache(&self) {
        let mut cache = self.cache.write().await;
        cache.clear();
        info!("Cleared protocol detection cache");
    }

    /// Batch protocol detection
    pub async fn detect_protocols_batch(&self, packets: &[(Vec<u8>, PacketInfo)]) -> Vec<ProtocolDetectionResult> {
        let mut results = Vec::new();
        
        for (payload, packet_info) in packets {
            let result = self.detect_protocol(payload, packet_info).await;
            results.push(result);
        }
        
        info!("Performed batch protocol detection on {} packets", packets.len());
        results
    }
}

impl Default for ProtocolDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_protocol_detector_creation() {
        let detector = ProtocolDetector::new();
        
        // Wait for initialization
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        let patterns = detector.patterns.read().await;
        assert!(!patterns.is_empty());
    }

    #[tokio::test]
    async fn test_http_detection() {
        let detector = ProtocolDetector::new();
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        let http_payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let packet_info = PacketInfo {
            timestamp: SystemTime::now(),
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            src_port: Some(12345),
            dst_port: Some(80),
            protocol: ProtocolType::Tcp,
            size: http_payload.len(),
            payload: None,
            flags: PacketFlags::default(),
            ttl: Some(64),
            direction: PacketDirection::Outbound,
        };
        
        let result = detector.detect_protocol(http_payload, &packet_info).await;
        
        assert_eq!(result.protocol, ProtocolType::Http);
        assert!(result.confidence > 0.9);
        assert!(!result.matched_patterns.is_empty());
    }

    #[tokio::test]
    async fn test_tls_detection() {
        let detector = ProtocolDetector::new();
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        let tls_payload = vec![0x16, 0x03, 0x01, 0x00, 0x20]; // TLS handshake
        let packet_info = PacketInfo {
            timestamp: SystemTime::now(),
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            src_port: Some(12345),
            dst_port: Some(443),
            protocol: ProtocolType::Tcp,
            size: tls_payload.len(),
            payload: None,
            flags: PacketFlags::default(),
            ttl: Some(64),
            direction: PacketDirection::Outbound,
        };
        
        let result = detector.detect_protocol(&tls_payload, &packet_info).await;
        
        assert_eq!(result.protocol, ProtocolType::Https);
        assert!(result.confidence > 0.8);
    }

    #[tokio::test]
    async fn test_heuristic_detection() {
        let detector = ProtocolDetector::new();
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        let unknown_payload = b"unknown protocol data";
        let packet_info = PacketInfo {
            timestamp: SystemTime::now(),
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            src_port: Some(12345),
            dst_port: Some(80), // HTTP port
            protocol: ProtocolType::Tcp,
            size: unknown_payload.len(),
            payload: None,
            flags: PacketFlags::default(),
            ttl: Some(64),
            direction: PacketDirection::Outbound,
        };
        
        let result = detector.detect_protocol(unknown_payload, &packet_info).await;
        
        // Should fall back to port-based heuristic
        assert_eq!(result.protocol, ProtocolType::Http);
        assert!(result.confidence > 0.5);
        assert!(result.matched_patterns.contains(&"port_heuristic".to_string()));
    }

    #[tokio::test]
    async fn test_pattern_caching() {
        let detector = ProtocolDetector::new();
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        let http_payload = b"GET /test HTTP/1.1\r\n\r\n";
        let packet_info = PacketInfo {
            timestamp: SystemTime::now(),
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            src_port: Some(12345),
            dst_port: Some(80),
            protocol: ProtocolType::Tcp,
            size: http_payload.len(),
            payload: None,
            flags: PacketFlags::default(),
            ttl: Some(64),
            direction: PacketDirection::Outbound,
        };
        
        // First detection
        let result1 = detector.detect_protocol(http_payload, &packet_info).await;
        
        // Second detection (should hit cache)
        let result2 = detector.detect_protocol(http_payload, &packet_info).await;
        
        assert_eq!(result1.protocol, result2.protocol);
        assert_eq!(result1.confidence, result2.confidence);
        
        let stats = detector.get_statistics().await;
        assert!(stats.cache_hits > 0);
    }
}
