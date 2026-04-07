//! Network Exfiltration Detection Module
//!
//! This module implements real-time network traffic analysis to detect:
//! - C2 (Command & Control) beacon communications
//! - Data exfiltration attempts
//! - Suspicious HTTP/HTTPS traffic patterns
//! - DNS tunneling and other covert channels

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tokio::time::interval;
use tracing::{info, warn, error};
use serde::{Deserialize, Serialize};

/// Network connection information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub protocol: NetworkProtocol,
    pub state: ConnectionState,
    pub process_id: u32,
    pub process_name: String,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub established_time: SystemTime,
    pub last_activity: SystemTime,
}

/// Network protocol types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkProtocol {
    Tcp,
    Udp,
    Http,
    Https,
    Dns,
    Other(u8),
}

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionState {
    Established,
    Listening,
    Closed,
    TimeWait,
}

/// C2 beacon detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconDetection {
    pub remote_addr: IpAddr,
    pub confidence: f64,
    pub beacon_interval: Duration,
    pub jitter_factor: f64,
    pub packet_count: u32,
    pub first_seen: SystemTime,
    pub last_seen: SystemTime,
    pub detection_reasons: Vec<String>,
}

/// Data exfiltration alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExfiltrationAlert {
    pub alert_id: String,
    pub severity: AlertSeverity,
    pub remote_addr: IpAddr,
    pub process_name: String,
    pub process_id: u32,
    pub bytes_transferred: u64,
    pub transfer_rate: f64, // bytes per second
    pub duration: Duration,
    pub detection_time: SystemTime,
    pub indicators: Vec<String>,
}

/// Alert severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlertSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Network traffic statistics
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
struct TrafficStats {
    packet_times: VecDeque<SystemTime>,
    byte_counts: VecDeque<u64>,
    intervals: VecDeque<Duration>,
    total_bytes: u64,
    packet_count: u32,
}

/// Configuration for exfiltration detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExfiltrationConfig {
    /// Minimum beacon interval to detect (seconds)
    pub min_beacon_interval: u64,
    /// Maximum beacon interval to detect (seconds)
    pub max_beacon_interval: u64,
    /// Maximum jitter factor for beacon detection (0.0-1.0)
    pub max_jitter_factor: f64,
    /// Minimum confidence threshold for beacon detection (0.0-1.0)
    pub beacon_confidence_threshold: f64,
    /// Data transfer rate threshold (bytes/sec) for exfiltration alerts
    pub exfiltration_rate_threshold: u64,
    /// Minimum transfer size for exfiltration detection (bytes)
    pub min_exfiltration_size: u64,
    /// Time window for traffic analysis (seconds)
    pub analysis_window: u64,
    /// Suspicious domains/IPs to monitor
    pub suspicious_indicators: Vec<String>,
}

impl Default for ExfiltrationConfig {
    fn default() -> Self {
        Self {
            min_beacon_interval: 30,
            max_beacon_interval: 3600,
            max_jitter_factor: 0.3,
            beacon_confidence_threshold: 0.7,
            exfiltration_rate_threshold: 1024 * 1024, // 1 MB/s
            min_exfiltration_size: 10 * 1024 * 1024, // 10 MB
            analysis_window: 300, // 5 minutes
            suspicious_indicators: vec![
                "pastebin.com".to_string(),
                "discord.com".to_string(),
                "telegram.org".to_string(),
                "dropbox.com".to_string(),
                "mega.nz".to_string(),
            ],
        }
    }
}

/// Network exfiltration detector
pub struct ExfiltrationDetector {
    config: ExfiltrationConfig,
    connections: Arc<RwLock<HashMap<SocketAddr, NetworkConnection>>>,
    traffic_stats: Arc<RwLock<HashMap<IpAddr, TrafficStats>>>,
    beacon_detections: Arc<RwLock<HashMap<IpAddr, BeaconDetection>>>,
    exfiltration_alerts: Arc<RwLock<Vec<ExfiltrationAlert>>>,
    monitoring: Arc<RwLock<bool>>,
}

impl ExfiltrationDetector {
    /// Create a new exfiltration detector
    pub fn new(config: ExfiltrationConfig) -> Self {
        Self {
            config,
            connections: Arc::new(RwLock::new(HashMap::new())),
            traffic_stats: Arc::new(RwLock::new(HashMap::new())),
            beacon_detections: Arc::new(RwLock::new(HashMap::new())),
            exfiltration_alerts: Arc::new(RwLock::new(Vec::new())),
            monitoring: Arc::new(RwLock::new(false)),
        }
    }

    /// Start network monitoring
    pub async fn start_monitoring(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut monitoring = self.monitoring.write().await;
        if *monitoring {
            return Err("Network monitoring already running".into());
        }
        *monitoring = true;
        drop(monitoring);

        info!("Starting network exfiltration detection...");

        // Start connection monitoring
        self.start_connection_monitoring().await?;
        
        // Start beacon detection
        self.start_beacon_detection().await?;
        
        // Start exfiltration analysis
        self.start_exfiltration_analysis().await?;

        Ok(())
    }

    /// Stop network monitoring
    pub async fn stop_monitoring(&self) {
        let mut monitoring = self.monitoring.write().await;
        *monitoring = false;
        info!("Stopped network exfiltration detection");
    }

    /// Start monitoring network connections
    async fn start_connection_monitoring(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let connections = Arc::clone(&self.connections);
        let traffic_stats = Arc::clone(&self.traffic_stats);
        let monitoring = Arc::clone(&self.monitoring);

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(1));
            
            while *monitoring.read().await {
                interval.tick().await;
                
                if let Err(e) = Self::update_network_connections(&connections, &traffic_stats).await {
                    error!("Failed to update network connections: {}", e);
                }
            }
        });

        Ok(())
    }

    /// Start C2 beacon detection
    async fn start_beacon_detection(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let traffic_stats = Arc::clone(&self.traffic_stats);
        let beacon_detections = Arc::clone(&self.beacon_detections);
        let monitoring = Arc::clone(&self.monitoring);
        let config = self.config.clone();

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(30));
            
            while *monitoring.read().await {
                interval.tick().await;
                
                if let Err(e) = Self::analyze_beacon_patterns(
                    &traffic_stats,
                    &beacon_detections,
                    &config,
                ).await {
                    error!("Beacon analysis failed: {}", e);
                }
            }
        });

        Ok(())
    }

    /// Start data exfiltration analysis
    async fn start_exfiltration_analysis(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let connections = Arc::clone(&self.connections);
        let exfiltration_alerts = Arc::clone(&self.exfiltration_alerts);
        let monitoring = Arc::clone(&self.monitoring);
        let config = self.config.clone();

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(10));
            
            while *monitoring.read().await {
                interval.tick().await;
                
                if let Err(e) = Self::analyze_data_exfiltration(
                    &connections,
                    &exfiltration_alerts,
                    &config,
                ).await {
                    error!("Exfiltration analysis failed: {}", e);
                }
            }
        });

        Ok(())
    }

    /// Update network connections using netstat-like functionality
    async fn update_network_connections(
        connections: &Arc<RwLock<HashMap<SocketAddr, NetworkConnection>>>,
        traffic_stats: &Arc<RwLock<HashMap<IpAddr, TrafficStats>>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // In a real implementation, this would use:
        // - Windows: GetTcpTable2, GetUdpTable, GetExtendedTcpTable
        // - Linux: /proc/net/tcp, /proc/net/udp
        // - Cross-platform: netstat parsing or system APIs
        
        // For now, simulate network connections
        let current_connections = Self::get_current_connections().await?;
        
        let mut conn_map = connections.write().await;
        let mut stats_map = traffic_stats.write().await;
        
        for conn in current_connections {
            let remote_ip = conn.remote_addr.ip();
            
            // Update connection
            conn_map.insert(conn.local_addr, conn.clone());
            
            // Update traffic statistics
            let stats = stats_map.entry(remote_ip).or_insert_with(TrafficStats::default);
            stats.total_bytes += conn.bytes_sent + conn.bytes_received;
            stats.packet_count += 1;
            stats.packet_times.push_back(SystemTime::now());
            stats.byte_counts.push_back(conn.bytes_sent + conn.bytes_received);
            
            // Keep only recent data (last 5 minutes)
            let cutoff = SystemTime::now() - Duration::from_secs(300);
            while let Some(&front_time) = stats.packet_times.front() {
                if front_time < cutoff {
                    stats.packet_times.pop_front();
                    stats.byte_counts.pop_front();
                } else {
                    break;
                }
            }
        }
        
        Ok(())
    }

    /// Get current network connections (simulated)
    async fn get_current_connections() -> Result<Vec<NetworkConnection>, Box<dyn std::error::Error + Send + Sync>> {
        // This is a simulation - in real implementation, use system APIs
        let mut connections = Vec::new();
        
        // Simulate some connections
        if rand::random::<f64>() < 0.1 { // 10% chance
            connections.push(NetworkConnection {
                local_addr: "192.168.1.100:12345".parse()?,
                remote_addr: "203.0.113.1:443".parse()?, // Suspicious IP
                protocol: NetworkProtocol::Https,
                state: ConnectionState::Established,
                process_id: 1234,
                process_name: "suspicious.exe".to_string(),
                bytes_sent: rand::random::<u32>() as u64,
                bytes_received: rand::random::<u32>() as u64,
                established_time: SystemTime::now() - Duration::from_secs(rand::random::<u64>() % 3600),
                last_activity: SystemTime::now(),
            });
        }
        
        Ok(connections)
    }

    /// Analyze traffic patterns for C2 beacons
    async fn analyze_beacon_patterns(
        traffic_stats: &Arc<RwLock<HashMap<IpAddr, TrafficStats>>>,
        beacon_detections: &Arc<RwLock<HashMap<IpAddr, BeaconDetection>>>,
        config: &ExfiltrationConfig,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let stats = traffic_stats.read().await;
        let mut detections = beacon_detections.write().await;
        
        for (ip, traffic) in stats.iter() {
            if traffic.packet_times.len() < 3 {
                continue; // Need at least 3 packets for pattern analysis
            }
            
            // Calculate intervals between packets
            let mut intervals = Vec::new();
            for i in 1..traffic.packet_times.len() {
                if let (Ok(prev), Ok(curr)) = (
                    traffic.packet_times[i-1].duration_since(UNIX_EPOCH),
                    traffic.packet_times[i].duration_since(UNIX_EPOCH)
                ) {
                    intervals.push(curr - prev);
                }
            }
            
            if intervals.is_empty() {
                continue;
            }
            
            // Analyze beacon characteristics
            let avg_interval = intervals.iter().sum::<Duration>() / intervals.len() as u32;
            let jitter = Self::calculate_jitter(&intervals, avg_interval);
            
            // Check if this looks like a beacon
            if avg_interval.as_secs() >= config.min_beacon_interval &&
               avg_interval.as_secs() <= config.max_beacon_interval &&
               jitter <= config.max_jitter_factor {
                
                let confidence = Self::calculate_beacon_confidence(&intervals, jitter);
                
                if confidence >= config.beacon_confidence_threshold {
                    let detection = BeaconDetection {
                        remote_addr: *ip,
                        confidence,
                        beacon_interval: avg_interval,
                        jitter_factor: jitter,
                        packet_count: traffic.packet_count,
                        first_seen: traffic.packet_times.front().copied().unwrap_or(SystemTime::now()),
                        last_seen: traffic.packet_times.back().copied().unwrap_or(SystemTime::now()),
                        detection_reasons: vec![
                            format!("Regular interval: {:?}", avg_interval),
                            format!("Low jitter: {:.2}", jitter),
                            format!("High confidence: {:.2}", confidence),
                        ],
                    };
                    
                    warn!("C2 beacon detected: {} (confidence: {:.2})", ip, confidence);
                    detections.insert(*ip, detection);
                }
            }
        }
        
        Ok(())
    }

    /// Analyze connections for data exfiltration
    async fn analyze_data_exfiltration(
        connections: &Arc<RwLock<HashMap<SocketAddr, NetworkConnection>>>,
        alerts: &Arc<RwLock<Vec<ExfiltrationAlert>>>,
        config: &ExfiltrationConfig,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let conns = connections.read().await;
        let mut alert_list = alerts.write().await;
        
        for conn in conns.values() {
            let total_bytes = conn.bytes_sent + conn.bytes_received;
            let duration = SystemTime::now().duration_since(conn.established_time).unwrap_or_default();
            
            if total_bytes >= config.min_exfiltration_size && duration.as_secs() > 0 {
                let transfer_rate = total_bytes as f64 / duration.as_secs() as f64;
                
                if transfer_rate >= config.exfiltration_rate_threshold as f64 {
                    let mut indicators = Vec::new();
                    
                    // Check for suspicious indicators
                    let remote_str = conn.remote_addr.to_string();
                    for indicator in &config.suspicious_indicators {
                        if remote_str.contains(indicator) {
                            indicators.push(format!("Suspicious domain: {}", indicator));
                        }
                    }
                    
                    // Check for unusual process names
                    if Self::is_suspicious_process(&conn.process_name) {
                        indicators.push(format!("Suspicious process: {}", conn.process_name));
                    }
                    
                    let severity = if transfer_rate > config.exfiltration_rate_threshold as f64 * 10.0 {
                        AlertSeverity::Critical
                    } else if transfer_rate > config.exfiltration_rate_threshold as f64 * 5.0 {
                        AlertSeverity::High
                    } else {
                        AlertSeverity::Medium
                    };
                    
                    let alert = ExfiltrationAlert {
                        alert_id: format!("exfil_{}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()),
                        severity,
                        remote_addr: conn.remote_addr.ip(),
                        process_name: conn.process_name.clone(),
                        process_id: conn.process_id,
                        bytes_transferred: total_bytes,
                        transfer_rate,
                        duration,
                        detection_time: SystemTime::now(),
                        indicators,
                    };
                    
                    warn!("Data exfiltration detected: {} -> {} ({:.2} MB/s)", 
                          conn.process_name, conn.remote_addr, transfer_rate / (1024.0 * 1024.0));
                    
                    alert_list.push(alert);
                }
            }
        }
        
        // Clean old alerts (keep last 1000)
        if alert_list.len() > 1000 {
            let drain_count = alert_list.len() - 1000;
            alert_list.drain(0..drain_count);
        }
        
        Ok(())
    }

    /// Calculate jitter factor for beacon detection
    fn calculate_jitter(intervals: &[Duration], avg_interval: Duration) -> f64 {
        if intervals.is_empty() {
            return 1.0;
        }
        
        let variance: f64 = intervals.iter()
            .map(|&interval| {
                let diff = interval.as_secs_f64() - avg_interval.as_secs_f64();
                diff * diff
            })
            .sum::<f64>() / intervals.len() as f64;
        
        let std_dev = variance.sqrt();
        std_dev / avg_interval.as_secs_f64()
    }

    /// Calculate confidence score for beacon detection
    fn calculate_beacon_confidence(intervals: &[Duration], jitter: f64) -> f64 {
        let regularity_score = (1.0 - jitter).max(0.0);
        let sample_size_score = (intervals.len() as f64 / 10.0).min(1.0);
        
        (regularity_score * 0.7 + sample_size_score * 0.3).min(1.0)
    }

    /// Check if process name is suspicious
    fn is_suspicious_process(process_name: &str) -> bool {
        let suspicious_names = [
            "powershell", "cmd", "rundll32", "regsvr32",
            "mshta", "wscript", "cscript", "certutil",
            "bitsadmin", "curl", "wget"
        ];
        
        let name_lower = process_name.to_lowercase();
        suspicious_names.iter().any(|&sus| name_lower.contains(sus))
    }

    /// Get current alert count
    pub async fn alerts_count(&self) -> usize {
        self.exfiltration_alerts.read().await.len()
    }

    /// Get beacon detections
    pub async fn get_beacon_detections(&self) -> Vec<BeaconDetection> {
        self.beacon_detections.read().await.values().cloned().collect()
    }

    /// Get exfiltration alerts
    pub async fn get_exfiltration_alerts(&self) -> Vec<ExfiltrationAlert> {
        self.exfiltration_alerts.read().await.clone()
    }

    /// Check if there are recent alerts
    pub async fn has_recent_alerts(&self, within_seconds: u64) -> bool {
        let alerts = self.exfiltration_alerts.read().await;
        let cutoff = SystemTime::now() - Duration::from_secs(within_seconds);
        
        alerts.iter().any(|alert| alert.detection_time > cutoff)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_exfiltration_detector_creation() {
        let config = ExfiltrationConfig::default();
        let detector = ExfiltrationDetector::new(config);
        
        assert!(!*detector.monitoring.read().await);
        assert_eq!(detector.alerts_count().await, 0);
    }
    
    #[test]
    fn test_jitter_calculation() {
        let intervals = vec![
            Duration::from_secs(30),
            Duration::from_secs(32),
            Duration::from_secs(28),
            Duration::from_secs(31),
        ];
        let avg = Duration::from_secs(30);
        
        let jitter = ExfiltrationDetector::calculate_jitter(&intervals, avg);
        assert!(jitter < 0.1); // Low jitter
    }
    
    #[test]
    fn test_suspicious_process_detection() {
        assert!(ExfiltrationDetector::is_suspicious_process("powershell.exe"));
        assert!(ExfiltrationDetector::is_suspicious_process("cmd.exe"));
        assert!(!ExfiltrationDetector::is_suspicious_process("notepad.exe"));
    }
}
