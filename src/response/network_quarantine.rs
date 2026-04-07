//! Network Quarantine System
//!
//! This module provides dynamic network isolation capabilities using Windows Firewall
//! rules via netsh advfirewall commands and the windows crate for system integration.

use std::collections::HashMap;
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;
// Windows API imports will be added as needed
use super::SecurityEvent;
use crate::metrics::MetricsCollector;

/// Network quarantine configuration
#[derive(Debug, Clone)]
pub struct NetworkQuarantineConfig {
    pub enable_auto_quarantine: bool,
    pub quarantine_duration: Duration,
    pub max_quarantine_rules: usize,
    pub allow_local_network: bool,
    pub allow_dns: bool,
    pub emergency_whitelist: Vec<String>,
    pub rule_prefix: String,
}

impl Default for NetworkQuarantineConfig {
    fn default() -> Self {
        Self {
            enable_auto_quarantine: true,
            quarantine_duration: Duration::from_secs(3600), // 1 hour
            max_quarantine_rules: 100,
            allow_local_network: true,
            allow_dns: true,
            emergency_whitelist: vec![
                "127.0.0.1".to_string(),
                "::1".to_string(),
                "169.254.0.0/16".to_string(), // Link-local
            ],
            rule_prefix: "ERDPS_Quarantine".to_string(),
        }
    }
}

/// Network quarantine target types
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum QuarantineTarget {
    ProcessId(u32),
    IpAddress(String),
    IpRange(String, String),
    Port(u16),
    PortRange(u16, u16),
    Domain(String),
    Application(String),
}

/// Quarantine rule definition
#[derive(Debug, Clone)]
pub struct QuarantineRule {
    pub id: String,
    pub name: String,
    pub target: QuarantineTarget,
    pub direction: TrafficDirection,
    pub action: FirewallAction,
    pub protocol: NetworkProtocol,
    pub created_at: SystemTime,
    pub expires_at: Option<SystemTime>,
    pub reason: String,
    pub active: bool,
}

/// Traffic direction for firewall rules
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum TrafficDirection {
    Inbound,
    Outbound,
    Both,
}

/// Firewall action types
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum FirewallAction {
    Block,
    Allow,
    Monitor,
}

/// Network protocol types
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum NetworkProtocol {
    TCP,
    UDP,
    ICMP,
    Any,
}

/// Network adapter information
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct NetworkAdapter {
    name: String,
    description: String,
    ip_addresses: Vec<String>,
    gateway: Option<String>,
    dns_servers: Vec<String>,
}

/// Quarantine operation result
#[derive(Debug, Clone)]
pub struct QuarantineResult {
    pub success: bool,
    pub rule_id: Option<String>,
    pub message: String,
    pub affected_connections: u32,
}

/// Network quarantine engine
pub struct NetworkQuarantine {
    config: NetworkQuarantineConfig,
    metrics: Arc<MetricsCollector>,
    active_rules: Arc<RwLock<HashMap<String, QuarantineRule>>>,
    network_adapters: Arc<RwLock<Vec<NetworkAdapter>>>,
    rule_counter: Arc<RwLock<u64>>,
}

impl NetworkQuarantine {
    /// Create a new network quarantine engine
    pub async fn new(
        config: NetworkQuarantineConfig,
        metrics: Arc<MetricsCollector>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let active_rules = Arc::new(RwLock::new(HashMap::new()));
        let network_adapters = Arc::new(RwLock::new(Vec::new()));
        let rule_counter = Arc::new(RwLock::new(0));

        let quarantine = NetworkQuarantine {
            config,
            metrics,
            active_rules,
            network_adapters,
            rule_counter,
        };

        // Initialize network adapter information
        quarantine.refresh_network_adapters().await?;

        // Clean up any existing ERDPS quarantine rules on startup
        quarantine.cleanup_existing_rules().await?;

        Ok(quarantine)
    }

    /// Quarantine a network target
    pub async fn quarantine_target(
        &self,
        target: QuarantineTarget,
        reason: &str,
        duration: Option<Duration>,
    ) -> Result<QuarantineResult, Box<dyn std::error::Error + Send + Sync>> {
        if !self.config.enable_auto_quarantine {
            return Ok(QuarantineResult {
                success: false,
                rule_id: None,
                message: "Network quarantine is disabled".to_string(),
                affected_connections: 0,
            });
        }

        // Check if we've reached the maximum number of rules
        let active_rules = self.active_rules.read().await;
        if active_rules.len() >= self.config.max_quarantine_rules {
            return Ok(QuarantineResult {
                success: false,
                rule_id: None,
                message: "Maximum quarantine rules limit reached".to_string(),
                affected_connections: 0,
            });
        }
        drop(active_rules);

        // Generate unique rule ID
        let rule_id = self.generate_rule_id().await;

        // Create quarantine rule
        let expires_at = duration
            .map(|d| SystemTime::now() + d)
            .or_else(|| Some(SystemTime::now() + self.config.quarantine_duration));

        let rule = QuarantineRule {
            id: rule_id.clone(),
            name: format!(
                "{}_{}_{}",
                self.config.rule_prefix,
                rule_id,
                self.get_target_name(&target)
            ),
            target: target.clone(),
            direction: TrafficDirection::Both,
            action: FirewallAction::Block,
            protocol: NetworkProtocol::Any,
            created_at: SystemTime::now(),
            expires_at,
            reason: reason.to_string(),
            active: false,
        };

        // Apply the quarantine rule
        match self.apply_quarantine_rule(&rule).await {
            Ok(affected_connections) => {
                // Store the active rule
                let mut active_rules = self.active_rules.write().await;
                let mut updated_rule = rule;
                updated_rule.active = true;
                active_rules.insert(rule_id.clone(), updated_rule);

                // Update metrics
                self.metrics.record_counter("quarantine_operations_total", 1.0);

                log::info!(
                    "Network quarantine applied: {} - Reason: {}",
                    rule_id,
                    reason
                );

                Ok(QuarantineResult {
                    success: true,
                    rule_id: Some(rule_id),
                    message: "Quarantine rule applied successfully".to_string(),
                    affected_connections,
                })
            }
            Err(e) => {
                log::error!("Failed to apply quarantine rule {}: {}", rule_id, e);
                Ok(QuarantineResult {
                    success: false,
                    rule_id: Some(rule_id),
                    message: format!("Failed to apply quarantine: {}", e),
                    affected_connections: 0,
                })
            }
        }
    }

    /// Remove quarantine for a specific rule
    pub async fn remove_quarantine(
        &self,
        rule_id: &str,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let mut active_rules = self.active_rules.write().await;

        if let Some(rule) = active_rules.get(rule_id) {
            match self.remove_quarantine_rule(rule).await {
                Ok(_) => {
                    active_rules.remove(rule_id);

                    self.metrics.record_counter("quarantine_operations_total", 1.0);

                    log::info!("Network quarantine removed: {}", rule_id);
                    Ok(true)
                }
                Err(e) => {
                    log::error!("Failed to remove quarantine rule {}: {}", rule_id, e);
                    Ok(false)
                }
            }
        } else {
            Ok(false) // Rule not found
        }
    }

    /// Quarantine based on security event
    pub async fn quarantine_from_event(
        &self,
        event: &SecurityEvent,
    ) -> Result<QuarantineResult, Box<dyn std::error::Error + Send + Sync>> {
        // Determine quarantine target from event
        let target = self.extract_quarantine_target(event).await?;

        // Generate reason from event
        let reason = format!(
            "Security event: {:?} (confidence: {:.2})",
            event.event_type, event.confidence
        );

        // Apply quarantine
        self.quarantine_target(target, &reason, None).await
    }

    /// Clean up expired quarantine rules
    pub async fn cleanup_expired_rules(
        &self,
    ) -> Result<u32, Box<dyn std::error::Error + Send + Sync>> {
        let now = SystemTime::now();
        let mut active_rules = self.active_rules.write().await;
        let mut expired_rules = Vec::new();

        // Find expired rules
        for (rule_id, rule) in active_rules.iter() {
            if let Some(expires_at) = rule.expires_at {
                if now > expires_at {
                    expired_rules.push(rule_id.clone());
                }
            }
        }

        // Remove expired rules
        let mut removed_count = 0;
        for rule_id in expired_rules {
            if let Some(rule) = active_rules.get(&rule_id) {
                if let Ok(_) = self.remove_quarantine_rule(rule).await {
                    active_rules.remove(&rule_id);
                    removed_count += 1;
                    log::info!("Expired quarantine rule removed: {}", rule_id);
                }
            }
        }

        if removed_count > 0 {
            self.metrics.record_counter("quarantine_operations_total", 1.0);
        }

        Ok(removed_count)
    }

    /// Get list of active quarantine rules
    pub async fn get_active_rules(&self) -> Vec<QuarantineRule> {
        let active_rules = self.active_rules.read().await;
        active_rules.values().cloned().collect()
    }

    /// Apply a quarantine rule using Windows Firewall
    async fn apply_quarantine_rule(
        &self,
        rule: &QuarantineRule,
    ) -> Result<u32, Box<dyn std::error::Error + Send + Sync>> {
        match &rule.target {
            QuarantineTarget::ProcessId(pid) => self.apply_process_quarantine(*pid, rule).await,
            QuarantineTarget::IpAddress(ip) => self.apply_ip_quarantine(ip, rule).await,
            QuarantineTarget::IpRange(start_ip, end_ip) => {
                self.apply_ip_range_quarantine(start_ip, end_ip, rule).await
            }
            QuarantineTarget::Port(port) => self.apply_port_quarantine(*port, rule).await,
            QuarantineTarget::PortRange(start_port, end_port) => {
                self.apply_port_range_quarantine(*start_port, *end_port, rule)
                    .await
            }
            QuarantineTarget::Domain(domain) => self.apply_domain_quarantine(domain, rule).await,
            QuarantineTarget::Application(app_path) => {
                self.apply_application_quarantine(app_path, rule).await
            }
        }
    }

    /// Apply process-based quarantine
    async fn apply_process_quarantine(
        &self,
        pid: u32,
        rule: &QuarantineRule,
    ) -> Result<u32, Box<dyn std::error::Error + Send + Sync>> {
        // Get process executable path
        let exe_path = self.get_process_executable_path(pid).await?;

        // Create firewall rule to block the executable
        let cmd_args = vec![
            "advfirewall".to_string(),
            "firewall".to_string(),
            "add".to_string(),
            "rule".to_string(),
            format!("name={}", rule.name),
            "dir=out".to_string(),
            "action=block".to_string(),
            format!("program={}", exe_path),
        ];

        self.execute_netsh_command(&cmd_args).await?;

        // Also create inbound rule
        let cmd_args_in = vec![
            "advfirewall".to_string(),
            "firewall".to_string(),
            "add".to_string(),
            "rule".to_string(),
            format!("name={}_IN", rule.name),
            "dir=in".to_string(),
            "action=block".to_string(),
            format!("program={}", exe_path),
        ];

        self.execute_netsh_command(&cmd_args_in).await?;

        Ok(1) // One process affected
    }

    /// Apply IP address quarantine
    async fn apply_ip_quarantine(
        &self,
        ip: &str,
        rule: &QuarantineRule,
    ) -> Result<u32, Box<dyn std::error::Error + Send + Sync>> {
        // Check if IP is in emergency whitelist
        if self.config.emergency_whitelist.contains(&ip.to_string()) {
            return Err("IP address is in emergency whitelist".into());
        }

        // Create outbound blocking rule
        let cmd_args_out = vec![
            "advfirewall".to_string(),
            "firewall".to_string(),
            "add".to_string(),
            "rule".to_string(),
            format!("name={}_OUT", rule.name),
            "dir=out".to_string(),
            "action=block".to_string(),
            format!("remoteip={}", ip),
        ];

        self.execute_netsh_command(&cmd_args_out).await?;

        // Create inbound blocking rule
        let cmd_args_in = vec![
            "advfirewall".to_string(),
            "firewall".to_string(),
            "add".to_string(),
            "rule".to_string(),
            format!("name={}_IN", rule.name),
            "dir=in".to_string(),
            "action=block".to_string(),
            format!("remoteip={}", ip),
        ];

        self.execute_netsh_command(&cmd_args_in).await?;

        Ok(1) // One IP affected
    }

    /// Apply IP range quarantine
    async fn apply_ip_range_quarantine(
        &self,
        start_ip: &str,
        end_ip: &str,
        rule: &QuarantineRule,
    ) -> Result<u32, Box<dyn std::error::Error + Send + Sync>> {
        let ip_range = format!("{}-{}", start_ip, end_ip);

        let cmd_args_out = vec![
            "advfirewall".to_string(),
            "firewall".to_string(),
            "add".to_string(),
            "rule".to_string(),
            format!("name={}_OUT", rule.name),
            "dir=out".to_string(),
            "action=block".to_string(),
            format!("remoteip={}", ip_range),
        ];

        self.execute_netsh_command(&cmd_args_out).await?;

        let cmd_args_in = vec![
            "advfirewall".to_string(),
            "firewall".to_string(),
            "add".to_string(),
            "rule".to_string(),
            format!("name={}_IN", rule.name),
            "dir=in".to_string(),
            "action=block".to_string(),
            format!("remoteip={}", ip_range),
        ];

        self.execute_netsh_command(&cmd_args_in).await?;

        Ok(1) // One range affected
    }

    /// Apply port quarantine
    async fn apply_port_quarantine(
        &self,
        port: u16,
        rule: &QuarantineRule,
    ) -> Result<u32, Box<dyn std::error::Error + Send + Sync>> {
        let protocol = match rule.protocol {
            NetworkProtocol::TCP => "TCP",
            NetworkProtocol::UDP => "UDP",
            _ => "TCP", // Default to TCP
        };

        let cmd_args = vec![
            "advfirewall".to_string(),
            "firewall".to_string(),
            "add".to_string(),
            "rule".to_string(),
            format!("name={}", rule.name),
            "dir=out".to_string(),
            "action=block".to_string(),
            format!("protocol={}", protocol),
            format!("remoteport={}", port),
        ];

        self.execute_netsh_command(&cmd_args).await?;

        Ok(1) // One port affected
    }

    /// Apply port range quarantine
    async fn apply_port_range_quarantine(
        &self,
        start_port: u16,
        end_port: u16,
        rule: &QuarantineRule,
    ) -> Result<u32, Box<dyn std::error::Error + Send + Sync>> {
        let protocol = match rule.protocol {
            NetworkProtocol::TCP => "TCP",
            NetworkProtocol::UDP => "UDP",
            _ => "TCP",
        };

        let port_range = format!("{}-{}", start_port, end_port);

        let cmd_args = vec![
            "advfirewall".to_string(),
            "firewall".to_string(),
            "add".to_string(),
            "rule".to_string(),
            format!("name={}", rule.name),
            "dir=out".to_string(),
            "action=block".to_string(),
            format!("protocol={}", protocol),
            format!("remoteport={}", port_range),
        ];

        self.execute_netsh_command(&cmd_args).await?;

        Ok(1) // One port range affected
    }

    /// Apply domain quarantine (simplified - would need DNS resolution)
    async fn apply_domain_quarantine(
        &self,
        domain: &str,
        rule: &QuarantineRule,
    ) -> Result<u32, Box<dyn std::error::Error + Send + Sync>> {
        // For now, we'll create a rule that blocks common ports for the domain
        // In a full implementation, this would resolve the domain to IPs
        log::warn!("Domain quarantine not fully implemented for: {}", domain);

        // Block common HTTP/HTTPS ports for any traffic
        let ports = vec![80, 443, 8080, 8443];
        let mut affected = 0;

        for port in ports {
            let port_rule = QuarantineRule {
                id: format!("{}_port_{}", rule.id, port),
                name: format!("{}_PORT_{}", rule.name, port),
                target: QuarantineTarget::Port(port),
                direction: rule.direction.clone(),
                action: rule.action.clone(),
                protocol: NetworkProtocol::TCP,
                created_at: rule.created_at,
                expires_at: rule.expires_at,
                reason: format!("{} (domain: {})", rule.reason, domain),
                active: false,
            };

            if let Ok(_) = self.apply_port_quarantine(port, &port_rule).await {
                affected += 1;
            }
        }

        Ok(affected)
    }

    /// Apply application quarantine
    async fn apply_application_quarantine(
        &self,
        app_path: &str,
        rule: &QuarantineRule,
    ) -> Result<u32, Box<dyn std::error::Error + Send + Sync>> {
        let cmd_args = vec![
            "advfirewall".to_string(),
            "firewall".to_string(),
            "add".to_string(),
            "rule".to_string(),
            format!("name={}", rule.name),
            "dir=out".to_string(),
            "action=block".to_string(),
            format!("program={}", app_path),
        ];

        self.execute_netsh_command(&cmd_args).await?;

        Ok(1) // One application affected
    }

    /// Remove a quarantine rule
    async fn remove_quarantine_rule(
        &self,
        rule: &QuarantineRule,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Remove the main rule
        let cmd_args = vec![
            "advfirewall".to_string(),
            "firewall".to_string(),
            "delete".to_string(),
            "rule".to_string(),
            format!("name={}", rule.name),
        ];

        let _ = self.execute_netsh_command(&cmd_args).await; // Ignore errors for cleanup

        // Remove associated rules (IN/OUT variants)
        let variants = vec![format!("{}_IN", rule.name), format!("{}_OUT", rule.name)];
        for variant in variants {
            let cmd_args_variant = vec![
                "advfirewall".to_string(),
                "firewall".to_string(),
                "delete".to_string(),
                "rule".to_string(),
                format!("name={}", variant),
            ];
            let _ = self.execute_netsh_command(&cmd_args_variant).await;
        }

        Ok(())
    }

    /// Execute netsh command
    async fn execute_netsh_command(
        &self,
        args: &[String],
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let output = Command::new("netsh")
            .args(args)
            .output()
            .map_err(|e| format!("Failed to execute netsh: {}", e))?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            Err(format!("netsh command failed: {}", error_msg).into())
        }
    }

    /// Extract quarantine target from security event
    async fn extract_quarantine_target(
        &self,
        event: &SecurityEvent,
    ) -> Result<QuarantineTarget, Box<dyn std::error::Error + Send + Sync>> {
        // Try to extract PID first
        if let Some(pid_str) = event.metadata.get("pid") {
            if let Ok(pid) = pid_str.parse::<u32>() {
                return Ok(QuarantineTarget::ProcessId(pid));
            }
        }

        // Try to extract IP address
        if let Some(ip) = event.metadata.get("remote_ip") {
            return Ok(QuarantineTarget::IpAddress(ip.clone()));
        }

        // Try to extract network target
        if let Some(target) = event.metadata.get("network_target") {
            // Check if it's an IP address or domain
            if target.chars().all(|c| c.is_ascii_digit() || c == '.') {
                return Ok(QuarantineTarget::IpAddress(target.clone()));
            } else {
                return Ok(QuarantineTarget::Domain(target.clone()));
            }
        }

        // Try to extract application path
        if let Some(app_path) = event.metadata.get("file_path") {
            return Ok(QuarantineTarget::Application(app_path.clone()));
        }

        Err("No suitable quarantine target found in event".into())
    }

    /// Generate unique rule ID
    async fn generate_rule_id(&self) -> String {
        let mut counter = self.rule_counter.write().await;
        *counter += 1;
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        format!("{}_{}", timestamp, *counter)
    }

    /// Get target type name for metrics
    #[allow(dead_code)]
    fn get_target_type_name(&self, target: &QuarantineTarget) -> String {
        match target {
            QuarantineTarget::ProcessId(_) => "process".to_string(),
            QuarantineTarget::IpAddress(_) => "ip_address".to_string(),
            QuarantineTarget::IpRange(_, _) => "ip_range".to_string(),
            QuarantineTarget::Port(_) => "port".to_string(),
            QuarantineTarget::PortRange(_, _) => "port_range".to_string(),
            QuarantineTarget::Domain(_) => "domain".to_string(),
            QuarantineTarget::Application(_) => "application".to_string(),
        }
    }

    /// Get target name for rule naming
    fn get_target_name(&self, target: &QuarantineTarget) -> String {
        match target {
            QuarantineTarget::ProcessId(pid) => format!("PID_{}", pid),
            QuarantineTarget::IpAddress(ip) => ip.replace(".", "_").replace(":", "_"),
            QuarantineTarget::IpRange(start, end) => {
                format!("{}_to_{}", start.replace(".", "_"), end.replace(".", "_"))
            }
            QuarantineTarget::Port(port) => format!("PORT_{}", port),
            QuarantineTarget::PortRange(start, end) => format!("PORTS_{}_{}", start, end),
            QuarantineTarget::Domain(domain) => domain.replace(".", "_"),
            QuarantineTarget::Application(path) => std::path::Path::new(path)
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
        }
    }

    /// Get process executable path (simplified implementation)
    async fn get_process_executable_path(
        &self,
        pid: u32,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        // Use tasklist command to get process information
        let output = Command::new("tasklist")
            .args(&["/FI", &format!("PID eq {}", pid), "/FO", "CSV", "/NH"])
            .output()
            .map_err(|e| format!("Failed to execute tasklist: {}", e))?;

        if output.status.success() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            if let Some(line) = output_str.lines().next() {
                // Parse CSV output to get process name
                let parts: Vec<&str> = line.split(',').collect();
                if parts.len() > 0 {
                    let process_name = parts[0].trim_matches('"');
                    // For simplicity, assume process is in System32 or current directory
                    return Ok(format!("C:\\Windows\\System32\\{}", process_name));
                }
            }
        }

        Err(format!("Could not find executable path for PID {}", pid).into())
    }

    /// Refresh network adapter information
    async fn refresh_network_adapters(
        &self,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // This is a simplified implementation
        // In a full implementation, this would use GetAdaptersAddresses API
        let mut adapters = self.network_adapters.write().await;
        adapters.clear();

        // Add a default adapter for demonstration
        adapters.push(NetworkAdapter {
            name: "Local Area Connection".to_string(),
            description: "Default Network Adapter".to_string(),
            ip_addresses: vec!["192.168.1.100".to_string()],
            gateway: Some("192.168.1.1".to_string()),
            dns_servers: vec!["8.8.8.8".to_string(), "8.8.4.4".to_string()],
        });

        Ok(())
    }

    /// Clean up existing ERDPS quarantine rules on startup
    async fn cleanup_existing_rules(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // List all firewall rules and remove those with our prefix
        let cmd_args = vec![
            "advfirewall".to_string(),
            "firewall".to_string(),
            "show".to_string(),
            "rule".to_string(),
            "name=all".to_string(),
        ];

        if let Ok(output) = self.execute_netsh_command(&cmd_args).await {
            // Parse output to find ERDPS rules and remove them
            for line in output.lines() {
                if line.contains(&self.config.rule_prefix) {
                    // Extract rule name and delete it
                    if let Some(rule_name) = self.extract_rule_name_from_line(line) {
                        let delete_args = vec![
                            "advfirewall".to_string(),
                            "firewall".to_string(),
                            "delete".to_string(),
                            "rule".to_string(),
                            format!("name={}", rule_name),
                        ];
                        let _ = self.execute_netsh_command(&delete_args).await;
                    }
                }
            }
        }

        Ok(())
    }

    /// Extract rule name from netsh output line
    fn extract_rule_name_from_line(&self, line: &str) -> Option<String> {
        // Simplified rule name extraction
        if let Some(start) = line.find("Rule Name:") {
            let name_part = &line[start + 10..].trim();
            if let Some(end) = name_part.find('\n') {
                Some(name_part[..end].trim().to_string())
            } else {
                Some(name_part.to_string())
            }
        } else {
            None
        }
    }
}

/// Background task to clean up expired rules
pub async fn start_cleanup_task(quarantine: Arc<NetworkQuarantine>, interval: Duration) {
    let mut cleanup_interval = tokio::time::interval(interval);

    loop {
        cleanup_interval.tick().await;

        match quarantine.cleanup_expired_rules().await {
            Ok(count) => {
                if count > 0 {
                    log::info!("Cleaned up {} expired quarantine rules", count);
                }
            }
            Err(e) => {
                log::error!("Failed to clean up expired quarantine rules: {}", e);
            }
        }
    }
}
