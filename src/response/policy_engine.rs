//! Policy Engine
//!
//! Implements policy-driven response escalation based on threat severity and confidence levels.
//! Handles escalation from monitoring → alerting → containment → recovery.

use super::ResponseEscalationLevel;
use super::{AlertSeverity, NetworkTarget, ResponseAction, SecurityEvent, SecurityEventType};
use crate::core::config::AutomatedResponseConfig;
use crate::metrics::MetricsCollector;
use log::{debug, info};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

/// Policy engine for automated response decisions
pub struct PolicyEngine {
    config: AutomatedResponseConfig,
    metrics: Arc<MetricsCollector>,
    event_history: HashMap<String, Vec<SecurityEvent>>,
    escalation_state: HashMap<String, EscalationState>,
}

/// Current escalation state for a threat source
#[derive(Debug, Clone)]
struct EscalationState {
    current_level: ResponseEscalationLevel,
    escalation_time: SystemTime,
    event_count: u32,
    last_action_time: Option<SystemTime>,
}

impl PolicyEngine {
    /// Create a new policy engine
    pub fn new(config: AutomatedResponseConfig, metrics: Arc<MetricsCollector>) -> Self {
        PolicyEngine {
            config,
            metrics,
            event_history: HashMap::new(),
            escalation_state: HashMap::new(),
        }
    }

    /// Start policy engine monitoring
    pub async fn start_monitoring(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Policy engine monitoring started");

        // In a full implementation, this would start background tasks for:
        // - Periodic escalation review
        // - Event history cleanup
        // - Policy rule updates

        Ok(())
    }

    /// Evaluate response actions for a security event
    pub async fn evaluate_response(
        &mut self,
        event: &SecurityEvent,
    ) -> Result<Vec<ResponseAction>, Box<dyn std::error::Error + Send + Sync>> {
        debug!("Evaluating response for event: {:?}", event.event_type);

        // Update event history
        self.update_event_history(event);

        // Determine threat source identifier
        let source_id = self.get_source_identifier(event);

        // Get or create escalation state
        let escalation_state = self.get_or_create_escalation_state(&source_id, event);

        // Calculate threat score
        let threat_score = self.calculate_threat_score(event, &source_id);

        // Determine appropriate escalation level
        let target_level = self.determine_escalation_level(threat_score, event);

        // Check if escalation is needed
        let mut actions = Vec::new();
        if self.should_escalate(&escalation_state, &target_level, event) {
            actions = self
                .generate_response_actions(&target_level, event, threat_score)
                .await?;

            // Update escalation state
            self.update_escalation_state(&source_id, target_level, &actions);
        }

        // Update metrics
        self.update_policy_metrics(event, &actions);

        Ok(actions)
    }

    /// Update event history for pattern analysis
    fn update_event_history(&mut self, event: &SecurityEvent) {
        let source_id = self.get_source_identifier(event);
        let history = self.event_history.entry(source_id).or_insert_with(Vec::new);

        history.push(event.clone());

        // Keep only recent events (last hour)
        let cutoff_time = SystemTime::now() - Duration::from_secs(3600);
        history.retain(|e| e.timestamp > cutoff_time);

        // Limit history size
        if history.len() > 100 {
            history.drain(0..history.len() - 100);
        }
    }

    /// Get source identifier for event grouping
    fn get_source_identifier(&self, event: &SecurityEvent) -> String {
        // Group events by source for escalation tracking
        match &event.event_type {
            SecurityEventType::SuspiciousProcessBehavior => event
                .metadata
                .get("pid")
                .map(|pid| format!("process_{}", pid))
                .unwrap_or_else(|| event.source.clone()),
            SecurityEventType::AnomalousFileActivity => event
                .metadata
                .get("file_path")
                .map(|path| format!("file_{}", path))
                .unwrap_or_else(|| event.source.clone()),
            SecurityEventType::NetworkThreatDetected => event
                .metadata
                .get("remote_ip")
                .map(|ip| format!("network_{}", ip))
                .unwrap_or_else(|| event.source.clone()),
            _ => event.source.clone(),
        }
    }

    /// Get or create escalation state for a source
    fn get_or_create_escalation_state(
        &mut self,
        source_id: &str,
        event: &SecurityEvent,
    ) -> EscalationState {
        self.escalation_state
            .get(source_id)
            .cloned()
            .unwrap_or_else(|| {
                let state = EscalationState {
                    current_level: ResponseEscalationLevel::Monitoring,
                    escalation_time: event.timestamp,
                    event_count: 0,
                    last_action_time: None,
                };
                self.escalation_state
                    .insert(source_id.to_string(), state.clone());
                state
            })
    }

    /// Calculate comprehensive threat score
    fn calculate_threat_score(&self, event: &SecurityEvent, source_id: &str) -> f64 {
        let mut score = event.severity * event.confidence;

        // Event type multipliers
        let type_multiplier = match event.event_type {
            SecurityEventType::RansomwareDetected => 2.0,
            SecurityEventType::SuspiciousProcessBehavior => 1.5,
            SecurityEventType::AnomalousFileActivity => 1.3,
            SecurityEventType::NetworkThreatDetected => 1.4,
            SecurityEventType::MLAnomalyDetected => 1.2,
            SecurityEventType::BehavioralAnomalyDetected => 1.0,
            // Phase 3 event types
            SecurityEventType::BehavioralAnomaly => 1.2,
            SecurityEventType::EntropySpike => 1.4,
            SecurityEventType::SuspiciousProcess => 1.3,
        };
        score *= type_multiplier;

        // Historical pattern analysis
        if let Some(history) = self.event_history.get(source_id) {
            let recent_events = history
                .iter()
                .filter(|e| e.timestamp > SystemTime::now() - Duration::from_secs(300)) // Last 5 minutes
                .count();

            if recent_events > 1 {
                score *= 1.0 + (recent_events as f64 * 0.2); // Increase score for repeated events
            }
        }

        // Cap the score at 10.0
        score.min(10.0)
    }

    /// Determine appropriate escalation level based on threat score
    fn determine_escalation_level(
        &self,
        threat_score: f64,
        event: &SecurityEvent,
    ) -> ResponseEscalationLevel {
        // Critical threats (ransomware, high-confidence high-severity)
        if threat_score >= 8.0 || matches!(event.event_type, SecurityEventType::RansomwareDetected)
        {
            return ResponseEscalationLevel::Recovery;
        }

        // High threats requiring containment
        if threat_score >= 6.0 {
            return ResponseEscalationLevel::Containment;
        }

        // Medium threats requiring alerting
        if threat_score >= 4.0 {
            return ResponseEscalationLevel::Alerting;
        }

        // Low threats - monitoring only
        ResponseEscalationLevel::Monitoring
    }

    /// Check if escalation is needed
    fn should_escalate(
        &self,
        current_state: &EscalationState,
        target_level: &ResponseEscalationLevel,
        event: &SecurityEvent,
    ) -> bool {
        // Always escalate if target level is higher
        if self.escalation_level_value(target_level)
            > self.escalation_level_value(&current_state.current_level)
        {
            return true;
        }

        // Check if enough time has passed for re-evaluation at the same level
        if let Some(last_action) = current_state.last_action_time {
            let time_since_action = event
                .timestamp
                .duration_since(last_action)
                .unwrap_or(Duration::from_secs(0));

            // Re-evaluate every 5 minutes for containment/recovery levels
            match current_state.current_level {
                ResponseEscalationLevel::Containment | ResponseEscalationLevel::Recovery => {
                    time_since_action > Duration::from_secs(300)
                }
                _ => false,
            }
        } else {
            // No previous action, should act
            true
        }
    }

    /// Convert escalation level to numeric value for comparison
    fn escalation_level_value(&self, level: &ResponseEscalationLevel) -> u8 {
        match level {
            ResponseEscalationLevel::Monitoring => 0,
            ResponseEscalationLevel::Alerting => 1,
            ResponseEscalationLevel::Containment => 2,
            ResponseEscalationLevel::Recovery => 3,
        }
    }

    /// Generate appropriate response actions for escalation level
    async fn generate_response_actions(
        &self,
        level: &ResponseEscalationLevel,
        event: &SecurityEvent,
        threat_score: f64,
    ) -> Result<Vec<ResponseAction>, Box<dyn std::error::Error + Send + Sync>> {
        let mut actions = Vec::new();

        match level {
            ResponseEscalationLevel::Monitoring => {
                // Monitoring level - just log
                debug!(
                    "Monitoring threat: {:?} (score: {:.2})",
                    event.event_type, threat_score
                );
            }

            ResponseEscalationLevel::Alerting => {
                // Generate alerts
                let severity = if threat_score >= 5.0 {
                    AlertSeverity::High
                } else {
                    AlertSeverity::Medium
                };
                let message = format!(
                    "Security threat detected: {:?} (Score: {:.2}, Confidence: {:.2})",
                    event.event_type, threat_score, event.confidence
                );

                actions.push(ResponseAction::Alert { message, severity });
            }

            ResponseEscalationLevel::Containment => {
                // Containment actions
                actions.push(ResponseAction::Alert {
                    message: format!(
                        "CONTAINMENT: High-severity threat detected: {:?}",
                        event.event_type
                    ),
                    severity: AlertSeverity::High,
                });

                // Process-specific containment
                if let Some(pid_str) = event.metadata.get("pid") {
                    if let Ok(pid) = pid_str.parse::<u32>() {
                        if self.config.enable_process_termination {
                            actions.push(ResponseAction::ProcessTermination {
                                pid,
                                reason: format!("Threat containment: {:?}", event.event_type),
                            });
                        }
                    }
                }

                // File-specific containment
                if let Some(file_path) = event.metadata.get("file_path") {
                    if self.config.enable_file_quarantine {
                        actions.push(ResponseAction::FileQuarantine {
                            path: file_path.clone(),
                            backup_location: format!(
                                "quarantine/{}",
                                SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs()
                            ),
                        });
                    }
                }

                // Network containment
                if matches!(event.event_type, SecurityEventType::NetworkThreatDetected) {
                    if self.config.enable_network_isolation {
                        if let Some(remote_ip) = event.metadata.get("remote_ip") {
                            if let Ok(ip) = remote_ip.parse() {
                                actions.push(ResponseAction::NetworkIsolation {
                                    target: NetworkTarget::IpAddress(ip),
                                    duration: Duration::from_secs(3600), // 1 hour
                                });
                            }
                        }
                    }
                }
            }

            ResponseEscalationLevel::Recovery => {
                // Critical response - all available actions
                actions.push(ResponseAction::Alert {
                    message: format!(
                        "CRITICAL: Ransomware or critical threat detected: {:?}",
                        event.event_type
                    ),
                    severity: AlertSeverity::Critical,
                });

                // Aggressive process termination
                if let Some(pid_str) = event.metadata.get("pid") {
                    if let Ok(pid) = pid_str.parse::<u32>() {
                        actions.push(ResponseAction::ProcessTermination {
                            pid,
                            reason: "Critical threat - immediate termination".to_string(),
                        });
                    }
                }

                // Immediate file quarantine
                if let Some(file_path) = event.metadata.get("file_path") {
                    actions.push(ResponseAction::FileQuarantine {
                        path: file_path.clone(),
                        backup_location: format!(
                            "critical_quarantine/{}",
                            SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs()
                        ),
                    });
                }

                // Network isolation
                if self.config.enable_network_isolation {
                    // For critical threats, consider broader network isolation
                    if let Some(pid_str) = event.metadata.get("pid") {
                        if let Ok(pid) = pid_str.parse::<u32>() {
                            actions.push(ResponseAction::NetworkIsolation {
                                target: NetworkTarget::Process(pid),
                                duration: Duration::from_secs(7200), // 2 hours
                            });
                        }
                    }
                }
            }
        }

        Ok(actions)
    }

    /// Update escalation state after actions
    fn update_escalation_state(
        &mut self,
        source_id: &str,
        new_level: ResponseEscalationLevel,
        actions: &[ResponseAction],
    ) {
        if let Some(state) = self.escalation_state.get_mut(source_id) {
            state.current_level = new_level;
            state.event_count += 1;
            if !actions.is_empty() {
                state.last_action_time = Some(SystemTime::now());
            }
        }
    }

    /// Update policy engine metrics
    fn update_policy_metrics(&self, _event: &SecurityEvent, actions: &[ResponseAction]) {
        // Update event type metrics
        self.metrics
            .record_counter("policy_evaluation_processed", 1.0);

        // Count actions by type
        for action in actions {
            match action {
                ResponseAction::ProcessTermination { .. } => {
                    self.metrics
                        .record_counter("process_termination_generated", 1.0);
                }
                ResponseAction::FileQuarantine { .. } => {
                    self.metrics
                        .record_counter("file_quarantine_generated", 1.0);
                }
                ResponseAction::NetworkIsolation { .. } => {
                    self.metrics
                        .record_counter("network_isolation_generated", 1.0);
                }
                ResponseAction::Alert { .. } => {
                    self.metrics
                        .record_counter("alert_generated", 1.0);
                }
                // Phase 3 autonomous response actions
                ResponseAction::ProcessSuspend { .. } => {
                    self.metrics
                        .record_counter("process_suspend_generated", 1.0);
                }
                ResponseAction::NetworkQuarantine { .. } => {
                    self.metrics
                        .record_counter("network_quarantine_generated", 1.0);
                }
                ResponseAction::FirewallBlock { .. } => {
                    self.metrics
                        .record_counter("firewall_block_generated", 1.0);
                }
                ResponseAction::RiskAssessment { .. } => {
                    self.metrics
                        .record_counter("risk_assessment_generated", 1.0);
                }
                ResponseAction::FirewallUnblock { .. } => {
                    self.metrics
                        .record_counter("firewall_unblock_generated", 1.0);
                }
            }
        }
    }

    /// Clean up old escalation states
    pub fn cleanup_old_states(&mut self) {
        let cutoff_time = SystemTime::now() - Duration::from_secs(3600 * 24); // 24 hours

        self.escalation_state
            .retain(|_, state| state.escalation_time > cutoff_time);

        self.event_history.retain(|_, events| {
            events.retain(|event| event.timestamp > cutoff_time);
            !events.is_empty()
        });
    }

    /// Get current escalation statistics
    pub fn get_escalation_stats(&self) -> EscalationStats {
        let mut stats = EscalationStats::default();

        for state in self.escalation_state.values() {
            match state.current_level {
                ResponseEscalationLevel::Monitoring => stats.monitoring_count += 1,
                ResponseEscalationLevel::Alerting => stats.alerting_count += 1,
                ResponseEscalationLevel::Containment => stats.containment_count += 1,
                ResponseEscalationLevel::Recovery => stats.recovery_count += 1,
            }
        }

        stats.total_sources = self.escalation_state.len();
        stats
    }
}

/// Escalation statistics
#[derive(Debug, Default)]
pub struct EscalationStats {
    pub total_sources: usize,
    pub monitoring_count: usize,
    pub alerting_count: usize,
    pub containment_count: usize,
    pub recovery_count: usize,
}
