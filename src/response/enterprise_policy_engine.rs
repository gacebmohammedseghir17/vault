//! Enterprise Policy Engine
//!
//! Enhanced policy engine with enterprise security hardening features including:
//! - Threat mapping configuration with specific response rules
//! - Configurable thresholds for risk, anomaly, entropy, and I/O rates
//! - Advanced threat correlation and escalation logic
//! - Integration with Windows COM firewall and quarantine systems

use super::{
    AlertSeverity, ResponseAction, ResponseEscalationLevel, SecurityEvent,
    SecurityEventType,
};
use crate::core::config::AutomatedResponseConfig;
// Removed unused imports: DetectionResult, ThreatSeverity, EnhancedAgentError
use crate::metrics::MetricsCollector;
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

/// Enterprise policy engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnterprisePolicyConfig {
    /// Threat mapping rules
    pub threat_mappings: HashMap<String, ThreatMappingRule>,
    /// Threshold configurations
    pub thresholds: ThresholdConfig,
    /// Feature toggles
    pub features: FeatureConfig,
    /// Escalation timing configuration
    pub escalation_timing: EscalationTimingConfig,
}

/// Threat mapping rule configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatMappingRule {
    /// Event types this rule applies to
    pub event_types: Vec<String>,
    /// Minimum severity threshold
    pub min_severity: f64,
    /// Minimum confidence threshold
    pub min_confidence: f64,
    /// Response actions to take
    pub response_actions: Vec<String>,
    /// Risk assessment configuration
    pub risk_assessment: RiskAssessmentConfig,
    /// Escalation behavior
    pub escalation_behavior: EscalationBehavior,
}

/// Risk assessment configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessmentConfig {
    /// Enable risk scoring
    pub enabled: bool,
    /// Risk score multiplier
    pub score_multiplier: f64,
    /// Recommendations to include
    pub recommendations: Vec<String>,
    /// Minimum score for high-risk classification
    pub high_risk_threshold: f64,
}

/// Escalation behavior configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationBehavior {
    /// Immediate escalation for critical threats
    pub immediate_escalation: bool,
    /// Time-based escalation intervals
    pub escalation_intervals: Vec<u64>, // seconds
    /// Maximum escalation level
    pub max_escalation_level: String,
}

/// Threshold configuration for various metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdConfig {
    /// Risk score thresholds
    pub risk_thresholds: RiskThresholds,
    /// Anomaly detection thresholds
    pub anomaly_thresholds: AnomalyThresholds,
    /// Entropy analysis thresholds
    pub entropy_thresholds: EntropyThresholds,
    /// I/O rate thresholds
    pub io_rate_thresholds: IoRateThresholds,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskThresholds {
    pub low: f64,
    pub medium: f64,
    pub high: f64,
    pub critical: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyThresholds {
    pub behavioral_anomaly: f64,
    pub process_anomaly: f64,
    pub network_anomaly: f64,
    pub file_system_anomaly: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyThresholds {
    pub file_entropy: f64,
    pub network_entropy: f64,
    pub process_entropy: f64,
    pub entropy_spike_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoRateThresholds {
    pub read_rate_mb_per_sec: f64,
    pub write_rate_mb_per_sec: f64,
    pub network_rate_mb_per_sec: f64,
    pub file_operations_per_sec: u32,
}

/// Feature configuration toggles
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureConfig {
    /// Enable quarantine actions
    pub enable_quarantine: bool,
    /// Enable firewall blocking
    pub enable_firewall_blocking: bool,
    /// Enable process suspension
    pub enable_process_suspend: bool,
    /// Enable network quarantine
    pub enable_network_quarantine: bool,
    /// Enable risk assessment
    pub enable_risk_assessment: bool,
    /// Enable advanced correlation
    pub enable_advanced_correlation: bool,
}

/// Escalation timing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationTimingConfig {
    /// Time between escalation checks (seconds)
    pub escalation_check_interval: u64,
    /// Time to wait before re-evaluating same threat (seconds)
    pub re_evaluation_interval: u64,
    /// Maximum time to keep escalation state (seconds)
    pub max_escalation_age: u64,
}

/// Enhanced escalation state with enterprise features
#[derive(Debug, Clone)]
struct EnterpriseEscalationState {
    current_level: ResponseEscalationLevel,
    escalation_time: SystemTime,
    event_count: u32,
    last_action_time: Option<SystemTime>,
    threat_correlation_score: f64,
    escalation_history: Vec<EscalationEvent>,
    risk_factors: HashMap<String, f64>,
}

#[derive(Debug, Clone)]
struct EscalationEvent {
    timestamp: SystemTime,
    level: ResponseEscalationLevel,
    trigger_reason: String,
    actions_taken: Vec<String>,
}

/// Enterprise policy engine with advanced threat handling
pub struct EnterprisePolicyEngine {
    config: EnterprisePolicyConfig,
    base_config: AutomatedResponseConfig,
    metrics: Arc<MetricsCollector>,
    event_history: HashMap<String, Vec<SecurityEvent>>,
    escalation_state: HashMap<String, EnterpriseEscalationState>,
    threat_correlations: HashMap<String, Vec<String>>,
    policy_decision_times: Vec<Duration>,
}

impl EnterprisePolicyEngine {
    /// Create a new enterprise policy engine
    pub fn new(
        config: EnterprisePolicyConfig,
        base_config: AutomatedResponseConfig,
        metrics: Arc<MetricsCollector>,
    ) -> Self {
        EnterprisePolicyEngine {
            config,
            base_config,
            metrics,
            event_history: HashMap::new(),
            escalation_state: HashMap::new(),
            threat_correlations: HashMap::new(),
            policy_decision_times: Vec::new(),
        }
    }

    /// Start enterprise policy engine monitoring
    pub async fn start_monitoring(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Enterprise policy engine monitoring started");

        // Start background tasks for enterprise features
        self.start_correlation_analysis().await?;
        self.start_threshold_monitoring().await?;
        self.start_escalation_cleanup().await?;

        Ok(())
    }

    /// Evaluate response actions with enterprise threat mapping
    pub async fn evaluate_response(
        &mut self,
        event: &SecurityEvent,
    ) -> Result<Vec<ResponseAction>, Box<dyn std::error::Error + Send + Sync>> {
        let start_time = std::time::Instant::now();

        debug!(
            "Enterprise policy evaluation for event: {:?}",
            event.event_type
        );

        // Update event history and correlations
        self.update_event_history(event);
        self.update_threat_correlations(event).await?;

        // Get threat mapping rules for this event
        let applicable_rules = self.get_applicable_threat_mappings(event);

        // Calculate enhanced threat score with enterprise factors
        let threat_score = self.calculate_enterprise_threat_score(event).await?;

        // Check thresholds against configuration
        let threshold_violations = self.check_threshold_violations(event, threat_score);

        // Generate response actions based on threat mappings
        let mut actions = Vec::new();

        for rule in applicable_rules {
            if self.rule_conditions_met(&rule, event, threat_score) {
                let rule_actions = self
                    .generate_rule_actions(&rule, event, threat_score)
                    .await?;
                actions.extend(rule_actions);
            }
        }

        // Add threshold-based actions
        if !threshold_violations.is_empty() {
            let threshold_actions = self
                .generate_threshold_actions(&threshold_violations, event)
                .await?;
            actions.extend(threshold_actions);
        }

        // Update escalation state
        let source_id = self.get_source_identifier(event);
        self.update_enterprise_escalation_state(&source_id, event, &actions, threat_score);

        // Record policy decision time for metrics
        let decision_time = start_time.elapsed();
        self.policy_decision_times.push(decision_time);

        // Update enterprise metrics
        self.update_enterprise_metrics(event, &actions, decision_time);

        Ok(actions)
    }

    /// Get applicable threat mapping rules for an event
    fn get_applicable_threat_mappings(&self, event: &SecurityEvent) -> Vec<&ThreatMappingRule> {
        let event_type_str = format!("{:?}", event.event_type);

        self.config
            .threat_mappings
            .values()
            .filter(|rule| {
                rule.event_types.contains(&event_type_str)
                    || rule.event_types.contains(&"*".to_string())
            })
            .collect()
    }

    /// Check if rule conditions are met
    fn rule_conditions_met(
        &self,
        rule: &ThreatMappingRule,
        event: &SecurityEvent,
        threat_score: f64,
    ) -> bool {
        event.severity >= rule.min_severity
            && event.confidence >= rule.min_confidence
            && threat_score >= rule.risk_assessment.high_risk_threshold
    }

    /// Generate actions based on threat mapping rule
    async fn generate_rule_actions(
        &self,
        rule: &ThreatMappingRule,
        event: &SecurityEvent,
        threat_score: f64,
    ) -> Result<Vec<ResponseAction>, Box<dyn std::error::Error + Send + Sync>> {
        let mut actions = Vec::new();

        for action_type in &rule.response_actions {
            match action_type.as_str() {
                "ProcessSuspend" => {
                    if self.config.features.enable_process_suspend {
                        if let Some(pid_str) = event.metadata.get("pid") {
                            if let Ok(pid) = pid_str.parse::<u32>() {
                                actions.push(ResponseAction::ProcessSuspend {
                                    pid,
                                    reason: format!(
                                        "Enterprise policy: {:?} threat detected",
                                        event.event_type
                                    ),
                                    duration: Some(Duration::from_secs(300)), // 5 minutes
                                });
                            }
                        }
                    }
                }
                "RiskAssessment" => {
                    if rule.risk_assessment.enabled && self.config.features.enable_risk_assessment {
                        let event_id = event
                            .metadata
                            .get("event_id")
                            .unwrap_or(&format!(
                                "evt_{}",
                                SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs()
                            ))
                            .clone();

                        actions.push(ResponseAction::RiskAssessment {
                            event_id,
                            risk_score: threat_score * rule.risk_assessment.score_multiplier,
                            recommendations: rule.risk_assessment.recommendations.clone(),
                        });
                    }
                }
                "FirewallBlock" => {
                    if self.config.features.enable_firewall_blocking {
                        if let Some(remote_ip) = event.metadata.get("remote_ip") {
                            if let Ok(ip) = remote_ip.parse::<std::net::IpAddr>() {
                                actions.push(ResponseAction::FirewallBlock {
                                    target: format!("{}", ip),
                                    rule_type: "enterprise_policy".to_string(),
                                    reason: format!("Enterprise policy: blocking malicious IP"),
                                });
                            }
                        }
                    }
                }
                "NetworkQuarantine" => {
                    if self.config.features.enable_network_quarantine {
                        if let Some(pid_str) = event.metadata.get("pid") {
                            if let Ok(pid) = pid_str.parse::<u32>() {
                                actions.push(ResponseAction::NetworkQuarantine {
                                    target: crate::response::network_quarantine::QuarantineTarget::ProcessId(pid),
                                    reason: format!("Enterprise policy: network isolation"),
                                    duration: Some(Duration::from_secs(1800)), // 30 minutes
                                });
                            }
                        }
                    }
                }
                _ => {
                    warn!("Unknown action type in threat mapping: {}", action_type);
                }
            }
        }

        Ok(actions)
    }

    /// Calculate enhanced threat score with enterprise factors
    async fn calculate_enterprise_threat_score(
        &self,
        event: &SecurityEvent,
    ) -> Result<f64, Box<dyn std::error::Error + Send + Sync>> {
        let mut base_score = event.severity * event.confidence;

        // Apply enterprise-specific multipliers
        let enterprise_multiplier = match event.event_type {
            SecurityEventType::RansomwareDetected => 3.0,
            SecurityEventType::EntropySpike => 2.5,
            SecurityEventType::BehavioralAnomaly => 2.0,
            SecurityEventType::SuspiciousProcess => 1.8,
            SecurityEventType::AnomalousFileActivity => 1.5,
            SecurityEventType::NetworkThreatDetected => 1.4,
            _ => 1.0,
        };

        base_score *= enterprise_multiplier;

        // Apply correlation factors
        let source_id = self.get_source_identifier(event);
        if let Some(correlations) = self.threat_correlations.get(&source_id) {
            if correlations.len() > 1 {
                base_score *= 1.0 + (correlations.len() as f64 * 0.3);
            }
        }

        // Apply threshold-based adjustments
        base_score = self.apply_threshold_adjustments(base_score, event);

        // Cap at maximum score
        Ok(base_score.min(10.0))
    }

    /// Apply threshold-based score adjustments
    fn apply_threshold_adjustments(&self, mut score: f64, event: &SecurityEvent) -> f64 {
        // Check entropy thresholds
        if let Some(entropy_str) = event.metadata.get("entropy") {
            if let Ok(entropy) = entropy_str.parse::<f64>() {
                if entropy > self.config.thresholds.entropy_thresholds.file_entropy {
                    score *= 1.5;
                }
            }
        }

        // Check I/O rate thresholds
        if let Some(io_rate_str) = event.metadata.get("io_rate_mb_per_sec") {
            if let Ok(io_rate) = io_rate_str.parse::<f64>() {
                if io_rate
                    > self
                        .config
                        .thresholds
                        .io_rate_thresholds
                        .write_rate_mb_per_sec
                {
                    score *= 1.3;
                }
            }
        }

        score
    }

    /// Check for threshold violations
    fn check_threshold_violations(&self, event: &SecurityEvent, threat_score: f64) -> Vec<String> {
        let mut violations = Vec::new();

        // Risk threshold violations
        if threat_score > self.config.thresholds.risk_thresholds.critical {
            violations.push("critical_risk".to_string());
        } else if threat_score > self.config.thresholds.risk_thresholds.high {
            violations.push("high_risk".to_string());
        }

        // Entropy threshold violations
        if let Some(entropy_str) = event.metadata.get("entropy") {
            if let Ok(entropy) = entropy_str.parse::<f64>() {
                if entropy > self.config.thresholds.entropy_thresholds.file_entropy {
                    violations.push("entropy_spike".to_string());
                }
            }
        }

        // I/O rate violations
        if let Some(io_rate_str) = event.metadata.get("io_rate_mb_per_sec") {
            if let Ok(io_rate) = io_rate_str.parse::<f64>() {
                if io_rate
                    > self
                        .config
                        .thresholds
                        .io_rate_thresholds
                        .write_rate_mb_per_sec
                {
                    violations.push("high_io_rate".to_string());
                }
            }
        }

        violations
    }

    /// Generate actions based on threshold violations
    async fn generate_threshold_actions(
        &self,
        violations: &[String],
        event: &SecurityEvent,
    ) -> Result<Vec<ResponseAction>, Box<dyn std::error::Error + Send + Sync>> {
        let mut actions = Vec::new();

        for violation in violations {
            match violation.as_str() {
                "critical_risk" => {
                    actions.push(ResponseAction::Alert {
                        message: format!(
                            "CRITICAL: Risk threshold exceeded for {:?}",
                            event.event_type
                        ),
                        severity: AlertSeverity::Critical,
                    });

                    // Immediate containment for critical risk
                    if let Some(pid_str) = event.metadata.get("pid") {
                        if let Ok(pid) = pid_str.parse::<u32>() {
                            actions.push(ResponseAction::ProcessSuspend {
                                pid,
                                reason: "Critical risk threshold exceeded".to_string(),
                                duration: Some(Duration::from_secs(600)), // 10 minutes
                            });
                        }
                    }
                }
                "entropy_spike" => {
                    if self.config.features.enable_quarantine {
                        if let Some(file_path) = event.metadata.get("file_path") {
                            actions.push(ResponseAction::FileQuarantine {
                                path: file_path.clone(),
                                backup_location: format!(
                                    "entropy_quarantine/{}",
                                    SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs()
                                ),
                            });
                        }
                    }
                }
                "high_io_rate" => {
                    actions.push(ResponseAction::Alert {
                        message: format!("High I/O rate detected: {:?}", event.event_type),
                        severity: AlertSeverity::High,
                    });
                }
                _ => {}
            }
        }

        Ok(actions)
    }

    /// Start correlation analysis background task
    async fn start_correlation_analysis(
        &self,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // In a full implementation, this would start a background task
        // to analyze threat correlations across different sources
        info!("Threat correlation analysis started");
        Ok(())
    }

    /// Start threshold monitoring background task
    async fn start_threshold_monitoring(
        &self,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // In a full implementation, this would monitor system metrics
        // against configured thresholds
        info!("Threshold monitoring started");
        Ok(())
    }

    /// Start escalation cleanup background task
    async fn start_escalation_cleanup(
        &self,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // In a full implementation, this would clean up old escalation states
        info!("Escalation cleanup task started");
        Ok(())
    }

    /// Update threat correlations
    async fn update_threat_correlations(
        &mut self,
        event: &SecurityEvent,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let source_id = self.get_source_identifier(event);
        let event_type = format!("{:?}", event.event_type);

        let correlations = self
            .threat_correlations
            .entry(source_id)
            .or_insert_with(Vec::new);
        if !correlations.contains(&event_type) {
            correlations.push(event_type);
        }

        // Keep only recent correlations
        if correlations.len() > 10 {
            correlations.drain(0..correlations.len() - 10);
        }

        Ok(())
    }

    /// Update enterprise escalation state
    fn update_enterprise_escalation_state(
        &mut self,
        source_id: &str,
        event: &SecurityEvent,
        actions: &[ResponseAction],
        threat_score: f64,
    ) {
        let state = self
            .escalation_state
            .entry(source_id.to_string())
            .or_insert_with(|| EnterpriseEscalationState {
                current_level: ResponseEscalationLevel::Monitoring,
                escalation_time: event.timestamp,
                event_count: 0,
                last_action_time: None,
                threat_correlation_score: 0.0,
                escalation_history: Vec::new(),
                risk_factors: HashMap::new(),
            });

        state.event_count += 1;
        state.threat_correlation_score = threat_score;

        // Update risk factors
        state
            .risk_factors
            .insert("severity".to_string(), event.severity);
        state
            .risk_factors
            .insert("confidence".to_string(), event.confidence);
        state
            .risk_factors
            .insert("threat_score".to_string(), threat_score);

        if !actions.is_empty() {
            state.last_action_time = Some(SystemTime::now());

            // Record escalation event
            let escalation_event = EscalationEvent {
                timestamp: SystemTime::now(),
                level: state.current_level.clone(),
                trigger_reason: format!("{:?}", event.event_type),
                actions_taken: actions.iter().map(|a| format!("{:?}", a)).collect(),
            };

            state.escalation_history.push(escalation_event);

            // Keep history limited
            if state.escalation_history.len() > 50 {
                state
                    .escalation_history
                    .drain(0..state.escalation_history.len() - 50);
            }
        }
    }

    /// Update enterprise metrics
    fn update_enterprise_metrics(
        &self,
        event: &SecurityEvent,
        actions: &[ResponseAction],
        decision_time: Duration,
    ) {
        // Record policy decision latency
        self.metrics.record_histogram(
            "policy_decision_latency_ms",
            decision_time.as_millis() as f64,
            &[],
        );

        // Record threat mapping evaluations
        self.metrics
            .record_counter("threat_mapping_evaluations_total", 1.0);

        // Record threshold violations
        let _event_type_str = format!("{:?}", event.event_type);
        self.metrics.record_counter("threshold_evaluations_total", 1.0);

        // Record actions generated
        for action in actions {
            let _action_type = match action {
                ResponseAction::ProcessSuspend { .. } => "process_suspend",
                ResponseAction::RiskAssessment { .. } => "risk_assessment",
                ResponseAction::FirewallBlock { .. } => "firewall_block",
                ResponseAction::NetworkQuarantine { .. } => "network_quarantine",
                ResponseAction::FileQuarantine { .. } => "file_quarantine",
                ResponseAction::Alert { .. } => "alert",
                _ => "other",
            };

            self.metrics.record_counter("erdps_actions_total", 1.0);
        }
    }

    /// Get source identifier for event grouping
    fn get_source_identifier(&self, event: &SecurityEvent) -> String {
        match &event.event_type {
            SecurityEventType::SuspiciousProcessBehavior | SecurityEventType::SuspiciousProcess => {
                event
                    .metadata
                    .get("pid")
                    .map(|pid| format!("process_{}", pid))
                    .unwrap_or_else(|| event.source.clone())
            }
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
            SecurityEventType::EntropySpike => event
                .metadata
                .get("file_path")
                .map(|path| format!("entropy_{}", path))
                .unwrap_or_else(|| event.source.clone()),
            _ => event.source.clone(),
        }
    }

    /// Update event history
    fn update_event_history(&mut self, event: &SecurityEvent) {
        let source_id = self.get_source_identifier(event);
        let history = self.event_history.entry(source_id).or_insert_with(Vec::new);

        history.push(event.clone());

        // Keep only recent events (last 2 hours)
        let cutoff_time = SystemTime::now() - Duration::from_secs(7200);
        history.retain(|e| e.timestamp > cutoff_time);

        // Limit history size
        if history.len() > 200 {
            history.drain(0..history.len() - 200);
        }
    }

    /// Evaluate threat against enterprise policies
    pub async fn evaluate_threat(
        &self,
        base_result: &crate::detection::DetectionResult,
    ) -> Result<PolicyEvaluation, Box<dyn std::error::Error + Send + Sync>> {
        // Create a security event from the detection result
        let security_event = SecurityEvent {
            event_type: SecurityEventType::SuspiciousProcess,
            source: base_result.file_path
                .as_ref()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            severity: base_result.confidence,
            confidence: base_result.confidence,
            timestamp: SystemTime::now(),
            metadata: std::collections::HashMap::new(),
        };

        // Get applicable threat mapping rules
        let applicable_rules = self.get_applicable_threat_mappings(&security_event);
        
        let mut matched_rules = Vec::new();
        let mut recommended_actions = Vec::new();
        let mut escalation_level = EscalationLevel::None;
        let mut confidence: f32 = 0.5;

        // Evaluate each applicable rule
        for rule in applicable_rules {
            if self.rule_conditions_met(rule, &security_event, base_result.confidence) {
                matched_rules.push(rule.clone());
                
                // Generate actions for this rule
                let rule_actions = self.generate_rule_actions(rule, &security_event, base_result.confidence).await?;
                recommended_actions.extend(rule_actions);
                
                // Update escalation level based on rule
                if rule.escalation_behavior.immediate_escalation {
                    escalation_level = EscalationLevel::High;
                } else if escalation_level == EscalationLevel::None {
                    escalation_level = EscalationLevel::Low;
                }
                
                // Update confidence
                confidence = confidence.max(security_event.confidence as f32);
            }
        }

        // If no rules matched, provide default response
        if recommended_actions.is_empty() {
            recommended_actions.push(ResponseAction::Alert {
                message: "Default threat response".to_string(),
                severity: AlertSeverity::Medium,
            });
        }

        Ok(PolicyEvaluation {
            matched_rules,
            recommended_actions,
            escalation_level,
            confidence: confidence as f64,
        })
    }

    /// Get enterprise policy statistics
    pub fn get_enterprise_stats(&self) -> EnterprisePolicyStats {
        let mut stats = EnterprisePolicyStats::default();

        stats.total_threat_mappings = self.config.threat_mappings.len();
        stats.active_escalations = self.escalation_state.len();
        stats.total_correlations = self.threat_correlations.values().map(|v| v.len()).sum();

        // Calculate average decision time
        if !self.policy_decision_times.is_empty() {
            let total_time: Duration = self.policy_decision_times.iter().sum();
            stats.avg_decision_time_ms =
                (total_time.as_millis() / self.policy_decision_times.len() as u128) as f64;
        }

        stats
    }
}

/// Default enterprise policy configuration
impl Default for EnterprisePolicyConfig {
    fn default() -> Self {
        let mut threat_mappings = HashMap::new();

        // Ransomware detection rule
        threat_mappings.insert(
            "ransomware_detection".to_string(),
            ThreatMappingRule {
                event_types: vec!["RansomwareDetected".to_string()],
                min_severity: 0.8,
                min_confidence: 0.7,
                response_actions: vec!["ProcessSuspend".to_string(), "RiskAssessment".to_string()],
                risk_assessment: RiskAssessmentConfig {
                    enabled: true,
                    score_multiplier: 2.0,
                    recommendations: vec![
                        "Immediate process isolation".to_string(),
                        "File system backup verification".to_string(),
                        "Network traffic analysis".to_string(),
                    ],
                    high_risk_threshold: 7.0,
                },
                escalation_behavior: EscalationBehavior {
                    immediate_escalation: true,
                    escalation_intervals: vec![0, 60, 300], // immediate, 1min, 5min
                    max_escalation_level: "Recovery".to_string(),
                },
            },
        );

        // Entropy spike detection rule
        threat_mappings.insert(
            "entropy_spike".to_string(),
            ThreatMappingRule {
                event_types: vec!["EntropySpike".to_string()],
                min_severity: 0.6,
                min_confidence: 0.5,
                response_actions: vec!["ProcessSuspend".to_string(), "RiskAssessment".to_string()],
                risk_assessment: RiskAssessmentConfig {
                    enabled: true,
                    score_multiplier: 1.5,
                    recommendations: vec![
                        "File entropy analysis".to_string(),
                        "Process behavior monitoring".to_string(),
                    ],
                    high_risk_threshold: 5.0,
                },
                escalation_behavior: EscalationBehavior {
                    immediate_escalation: false,
                    escalation_intervals: vec![30, 120, 600], // 30s, 2min, 10min
                    max_escalation_level: "Containment".to_string(),
                },
            },
        );

        // Behavioral anomaly detection rule
        threat_mappings.insert(
            "behavioral_anomaly".to_string(),
            ThreatMappingRule {
                event_types: vec!["BehavioralAnomaly".to_string()],
                min_severity: 0.5,
                min_confidence: 0.6,
                response_actions: vec!["RiskAssessment".to_string()],
                risk_assessment: RiskAssessmentConfig {
                    enabled: true,
                    score_multiplier: 1.2,
                    recommendations: vec![
                        "Behavioral pattern analysis".to_string(),
                        "User activity correlation".to_string(),
                    ],
                    high_risk_threshold: 4.0,
                },
                escalation_behavior: EscalationBehavior {
                    immediate_escalation: false,
                    escalation_intervals: vec![60, 300, 900], // 1min, 5min, 15min
                    max_escalation_level: "Alerting".to_string(),
                },
            },
        );

        EnterprisePolicyConfig {
            threat_mappings,
            thresholds: ThresholdConfig {
                risk_thresholds: RiskThresholds {
                    low: 2.0,
                    medium: 4.0,
                    high: 6.0,
                    critical: 8.0,
                },
                anomaly_thresholds: AnomalyThresholds {
                    behavioral_anomaly: 0.7,
                    process_anomaly: 0.8,
                    network_anomaly: 0.6,
                    file_system_anomaly: 0.75,
                },
                entropy_thresholds: EntropyThresholds {
                    file_entropy: 7.5,
                    network_entropy: 6.0,
                    process_entropy: 7.0,
                    entropy_spike_rate: 2.0,
                },
                io_rate_thresholds: IoRateThresholds {
                    read_rate_mb_per_sec: 100.0,
                    write_rate_mb_per_sec: 50.0,
                    network_rate_mb_per_sec: 25.0,
                    file_operations_per_sec: 1000,
                },
            },
            features: FeatureConfig {
                enable_quarantine: true,
                enable_firewall_blocking: true,
                enable_process_suspend: true,
                enable_network_quarantine: true,
                enable_risk_assessment: true,
                enable_advanced_correlation: true,
            },
            escalation_timing: EscalationTimingConfig {
                escalation_check_interval: 30,
                re_evaluation_interval: 300,
                max_escalation_age: 86400, // 24 hours
            },
        }
    }
}

/// Escalation level enumeration
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum EscalationLevel {
    None,
    Low,
    Medium,
    High,
    Critical,
}

/// Policy evaluation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEvaluation {
    pub matched_rules: Vec<ThreatMappingRule>,
    pub recommended_actions: Vec<ResponseAction>,
    pub escalation_level: EscalationLevel,
    pub confidence: f64,
}

/// Enterprise policy statistics
#[derive(Debug, Default)]
pub struct EnterprisePolicyStats {
    pub total_threat_mappings: usize,
    pub active_escalations: usize,
    pub total_correlations: usize,
    pub avg_decision_time_ms: f64,
}
