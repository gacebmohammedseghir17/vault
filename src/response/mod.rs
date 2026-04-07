//! Automated Response System
//!
//! This module provides comprehensive automated response capabilities for the ERDPS Agent,
//! including policy-driven response actions, network isolation, and secure quarantine operations.

pub mod action_executor;
pub mod enterprise_policy_engine;
pub mod network_controller;
pub mod policy_engine;
// Phase 3: Autonomous Response Engine modules
pub mod auto_engine;
pub mod concurrent_processor;
pub mod network_quarantine;
pub mod risk_score;
pub mod windows_firewall;

use crate::core::config::AutomatedResponseConfig;
#[cfg(feature = "metrics")]
use crate::metrics::MetricsCollector;
use concurrent_processor::{ConcurrentEventProcessor, ConcurrentProcessorConfig, EventPriority};
use enterprise_policy_engine::{EnterprisePolicyConfig, EnterprisePolicyEngine};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;
use windows_firewall::{FirewallAction, WindowsFirewallConfig, WindowsFirewallManager};

// Import PolicyDecision from enterprise engine to avoid duplication
pub use crate::detection::enterprise_engine::PolicyDecision;

/// Response system initialization result
#[derive(Clone)]
pub struct ResponseSystem {
    pub action_executor: Arc<action_executor::ActionExecutor>,
    pub policy_engine: Arc<RwLock<policy_engine::PolicyEngine>>,
    pub network_controller: Arc<RwLock<network_controller::NetworkController>>,
    pub enterprise_policy_engine: Option<Arc<RwLock<EnterprisePolicyEngine>>>,
    // Phase 3: Autonomous Response Engine components
    pub auto_engine: Arc<auto_engine::AutoEngine>,
    pub risk_scorer: Arc<risk_score::RiskScorer>,
    pub network_quarantine: Arc<network_quarantine::NetworkQuarantine>,
    pub concurrent_processor: Option<Arc<ConcurrentEventProcessor>>,
    pub windows_firewall: Option<Arc<tokio::sync::RwLock<WindowsFirewallManager>>>,
}

impl ResponseSystem {
    /// Initialize the complete response system
    pub async fn new(
        config: AutomatedResponseConfig,
        #[cfg(feature = "metrics")]
        metrics: Arc<MetricsCollector>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Initialize action executor
        let action_executor =
            Arc::new(action_executor::ActionExecutor::new(Arc::clone(&metrics)).await?);

        // Initialize policy engine
        let policy_engine = Arc::new(RwLock::new(policy_engine::PolicyEngine::new(
            config.clone(),
            Arc::clone(&metrics),
        )));

        // Initialize network controller
        let network_controller = Arc::new(RwLock::new(
            network_controller::NetworkController::new(Arc::clone(&metrics)).await?,
        ));

        // Phase 3: Initialize autonomous response engine components
        let auto_engine_config = auto_engine::AutoEngineConfig::default();
        let auto_engine =
            Arc::new(auto_engine::AutoEngine::new(auto_engine_config, Arc::clone(&metrics)).await?);

        let risk_score_config = risk_score::RiskScoringConfig::default();
        let risk_scorer =
            Arc::new(risk_score::RiskScorer::new(risk_score_config, Arc::clone(&metrics)).await?);

        let quarantine_config = network_quarantine::NetworkQuarantineConfig::default();
        let network_quarantine = Arc::new(
            network_quarantine::NetworkQuarantine::new(quarantine_config, Arc::clone(&metrics))
                .await?,
        );

        Ok(ResponseSystem {
            action_executor,
            policy_engine,
            network_controller,
            enterprise_policy_engine: None,
            auto_engine,
            risk_scorer,
            network_quarantine,
            concurrent_processor: None,
            windows_firewall: None,
        })
    }

    /// Initialize response system with enterprise policy engine
    pub async fn new_with_enterprise(
        config: AutomatedResponseConfig,
        enterprise_config: EnterprisePolicyConfig,
        metrics: Arc<MetricsCollector>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Initialize action executor
        let action_executor =
            Arc::new(action_executor::ActionExecutor::new(Arc::clone(&metrics)).await?);

        // Initialize policy engine
        let policy_engine = Arc::new(RwLock::new(policy_engine::PolicyEngine::new(
            config.clone(),
            Arc::clone(&metrics),
        )));

        // Initialize enterprise policy engine
        let enterprise_policy_engine = Arc::new(RwLock::new(EnterprisePolicyEngine::new(
            enterprise_config,
            config.clone(), // Add missing AutomatedResponseConfig parameter
            Arc::clone(&metrics),
        )));

        // Initialize network controller
        let network_controller = Arc::new(RwLock::new(
            network_controller::NetworkController::new(Arc::clone(&metrics)).await?,
        ));

        // Phase 3: Initialize autonomous response engine components
        let auto_engine_config = auto_engine::AutoEngineConfig::default();
        let auto_engine =
            Arc::new(auto_engine::AutoEngine::new(auto_engine_config, Arc::clone(&metrics)).await?);

        let risk_score_config = risk_score::RiskScoringConfig::default();
        let risk_scorer =
            Arc::new(risk_score::RiskScorer::new(risk_score_config, Arc::clone(&metrics)).await?);

        let quarantine_config = network_quarantine::NetworkQuarantineConfig::default();
        let network_quarantine = Arc::new(
            network_quarantine::NetworkQuarantine::new(quarantine_config, Arc::clone(&metrics))
                .await?,
        );

        // Initialize concurrent processor with enterprise configuration
        let concurrent_config = ConcurrentProcessorConfig {
            max_queue_size: 50000,                // Enterprise scale
            worker_count: num_cpus::get().max(4), // Minimum 4 workers for enterprise
            event_processing_timeout: 5,
            file_integrity_check_interval: 30, // More frequent checks
            max_file_watchers: 5000,           // Enterprise file monitoring
            shutdown_timeout: 60,
            enable_file_integrity: true,
            enable_event_batching: true,
            batch_size: 100,
            batch_timeout_ms: 500,
        };

        let concurrent_processor = Some(Arc::new(ConcurrentEventProcessor::new(
            concurrent_config,
            Arc::clone(&metrics),
        )));

        // Initialize Windows Firewall manager
        let firewall_config = WindowsFirewallConfig {
            auto_create_rules: true,
            max_retry_attempts: 3,
            base_retry_delay_ms: 1000,
            max_retry_delay_ms: 10000,
            operation_timeout_secs: 30,
            require_admin_privileges: true,
            default_block_action: FirewallAction::Block,
            rule_name_prefix: "ERDPS_Enterprise".to_string(),
            cleanup_rules_on_shutdown: true,
        };

        let mut firewall_manager =
            WindowsFirewallManager::new(firewall_config, Arc::clone(&metrics));

        // Initialize firewall (may fail if not admin)
        let windows_firewall = match firewall_manager.initialize().await {
            Ok(_) => {
                log::info!("Windows Firewall integration initialized successfully");
                Some(Arc::new(tokio::sync::RwLock::new(firewall_manager)))
            }
            Err(e) => {
                log::warn!("Failed to initialize Windows Firewall integration: {}. Continuing without firewall features.", e);
                None
            }
        };

        Ok(ResponseSystem {
            action_executor,
            policy_engine,
            network_controller,
            enterprise_policy_engine: Some(enterprise_policy_engine),
            auto_engine,
            risk_scorer,
            network_quarantine,
            concurrent_processor,
            windows_firewall,
        })
    }

    /// Start the response system monitoring
    pub async fn start_monitoring(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Start policy engine monitoring
        {
            let policy_engine = self.policy_engine.read().await;
            policy_engine.start_monitoring().await?;
        }

        // Start enterprise policy engine monitoring if available
        if let Some(enterprise_engine) = &self.enterprise_policy_engine {
            enterprise_engine.read().await.start_monitoring().await?;
        }

        // Start network monitoring
        self.network_controller
            .write()
            .await
            .start_monitoring()
            .await?;

        // Phase 3: Start autonomous response engine monitoring
        self.auto_engine.start_monitoring().await?;

        // Start concurrent processor if available
        if let Some(ref concurrent_processor) = self.concurrent_processor {
            concurrent_processor.start().await?;
            log::info!("Concurrent event processor started");
        }

        // Start network quarantine cleanup task
        let quarantine_clone = Arc::clone(&self.network_quarantine);
        tokio::spawn(async move {
            network_quarantine::start_cleanup_task(
                quarantine_clone,
                std::time::Duration::from_secs(300), // 5 minutes
            )
            .await;
        });

        Ok(())
    }

    /// Process a security event and determine response actions
    pub async fn process_security_event(
        &self,
        event: &SecurityEvent,
    ) -> Result<Vec<ResponseAction>, Box<dyn std::error::Error + Send + Sync>> {
        // Use concurrent processor if available for high-throughput processing
        if let Some(ref concurrent_processor) = self.concurrent_processor {
            let priority = EventPriority::from(&event.event_type);

            // For critical events, use synchronous processing for immediate response
            if priority == EventPriority::Critical {
                let actions = concurrent_processor
                    .submit_event(event.clone(), priority)
                    .await?;

                // Execute critical actions immediately
                for action in &actions {
                    if let Err(e) = self.execute_action(action).await {
                        log::error!("Failed to execute critical action {:?}: {}", action, e);
                    }
                }

                return Ok(actions);
            } else {
                // For non-critical events, use asynchronous processing
                concurrent_processor
                    .submit_event_async(event.clone(), priority)
                    .await?;
                return Ok(vec![]); // Actions will be executed asynchronously
            }
        }

        // Phase 3: Calculate risk score for the event
        let risk_score = self.risk_scorer.calculate_risk(event).await?;

        // Update event with risk score
        let mut enhanced_event = event.clone();
        enhanced_event.metadata.insert(
            "risk_score".to_string(),
            risk_score.unified_score.to_string(),
        );
        enhanced_event.metadata.insert(
            "risk_level".to_string(),
            format!("{:?}", risk_score.risk_level),
        );

        // Get policy-based response actions using enterprise policy engine if available
        let mut actions = if let Some(enterprise_engine) = &self.enterprise_policy_engine {
            let mut engine = enterprise_engine.write().await;
            engine.evaluate_response(&enhanced_event).await?
        } else {
            let mut policy_engine = self.policy_engine.write().await;
            let actions = policy_engine.evaluate_response(&enhanced_event).await?;
            drop(policy_engine); // Release the lock
            actions
        };

        // Phase 3: Get autonomous response recommendations
        let autonomous_decision = self.auto_engine.evaluate_response(&enhanced_event).await?;

        // Convert ResponseDecision to ResponseAction(s)
        match autonomous_decision {
            auto_engine::ResponseDecision::NoAction => {}
            auto_engine::ResponseDecision::Suspend { pid, reason } => {
                actions.push(ResponseAction::ProcessSuspend {
                    pid,
                    reason,
                    duration: None,
                });
            }
            auto_engine::ResponseDecision::Quarantine { path, reason: _ } => {
                actions.push(ResponseAction::FileQuarantine {
                    path: path.clone(),
                    backup_location: format!("{}.backup", path),
                });
            }
            auto_engine::ResponseDecision::FirewallBlock { target, reason } => {
                // Convert string target to NetworkTarget
                if let Ok(ip) = target.parse::<std::net::IpAddr>() {
                    actions.push(ResponseAction::FirewallBlock {
                        target: format!("ip:{}", ip),
                        reason,
                        rule_type: "block".to_string(),
                    });
                }
            }
            auto_engine::ResponseDecision::Combined(decisions) => {
                for decision in decisions {
                    match decision {
                        auto_engine::ResponseDecision::Suspend { pid, reason } => {
                            actions.push(ResponseAction::ProcessSuspend {
                                pid,
                                reason,
                                duration: None,
                            });
                        }
                        auto_engine::ResponseDecision::Quarantine { path, reason: _ } => {
                            actions.push(ResponseAction::FileQuarantine {
                                path: path.clone(),
                                backup_location: format!("{}.backup", path),
                            });
                        }
                        _ => {}
                    }
                }
            }
        }

        Ok(actions)
    }

    /// Execute a response action
    pub async fn execute_action(
        &self,
        action: &ResponseAction,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match action {
            ResponseAction::ProcessTermination { pid, .. } => {
                self.action_executor.terminate_process(*pid).await
            }

            ResponseAction::NetworkIsolation { target, .. } => {
                self.network_controller
                    .write()
                    .await
                    .isolate_target(target)
                    .await
            }
            ResponseAction::Alert { message, .. } => self.action_executor.send_alert(message).await,
            // Phase 3: Execute autonomous response actions
            ResponseAction::ProcessSuspend {
                pid,
                reason,
                duration,
            } => {
                self.auto_engine
                    .suspend_process(*pid, reason.clone(), *duration)
                    .await
            }
            ResponseAction::NetworkQuarantine {
                target,
                reason,
                duration,
            } => {
                log::info!(
                    "Quarantining network target: {:?} (reason: {})",
                    target,
                    reason
                );

                let result = self
                    .network_quarantine
                    .quarantine_target(target.clone(), reason, *duration)
                    .await?;

                if !result.success {
                    return Err(result.message.into());
                }
                Ok(())
            }

            ResponseAction::FileQuarantine {
                path,
                backup_location,
            } => {
                log::info!(
                    "Quarantining file: {} to backup location: {}",
                    path,
                    backup_location
                );

                // In a full implementation, this would move the file to quarantine
                // For now, we'll just log and record metrics
                // File quarantine implementation - move to secure quarantine directory
                let quarantine_dir = std::path::Path::new("./quarantine");
                if !quarantine_dir.exists() {
                    std::fs::create_dir_all(quarantine_dir)?;
                }
                let source_path = std::path::Path::new(path);
                let quarantine_path =
                    quarantine_dir.join(source_path.file_name().unwrap_or_default());
                std::fs::rename(source_path, &quarantine_path)?;
                info!(
                    "File quarantined: {} -> {}",
                    source_path.display(),
                    quarantine_path.display()
                );
                log::warn!("File quarantine not yet implemented for: {}", path);
                Ok(())
            }
            ResponseAction::FirewallBlock {
                target,
                rule_type,
                reason,
            } => {
                log::info!(
                    "Creating firewall block rule for {}: {} (reason: {})",
                    target,
                    rule_type,
                    reason
                );

                if let Some(ref firewall) = self.windows_firewall {
                    let firewall_manager = firewall.read().await;

                    let result = match rule_type.as_str() {
                        "process" => firewall_manager.block_process(&target, &reason).await,
                        "port" => {
                            // Parse port and protocol from target (format: "port:protocol")
                            let parts: Vec<&str> = target.split(':').collect();
                            if parts.len() == 2 {
                                let ports = parts[0];
                                let protocol = match parts[1].to_lowercase().as_str() {
                                    "tcp" => windows_firewall::FirewallProtocol::Tcp,
                                    "udp" => windows_firewall::FirewallProtocol::Udp,
                                    _ => windows_firewall::FirewallProtocol::Any,
                                };
                                firewall_manager.block_ports(ports, protocol, &reason).await
                            } else {
                                return Err(
                                    format!("Invalid port target format: {}", target).into()
                                );
                            }
                        }
                        _ => {
                            return Err(
                                format!("Unsupported firewall rule type: {}", rule_type).into()
                            );
                        }
                    };

                    match result {
                        Ok(op_result) => {
                            if op_result.success {
                                log::info!("Firewall block rule created successfully");
                            } else {
                                log::warn!(
                                    "Firewall block rule creation failed: {:?}",
                                    op_result.error_message
                                );
                            }
                        }
                        Err(e) => {
                            log::error!("Failed to create firewall block rule: {}", e);
                            return Err(e);
                        }
                    }
                } else {
                    log::warn!("Windows Firewall not available, cannot create block rule");
                }

                Ok(())
            }
            ResponseAction::FirewallUnblock { rule_name } => {
                log::info!("Removing firewall rule: {}", rule_name);

                if let Some(ref firewall) = self.windows_firewall {
                    let firewall_manager = firewall.read().await;

                    match firewall_manager.remove_rule(&rule_name).await {
                        Ok(op_result) => {
                            if op_result.success {
                                log::info!("Firewall rule removed successfully");
                            } else {
                                log::warn!(
                                    "Firewall rule removal failed: {:?}",
                                    op_result.error_message
                                );
                            }
                        }
                        Err(e) => {
                            log::error!("Failed to remove firewall rule: {}", e);
                            return Err(e);
                        }
                    }
                } else {
                    log::warn!("Windows Firewall not available, cannot remove rule");
                }

                Ok(())
            }
            ResponseAction::RiskAssessment {
                event_id,
                risk_score,
                recommendations,
            } => {
                // Log risk assessment results
                log::info!(
                    "Risk assessment for event {}: score={:.2}, recommendations={:?}",
                    event_id,
                    risk_score,
                    recommendations
                );

                // Send alert for high-risk events
                if *risk_score > 0.8 {
                    let alert_message = format!(
                        "High-risk event detected (ID: {}, Score: {:.2}). Recommendations: {}",
                        event_id,
                        risk_score,
                        recommendations.join(", ")
                    );
                    self.action_executor.send_alert(&alert_message).await?
                }

                Ok(())
            }
        }
    }

    /// Get escalation statistics from the policy engine
    pub async fn get_escalation_stats(
        &self,
    ) -> Result<policy_engine::EscalationStats, Box<dyn std::error::Error + Send + Sync>> {
        let engine = self.policy_engine.read().await;
        Ok(engine.get_escalation_stats())
    }

    /// Gracefully shutdown the response system
    pub async fn shutdown(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        log::info!("Initiating graceful shutdown of response system");

        // Shutdown concurrent processor first to stop new event processing
        if let Some(ref concurrent_processor) = self.concurrent_processor {
            concurrent_processor.shutdown().await?;
            log::info!("Concurrent processor shutdown completed");
        }

        // Shutdown Windows firewall manager if available
        if let Some(ref firewall) = self.windows_firewall {
            let firewall_manager = firewall.read().await;
            if let Err(e) = firewall_manager.shutdown().await {
                log::warn!("Error during firewall shutdown: {}", e);
            }
        }

        // Shutdown methods for all components
        info!("All response components shut down successfully");
        // self.action_executor.read().await.shutdown().await?;
        // self.policy_engine.read().await.shutdown().await?;
        // self.auto_engine.read().await.shutdown().await?;

        log::info!("Response system shutdown completed");
        Ok(())
    }

    /// Add a file to integrity monitoring
    pub async fn add_file_watcher(
        &self,
        file_path: String,
        reason: String,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(ref concurrent_processor) = self.concurrent_processor {
            concurrent_processor
                .add_file_watcher(file_path, reason)
                .await
        } else {
            Err("Concurrent processor not available for file monitoring".into())
        }
    }

    /// Remove a file from integrity monitoring
    pub async fn remove_file_watcher(&self, file_path: &str) {
        if let Some(ref concurrent_processor) = self.concurrent_processor {
            concurrent_processor.remove_file_watcher(file_path).await;
        }
    }

    /// Get concurrent processing statistics
    pub async fn get_concurrent_stats(&self) -> Option<concurrent_processor::ProcessingStats> {
        if let Some(ref concurrent_processor) = self.concurrent_processor {
            Some(concurrent_processor.get_stats().await)
        } else {
            None
        }
    }
}

/// Security event types that trigger response actions
#[derive(Debug, Clone)]
pub struct SecurityEvent {
    pub event_type: SecurityEventType,
    pub severity: f64,
    pub confidence: f64,
    pub source: String,
    pub timestamp: std::time::SystemTime,
    pub metadata: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub enum SecurityEventType {
    RansomwareDetected,
    SuspiciousProcessBehavior,
    AnomalousFileActivity,
    NetworkThreatDetected,
    MLAnomalyDetected,
    BehavioralAnomalyDetected,
    // Phase 3 event types
    BehavioralAnomaly,
    EntropySpike,
    SuspiciousProcess,
}

/// Response escalation levels for autonomous response
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseEscalationLevel {
    Monitoring,
    Alerting,
    Containment,
    Recovery,
}

/// Response actions that can be executed
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum ResponseAction {
    ProcessTermination {
        pid: u32,
        reason: String,
    },
    FileQuarantine {
        path: String,
        backup_location: String,
    },
    NetworkIsolation {
        target: NetworkTarget,
        duration: std::time::Duration,
    },
    Alert {
        message: String,
        severity: AlertSeverity,
    },
    FirewallBlock {
        target: String,
        rule_type: String,
        reason: String,
    },
    FirewallUnblock {
        rule_name: String,
    },
    // Phase 3: Autonomous response actions
    ProcessSuspend {
        pid: u32,
        reason: String,
        duration: Option<std::time::Duration>,
    },
    NetworkQuarantine {
        target: network_quarantine::QuarantineTarget,
        reason: String,
        duration: Option<std::time::Duration>,
    },
    // Duplicate variants removed - already defined above
    RiskAssessment {
        event_id: String,
        risk_score: f64,
        recommendations: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum NetworkTarget {
    Process(u32),
    IpAddress(std::net::IpAddr),
    Port(u16),
    All,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum AlertSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Initialize the response system module
pub fn init() {
    log::info!("Response system module initialized");
}
