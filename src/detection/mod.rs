//! Detection engine module
//! Provides various detection engines for malware analysis

// Core detection engines
pub mod behavioral;
pub mod heuristic;
// ML modules removed for production
// pub mod machine_learning;
// pub mod ml;

// Enterprise detection engine
pub mod enterprise_engine;

// Specialized detection modules
pub mod network;
pub mod pattern_matcher;
pub mod polymorphic;
pub mod signature;

// Rule and pattern storage
pub mod rule_store;

// Phase 2 detection engines integration
pub mod integration;

// YARA integration
#[cfg(feature = "yara")]
pub mod yara_engine;
#[cfg(feature = "yara")]
pub mod yara_events;
#[cfg(feature = "yara")]
pub mod yara_periodic_scanner;
#[cfg(feature = "yara")]
pub mod yara_rules;

// Provide a `detection::yara` module alias expected by tests
// This submodule re-exports items from the YARA integration modules
#[cfg(feature = "yara")]
pub mod yara {
    // Explicit re-exports to avoid ambiguous glob re-exports
    pub use super::yara_engine::{YaraEngine, YaraMatch};
    pub use super::yara_events::YaraDetectionEvent;
    pub use super::yara_events::helpers::{
        create_file_detection_event,
        create_process_detection_event,
    };
    pub use super::yara_periodic_scanner::YaraPeriodicScanner;
    pub use super::yara_rules::{YaraRuleManager, YaraRuleError};
}

// Re-export core detection types and traits from the core module
pub use crate::core::agent::{BehavioralEngine, HeuristicEngine, PreventionEngine};
// MachineLearningEngine not available in core::agent, use from machine_learning module
// pub use crate::core::agent::MachineLearningEngine;
// DetectionEngine not available in core::agent module
// pub use crate::core::agent::DetectionEngine;
pub use crate::core::types::{DetectionMethod, DetectionResult, ThreatSeverity, ThreatType};

// Re-export enterprise detection engine
pub use enterprise_engine::{
    AnomalyAnalysisResult, DetectionTiming, EnterpriseDetectionResult, EnterpriseThreatConfig,
    EnterpriseThreatEngine, EntropyAnalysisResult, PolicyEvaluationResult, RansomwareIndicators,
    ThreatCorrelation,
};

// Re-export behavioral analysis components
pub use behavioral::EntropyAnalyzer;

// Re-export config and error types
pub use crate::core::config::{
    BehavioralEngineConfig,
    HeuristicEngineConfig,
    // MLEngineConfig, // Commented out - ML engine not implemented
    // DetectionEngineConfig not available, using DetectionConfig instead
    // DetectionEngineConfig,
};
pub use crate::core::error::EnhancedAgentError;
// DetectionEngineError not available in core::error module
// pub use crate::core::error::DetectionEngineError;

// Conditional exports based on features
#[cfg(feature = "network-monitoring")]
pub use network::*;

#[cfg(feature = "yara")]
pub use yara_engine::YaraEngine;
// YaraEngineConfig not available in yara_engine module
// pub use yara_engine::YaraEngineConfig;

// YaraEvent and YaraEventHandler not available in yara_events module
// pub use yara_events::{YaraEvent, YaraEventHandler};
#[cfg(feature = "yara")]
pub use yara_periodic_scanner::YaraPeriodicScanner;
// YaraScannerConfig import commented out as unused
// use crate::scanning::YaraScannerConfig;
#[cfg(feature = "yara")]
pub use yara_rules::YaraRuleManager;
// YaraRuleConfig not available in yara_rules module
// pub use yara_rules::YaraRuleConfig;
