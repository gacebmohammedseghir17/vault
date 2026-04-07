//! Core module for the Enhanced ERDPS Agent
//!
//! This module contains the main agent structure and coordination logic
//! for the multi-layered ransomware detection and prevention system.

pub mod agent;
pub mod bootstrap;
pub mod cli;
pub mod config;
pub mod error;
pub mod performance;
pub mod types;

pub use agent::{
    AgentCoordinator, BehavioralEngine, EnhancedErdpsAgent, HeuristicEngine, // MLEngine, // Commented out - ML engine not implemented
    PreventionEngine, QuarantineManager, RollbackEngine, SignatureEngine, TelemetryEngine,
    ThreatIntelligenceEngine,
};

#[cfg(feature = "network-monitoring")]
pub use agent::NetworkEngine;
pub use config::EnhancedAgentConfig;

// Stable public types from types module
pub use types::{
    AgentId, ApiCallSequence, BehaviorMetric, ConfidenceScore, DetectionMethod, DetectionResult,
    FileOperation, FileOperationEvent, NetworkInfo, NetworkPattern, ProcessInfo, QuarantineId,
    RegistryOperation, RegistryOperationEvent, ResponseAction, ThreatId, ThreatSeverity,
    ThreatType,
};

// Stable public error types from error module
pub use error::{
    BehavioralEngineError, EnhancedAgentError, HeuristicEngineError, // MLEngineError, // Commented out - ML engine not implemented
    SignatureEngineError,
};

#[cfg(feature = "network-monitoring")]
pub use error::NetworkEngineError;
