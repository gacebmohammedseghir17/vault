//! API Hooking Module
//!
//! This module provides API hooking and system call monitoring capabilities
//! for detecting suspicious behavior in real-time.

pub mod hooking_engine;

pub use hooking_engine::{
    ApiCallInfo, ApiCallType, ApiHookingConfig, ApiHookingEngine, ApiHookingStats, PatternMatch,
    SuspiciousPattern,
};

/// API module initialization result
#[derive(Debug)]
pub struct ApiModuleResult {
    pub success: bool,
    pub message: String,
    pub hooking_engine: Option<ApiHookingEngine>,
}

/// Initialize the API hooking module
pub async fn initialize_api_module(config: ApiHookingConfig) -> ApiModuleResult {
    match ApiHookingEngine::new(config) {
        engine => ApiModuleResult {
            success: true,
            message: "API hooking module initialized successfully".to_string(),
            hooking_engine: Some(engine),
        },
    }
}

/// API module error types
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("API hooking initialization failed: {0}")]
    InitializationError(String),

    #[error("Pattern matching error: {0}")]
    PatternMatchingError(String),

    #[error("API call monitoring error: {0}")]
    MonitoringError(String),

    #[error("Configuration error: {0}")]
    ConfigurationError(String),
}
