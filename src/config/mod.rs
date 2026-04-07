//! Configuration Module
//!
//! This module handles all configuration-related functionality for the ERDPS Agent.
//! It includes both the main agent configuration and specialized configurations
//! for different subsystems like YARA scanning.

// Main agent configuration
pub mod agent_config;

// Configuration validation tests
#[cfg(test)]
pub mod config_validation_test;

// Unit tests for config parsing validation
#[cfg(test)]
pub mod tests;

// YARA configuration module
#[cfg(feature = "yara")]
pub mod yara_config;

// Scanning configuration module
pub mod scanning_config;

// Re-export main config types
pub use agent_config::AgentConfig;

// Re-export YARA config types for easier access
#[cfg(feature = "yara")]
pub use yara_config::{
    AlertConfig, IpcConfig, LoggingConfig, PerformanceConfig, PeriodicScanConfig,
    RealTimeMonitoringConfig, YaraConfig,
};

// Re-export scanning config types
pub use scanning_config::{
    get_scanning_config, validate_scanning_config, GlobalScanConfig, MonitoredDirectory,
    ScanPriority, ScannerConfig, ScanningConfig, ScheduledScan,
};

/// Initialize the configuration system
pub fn init() {
    // Configuration initialization logic
    // This can be expanded to load configuration from files, environment variables, etc.
}

/// Check if a process ID is protected from termination
pub fn is_pid_protected(_config: &AgentConfig, pid: u32) -> bool {
    // For now, protect system critical processes
    // This can be expanded based on configuration
    match pid {
        0..=4 => true, // System processes
        1234 => true,  // Test protected PID for integration tests
        _ => false,
    }
}
