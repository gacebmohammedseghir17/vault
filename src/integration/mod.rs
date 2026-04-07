//! Integration module for external systems and services
//!
//! This module provides integration capabilities with various external systems
//! including SIEM platforms, databases, APIs, and other security tools.

pub mod siem;

// Re-export main integration components
pub use siem::{
    SiemIntegrationManager,
    SiemConfig,
    SiemEvent,
    SiemAlert,
    SiemType,
    SeverityLevel,
    EventType,
    SiemError,
};
