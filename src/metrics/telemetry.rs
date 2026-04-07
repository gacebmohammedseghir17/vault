//! Telemetry and observability functionality

use std::collections::HashMap;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Telemetry event types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TelemetryEventType {
    Detection,
    Performance,
    Error,
    Warning,
    Info,
    Debug,
}

impl std::fmt::Display for TelemetryEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TelemetryEventType::Detection => write!(f, "Detection"),
            TelemetryEventType::Performance => write!(f, "Performance"),
            TelemetryEventType::Error => write!(f, "Error"),
            TelemetryEventType::Warning => write!(f, "Warning"),
            TelemetryEventType::Info => write!(f, "Info"),
            TelemetryEventType::Debug => write!(f, "Debug"),
        }
    }
}

/// Telemetry event data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEvent {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub event_type: TelemetryEventType,
    pub component: String,
    pub message: String,
    pub metadata: HashMap<String, String>,
    pub severity: String,
}

/// Telemetry configuration
#[derive(Debug, Clone)]
pub struct TelemetryConfig {
    pub enabled: bool,
    pub endpoint: Option<String>,
    pub batch_size: usize,
    pub flush_interval_seconds: u64,
    pub max_events_per_second: u64,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            endpoint: None,
            batch_size: 100,
            flush_interval_seconds: 30,
            max_events_per_second: 1000,
        }
    }
}

/// Telemetry collector for gathering and forwarding events
#[derive(Debug)]
pub struct TelemetryCollector {
    config: TelemetryConfig,
    events: std::sync::Arc<std::sync::RwLock<Vec<TelemetryEvent>>>,
    last_flush: std::sync::Arc<std::sync::RwLock<DateTime<Utc>>>,
}

impl TelemetryCollector {
    /// Create a new telemetry collector
    pub fn new(config: TelemetryConfig) -> Self {
        Self {
            config,
            events: std::sync::Arc::new(std::sync::RwLock::new(Vec::new())),
            last_flush: std::sync::Arc::new(std::sync::RwLock::new(Utc::now())),
        }
    }

    /// Record a telemetry event
    pub fn record_event(&self, event: TelemetryEvent) -> anyhow::Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let mut events = self.events.write().map_err(|_| anyhow::anyhow!("Failed to acquire write lock"))?;
        events.push(event);

        // Check if we need to flush
        if events.len() >= self.config.batch_size {
            self.flush_events_internal(&mut events)?;
        }

        Ok(())
    }

    /// Flush all pending events
    pub fn flush(&self) -> anyhow::Result<()> {
        let mut events = self.events.write().map_err(|_| anyhow::anyhow!("Failed to acquire write lock"))?;
        self.flush_events_internal(&mut events)
    }

    /// Internal flush implementation
    fn flush_events_internal(&self, events: &mut Vec<TelemetryEvent>) -> anyhow::Result<()> {
        if events.is_empty() {
            return Ok(());
        }

        // In a real implementation, this would send events to a telemetry service
        // For now, we'll just log them
        for event in events.iter() {
            log::info!("Telemetry: {} - {} - {}", event.component, event.event_type, event.message);
        }

        events.clear();
        let mut last_flush = self.last_flush.write().map_err(|_| anyhow::anyhow!("Failed to acquire write lock"))?;
        *last_flush = Utc::now();

        Ok(())
    }

    /// Get pending event count
    pub fn pending_count(&self) -> anyhow::Result<usize> {
        let events = self.events.read().map_err(|_| anyhow::anyhow!("Failed to acquire read lock"))?;
        Ok(events.len())
    }
}

/// Helper function to create a telemetry event
pub fn create_event(
    component: &str,
    event_type: TelemetryEventType,
    message: &str,
    severity: &str,
) -> TelemetryEvent {
    TelemetryEvent {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
        event_type,
        component: component.to_string(),
        message: message.to_string(),
        metadata: HashMap::new(),
        severity: severity.to_string(),
    }
}
