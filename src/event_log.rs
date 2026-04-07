//! Windows Event Log Integration for Enterprise Validation
//!
//! This module provides comprehensive Windows Event Log integration for ERDPS Agent,
//! enabling enterprise-grade audit logging and compliance reporting.
//! All security events, detections, and system activities are logged to Windows Event Log
//! for centralized monitoring and forensic analysis.

use serde::{Deserialize, Serialize};
use std::ptr;
use std::time::SystemTime;
use tracing::warn;

/// Windows Event Log integration for enterprise validation
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct WindowsEventLogger {
    source_name: String,
    event_log_handle: Option<isize>,
}

/// Event types for Windows Event Log
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventType {
    Information = 1,
    Warning = 2,
    Error = 3,
    SuccessAudit = 4,
    FailureAudit = 5,
}

/// Event categories for ERDPS Agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventCategory {
    ThreatDetection = 1,
    BehavioralAnalysis = 2,
    MLDetection = 3,
    NetworkMonitoring = 4,
    ResponseAction = 5,
    SystemStatus = 6,
    Configuration = 7,
    Performance = 8,
}

/// Event IDs for different ERDPS operations
#[derive(Debug, Clone, Copy)]
pub enum EventId {
    // Threat Detection Events (1000-1999)
    ThreatDetected = 1001,
    MalwareQuarantined = 1002,
    SuspiciousFileBlocked = 1003,
    RansomwareDetected = 1004,

    // Behavioral Analysis Events (2000-2999)
    ProcessInjectionDetected = 2001,
    RegistryModificationDetected = 2002,
    FileSystemAnomalyDetected = 2003,
    NetworkAnomalyDetected = 2004,

    // ML Detection Events (3000-3999)
    MLAnomalyDetected = 3001,
    ModelAccuracyUpdated = 3002,
    FeatureExtractionCompleted = 3003,

    // Network Monitoring Events (4000-4999)
    SuspiciousConnectionDetected = 4001,
    DataExfiltrationAttempt = 4002,
    C2CommunicationDetected = 4003,
    DNSAnomalyDetected = 4004,

    // Response Action Events (5000-5999)
    ProcessTerminated = 5001,
    FileQuarantined = 5002,
    NetworkIsolationActivated = 5003,
    AlertSent = 5004,

    // System Status Events (6000-6999)
    ServiceStarted = 6001,
    ServiceStopped = 6002,
    ConfigurationLoaded = 6003,
    MetricsEndpointStarted = 6004,

    // Performance Events (7000-7999)
    PerformanceThresholdExceeded = 7001,
    MTTDRecorded = 7002,
    FalsePositiveDetected = 7003,

    // Error Events (8000-8999)
    InitializationError = 8001,
    ConfigurationError = 8002,
    DetectionEngineError = 8003,
    NetworkError = 8004,
}

/// Security event data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub event_id: u32,
    pub event_type: EventType,
    pub category: EventCategory,
    pub timestamp: SystemTime,
    pub source: String,
    pub message: String,
    pub details: Option<serde_json::Value>,
    pub severity: String,
    pub user_context: Option<String>,
    pub process_id: Option<u32>,
    pub thread_id: Option<u32>,
}

impl WindowsEventLogger {
    /// Create a new Windows Event Logger instance
    pub fn new(source_name: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let logger = Self {
            source_name: source_name.to_string(),
            event_log_handle: None,
        };

        // Register event source if not already registered
        logger.register_event_source()?;

        Ok(logger)
    }

    /// Register the event source with Windows Event Log
    #[cfg(windows)]
    fn register_event_source(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        use winapi::um::winnt::*;
        use winapi::um::winreg::*;

        let key_path = format!(
            "SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\{}",
            self.source_name
        );

        let key_path_wide: Vec<u16> = OsStr::new(&key_path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let mut hkey = ptr::null_mut();
        let result = unsafe {
            RegCreateKeyExW(
                HKEY_LOCAL_MACHINE,
                key_path_wide.as_ptr(),
                0,
                ptr::null_mut(),
                REG_OPTION_NON_VOLATILE,
                KEY_WRITE,
                ptr::null_mut(),
                &mut hkey,
                ptr::null_mut(),
            )
        };

        if result == 0 {
            // Set EventMessageFile value
            let exe_path = std::env::current_exe()
                .unwrap_or_else(|_| std::path::PathBuf::from("erdps-agent.exe"));
            let exe_path_str = exe_path.to_string_lossy();
            let exe_path_wide: Vec<u16> = OsStr::new(exe_path_str.as_ref())
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            let value_name_wide: Vec<u16> = OsStr::new("EventMessageFile")
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            unsafe {
                RegSetValueExW(
                    hkey,
                    value_name_wide.as_ptr(),
                    0,
                    REG_SZ,
                    exe_path_wide.as_ptr() as *const u8,
                    (exe_path_wide.len() * 2) as u32,
                );

                // Set TypesSupported value
                let types_supported: u32 = 0x1F; // All event types
                let types_name_wide: Vec<u16> = OsStr::new("TypesSupported")
                    .encode_wide()
                    .chain(std::iter::once(0))
                    .collect();

                RegSetValueExW(
                    hkey,
                    types_name_wide.as_ptr(),
                    0,
                    REG_DWORD,
                    &types_supported as *const u32 as *const u8,
                    4,
                );

                RegCloseKey(hkey);
            }
        }

        Ok(())
    }

    /// Register event source on non-Windows platforms (no-op)
    #[cfg(not(windows))]
    fn register_event_source(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Event source registration skipped on non-Windows platform");
        Ok(())
    }

    /// Log a security event to Windows Event Log
    pub async fn log_security_event(
        &self,
        event: SecurityEvent,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        #[cfg(windows)]
        {
            self.write_windows_event_log(&event).await?
        }

        #[cfg(not(windows))]
        {
            self.write_fallback_log(&event).await?
        }

        Ok(())
    }

    /// Write event to Windows Event Log
    #[cfg(windows)]
    async fn write_windows_event_log(
        &self,
        event: &SecurityEvent,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        use winapi::um::winbase::*;

        let source_name_wide: Vec<u16> = OsStr::new(&self.source_name)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let handle = unsafe { RegisterEventSourceW(ptr::null_mut(), source_name_wide.as_ptr()) };

        if handle.is_null() {
            return Err("Failed to register event source".into());
        }

        // Format the event message
        let message = self.format_event_message(event);
        let message_wide: Vec<u16> = OsStr::new(&message)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let messages = [message_wide.as_ptr()];

        let success = unsafe {
            ReportEventW(
                handle,
                event.event_type.clone() as u16,
                event.category.clone() as u16,
                event.event_id,
                ptr::null_mut(),
                1,
                0,
                messages.as_ptr() as *mut *const u16,
                ptr::null_mut(),
            )
        };

        unsafe {
            DeregisterEventSource(handle);
        }

        if success == 0 {
            return Err("Failed to write event to Windows Event Log".into());
        }

        Ok(())
    }

    /// Write event to fallback log on non-Windows platforms
    #[cfg(not(windows))]
    async fn write_fallback_log(
        &self,
        event: &SecurityEvent,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let formatted_message = self.format_event_message(event);

        match event.event_type {
            EventType::Error | EventType::FailureAudit => {
                error!("[{}] {}", event.event_id, formatted_message);
            }
            EventType::Warning => {
                warn!("[{}] {}", event.event_id, formatted_message);
            }
            _ => {
                info!("[{}] {}", event.event_id, formatted_message);
            }
        }

        Ok(())
    }

    /// Format event message for logging
    fn format_event_message(&self, event: &SecurityEvent) -> String {
        let mut message = format!(
            "[ERDPS-{}] {} | Category: {:?} | Severity: {} | Source: {}",
            event.event_id, event.message, event.category, event.severity, event.source
        );

        if let Some(details) = &event.details {
            message.push_str(&format!(" | Details: {}", details));
        }

        if let Some(pid) = event.process_id {
            message.push_str(&format!(" | PID: {}", pid));
        }

        if let Some(user) = &event.user_context {
            message.push_str(&format!(" | User: {}", user));
        }

        message
    }

    /// Log threat detection event
    pub async fn log_threat_detection(
        &self,
        threat_type: &str,
        file_path: &str,
        details: Option<serde_json::Value>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let event = SecurityEvent {
            event_id: EventId::ThreatDetected as u32,
            event_type: EventType::Warning,
            category: EventCategory::ThreatDetection,
            timestamp: SystemTime::now(),
            source: "ERDPS-ThreatEngine".to_string(),
            message: format!("Threat detected: {} in file: {}", threat_type, file_path),
            details,
            severity: "HIGH".to_string(),
            user_context: None,
            process_id: Some(std::process::id()),
            thread_id: None,
        };

        self.log_security_event(event).await
    }

    /// Log ransomware detection event
    pub async fn log_ransomware_detection(
        &self,
        sample_path: &str,
        mttd_seconds: f64,
        detection_method: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let details = serde_json::json!({
            "sample_path": sample_path,
            "mttd_seconds": mttd_seconds,
            "detection_method": detection_method,
            "timestamp": SystemTime::now()
        });

        let event = SecurityEvent {
            event_id: EventId::RansomwareDetected as u32,
            event_type: EventType::Warning,
            category: EventCategory::ThreatDetection,
            timestamp: SystemTime::now(),
            source: "ERDPS-RansomwareEngine".to_string(),
            message: format!(
                "Ransomware detected in {} seconds using {} method",
                mttd_seconds, detection_method
            ),
            details: Some(details),
            severity: "CRITICAL".to_string(),
            user_context: None,
            process_id: Some(std::process::id()),
            thread_id: None,
        };

        self.log_security_event(event).await
    }

    /// Log false positive detection
    pub async fn log_false_positive(
        &self,
        application: &str,
        operation: &str,
        file_path: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let details = serde_json::json!({
            "application": application,
            "operation": operation,
            "file_path": file_path,
            "timestamp": SystemTime::now()
        });

        let event = SecurityEvent {
            event_id: EventId::FalsePositiveDetected as u32,
            event_type: EventType::Error,
            category: EventCategory::Performance,
            timestamp: SystemTime::now(),
            source: "ERDPS-ValidationEngine".to_string(),
            message: format!(
                "False positive detected: {} operation in {} triggered alert for {}",
                operation, application, file_path
            ),
            details: Some(details),
            severity: "HIGH".to_string(),
            user_context: None,
            process_id: Some(std::process::id()),
            thread_id: None,
        };

        self.log_security_event(event).await
    }

    /// Log performance metrics
    pub async fn log_performance_metrics(
        &self,
        cpu_usage: f64,
        memory_usage: u64,
        mttd_seconds: f64,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let details = serde_json::json!({
            "cpu_usage_percent": cpu_usage,
            "memory_usage_bytes": memory_usage,
            "mttd_seconds": mttd_seconds,
            "timestamp": SystemTime::now()
        });

        let event = SecurityEvent {
            event_id: EventId::MTTDRecorded as u32,
            event_type: EventType::Information,
            category: EventCategory::Performance,
            timestamp: SystemTime::now(),
            source: "ERDPS-PerformanceMonitor".to_string(),
            message: format!(
                "Performance metrics: CPU: {:.2}%, Memory: {} bytes, MTTD: {:.2}s",
                cpu_usage, memory_usage, mttd_seconds
            ),
            details: Some(details),
            severity: "INFO".to_string(),
            user_context: None,
            process_id: Some(std::process::id()),
            thread_id: None,
        };

        self.log_security_event(event).await
    }

    /// Log system startup event
    pub async fn log_service_started(
        &self,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let event = SecurityEvent {
            event_id: EventId::ServiceStarted as u32,
            event_type: EventType::Information,
            category: EventCategory::SystemStatus,
            timestamp: SystemTime::now(),
            source: "ERDPS-ServiceManager".to_string(),
            message: "ERDPS Agent service started successfully".to_string(),
            details: None,
            severity: "INFO".to_string(),
            user_context: None,
            process_id: Some(std::process::id()),
            thread_id: None,
        };

        self.log_security_event(event).await
    }

    /// Log system shutdown event
    pub async fn log_service_stopped(
        &self,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let event = SecurityEvent {
            event_id: EventId::ServiceStopped as u32,
            event_type: EventType::Information,
            category: EventCategory::SystemStatus,
            timestamp: SystemTime::now(),
            source: "ERDPS-ServiceManager".to_string(),
            message: "ERDPS Agent service stopped".to_string(),
            details: None,
            severity: "INFO".to_string(),
            user_context: None,
            process_id: Some(std::process::id()),
            thread_id: None,
        };

        self.log_security_event(event).await
    }
}

/// Global event logger instance
static EVENT_LOGGER: tokio::sync::RwLock<Option<WindowsEventLogger>> =
    tokio::sync::RwLock::const_new(None);

/// Initialize global event logger
pub async fn init_event_logger() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let logger = WindowsEventLogger::new("ERDPS-Agent")?;
    let mut global_logger = EVENT_LOGGER.write().await;
    *global_logger = Some(logger);
    Ok(())
}

/// Get global event logger
pub async fn get_event_logger() -> Option<WindowsEventLogger> {
    let logger = EVENT_LOGGER.read().await;
    logger.clone()
}

/// Convenience function to log threat detection
pub async fn log_threat_detection(
    threat_type: &str,
    file_path: &str,
    details: Option<serde_json::Value>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if let Some(logger) = get_event_logger().await {
        logger
            .log_threat_detection(threat_type, file_path, details)
            .await
    } else {
        warn!("Event logger not initialized");
        Ok(())
    }
}

/// Convenience function to log ransomware detection
pub async fn log_ransomware_detection(
    sample_path: &str,
    mttd_seconds: f64,
    detection_method: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if let Some(logger) = get_event_logger().await {
        logger
            .log_ransomware_detection(sample_path, mttd_seconds, detection_method)
            .await
    } else {
        warn!("Event logger not initialized");
        Ok(())
    }
}

/// Convenience function to log false positive
pub async fn log_false_positive(
    application: &str,
    operation: &str,
    file_path: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if let Some(logger) = get_event_logger().await {
        logger
            .log_false_positive(application, operation, file_path)
            .await
    } else {
        warn!("Event logger not initialized");
        Ok(())
    }
}

/// Convenience function to log performance metrics
pub async fn log_performance_metrics(
    cpu_usage: f64,
    memory_usage: u64,
    mttd_seconds: f64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if let Some(logger) = get_event_logger().await {
        logger
            .log_performance_metrics(cpu_usage, memory_usage, mttd_seconds)
            .await
    } else {
        warn!("Event logger not initialized");
        Ok(())
    }
}
