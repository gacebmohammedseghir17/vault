//! Log Analyzer Component
//!
//! This module provides comprehensive log analysis capabilities for the YARA agent,
//! including pattern detection, anomaly detection, and log insights.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use tokio::time::interval;
use tracing::{debug, error, info, warn};
use regex::Regex;

use crate::error::{AgentError, AgentResult};

/// Log level enumeration
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Fatal,
}

impl From<&str> for LogLevel {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "trace" => LogLevel::Trace,
            "debug" => LogLevel::Debug,
            "info" => LogLevel::Info,
            "warn" | "warning" => LogLevel::Warn,
            "error" => LogLevel::Error,
            "fatal" | "critical" => LogLevel::Fatal,
            _ => LogLevel::Info,
        }
    }
}

/// Log entry structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: u64,
    pub level: LogLevel,
    pub message: String,
    pub source: String,
    pub thread_id: Option<String>,
    pub process_id: Option<u32>,
    pub tags: HashMap<String, String>,
    pub raw_line: String,
}

impl LogEntry {
    /// Create a new log entry
    pub fn new(
        level: LogLevel,
        message: String,
        source: String,
    ) -> Self {
        Self {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            level,
            message,
            source,
            thread_id: None,
            process_id: None,
            tags: HashMap::new(),
            raw_line: String::new(),
        }
    }
    
    /// Add a tag to the log entry
    pub fn with_tag(mut self, key: String, value: String) -> Self {
        self.tags.insert(key, value);
        self
    }
    
    /// Set the raw log line
    pub fn with_raw_line(mut self, raw_line: String) -> Self {
        self.raw_line = raw_line;
        self
    }
}

/// Log pattern for matching log entries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogPattern {
    pub id: String,
    pub name: String,
    pub description: String,
    pub regex: String,
    pub level_filter: Option<LogLevel>,
    pub source_filter: Option<String>,
    pub severity: PatternSeverity,
    pub action: PatternAction,
    pub enabled: bool,
    pub match_count: u64,
    pub last_match: Option<u64>,
    pub created_at: u64,
}

/// Pattern severity levels
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PatternSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Actions to take when a pattern matches
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PatternAction {
    Log,
    Alert,
    Block,
    Quarantine,
    Notify(String), // Notification channel
    Custom(String), // Custom action command
}

/// Anomaly detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyDetection {
    pub id: String,
    pub anomaly_type: AnomalyType,
    pub description: String,
    pub severity: PatternSeverity,
    pub confidence: f64, // 0.0 to 1.0
    pub detected_at: u64,
    pub affected_entries: Vec<String>, // Log entry IDs
    pub metrics: HashMap<String, f64>,
    pub recommendations: Vec<String>,
}

/// Types of anomalies that can be detected
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnomalyType {
    VolumeSpike,        // Sudden increase in log volume
    ErrorRateIncrease,  // Increase in error rate
    UnusualPattern,     // New or unusual log patterns
    PerformanceDrop,    // Performance degradation indicators
    SecurityThreat,     // Security-related anomalies
    SystemFailure,      // System failure indicators
    Custom(String),     // Custom anomaly type
}

impl std::fmt::Display for AnomalyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnomalyType::VolumeSpike => write!(f, "Volume Spike"),
            AnomalyType::ErrorRateIncrease => write!(f, "Error Rate Increase"),
            AnomalyType::UnusualPattern => write!(f, "Unusual Pattern"),
            AnomalyType::PerformanceDrop => write!(f, "Performance Drop"),
            AnomalyType::SecurityThreat => write!(f, "Security Threat"),
            AnomalyType::SystemFailure => write!(f, "System Failure"),
            AnomalyType::Custom(s) => write!(f, "Custom: {}", s),
        }
    }
}

/// Log analysis statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogAnalysisStats {
    pub total_entries: u64,
    pub entries_by_level: HashMap<LogLevel, u64>,
    pub entries_by_source: HashMap<String, u64>,
    pub patterns_matched: u64,
    pub anomalies_detected: u64,
    pub analysis_duration_ms: u64,
    pub last_analysis: u64,
    pub error_rate: f64,
    pub warning_rate: f64,
    pub throughput_entries_per_second: f64,
}

/// Log analyzer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogAnalyzerConfig {
    pub enabled: bool,
    pub analysis_interval_seconds: u64,
    pub max_entries: usize,
    pub retention_hours: u64,
    pub anomaly_detection_enabled: bool,
    pub anomaly_threshold: f64,
    pub pattern_matching_enabled: bool,
    pub real_time_analysis: bool,
    pub export_enabled: bool,
    pub export_path: String,
    pub log_sources: Vec<String>,
    pub excluded_patterns: Vec<String>,
}

impl Default for LogAnalyzerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            analysis_interval_seconds: 60,
            max_entries: 10000,
            retention_hours: 24,
            anomaly_detection_enabled: true,
            anomaly_threshold: 0.7,
            pattern_matching_enabled: true,
            real_time_analysis: true,
            export_enabled: false,
            export_path: "./logs/analysis".to_string(),
            log_sources: Vec::new(),
            excluded_patterns: vec![
                r"^\s*$".to_string(),
                r"DEBUG.*routine".to_string(),
            ],
        }
    }
}

/// Log analyzer implementation
#[derive(Debug)]
pub struct LogAnalyzer {
    config: Arc<RwLock<LogAnalyzerConfig>>,
    entries: Arc<RwLock<VecDeque<LogEntry>>>,
    patterns: Arc<RwLock<HashMap<String, LogPattern>>>,
    compiled_patterns: Arc<RwLock<HashMap<String, Regex>>>,
    anomalies: Arc<RwLock<Vec<AnomalyDetection>>>,
    stats: Arc<RwLock<LogAnalysisStats>>,
    running: Arc<RwLock<bool>>,
    start_time: Instant,
}

impl LogAnalyzer {
    /// Create a new log analyzer
    pub fn new(config: LogAnalyzerConfig) -> AgentResult<Self> {
        Ok(Self {
            config: Arc::new(RwLock::new(config)),
            entries: Arc::new(RwLock::new(VecDeque::new())),
            patterns: Arc::new(RwLock::new(HashMap::new())),
            compiled_patterns: Arc::new(RwLock::new(HashMap::new())),
            anomalies: Arc::new(RwLock::new(Vec::new())),
            stats: Arc::new(RwLock::new(LogAnalysisStats {
                total_entries: 0,
                entries_by_level: HashMap::new(),
                entries_by_source: HashMap::new(),
                patterns_matched: 0,
                anomalies_detected: 0,
                analysis_duration_ms: 0,
                last_analysis: 0,
                error_rate: 0.0,
                warning_rate: 0.0,
                throughput_entries_per_second: 0.0,
            })),
            running: Arc::new(RwLock::new(false)),
            start_time: Instant::now(),
        })
    }
    
    /// Start the log analyzer
    pub async fn start(&self) -> AgentResult<()> {
        info!("Starting log analyzer");
        
        {
            let mut running = self.running.write().map_err(|e| {
                AgentError::Service { message: format!("Failed to acquire running lock: {}", e), service: "log_analyzer".to_string(), context: None }
            })?;
            
            if *running {
                return Err(AgentError::Service { message: "Log analyzer is already running".to_string(), service: "log_analyzer".to_string(), context: None });
            }
            
            *running = true;
        }
        
        // Initialize default patterns
        self.initialize_default_patterns().await?;
        
        // Start analysis loop
        self.start_analysis_loop().await?;
        
        info!("Log analyzer started successfully");
        Ok(())
    }
    
    /// Stop the log analyzer
    pub async fn stop(&self) -> AgentResult<()> {
        info!("Stopping log analyzer");
        
        {
            let mut running = self.running.write().map_err(|e| {
                AgentError::Service { message: format!("Failed to acquire running lock: {}", e), service: "log_analyzer".to_string(), context: None }
            })?;
            
            if !*running {
                return Ok(());
            }
            
            *running = false;
        }
        
        info!("Log analyzer stopped successfully");
        Ok(())
    }
    
    /// Add a log entry for analysis
    pub async fn add_log_entry(&self, entry: LogEntry) -> AgentResult<()> {
        let config = {
            let config = self.config.read().map_err(|e| {
                AgentError::Service { message: format!("Failed to read log analyzer config: {}", e), service: "log_analyzer".to_string(), context: None }
            })?;
            config.clone()
        };
        
        if !config.enabled {
            return Ok(());
        }
        
        // Check if entry should be excluded
        if self.should_exclude_entry(&entry)? {
            return Ok(());
        }
        
        // Add entry to collection
        {
            let mut entries = self.entries.write().map_err(|e| {
                AgentError::Service { message: format!("Failed to write log entries: {}", e), service: "log_analyzer".to_string(), context: None }
            })?;
            
            entries.push_back(entry.clone());
            
            // Maintain max entries limit
            while entries.len() > config.max_entries {
                entries.pop_front();
            }
        }
        
        // Update statistics
        self.update_entry_stats(&entry)?;
        
        // Real-time analysis if enabled
        if config.real_time_analysis {
            self.analyze_entry(&entry).await?;
        }
        
        Ok(())
    }
    
    /// Add a log pattern
    pub fn add_pattern(&self, pattern: LogPattern) -> AgentResult<()> {
        // Compile regex
        let regex = Regex::new(&pattern.regex).map_err(|e| {
            AgentError::Service { message: format!("Invalid regex pattern '{}': {}", pattern.regex, e), service: "log_analyzer".to_string(), context: None }
        })?;
        
        let pattern_id = pattern.id.clone();
        
        // Store pattern
        {
            let mut patterns = self.patterns.write().map_err(|e| {
                AgentError::Service { message: format!("Failed to write log patterns: {}", e), service: "log_analyzer".to_string() , context: None }
            })?;
            
            patterns.insert(pattern_id.clone(), pattern);
        }
        
        // Store compiled regex
        {
            let mut compiled_patterns = self.compiled_patterns.write().map_err(|e| {
                AgentError::Service { message: format!("Failed to write compiled patterns: {}", e), service: "log_analyzer".to_string() , context: None }
            })?;
            
            compiled_patterns.insert(pattern_id.clone(), regex);
        }
        
        debug!("Added log pattern: {}", pattern_id);
        Ok(())
    }
    
    /// Remove a log pattern
    pub fn remove_pattern(&self, pattern_id: &str) -> AgentResult<()> {
        {
            let mut patterns = self.patterns.write().map_err(|e| {
                AgentError::Service { message: format!("Failed to write log patterns: {}", e), service: "log_analyzer".to_string() , context: None }
            })?;
            
            patterns.remove(pattern_id);
        }
        
        {
            let mut compiled_patterns = self.compiled_patterns.write().map_err(|e| {
                AgentError::Service { message: format!("Failed to write compiled patterns: {}", e), service: "log_analyzer".to_string() , context: None }
            })?;
            
            compiled_patterns.remove(pattern_id);
        }
        
        debug!("Removed log pattern: {}", pattern_id);
        Ok(())
    }
    
    /// Get all log patterns
    pub fn get_patterns(&self) -> AgentResult<HashMap<String, LogPattern>> {
        let patterns = self.patterns.read().map_err(|e| {
            AgentError::Service { message: format!("Failed to read log patterns: {}", e), service: "log_analyzer".to_string() , context: None }
        })?;
        
        Ok(patterns.clone())
    }
    
    /// Get recent log entries
    pub fn get_recent_entries(&self, limit: usize) -> AgentResult<Vec<LogEntry>> {
        let entries = self.entries.read().map_err(|e| {
            AgentError::Service { message: format!("Failed to read log entries: {}", e), service: "log_analyzer".to_string() , context: None }
        })?;
        
        Ok(entries.iter().rev().take(limit).cloned().collect())
    }
    
    /// Get log entries by level
    pub fn get_entries_by_level(&self, level: LogLevel, limit: usize) -> AgentResult<Vec<LogEntry>> {
        let entries = self.entries.read().map_err(|e| {
            AgentError::Service { message: format!("Failed to read log entries: {}", e), service: "log_analyzer".to_string() , context: None }
        })?;
        
        Ok(entries
            .iter()
            .filter(|entry| entry.level == level)
            .rev()
            .take(limit)
            .cloned()
            .collect())
    }
    
    /// Get detected anomalies
    pub fn get_anomalies(&self) -> AgentResult<Vec<AnomalyDetection>> {
        let anomalies = self.anomalies.read().map_err(|e| {
            AgentError::Service { message: format!("Failed to read anomalies: {}", e), service: "log_analyzer".to_string() , context: None }
        })?;
        
        Ok(anomalies.clone())
    }
    
    /// Get analysis statistics
    pub fn get_stats(&self) -> AgentResult<LogAnalysisStats> {
        let stats = self.stats.read().map_err(|e| {
            AgentError::Service { message: format!("Failed to read log analysis stats: {}", e), service: "log_analyzer".to_string() , context: None }
        })?;
        
        Ok(stats.clone())
    }
    
    /// Clear all log entries
    pub fn clear_entries(&self) -> AgentResult<()> {
        let mut entries = self.entries.write().map_err(|e| {
            AgentError::Service { message: format!("Failed to write log entries: {}", e), service: "log_analyzer".to_string() , context: None }
        })?;
        
        entries.clear();
        
        info!("All log entries cleared");
        Ok(())
    }
    
    /// Clear detected anomalies
    pub fn clear_anomalies(&self) -> AgentResult<()> {
        let mut anomalies = self.anomalies.write().map_err(|e| {
            AgentError::Service { message: format!("Failed to write anomalies: {}", e), service: "log_analyzer".to_string() , context: None }
        })?;
        
        anomalies.clear();
        
        info!("All anomalies cleared");
        Ok(())
    }
    
    /// Reset analysis statistics
    pub fn reset_stats(&self) -> AgentResult<()> {
        let mut stats = self.stats.write().map_err(|e| {
            AgentError::Service { message: format!("Failed to write log analysis stats: {}", e), service: "log_analyzer".to_string() , context: None }
        })?;
        
        *stats = LogAnalysisStats {
            total_entries: 0,
            entries_by_level: HashMap::new(),
            entries_by_source: HashMap::new(),
            patterns_matched: 0,
            anomalies_detected: 0,
            analysis_duration_ms: 0,
            last_analysis: 0,
            error_rate: 0.0,
            warning_rate: 0.0,
            throughput_entries_per_second: 0.0,
        };
        
        info!("Log analysis statistics reset");
        Ok(())
    }
    
    /// Check if log analyzer is running
    pub fn is_running(&self) -> AgentResult<bool> {
        let running = self.running.read().map_err(|e| {
            AgentError::Service { message: format!("Failed to read running status: {}", e), service: "log_analyzer".to_string() , context: None }
        })?;
        
        Ok(*running)
    }
    
    /// Update log analyzer configuration
    pub fn update_config(&self, new_config: LogAnalyzerConfig) -> AgentResult<()> {
        let mut config = self.config.write().map_err(|e| {
            AgentError::Service { message: format!("Failed to write log analyzer config: {}", e), service: "log_analyzer".to_string() , context: None }
        })?;
        
        *config = new_config;
        info!("Log analyzer configuration updated");
        Ok(())
    }
    
    /// Search log entries by pattern
    pub fn search_entries(&self, pattern: &str, limit: usize) -> AgentResult<Vec<LogEntry>> {
        let regex = Regex::new(pattern).map_err(|e| {
            AgentError::Service { message: format!("Invalid search pattern '{}': {}", pattern, e), service: "log_analyzer".to_string() , context: None }
        })?;
        
        let entries = self.entries.read().map_err(|e| {
            AgentError::Service { message: format!("Failed to read log entries: {}", e), service: "log_analyzer".to_string() , context: None }
        })?;
        
        Ok(entries
            .iter()
            .filter(|entry| {
                regex.is_match(&entry.message) || (!entry.raw_line.is_empty() && regex.is_match(&entry.raw_line))
            })
            .rev()
            .take(limit)
            .cloned()
            .collect())
    }
    
    /// Initialize default log patterns
    async fn initialize_default_patterns(&self) -> AgentResult<()> {
        let default_patterns = vec![
            LogPattern {
                id: "error_pattern".to_string(),
                name: "Error Pattern".to_string(),
                description: "Detects error messages".to_string(),
                regex: r"(?i)error|exception|failed|failure".to_string(),
                level_filter: Some(LogLevel::Error),
                source_filter: None,
                severity: PatternSeverity::High,
                action: PatternAction::Alert,
                enabled: true,
                match_count: 0,
                last_match: None,
                created_at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            },
            LogPattern {
                id: "security_threat".to_string(),
                name: "Security Threat".to_string(),
                description: "Detects potential security threats".to_string(),
                regex: r"(?i)malware|virus|threat|attack|breach|unauthorized".to_string(),
                level_filter: None,
                source_filter: Some("yara".to_string()),
                severity: PatternSeverity::Critical,
                action: PatternAction::Alert,
                enabled: true,
                match_count: 0,
                last_match: None,
                created_at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            },
            LogPattern {
                id: "performance_issue".to_string(),
                name: "Performance Issue".to_string(),
                description: "Detects performance-related issues".to_string(),
                regex: r"(?i)timeout|slow|performance|memory.*leak|high.*cpu".to_string(),
                level_filter: Some(LogLevel::Warn),
                source_filter: None,
                severity: PatternSeverity::Medium,
                action: PatternAction::Log,
                enabled: true,
                match_count: 0,
                last_match: None,
                created_at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            },
        ];
        
        for pattern in default_patterns {
            self.add_pattern(pattern)?;
        }
        
        debug!("Default log patterns initialized");
        Ok(())
    }
    
    /// Start analysis loop
    async fn start_analysis_loop(&self) -> AgentResult<()> {
        let config = Arc::clone(&self.config);
        let entries = Arc::clone(&self.entries);
        let _patterns = Arc::clone(&self.patterns);
        let _compiled_patterns = Arc::clone(&self.compiled_patterns);
        let stats = Arc::clone(&self.stats);
        let running = Arc::clone(&self.running);
        
        tokio::spawn(async move {
            let config_data = {
                let config = config.read().unwrap();
                config.clone()
            };
            
            let mut interval = interval(Duration::from_secs(config_data.analysis_interval_seconds));
            
            loop {
                interval.tick().await;
                
                // Check if still running
                let is_running = {
                    match running.read() {
                        Ok(running_guard) => *running_guard,
                        Err(e) => {
                            error!("Failed to read running status: {}", e);
                            false
                        }
                    }
                };
                
                if !is_running {
                    break;
                }
                
                // Perform analysis
                let start_time = Instant::now();
                
                // Pattern matching analysis
                if config_data.pattern_matching_enabled {
                    // Analyze patterns across all entries
                    let entries_data = {
                        match entries.read() {
                            Ok(entries_guard) => entries_guard.clone(),
                            Err(e) => {
                                error!("Failed to read log entries: {}", e);
                                continue;
                            }
                        }
                    };
                    
                    // Process entries (simplified pattern matching)
                    for _entry in entries_data.iter() {
                        // Pattern matching logic would go here
                        // For now, just continue to avoid compilation errors
                    }
                }
                
                // Update analysis stats
                let duration = start_time.elapsed().as_millis() as u64;
                {
                    match stats.write() {
                        Ok(mut stats_guard) => {
                             stats_guard.analysis_duration_ms = duration;
                             stats_guard.last_analysis = std::time::SystemTime::now()
                                 .duration_since(std::time::UNIX_EPOCH)
                                 .unwrap_or_default()
                                 .as_secs();
                         }
                        Err(e) => {
                            error!("Failed to update analysis stats: {}", e);
                        }
                    }
                }
                
                debug!("Log analysis completed in {}ms", duration);
            }
            
            debug!("Log analysis loop stopped");
        });
        
        Ok(())
    }
    
    /// Perform comprehensive log analysis
    async fn perform_analysis(&self) -> AgentResult<()> {
        let config = {
            let config = self.config.read().map_err(|e| {
                AgentError::Service { message: format!("Failed to read log analyzer config: {}", e), service: "log_analyzer".to_string() , context: None }
            })?;
            config.clone()
        };
        
        // Pattern matching analysis
        if config.pattern_matching_enabled {
            self.analyze_patterns().await?;
        }
        
        // Anomaly detection
        if config.anomaly_detection_enabled {
            self.detect_anomalies().await?;
        }
        
        // Cleanup old entries
        self.cleanup_old_entries().await?;
        
        Ok(())
    }
    
    /// Analyze a single log entry
    async fn analyze_entry(&self, entry: &LogEntry) -> AgentResult<()> {
        let config = {
            let config = self.config.read().map_err(|e| {
                AgentError::Service { message: format!("Failed to read log analyzer config: {}", e), service: "log_analyzer".to_string() , context: None }
            })?;
            config.clone()
        };
        
        if config.pattern_matching_enabled {
            self.match_patterns_for_entry(entry).await?;
        }
        
        Ok(())
    }
    
    /// Analyze patterns across all entries
    async fn analyze_patterns(&self) -> AgentResult<()> {
        let entries = {
            let entries = self.entries.read().map_err(|e| {
                AgentError::Service { message: format!("Failed to read log entries: {}", e), service: "log_analyzer".to_string() , context: None }
            })?;
            entries.clone()
        };
        
        for entry in entries.iter() {
            self.match_patterns_for_entry(entry).await?;
        }
        
        Ok(())
    }
    
    /// Match patterns for a specific entry
    async fn match_patterns_for_entry(&self, entry: &LogEntry) -> AgentResult<()> {
        let patterns = {
            let patterns = self.patterns.read().map_err(|e| {
                AgentError::Service { message: format!("Failed to read log patterns: {}", e), service: "log_analyzer".to_string() , context: None }
            })?;
            patterns.clone()
        };
        
        let compiled_patterns = {
            let compiled_patterns = self.compiled_patterns.read().map_err(|e| {
                AgentError::Service { message: format!("Failed to read compiled patterns: {}", e), service: "log_analyzer".to_string() , context: None }
            })?;
            compiled_patterns.clone()
        };
        
        for (pattern_id, pattern) in patterns.iter() {
            if !pattern.enabled {
                continue;
            }
            
            // Check level filter
            if let Some(ref level_filter) = pattern.level_filter {
                if entry.level != *level_filter {
                    continue;
                }
            }
            
            // Check source filter
            if let Some(ref source_filter) = pattern.source_filter {
                if entry.source != *source_filter {
                    continue;
                }
            }
            
            // Check regex match
            if let Some(regex) = compiled_patterns.get(pattern_id) {
                if regex.is_match(&entry.message) || regex.is_match(&entry.raw_line) {
                    self.handle_pattern_match(pattern_id, pattern, entry).await?;
                }
            }
        }
        
        Ok(())
    }
    
    /// Handle a pattern match
    async fn handle_pattern_match(
        &self,
        pattern_id: &str,
        pattern: &LogPattern,
        entry: &LogEntry,
    ) -> AgentResult<()> {
        // Update pattern match count
        {
            let mut patterns = self.patterns.write().map_err(|e| {
                AgentError::Service { message: format!("Failed to write log patterns: {}", e), service: "log_analyzer".to_string() , context: None }
            })?;
            
            if let Some(pattern_mut) = patterns.get_mut(pattern_id) {
                pattern_mut.match_count += 1;
                pattern_mut.last_match = Some(entry.timestamp);
            }
        }
        
        // Update statistics
        {
            let mut stats = self.stats.write().map_err(|e| {
                AgentError::Service { message: format!("Failed to write log analysis stats: {}", e), service: "log_analyzer".to_string() , context: None }
            })?;
            
            stats.patterns_matched += 1;
        }
        
        // Execute pattern action
        match &pattern.action {
            PatternAction::Log => {
                info!("Pattern '{}' matched: {}", pattern.name, entry.message);
            }
            PatternAction::Alert => {
                warn!("ALERT - Pattern '{}' matched: {}", pattern.name, entry.message);
                // TODO: Send alert to monitoring system
            }
            PatternAction::Block => {
                error!("BLOCK - Pattern '{}' matched: {}", pattern.name, entry.message);
                // TODO: Implement blocking action
            }
            PatternAction::Quarantine => {
                error!("QUARANTINE - Pattern '{}' matched: {}", pattern.name, entry.message);
                // TODO: Implement quarantine action
            }
            PatternAction::Notify(channel) => {
                info!("NOTIFY[{}] - Pattern '{}' matched: {}", channel, pattern.name, entry.message);
                // TODO: Send notification to specified channel
            }
            PatternAction::Custom(command) => {
                info!("CUSTOM[{}] - Pattern '{}' matched: {}", command, pattern.name, entry.message);
                // TODO: Execute custom command
            }
        }
        
        debug!("Pattern '{}' matched for entry: {}", pattern.name, entry.message);
        Ok(())
    }
    
    /// Detect anomalies in log data
    async fn detect_anomalies(&self) -> AgentResult<()> {
        let config = {
            let config = self.config.read().map_err(|e| {
                AgentError::Service { message: format!("Failed to read log analyzer config: {}", e), service: "log_analyzer".to_string() , context: None }
            })?;
            config.clone()
        };
        
        // Volume spike detection
        self.detect_volume_spikes(&config).await?;
        
        // Error rate increase detection
        self.detect_error_rate_increase(&config).await?;
        
        // Unusual pattern detection
        self.detect_unusual_patterns(&config).await?;
        
        Ok(())
    }
    
    /// Detect volume spikes
    async fn detect_volume_spikes(&self, config: &LogAnalyzerConfig) -> AgentResult<()> {
        let entries = {
            let entries = self.entries.read().map_err(|e| {
                AgentError::Service { message: format!("Failed to read log entries: {}", e), service: "log_analyzer".to_string() , context: None }
            })?;
            entries.clone()
        };
        
        if entries.len() < 100 {
            return Ok(()); // Not enough data
        }
        
        // Calculate recent volume vs historical average
        let recent_count = entries.iter().rev().take(50).count();
        let historical_count = entries.iter().take(entries.len() - 50).count();
        
        if historical_count == 0 {
            return Ok(());
        }
        
        let recent_rate = recent_count as f64;
        let historical_rate = historical_count as f64 / (entries.len() - 50) as f64 * 50.0;
        
        let spike_ratio = recent_rate / historical_rate;
        
        if spike_ratio > 2.0 && spike_ratio > config.anomaly_threshold {
            let anomaly = AnomalyDetection {
                id: format!("volume_spike_{}", SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()),
                anomaly_type: AnomalyType::VolumeSpike,
                description: format!(
                    "Log volume spike detected: {}x increase (recent: {}, historical avg: {:.1})",
                    spike_ratio, recent_count, historical_rate
                ),
                severity: if spike_ratio > 5.0 {
                    PatternSeverity::Critical
                } else if spike_ratio > 3.0 {
                    PatternSeverity::High
                } else {
                    PatternSeverity::Medium
                },
                confidence: (spike_ratio - 1.0).min(1.0),
                detected_at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                affected_entries: entries.iter().rev().take(recent_count)
                    .map(|e| format!("{}-{}", e.timestamp, e.source))
                    .collect(),
                metrics: {
                    let mut metrics = HashMap::new();
                    metrics.insert("spike_ratio".to_string(), spike_ratio);
                    metrics.insert("recent_count".to_string(), recent_count as f64);
                    metrics.insert("historical_rate".to_string(), historical_rate);
                    metrics
                },
                recommendations: vec![
                    "Check system resources and performance".to_string(),
                    "Review recent configuration changes".to_string(),
                    "Monitor for error patterns".to_string(),
                ],
            };
            
            self.add_anomaly(anomaly).await?;
        }
        
        Ok(())
    }
    
    /// Detect error rate increases
    async fn detect_error_rate_increase(&self, config: &LogAnalyzerConfig) -> AgentResult<()> {
        let entries = {
            let entries = self.entries.read().map_err(|e| {
                AgentError::Service { message: format!("Failed to read log entries: {}", e), service: "log_analyzer".to_string() , context: None }
            })?;
            entries.clone()
        };
        
        if entries.len() < 50 {
            return Ok(()); // Not enough data
        }
        
        // Calculate recent error rate vs historical average
        let recent_entries: Vec<_> = entries.iter().rev().take(25).collect();
        let historical_entries: Vec<_> = entries.iter().take(entries.len() - 25).collect();
        
        let recent_errors = recent_entries.iter()
            .filter(|e| matches!(e.level, LogLevel::Error | LogLevel::Fatal))
            .count();
        
        let historical_errors = historical_entries.iter()
            .filter(|e| matches!(e.level, LogLevel::Error | LogLevel::Fatal))
            .count();
        
        let recent_error_rate = recent_errors as f64 / recent_entries.len() as f64;
        let historical_error_rate = if historical_entries.is_empty() {
            0.0
        } else {
            historical_errors as f64 / historical_entries.len() as f64
        };
        
        if recent_error_rate > historical_error_rate * 2.0 && 
           recent_error_rate > config.anomaly_threshold * 0.1 {
            let anomaly = AnomalyDetection {
                id: format!("error_rate_increase_{}", SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()),
                anomaly_type: AnomalyType::ErrorRateIncrease,
                description: format!(
                    "Error rate increase detected: {:.2}% (was {:.2}%)",
                    recent_error_rate * 100.0, historical_error_rate * 100.0
                ),
                severity: if recent_error_rate > 0.5 {
                    PatternSeverity::Critical
                } else if recent_error_rate > 0.2 {
                    PatternSeverity::High
                } else {
                    PatternSeverity::Medium
                },
                confidence: (recent_error_rate / (historical_error_rate + 0.01)).min(1.0),
                detected_at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                affected_entries: recent_entries.iter()
                    .filter(|e| matches!(e.level, LogLevel::Error | LogLevel::Fatal))
                    .map(|e| format!("{}-{}", e.timestamp, e.source))
                    .collect(),
                metrics: {
                    let mut metrics = HashMap::new();
                    metrics.insert("recent_error_rate".to_string(), recent_error_rate);
                    metrics.insert("historical_error_rate".to_string(), historical_error_rate);
                    metrics.insert("recent_errors".to_string(), recent_errors as f64);
                    metrics.insert("historical_errors".to_string(), historical_errors as f64);
                    metrics
                },
                recommendations: vec![
                    "Review recent error messages for patterns".to_string(),
                    "Check system logs for underlying issues".to_string(),
                    "Verify service health and dependencies".to_string(),
                ],
            };
            
            self.add_anomaly(anomaly).await?;
        }
        
        Ok(())
    }
    
    /// Detect unusual patterns
    async fn detect_unusual_patterns(&self, _config: &LogAnalyzerConfig) -> AgentResult<()> {
        // TODO: Implement machine learning-based unusual pattern detection
        // This would involve analyzing message patterns, frequency distributions,
        // and identifying outliers or new patterns not seen before
        
        Ok(())
    }
    
    /// Add an anomaly detection result
    async fn add_anomaly(&self, anomaly: AnomalyDetection) -> AgentResult<()> {
        {
            let mut anomalies = self.anomalies.write().map_err(|e| {
                AgentError::Service { message: format!("Failed to write anomalies: {}", e), service: "log_analyzer".to_string() , context: None }
            })?;
            
            anomalies.push(anomaly.clone());
            
            // Keep only recent anomalies (last 100)
            if anomalies.len() > 100 {
                anomalies.remove(0);
            }
        }
        
        // Update statistics
        {
            let mut stats = self.stats.write().map_err(|e| {
                AgentError::Service { message: format!("Failed to write log analysis stats: {}", e), service: "log_analyzer".to_string() , context: None }
            })?;
            
            stats.anomalies_detected += 1;
        }
        
        warn!("Anomaly detected: {} - {}", anomaly.anomaly_type, anomaly.description);
        Ok(())
    }
    
    /// Check if an entry should be excluded
    fn should_exclude_entry(&self, entry: &LogEntry) -> AgentResult<bool> {
        let config = {
            let config = self.config.read().map_err(|e| {
                AgentError::Service { message: format!("Failed to read log analyzer config: {}", e), service: "log_analyzer".to_string() , context: None }
            })?;
            config.clone()
        };
        
        // Check excluded patterns
        for pattern_str in &config.excluded_patterns {
            if let Ok(regex) = Regex::new(pattern_str) {
                if regex.is_match(&entry.message) || (!entry.raw_line.is_empty() && regex.is_match(&entry.raw_line)) {
                    return Ok(true);
                }
            }
        }
        
        // Check if source is in allowed list
        if !config.log_sources.is_empty() && !config.log_sources.contains(&entry.source) {
            return Ok(true);
        }
        
        Ok(false)
    }
    
    /// Update entry statistics
    fn update_entry_stats(&self, entry: &LogEntry) -> AgentResult<()> {
        let mut stats = self.stats.write().map_err(|e| {
            AgentError::Service { message: format!("Failed to write log analysis stats: {}", e), service: "log_analyzer".to_string() , context: None }
        })?;
        
        stats.total_entries += 1;
        
        // Update level counts
        *stats.entries_by_level.entry(entry.level.clone()).or_insert(0) += 1;
        
        // Update source counts
        *stats.entries_by_source.entry(entry.source.clone()).or_insert(0) += 1;
        
        // Calculate rates
        let total = stats.total_entries as f64;
        let errors = *stats.entries_by_level.get(&LogLevel::Error).unwrap_or(&0)
            + *stats.entries_by_level.get(&LogLevel::Fatal).unwrap_or(&0);
        let warnings = *stats.entries_by_level.get(&LogLevel::Warn).unwrap_or(&0);
        
        stats.error_rate = errors as f64 / total;
        stats.warning_rate = warnings as f64 / total;
        
        // Calculate throughput
        let uptime_seconds = self.start_time.elapsed().as_secs() as f64;
        if uptime_seconds > 0.0 {
            stats.throughput_entries_per_second = total / uptime_seconds;
        }
        
        Ok(())
    }
    
    /// Update analysis statistics
    fn update_analysis_stats(&self, duration_ms: u64) -> AgentResult<()> {
        let mut stats = self.stats.write().map_err(|e| {
            AgentError::Service { message: format!("Failed to write log analysis stats: {}", e), service: "log_analyzer".to_string() , context: None }
        })?;
        
        stats.analysis_duration_ms = duration_ms;
        stats.last_analysis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        Ok(())
    }
    
    /// Cleanup old entries based on retention policy
    async fn cleanup_old_entries(&self) -> AgentResult<()> {
        let config = {
            let config = self.config.read().map_err(|e| {
                AgentError::Service { message: format!("Failed to read log analyzer config: {}", e), service: "log_analyzer".to_string() , context: None }
            })?;
            config.clone()
        };
        
        let retention_seconds = config.retention_hours * 3600;
        let cutoff_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .saturating_sub(retention_seconds);
        
        let mut entries = self.entries.write().map_err(|e| {
            AgentError::Service { message: format!("Failed to write log entries: {}", e), service: "log_analyzer".to_string() , context: None }
        })?;
        
        let original_len = entries.len();
        entries.retain(|entry| entry.timestamp >= cutoff_time);
        let removed = original_len - entries.len();
        
        if removed > 0 {
            debug!("Cleaned up {} old log entries", removed);
        }
        
        Ok(())
    }
}

#[cfg(all(test, feature = "metrics"))]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_log_analyzer_creation() {
        let config = LogAnalyzerConfig::default();
        let analyzer = LogAnalyzer::new(config);
        assert!(analyzer.is_ok());
    }
    
    #[tokio::test]
    async fn test_log_entry_addition() {
        let config = LogAnalyzerConfig::default();
        let analyzer = LogAnalyzer::new(config).unwrap();
        
        let entry = LogEntry::new(
            LogLevel::Info,
            "Test message".to_string(),
            "test".to_string(),
        );
        
        let result = analyzer.add_log_entry(entry).await;
        assert!(result.is_ok());
        
        let entries = analyzer.get_recent_entries(10).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].message, "Test message");
    }
    
    #[tokio::test]
    async fn test_pattern_management() {
        let config = LogAnalyzerConfig::default();
        let analyzer = LogAnalyzer::new(config).unwrap();
        
        let pattern = LogPattern {
            id: "test_pattern".to_string(),
            name: "Test Pattern".to_string(),
            description: "Test pattern description".to_string(),
            regex: r"test.*message".to_string(),
            level_filter: None,
            source_filter: None,
            severity: PatternSeverity::Low,
            action: PatternAction::Log,
            enabled: true,
            match_count: 0,
            last_match: None,
            created_at: 0,
        };
        
        let result = analyzer.add_pattern(pattern);
        assert!(result.is_ok());
        
        let patterns = analyzer.get_patterns().unwrap();
        assert!(patterns.contains_key("test_pattern"));
        
        let result = analyzer.remove_pattern("test_pattern");
        assert!(result.is_ok());
        
        let patterns = analyzer.get_patterns().unwrap();
        assert!(!patterns.contains_key("test_pattern"));
    }
    
    #[test]
    fn test_log_level_conversion() {
        assert_eq!(LogLevel::from("info"), LogLevel::Info);
        assert_eq!(LogLevel::from("ERROR"), LogLevel::Error);
        assert_eq!(LogLevel::from("warn"), LogLevel::Warn);
        assert_eq!(LogLevel::from("unknown"), LogLevel::Info);
    }
    
    #[test]
    fn test_metric_point_operations() {
        let entry = LogEntry::new(
            LogLevel::Error,
            "Test error message".to_string(),
            "test_source".to_string(),
        );
        
        assert_eq!(entry.level, LogLevel::Error);
        assert_eq!(entry.message, "Test error message");
        assert_eq!(entry.source, "test_source");
        
        let entry_with_tag = entry.with_tag("key".to_string(), "value".to_string());
        assert_eq!(entry_with_tag.tags.get("key"), Some(&"value".to_string()));
    }
}
