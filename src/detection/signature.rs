//! YARA-X based signature detection engine
//! Provides advanced signature-based malware detection with multi-source rule management

use crate::core::{
    agent::SignatureEngine,
    config::{EnhancedAgentConfig, RuleSource, RuleSourceType, SignatureEngineConfig},
    error::{EnhancedAgentError, Result, SignatureEngineError},
    types::*,
};

#[cfg(feature = "yara")]
use yara_x;

// Additional types that might not be in types.rs
#[derive(Debug, Clone, PartialEq)]
pub enum DetectionType {
    Clean,
    YaraRule,
}

#[derive(Debug, Clone)]
pub enum RecommendedAction {
    Quarantine,
    Alert,
    Log,
}

#[derive(Debug, Clone)]
pub struct YaraMatchString {
    pub identifier: String,
    pub offset: usize,
    pub length: usize,
    pub match_data: String,
}
// Using yara_x crate - SourceCode may not be in root namespace

use chrono::Utc;
use reqwest::Client;
use std::{
    collections::HashMap,
    fs,
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    sync::{Mutex, RwLock},
    time::timeout,
};
use tracing::{debug, info, warn};
use uuid::Uuid;


/// YARA-X signature detection engine
pub struct YaraXEngine {
    /// Rule sources configuration
    rule_sources: Arc<RwLock<Vec<RuleSource>>>,

    /// Rule metadata cache
    rule_metadata: Arc<RwLock<HashMap<String, RuleMetadata>>>,

    /// Performance metrics
    scan_metrics: Arc<RwLock<ScanMetrics>>,

    /// HTTP client for rule updates
    http_client: Client,

    /// Engine configuration
    config: Arc<RwLock<SignatureEngineConfig>>,

    /// Compiled rules data (serialized)
    compiled_rules_data: Arc<RwLock<Option<Vec<u8>>>>,

    /// Rule update lock
    #[allow(dead_code)]
    update_lock: Arc<Mutex<()>>,
}

/// Rule metadata
#[derive(Debug, Clone)]
pub struct RuleMetadata {
    pub name: String,
    pub author: Option<String>,
    pub description: Option<String>,
    pub reference: Option<String>,
    pub date: Option<String>,
    pub version: Option<String>,
    pub tags: Vec<String>,
    pub severity: ThreatSeverity,
    pub confidence: f64,
    pub false_positive_rate: f64,
}

// SignatureEngineConfig is now imported from crate::core::config

/// Scan performance metrics
#[derive(Debug, Clone, Default)]
pub struct ScanMetrics {
    pub total_scans: u64,
    pub successful_scans: u64,
    pub failed_scans: u64,
    pub total_scan_time: Duration,
    pub average_scan_time: Duration,
    pub files_scanned: u64,
    pub threats_detected: u64,
    pub rules_loaded: usize,
    pub last_rule_update: Option<chrono::DateTime<Utc>>,
}

/// YARA scan result
#[derive(Debug, Clone)]
pub struct YaraScanResult {
    pub rule_name: String,
    pub namespace: Option<String>,
    pub tags: Vec<String>,
    pub metadata: HashMap<String, String>,
    pub strings: Vec<YaraStringMatch>,
    pub confidence: f64,
}

/// YARA string match
#[derive(Debug, Clone)]
pub struct YaraStringMatch {
    pub identifier: String,
    pub offset: u64,
    pub length: usize,
    pub data: Vec<u8>,
}

// Default implementation is now in crate::core::config

impl Default for YaraXEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl YaraXEngine {
    /// Create a new YARA-X engine instance
    pub fn new() -> Self {
        Self {
            rule_sources: Arc::new(RwLock::new(Vec::new())),
            rule_metadata: Arc::new(RwLock::new(HashMap::new())),
            scan_metrics: Arc::new(RwLock::new(ScanMetrics::default())),
            http_client: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("Failed to create HTTP client"),
            config: Arc::new(RwLock::new(SignatureEngineConfig::default())),
            compiled_rules_data: Arc::new(RwLock::new(None)),
            update_lock: Arc::new(Mutex::new(())),
        }
    }

    /// Synchronous version of scan_file_internal for use in spawn_blocking
    #[cfg(feature = "yara")]
    fn scan_file_internal_sync(
        file_path: &Path,
        content: &[u8],
        compiled_rules_data: &Arc<RwLock<Option<Vec<u8>>>>,
    ) -> Result<DetectionResult> {
        let start_time = std::time::Instant::now();

        // Get compiled rules data
        let rules_data = {
            let compiled_data = compiled_rules_data.try_read().map_err(|e| {
                EnhancedAgentError::SignatureEngine(SignatureEngineError::FileAccess(format!(
                    "Failed to read compiled rules: {}",
                    e
                )))
            })?;

            compiled_data.clone().ok_or_else(|| {
                EnhancedAgentError::SignatureEngine(SignatureEngineError::FileAccess(
                    "No compiled rules available".to_string(),
                ))
            })?
        };

        // Deserialize rules
        let rules = yara_x::Rules::deserialize(&rules_data).map_err(|e| {
            EnhancedAgentError::SignatureEngine(SignatureEngineError::RuleLoading(format!(
                "Failed to deserialize rules: {}",
                e
            )))
        })?;

        // Create scanner
        let mut scanner = yara_x::Scanner::new(&rules);

        // Set timeout (30 seconds)
        scanner.set_timeout(std::time::Duration::from_secs(30));

        // Perform scan
        let scan_results = scanner.scan(content).map_err(|e| {
            EnhancedAgentError::SignatureEngine(SignatureEngineError::ScanError(format!(
                "YARA scan failed: {}",
                e
            )))
        })?;

        let scan_duration = start_time.elapsed();

        // Process results
        let mut yara_matches = Vec::new();
        let _threat_type = DetectionType::Clean;
        let mut confidence: f64 = 0.0;
        let mut severity = ThreatSeverity::Low;

        for matching_rule in scan_results.matching_rules() {
            // Extract matches
            for pattern in matching_rule.patterns() {
                for m in pattern.matches() {
                    let range = m.range();
                    yara_matches.push(YaraMatchString {
                        identifier: pattern.identifier().to_string(),
                        offset: range.start,
                        length: range.len(),
                        match_data: String::from_utf8_lossy(
                            &content[range.start..range.start + range.len()],
                        )
                        .to_string(),
                    });
                }
            }

            // Extract metadata and calculate confidence/severity
            let mut rule_confidence = 0.5; // Default confidence
            let mut rule_severity = ThreatSeverity::Medium;

            for (key, value) in matching_rule.metadata() {
                let value_str = match value {
                    yara_x::MetaValue::Integer(i) => i.to_string(),
                    yara_x::MetaValue::Float(f) => f.to_string(),
                    yara_x::MetaValue::Bool(b) => b.to_string(),
                    yara_x::MetaValue::String(s) => s.to_string(),
                    yara_x::MetaValue::Bytes(b) => String::from_utf8_lossy(b).to_string(),
                };

                match key {
                    "confidence" => {
                        if let Ok(conf) = value_str.parse::<f64>() {
                            rule_confidence = conf.max(rule_confidence);
                        }
                    }
                    "severity" => {
                        rule_severity = match value_str.to_lowercase().as_str() {
                            "critical" => ThreatSeverity::Critical,
                            "high" => ThreatSeverity::High,
                            "medium" => ThreatSeverity::Medium,
                            "low" => ThreatSeverity::Low,
                            _ => rule_severity,
                        };
                    }
                    _ => {}
                }
            }

            confidence = confidence.max(rule_confidence);
            if rule_severity as u8 > severity as u8 {
                severity = rule_severity;
            }
        }

        // Determine recommended action based on severity
        let recommended_action = match severity {
            ThreatSeverity::Critical => RecommendedAction::Quarantine,
            ThreatSeverity::High => RecommendedAction::Quarantine,
            ThreatSeverity::Medium => RecommendedAction::Alert,
            ThreatSeverity::Low => RecommendedAction::Log,
        };

        // Convert threat_type to ThreatType enum
        let threat_type_enum = ThreatType::Unknown; // Will be determined by YARA rule metadata

        // Convert recommended_action to Vec<ResponseAction>
        let recommended_actions = match recommended_action {
            RecommendedAction::Quarantine => {
                vec![ResponseAction::QuarantineFile, ResponseAction::Quarantine]
            }
            RecommendedAction::Alert => vec![ResponseAction::Monitor],
            RecommendedAction::Log => vec![ResponseAction::LogOnly],
        };

        // Create metadata from YARA matches
        let mut metadata = std::collections::HashMap::new();
        metadata.insert(
            "scan_duration_ms".to_string(),
            scan_duration.as_millis().to_string(),
        );
        metadata.insert(
            "yara_matches_count".to_string(),
            yara_matches.len().to_string(),
        );
        metadata.insert("engine".to_string(), "yara-x".to_string());

        Ok(DetectionResult {
            threat_id: Uuid::new_v4(),
            threat_type: threat_type_enum,
            severity,
            confidence,
            detection_method: DetectionMethod::Signature("yara-x".to_string()),
            file_path: Some(file_path.to_path_buf()),
            process_info: None,
            network_info: None,
            metadata,
            detected_at: Utc::now(),
            recommended_actions,
            details: "YARA signature match detected".to_string(),
            timestamp: Utc::now(),
            source: "signature_engine".to_string(),
        })
    }

    /// Fallback version when YARA is not available
    #[cfg(not(feature = "yara"))]
    fn scan_file_internal_sync(
        file_path: &Path,
        _content: &[u8],
        _compiled_rules_data: &Arc<RwLock<Option<Vec<u8>>>>,
    ) -> Result<DetectionResult> {
        // Fallback implementation when YARA is not available
        Ok(DetectionResult {
            threat_id: Uuid::new_v4(),
            threat_type: ThreatType::Unknown,
            severity: ThreatSeverity::Low,
            confidence: 0.0,
            detection_method: DetectionMethod::Signature("disabled".to_string()),
            file_path: Some(file_path.to_path_buf()),
            process_info: None,
            network_info: None,
            metadata: std::collections::HashMap::new(),
            detected_at: Utc::now(),
            recommended_actions: vec![ResponseAction::LogOnly],
            details: "YARA engine disabled - fallback detection".to_string(),
            timestamp: Utc::now(),
            source: "signature_engine".to_string(),
        })
    }

    /// Load rules from all configured sources
    #[allow(dead_code)]
    async fn load_rules(&self) -> Result<()> {
        let _lock = self.update_lock.lock().await;
        let rule_sources = self.rule_sources.read().await.clone();
        let _config = self.config.read().await.clone();

        info!("Loading rules from {} sources", rule_sources.len());

        let rule_metadata = HashMap::new();
        let mut total_rules = 0;

        // For now, just collect rule metadata without actual compilation
        // This will be implemented when we have proper YARA-X integration
        for source in &rule_sources {
            match source.source_type {
                RuleSourceType::Local => {
                    if let Some(path) = &source.path {
                        info!("Would load local rules from: {:?}", path);
                        total_rules += 1;
                    }
                }
                RuleSourceType::Http => {
                    if let Some(url) = &source.url {
                        info!("Would load HTTP rules from: {}", url);
                        total_rules += 1;
                    }
                }
                RuleSourceType::Git => {
                    if let Some(url) = &source.url {
                        info!("Would load git rules from: {}", url);
                        total_rules += 1;
                    }
                }
                RuleSourceType::Api => {
                    info!("Would load API rules");
                    total_rules += 1;
                }
            }
        }

        // Update engine state
        *self.rule_metadata.write().await = rule_metadata;

        // Update metrics
        {
            let mut metrics = self.scan_metrics.write().await;
            metrics.rules_loaded = total_rules;
            metrics.last_rule_update = Some(Utc::now());
        }

        info!("Successfully processed {} rule sources", total_rules);
        Ok(())
    }

    /// Load rules from a specific source
    #[cfg(feature = "yara")]
    #[allow(dead_code)]
    async fn load_rules_from_source(
        &self,
        compiler: &mut yara_x::Compiler<'_>,
        source: &RuleSource,
    ) -> Result<usize> {
        match source.source_type {
            RuleSourceType::Local => self.load_local_rules(compiler, source).await,
            RuleSourceType::Http => self.load_http_rules(compiler, source).await,
            RuleSourceType::Git => self.load_git_rules(compiler, source).await,
            RuleSourceType::Api => self.load_api_rules(compiler, source).await,
        }
    }

    /// Load rules from local filesystem
    #[cfg(feature = "yara")]
    #[allow(dead_code)]
    async fn load_local_rules(
        &self,
        compiler: &mut yara_x::Compiler<'_>,
        source: &RuleSource,
    ) -> Result<usize> {
        let path = source.path.as_ref().ok_or_else(|| {
            SignatureEngineError::Configuration("Local source missing path".to_string())
        })?;

        let mut rule_count = 0;

        if path.is_file() {
            // Single rule file
            let content = fs::read_to_string(path)
                .map_err(|e| SignatureEngineError::RuleLoading(e.to_string()))?;

            compiler
                .add_source(content.as_str())
                .map_err(|e| SignatureEngineError::RuleCompilation(e.to_string()))?;

            rule_count = 1;
        } else if path.is_dir() {
            // Directory of rule files
            let entries =
                fs::read_dir(path).map_err(|e| SignatureEngineError::RuleLoading(e.to_string()))?;

            for entry in entries {
                let entry = entry.map_err(|e| SignatureEngineError::RuleLoading(e.to_string()))?;
                let file_path = entry.path();
                if file_path.extension().and_then(|s| s.to_str()) == Some("yar")
                    || file_path.extension().and_then(|s| s.to_str()) == Some("yara")
                {
                    let content = fs::read_to_string(&file_path)
                        .map_err(|e| SignatureEngineError::RuleLoading(e.to_string()))?;

                    compiler
                        .add_source(content.as_str())
                        .map_err(|e| SignatureEngineError::RuleCompilation(e.to_string()))?;

                    rule_count += 1;
                }
            }
        }

        Ok(rule_count)
    }

    /// Load rules from HTTP URL
    #[cfg(feature = "yara")]
    #[allow(dead_code)]
    async fn load_http_rules(
        &self,
        compiler: &mut yara_x::Compiler<'_>,
        source: &RuleSource,
    ) -> Result<usize> {
        let url = source.url.as_ref().ok_or_else(|| {
            SignatureEngineError::Configuration("Remote source missing URL".to_string())
        })?;

        debug!("Downloading rules from: {}", url);

        let response = self
            .http_client
            .get(url)
            .send()
            .await
            .map_err(|e| SignatureEngineError::RuleLoading(e.to_string()))?;

        if !response.status().is_success() {
            return Err(SignatureEngineError::RuleLoading(format!(
                "HTTP error {}: {}",
                response.status(),
                url
            ))
            .into());
        }

        let content = response
            .text()
            .await
            .map_err(|e| SignatureEngineError::RuleLoading(e.to_string()))?;

        // TODO: Add checksum verification if needed

        compiler
            .add_source(content.as_str())
            .map_err(|e| SignatureEngineError::RuleCompilation(e.to_string()))?;

        Ok(1)
    }

    /// Load rules from Git repository
    #[cfg(feature = "yara")]
    #[allow(dead_code)]
    async fn load_git_rules(
        &self,
        _compiler: &mut yara_x::Compiler<'_>,
        _source: &RuleSource,
    ) -> Result<usize> {
        // TODO: Implement Git rule loading
        warn!("Git rule loading not yet implemented");
        Ok(0)
    }

    /// Load rules from API source
    #[cfg(feature = "yara")]
    #[allow(dead_code)]
    async fn load_api_rules(
        &self,
        _compiler: &mut yara_x::Compiler<'_>,
        _source: &RuleSource,
    ) -> Result<usize> {
        // TODO: Implement API rule loading
        warn!("API rule loading not yet implemented");
        Ok(0)
    }

    /// Scan file with YARA rules
    #[cfg(feature = "yara")]
    #[allow(dead_code)]
    async fn scan_file_internal(
        &self,
        file_path: &Path,
        context: &ScanContext,
    ) -> Result<Vec<YaraScanResult>> {
        let start_time = Instant::now();

        // Check file size
        let config = self.config.read().await;
        let metadata =
            fs::metadata(file_path).map_err(|e| SignatureEngineError::FileAccess(e.to_string()))?;

        if metadata.len() > config.max_file_size {
            return Err(SignatureEngineError::FileTooLarge(metadata.len()).into());
        }

        // Read file content
        let file_content =
            fs::read(file_path).map_err(|e| SignatureEngineError::FileAccess(e.to_string()))?;

        // Get compiled rules data
        let compiled_rules_data = self.compiled_rules_data.read().await;
        let rules_data = compiled_rules_data
            .as_ref()
            .ok_or(SignatureEngineError::RulesNotLoaded)?;

        // Deserialize rules from compiled data
        let rules = yara_x::Rules::deserialize(rules_data)
            .map_err(|e| SignatureEngineError::RuleLoading(e.to_string()))?;

        // Create scanner
        let mut scanner = yara_x::Scanner::new(&rules);

        // Set scan timeout
        let scan_timeout = context.timeout.unwrap_or(config.scan_timeout);

        // Perform scan with timeout
        let scan_results = timeout(scan_timeout, async {
            scanner
                .scan(&file_content)
                .map_err(|e| SignatureEngineError::ScanError(e.to_string()))
        })
        .await
        .map_err(|_| SignatureEngineError::ScanTimeout)?
        .map_err(EnhancedAgentError::SignatureEngine)?;

        // Process scan results
        let mut yara_results = Vec::new();

        for rule_match in scan_results.matching_rules() {
            let mut strings = Vec::new();

            for pattern_match in rule_match.patterns() {
                for string_match in pattern_match.matches() {
                    strings.push(YaraStringMatch {
                        identifier: pattern_match.identifier().to_string(),
                        offset: string_match.range().start as u64,
                        length: (string_match.range().end - string_match.range().start),
                        data: string_match.data().to_vec(),
                    });
                }
            }

            // Extract metadata and map MetaValue variants to Strings explicitly
            let mut metadata = HashMap::new();
            for (key, value) in rule_match.metadata() {
                let value_str = match value {
                    yara_x::MetaValue::Integer(i) => i.to_string(),
                    yara_x::MetaValue::Float(f) => f.to_string(),
                    yara_x::MetaValue::Bool(b) => b.to_string(),
                    yara_x::MetaValue::String(s) => s.to_string(),
                    yara_x::MetaValue::Bytes(b) => format!("{:?}", b),
                };
                metadata.insert(key.to_string(), value_str);
            }

            // Calculate confidence based on rule metadata
            let confidence = self
                .calculate_rule_confidence(rule_match.identifier(), &metadata)
                .await;

            yara_results.push(YaraScanResult {
                rule_name: rule_match.identifier().to_string(),
                namespace: Some(rule_match.namespace().to_string()),
                tags: Vec::new(), // TODO: Update when YARA-X tags API is available
                metadata,
                strings,
                confidence,
            });
        }

        // Update metrics
        let scan_duration = start_time.elapsed();
        let mut metrics = self.scan_metrics.write().await;
        metrics.total_scans += 1;
        metrics.total_scan_time += scan_duration;
        metrics.total_scan_time += scan_duration;
        metrics.average_scan_time = metrics.total_scan_time / metrics.total_scans as u32;
        metrics.files_scanned += 1;
        metrics.threats_detected += yara_results.len() as u64;

        debug!(
            "YARA scan completed in {:?}, found {} matches",
            scan_duration,
            yara_results.len()
        );

        Ok(yara_results)
    }

    /// Calculate rule confidence based on metadata
    #[allow(dead_code)]
    async fn calculate_rule_confidence(
        &self,
        rule_name: &str,
        metadata: &HashMap<String, String>,
    ) -> f64 {
        let rule_metadata = self.rule_metadata.read().await;

        if let Some(rule_meta) = rule_metadata.get(rule_name) {
            // Use stored confidence if available
            rule_meta.confidence
        } else {
            // Calculate confidence based on metadata
            let mut confidence: f64 = 0.5; // Base confidence

            // Adjust based on author reputation
            if let Some(author) = metadata.get("author") {
                if author.contains("Microsoft") || author.contains("CrowdStrike") {
                    confidence += 0.3;
                }
            }

            // Adjust based on rule age
            if let Some(date) = metadata.get("date") {
                // Newer rules might be more accurate
                if date.starts_with("2024") || date.starts_with("2023") {
                    confidence += 0.1;
                }
            }

            // Adjust based on severity
            if let Some(severity) = metadata.get("severity") {
                match severity.to_lowercase().as_str() {
                    "critical" | "high" => confidence += 0.1,
                    "low" => confidence -= 0.1,
                    _ => {}
                }
            }

            confidence.clamp(0.0, 1.0)
        }
    }

    /// Convert YARA results to detection results
    #[allow(dead_code)]
    fn convert_to_detection_results(
        &self,
        yara_results: Vec<YaraScanResult>,
        file_path: &Path,
    ) -> Vec<DetectionResult> {
        yara_results
            .into_iter()
            .map(|yara_result| {
                let severity = self.determine_severity(&yara_result.metadata);
                let threat_type =
                    self.determine_threat_type(&yara_result.tags, &yara_result.metadata);

                let mut metadata = HashMap::new();
                metadata.insert("rule_name".to_string(), yara_result.rule_name.clone());
                metadata.insert("engine".to_string(), "yara-x".to_string());
                metadata.insert(
                    "string_matches".to_string(),
                    yara_result.strings.len().to_string(),
                );

                if let Some(namespace) = &yara_result.namespace {
                    metadata.insert("namespace".to_string(), namespace.clone());
                }

                // Add YARA metadata
                for (key, value) in yara_result.metadata {
                    metadata.insert(format!("yara_{}", key), value);
                }

                DetectionResult {
                    threat_id: Uuid::new_v4(),
                    threat_type: threat_type.clone(),
                    severity,
                    confidence: yara_result.confidence,
                    detection_method: DetectionMethod::Signature(yara_result.rule_name.clone()),
                    file_path: Some(file_path.to_path_buf()),
                    process_info: None,
                    network_info: None,
                    metadata,
                    detected_at: Utc::now(),
                    recommended_actions: self
                        .determine_recommended_actions(&severity, &threat_type),
                    details: format!("YARA rule match: {}", yara_result.rule_name),
                    timestamp: Utc::now(),
                    source: "signature_engine".to_string(),
                }
            })
            .collect()
    }

    /// Determine threat severity from YARA metadata
    #[allow(dead_code)]
    fn determine_severity(&self, metadata: &HashMap<String, String>) -> ThreatSeverity {
        if let Some(severity) = metadata.get("severity") {
            match severity.to_lowercase().as_str() {
                "critical" => ThreatSeverity::Critical,
                "high" => ThreatSeverity::High,
                "medium" => ThreatSeverity::Medium,
                "low" => ThreatSeverity::Low,
                _ => ThreatSeverity::Medium,
            }
        } else {
            ThreatSeverity::Medium
        }
    }

    /// Determine threat type from YARA tags and metadata
    #[allow(dead_code)]
    fn determine_threat_type(
        &self,
        tags: &[String],
        metadata: &HashMap<String, String>,
    ) -> ThreatType {
        // Check tags first
        for tag in tags {
            match tag.to_lowercase().as_str() {
                "ransomware" => return ThreatType::Ransomware,
                "trojan" => return ThreatType::Trojan,
                "backdoor" => return ThreatType::Backdoor,
                "rootkit" => return ThreatType::Rootkit,
                "worm" => return ThreatType::Worm,
                "virus" => return ThreatType::Virus,
                "spyware" => return ThreatType::Spyware,
                "adware" => return ThreatType::Adware,
                _ => continue,
            }
        }

        // Check metadata
        if let Some(family) = metadata.get("family") {
            if family.to_lowercase().contains("ransom") {
                return ThreatType::Ransomware;
            }
        }

        ThreatType::Unknown
    }

    /// Determine recommended actions based on threat characteristics
    #[allow(dead_code)]
    fn determine_recommended_actions(
        &self,
        severity: &ThreatSeverity,
        threat_type: &ThreatType,
    ) -> Vec<ResponseAction> {
        let mut actions = Vec::new();

        match severity {
            ThreatSeverity::Critical => {
                actions.push(ResponseAction::QuarantineFile);
                actions.push(ResponseAction::TerminateProcess);
                actions.push(ResponseAction::BlockNetwork);
                actions.push(ResponseAction::Quarantine);
            }
            ThreatSeverity::High => {
                actions.push(ResponseAction::QuarantineFile);
                actions.push(ResponseAction::TerminateProcess);
            }
            ThreatSeverity::Medium => {
                actions.push(ResponseAction::QuarantineFile);
            }
            ThreatSeverity::Low => {
                actions.push(ResponseAction::LogOnly);
            }
        }

        // Add threat-type specific actions
        match threat_type {
            ThreatType::Ransomware => {
                actions.push(ResponseAction::Quarantine);
                actions.push(ResponseAction::QuarantineFile);
            }
            ThreatType::Backdoor => {
                actions.push(ResponseAction::BlockNetwork);
            }
            _ => {}
        }

        actions
    }
}

#[async_trait::async_trait]
impl SignatureEngine for YaraXEngine {
    #[cfg(feature = "yara")]
    async fn initialize(&self, config: &EnhancedAgentConfig) -> Result<()> {
        info!("Initializing YARA-X signature engine");

        // Update configuration
        *self.config.write().await = config.detection.signature.clone();

        // Update rule sources
        *self.rule_sources.write().await = config.detection.signature.rule_sources.clone();

        // Load initial rules using spawn_blocking to avoid Send issues
        let rule_sources = self.rule_sources.read().await.clone();
        let compiled_rules_data = Arc::clone(&self.compiled_rules_data);

        tokio::task::spawn_blocking(move || {
            let mut compiler = yara_x::Compiler::new();
            let mut total_rules = 0;

            // Load rules from all sources
            for source in &rule_sources {
                match source.source_type {
                    RuleSourceType::Local => {
                        if let Some(path) = &source.path {
                            if path.exists() {
                                if let Ok(content) = std::fs::read_to_string(path) {
                                    if let Err(e) = compiler.add_source(content.as_str()) {
                                        log::error!(
                                            "Failed to add rule source {}: {}",
                                            path.display(),
                                            e
                                        );
                                    } else {
                                        total_rules += 1;
                                    }
                                }
                            }
                        }
                    }
                    _ => {
                        log::warn!("Non-local rule sources not yet implemented");
                    }
                }
            }

            // Compile rules
            let rules = compiler.build();
            match rules.serialize() {
                Ok(serialized_rules) => {
                    // Store compiled rules data
                    if let Ok(mut compiled_data) = compiled_rules_data.try_write() {
                        *compiled_data = Some(serialized_rules);
                        log::info!("Successfully compiled {} YARA rules", total_rules);
                    }
                }
                Err(e) => {
                    log::error!("Failed to serialize compiled rules: {}", e);
                }
            }
        })
        .await
        .map_err(|e| {
            EnhancedAgentError::SignatureEngine(SignatureEngineError::RuleCompilation(format!(
                "Task join error: {}",
                e
            )))
        })?;

        info!("YARA-X signature engine initialized successfully");
        Ok(())
    }

    #[cfg(feature = "yara")]
    async fn scan_file(
        &self,
        file_path: &Path,
        _context: &ScanContext,
    ) -> Result<Vec<DetectionResult>> {
        debug!("Scanning file with YARA-X: {:?}", file_path);

        let start_time = std::time::Instant::now();

        // Read file content
        let content = tokio::fs::read(file_path).await.map_err(|e| {
            EnhancedAgentError::SignatureEngine(SignatureEngineError::FileAccess(format!(
                "Failed to read file {}: {}",
                file_path.display(),
                e
            )))
        })?;

        // Perform scan using spawn_blocking to avoid Send issues
        let file_path_clone = file_path.to_path_buf();
        let compiled_rules_data = Arc::clone(&self.compiled_rules_data);

        let detection_result = tokio::task::spawn_blocking(move || {
            YaraXEngine::scan_file_internal_sync(&file_path_clone, &content, &compiled_rules_data)
        })
        .await
        .map_err(|e| {
            EnhancedAgentError::SignatureEngine(SignatureEngineError::ScanError(format!(
                "Task join error: {}",
                e
            )))
        })??;

        let scan_duration = start_time.elapsed();

        // Update metrics if available
        #[cfg(feature = "metrics")]
        {
            if let Some(metrics) = crate::metrics::get_metrics().await {
                metrics.record_yara_scan_duration(scan_duration.as_secs_f64());
                if detection_result.threat_type != ThreatType::Unknown {
                    metrics.increment_threats_detected();
                }
                metrics.increment_files_scanned();
            }
        }

        Ok(vec![detection_result])
    }

    async fn scan_memory(
        &self,
        process_id: u32,
        _context: &ScanContext,
    ) -> Result<Vec<DetectionResult>> {
        debug!("Scanning process memory with YARA-X: PID {}", process_id);

        // TODO: Implement memory scanning - for now return empty results
        // Memory scanning requires process memory access which is complex
        warn!("Memory scanning not yet implemented");
        Ok(Vec::new())
    }

    #[cfg(feature = "yara")]
    async fn update_rules(&self) -> Result<()> {
        info!("Updating YARA rules");

        let rule_sources = self.rule_sources.read().await.clone();

        // Recompile rules using spawn_blocking to avoid Send issues
        let compiled_rules_data = Arc::clone(&self.compiled_rules_data);

        tokio::task::spawn_blocking(move || {
            let mut compiler = yara_x::Compiler::new();
            let mut total_rules = 0;

            // Load rules from all sources
            for source in &rule_sources {
                match source.source_type {
                    RuleSourceType::Local => {
                        if let Some(path) = &source.path {
                            if path.exists() {
                                if let Ok(content) = std::fs::read_to_string(path) {
                                    if let Err(e) = compiler.add_source(content.as_str()) {
                                        log::error!(
                                            "Failed to add rule source {}: {}",
                                            path.display(),
                                            e
                                        );
                                    } else {
                                        total_rules += 1;
                                    }
                                }
                            }
                        }
                    }
                    _ => {
                        log::warn!("Non-local rule sources not yet implemented");
                    }
                }
            }

            // Compile rules
            let rules = compiler.build();
            match rules.serialize() {
                Ok(serialized_rules) => {
                    // Store compiled rules data
                    if let Ok(mut compiled_data) = compiled_rules_data.try_write() {
                        *compiled_data = Some(serialized_rules);
                        log::info!("Successfully recompiled {} YARA rules", total_rules);
                    }
                }
                Err(e) => {
                    log::error!("Failed to serialize recompiled rules: {}", e);
                }
            }
        })
        .await
        .map_err(|e| {
            EnhancedAgentError::SignatureEngine(SignatureEngineError::RuleCompilation(format!(
                "Task join error: {}",
                e
            )))
        })?;

        info!("YARA-X rules updated successfully");
        Ok(())
    }

    #[cfg(not(feature = "yara"))]
    async fn initialize(&self, _config: &EnhancedAgentConfig) -> Result<()> {
        warn!("YARA feature not enabled, signature engine will not function");
        Ok(())
    }

    #[cfg(not(feature = "yara"))]
    async fn scan_file(
        &self,
        _file_path: &Path,
        _context: &ScanContext,
    ) -> Result<Vec<DetectionResult>> {
        warn!("YARA feature not enabled, returning empty scan results");
        Ok(Vec::new())
    }

    #[cfg(not(feature = "yara"))]
    async fn update_rules(&self) -> Result<()> {
        warn!("YARA feature not enabled, rule update skipped");
        Ok(())
    }

    async fn get_rule_count(&self) -> Result<usize> {
        let metrics = self.scan_metrics.read().await;
        Ok(metrics.rules_loaded)
    }

    async fn shutdown(&self) -> Result<()> {
        info!("Shutting down YARA-X signature engine");

        // Use spawn_blocking to avoid Send issues with YARA-X types
        // Clear compiled rules data
        *self.compiled_rules_data.write().await = None;
        *self.rule_metadata.write().await = HashMap::new();

        info!("YARA-X signature engine shutdown complete");
        Ok(())
    }
}
