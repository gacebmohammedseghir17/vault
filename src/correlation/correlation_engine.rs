//! Main correlation engine implementation
//! Orchestrates AI analysis, YARA matching, and threat correlation

use super::{CorrelationResultType, *};
use crate::ai::{AnalysisType, AnalysisInput};
use crate::detection::yara_engine::YaraEngine;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::RwLock;
use tokio::time::timeout;
use tracing::{debug, info, warn, error, instrument};

/// Cache entry for correlation results
#[derive(Debug, Clone)]
struct CacheEntry {
    /// Cached result
    result: CorrelationResult,
    /// Cache timestamp
    timestamp: SystemTime,
    /// TTL for this entry
    ttl: Duration,
}

impl CacheEntry {
    /// Check if cache entry is expired
    fn is_expired(&self) -> bool {
        SystemTime::now()
            .duration_since(self.timestamp)
            .unwrap_or_default() > self.ttl
    }
}

/// Main correlation engine implementation
pub struct CorrelationEngineImpl {
    /// Configuration
    config: Arc<RwLock<CorrelationConfig>>,
    /// AI analyzer
    ai_analyzer: Arc<dyn crate::ai::AIAnalyzer + Send + Sync>,
    /// YARA engine
    yara_engine: Arc<YaraEngine>,
    /// Rule generator
    rule_generator: Arc<super::rule_generator::RuleGenerator>,
    /// Threat scorer
    threat_scorer: Arc<super::threat_scorer::ThreatScorer>,
    /// Results cache
    cache: Arc<RwLock<HashMap<String, CacheEntry>>>,
    /// Dynamic rules storage
    dynamic_rules: Arc<RwLock<HashMap<String, DynamicRule>>>,
    /// Statistics
    stats: Arc<RwLock<CorrelationStats>>,
}

impl CorrelationEngineImpl {
    /// Create new correlation engine
    pub fn new(
        config: CorrelationConfig,
        ai_analyzer: Arc<dyn crate::ai::AIAnalyzer + Send + Sync>,
        yara_engine: Arc<YaraEngine>,
    ) -> Result<Self, CorrelationError> {
        let rule_generator = Arc::new(super::rule_generator::RuleGenerator::new(
            ai_analyzer.clone(),
            config.clone(),
        )?);
        
        let threat_scorer = Arc::new(super::threat_scorer::ThreatScorer::new(
            config.clone(),
        ));

        Ok(Self {
            config: Arc::new(RwLock::new(config)),
            ai_analyzer,
            yara_engine,
            rule_generator,
            threat_scorer,
            cache: Arc::new(RwLock::new(HashMap::new())),
            dynamic_rules: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(CorrelationStats::default())),
        })
    }

    /// Generate cache key for input
    fn generate_cache_key(&self, input: &CorrelationInput) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        input.file_path.hash(&mut hasher);
        input.metadata.hash.hash(&mut hasher);
        input.metadata.size.hash(&mut hasher);
        
        // Include behavioral indicators in hash
        for indicator in &input.behavioral_indicators {
            indicator.indicator_type.hash(&mut hasher);
            indicator.description.hash(&mut hasher);
        }
        
        // Include network indicators in hash
        for indicator in &input.network_indicators {
            indicator.indicator_type.hash(&mut hasher);
            indicator.address.hash(&mut hasher);
        }

        format!("correlation_{:x}", hasher.finish())
    }

    /// Check cache for existing result
    async fn check_cache(&self, cache_key: &str) -> Option<CorrelationResult> {
        let cache = self.cache.read().await;
        
        if let Some(entry) = cache.get(cache_key) {
            if !entry.is_expired() {
                debug!("Cache hit for key: {}", cache_key);
                
                // Update stats
                {
                    let mut stats = self.stats.write().await;
                    let total = stats.total_correlations + 1;
                    stats.cache_hit_rate = (stats.cache_hit_rate * stats.total_correlations as f32 + 1.0) / total as f32;
                }
                
                return Some(entry.result.clone());
            } else {
                debug!("Cache entry expired for key: {}", cache_key);
            }
        }
        
        None
    }

    /// Store result in cache
    async fn store_in_cache(&self, cache_key: String, result: CorrelationResult) {
        let config = self.config.read().await;
        let ttl = Duration::from_secs(config.cache_ttl_seconds);
        
        let entry = CacheEntry {
            result,
            timestamp: SystemTime::now(),
            ttl,
        };
        
        let mut cache = self.cache.write().await;
        cache.insert(cache_key, entry);
        
        // Clean up expired entries periodically
        if cache.len() > 1000 {
            cache.retain(|_, entry| !entry.is_expired());
        }
    }

    /// Perform AI analysis
    #[instrument(skip(self, input))]
    async fn perform_ai_analysis(&self, input: &CorrelationInput) -> Result<Vec<AnalysisResult>, CorrelationError> {
        let config = self.config.read().await;
        
        if !config.enable_ai_correlation {
            return Ok(Vec::new());
        }

        let mut results = Vec::new();
        let analysis_timeout = Duration::from_secs(30);

        // Prepare analysis input
        let analysis_input = if let Some(content) = &input.file_content {
            AnalysisInput::BinaryData {
                data: content.clone(),
                filename: input.file_path.clone(),
                file_type: input.metadata.file_type.clone(),
            }
        } else {
            AnalysisInput::TextData {
                content: format!("File path: {}", input.file_path),
                data_type: "file_path".to_string(),
            }
        };

        // Malware classification analysis
        let classification_request = AnalysisRequest {
            analysis_type: AnalysisType::MalwareClassification,
            input_data: analysis_input.clone(),
            model: None,
            context: self.build_analysis_context(input),
        };

        match timeout(analysis_timeout, self.ai_analyzer.analyze(classification_request)).await {
            Ok(Ok(result)) => {
                if result.confidence >= config.ai_confidence_threshold {
                    results.push(result);
                }
            }
            Ok(Err(e)) => {
                warn!("AI malware classification failed: {}", e);
                self.update_ai_failure_stats().await;
            }
            Err(_) => {
                warn!("AI malware classification timed out");
                self.update_ai_failure_stats().await;
            }
        }

        // Behavioral analysis if indicators are present
        if !input.behavioral_indicators.is_empty() {
            let behavioral_request = AnalysisRequest {
                analysis_type: AnalysisType::BehavioralAnalysis,
                input_data: AnalysisInput::TextData {
                    content: self.serialize_behavioral_indicators(&input.behavioral_indicators),
                    data_type: "behavioral_indicators".to_string(),
                },
                model: None,
                context: self.build_analysis_context(input),
            };

            match timeout(analysis_timeout, self.ai_analyzer.analyze(behavioral_request)).await {
                Ok(Ok(result)) => {
                    if result.confidence >= config.ai_confidence_threshold {
                        results.push(result);
                    }
                }
                Ok(Err(e)) => {
                    warn!("AI behavioral analysis failed: {}", e);
                    self.update_ai_failure_stats().await;
                }
                Err(_) => {
                    warn!("AI behavioral analysis timed out");
                    self.update_ai_failure_stats().await;
                }
            }
        }

        // YARA rule generation if enabled
        if config.enable_dynamic_rules {
            let yara_request = AnalysisRequest {
                analysis_type: AnalysisType::YaraRuleGeneration,
                input_data: analysis_input.clone(),
                model: None,
                context: self.build_analysis_context(input),
            };

            match timeout(analysis_timeout, self.ai_analyzer.analyze(yara_request)).await {
                Ok(Ok(result)) => {
                    if result.confidence >= config.rule_generation_threshold {
                        results.push(result);
                    }
                }
                Ok(Err(e)) => {
                    warn!("AI YARA rule generation failed: {}", e);
                    self.update_ai_failure_stats().await;
                }
                Err(_) => {
                    warn!("AI YARA rule generation timed out");
                    self.update_ai_failure_stats().await;
                }
            }
        }

        self.update_ai_success_stats().await;
        Ok(results)
    }

    /// Build analysis context from input
    fn build_analysis_context(&self, input: &CorrelationInput) -> HashMap<String, String> {
        let mut context = HashMap::new();
        
        context.insert("file_path".to_string(), input.file_path.clone());
        context.insert("file_size".to_string(), input.metadata.size.to_string());
        context.insert("file_type".to_string(), input.metadata.file_type.clone());
        context.insert("file_hash".to_string(), input.metadata.hash.clone());
        
        if let Some(entropy) = input.metadata.entropy {
            context.insert("entropy".to_string(), entropy.to_string());
        }
        
        if let Some(binary_meta) = &input.metadata.binary_metadata {
            context.insert("architecture".to_string(), binary_meta.architecture.clone());
            context.insert("imports_count".to_string(), binary_meta.imports.len().to_string());
            context.insert("exports_count".to_string(), binary_meta.exports.len().to_string());
        }
        
        context.insert("behavioral_indicators_count".to_string(), input.behavioral_indicators.len().to_string());
        context.insert("network_indicators_count".to_string(), input.network_indicators.len().to_string());
        
        context
    }

    /// Serialize behavioral indicators for AI analysis
    fn serialize_behavioral_indicators(&self, indicators: &[BehavioralIndicator]) -> String {
        let mut serialized = String::new();
        
        for indicator in indicators {
            serialized.push_str(&format!(
                "Type: {:?}, Description: {}, Severity: {:?}, Confidence: {:.2}\n",
                indicator.indicator_type,
                indicator.description,
                indicator.severity,
                indicator.confidence
            ));
        }
        
        serialized
    }

    /// Perform YARA analysis
    #[instrument(skip(self, input))]
    async fn perform_yara_analysis(&self, input: &CorrelationInput) -> Result<Vec<YaraMatch>, CorrelationError> {
        let config = self.config.read().await;
        let mut matches = Vec::new();

        // Analyze with static YARA rules
        if let Some(_content) = &input.file_content {
            match self.yara_engine.read_and_scan_file(std::path::Path::new(&input.file_path)).await {
                Ok(yara_matches) => {
                    for yara_match in yara_matches {
                        let score = self.calculate_yara_match_score(&yara_match);
                        if score >= config.yara_score_threshold {
                            matches.push(YaraMatch {
                                rule_name: yara_match.rule.clone(),
                                namespace: Some("default".to_string()),
                                score,
                                matched_strings: yara_match.strings.into_iter().map(|s| MatchedString {
                                    identifier: s.identifier,
                                    content: format!("offset:{}", s.offset),
                                    offset: s.offset,
                                    length: s.length as u32,
                                }).collect(),
                                metadata: yara_match.meta,
                                timestamp: SystemTime::now(),
                            });
                        }
                    }
                    self.update_yara_success_stats().await;
                }
                Err(e) => {
                    warn!("YARA analysis failed: {}", e);
                    self.update_yara_failure_stats().await;
                    return Err(CorrelationError::YaraEngineError(e.to_string()));
                }
            }
        }

        // Analyze with dynamic rules
        let dynamic_rules = self.dynamic_rules.read().await;
        for (rule_name, rule) in dynamic_rules.iter() {
            if let Some(content) = &input.file_content {
                // Apply dynamic rule (simplified - in practice would compile and run YARA rule)
                if self.apply_dynamic_rule(rule, content).await {
                    matches.push(YaraMatch {
                        rule_name: rule_name.clone(),
                        namespace: Some("dynamic".to_string()),
                        score: rule.confidence,
                        matched_strings: Vec::new(), // Would be populated by actual YARA execution
                        metadata: HashMap::new(),
                        timestamp: SystemTime::now(),
                    });
                    
                    // Update rule usage stats
                    self.update_rule_usage_stats(rule_name).await;
                }
            }
        }

        Ok(matches)
    }

    /// Calculate YARA match score
    fn calculate_yara_match_score(&self, yara_match: &crate::detection::yara_engine::YaraMatch) -> f32 {
        // Base score from number of matched strings
        let base_score = (yara_match.strings.len() as f32 * 0.2).min(1.0);
        
        // Bonus for metadata indicating high confidence
        let metadata_bonus = if yara_match.meta.contains_key("confidence") {
            yara_match.meta.get("confidence")
                .and_then(|v| v.parse::<f32>().ok())
                .unwrap_or(0.0)
        } else {
            0.5 // Default confidence
        };
        
        (base_score + metadata_bonus * 0.5).min(1.0)
    }

    /// Apply dynamic rule (simplified implementation)
    async fn apply_dynamic_rule(&self, rule: &DynamicRule, content: &[u8]) -> bool {
        // This is a simplified implementation
        // In practice, this would compile the YARA rule and execute it
        
        // For now, just check if any target threats match basic patterns
        for threat in &rule.target_threats {
            if threat.contains("ransomware") && self.has_ransomware_indicators(content) {
                return true;
            }
            if threat.contains("trojan") && self.has_trojan_indicators(content) {
                return true;
            }
        }
        
        false
    }

    /// Check for ransomware indicators (simplified)
    fn has_ransomware_indicators(&self, content: &[u8]) -> bool {
        let content_str = String::from_utf8_lossy(content).to_lowercase();
        content_str.contains("encrypt") || 
        content_str.contains("ransom") || 
        content_str.contains("bitcoin") ||
        content_str.contains("decrypt")
    }

    /// Check for trojan indicators (simplified)
    fn has_trojan_indicators(&self, content: &[u8]) -> bool {
        let content_str = String::from_utf8_lossy(content).to_lowercase();
        content_str.contains("backdoor") || 
        content_str.contains("keylog") || 
        content_str.contains("steal") ||
        content_str.contains("remote")
    }

    /// Generate correlation findings
    async fn generate_findings(
        &self,
        input: &CorrelationInput,
        ai_results: &[AnalysisResult],
        yara_matches: &[YaraMatch],
    ) -> Vec<CorrelationFinding> {
        let mut findings = Vec::new();

        // Malware family identification from AI results
        for ai_result in ai_results {
            if ai_result.analysis_type == AnalysisType::MalwareClassification {
                if let Some(classification) = &ai_result.threat_classification {
                    findings.push(CorrelationFinding {
                        finding_type: FindingType::MalwareFamilyIdentification,
                        description: format!("AI identified malware family: {:?}", classification),
                        confidence: ai_result.confidence,
                        severity: Severity::Medium, // Default severity for AI findings
                        evidence: vec![Evidence {
                            evidence_type: EvidenceType::CodePattern,
                            description: "AI analysis result".to_string(),
                            data: format!("AI Analysis: {}", ai_result.analysis_type.to_string()),
                            confidence: ai_result.confidence,
                            source: "AI Analysis".to_string(),
                        }],
                        related_indicators: Vec::new(),
                        mitigations: vec!["Review AI analysis findings".to_string()],
                    });
                }
            }
        }

        // YARA rule correlations
        for yara_match in yara_matches {
            findings.push(CorrelationFinding {
                finding_type: FindingType::AttackTechniqueDetection,
                description: format!("YARA rule match: {}", yara_match.rule_name),
                confidence: yara_match.score,
                severity: if yara_match.score > 0.8 { Severity::High } else { Severity::Medium },
                evidence: yara_match.matched_strings.iter().map(|s| Evidence {
                    evidence_type: EvidenceType::StringPattern,
                    description: format!("Matched string: {}", s.identifier),
                    data: s.content.clone(),
                    confidence: yara_match.score,
                    source: format!("YARA Rule: {}", yara_match.rule_name),
                }).collect(),
                related_indicators: Vec::new(),
                mitigations: vec!["Quarantine file".to_string(), "Analyze in sandbox".to_string()],
            });
        }

        // Behavioral pattern correlations
        if !input.behavioral_indicators.is_empty() {
            let behavioral_risk = utils::calculate_behavioral_risk(&input.behavioral_indicators);
            if behavioral_risk > 0.6 {
                findings.push(CorrelationFinding {
                    finding_type: FindingType::BehavioralPatternCorrelation,
                    description: "Suspicious behavioral patterns detected".to_string(),
                    confidence: behavioral_risk,
                    severity: if behavioral_risk > 0.8 { Severity::High } else { Severity::Medium },
                    evidence: input.behavioral_indicators.iter().map(|indicator| Evidence {
                        evidence_type: EvidenceType::BehavioralIndicator,
                        description: indicator.description.clone(),
                        data: format!("{:?}", indicator.indicator_type),
                        confidence: indicator.confidence,
                        source: "Behavioral Analysis".to_string(),
                    }).collect(),
                    related_indicators: Vec::new(),
                    mitigations: vec!["Monitor process behavior".to_string(), "Block suspicious activities".to_string()],
                });
            }
        }

        // Network pattern correlations
        if !input.network_indicators.is_empty() {
            let network_risk = utils::calculate_network_risk(&input.network_indicators);
            if network_risk > 0.6 {
                findings.push(CorrelationFinding {
                    finding_type: FindingType::NetworkPatternCorrelation,
                    description: "Suspicious network patterns detected".to_string(),
                    confidence: network_risk,
                    severity: if network_risk > 0.8 { Severity::High } else { Severity::Medium },
                    evidence: input.network_indicators.iter().map(|indicator| Evidence {
                        evidence_type: EvidenceType::NetworkIndicator,
                        description: format!("{} to {}", indicator.protocol, indicator.address),
                        data: format!("{:?}", indicator.indicator_type),
                        confidence: 0.8, // Default confidence for network indicators
                        source: "Network Analysis".to_string(),
                    }).collect(),
                    related_indicators: Vec::new(),
                    mitigations: vec!["Block network connections".to_string(), "Monitor traffic".to_string()],
                });
            }
        }

        findings
    }

    /// Generate behavioral summary
    fn generate_behavioral_summary(&self, indicators: &[BehavioralIndicator]) -> BehavioralSummary {
        let mut behavior_counts = HashMap::new();
        let mut high_severity_count = 0;
        let mut timeline = Vec::new();

        for indicator in indicators {
            *behavior_counts.entry(indicator.indicator_type.clone()).or_insert(0) += 1;
            
            if indicator.severity == Severity::High || indicator.severity == Severity::Critical {
                high_severity_count += 1;
            }
            
            timeline.push(BehaviorTimelineEntry {
                timestamp: indicator.timestamp,
                behavior_type: indicator.indicator_type.clone(),
                description: indicator.description.clone(),
                severity: indicator.severity.clone(),
            });
        }

        // Sort timeline by timestamp
        timeline.sort_by_key(|entry| entry.timestamp);

        // Convert counts to sorted vector
        let mut common_behaviors: Vec<_> = behavior_counts.into_iter().collect();
        common_behaviors.sort_by(|a, b| b.1.cmp(&a.1));

        BehavioralSummary {
            total_indicators: indicators.len(),
            high_severity_count,
            common_behaviors,
            risk_score: utils::calculate_behavioral_risk(indicators),
            behavior_timeline: timeline,
        }
    }

    /// Generate network summary
    fn generate_network_summary(&self, indicators: &[NetworkIndicator]) -> NetworkSummary {
        let mut unique_destinations = std::collections::HashSet::new();
        let mut total_bytes = 0;
        let mut suspicious_connections = 0;
        let mut geographic_distribution = HashMap::new();
        let mut protocol_distribution = HashMap::new();

        for indicator in indicators {
            unique_destinations.insert(indicator.address.clone());
            total_bytes += indicator.bytes_transferred;
            
            if matches!(indicator.indicator_type, 
                NetworkType::CommandAndControl | 
                NetworkType::DataExfiltration | 
                NetworkType::MalwareDownload |
                NetworkType::BotnetCommunication
            ) {
                suspicious_connections += 1;
            }
            
            if let Some(geo) = &indicator.geolocation {
                *geographic_distribution.entry(geo.country.clone()).or_insert(0) += 1;
            }
            
            *protocol_distribution.entry(indicator.protocol.clone()).or_insert(0) += 1;
        }

        NetworkSummary {
            total_indicators: indicators.len(),
            unique_destinations: unique_destinations.len(),
            total_bytes,
            suspicious_connections,
            geographic_distribution,
            protocol_distribution,
            risk_score: utils::calculate_network_risk(indicators),
        }
    }

    /// Update AI success statistics
    async fn update_ai_success_stats(&self) {
        let mut stats = self.stats.write().await;
        let total = stats.total_correlations + 1;
        stats.ai_success_rate = (stats.ai_success_rate * stats.total_correlations as f32 + 1.0) / total as f32;
    }

    /// Update AI failure statistics
    async fn update_ai_failure_stats(&self) {
        let mut stats = self.stats.write().await;
        let total = stats.total_correlations + 1;
        stats.ai_success_rate = (stats.ai_success_rate * stats.total_correlations as f32) / total as f32;
    }

    /// Update YARA success statistics
    async fn update_yara_success_stats(&self) {
        let mut stats = self.stats.write().await;
        let total = stats.total_correlations + 1;
        stats.yara_success_rate = (stats.yara_success_rate * stats.total_correlations as f32 + 1.0) / total as f32;
    }

    /// Update YARA failure statistics
    async fn update_yara_failure_stats(&self) {
        let mut stats = self.stats.write().await;
        let total = stats.total_correlations + 1;
        stats.yara_success_rate = (stats.yara_success_rate * stats.total_correlations as f32) / total as f32;
    }

    /// Update rule usage statistics
    async fn update_rule_usage_stats(&self, rule_name: &str) {
        let mut dynamic_rules = self.dynamic_rules.write().await;
        if let Some(rule) = dynamic_rules.get_mut(rule_name) {
            rule.usage_stats.total_applications += 1;
            rule.usage_stats.last_used = Some(SystemTime::now());
        }
    }
}

#[async_trait::async_trait]
impl CorrelationEngine for CorrelationEngineImpl {
    #[instrument(skip(self, input))]
    async fn correlate(&self, input: CorrelationInput) -> CorrelationResultType {
        let start_time = Instant::now();
        
        // Update total correlations count
        {
            let mut stats = self.stats.write().await;
            stats.total_correlations += 1;
        }

        // Generate cache key
        let cache_key = self.generate_cache_key(&input);
        
        // Check cache first
        if let Some(cached_result) = self.check_cache(&cache_key).await {
            debug!("Returning cached correlation result for {}", input.file_path);
            return Ok(cached_result);
        }

        info!("Starting correlation analysis for {}", input.file_path);

        // Perform AI analysis
        let ai_results = match self.perform_ai_analysis(&input).await {
            Ok(results) => results,
            Err(e) => {
                error!("AI analysis failed: {}", e);
                Vec::new() // Continue with YARA analysis even if AI fails
            }
        };

        // Perform YARA analysis
        let yara_matches = match self.perform_yara_analysis(&input).await {
            Ok(matches) => matches,
            Err(e) => {
                error!("YARA analysis failed: {}", e);
                Vec::new() // Continue even if YARA fails
            }
        };

        // Generate dynamic rules if enabled and AI analysis succeeded
        let mut dynamic_rules = Vec::new();
        let config = self.config.read().await;
        if config.enable_dynamic_rules && !ai_results.is_empty() {
            for ai_result in &ai_results {
                if ai_result.analysis_type == AnalysisType::YaraRuleGeneration && 
                   ai_result.confidence >= config.rule_generation_threshold {
                    
                    match self.rule_generator.generate_rule_from_ai_result(ai_result).await {
                        Ok(rule) => {
                            // Store the dynamic rule
                            {
                                let mut rules_storage = self.dynamic_rules.write().await;
                                rules_storage.insert(rule.name.clone(), rule.clone());
                                
                                // Limit number of dynamic rules
                                if rules_storage.len() > config.max_dynamic_rules {
                                    // Remove oldest rules (simplified - could be more sophisticated)
                                    let oldest_rule = rules_storage.iter()
                                        .min_by_key(|(_, rule)| rule.created_at)
                                        .map(|(name, _)| name.clone());
                                    
                                    if let Some(oldest) = oldest_rule {
                                        rules_storage.remove(&oldest);
                                    }
                                }
                            }
                            
                            dynamic_rules.push(rule);
                            
                            // Update stats
                            {
                                let mut stats = self.stats.write().await;
                                stats.dynamic_rules_generated += 1;
                            }
                        }
                        Err(e) => {
                            warn!("Failed to generate dynamic rule: {}", e);
                        }
                    }
                }
            }
        }

        // Generate correlation findings
        let findings = self.generate_findings(&input, &ai_results, &yara_matches).await;

        // Calculate overall threat score
        // Create a temporary correlation result for scoring
        let temp_result = CorrelationResult {
            threat_score: 0.0,
            classification: ThreatClassification {
                family: "Unknown".to_string(),
                variant: None,
                malware_type: vec![],
                attack_techniques: vec![],
                confidence: 0.0,
            },
            severity: Severity::Info,
            ai_results: ai_results.clone(),
            yara_matches: yara_matches.clone(),
            dynamic_rules: dynamic_rules.clone(),
            findings: findings.clone(),
            behavioral_summary: self.generate_behavioral_summary(&input.behavioral_indicators),
            network_summary: self.generate_network_summary(&input.network_indicators),
            recommended_actions: vec![],
            timestamp: SystemTime::now(),
            processing_time_ms: 0,
        };

        let threat_score = {
            let scorer = self.threat_scorer.clone();
            Arc::try_unwrap(scorer).unwrap_or_else(|arc| (*arc).clone()).calculate_threat_score(
                &temp_result,
                Some(&input.metadata.hash),
            ).await?
        };

        // Determine overall classification and severity based on threat score
        let (classification, severity) = if threat_score.total_score > 80.0 {
            ("Malware".to_string(), "Critical".to_string())
        } else if threat_score.total_score > 60.0 {
            ("Suspicious".to_string(), "High".to_string())
        } else if threat_score.total_score > 40.0 {
            ("Potentially Unwanted".to_string(), "Medium".to_string())
        } else if threat_score.total_score > 20.0 {
            ("Low Risk".to_string(), "Low".to_string())
        } else {
            ("Benign".to_string(), "Info".to_string())
        };

        // Generate summaries
        let behavioral_summary = self.generate_behavioral_summary(&input.behavioral_indicators);
        let network_summary = self.generate_network_summary(&input.network_indicators);

        // Generate recommended actions based on classification and severity
        let recommended_actions = match classification.as_str() {
            "Malware" => vec![
                "Quarantine file immediately".to_string(),
                "Run full system scan".to_string(),
                "Check for lateral movement".to_string(),
                "Review network connections".to_string(),
            ],
            "Suspicious" => vec![
                "Monitor file behavior".to_string(),
                "Analyze in sandbox environment".to_string(),
                "Check file reputation".to_string(),
            ],
            "Potentially Unwanted" => vec![
                "Review file purpose".to_string(),
                "Check installation source".to_string(),
                "Consider removal if unwanted".to_string(),
            ],
            _ => vec![
                "Continue monitoring".to_string(),
                "No immediate action required".to_string(),
            ],
        };

        let processing_time = start_time.elapsed();
        
        let result = CorrelationResult {
            threat_score: threat_score.total_score,
            classification: ThreatClassification {
                family: classification.clone(),
                variant: None,
                malware_type: vec![classification.clone()],
                attack_techniques: vec![],
                confidence: threat_score.confidence,
            },
            severity: match severity.as_str() {
                "Critical" => Severity::Critical,
                "High" => Severity::High,
                "Medium" => Severity::Medium,
                "Low" => Severity::Low,
                _ => Severity::Info,
            },
            ai_results,
            yara_matches,
            dynamic_rules,
            findings,
            behavioral_summary,
            network_summary,
            recommended_actions,
            timestamp: SystemTime::now(),
            processing_time_ms: processing_time.as_millis() as u64,
        };

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.successful_correlations += 1;
            let total_time = stats.avg_processing_time_ms * (stats.successful_correlations - 1) as f64 + processing_time.as_millis() as f64;
            stats.avg_processing_time_ms = total_time / stats.successful_correlations as f64;
        }

        // Store in cache
        self.store_in_cache(cache_key, result.clone()).await;

        info!("Correlation analysis completed for {} in {}ms with threat score {:.2}",
              input.file_path, processing_time.as_millis(), threat_score.total_score);

        Ok(result)
    }

    async fn get_stats(&self) -> CorrelationStats {
        let stats = self.stats.read().await;
        stats.clone()
    }

    async fn update_config(&self, config: CorrelationConfig) -> Result<(), CorrelationError> {
        let mut current_config = self.config.write().await;
        *current_config = config;
        info!("Correlation engine configuration updated");
        Ok(())
    }

    async fn clear_cache(&self) -> Result<(), CorrelationError> {
        let mut cache = self.cache.write().await;
        cache.clear();
        info!("Correlation cache cleared");
        Ok(())
    }

    async fn get_dynamic_rules(&self) -> Result<Vec<DynamicRule>, CorrelationError> {
        let rules = self.dynamic_rules.read().await;
        Ok(rules.values().cloned().collect())
    }

    async fn add_custom_rule(&self, rule: DynamicRule) -> Result<(), CorrelationError> {
        let mut rules = self.dynamic_rules.write().await;
        rules.insert(rule.name.clone(), rule);
        info!("Custom dynamic rule added");
        Ok(())
    }

    async fn remove_dynamic_rule(&self, rule_name: &str) -> Result<(), CorrelationError> {
        let mut rules = self.dynamic_rules.write().await;
        if rules.remove(rule_name).is_some() {
            info!("Dynamic rule '{}' removed", rule_name);
            Ok(())
        } else {
            Err(CorrelationError::ConfigurationError(format!("Rule '{}' not found", rule_name)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::{AIAnalyzer, AnalysisRequest, AnalysisResult, AnalysisType, ThreatClassification, Severity};
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio;

    // Mock implementations for testing
    struct MockAIAnalyzer;
    
    #[async_trait::async_trait]
    impl AIAnalyzer for MockAIAnalyzer {
        async fn analyze(&self, _request: AnalysisRequest) -> Result<AnalysisResult, crate::ai::AIError> {
            Ok(AnalysisResult {
                analysis_type: AnalysisType::MalwareClassification,
                confidence: 0.8,
                findings: vec![
                    crate::ai::Finding {
                        category: "test".to_string(),
                        severity: Severity::High,
                        description: "Mock analysis result".to_string(),
                        confidence: 0.8,
                        evidence: vec!["test evidence".to_string()],
                        recommendations: vec!["Test recommendation".to_string()],
                    }
                ],
                yara_rules: Some(vec!["test_rule".to_string()]),
                threat_classification: Some(ThreatClassification {
                    family: "TestMalware".to_string(),
                    variant: Some("TestVariant".to_string()),
                    malware_type: vec!["Test".to_string()],
                    attack_techniques: vec!["T1000".to_string()],
                    confidence: 0.8,
                }),
                processing_time_ms: 100,
                model_used: "test-model".to_string(),
                metadata: HashMap::new(),
            })
        }

        async fn is_available(&self) -> bool {
            true
        }

        async fn get_available_models(&self) -> Result<Vec<String>, crate::ai::AIError> {
            Ok(vec!["test-model".to_string()])
        }

        fn get_statistics(&self) -> crate::ai::AnalysisStats {
            crate::ai::AnalysisStats::default()
        }
    }

    #[tokio::test]
    async fn test_correlation_engine_creation() {
        let config = CorrelationConfig::default();
        let ai_analyzer = Arc::new(MockAIAnalyzer);
        let agent_config = Arc::new(crate::config::agent_config::AgentConfig::default());
        let yara_engine = Arc::new(YaraEngine::new(agent_config));
        
        let engine = CorrelationEngineImpl::new(config, ai_analyzer, yara_engine);
        assert!(engine.is_ok());
    }

    #[tokio::test]
    async fn test_cache_key_generation() {
        let config = CorrelationConfig::default();
        let ai_analyzer = Arc::new(MockAIAnalyzer);
        let agent_config = Arc::new(crate::config::agent_config::AgentConfig::default());
        let yara_engine = Arc::new(YaraEngine::new(agent_config));
        let engine = CorrelationEngineImpl::new(config, ai_analyzer, yara_engine).unwrap();
        
        let input = CorrelationInput {
            file_path: "test.exe".to_string(),
            file_content: None,
            metadata: FileMetadata {
                size: 1024,
                hash: "abc123".to_string(),
                file_type: "exe".to_string(),
                created_at: None,
                modified_at: None,
                entropy: None,
                binary_metadata: None,
            },
            behavioral_indicators: Vec::new(),
            network_indicators: Vec::new(),
            process_info: None,
        };
        
        let key1 = engine.generate_cache_key(&input);
        let key2 = engine.generate_cache_key(&input);
        assert_eq!(key1, key2);
    }
}
