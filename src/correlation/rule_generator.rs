//! Dynamic YARA rule generation using AI analysis
//! Converts AI analysis results into executable YARA rules

use super::*;
use crate::ai::{AnalysisResult, AnalysisType};
use regex::Regex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;
use tracing::{debug, info, warn};

/// Rule generation configuration
#[derive(Debug, Clone)]
pub struct RuleGeneratorConfig {
    /// Minimum confidence for rule generation
    pub min_confidence: f32,
    /// Maximum rules per analysis
    pub max_rules_per_analysis: usize,
    /// Rule naming prefix
    pub rule_prefix: String,
    /// Enable string extraction
    pub enable_string_extraction: bool,
    /// Maximum string length for extraction
    pub max_string_length: usize,
    /// Minimum string length for extraction
    pub min_string_length: usize,
    /// Enable behavioral rule generation
    pub enable_behavioral_rules: bool,
    /// Enable metadata enrichment
    pub enable_metadata_enrichment: bool,
}

impl Default for RuleGeneratorConfig {
    fn default() -> Self {
        Self {
            min_confidence: 0.7,
            max_rules_per_analysis: 5,
            rule_prefix: "ai_generated".to_string(),
            enable_string_extraction: true,
            max_string_length: 256,
            min_string_length: 4,
            enable_behavioral_rules: true,
            enable_metadata_enrichment: true,
        }
    }
}

/// String pattern for YARA rule
#[derive(Debug, Clone)]
pub struct StringPattern {
    /// Pattern identifier
    pub identifier: String,
    /// Pattern content
    pub content: String,
    /// Pattern type (text, hex, regex)
    pub pattern_type: StringPatternType,
    /// Pattern modifiers
    pub modifiers: Vec<String>,
    /// Confidence in pattern
    pub confidence: f32,
}

/// Types of string patterns
#[derive(Debug, Clone, PartialEq)]
pub enum StringPatternType {
    /// Plain text string
    Text,
    /// Hexadecimal pattern
    Hex,
    /// Regular expression
    Regex,
    /// Wide string (Unicode)
    Wide,
}

/// Condition for YARA rule
#[derive(Debug, Clone)]
pub struct RuleCondition {
    /// Condition expression
    pub expression: String,
    /// Condition type
    pub condition_type: ConditionType,
    /// Confidence in condition
    pub confidence: f32,
}

/// Types of rule conditions
#[derive(Debug, Clone, PartialEq)]
pub enum ConditionType {
    /// String match condition
    StringMatch,
    /// File size condition
    FileSize,
    /// Entropy condition
    Entropy,
    /// Import condition
    Import,
    /// Section condition
    Section,
    /// Behavioral condition
    Behavioral,
    /// Composite condition
    Composite,
}

/// Rule template for different malware types
#[derive(Debug, Clone)]
pub struct RuleTemplate {
    /// Template name
    pub name: String,
    /// Template description
    pub description: String,
    /// Default strings
    pub default_strings: Vec<StringPattern>,
    /// Default conditions
    pub default_conditions: Vec<RuleCondition>,
    /// Applicable threat types
    pub threat_types: Vec<String>,
    /// Template priority
    pub priority: u32,
}

/// Dynamic YARA rule generator
pub struct RuleGenerator {
    /// AI analyzer for additional context
    ai_analyzer: Arc<dyn crate::ai::AIAnalyzer + Send + Sync>,
    /// Configuration
    config: RuleGeneratorConfig,
    /// Rule templates
    templates: HashMap<String, RuleTemplate>,
    /// String extraction regex patterns
    string_patterns: Vec<Regex>,
    /// Generated rule counter
    rule_counter: std::sync::atomic::AtomicU64,
}

impl RuleGenerator {
    /// Create new rule generator
    pub fn new(
        ai_analyzer: Arc<dyn crate::ai::AIAnalyzer + Send + Sync>,
        correlation_config: CorrelationConfig,
    ) -> Result<Self, CorrelationError> {
        let config = RuleGeneratorConfig {
            min_confidence: correlation_config.rule_generation_threshold,
            ..Default::default()
        };

        let mut generator = Self {
            ai_analyzer,
            config,
            templates: HashMap::new(),
            string_patterns: Vec::new(),
            rule_counter: std::sync::atomic::AtomicU64::new(0),
        };

        generator.initialize_templates()?;
        generator.initialize_string_patterns()?;

        Ok(generator)
    }

    /// Initialize rule templates
    fn initialize_templates(&mut self) -> Result<(), CorrelationError> {
        // Ransomware template
        self.templates.insert("ransomware".to_string(), RuleTemplate {
            name: "ransomware".to_string(),
            description: "Generic ransomware detection template".to_string(),
            default_strings: vec![
                StringPattern {
                    identifier: "encrypt_str".to_string(),
                    content: "encrypt".to_string(),
                    pattern_type: StringPatternType::Text,
                    modifiers: vec!["nocase".to_string()],
                    confidence: 0.6,
                },
                StringPattern {
                    identifier: "ransom_str".to_string(),
                    content: "ransom".to_string(),
                    pattern_type: StringPatternType::Text,
                    modifiers: vec!["nocase".to_string()],
                    confidence: 0.8,
                },
            ],
            default_conditions: vec![
                RuleCondition {
                    expression: "any of them".to_string(),
                    condition_type: ConditionType::StringMatch,
                    confidence: 0.7,
                },
            ],
            threat_types: vec!["ransomware".to_string(), "crypto".to_string()],
            priority: 1,
        });

        // Trojan template
        self.templates.insert("trojan".to_string(), RuleTemplate {
            name: "trojan".to_string(),
            description: "Generic trojan detection template".to_string(),
            default_strings: vec![
                StringPattern {
                    identifier: "backdoor_str".to_string(),
                    content: "backdoor".to_string(),
                    pattern_type: StringPatternType::Text,
                    modifiers: vec!["nocase".to_string()],
                    confidence: 0.7,
                },
                StringPattern {
                    identifier: "keylog_str".to_string(),
                    content: "keylog".to_string(),
                    pattern_type: StringPatternType::Text,
                    modifiers: vec!["nocase".to_string()],
                    confidence: 0.8,
                },
            ],
            default_conditions: vec![
                RuleCondition {
                    expression: "any of them".to_string(),
                    condition_type: ConditionType::StringMatch,
                    confidence: 0.7,
                },
            ],
            threat_types: vec!["trojan".to_string(), "backdoor".to_string()],
            priority: 2,
        });

        // Spyware template
        self.templates.insert("spyware".to_string(), RuleTemplate {
            name: "spyware".to_string(),
            description: "Generic spyware detection template".to_string(),
            default_strings: vec![
                StringPattern {
                    identifier: "steal_str".to_string(),
                    content: "steal".to_string(),
                    pattern_type: StringPatternType::Text,
                    modifiers: vec!["nocase".to_string()],
                    confidence: 0.6,
                },
                StringPattern {
                    identifier: "monitor_str".to_string(),
                    content: "monitor".to_string(),
                    pattern_type: StringPatternType::Text,
                    modifiers: vec!["nocase".to_string()],
                    confidence: 0.5,
                },
            ],
            default_conditions: vec![
                RuleCondition {
                    expression: "any of them".to_string(),
                    condition_type: ConditionType::StringMatch,
                    confidence: 0.6,
                },
            ],
            threat_types: vec!["spyware".to_string(), "infostealer".to_string()],
            priority: 3,
        });

        info!("Initialized {} rule templates", self.templates.len());
        Ok(())
    }

    /// Initialize string extraction patterns
    fn initialize_string_patterns(&mut self) -> Result<(), CorrelationError> {
        let patterns = vec![
            // URLs and domains
            r"https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[/\w\-._~:/?#[\]@!$&'()*+,;=]*",
            // IP addresses
            r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
            // Email addresses
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            // File paths
            r"[A-Za-z]:\\(?:[^\\/:*?<>|\r\n]+\\)*[^\\/:*?<>|\r\n]*",
            // Registry keys
            r"HKEY_[A-Z_]+\\[^\\]+(?:\\[^\\]+)*",
            // Cryptocurrency addresses (Bitcoin)
            r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b",
            // Base64 encoded strings (minimum 16 chars)
            r"[A-Za-z0-9+/]{16,}={0,2}",
            // Hex strings (minimum 8 chars)
            r"\b[0-9a-fA-F]{8,}\b",
        ];

        for pattern in patterns {
            match Regex::new(pattern) {
                Ok(regex) => self.string_patterns.push(regex),
                Err(e) => warn!("Failed to compile regex pattern '{}': {}", pattern, e),
            }
        }

        info!("Initialized {} string extraction patterns", self.string_patterns.len());
        Ok(())
    }

    /// Generate rule from AI analysis result
    pub async fn generate_rule_from_ai_result(&self, ai_result: &AnalysisResult) -> Result<DynamicRule, CorrelationError> {
        if ai_result.confidence < self.config.min_confidence {
            return Err(CorrelationError::RuleGenerationError(
                format!("AI result confidence {} below threshold {}", 
                        ai_result.confidence, self.config.min_confidence)
            ));
        }

        debug!("Generating rule from AI result with confidence {}", ai_result.confidence);

        // Determine rule template based on classification
        let template = self.select_template(ai_result)?;
        
        // Extract strings from AI analysis
        let extracted_strings = self.extract_strings_from_analysis(ai_result).await?;
        
        // Generate rule conditions
        let conditions = self.generate_conditions(ai_result, &extracted_strings)?;
        
        // Create rule metadata
        let metadata = self.generate_metadata(ai_result)?;
        
        // Generate unique rule name
        let rule_id = self.rule_counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let rule_name = format!("{}_{}_{}_{}", 
                               self.config.rule_prefix,
                               template.name,
                               rule_id,
                               chrono::Utc::now().format("%Y%m%d"));

        // Build YARA rule content
        let rule_content = self.build_yara_rule(
            &rule_name,
            &template,
            &extracted_strings,
            &conditions,
            &metadata,
        )?;

        let dynamic_rule = DynamicRule {
            name: rule_name,
            content: rule_content,
            confidence: ai_result.confidence,
            description: format!("AI-generated rule based on {} analysis", 
                               template.description),
            target_threats: self.extract_target_threats(ai_result),
            created_at: SystemTime::now(),
            effectiveness_score: None,
            usage_stats: RuleUsageStats::default(),
        };

        info!("Generated dynamic rule: {}", dynamic_rule.name);
        Ok(dynamic_rule)
    }

    /// Select appropriate template based on AI result
    fn select_template(&self, ai_result: &AnalysisResult) -> Result<&RuleTemplate, CorrelationError> {
        let threat_indicators = vec![
            ai_result.findings.iter()
                .map(|f| f.description.clone())
                .collect::<Vec<_>>()
                .join(" ")
                .to_lowercase(),
        ];

        let combined_text = threat_indicators.join(" ");

        // Score templates based on content match
        let mut template_scores = Vec::new();
        
        for (name, template) in &self.templates {
            let mut score = 0.0;
            
            for threat_type in &template.threat_types {
                if combined_text.contains(threat_type) {
                    score += 1.0;
                }
            }
            
            // Boost score based on template priority (lower priority = higher boost)
            score += (10.0 - template.priority as f32) * 0.1;
            
            template_scores.push((name, template, score));
        }

        // Sort by score (highest first)
        template_scores.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap());

        if let Some((_, template, score)) = template_scores.first() {
            if *score > 0.0 {
                debug!("Selected template '{}' with score {}", template.name, score);
                return Ok(template);
            }
        }

        // Fallback to generic template
        self.templates.get("trojan")
            .ok_or_else(|| CorrelationError::RuleGenerationError("No suitable template found".to_string()))
    }

    /// Extract strings from AI analysis
    async fn extract_strings_from_analysis(&self, ai_result: &AnalysisResult) -> Result<Vec<StringPattern>, CorrelationError> {
        if !self.config.enable_string_extraction {
            return Ok(Vec::new());
        }

        let mut extracted_strings = Vec::new();
        let analysis_text = ai_result.findings.iter()
            .map(|f| f.description.clone())
            .collect::<Vec<_>>()
            .join(" ");

        // Extract using regex patterns
        for (_i, pattern) in self.string_patterns.iter().enumerate() {
            for mat in pattern.find_iter(&analysis_text) {
                let content = mat.as_str();
                
                if content.len() >= self.config.min_string_length && 
                   content.len() <= self.config.max_string_length {
                    
                    let pattern_type = self.determine_string_type(content);
                    let modifiers = self.generate_string_modifiers(&pattern_type, content);
                    
                    extracted_strings.push(StringPattern {
                        identifier: format!("str_{}", extracted_strings.len() + 1),
                        content: content.to_string(),
                        pattern_type,
                        modifiers,
                        confidence: 0.7, // Base confidence for extracted strings
                    });
                    
                    if extracted_strings.len() >= 20 {
                        break; // Limit number of extracted strings
                    }
                }
            }
        }

        // Extract high-confidence strings from findings
        for finding in &ai_result.findings {
            if finding.description.len() >= self.config.min_string_length && 
               finding.description.len() <= self.config.max_string_length {
                
                extracted_strings.push(StringPattern {
                    identifier: format!("finding_{}", extracted_strings.len() + 1),
                    content: finding.description.clone(),
                    pattern_type: StringPatternType::Text,
                    modifiers: vec!["nocase".to_string()],
                    confidence: 0.8,
                });
            }
        }

        // Remove duplicates
        extracted_strings.sort_by(|a, b| a.content.cmp(&b.content));
        extracted_strings.dedup_by(|a, b| a.content == b.content);

        debug!("Extracted {} strings from AI analysis", extracted_strings.len());
        Ok(extracted_strings)
    }

    /// Determine string pattern type
    fn determine_string_type(&self, content: &str) -> StringPatternType {
        // Check if it's a hex string
        if content.chars().all(|c| c.is_ascii_hexdigit()) && content.len() % 2 == 0 {
            return StringPatternType::Hex;
        }
        
        // Check if it contains wide characters or Unicode
        if content.chars().any(|c| !c.is_ascii()) {
            return StringPatternType::Wide;
        }
        
        // Check if it looks like a regex pattern
        if content.contains('[') || content.contains('*') || content.contains('+') || content.contains('?') {
            return StringPatternType::Regex;
        }
        
        StringPatternType::Text
    }

    /// Generate string modifiers
    fn generate_string_modifiers(&self, pattern_type: &StringPatternType, content: &str) -> Vec<String> {
        let mut modifiers = Vec::new();
        
        match pattern_type {
            StringPatternType::Text => {
                if content.chars().any(|c| c.is_alphabetic()) {
                    modifiers.push("nocase".to_string());
                }
            }
            StringPatternType::Wide => {
                modifiers.push("wide".to_string());
            }
            StringPatternType::Hex => {
                // No special modifiers for hex patterns
            }
            StringPatternType::Regex => {
                // No special modifiers for regex patterns
            }
        }
        
        modifiers
    }

    /// Generate rule conditions
    fn generate_conditions(&self, ai_result: &AnalysisResult, strings: &[StringPattern]) -> Result<Vec<RuleCondition>, CorrelationError> {
        let mut conditions = Vec::new();

        // Basic string matching condition
        if !strings.is_empty() {
            let high_confidence_count = strings.iter().filter(|s| s.confidence > 0.8).count();
            let condition_expr = if high_confidence_count > 0 {
                format!("{} of them", (high_confidence_count.min(3)))
            } else {
                "any of them".to_string()
            };

            conditions.push(RuleCondition {
                expression: condition_expr,
                condition_type: ConditionType::StringMatch,
                confidence: ai_result.confidence,
            });
        }

        // File size condition based on analysis
        if ai_result.metadata.contains_key("file_size") {
            if let Some(size_str) = ai_result.metadata.get("file_size") {
                if let Ok(size) = size_str.parse::<u64>() {
                    conditions.push(RuleCondition {
                        expression: format!("filesize > {} and filesize < {}", size / 2, size * 2),
                        condition_type: ConditionType::FileSize,
                        confidence: 0.6,
                    });
                }
            }
        }

        // Entropy condition for packed/encrypted files
        if ai_result.metadata.contains_key("entropy") {
            if let Some(entropy_str) = ai_result.metadata.get("entropy") {
                if let Ok(entropy) = entropy_str.parse::<f64>() {
                    if entropy > 7.0 {
                        conditions.push(RuleCondition {
                            expression: "math.entropy(0, filesize) > 7.0".to_string(),
                            condition_type: ConditionType::Entropy,
                            confidence: 0.7,
                        });
                    }
                }
            }
        }

        Ok(conditions)
    }

    /// Generate rule metadata
    fn generate_metadata(&self, ai_result: &AnalysisResult) -> Result<HashMap<String, String>, CorrelationError> {
        let mut metadata = HashMap::new();
        
        metadata.insert("author".to_string(), "ERDPS AI Engine".to_string());
        metadata.insert("date".to_string(), chrono::Utc::now().format("%Y-%m-%d").to_string());
        metadata.insert("version".to_string(), "1.0".to_string());
        metadata.insert("description".to_string(), format!("AI-generated rule based on {} analysis", 
                        match ai_result.analysis_type {
                            AnalysisType::MalwareClassification => "malware classification",
                            AnalysisType::BehavioralAnalysis => "behavioral analysis",
                            AnalysisType::YaraRuleGeneration => "YARA rule generation",
                            _ => "general analysis",
                        }));
        
        if let Some(classification) = &ai_result.threat_classification {
            metadata.insert("threat_type".to_string(), classification.family.clone());
            metadata.insert("malware_types".to_string(), classification.malware_type.join(", "));
        }
        
        metadata.insert("confidence".to_string(), ai_result.confidence.to_string());
        
        // Add AI-specific metadata
        metadata.insert("ai_generated".to_string(), "true".to_string());
        metadata.insert("processing_time_ms".to_string(), ai_result.processing_time_ms.to_string());
        
        Ok(metadata)
    }

    /// Build YARA rule content
    fn build_yara_rule(
        &self,
        rule_name: &str,
        _template: &RuleTemplate,
        strings: &[StringPattern],
        conditions: &[RuleCondition],
        metadata: &HashMap<String, String>,
    ) -> Result<String, CorrelationError> {
        let mut rule_content = String::new();
        
        // Rule header
        rule_content.push_str(&format!("rule {}\n{{\n", rule_name));
        
        // Metadata section
        if !metadata.is_empty() {
            rule_content.push_str("    meta:\n");
            for (key, value) in metadata {
                rule_content.push_str(&format!("        {} = \"{}\"\n", key, value));
            }
            rule_content.push('\n');
        }
        
        // Strings section
        if !strings.is_empty() {
            rule_content.push_str("    strings:\n");
            for string_pattern in strings {
                let modifiers_str = if string_pattern.modifiers.is_empty() {
                    String::new()
                } else {
                    format!(" {}", string_pattern.modifiers.join(" "))
                };
                
                match string_pattern.pattern_type {
                    StringPatternType::Text | StringPatternType::Wide => {
                        rule_content.push_str(&format!("        ${} = \"{}\"{}\n", 
                                                     string_pattern.identifier,
                                                     self.escape_string(&string_pattern.content),
                                                     modifiers_str));
                    }
                    StringPatternType::Hex => {
                        rule_content.push_str(&format!("        ${} = {{ {} }}{}\n", 
                                                     string_pattern.identifier,
                                                     string_pattern.content,
                                                     modifiers_str));
                    }
                    StringPatternType::Regex => {
                        rule_content.push_str(&format!("        ${} = /{}/{}\n", 
                                                     string_pattern.identifier,
                                                     string_pattern.content,
                                                     modifiers_str));
                    }
                }
            }
            rule_content.push('\n');
        }
        
        // Condition section
        rule_content.push_str("    condition:\n");
        if conditions.is_empty() {
            rule_content.push_str("        true\n");
        } else {
            let condition_exprs: Vec<String> = conditions.iter()
                .map(|c| c.expression.clone())
                .collect();
            rule_content.push_str(&format!("        {}\n", condition_exprs.join(" and ")));
        }
        
        // Rule footer
        rule_content.push_str("}\n");
        
        Ok(rule_content)
    }

    /// Escape string for YARA rule
    fn escape_string(&self, s: &str) -> String {
        s.replace('\\', "\\\\")
         .replace('"', "\\\"")
         .replace('\n', "\\n")
         .replace('\r', "\\r")
         .replace('\t', "\\t")
    }

    /// Extract target threats from AI result
    fn extract_target_threats(&self, ai_result: &AnalysisResult) -> Vec<String> {
        let mut threats = Vec::new();
        
        if let Some(classification) = &ai_result.threat_classification {
            threats.push(classification.family.to_lowercase());
            threats.extend(classification.malware_type.iter().map(|t| t.to_lowercase()));
        }
        
        // Extract from findings
        let findings_text = ai_result.findings.iter()
            .map(|f| f.description.clone())
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase();
        
        let threat_keywords = vec![
            "ransomware", "trojan", "spyware", "adware", "rootkit", "keylogger",
            "backdoor", "botnet", "worm", "virus", "malware", "pup", "potentially unwanted",
            "crypto", "miner", "stealer", "infostealer", "banker", "downloader",
        ];
        
        for keyword in threat_keywords {
            if findings_text.contains(keyword) && !threats.contains(&keyword.to_string()) {
                threats.push(keyword.to_string());
            }
        }
        
        if threats.is_empty() {
            threats.push("unknown".to_string());
        }
        
        threats
    }

    /// Validate generated rule
    pub fn validate_rule(&self, rule_content: &str) -> Result<bool, CorrelationError> {
        // Basic syntax validation
        if !rule_content.starts_with("rule ") {
            return Err(CorrelationError::RuleGenerationError("Rule must start with 'rule'".to_string()));
        }
        
        if !rule_content.contains("condition:") {
            return Err(CorrelationError::RuleGenerationError("Rule must contain condition section".to_string()));
        }
        
        if !rule_content.ends_with("}\n") && !rule_content.ends_with('}') {
            return Err(CorrelationError::RuleGenerationError("Rule must end with closing brace".to_string()));
        }
        
        // Count braces
        let open_braces = rule_content.matches('{').count();
        let close_braces = rule_content.matches('}').count();
        
        if open_braces != close_braces {
            return Err(CorrelationError::RuleGenerationError("Mismatched braces in rule".to_string()));
        }
        
        Ok(true)
    }

    /// Get rule generation statistics
    pub fn get_stats(&self) -> HashMap<String, u64> {
        let mut stats = HashMap::new();
        stats.insert("total_rules_generated".to_string(), 
                     self.rule_counter.load(std::sync::atomic::Ordering::SeqCst));
        stats.insert("templates_available".to_string(), self.templates.len() as u64);
        stats.insert("string_patterns_available".to_string(), self.string_patterns.len() as u64);
        stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::{AIError, Severity, AIAnalyzer, AnalysisResult, AnalysisType, ThreatClassification, Finding};

    struct MockAIAnalyzer;
    
    #[async_trait::async_trait]
    impl AIAnalyzer for MockAIAnalyzer {
        async fn analyze(&self, _request: crate::ai::AnalysisRequest) -> Result<AnalysisResult, AIError> {
            Ok(AnalysisResult {
                analysis_type: AnalysisType::MalwareClassification,
                confidence: 0.8,
                findings: vec![
                    Finding {
                        category: "encryption".to_string(),
                        severity: Severity::High,
                        description: "Detected encryption behavior".to_string(),
                        confidence: 0.8,
                        evidence: vec!["encrypt".to_string()],
                        recommendations: vec!["Block file".to_string()],
                    }
                ],
                yara_rules: Some(vec!["test_rule".to_string()]),
                threat_classification: Some(ThreatClassification {
                    family: "Ransomware".to_string(),
                    variant: Some("TestVariant".to_string()),
                    malware_type: vec!["Ransomware".to_string()],
                    attack_techniques: vec!["T1486".to_string()],
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

        async fn get_available_models(&self) -> Result<Vec<String>, AIError> {
            Ok(vec!["test-model".to_string()])
        }

        fn get_statistics(&self) -> crate::ai::AnalysisStats {
            crate::ai::AnalysisStats::default()
        }
    }

    #[tokio::test]
    async fn test_rule_generator_creation() {
        let ai_analyzer = Arc::new(MockAIAnalyzer);
        let config = CorrelationConfig::default();
        let generator = RuleGenerator::new(ai_analyzer, config);
        assert!(generator.is_ok());
    }

    #[tokio::test]
    async fn test_rule_generation() {
        let ai_analyzer = Arc::new(MockAIAnalyzer);
        let config = CorrelationConfig::default();
        let generator = RuleGenerator::new(ai_analyzer, config).unwrap();
        
        let ai_result = AnalysisResult {
            analysis_type: AnalysisType::MalwareClassification,
            confidence: 0.8,
            findings: vec![
                Finding {
                    category: "encryption".to_string(),
                    severity: Severity::High,
                    description: "Detected encryption behavior".to_string(),
                    confidence: 0.8,
                    evidence: vec!["encrypt".to_string()],
                    recommendations: vec!["Block file".to_string()],
                },
                Finding {
                    category: "ransom".to_string(),
                    severity: Severity::High,
                    description: "Detected ransom behavior".to_string(),
                    confidence: 0.9,
                    evidence: vec!["ransom".to_string()],
                    recommendations: vec!["Quarantine file".to_string()],
                }
            ],
            yara_rules: Some(vec!["test_rule".to_string()]),
            threat_classification: Some(ThreatClassification {
                family: "Ransomware".to_string(),
                variant: Some("TestVariant".to_string()),
                malware_type: vec!["Ransomware".to_string()],
                attack_techniques: vec!["T1486".to_string()],
                confidence: 0.8,
            }),
            processing_time_ms: 100,
            model_used: "test-model".to_string(),
            metadata: HashMap::new(),
        };
        
        let rule = generator.generate_rule_from_ai_result(&ai_result).await;
        assert!(rule.is_ok());
        
        let rule = rule.unwrap();
        assert!(rule.name.contains("ai_generated"));
        assert!(rule.content.contains("rule "));
        assert!(rule.content.contains("condition:"));
    }

    #[test]
    fn test_string_type_determination() {
        let ai_analyzer = Arc::new(MockAIAnalyzer);
        let config = CorrelationConfig::default();
        let generator = RuleGenerator::new(ai_analyzer, config).unwrap();
        
        assert_eq!(generator.determine_string_type("deadbeef"), StringPatternType::Hex);
        assert_eq!(generator.determine_string_type("hello world"), StringPatternType::Text);
        assert_eq!(generator.determine_string_type("test*pattern"), StringPatternType::Regex);
    }

    #[test]
    fn test_rule_validation() {
        let ai_analyzer = Arc::new(MockAIAnalyzer);
        let config = CorrelationConfig::default();
        let generator = RuleGenerator::new(ai_analyzer, config).unwrap();
        
        let valid_rule = r#"rule test_rule
{
    strings:
        $str1 = "test"
    condition:
        $str1
}
"#;
        
        assert!(generator.validate_rule(valid_rule).is_ok());
        
        let invalid_rule = "invalid rule content";
        assert!(generator.validate_rule(invalid_rule).is_err());
    }
}
