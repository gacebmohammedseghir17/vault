//! AI analysis pipeline for coordinated malware analysis
//! Orchestrates multiple AI analysis types and correlates results

use super::{
    AIResult, AnalysisRequest, AnalysisResult, AnalysisType,
    AnalysisInput, Finding, Severity,
    ollama_client::OllamaClient
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Analysis pipeline configuration
#[derive(Debug, Clone)]
pub struct PipelineConfig {
    /// Enable parallel analysis
    pub parallel_analysis: bool,
    /// Maximum concurrent analyses
    pub max_concurrent: usize,
    /// Minimum confidence threshold for results
    pub confidence_threshold: f32,
    /// Enable result correlation
    pub enable_correlation: bool,
    /// Correlation weight factors
    pub correlation_weights: HashMap<String, f32>,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        let mut correlation_weights = HashMap::new();
        correlation_weights.insert("malware_classification".to_string(), 1.0);
        correlation_weights.insert("behavioral_analysis".to_string(), 0.8);
        correlation_weights.insert("similarity_analysis".to_string(), 0.6);
        correlation_weights.insert("threat_correlation".to_string(), 0.9);

        Self {
            parallel_analysis: true,
            max_concurrent: 4,
            confidence_threshold: 0.5,
            enable_correlation: true,
            correlation_weights,
        }
    }
}

/// Analysis pipeline for coordinated AI analysis
pub struct AnalysisPipeline {
    /// Ollama client
    ollama_client: Arc<OllamaClient>,
    /// Pipeline configuration
    config: PipelineConfig,
    /// Analysis statistics
    stats: Arc<RwLock<PipelineStats>>,
}

/// Pipeline statistics
#[derive(Debug, Clone, Default)]
pub struct PipelineStats {
    /// Total pipeline runs
    pub total_runs: u64,
    /// Successful pipeline runs
    pub successful_runs: u64,
    /// Failed pipeline runs
    pub failed_runs: u64,
    /// Average pipeline duration
    pub avg_duration_ms: f64,
    /// Analysis type success rates
    pub analysis_success_rates: HashMap<String, f32>,
    /// Correlation accuracy
    pub correlation_accuracy: f32,
}

/// Pipeline analysis result
#[derive(Debug, Clone)]
pub struct PipelineResult {
    /// Individual analysis results
    pub analysis_results: Vec<AnalysisResult>,
    /// Correlated findings
    pub correlated_findings: Vec<Finding>,
    /// Overall confidence score
    pub overall_confidence: f32,
    /// Threat assessment
    pub threat_assessment: ThreatAssessment,
    /// Processing time in milliseconds
    pub processing_time_ms: u64,
    /// Pipeline metadata
    pub metadata: HashMap<String, String>,
}

/// Comprehensive threat assessment
#[derive(Debug, Clone)]
pub struct ThreatAssessment {
    /// Overall threat level
    pub threat_level: ThreatLevel,
    /// Threat score (0.0 to 1.0)
    pub threat_score: f32,
    /// Primary threat indicators
    pub primary_indicators: Vec<String>,
    /// Recommended actions
    pub recommended_actions: Vec<String>,
    /// Risk factors
    pub risk_factors: Vec<RiskFactor>,
}

/// Threat level classification
#[derive(Debug, Clone, PartialEq)]
pub enum ThreatLevel {
    /// No threat detected
    None,
    /// Low threat level
    Low,
    /// Medium threat level
    Medium,
    /// High threat level
    High,
    /// Critical threat level
    Critical,
}

/// Risk factor assessment
#[derive(Debug, Clone)]
pub struct RiskFactor {
    /// Risk category
    pub category: String,
    /// Risk description
    pub description: String,
    /// Risk score (0.0 to 1.0)
    pub score: f32,
    /// Mitigation suggestions
    pub mitigations: Vec<String>,
}

impl AnalysisPipeline {
    /// Create new analysis pipeline
    pub fn new(ollama_client: Arc<OllamaClient>, config: PipelineConfig) -> Self {
        Self {
            ollama_client,
            config,
            stats: Arc::new(RwLock::new(PipelineStats::default())),
        }
    }

    /// Run comprehensive analysis pipeline
    pub async fn run_comprehensive_analysis(&self, input: AnalysisInput) -> AIResult<PipelineResult> {
        let start_time = std::time::Instant::now();
        
        info!("Starting comprehensive analysis pipeline");
        
        // Define analysis types to run
        let analysis_types = vec![
            AnalysisType::MalwareClassification,
            AnalysisType::BehavioralAnalysis,
            AnalysisType::SimilarityAnalysis,
            AnalysisType::ThreatCorrelation,
        ];

        // Run analyses
        let analysis_results = if self.config.parallel_analysis {
            self.run_parallel_analyses(&input, &analysis_types).await?
        } else {
            self.run_sequential_analyses(&input, &analysis_types).await?
        };

        // Filter results by confidence threshold
        let filtered_results: Vec<_> = analysis_results
            .into_iter()
            .filter(|result| result.confidence >= self.config.confidence_threshold)
            .collect();

        // Correlate findings
        let correlated_findings = if self.config.enable_correlation {
            self.correlate_findings(&filtered_results).await?
        } else {
            Vec::new()
        };

        // Calculate overall confidence
        let overall_confidence = self.calculate_overall_confidence(&filtered_results);

        // Generate threat assessment
        let threat_assessment = self.generate_threat_assessment(&filtered_results, &correlated_findings).await?;

        let processing_time = start_time.elapsed().as_millis() as u64;

        // Update statistics
        self.update_pipeline_stats(true, processing_time, &filtered_results).await;

        let result = PipelineResult {
            analysis_results: filtered_results,
            correlated_findings,
            overall_confidence,
            threat_assessment,
            processing_time_ms: processing_time,
            metadata: HashMap::new(),
        };

        info!("Comprehensive analysis pipeline completed in {}ms", processing_time);
        Ok(result)
    }

    /// Run analyses in parallel
    async fn run_parallel_analyses(
        &self,
        input: &AnalysisInput,
        analysis_types: &[AnalysisType],
    ) -> AIResult<Vec<AnalysisResult>> {
        use tokio::sync::Semaphore;
        
        let semaphore = Arc::new(Semaphore::new(self.config.max_concurrent));
        let mut tasks = Vec::new();

        for analysis_type in analysis_types {
            let client = Arc::clone(&self.ollama_client);
            let input_clone = input.clone();
            let analysis_type_clone = analysis_type.clone();
            let semaphore_clone = Arc::clone(&semaphore);

            let task = tokio::spawn(async move {
                let _permit = semaphore_clone.acquire().await.unwrap();
                
                let request = AnalysisRequest {
                    analysis_type: analysis_type_clone,
                    input_data: input_clone,
                    model: None,
                    context: HashMap::new(),
                };

                client.analyze(request).await
            });

            tasks.push(task);
        }

        let mut results = Vec::new();
        for task in tasks {
            match task.await {
                Ok(Ok(result)) => results.push(result),
                Ok(Err(e)) => warn!("Analysis failed: {}", e),
                Err(e) => warn!("Task failed: {}", e),
            }
        }

        Ok(results)
    }

    /// Run analyses sequentially
    async fn run_sequential_analyses(
        &self,
        input: &AnalysisInput,
        analysis_types: &[AnalysisType],
    ) -> AIResult<Vec<AnalysisResult>> {
        let mut results = Vec::new();

        for analysis_type in analysis_types {
            let request = AnalysisRequest {
                analysis_type: analysis_type.clone(),
                input_data: input.clone(),
                model: None,
                context: HashMap::new(),
            };

            match self.ollama_client.analyze(request).await {
                Ok(result) => results.push(result),
                Err(e) => warn!("Analysis {} failed: {}", format!("{:?}", analysis_type), e),
            }
        }

        Ok(results)
    }

    /// Correlate findings from multiple analyses
    async fn correlate_findings(&self, results: &[AnalysisResult]) -> AIResult<Vec<Finding>> {
        let mut correlated_findings = Vec::new();
        let mut finding_groups: HashMap<String, Vec<&Finding>> = HashMap::new();

        // Group findings by category
        for result in results {
            for finding in &result.findings {
                finding_groups
                    .entry(finding.category.clone())
                    .or_insert_with(Vec::new)
                    .push(finding);
            }
        }

        // Correlate findings within each category
        for (category, findings) in finding_groups {
            if findings.len() > 1 {
                let correlated_finding = self.correlate_category_findings(&category, &findings);
                correlated_findings.push(correlated_finding);
            }
        }

        // Cross-category correlation
        let cross_correlated = self.cross_correlate_findings(results).await?;
        correlated_findings.extend(cross_correlated);

        Ok(correlated_findings)
    }

    /// Correlate findings within a category
    fn correlate_category_findings(&self, category: &str, findings: &[&Finding]) -> Finding {
        let avg_confidence = findings.iter().map(|f| f.confidence).sum::<f32>() / findings.len() as f32;
        let max_severity = findings.iter().map(|f| &f.severity).max().unwrap_or(&Severity::Info);
        
        let mut all_evidence = Vec::new();
        let mut all_recommendations = Vec::new();
        
        for finding in findings {
            all_evidence.extend(finding.evidence.clone());
            all_recommendations.extend(finding.recommendations.clone());
        }

        // Remove duplicates
        all_evidence.sort();
        all_evidence.dedup();
        all_recommendations.sort();
        all_recommendations.dedup();

        Finding {
            category: format!("correlated_{}", category),
            severity: max_severity.clone(),
            description: format!("Correlated findings from {} analyses in category: {}", findings.len(), category),
            confidence: avg_confidence * 1.1, // Boost confidence for correlated findings
            evidence: all_evidence,
            recommendations: all_recommendations,
        }
    }

    /// Cross-correlate findings between categories
    async fn cross_correlate_findings(&self, results: &[AnalysisResult]) -> AIResult<Vec<Finding>> {
        let mut cross_findings = Vec::new();

        // Look for patterns across different analysis types
        let malware_results: Vec<_> = results.iter()
            .filter(|r| r.analysis_type == AnalysisType::MalwareClassification)
            .collect();
        
        let behavioral_results: Vec<_> = results.iter()
            .filter(|r| r.analysis_type == AnalysisType::BehavioralAnalysis)
            .collect();

        // Correlate malware classification with behavioral analysis
        if !malware_results.is_empty() && !behavioral_results.is_empty() {
            for malware_result in &malware_results {
                for behavioral_result in &behavioral_results {
                    if let Some(correlation) = self.find_malware_behavior_correlation(malware_result, behavioral_result) {
                        cross_findings.push(correlation);
                    }
                }
            }
        }

        Ok(cross_findings)
    }

    /// Find correlation between malware classification and behavioral analysis
    fn find_malware_behavior_correlation(
        &self,
        malware_result: &AnalysisResult,
        behavioral_result: &AnalysisResult,
    ) -> Option<Finding> {
        // Check if threat classifications align
        if let Some(threat_class) = &malware_result.threat_classification {
            let malware_family = &threat_class.family;
            
            // Look for behavioral patterns that match the malware family
            for finding in &behavioral_result.findings {
                if finding.description.to_lowercase().contains(&malware_family.to_lowercase()) ||
                   finding.evidence.iter().any(|e| e.to_lowercase().contains(&malware_family.to_lowercase())) {
                    
                    return Some(Finding {
                        category: "cross_correlation".to_string(),
                        severity: Severity::High,
                        description: format!("Behavioral patterns consistent with {} malware family", malware_family),
                        confidence: (malware_result.confidence + behavioral_result.confidence) / 2.0 * 1.2,
                        evidence: vec![
                            format!("Malware classification: {}", malware_family),
                            format!("Behavioral evidence: {}", finding.description),
                        ],
                        recommendations: vec![
                            "High confidence threat detected".to_string(),
                            "Immediate containment recommended".to_string(),
                        ],
                    });
                }
            }
        }

        None
    }

    /// Calculate overall confidence from multiple results
    fn calculate_overall_confidence(&self, results: &[AnalysisResult]) -> f32 {
        if results.is_empty() {
            return 0.0;
        }

        let mut weighted_sum = 0.0;
        let mut total_weight = 0.0;

        for result in results {
            let analysis_type_key = format!("{:?}", result.analysis_type).to_lowercase();
            let weight = self.config.correlation_weights
                .get(&analysis_type_key)
                .copied()
                .unwrap_or(1.0);
            
            weighted_sum += result.confidence * weight;
            total_weight += weight;
        }

        if total_weight > 0.0 {
            (weighted_sum / total_weight).min(1.0)
        } else {
            results.iter().map(|r| r.confidence).sum::<f32>() / results.len() as f32
        }
    }

    /// Generate comprehensive threat assessment
    async fn generate_threat_assessment(
        &self,
        results: &[AnalysisResult],
        correlated_findings: &[Finding],
    ) -> AIResult<ThreatAssessment> {
        // Calculate threat score based on findings severity and confidence
        let mut threat_score = 0.0;
        let mut severity_counts = HashMap::new();
        let mut primary_indicators = Vec::new();
        let mut risk_factors = Vec::new();

        // Analyze individual results
        for result in results {
            for finding in &result.findings {
                let severity_weight = match finding.severity {
                    Severity::Critical => 1.0,
                    Severity::High => 0.8,
                    Severity::Medium => 0.6,
                    Severity::Low => 0.4,
                    Severity::Info => 0.2,
                };

                threat_score += finding.confidence * severity_weight;
                *severity_counts.entry(&finding.severity).or_insert(0) += 1;

                if finding.confidence > 0.7 {
                    primary_indicators.push(finding.description.clone());
                }

                // Create risk factors
                risk_factors.push(RiskFactor {
                    category: finding.category.clone(),
                    description: finding.description.clone(),
                    score: finding.confidence * severity_weight,
                    mitigations: finding.recommendations.clone(),
                });
            }
        }

        // Analyze correlated findings (higher weight)
        for finding in correlated_findings {
            let severity_weight = match finding.severity {
                Severity::Critical => 1.0,
                Severity::High => 0.8,
                Severity::Medium => 0.6,
                Severity::Low => 0.4,
                Severity::Info => 0.2,
            };

            threat_score += finding.confidence * severity_weight * 1.5; // Boost for correlation
            primary_indicators.push(format!("CORRELATED: {}", finding.description));
        }

        // Normalize threat score
        let total_findings = results.iter().map(|r| r.findings.len()).sum::<usize>() + correlated_findings.len();
        if total_findings > 0 {
            threat_score /= total_findings as f32;
        }
        threat_score = threat_score.min(1.0);

        // Determine threat level
        let threat_level = match threat_score {
            score if score >= 0.9 => ThreatLevel::Critical,
            score if score >= 0.7 => ThreatLevel::High,
            score if score >= 0.5 => ThreatLevel::Medium,
            score if score >= 0.3 => ThreatLevel::Low,
            _ => ThreatLevel::None,
        };

        // Generate recommended actions
        let recommended_actions = self.generate_recommended_actions(&threat_level, &severity_counts);

        // Remove duplicate indicators
        primary_indicators.sort();
        primary_indicators.dedup();

        Ok(ThreatAssessment {
            threat_level,
            threat_score,
            primary_indicators,
            recommended_actions,
            risk_factors,
        })
    }

    /// Generate recommended actions based on threat assessment
    fn generate_recommended_actions(
        &self,
        threat_level: &ThreatLevel,
        severity_counts: &HashMap<&Severity, i32>,
    ) -> Vec<String> {
        let mut actions = Vec::new();

        match threat_level {
            ThreatLevel::Critical => {
                actions.push("IMMEDIATE ISOLATION: Disconnect system from network".to_string());
                actions.push("EMERGENCY RESPONSE: Activate incident response team".to_string());
                actions.push("FORENSIC PRESERVATION: Create memory and disk images".to_string());
                actions.push("STAKEHOLDER NOTIFICATION: Alert security team and management".to_string());
            }
            ThreatLevel::High => {
                actions.push("CONTAINMENT: Isolate affected systems".to_string());
                actions.push("INVESTIGATION: Conduct detailed forensic analysis".to_string());
                actions.push("MONITORING: Increase monitoring of related systems".to_string());
                actions.push("REMEDIATION: Begin malware removal procedures".to_string());
            }
            ThreatLevel::Medium => {
                actions.push("QUARANTINE: Move suspicious files to quarantine".to_string());
                actions.push("ANALYSIS: Perform additional malware analysis".to_string());
                actions.push("MONITORING: Monitor system for suspicious activity".to_string());
                actions.push("VALIDATION: Verify threat indicators".to_string());
            }
            ThreatLevel::Low => {
                actions.push("MONITORING: Continue monitoring for indicators".to_string());
                actions.push("LOGGING: Increase logging verbosity".to_string());
                actions.push("REVIEW: Review security policies and controls".to_string());
            }
            ThreatLevel::None => {
                actions.push("ROUTINE: Continue normal security monitoring".to_string());
                actions.push("DOCUMENTATION: Document analysis results".to_string());
            }
        }

        // Add specific actions based on severity distribution
        if severity_counts.get(&Severity::Critical).unwrap_or(&0) > &0 {
            actions.push("CRITICAL FINDINGS: Address critical security issues immediately".to_string());
        }

        actions
    }

    /// Update pipeline statistics
    async fn update_pipeline_stats(&self, success: bool, duration_ms: u64, results: &[AnalysisResult]) {
        let mut stats = self.stats.write().await;
        stats.total_runs += 1;

        if success {
            stats.successful_runs += 1;
        } else {
            stats.failed_runs += 1;
        }

        // Update average duration
        let total_duration = stats.avg_duration_ms * (stats.total_runs - 1) as f64 + duration_ms as f64;
        stats.avg_duration_ms = total_duration / stats.total_runs as f64;

        // Update analysis success rates
        for result in results {
            let analysis_type = format!("{:?}", result.analysis_type);
            let current_rate = stats.analysis_success_rates.get(&analysis_type).unwrap_or(&0.0);
            let new_rate = (current_rate + 1.0) / 2.0; // Simple moving average
            stats.analysis_success_rates.insert(analysis_type, new_rate);
        }
    }

    /// Get pipeline statistics
    pub async fn get_statistics(&self) -> PipelineStats {
        self.stats.read().await.clone()
    }

    /// Update pipeline configuration
    pub fn update_config(&mut self, config: PipelineConfig) {
        self.config = config;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::AIConfig;

    #[tokio::test]
    async fn test_pipeline_creation() {
        let ai_config = AIConfig::default();
        let ollama_client = Arc::new(OllamaClient::new(ai_config).unwrap());
        let pipeline_config = PipelineConfig::default();
        
        let pipeline = AnalysisPipeline::new(ollama_client, pipeline_config);
        let stats = pipeline.get_statistics().await;
        assert_eq!(stats.total_runs, 0);
    }

    #[test]
    fn test_threat_level_classification() {
        let threat_level = ThreatLevel::High;
        assert_eq!(threat_level, ThreatLevel::High);
        assert_ne!(threat_level, ThreatLevel::Critical);
    }

    #[test]
    fn test_pipeline_config_default() {
        let config = PipelineConfig::default();
        assert!(config.parallel_analysis);
        assert_eq!(config.max_concurrent, 4);
        assert_eq!(config.confidence_threshold, 0.5);
    }
}
