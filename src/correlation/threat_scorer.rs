//! Advanced threat scoring and risk assessment engine
//! Combines multiple analysis results to generate comprehensive threat scores

use super::*;
use std::collections::HashMap;
use std::time::{Duration, SystemTime};
use tracing::{debug, info};

/// Threat scoring configuration
#[derive(Debug, Clone)]
pub struct ThreatScorerConfig {
    /// Base score weights for different analysis types
    pub analysis_weights: HashMap<String, f32>,
    /// Confidence threshold for scoring
    pub confidence_threshold: f32,
    /// Maximum score value
    pub max_score: f32,
    /// Minimum score value
    pub min_score: f32,
    /// Time decay factor for historical data
    pub time_decay_factor: f32,
    /// Enable behavioral scoring
    pub enable_behavioral_scoring: bool,
    /// Enable network scoring
    pub enable_network_scoring: bool,
    /// Enable reputation scoring
    pub enable_reputation_scoring: bool,
}

impl Default for ThreatScorerConfig {
    fn default() -> Self {
        let mut analysis_weights = HashMap::new();
        analysis_weights.insert("yara_match".to_string(), 0.3);
        analysis_weights.insert("ai_analysis".to_string(), 0.25);
        analysis_weights.insert("behavioral".to_string(), 0.2);
        analysis_weights.insert("network".to_string(), 0.15);
        analysis_weights.insert("reputation".to_string(), 0.1);

        Self {
            analysis_weights,
            confidence_threshold: 0.5,
            max_score: 100.0,
            min_score: 0.0,
            time_decay_factor: 0.95,
            enable_behavioral_scoring: true,
            enable_network_scoring: true,
            enable_reputation_scoring: true,
        }
    }
}

/// Threat score breakdown
#[derive(Debug, Clone)]
pub struct ThreatScoreBreakdown {
    /// Total threat score
    pub total_score: f32,
    /// Individual component scores
    pub component_scores: HashMap<String, f32>,
    /// Confidence in the score
    pub confidence: f32,
    /// Risk level based on score
    pub risk_level: RiskLevel,
    /// Contributing factors
    pub contributing_factors: Vec<String>,
    /// Score calculation timestamp
    pub calculated_at: SystemTime,
}

/// Risk levels based on threat score
#[derive(Debug, Clone, PartialEq)]
pub enum RiskLevel {
    /// Very low risk (0-20)
    VeryLow,
    /// Low risk (21-40)
    Low,
    /// Medium risk (41-60)
    Medium,
    /// High risk (61-80)
    High,
    /// Critical risk (81-100)
    Critical,
}

impl RiskLevel {
    /// Convert score to risk level
    pub fn from_score(score: f32) -> Self {
        match score {
            s if s <= 20.0 => RiskLevel::VeryLow,
            s if s <= 40.0 => RiskLevel::Low,
            s if s <= 60.0 => RiskLevel::Medium,
            s if s <= 80.0 => RiskLevel::High,
            _ => RiskLevel::Critical,
        }
    }

    /// Get numeric value for risk level
    pub fn to_numeric(&self) -> u8 {
        match self {
            RiskLevel::VeryLow => 1,
            RiskLevel::Low => 2,
            RiskLevel::Medium => 3,
            RiskLevel::High => 4,
            RiskLevel::Critical => 5,
        }
    }
}

/// Historical threat data for trend analysis
#[derive(Debug, Clone)]
pub struct ThreatHistory {
    /// Historical scores
    pub scores: Vec<(SystemTime, f32)>,
    /// Score trend (increasing, decreasing, stable)
    pub trend: ScoreTrend,
    /// Average score over time
    pub average_score: f32,
    /// Peak score recorded
    pub peak_score: f32,
    /// Time of peak score
    pub peak_time: Option<SystemTime>,
}

/// Score trend indicators
#[derive(Debug, Clone, PartialEq)]
pub enum ScoreTrend {
    /// Score is increasing over time
    Increasing,
    /// Score is decreasing over time
    Decreasing,
    /// Score is relatively stable
    Stable,
    /// Insufficient data for trend analysis
    Unknown,
}

/// Reputation data for scoring
#[derive(Debug, Clone)]
pub struct ReputationData {
    /// File hash reputation
    pub hash_reputation: Option<f32>,
    /// Domain reputation
    pub domain_reputation: Option<f32>,
    /// IP reputation
    pub ip_reputation: Option<f32>,
    /// Certificate reputation
    pub cert_reputation: Option<f32>,
    /// Overall reputation score
    pub overall_reputation: f32,
    /// Reputation sources
    pub sources: Vec<String>,
}

/// Advanced threat scorer
#[derive(Clone)]
pub struct ThreatScorer {
    /// Configuration
    config: ThreatScorerConfig,
    /// Historical threat data
    threat_history: HashMap<String, ThreatHistory>,
    /// Reputation cache
    reputation_cache: HashMap<String, (ReputationData, SystemTime)>,
    /// Scoring statistics
    stats: ThreatScoringStats,
}

/// Threat scoring statistics
#[derive(Debug, Clone, Default)]
pub struct ThreatScoringStats {
    /// Total scores calculated
    pub total_scores_calculated: u64,
    /// Average processing time
    pub average_processing_time_ms: f64,
    /// Score distribution by risk level
    pub risk_level_distribution: HashMap<String, u64>,
    /// Most common contributing factors
    pub common_factors: HashMap<String, u64>,
}

impl ThreatScorer {
    /// Create new threat scorer
    pub fn new(correlation_config: CorrelationConfig) -> Self {
        let config = ThreatScorerConfig {
            confidence_threshold: correlation_config.ai_confidence_threshold,
            ..Default::default()
        };

        Self {
            config,
            threat_history: HashMap::new(),
            reputation_cache: HashMap::new(),
            stats: ThreatScoringStats::default(),
        }
    }

    /// Calculate comprehensive threat score
    pub async fn calculate_threat_score(
        &mut self,
        correlation_result: &CorrelationResult,
        file_hash: Option<&str>,
    ) -> Result<ThreatScoreBreakdown, CorrelationError> {
        let start_time = std::time::Instant::now();
        
        debug!("Calculating threat score for correlation result");

        let mut component_scores = HashMap::new();
        let mut contributing_factors = Vec::new();
        let mut total_confidence = 0.0;
        let mut confidence_count = 0;

        // YARA match scoring
        let yara_score = self.calculate_yara_score(&correlation_result.yara_matches)?;
        if yara_score > 0.0 {
            component_scores.insert("yara_match".to_string(), yara_score);
            contributing_factors.push(format!("YARA matches ({})", correlation_result.yara_matches.len()));
            total_confidence += correlation_result.yara_matches.iter()
                .map(|m| m.score)
                .sum::<f32>() / correlation_result.yara_matches.len().max(1) as f32;
            confidence_count += 1;
        }

        // AI analysis scoring
        if let Some(ai_result) = correlation_result.ai_results.first() {
            let ai_score = self.calculate_ai_score(ai_result)?;
            if ai_score > 0.0 {
                component_scores.insert("ai_analysis".to_string(), ai_score);
                contributing_factors.push(format!("AI analysis confidence: {:.2}", ai_result.confidence));
                total_confidence += ai_result.confidence;
                confidence_count += 1;
            }
        }

        // Behavioral scoring
        if self.config.enable_behavioral_scoring {
            let behavioral_score = self.calculate_behavioral_score(&correlation_result.behavioral_summary)?;
            if behavioral_score > 0.0 {
                component_scores.insert("behavioral".to_string(), behavioral_score);
                contributing_factors.push("Behavioral indicators detected".to_string());
            }
        }

        // Network scoring
        if self.config.enable_network_scoring {
            let network_score = self.calculate_network_score(&correlation_result.network_summary)?;
            if network_score > 0.0 {
                component_scores.insert("network".to_string(), network_score);
                contributing_factors.push("Network activity indicators".to_string());
            }
        }

        // Reputation scoring
        if self.config.enable_reputation_scoring {
            if let Some(hash) = file_hash {
                let reputation_score = self.calculate_reputation_score(hash).await?;
                if reputation_score > 0.0 {
                    component_scores.insert("reputation".to_string(), reputation_score);
                    contributing_factors.push("Reputation data available".to_string());
                }
            }
        }

        // Calculate weighted total score
        let total_score = self.calculate_weighted_score(&component_scores)?;
        
        // Apply confidence adjustment
        let confidence = if confidence_count > 0 {
            total_confidence / confidence_count as f32
        } else {
            0.5 // Default confidence
        };

        let adjusted_score = total_score * confidence;
        let clamped_score = adjusted_score.clamp(self.config.min_score, self.config.max_score);
        
        // Determine risk level
        let risk_level = RiskLevel::from_score(clamped_score);

        // Update historical data
        if let Some(hash) = file_hash {
            self.update_threat_history(hash, clamped_score);
        }

        // Update statistics
        self.update_stats(&risk_level, &contributing_factors, start_time.elapsed());

        let breakdown = ThreatScoreBreakdown {
            total_score: clamped_score,
            component_scores,
            confidence,
            risk_level,
            contributing_factors,
            calculated_at: SystemTime::now(),
        };

        info!("Calculated threat score: {:.2} ({})", clamped_score, 
              format!("{:?}", breakdown.risk_level));

        Ok(breakdown)
    }

    /// Calculate YARA match score
    fn calculate_yara_score(&self, yara_matches: &[YaraMatch]) -> Result<f32, CorrelationError> {
        if yara_matches.is_empty() {
            return Ok(0.0);
        }

        let mut total_score = 0.0;
        let mut weight_sum = 0.0;

        for yara_match in yara_matches {
            // Base score from confidence
            let base_score = yara_match.score * 100.0;
            
            // Weight based on rule type and severity
            let mut weight = 1.0;
            
            // Higher weight for high-score matches
            if yara_match.score > 0.8 {
                weight *= 1.5;
            }
            
            // Higher weight for multiple string matches
            if yara_match.matched_strings.len() > 3 {
                weight *= 1.2;
            }
            
            // Higher weight for specific threat indicators
            let rule_name_lower = yara_match.rule_name.to_lowercase();
            if rule_name_lower.contains("ransomware") || rule_name_lower.contains("trojan") {
                weight *= 1.3;
            }
            
            total_score += base_score * weight;
            weight_sum += weight;
        }

        let average_score = if weight_sum > 0.0 {
            total_score / weight_sum
        } else {
            0.0
        };

        // Apply diminishing returns for multiple matches
        let match_count_factor = 1.0 - (-0.1 * yara_matches.len() as f32).exp();
        let final_score = average_score * (1.0 + match_count_factor * 0.5);

        Ok(final_score.min(100.0))
    }

    /// Calculate AI analysis score
    fn calculate_ai_score(&self, ai_result: &crate::ai::AnalysisResult) -> Result<f32, CorrelationError> {
        let base_score = ai_result.confidence * 100.0;
        
        // Severity multiplier based on threat classification confidence
        let severity_multiplier = if let Some(ref classification) = ai_result.threat_classification {
            if classification.confidence > 0.9 {
                1.5 // Critical confidence
            } else if classification.confidence > 0.7 {
                1.3 // High confidence
            } else if classification.confidence > 0.5 {
                1.0 // Medium confidence
            } else {
                0.7 // Low confidence
            }
        } else {
            0.5 // No classification available
        };
        
        // Classification multiplier based on threat family
        let classification_multiplier = if let Some(ref classification) = ai_result.threat_classification {
            match classification.family.as_str() {
                "Malware" => 2.0,
                "Trojan" => 1.8,
                "Ransomware" => 2.5,
                "Rootkit" => 2.2,
                "Worm" => 1.6,
                "Virus" => 1.7,
                "Adware" => 1.2,
                "Spyware" => 1.9,
                "Backdoor" => 2.1,
                "Suspicious" => 1.3,
                "Benign" => 0.5,
                _ => 1.0,
            }
        } else {
            0.8 // No classification available
        };
        
        // Findings count bonus
        let findings_bonus = (ai_result.findings.len() as f32 * 0.1).min(0.5);
        
        let final_score = base_score * severity_multiplier * classification_multiplier * (1.0 + findings_bonus);
        
        Ok(final_score.min(100.0))
    }

    /// Calculate behavioral score
    fn calculate_behavioral_score(&self, behavioral_summary: &BehavioralSummary) -> Result<f32, CorrelationError> {
        let mut score = 0.0;
        
        // Score based on behavioral summary metrics
        score += behavioral_summary.total_indicators as f32 * 2.0;
        score += behavioral_summary.high_severity_count as f32 * 5.0;
        score += behavioral_summary.risk_score;
        
        // Common behaviors bonus
        for (behavior_type, count) in &behavioral_summary.common_behaviors {
            let behavior_score = match behavior_type {
                BehavioralType::FileSystem => 15.0,
                BehavioralType::Registry => 20.0,
                BehavioralType::Network => 25.0,
                BehavioralType::Process => 10.0,
                BehavioralType::Memory => 30.0,
                BehavioralType::Cryptographic => 35.0,
                BehavioralType::AntiAnalysis => 40.0,
                BehavioralType::Persistence => 45.0,
                BehavioralType::PrivilegeEscalation => 50.0,
                BehavioralType::DataExfiltration => 55.0,
            };
            score += behavior_score * (*count as f32 * 0.1);
        }
        
        // Apply timeline density factor
        let timeline_factor = if behavioral_summary.behavior_timeline.len() > 10 {
            1.2 // More activity = higher score
        } else {
            1.0
        };
        
        let final_score: f32 = score * timeline_factor;
        
        Ok(final_score.min(100.0))
    }

    /// Calculate network score
    fn calculate_network_score(&self, network_summary: &NetworkSummary) -> Result<f32, CorrelationError> {
        let mut score: f32 = 0.0;
        
        // Score based on network summary metrics
        score += network_summary.total_indicators as f32 * 2.0;
        score += network_summary.unique_destinations as f32 * 1.5;
        score += (network_summary.total_bytes as f32 / 1024.0 / 1024.0) * 0.1; // MB factor
        
        // Suspicious connections bonus
        score += network_summary.suspicious_connections as f32 * 10.0;
        
        // Geolocation risk factor
        let high_risk_countries: usize = network_summary.geographic_distribution.iter()
            .filter(|(country, _)| {
                // Example high-risk countries (this would be configurable)
                matches!(country.as_str(), "CN" | "RU" | "KP" | "IR")
            })
            .map(|(_, count)| *count)
            .sum();
        
        if high_risk_countries > 0 {
            score += high_risk_countries as f32 * 10.0;
        }
        
        Ok(score.min(100.0))
    }

    /// Calculate reputation score
    async fn calculate_reputation_score(&mut self, file_hash: &str) -> Result<f32, CorrelationError> {
        // Check cache first
        if let Some((reputation_data, timestamp)) = self.reputation_cache.get(file_hash) {
            if timestamp.elapsed().unwrap_or(Duration::from_secs(3600)) < Duration::from_secs(1800) {
                return Ok(self.reputation_to_score(reputation_data));
            }
        }

        // In a real implementation, this would query reputation services
        // For now, we'll simulate reputation data
        let reputation_data = self.simulate_reputation_lookup(file_hash).await?;
        
        let score = self.reputation_to_score(&reputation_data);
        
        // Cache the result
        self.reputation_cache.insert(
            file_hash.to_string(),
            (reputation_data, SystemTime::now())
        );
        
        Ok(score)
    }

    /// Simulate reputation lookup (placeholder for real implementation)
    async fn simulate_reputation_lookup(&self, _file_hash: &str) -> Result<ReputationData, CorrelationError> {
        // This would integrate with real reputation services like VirusTotal, etc.
        Ok(ReputationData {
            hash_reputation: Some(0.3), // Neutral reputation
            domain_reputation: None,
            ip_reputation: None,
            cert_reputation: None,
            overall_reputation: 0.3,
            sources: vec!["simulated".to_string()],
        })
    }

    /// Convert reputation data to score
    fn reputation_to_score(&self, reputation_data: &ReputationData) -> f32 {
        // Convert reputation (0.0 = good, 1.0 = bad) to score (0-100)
        reputation_data.overall_reputation * 100.0
    }

    /// Calculate weighted total score
    fn calculate_weighted_score(&self, component_scores: &HashMap<String, f32>) -> Result<f32, CorrelationError> {
        let mut weighted_sum = 0.0;
        let mut total_weight = 0.0;

        for (component, score) in component_scores {
            if let Some(&weight) = self.config.analysis_weights.get(component) {
                weighted_sum += score * weight;
                total_weight += weight;
            }
        }

        if total_weight > 0.0 {
            Ok(weighted_sum / total_weight)
        } else {
            Ok(0.0)
        }
    }

    /// Update threat history for trend analysis
    fn update_threat_history(&mut self, file_hash: &str, score: f32) {
        let now = SystemTime::now();
        
        // Calculate trend slope first if we have enough data
        let trend_slope = if let Some(history) = self.threat_history.get(file_hash) {
            if history.scores.len() >= 3 {
                let recent_scores: Vec<f32> = history.scores.iter()
                    .rev()
                    .take(5)
                    .map(|(_, s)| *s)
                    .collect();
                self.calculate_trend_slope(&recent_scores)
            } else {
                0.0
            }
        } else {
            0.0
        };
        
        // Now update the history
        let history = self.threat_history.entry(file_hash.to_string())
            .or_insert_with(|| ThreatHistory {
                scores: Vec::new(),
                trend: ScoreTrend::Unknown,
                average_score: 0.0,
                peak_score: 0.0,
                peak_time: None,
            });

        history.scores.push((now, score));

        // Keep only recent scores (last 100 entries)
        if history.scores.len() > 100 {
            history.scores.drain(0..history.scores.len() - 100);
        }

        // Update peak score
        if score > history.peak_score {
            history.peak_score = score;
            history.peak_time = Some(now);
        }

        // Calculate average
        history.average_score = history.scores.iter()
            .map(|(_, s)| s)
            .sum::<f32>() / history.scores.len() as f32;

        // Set trend based on calculated slope
        history.trend = if trend_slope > 5.0 {
            ScoreTrend::Increasing
        } else if trend_slope < -5.0 {
            ScoreTrend::Decreasing
        } else {
            ScoreTrend::Stable
        };
    }

    /// Calculate trend slope for score analysis
    fn calculate_trend_slope(&self, scores: &[f32]) -> f32 {
        if scores.len() < 2 {
            return 0.0;
        }

        let n = scores.len() as f32;
        let sum_x: f32 = (0..scores.len()).map(|i| i as f32).sum();
        let sum_y: f32 = scores.iter().sum();
        let sum_xy: f32 = scores.iter().enumerate()
            .map(|(i, &y)| i as f32 * y)
            .sum();
        let sum_x2: f32 = (0..scores.len()).map(|i| (i as f32).powi(2)).sum();

        let slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x.powi(2));
        slope
    }

    /// Update scoring statistics
    fn update_stats(&mut self, risk_level: &RiskLevel, factors: &[String], processing_time: Duration) {
        self.stats.total_scores_calculated += 1;
        
        // Update average processing time
        let new_time_ms = processing_time.as_millis() as f64;
        let count = self.stats.total_scores_calculated as f64;
        self.stats.average_processing_time_ms = 
            (self.stats.average_processing_time_ms * (count - 1.0) + new_time_ms) / count;
        
        // Update risk level distribution
        let risk_key = format!("{:?}", risk_level);
        *self.stats.risk_level_distribution.entry(risk_key).or_insert(0) += 1;
        
        // Update common factors
        for factor in factors {
            *self.stats.common_factors.entry(factor.clone()).or_insert(0) += 1;
        }
    }

    /// Get threat history for a file
    pub fn get_threat_history(&self, file_hash: &str) -> Option<&ThreatHistory> {
        self.threat_history.get(file_hash)
    }

    /// Get scoring statistics
    pub fn get_stats(&self) -> &ThreatScoringStats {
        &self.stats
    }

    /// Clear old reputation cache entries
    pub fn cleanup_reputation_cache(&mut self, max_age: Duration) {
        let _now = SystemTime::now();
        self.reputation_cache.retain(|_, (_, timestamp)| {
            timestamp.elapsed().unwrap_or(Duration::from_secs(0)) < max_age
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn test_threat_scorer_creation() {
        let config = CorrelationConfig::default();
        let scorer = ThreatScorer::new(config);
        assert_eq!(scorer.config.confidence_threshold, 0.7);
    }

    #[test]
    fn test_risk_level_from_score() {
        assert_eq!(RiskLevel::from_score(10.0), RiskLevel::VeryLow);
        assert_eq!(RiskLevel::from_score(30.0), RiskLevel::Low);
        assert_eq!(RiskLevel::from_score(50.0), RiskLevel::Medium);
        assert_eq!(RiskLevel::from_score(70.0), RiskLevel::High);
        assert_eq!(RiskLevel::from_score(90.0), RiskLevel::Critical);
    }

    #[test]
    fn test_yara_score_calculation() {
        let config = CorrelationConfig::default();
        let scorer = ThreatScorer::new(config);
        
        let yara_matches = vec![
            YaraMatch {
                rule_name: "test_rule".to_string(),
                namespace: Some("test".to_string()),
                score: 0.8,
                matched_strings: vec![
                    MatchedString {
                        identifier: "str1".to_string(),
                        content: "test".to_string(),
                        offset: 0,
                        length: 4,
                    }
                ],
                metadata: HashMap::new(),
                timestamp: std::time::SystemTime::now(),
            }
        ];
        
        let score = scorer.calculate_yara_score(&yara_matches).unwrap();
        assert!(score > 0.0);
        assert!(score <= 100.0);
    }

    #[test]
    fn test_trend_slope_calculation() {
        let config = CorrelationConfig::default();
        let scorer = ThreatScorer::new(config);
        
        // Increasing trend
        let increasing_scores = vec![10.0, 20.0, 30.0, 40.0, 50.0];
        let slope = scorer.calculate_trend_slope(&increasing_scores);
        assert!(slope > 0.0);
        
        // Decreasing trend
        let decreasing_scores = vec![50.0, 40.0, 30.0, 20.0, 10.0];
        let slope = scorer.calculate_trend_slope(&decreasing_scores);
        assert!(slope < 0.0);
    }
}
