//! Memory Forensics Feature Extractor
//!
//! This module provides feature extraction capabilities for memory forensics analysis.

use super::{
    forensics_engine::MemoryForensicsResult,
    integrated_analyzer::MemoryForensicsFeatures,
};
use anyhow::Result;
use std::collections::HashMap;

/// Memory forensics feature extractor
#[derive(Debug, Clone)]
pub struct MemoryForensicsFeatureExtractor {
    feature_weights: HashMap<String, f64>,
}

impl MemoryForensicsFeatureExtractor {
    /// Create a new feature extractor
    pub fn new() -> Self {
        let mut feature_weights = HashMap::new();
        feature_weights.insert("injection_count".to_string(), 1.0);
        feature_weights.insert("shellcode_count".to_string(), 0.8);
        feature_weights.insert("high_entropy_regions".to_string(), 0.6);
        feature_weights.insert("critical_threats".to_string(), 1.0);
        
        Self {
            feature_weights,
        }
    }
    
    /// Extract features from memory forensics results
    pub fn extract_features(&self, results: &[MemoryForensicsResult]) -> Result<MemoryForensicsFeatures> {
        if results.is_empty() {
            return Ok(MemoryForensicsFeatures::default());
        }
        
        let mut injection_count = 0.0;
        let mut shellcode_count = 0.0;
        let mut high_entropy_regions = 0.0;
        let mut critical_threats = 0.0;
        let mut anomaly_indicators = Vec::new();
        
        for result in results {
            // Count threat indicators by type
            for indicator in &result.threat_indicators {
                match indicator.indicator_type.as_str() {
                    "Process Injection" => injection_count += 1.0,
                    "Shellcode Detection" => shellcode_count += 1.0,
                    _ => {}
                }
                
                if indicator.confidence > 0.8 {
                    critical_threats += 1.0;
                }
                
                anomaly_indicators.push(format!("{}: {}", 
                    indicator.indicator_type, 
                    indicator.description));
            }
            
            // Count high entropy regions
            for region in &result.suspicious_regions {
                if region.entropy > 7.0 {
                    high_entropy_regions += 1.0;
                }
            }
        }
        
        Ok(MemoryForensicsFeatures {
            feature_count: results.len(),
            anomaly_indicators,
            injection_count,
            shellcode_count,
            high_entropy_regions,
            avg_entropy_regions: high_entropy_regions / results.len() as f64,
            critical_threats,
        })
    }
}

impl Default for MemoryForensicsFeatureExtractor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::forensics_engine::{MemoryForensicsResult, ThreatIndicator, ThreatSeverity, SuspiciousMemoryRegion};
    use crate::memory::MemoryAnalysisResult;
    use std::time::{Duration, SystemTime};
    use uuid::Uuid;
    
    fn create_test_result() -> MemoryForensicsResult {
        MemoryForensicsResult {
            analysis_id: Uuid::new_v4(),
            timestamp: SystemTime::now(),
            process_id: 1234,
            process_name: "test.exe".to_string(),
            analysis_duration: Duration::from_millis(100),
            memory_analysis: MemoryAnalysisResult {
                entropy_scores: std::collections::HashMap::new(),
                suspicious_regions: Vec::new(),
                detected_patterns: Vec::new(),
                confidence_score: 0.8,
            },
            threat_indicators: vec![
                ThreatIndicator {
                    indicator_type: "Process Injection".to_string(),
                    description: "Test injection".to_string(),
                    severity: ThreatSeverity::Critical,
                    confidence: 0.9,
                    memory_address: 0x12345678,
                    evidence: vec!["Test evidence".to_string()],
                },
            ],
            recommended_actions: Vec::new(),
            suspicious_regions: vec![
                SuspiciousMemoryRegion {
                    address: 0x12345678,
                    size: 4096,
                    entropy: 7.5,
                    permissions: "RWX".to_string(),
                    detected_patterns: vec!["test_pattern".to_string()],
                },
            ],
            total_memory_scanned: 1048576,
            scan_duration: Duration::from_millis(100),
        }
    }
    
    #[test]
    fn test_feature_extraction() {
        let extractor = MemoryForensicsFeatureExtractor::new();
        let results = vec![create_test_result()];
        
        let features = extractor.extract_features(&results).unwrap();
        
        assert_eq!(features.feature_count, 1);
        assert_eq!(features.injection_count, 1.0);
        assert_eq!(features.high_entropy_regions, 1.0);
        assert_eq!(features.critical_threats, 1.0);
        assert!(!features.anomaly_indicators.is_empty());
    }
    
    #[test]
    fn test_empty_results() {
        let extractor = MemoryForensicsFeatureExtractor::new();
        let results = vec![];
        
        let features = extractor.extract_features(&results).unwrap();
        
        assert_eq!(features.feature_count, 0);
        assert_eq!(features.injection_count, 0.0);
        assert_eq!(features.shellcode_count, 0.0);
        assert_eq!(features.high_entropy_regions, 0.0);
        assert_eq!(features.critical_threats, 0.0);
        assert!(features.anomaly_indicators.is_empty());
    }
}
