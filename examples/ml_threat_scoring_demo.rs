//! Demo of ML Threat Scoring functionality
//! This example demonstrates how to use threat scoring concepts
//! Note: The actual ML threat scoring module was removed from production

// use erdps_agent::yara::ml_threat_scoring::ThreatScorer; // Removed from production
use erdps_agent::yara::multi_layer_scanner::RuleMatch;
use std::collections::HashMap;

/// Mock threat score structure for demonstration
#[derive(Debug, Clone)]
pub struct ThreatScore {
    pub rule_id: String,
    pub score: f32,
    pub label: String,
}

/// Mock threat scorer for demonstration purposes
pub struct MockThreatScorer {
    // In a real implementation, this would contain ML models
}

impl MockThreatScorer {
    pub fn new() -> Self {
        Self {}
    }

    /// Mock scoring function that demonstrates the concept
    pub fn score_matches(&self, matches: &[RuleMatch]) -> Vec<ThreatScore> {
        matches
            .iter()
            .map(|rule_match| {
                // Mock scoring logic based on rule characteristics
                let base_score = rule_match.confidence;
                let severity_multiplier = match rule_match.severity.as_str() {
                    "high" => 1.2,
                    "medium" => 1.0,
                    "low" => 0.8,
                    _ => 1.0,
                };
                
                let tag_bonus = if rule_match.tags.contains(&"malware".to_string()) {
                    0.2
                } else if rule_match.tags.contains(&"suspicious".to_string()) {
                    0.1
                } else {
                    0.0
                };

                let final_score = (base_score * severity_multiplier + tag_bonus).min(1.0);

                let label = if final_score >= 0.8 {
                    "high".to_string()
                } else if final_score >= 0.5 {
                    "medium".to_string()
                } else {
                    "low".to_string()
                };

                ThreatScore {
                    rule_id: rule_match.rule_name.clone(),
                    score: final_score,
                    label,
                }
            })
            .collect()
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    env_logger::init();

    println!("ML Threat Scoring Demo (Mock Implementation)");
    println!("============================================");
    println!("Note: This is a demonstration using mock scoring logic.");
    println!("The actual ML threat scoring module was removed from production.\n");

    // Create a mock threat scorer
    let scorer = MockThreatScorer::new();

    // Create some sample rule matches
    let matches = create_sample_matches();

    println!("Scoring {} rule matches...", matches.len());

    // Score the matches
    let scores = scorer.score_matches(&matches);

    // Display results
    println!("\nThreat Scoring Results:");
    println!("-----------------------");
    for score in &scores {
        println!(
            "Rule: {} | Score: {:.3} | Label: {}",
            score.rule_id, score.score, score.label
        );
    }

    println!("\nDemo completed successfully!");
    println!("This demonstrates the concept of ML-based threat scoring.");
    println!("In a production environment, this would use trained ML models.");

    Ok(())
}

fn create_sample_matches() -> Vec<RuleMatch> {
    vec![
        RuleMatch {
            rule_name: "suspicious_api_calls".to_string(),
            namespace: Some("malware".to_string()),
            tags: vec!["api".to_string(), "suspicious".to_string()],
            metadata: {
                let mut map = HashMap::new();
                map.insert("api_count".to_string(), "15".to_string());
                map.insert("entropy".to_string(), "7.2".to_string());
                map.insert(
                    "description".to_string(),
                    "Detects suspicious Windows API calls".to_string(),
                );
                map
            },
            confidence: 0.85,
            severity: "high".to_string(),
        },
        RuleMatch {
            rule_name: "packed_executable".to_string(),
            namespace: Some("packer".to_string()),
            tags: vec!["packer".to_string(), "upx".to_string()],
            metadata: {
                let mut map = HashMap::new();
                map.insert("packer_type".to_string(), "UPX".to_string());
                map.insert("compression_ratio".to_string(), "0.3".to_string());
                map.insert(
                    "description".to_string(),
                    "Detects packed or obfuscated executables".to_string(),
                );
                map
            },
            confidence: 0.72,
            severity: "medium".to_string(),
        },
        RuleMatch {
            rule_name: "registry_persistence".to_string(),
            namespace: Some("persistence".to_string()),
            tags: vec!["registry".to_string(), "persistence".to_string()],
            metadata: {
                let mut map = HashMap::new();
                map.insert(
                    "registry_key".to_string(),
                    "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(),
                );
                map.insert("value_name".to_string(), "SystemUpdate".to_string());
                map.insert(
                    "description".to_string(),
                    "Detects registry-based persistence mechanisms".to_string(),
                );
                map
            },
            confidence: 0.65,
            severity: "medium".to_string(),
        },
    ]
}
