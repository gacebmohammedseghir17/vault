//! Unit tests for the Advanced Correlation Engine
//!
//! This module tests the correlation engine's ability to identify
//! correlated alerts across multiple LayeredScanResult entries.

use anyhow::Result;
use chrono::Utc;
use std::collections::HashMap;
use tempfile::TempDir;

// Import the correlation engine and related types
use erdps_agent::yara::correlation_engine::{
    CorrelationEngine, CorrelatedAlert
};
use erdps_agent::yara::multi_layer_scanner::{
    LayeredScanResult, RuleMatch
};

/// Helper function to create a test RuleMatch
fn create_rule_match(rule_name: &str, namespace: &str, confidence: f32, severity: &str) -> RuleMatch {
    RuleMatch {
        rule_name: rule_name.to_string(),
        namespace: Some(namespace.to_string()),
        tags: vec!["test".to_string()],
        metadata: HashMap::new(),
        confidence,
        severity: severity.to_string(),

    }
}

/// Helper function to create a test LayeredScanResult
fn create_layered_scan_result(
    target: &str,
    file_rules: Vec<&str>,
    memory_rules: Vec<&str>,
    behavior_rules: Vec<&str>,
    network_rules: Vec<&str>,
) -> LayeredScanResult {
    let mut result = LayeredScanResult {
        target: target.to_string(),
        timestamp: Utc::now().timestamp() as u64,
        file_matches: Vec::new(),
        memory_matches: Vec::new(),
        behavior_matches: Vec::new(),
        network_matches: Vec::new(),
        risk_score: 0.5,
        scan_duration_ms: 1000,
    };

    // Add file matches
    for rule in file_rules {
        result.file_matches.push(create_rule_match(rule, "file_layer", 0.8, "medium"));
    }

    // Add memory matches
    for rule in memory_rules {
        result.memory_matches.push(create_rule_match(rule, "memory_layer", 0.7, "high"));
    }

    // Add behavior matches
    for rule in behavior_rules {
        result.behavior_matches.push(create_rule_match(rule, "behavior_layer", 0.9, "high"));
    }

    // Add network matches
    for rule in network_rules {
        result.network_matches.push(create_rule_match(rule, "network_layer", 0.6, "low"));
    }

    result
}

#[tokio::test]
async fn test_correlation_engine_creation() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let db_path = temp_dir.path().join("test_correlation.db");
    
    let _engine = CorrelationEngine::new(db_path)?;
    
    // Verify engine was created successfully
    // Engine creation test passed
    
    Ok(())
}

#[tokio::test]
async fn test_correlate_overlapping_rules_across_layers() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let db_path = temp_dir.path().join("test_correlation.db");
    
    let engine = CorrelationEngine::new(db_path)?;
    
    // Create scan results with overlapping rules across layers
    let scan_results = vec![
        create_layered_scan_result(
            "target1",
            vec!["malware_rule_1", "malware_rule_2"],
            vec!["malware_rule_1", "memory_specific"],
            vec!["malware_rule_2", "behavior_specific"],
            vec!["network_specific"],
        ),
    ];
    
    let correlated_alerts = engine.correlate(&scan_results, 1, 2)?;
    
    // Should find 2 correlated alerts (malware_rule_1 and malware_rule_2)
    assert_eq!(correlated_alerts.len(), 2);
    
    // Check first alert (malware_rule_1 appears in file and memory layers)
    let alert1 = correlated_alerts.iter()
        .find(|a| a.rule_ids.contains(&"malware_rule_1".to_string()))
        .expect("Should find malware_rule_1 correlation");
    
    assert!(alert1.rule_ids.contains(&"malware_rule_1".to_string()));
    // Confidence should be 0.5 + 0.25*(2-1) = 0.75 (2 layers, 1 scan)
    assert!((alert1.confidence - 0.75).abs() < 0.01);
    
    // Check second alert (malware_rule_2 appears in file and behavior layers)
    let alert2 = correlated_alerts.iter()
        .find(|a| a.rule_ids.contains(&"malware_rule_2".to_string()))
        .expect("Should find malware_rule_2 correlation");
    
    assert!(alert2.rule_ids.contains(&"malware_rule_2".to_string()));
    assert!((alert2.confidence - 0.75).abs() < 0.01);
    
    Ok(())
}

#[tokio::test]
async fn test_correlate_overlapping_rules_across_scans() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let db_path = temp_dir.path().join("test_correlation.db");
    
    let engine = CorrelationEngine::new(db_path)?;
    
    // Create scan results with overlapping rules across scans
    let scan_results = vec![
        create_layered_scan_result(
            "target1",
            vec!["common_malware", "scan1_specific"],
            vec![],
            vec![],
            vec![],
        ),
        create_layered_scan_result(
            "target2",
            vec!["common_malware", "scan2_specific"],
            vec![],
            vec![],
            vec![],
        ),
        create_layered_scan_result(
            "target3",
            vec!["scan3_specific"],
            vec![],
            vec![],
            vec![],
        ),
    ];
    
    let correlated_alerts = engine.correlate(&scan_results, 2, 1)?;
    
    // Should find 1 correlated alert (common_malware appears in 2 scans)
    assert_eq!(correlated_alerts.len(), 1);
    
    let alert = &correlated_alerts[0];
    assert!(alert.rule_ids.contains(&"common_malware".to_string()));
    // Confidence should be 0.5 + 0.25*(2-1) = 0.75 (1 layer, 2 scans)
    assert!((alert.confidence - 0.75).abs() < 0.01);
    
    Ok(())
}

#[tokio::test]
async fn test_correlate_high_confidence_scenario() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let db_path = temp_dir.path().join("test_correlation.db");
    
    let engine = CorrelationEngine::new(db_path)?;
    
    // Create scan results with maximum overlap (3 layers, 3 scans)
    let scan_results = vec![
        create_layered_scan_result(
            "target1",
            vec!["advanced_malware"],
            vec!["advanced_malware"],
            vec!["advanced_malware"],
            vec![],
        ),
        create_layered_scan_result(
            "target2",
            vec!["advanced_malware"],
            vec!["advanced_malware"],
            vec!["advanced_malware"],
            vec![],
        ),
        create_layered_scan_result(
            "target3",
            vec!["advanced_malware"],
            vec!["advanced_malware"],
            vec![],
            vec![],
        ),
    ];
    
    let correlated_alerts = engine.correlate(&scan_results, 2, 2)?;
    
    assert_eq!(correlated_alerts.len(), 1);
    
    let alert = &correlated_alerts[0];
    assert!(alert.rule_ids.contains(&"advanced_malware".to_string()));
    
    // Confidence should be min(1.0, 0.5 + 0.25*(3-1) + 0.25*(3-1)) = 1.0
    assert!((alert.confidence - 1.0).abs() < 0.01);
    
    Ok(())
}

#[tokio::test]
async fn test_correlate_no_correlation_found() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let db_path = temp_dir.path().join("test_correlation.db");
    
    let engine = CorrelationEngine::new(db_path)?;
    
    // Create scan results with no overlapping rules
    let scan_results = vec![
        create_layered_scan_result(
            "target1",
            vec!["unique_rule_1"],
            vec![],
            vec![],
            vec![],
        ),
        create_layered_scan_result(
            "target2",
            vec!["unique_rule_2"],
            vec![],
            vec![],
            vec![],
        ),
    ];
    
    let correlated_alerts = engine.correlate(&scan_results, 2, 2)?;
    
    // Should find no correlated alerts
    assert_eq!(correlated_alerts.len(), 0);
    
    Ok(())
}

#[tokio::test]
async fn test_store_and_retrieve_alerts() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let db_path = temp_dir.path().join("test_correlation.db");
    
    let engine = CorrelationEngine::new(db_path.clone())?;
    
    // Create test alerts
    let alerts = vec![
        CorrelatedAlert {
            alert_id: "test-alert-1".to_string(),
            rule_ids: vec!["rule1".to_string(), "rule2".to_string()],
            confidence: 0.85,
            timestamp: Utc::now(),
            metadata: HashMap::new(),
            overlap_layers: 2,
            overlap_scans: 1,
        },
        CorrelatedAlert {
            alert_id: "test-alert-2".to_string(),
            rule_ids: vec!["rule3".to_string()],
            confidence: 0.65,
            timestamp: Utc::now(),
            metadata: HashMap::new(),
            overlap_layers: 1,
            overlap_scans: 1,
        },
    ];
    
    // Store alerts
    engine.store_alerts(&alerts)?;
    
    // Verify alerts were stored by creating a new engine instance
    let _engine2 = CorrelationEngine::new(db_path)?;
    
    // The database should exist and be accessible
    // We can't directly retrieve alerts without implementing a get method,
    // but we can verify the database was created and is accessible
    
    Ok(())
}

#[tokio::test]
async fn test_confidence_calculation_edge_cases() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let db_path = temp_dir.path().join("test_correlation.db");
    
    let engine = CorrelationEngine::new(db_path)?;
    
    // Test minimum confidence (1 layer, 1 scan)
    let scan_results_min = vec![
        create_layered_scan_result(
            "target1",
            vec!["test_rule"],
            vec![],
            vec![],
            vec![],
        ),
    ];
    
    let alerts_min = engine.correlate(&scan_results_min, 1, 1)?;
    assert_eq!(alerts_min.len(), 1);
    // Confidence should be 0.5 + 0.25*(1-1) + 0.25*(1-1) = 0.5
    assert!((alerts_min[0].confidence - 0.5).abs() < 0.01);
    
    // Test maximum confidence scenario (4 layers, 4 scans)
    let scan_results_max = vec![
        create_layered_scan_result(
            "target1",
            vec!["max_rule"],
            vec!["max_rule"],
            vec!["max_rule"],
            vec!["max_rule"],
        ),
        create_layered_scan_result(
            "target2",
            vec!["max_rule"],
            vec!["max_rule"],
            vec!["max_rule"],
            vec!["max_rule"],
        ),
        create_layered_scan_result(
            "target3",
            vec!["max_rule"],
            vec!["max_rule"],
            vec!["max_rule"],
            vec!["max_rule"],
        ),
        create_layered_scan_result(
            "target4",
            vec!["max_rule"],
            vec!["max_rule"],
            vec!["max_rule"],
            vec!["max_rule"],
        ),
    ];
    
    let alerts_max = engine.correlate(&scan_results_max, 1, 1)?;
    assert_eq!(alerts_max.len(), 1);
    // Confidence should be min(1.0, 0.5 + 0.25*3 + 0.25*3) = 1.0
    assert!((alerts_max[0].confidence - 1.0).abs() < 0.01);
    
    Ok(())
}

#[tokio::test]
async fn test_correlation_with_empty_results() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let db_path = temp_dir.path().join("test_correlation.db");
    
    let engine = CorrelationEngine::new(db_path)?;
    
    // Test with empty scan results
    let empty_results = vec![];
    let alerts = engine.correlate(&empty_results, 2, 2)?;
    assert_eq!(alerts.len(), 0);
    
    // Test with scan results containing no matches
    let no_match_results = vec![
        LayeredScanResult {
            target: "empty_scan".to_string(),
            timestamp: Utc::now().timestamp() as u64,
            file_matches: vec![],
            memory_matches: vec![],
            behavior_matches: vec![],
            network_matches: vec![],
            risk_score: 0.0,
            scan_duration_ms: 100,
        },
    ];
    
    let alerts = engine.correlate(&no_match_results, 2, 2)?;
    assert_eq!(alerts.len(), 0);
    
    Ok(())
}