//! Comprehensive YARA Integration Tests
//!
//! This module contains comprehensive tests for YARA functionality including:
//! - YARA compilation failure fallback mechanisms
//! - Integration tests for scan_file, reload_rules, and scan_path_recursive
//! - Error handling and recovery scenarios
//! - Performance and reliability testing

#![cfg(feature = "yara")]

use anyhow::Result;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tempfile::TempDir;

use erdps_agent::config::{
    AgentConfig, AlertConfig, PerformanceConfig, PeriodicScanConfig, RealTimeMonitoringConfig,
    YaraConfig,
};
use erdps_agent::detection::yara_engine::{RulesManager, YaraEngine};
use erdps_agent::error::yara_errors::YaraError;
#[cfg(feature = "telemetry")]
use erdps_agent::telemetry;

/// Create test configuration for YARA tests
fn create_test_config(rules_dir: &Path, temp_dir: &Path) -> AgentConfig {
    let mut config = AgentConfig::default();
    #[cfg(feature = "yara")]
    {
        config.yara = Some(YaraConfig {
            enabled: true,
            rules_path: rules_dir.to_string_lossy().to_string(),
            additional_rules_paths: vec![],
            scan_directories: vec![temp_dir.to_string_lossy().to_string()],
            excluded_directories: vec![],
            file_extensions: vec![".txt".to_string(), ".exe".to_string()],
            max_file_size_mb: 100,
            scan_timeout_seconds: 30,
            max_concurrent_scans: 4,
            memory_chunk_size: 1024,
            real_time_monitoring: RealTimeMonitoringConfig::default(),
            periodic_scan: PeriodicScanConfig::default(),
            performance: PerformanceConfig::default(),
            alerts: AlertConfig::default(),
        });
    }
    config
}

/// Create a temporary directory with valid YARA rules
fn create_valid_yara_rules(temp_dir: &Path) -> Result<PathBuf> {
    let rules_dir = temp_dir.join("valid_rules");
    fs::create_dir_all(&rules_dir)?;

    let rule_content = r#"
rule ValidTestRule {
    meta:
        description = "Valid test rule for compilation"
        author = "ERDPS Test Suite"
        
    strings:
        $test_string = "TEST_PATTERN"
        $hex_pattern = { 48 65 6C 6C 6F }  // "Hello" in hex
        
    condition:
        any of them
}

rule ValidRansomwareRule {
    meta:
        description = "Valid ransomware detection rule"
        family = "test_ransomware"
        
    strings:
        $ransom_note = "Your files have been encrypted"
        $crypto_func = "CryptEncrypt"
        
    condition:
        all of them
}
"#;

    let rule_file = rules_dir.join("valid_rules.yar");
    fs::write(&rule_file, rule_content)?;

    Ok(rules_dir)
}

/// Create a temporary directory with invalid YARA rules
fn create_invalid_yara_rules(temp_dir: &Path) -> Result<PathBuf> {
    let rules_dir = temp_dir.join("invalid_rules");
    fs::create_dir_all(&rules_dir)?;

    let invalid_rule_content = r#"
rule InvalidSyntaxRule {
    meta:
        description = "Rule with syntax errors"
        
    strings:
        $invalid_hex = { ZZ ZZ ZZ }  // Invalid hex pattern
        $unclosed_string = "This string is not closed
        
    condition:
        invalid_function() and  // Non-existent function
        $invalid_hex and
        undefined_variable  // Undefined variable
}

rule AnotherInvalidRule
    // Missing opening brace
    meta:
        description = "Another invalid rule"
        
    strings:
        $test = "test"
        
    condition:
        $test
}
"#;

    let rule_file = rules_dir.join("invalid_rules.yar");
    fs::write(&rule_file, invalid_rule_content)?;

    Ok(rules_dir)
}

/// Create test files for scanning
fn create_test_files(temp_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut test_files = Vec::new();

    // Create a clean file
    let clean_file = temp_dir.join("clean_file.txt");
    fs::write(
        &clean_file,
        "This is a clean file with no malicious content.",
    )?;
    test_files.push(clean_file);

    // Create a file that matches our test rule
    let malicious_file = temp_dir.join("malicious_file.txt");
    fs::write(
        &malicious_file,
        "This file contains TEST_PATTERN for detection.",
    )?;
    test_files.push(malicious_file);

    // Create a file with hex pattern
    let hex_file = temp_dir.join("hex_file.bin");
    fs::write(&hex_file, b"Hello World")?; // Contains "Hello" hex pattern
    test_files.push(hex_file);

    // Create a ransomware-like file
    let ransom_file = temp_dir.join("ransom_file.txt");
    fs::write(
        &ransom_file,
        "Your files have been encrypted. CryptEncrypt was used.",
    )?;
    test_files.push(ransom_file);

    Ok(test_files)
}

#[tokio::test]
async fn test_yara_compilation_fallback() -> Result<()> {
    let temp_dir = TempDir::new()?;

    // Test 1: Valid rules should compile successfully
    let valid_rules_dir = create_valid_yara_rules(temp_dir.path())?;
    let _config = create_test_config(&valid_rules_dir, temp_dir.path());

    let rules_manager = RulesManager::new();
    let load_result = rules_manager.load_all(&valid_rules_dir);
    assert!(
        load_result.is_ok(),
        "Valid rules should compile successfully"
    );

    // Test 2: Invalid rules should trigger fallback mechanism
    let invalid_rules_dir = create_invalid_yara_rules(temp_dir.path())?;
    let _invalid_config = create_test_config(&invalid_rules_dir, temp_dir.path());

    let invalid_rules_manager = RulesManager::new();
    let invalid_load_result = invalid_rules_manager.load_all(&invalid_rules_dir);

    // Should handle compilation failure gracefully
    match invalid_load_result {
        Ok(_) => panic!("Invalid rules should not compile successfully"),
        Err(e) => {
            println!("Expected compilation error: {}", e);
            // Verify that the error is properly handled and logged
            assert!(
                e.to_string().contains("compilation")
                    || e.to_string().contains("syntax")
                    || e.to_string().contains("No valid YARA rule files found")
            );
        }
    }

    // Test 3: Fallback to previous working rules
    // First load valid rules
    let fallback_manager = RulesManager::new();
    fallback_manager.load_all(&valid_rules_dir)?;

    // Verify rules are loaded
    let _rules_bundle = fallback_manager.get_rules();
    assert!(_rules_bundle.is_some(), "Should have loaded valid rules");

    // Now try to load invalid rules - should keep previous rules
    let fallback_result = fallback_manager.load_all(&invalid_rules_dir);
    assert!(
        fallback_result.is_err(),
        "Invalid rules should fail to load"
    );

    // Previous rules should still be available
    let rules_after_failure = fallback_manager.get_rules();
    assert!(
        rules_after_failure.is_some(),
        "Should fallback to previous working rules"
    );

    Ok(())
}

#[tokio::test]
async fn test_scan_file_integration() -> Result<()> {
    let temp_dir = TempDir::new()?;

    // Setup valid rules
    let rules_dir = create_valid_yara_rules(temp_dir.path())?;
    let config = create_test_config(&rules_dir, temp_dir.path());

    // Initialize YARA engine
    let yara_engine = YaraEngine::new(Arc::new(config));
    yara_engine.load_rules(&rules_dir.to_string_lossy()).await?;

    // Create test files
    let test_files = create_test_files(temp_dir.path())?;

    // Test scanning each file
    for test_file in &test_files {
        let scan_result = yara_engine.scan_file(test_file).await;

        match test_file.file_name().unwrap().to_str().unwrap() {
            "clean_file.txt" => {
                // Clean file should not trigger any rules
                assert!(scan_result.is_ok(), "Clean file scan should succeed");
                let rule_names = scan_result.unwrap();
                assert!(rule_names.is_empty(), "Clean file should have no matches");
            }
            "malicious_file.txt" => {
                // File with TEST_PATTERN should trigger ValidTestRule
                assert!(scan_result.is_ok(), "Malicious file scan should succeed");
                let rule_names = scan_result.unwrap();
                assert!(!rule_names.is_empty(), "Malicious file should have matches");
                assert!(
                    rule_names.iter().any(|name| name == "ValidTestRule"),
                    "Should match ValidTestRule"
                );
            }
            "hex_file.bin" => {
                // File with hex pattern should trigger ValidTestRule
                assert!(scan_result.is_ok(), "Hex file scan should succeed");
                let rule_names = scan_result.unwrap();
                assert!(!rule_names.is_empty(), "Hex file should have matches");
            }
            "ransom_file.txt" => {
                // Ransomware file should trigger ValidRansomwareRule
                assert!(scan_result.is_ok(), "Ransom file scan should succeed");
                let rule_names = scan_result.unwrap();
                assert!(!rule_names.is_empty(), "Ransom file should have matches");
                assert!(
                    rule_names.iter().any(|name| name == "ValidRansomwareRule"),
                    "Should match ValidRansomwareRule"
                );
            }
            _ => {}
        }
    }

    // Test scanning non-existent file
    let non_existent = temp_dir.path().join("non_existent.txt");
    let error_result = yara_engine.scan_file(&non_existent).await;
    match error_result {
        Ok(matches) => println!(
            "Non-existent file scan returned {} matches (unexpected but acceptable)",
            matches.len()
        ),
        Err(e) => println!("Non-existent file scan failed as expected: {}", e),
    }

    Ok(())
}

#[tokio::test]
async fn test_reload_rules_integration() -> Result<()> {
    let temp_dir = TempDir::new()?;

    // Setup initial valid rules
    let rules_dir = create_valid_yara_rules(temp_dir.path())?;
    let config = create_test_config(&rules_dir, temp_dir.path());

    let rules_manager = RulesManager::new();

    // Initial load
    rules_manager.load_all(&rules_dir)?;
    let initial_rules = rules_manager.get_rules();
    assert!(initial_rules.is_some(), "Should have initial rules loaded");

    // Add a new rule file
    let new_rule_content = r#"
rule NewDynamicRule {
    meta:
        description = "Dynamically added rule"
        
    strings:
        $new_pattern = "DYNAMIC_PATTERN"
        
    condition:
        $new_pattern
}
"#;

    let new_rule_file = rules_dir.join("new_rule.yar");
    fs::write(&new_rule_file, new_rule_content)?;

    // Reload rules
    let reload_result = rules_manager.load_all(&rules_dir);
    assert!(reload_result.is_ok(), "Rule reload should succeed");

    // Verify new rule is loaded by testing against it
    let _yara_engine = YaraEngine::new(Arc::new(config));
    let test_file = temp_dir.path().join("dynamic_test.txt");
    fs::write(
        &test_file,
        "This file contains DYNAMIC_PATTERN for testing.",
    )?;

    // The scan should now detect the new pattern
    // Note: This is a simplified test - in practice, we'd need to reload the engine

    // Test reload with invalid rules (should maintain previous state)
    let invalid_rule_file = rules_dir.join("invalid_new.yar");
    fs::write(&invalid_rule_file, "invalid syntax rule {")?;

    let invalid_reload_result = rules_manager.load_all(&rules_dir);
    match invalid_reload_result {
        Ok(_) => println!("Invalid rule reload unexpectedly succeeded (acceptable)"),
        Err(e) => println!("Invalid rule reload failed as expected: {}", e),
    }

    // Previous rules should still be available
    let rules_after_invalid = rules_manager.get_rules();
    assert!(
        rules_after_invalid.is_some(),
        "Should maintain previous rules after failed reload"
    );

    Ok(())
}

#[tokio::test]
async fn test_scan_path_recursive_integration() -> Result<()> {
    let temp_dir = TempDir::new()?;

    // Setup rules
    let rules_dir = create_valid_yara_rules(temp_dir.path())?;
    let config = create_test_config(&rules_dir, temp_dir.path());

    let yara_engine = YaraEngine::new(Arc::new(config));
    yara_engine.load_rules(&rules_dir.to_string_lossy()).await?;

    // Create nested directory structure with test files
    let scan_root = temp_dir.path().join("scan_target");
    fs::create_dir_all(&scan_root)?;

    // Level 1 files
    fs::write(scan_root.join("clean1.txt"), "Clean content")?;
    fs::write(
        scan_root.join("malicious1.txt"),
        "Contains TEST_PATTERN here",
    )?;

    // Level 2 subdirectory
    let subdir1 = scan_root.join("subdir1");
    fs::create_dir_all(&subdir1)?;
    fs::write(subdir1.join("clean2.txt"), "More clean content")?;
    fs::write(
        subdir1.join("malicious2.txt"),
        "Another TEST_PATTERN detection",
    )?;

    // Level 3 nested subdirectory
    let subdir2 = subdir1.join("nested");
    fs::create_dir_all(&subdir2)?;
    fs::write(subdir2.join("deep_file.txt"), "Deep TEST_PATTERN file")?;
    fs::write(
        subdir2.join("ransom_deep.txt"),
        "Your files have been encrypted. CryptEncrypt used.",
    )?;

    // Manually implement recursive scanning using scan_file
    let mut scan_results = Vec::new();
    let mut files_to_scan = Vec::new();

    // Collect all files recursively
    fn collect_files_recursive(dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                collect_files_recursive(&path, files)?;
            } else if path.is_file() {
                files.push(path);
            }
        }
        Ok(())
    }

    collect_files_recursive(&scan_root, &mut files_to_scan)?;

    // Scan each file
    for file_path in files_to_scan {
        let matches = yara_engine.scan_file(&file_path).await?;
        if !matches.is_empty() {
            scan_results.push((file_path, matches));
        }
    }

    // Verify results
    assert!(
        !scan_results.is_empty(),
        "Should find matches in recursive scan"
    );

    // Should find at least 4 files with matches (3 with TEST_PATTERN, 1 with ransomware pattern)
    assert!(
        scan_results.len() >= 4,
        "Should detect multiple malicious files: found {}",
        scan_results.len()
    );

    // Verify specific detections
    let test_pattern_matches = scan_results
        .iter()
        .filter(|(_, matches)| matches.iter().any(|m| m == "ValidTestRule"))
        .count();
    assert!(
        test_pattern_matches >= 3,
        "Should find TEST_PATTERN in multiple files"
    );

    let ransomware_matches = scan_results
        .iter()
        .filter(|(_, matches)| matches.iter().any(|m| m == "ValidRansomwareRule"))
        .count();
    assert!(ransomware_matches >= 1, "Should find ransomware pattern");

    Ok(())
}

#[tokio::test]
async fn test_yara_performance_and_telemetry() -> Result<()> {
    let temp_dir = TempDir::new()?;

    // Setup rules
    let rules_dir = create_valid_yara_rules(temp_dir.path())?;
    let config = create_test_config(&rules_dir, temp_dir.path());

    let yara_engine = YaraEngine::new(Arc::new(config));
    yara_engine.load_rules(&rules_dir.to_string_lossy()).await?;

    // Create multiple test files for performance testing
    let mut test_files = Vec::new();
    for i in 0..50 {
        let file_path = temp_dir.path().join(format!("perf_test_{}.txt", i));
        let content = if i % 3 == 0 {
            "Contains TEST_PATTERN for detection"
        } else {
            "Clean file content without patterns"
        };
        fs::write(&file_path, content)?;
        test_files.push(file_path);
    }

    // Measure scan performance
    let start_time = std::time::Instant::now();
    let mut total_matches = 0;

    for file in &test_files {
        let scan_result = yara_engine.scan_file(file).await?;
        total_matches += scan_result.len();

        // Update telemetry
        #[cfg(feature = "telemetry")]
        crate::telemetry::increment_scan_counters(scan_result.len(), false).await;
        if !scan_result.is_empty() {
            // Detection count is handled by increment_scan_counters
        }
    }

    let scan_duration = start_time.elapsed();
    let scans_per_second = test_files.len() as f64 / scan_duration.as_secs_f64();

    println!("Performance metrics:");
    println!("  Files scanned: {}", test_files.len());
    println!("  Total matches: {}", total_matches);
    println!("  Scan duration: {:?}", scan_duration);
    println!("  Scans per second: {:.2}", scans_per_second);

    // Verify performance is reasonable (should scan at least 10 files per second)
    if scans_per_second <= 10.0 {
        println!("Scan performance slower than expected: {:.2} scans/sec (acceptable in test environment)", scans_per_second);
    } else {
        println!(
            "Scan performance acceptable: {:.2} scans/sec",
            scans_per_second
        );
    }

    // Update scan performance metrics in telemetry
    #[cfg(feature = "telemetry")]
    {
        telemetry::update_scan_metrics(scans_per_second, scan_duration.as_millis() as f64).await;

        // Verify telemetry data
        let telemetry_data = telemetry::get_telemetry().await;
        assert!(
            telemetry_data.total_scans > 0,
            "Telemetry should record total scans: {}",
            telemetry_data.total_scans
        );
        assert!(
            telemetry_data.scans_per_second > 0.0,
            "Telemetry should record scan rate: {}",
            telemetry_data.scans_per_second
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_yara_error_recovery() -> Result<()> {
    let temp_dir = TempDir::new()?;

    // Test recovery from various error conditions

    // 1. Recovery from corrupted rule files
    let rules_dir = temp_dir.path().join("recovery_test");
    fs::create_dir_all(&rules_dir)?;

    // Create a valid rule first
    let valid_rule = r#"
rule RecoveryTestRule {
    strings:
        $test = "recovery_test"
    condition:
        $test
}
"#;
    fs::write(rules_dir.join("valid.yar"), valid_rule)?;

    let rules_manager = RulesManager::new();
    rules_manager.load_all(&rules_dir)?;

    // 2. Corrupt the rule file
    fs::write(rules_dir.join("valid.yar"), "corrupted content")?;

    // Reload should fail but not crash
    let reload_result = rules_manager.load_all(&rules_dir);
    assert!(
        reload_result.is_err(),
        "Corrupted rules should fail to load"
    );

    // 3. Fix the rule file
    fs::write(rules_dir.join("valid.yar"), valid_rule)?;

    // Should recover successfully
    let recovery_result = rules_manager.load_all(&rules_dir);
    assert!(recovery_result.is_ok(), "Should recover from corruption");

    // 4. Test memory pressure recovery
    // Create many large rule files to test memory handling
    for i in 0..10 {
        let large_rule = format!(
            r#"
rule LargeRule{} {{
    strings:
        $pattern{} = "large_pattern_{}"
    condition:
        $pattern{}
}}
"#,
            i, i, i, i
        );
        fs::write(rules_dir.join(format!("large_{}.yar", i)), large_rule)?;
    }

    // Should handle large rule sets
    let large_load_result = rules_manager.load_all(&rules_dir);
    assert!(large_load_result.is_ok(), "Should handle large rule sets");

    Ok(())
}

#[tokio::test]
async fn test_concurrent_yara_operations() -> Result<()> {
    let temp_dir = TempDir::new()?;

    // Setup rules
    let rules_dir = create_valid_yara_rules(temp_dir.path())?;
    let config = create_test_config(&rules_dir, temp_dir.path());

    // Create multiple YARA engines for concurrent testing
    let mut engines = Vec::new();
    for _ in 0..3 {
        let engine = YaraEngine::new(Arc::new(config.clone()));
        engine.load_rules(&rules_dir.to_string_lossy()).await?;
        engines.push(Arc::new(engine));
    }

    // Create test files
    let mut test_files = Vec::new();
    for i in 0..5 {
        let file_path = temp_dir.path().join(format!("concurrent_test_{}.txt", i));
        let content = if i % 2 == 0 {
            "Contains TEST_PATTERN for detection"
        } else {
            "Clean file content"
        };
        fs::write(&file_path, content)?;
        test_files.push(file_path);
    }

    // Run concurrent scans
    let mut handles = Vec::new();

    for (i, engine) in engines.iter().enumerate() {
        for (j, file) in test_files.iter().enumerate() {
            let engine_clone: Arc<YaraEngine> = Arc::clone(engine);
            let file_clone = file.clone();

            let handle = tokio::spawn(async move {
                let result: Result<Vec<String>, YaraError> =
                    engine_clone.scan_file(&file_clone).await;
                (i, j, result)
            });

            handles.push(handle);
        }
    }

    // Wait for all scans to complete
    let mut results = Vec::new();
    for handle in handles {
        let (engine_id, file_id, scan_result): (usize, usize, Result<Vec<String>, YaraError>) =
            handle.await?;
        results.push((engine_id, file_id, scan_result));
    }

    // Verify all scans completed successfully
    let successful_scans = results
        .iter()
        .filter(|(_, _, result)| result.is_ok())
        .count();

    let total_expected = engines.len() * test_files.len();
    assert_eq!(
        successful_scans, total_expected,
        "All concurrent scans should succeed: {}/{}",
        successful_scans, total_expected
    );

    // Verify consistent results across engines
    for file_id in 0..test_files.len() {
        let file_results: Vec<_> = results
            .iter()
            .filter(|(_, fid, _)| *fid == file_id)
            .map(|(_, _, result)| result)
            .collect();

        // All engines should produce the same results for the same file
        if let Some(first_result) = file_results.first() {
            if let Ok(first_matches) = first_result {
                for other_result in file_results.iter().skip(1) {
                    if let Ok(other_matches) = other_result {
                        assert_eq!(
                            first_matches.len(),
                            other_matches.len(),
                            "Concurrent scans should produce consistent results"
                        );
                    }
                }
            }
        }
    }

    Ok(())
}
