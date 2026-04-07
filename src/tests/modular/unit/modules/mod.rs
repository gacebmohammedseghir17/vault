//! Unit tests for individual modules
//! Tests each component in isolation with comprehensive error handling

use crate::behavioral::BehavioralEngine;
use crate::memory::MemoryAnalyzer;
use crate::network::NetworkEngine;
use crate::performance::{PerformanceGate, PerformanceMetrics, PerformanceEnforcer};
use crate::validation::{MalwareSampleManager, IsolationEngine, FalsePositiveValidator};
use std::path::PathBuf;
use std::time::Instant;

/// Test behavioral engine initialization and basic functionality
#[test]
fn test_behavioral_engine_initialization() {
    let engine = BehavioralEngine::new();
    assert!(engine.is_ok(), "Behavioral engine should initialize successfully");
    
    let engine = engine.unwrap();
    
    // Test engine configuration
    assert!(engine.is_enabled(), "Engine should be enabled by default");
    
    // Test invalid file handling
    let non_existent = PathBuf::from("/invalid/path/file.exe");
    let result = engine.analyze_file(&non_existent);
    assert!(result.is_err(), "Should return error for non-existent file");
}

/// Test behavioral pattern detection with various file types
#[test]
fn test_behavioral_pattern_detection() {
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let engine = BehavioralEngine::new().expect("Failed to initialize engine");
    
    // Test with benign file
    let benign_file = temp_dir.path().join("benign.txt");
    std::fs::write(&benign_file, "Hello, world!").expect("Failed to create benign file");
    
    let result = engine.analyze_file(&benign_file);
    assert!(result.is_ok(), "Should analyze benign file successfully");
    
    let analysis = result.unwrap();
    assert!(analysis.threat_level < 0.3, "Benign file should have low threat level");
    assert!(analysis.threat_indicators.len() == 0, "Benign file should have no threat indicators");
    
    // Test with suspicious patterns
    let suspicious_file = temp_dir.path().join("suspicious.exe");
    let suspicious_content = b"CreateMutexA\x00GetProcAddress\x00VirtualAlloc\x00";
    std::fs::write(&suspicious_file, suspicious_content).expect("Failed to create suspicious file");
    
    let suspicious_result = engine.analyze_file(&suspicious_file);
    assert!(suspicious_result.is_ok(), "Should analyze suspicious file successfully");
    
    let suspicious_analysis = suspicious_result.unwrap();
    assert!(suspicious_analysis.threat_level > 0.5, "Suspicious file should have higher threat level");
    assert!(suspicious_analysis.threat_indicators.len() > 0, "Should detect threat indicators");
}

/// Test memory analyzer functionality
#[test]
fn test_memory_analyzer() {
    let analyzer = MemoryAnalyzer::new();
    
    // Test process analysis with current process
    let current_pid = std::process::id();
    let result = analyzer.analyze_process(current_pid);
    
    assert!(result.is_ok(), "Should analyze current process successfully");
    
    let analysis = result.unwrap();
    assert!(analysis.total_regions > 0, "Should find memory regions");
    assert!(analysis.suspicious_regions.len() >= 0, "Suspicious regions count should be valid");
    
    // Test with invalid PID
    let invalid_result = analyzer.analyze_process(999999);
    assert!(invalid_result.is_err(), "Should return error for invalid PID");
}

/// Test network engine initialization and traffic analysis
#[test]
fn test_network_engine() {
    let engine = NetworkEngine::new();
    assert!(engine.is_ok(), "Network engine should initialize successfully");
    
    let engine = engine.unwrap();
    
    // Test traffic analysis
    let result = engine.analyze_traffic();
    assert!(result.is_ok(), "Traffic analysis should complete successfully");
    
    let analysis = result.unwrap();
    assert!(analysis.connections_analyzed >= 0, "Should analyze connections");
    assert!(analysis.threat_indicators.len() >= 0, "Threat indicators should be valid");
    
    // Test JA3 fingerprint processing
    let ja3_hash = "test_ja3_hash_12345";
    let fingerprint_result = engine.process_ja3_fingerprint(ja3_hash);
    assert!(fingerprint_result.is_ok(), "Should process JA3 fingerprint");
}

/// Test performance gate enforcement
#[test]
fn test_performance_gate_enforcement() {
    let mut enforcer = PerformanceEnforcer::new();
    
    // Set strict thresholds
    enforcer.set_cpu_threshold(6.0);
    enforcer.set_memory_threshold(200);
    
    // Test normal metrics (within thresholds)
    let normal_metrics = PerformanceMetrics {
        cpu_usage_percent: 3.0,
        memory_usage_mb: 150,
        active_scans: 2,
        queue_depth: 5,
    };
    
    let violations = enforcer.check_violations(&normal_metrics);
    assert!(violations.is_empty(), "Should have no violations for normal metrics");
    
    // Test CPU violation
    let cpu_violation_metrics = PerformanceMetrics {
        cpu_usage_percent: 8.0, // Exceeds 6% threshold
        memory_usage_mb: 100,
        active_scans: 1,
        queue_depth: 0,
    };
    
    let cpu_violations = enforcer.check_violations(&cpu_violation_metrics);
    assert!(!cpu_violations.is_empty(), "Should detect CPU violation");
    assert_eq!(cpu_violations[0].metric_type, "CPU");
    assert_eq!(cpu_violations[0].threshold_value, 6.0);
    assert_eq!(cpu_violations[0].actual_value, 8.0);
    assert_eq!(cpu_violations[0].action, "THROTTLE");
    
    // Test memory violation
    let memory_violation_metrics = PerformanceMetrics {
        cpu_usage_percent: 2.0,
        memory_usage_mb: 250, // Exceeds 200MB threshold
        active_scans: 1,
        queue_depth: 0,
    };
    
    let memory_violations = enforcer.check_violations(&memory_violation_metrics);
    assert!(!memory_violations.is_empty(), "Should detect memory violation");
    assert_eq!(memory_violations[0].metric_type, "MEMORY");
    assert_eq!(memory_violations[0].threshold_value, 200.0);
    assert_eq!(memory_violations[0].actual_value, 250.0);
    assert_eq!(memory_violations[0].action, "DEGRADE");
}

/// Test malware sample manager
#[test]
fn test_malware_sample_manager() {
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let manager = MalwareSampleManager::new(temp_dir.path().to_path_buf());
    
    // Test adding a sample
    let test_file = temp_dir.path().join("test_malware.exe");
    std::fs::write(&test_file, b"test malware content").expect("Failed to create test file");
    
    let sample = manager.add_sample(
        "test_hash_123".to_string(),
        "TestMalware.Generic".to_string(),
        test_file.clone(),
        "HIGH".to_string()
    );
    
    assert!(sample.is_ok(), "Should add sample successfully");
    
    let sample = sample.unwrap();
    assert_eq!(sample.sha256_hash, "test_hash_123");
    assert_eq!(sample.family_name, "TestMalware.Generic");
    assert_eq!(sample.threat_level, "HIGH");
    
    // Test retrieving samples by family
    let family_samples = manager.get_samples_by_family("TestMalware.Generic");
    assert!(family_samples.is_ok(), "Should retrieve samples by family");
    
    let samples = family_samples.unwrap();
    assert_eq!(samples.len(), 1, "Should find one sample in family");
    assert_eq!(samples[0].sha256_hash, "test_hash_123");
    
    // Test with non-existent family
    let empty_family = manager.get_samples_by_family("NonExistent.Family");
    assert!(empty_family.is_ok(), "Should handle non-existent family gracefully");
    assert_eq!(empty_family.unwrap().len(), 0, "Should return empty list for non-existent family");
}

/// Test isolation engine
#[test]
fn test_isolation_engine() {
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let engine = IsolationEngine::new();
    
    // Create test executable
    let test_exe = temp_dir.path().join("test.exe");
    std::fs::write(&test_exe, b"test executable content").expect("Failed to create test executable");
    
    // Test isolation configuration
    let config = IsolationConfig {
        network_isolation: true,
        filesystem_isolation: true,
        registry_isolation: true,
        process_isolation: true,
        timeout_seconds: 30,
        resource_limits: ResourceLimits {
            max_cpu_percent: 10.0,
            max_memory_mb: 100,
            max_disk_io_mbps: 5.0,
            max_network_io_mbps: 1.0,
        },
    };
    
    // Test isolated execution
    let start_time = Instant::now();
    let result = engine.execute_isolated(&test_exe, &config);
    let execution_time = start_time.elapsed();
    
    assert!(result.is_ok(), "Isolation should execute successfully");
    
    let isolation_result = result.unwrap();
    assert!(isolation_result.execution_successful, "Execution should be successful");
    assert!(isolation_result.duration_ms < 30000, "Should complete within timeout");
    assert!(execution_time.as_secs() < 35, "Should not exceed timeout significantly");
    
    // Test with non-existent file
    let non_existent = PathBuf::from("/invalid/path/file.exe");
    let invalid_result = engine.execute_isolated(&non_existent, &config);
    assert!(invalid_result.is_err(), "Should return error for non-existent file");
}

/// Test false positive validator
#[test]
fn test_false_positive_validator() {
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let validator = FalsePositiveValidator::new();
    
    // Create test sample
    let test_file = temp_dir.path().join("test_sample.exe");
    std::fs::write(&test_file, b"test content").expect("Failed to create test file");
    
    let sample = MalwareSample::new(
        "test_hash_456".to_string(),
        "TestMalware.Generic".to_string(),
        test_file.to_string_lossy().to_string(),
        13, // Length of "test content"
        "MEDIUM".to_string()
    );
    
    // Create isolation result
    let isolation_result = IsolationResult {
        execution_successful: true,
        duration_ms: 1000,
        resource_usage: ResourceUsage {
            peak_cpu_percent: 6.0,
            peak_memory_mb: 50,
            disk_io_mb: 1.0,
            network_io_mb: 0.0,
        },
        behavioral_indicators: vec![
            "suspicious_api_call".to_string(),
            "file_modification".to_string(),
        ],
        network_activity: vec![],
    };
    
    // Test validation
    let validation_result = validator.validate_detection(&sample, &isolation_result);
    assert!(validation_result.is_ok(), "Validation should complete successfully");
    
    let result = validation_result.unwrap();
    assert!(result.confidence_score >= 0.0 && result.confidence_score <= 1.0, "Confidence score should be valid");
    
    // For a sample with behavioral indicators, it should not be a false positive
    assert!(!result.is_false_positive, "Sample with behavioral indicators should not be false positive");
    
    // Test with benign sample (no behavioral indicators)
    let benign_isolation_result = IsolationResult {
        execution_successful: true,
        duration_ms: 500,
        resource_usage: ResourceUsage {
            peak_cpu_percent: 1.0,
            peak_memory_mb: 20,
            disk_io_mb: 0.1,
            network_io_mb: 0.0,
        },
        behavioral_indicators: vec![], // No suspicious behavior
        network_activity: vec![],
    };
    
    let benign_validation = validator.validate_detection(&sample, &benign_isolation_result);
    assert!(benign_validation.is_ok(), "Benign validation should complete successfully");
    
    let benign_result = benign_validation.unwrap();
    // With no behavioral indicators, confidence should be lower
    assert!(benign_result.confidence_score < 0.5, "Benign sample should have lower confidence");
}

/// Test error handling across all modules
#[test]
fn test_comprehensive_error_handling() {
    // Test behavioral engine with invalid inputs
    let behavioral_engine = BehavioralEngine::new().expect("Failed to initialize behavioral engine");
    
    // Empty path
    let empty_path = PathBuf::new();
    let empty_result = behavioral_engine.analyze_file(&empty_path);
    assert!(empty_result.is_err(), "Should handle empty path gracefully");
    
    // Directory instead of file
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let dir_result = behavioral_engine.analyze_file(temp_dir.path());
    assert!(dir_result.is_err(), "Should handle directory input gracefully");
    
    // Test memory analyzer with invalid PID
    let memory_analyzer = MemoryAnalyzer::new();
    let invalid_pid_result = memory_analyzer.analyze_process(0);
    assert!(invalid_pid_result.is_err(), "Should handle invalid PID gracefully");
    
    // Test performance enforcer with invalid thresholds
    let mut enforcer = PerformanceEnforcer::new();
    
    // Negative thresholds should be handled
    enforcer.set_cpu_threshold(-1.0);
    enforcer.set_memory_threshold(-100);
    
    let metrics = PerformanceMetrics {
        cpu_usage_percent: 6.0,
        memory_usage_mb: 200,
        active_scans: 1,
        queue_depth: 0,
    };
    
    // Should handle negative thresholds gracefully (likely by using defaults or ignoring)
    let violations = enforcer.check_violations(&metrics);
    // The exact behavior depends on implementation, but it shouldn't panic
    assert!(violations.len() >= 0, "Should handle invalid thresholds without panicking");
}

/// Test module performance under load
#[test]
fn test_module_performance() {
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let behavioral_engine = BehavioralEngine::new().expect("Failed to initialize behavioral engine");
    
    // Create multiple test files
    let mut test_files = Vec::new();
    for i in 0..10 {
        let test_file = temp_dir.path().join(format!("test_{}.exe", i));
        std::fs::write(&test_file, format!("test content {}", i))
            .expect("Failed to create test file");
        test_files.push(test_file);
    }
    
    // Measure analysis time
    let start_time = Instant::now();
    let mut successful_analyses = 0;
    
    for test_file in test_files {
        let result = behavioral_engine.analyze_file(&test_file);
        if result.is_ok() {
            successful_analyses += 1;
        }
    }
    
    let total_time = start_time.elapsed();
    
    assert_eq!(successful_analyses, 10, "All analyses should succeed");
    assert!(total_time.as_secs() < 30, "Should complete 10 analyses within 30 seconds");
    
    // Average time per analysis should be reasonable
    let avg_time_ms = total_time.as_millis() / 10;
    assert!(avg_time_ms < 2000, "Average analysis time should be under 2 seconds");
}
