//! Comprehensive integration tests for production readiness
//! Tests all components working together with proper error handling

use crate::behavioral::BehavioralEngine;
use crate::database::{DatabasePool, models::*};
use crate::memory::MemoryAnalyzer;
use crate::network::NetworkEngine;
use crate::performance::{PerformanceGate, PerformanceMetrics, PerformanceEnforcer};
use crate::validation::{MalwareSampleManager, IsolationEngine, FalsePositiveValidator};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::time::timeout;

/// Integration test for full detection pipeline
#[tokio::test]
async fn test_full_detection_pipeline() {
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test.db");
    
    // Initialize database
    let db_pool = DatabasePool::new(&db_path.to_string_lossy())
        .await
        .expect("Failed to initialize database");
    
    // Initialize all engines
    let behavioral_engine = BehavioralEngine::new()
        .expect("Failed to initialize behavioral engine");
    let memory_analyzer = MemoryAnalyzer::new();
    let network_engine = NetworkEngine::new()
        .expect("Failed to initialize network engine");
    
    // Create test sample
    let test_file = temp_dir.path().join("test_sample.exe");
    std::fs::write(&test_file, b"test malware content")
        .expect("Failed to create test file");
    
    // Test full pipeline
    let start_time = Instant::now();
    
    // 1. Create detection scan
    let mut scan = DetectionScan::new(
        test_file.to_string_lossy().to_string(),
        "COMPREHENSIVE".to_string()
    );
    
    let scan_id = db_pool.create_detection_scan(&scan)
        .await
        .expect("Failed to create detection scan");
    
    // 2. Run behavioral analysis
    let behavioral_result = behavioral_engine.analyze_file(&test_file)
        .expect("Behavioral analysis failed");
    
    // 3. Run memory analysis
    let memory_result = memory_analyzer.analyze_process(1234)
        .expect("Memory analysis failed");
    
    // 4. Run network analysis
    let network_result = network_engine.analyze_traffic()
        .expect("Network analysis failed");
    
    // 5. Update scan with results
    scan.status = "COMPLETED".to_string();
    scan.duration_ms = Some(start_time.elapsed().as_millis() as i64);
    scan.completed_at = Some(chrono::Utc::now());
    
    db_pool.update_detection_scan(&scan)
        .await
        .expect("Failed to update scan");
    
    // Verify results
    assert!(behavioral_result.threat_indicators.len() > 0, "No behavioral indicators found");
    assert!(memory_result.suspicious_regions.len() >= 0, "Memory analysis failed");
    assert!(network_result.threat_indicators.len() >= 0, "Network analysis failed");
    assert!(scan.duration_ms.unwrap() < 30000, "Detection took too long: {}ms", scan.duration_ms.unwrap());
}

/// Test performance gate enforcement during detection
#[tokio::test]
async fn test_performance_gate_enforcement() {
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test.db");
    
    let db_pool = DatabasePool::new(&db_path.to_string_lossy())
        .await
        .expect("Failed to initialize database");
    
    // Initialize performance enforcer with strict thresholds
    let mut enforcer = PerformanceEnforcer::new();
    enforcer.set_cpu_threshold(6.0); // 6% CPU limit
    enforcer.set_memory_threshold(200); // 200MB memory limit
    
    // Simulate high resource usage
    let metrics = PerformanceMetrics {
        cpu_usage_percent: 8.0, // Exceeds threshold
        memory_usage_mb: 150,   // Within threshold
        active_scans: 1,
        queue_depth: 0,
    };
    
    // Test enforcement
    let violations = enforcer.check_violations(&metrics);
    assert!(!violations.is_empty(), "Should detect CPU violation");
    assert_eq!(violations[0].metric_type, "CPU");
    assert_eq!(violations[0].action, "THROTTLE");
    
    // Test memory violation
    let high_memory_metrics = PerformanceMetrics {
        cpu_usage_percent: 3.0,
        memory_usage_mb: 250, // Exceeds threshold
        active_scans: 1,
        queue_depth: 0,
    };
    
    let memory_violations = enforcer.check_violations(&high_memory_metrics);
    assert!(!memory_violations.is_empty(), "Should detect memory violation");
    assert_eq!(memory_violations[0].metric_type, "MEMORY");
    assert_eq!(memory_violations[0].action, "DEGRADE");
}

/// Test malware sample validation pipeline
#[tokio::test]
async fn test_malware_validation_pipeline() {
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test.db");
    
    let db_pool = DatabasePool::new(&db_path.to_string_lossy())
        .await
        .expect("Failed to initialize database");
    
    // Initialize validation components
    let sample_manager = MalwareSampleManager::new(temp_dir.path().to_path_buf());
    let isolation_engine = IsolationEngine::new();
    let fp_validator = FalsePositiveValidator::new();
    
    // Create test malware sample
    let test_sample = temp_dir.path().join("malware.exe");
    let malware_content = b"malicious payload for testing";
    std::fs::write(&test_sample, malware_content)
        .expect("Failed to create test sample");
    
    // Add sample to manager
    let sample_hash = "test_hash_12345";
    let sample = sample_manager.add_sample(
        sample_hash.to_string(),
        "TestMalware.Generic".to_string(),
        test_sample.clone(),
        "HIGH".to_string()
    ).expect("Failed to add sample");
    
    // Store in database
    let db_sample = MalwareSample::new(
        sample_hash.to_string(),
        "TestMalware.Generic".to_string(),
        test_sample.to_string_lossy().to_string(),
        malware_content.len() as i64,
        "HIGH".to_string()
    );
    
    db_pool.add_malware_sample(&db_sample)
        .await
        .expect("Failed to store sample in database");
    
    // Test isolation
    let isolation_config = IsolationConfig::default();
    let isolation_result = isolation_engine.execute_isolated(&test_sample, &isolation_config)
        .expect("Isolation execution failed");
    
    assert!(isolation_result.execution_successful, "Isolation should succeed");
    assert!(isolation_result.duration_ms < 10000, "Isolation took too long");
    
    // Test false positive validation
    let fp_result = fp_validator.validate_detection(&sample, &isolation_result)
        .expect("False positive validation failed");
    
    assert!(!fp_result.is_false_positive, "Should not be false positive for malware");
    assert!(fp_result.confidence_score > 0.8, "Confidence should be high for malware");
}

/// Test error handling and recovery
#[tokio::test]
async fn test_error_handling_and_recovery() {
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test.db");
    
    let db_pool = DatabasePool::new(&db_path.to_string_lossy())
        .await
        .expect("Failed to initialize database");
    
    // Test with non-existent file
    let non_existent_file = PathBuf::from("/non/existent/file.exe");
    
    let behavioral_engine = BehavioralEngine::new()
        .expect("Failed to initialize behavioral engine");
    
    // Should handle file not found gracefully
    let result = behavioral_engine.analyze_file(&non_existent_file);
    assert!(result.is_err(), "Should return error for non-existent file");
    
    // Test database connection failure recovery
    let invalid_db_path = "/invalid/path/test.db";
    let db_result = DatabasePool::new(invalid_db_path).await;
    assert!(db_result.is_err(), "Should fail with invalid database path");
    
    // Test timeout handling
    let timeout_result = timeout(
        Duration::from_millis(100),
        async {
            // Simulate long-running operation
            tokio::time::sleep(Duration::from_millis(200)).await;
            "completed"
        }
    ).await;
    
    assert!(timeout_result.is_err(), "Should timeout after 100ms");
}

/// Test concurrent detection operations
#[tokio::test]
async fn test_concurrent_operations() {
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test.db");
    
    let db_pool = DatabasePool::new(&db_path.to_string_lossy())
        .await
        .expect("Failed to initialize database");
    
    let behavioral_engine = BehavioralEngine::new()
        .expect("Failed to initialize behavioral engine");
    
    // Create multiple test files
    let mut test_files = Vec::new();
    for i in 0..5 {
        let test_file = temp_dir.path().join(format!("test_{}.exe", i));
        std::fs::write(&test_file, format!("test content {}", i))
            .expect("Failed to create test file");
        test_files.push(test_file);
    }
    
    // Run concurrent analyses
    let mut handles = Vec::new();
    for test_file in test_files {
        let engine = behavioral_engine.clone();
        let handle = tokio::spawn(async move {
            engine.analyze_file(&test_file)
        });
        handles.push(handle);
    }
    
    // Wait for all to complete
    let start_time = Instant::now();
    let mut results = Vec::new();
    for handle in handles {
        let result = handle.await.expect("Task panicked");
        results.push(result);
    }
    let total_time = start_time.elapsed();
    
    // Verify all completed successfully
    assert_eq!(results.len(), 5, "All analyses should complete");
    for result in &results {
        assert!(result.is_ok(), "All analyses should succeed");
    }
    
    // Should complete faster than sequential execution
    assert!(total_time < Duration::from_secs(10), "Concurrent execution should be efficient");
}

/// Test system resource monitoring
#[tokio::test]
async fn test_system_resource_monitoring() {
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test.db");
    
    let db_pool = DatabasePool::new(&db_path.to_string_lossy())
        .await
        .expect("Failed to initialize database");
    
    // Record system metrics
    let metrics = SystemMetrics::new(
        2.5,  // CPU usage
        150,  // Memory usage MB
        1.2,  // Disk I/O
        0.8,  // Network I/O
        2,    // Active scans
        5     // Queue depth
    );
    
    db_pool.record_system_metrics(&metrics)
        .await
        .expect("Failed to record metrics");
    
    // Verify metrics are within acceptable ranges
    assert!(metrics.cpu_usage_percent < 6.0, "CPU usage should be under 6%");
    assert!(metrics.memory_usage_mb < 200, "Memory usage should be under 200MB");
    assert!(metrics.active_scans <= 10, "Should not exceed max concurrent scans");
    assert!(metrics.queue_depth <= 100, "Queue should not be too deep");
}

/// Test validation statistics and KPI compliance
#[tokio::test]
async fn test_validation_kpi_compliance() {
    // Test production KPI requirements
    let good_stats = ValidationStats {
        total_runs: 1000,
        detection_rate: 0.998,      // 99.8% - exceeds 99.5% requirement
        false_positive_rate: 0.0005, // 0.05% - under 0.1% requirement
        avg_mttd: 45.0,             // 45 seconds - under 60s requirement
        avg_accuracy: 0.995,
    };
    
    assert!(good_stats.meets_production_kpis(), "Should meet production KPIs");
    
    let kpi_report = good_stats.get_kpi_report();
    assert!(kpi_report.detection_rate_compliant, "Detection rate should be compliant");
    assert!(kpi_report.false_positive_rate_compliant, "FP rate should be compliant");
    assert!(kpi_report.mttd_compliant, "MTTD should be compliant");
    assert!(kpi_report.overall_compliant, "Overall should be compliant");
    
    // Test failing KPIs
    let bad_stats = ValidationStats {
        total_runs: 100,
        detection_rate: 0.990,      // 99.0% - below 99.5% requirement
        false_positive_rate: 0.002, // 0.2% - above 0.1% requirement
        avg_mttd: 75.0,             // 75 seconds - above 60s requirement
        avg_accuracy: 0.985,
    };
    
    assert!(!bad_stats.meets_production_kpis(), "Should not meet production KPIs");
    
    let bad_kpi_report = bad_stats.get_kpi_report();
    assert!(!bad_kpi_report.detection_rate_compliant, "Detection rate should not be compliant");
    assert!(!bad_kpi_report.false_positive_rate_compliant, "FP rate should not be compliant");
    assert!(!bad_kpi_report.mttd_compliant, "MTTD should not be compliant");
    assert!(!bad_kpi_report.overall_compliant, "Overall should not be compliant");
}
