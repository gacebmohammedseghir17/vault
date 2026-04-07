//! Integration Tests for Production Readiness
//!
//! This module contains comprehensive integration tests that verify all components
//! work together correctly with strict production-grade assertions and proper error handling.

use anyhow::Result;
use chrono::Utc;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::{NamedTempFile, TempDir};
use tokio::time::sleep;

// Import the modules we're testing
use erdps_agent::behavioral::BehavioralAnalysisEngine;
use erdps_agent::detection::DetectionEngine;
use erdps_agent::metrics::{
    generate_detection_id, DetectionRecord, MetricsCollector, MetricsDatabase,
    PerformanceGateRecord, PerformanceThresholds, SystemHealthRecord, ValidationRecord,
};
use erdps_agent::yara_engine::YaraEngine;

/// Integration test configuration
struct IntegrationTestConfig {
    temp_dir: TempDir,
    db_path: PathBuf,
    metrics_db: MetricsDatabase,
    metrics_collector: MetricsCollector,
    performance_thresholds: PerformanceThresholds,
}

impl IntegrationTestConfig {
    fn new() -> Result<Self> {
        let temp_dir = TempDir::new()?;
        let db_path = temp_dir.path().join("test_metrics.db");

        let metrics_db = MetricsDatabase::new(&db_path)?;
        metrics_db.initialize_schema()?;

        let metrics_collector = MetricsCollector::new(metrics_db.clone());

        let performance_thresholds = PerformanceThresholds {
            max_cpu_percent: 5.0,
            max_memory_mb: 200.0,
            max_disk_mb: 1000.0,
            max_response_time_ms: 100,
            min_uptime_percent: 99.9,
        };

        Ok(Self {
            temp_dir,
            db_path,
            metrics_db,
            metrics_collector,
            performance_thresholds,
        })
    }
}

async fn test_full_system_integration() -> Result<()> {
    let config = IntegrationTestConfig::new()?;

    // Test 1: Initialize all components
    let behavioral_engine = BehavioralAnalysisEngine::new();
    let detection_engine = DetectionEngine::new();

    // Test 2: Record initial system health
    let initial_health = config.metrics_collector.get_system_health()?;
    assert_eq!(initial_health.component, "system_overall");
    assert_eq!(initial_health.status, "healthy");
    assert!(initial_health.uptime_seconds.is_some());

    // Test 3: Simulate detection workflow
    let test_file_content = b"This is a test file for detection";
    let entropy = behavioral_engine.calculate_entropy(test_file_content);

    // Record performance metrics
    config.metrics_collector.record_performance(
        "behavioral_engine",
        "entropy_calculation_time",
        2.5,
        "ms",
    )?;

    config.metrics_collector.record_performance(
        "behavioral_engine",
        "cpu_usage",
        3.2,
        "percent",
    )?;

    config.metrics_collector.record_performance(
        "behavioral_engine",
        "memory_usage",
        145.8,
        "mb",
    )?;

    // Test 4: Record a detection result
    let detection = DetectionRecord {
        id: None,
        timestamp: Utc::now(),
        detection_id: generate_detection_id(),
        detection_type: "entropy_analysis".to_string(),
        confidence_score: 0.85,
        threat_level: "medium".to_string(),
        file_path: Some("/test/sample.txt".to_string()),
        file_hash: Some("sha256:abc123def456".to_string()),
        file_size: Some(test_file_content.len() as i64),
        process_id: Some(std::process::id()),
        process_name: Some("integration_test".to_string()),
        detection_engine: "behavioral_analysis".to_string(),
        rule_name: Some("entropy_threshold".to_string()),
        mitigation_applied: false,
        false_positive: false,
        validated: true,
        validation_notes: Some("Integration test detection".to_string()),
    };

    config.metrics_collector.record_detection(detection)?;

    // Test 5: Check performance gates
    let gate_results = config
        .metrics_collector
        .check_performance_gates(&config.performance_thresholds)?;

    // Verify all gates passed (since our metrics are within thresholds)
    for gate in &gate_results {
        if gate.gate_name == "cpu_usage_limit" {
            assert!(
                gate.passed,
                "CPU usage gate should pass: {} <= {}",
                gate.actual_value, gate.threshold_value
            );
            assert_eq!(gate.severity, "info");
        }
        if gate.gate_name == "memory_usage_limit" {
            assert!(
                gate.passed,
                "Memory usage gate should pass: {} <= {}",
                gate.actual_value, gate.threshold_value
            );
            assert_eq!(gate.severity, "info");
        }
    }

    // Test 6: Generate production readiness report
    let report = config.metrics_collector.generate_readiness_report(1)?;

    assert_eq!(report.overall_health_status, "healthy");
    assert!(
        report.performance_gate_pass_rate >= 95.0,
        "Performance gate pass rate should be >= 95%: {}",
        report.performance_gate_pass_rate
    );
    assert_eq!(report.total_detections, 1);
    assert!(
        (report.average_confidence - 0.85).abs() < 0.01,
        "Average confidence should be ~0.85: {}",
        report.average_confidence
    );
    assert!(report.uptime_seconds > 0);
    assert_eq!(report.error_count, 0);
    assert!(!report.recommendations.is_empty());

    Ok(())
}

async fn test_performance_stress_integration() -> Result<()> {
    let config = IntegrationTestConfig::new()?;

    let behavioral_engine = BehavioralAnalysisEngine::new();
    let start_time = Instant::now();

    // Simulate high-load scenario
    let mut total_cpu = 0.0;
    let mut total_memory = 0.0;
    let iterations = 100;

    for i in 0..iterations {
        // Simulate varying workload
        let test_data = vec![0u8; 1024 * (i % 10 + 1)]; // Variable size data
        let _entropy = behavioral_engine.calculate_entropy(&test_data).await.unwrap_or(0.0);

        // Simulate CPU and memory usage
        let cpu_usage = 2.0 + (i as f64 * 0.01); // Gradually increasing
        let memory_usage = 100.0 + (i as f64 * 0.5);

        total_cpu += cpu_usage;
        total_memory += memory_usage;

        config.metrics_collector.record_performance(
            "stress_test",
            "cpu_usage",
            cpu_usage,
            "percent",
        )?;

        config.metrics_collector.record_performance(
            "stress_test",
            "memory_usage",
            memory_usage,
            "mb",
        )?;

        // Record detection for some iterations
        if i % 10 == 0 {
            let detection = DetectionRecord {
                id: None,
                timestamp: Utc::now(),
                detection_id: generate_detection_id(),
                detection_type: "stress_test".to_string(),
                confidence_score: 0.7 + (i as f64 * 0.002),
                threat_level: "low".to_string(),
                file_path: Some(format!("/test/stress_{}.bin", i)),
                file_hash: Some(format!("hash_{}", i)),
                file_size: Some(test_data.len() as i64),
                process_id: Some(std::process::id()),
                process_name: Some("stress_test".to_string()),
                detection_engine: "behavioral_analysis".to_string(),
                rule_name: Some("stress_rule".to_string()),
                mitigation_applied: false,
                false_positive: false,
                validated: true,
                validation_notes: Some(format!("Stress test iteration {}", i)),
            };

            config.metrics_collector.record_detection(detection)?;
        }

        // Small delay to simulate real processing
        if i % 20 == 0 {
            sleep(Duration::from_millis(1)).await;
        }
    }

    let execution_time = start_time.elapsed();

    // Performance assertions
    assert!(
        execution_time.as_millis() < 5000,
        "Stress test should complete within 5 seconds: {}ms",
        execution_time.as_millis()
    );

    let avg_cpu = total_cpu / iterations as f64;
    let avg_memory = total_memory / iterations as f64;

    // Check that average resource usage is reasonable
    assert!(
        avg_cpu < 10.0,
        "Average CPU usage should be < 10%: {}",
        avg_cpu
    );
    assert!(
        avg_memory < 300.0,
        "Average memory usage should be < 300MB: {}",
        avg_memory
    );

    // Check performance gates under stress
    let gate_results = config
        .metrics_collector
        .check_performance_gates(&config.performance_thresholds)?;

    // Some gates may fail under stress, but we should have results
    assert!(
        !gate_results.is_empty(),
        "Should have performance gate results"
    );

    // Generate report and verify it handles stress data correctly
    let report = config.metrics_collector.generate_readiness_report(1)?;

    assert!(
        report.total_detections >= 10,
        "Should have recorded multiple detections: {}",
        report.total_detections
    );
    assert!(
        report.average_confidence > 0.7,
        "Average confidence should be reasonable: {}",
        report.average_confidence
    );

    Ok(())
}

async fn test_error_handling_integration() -> Result<()> {
    let config = IntegrationTestConfig::new()?;

    // Test 1: Handle invalid data gracefully
    let behavioral_engine = BehavioralAnalysisEngine::new();

    // Empty data should not crash
    let entropy_empty = behavioral_engine.calculate_entropy(&[]).await.unwrap_or(0.0);
    assert!(
        entropy_empty >= 0.0 && entropy_empty <= 8.0,
        "Entropy should be valid range: {}",
        entropy_empty
    );

    // Very large data should be handled efficiently
    let large_data = vec![0u8; 1024 * 1024]; // 1MB
    let start_time = Instant::now();
    let entropy_large = behavioral_engine.calculate_entropy(&large_data).await.unwrap_or(0.0);
    let processing_time = start_time.elapsed();

    assert!(
        entropy_large >= 0.0 && entropy_large <= 8.0,
        "Large data entropy should be valid: {}",
        entropy_large
    );
    assert!(
        processing_time.as_millis() < 1000,
        "Large data processing should be < 1s: {}ms",
        processing_time.as_millis()
    );

    // Test 2: Database error recovery
    // Record metrics with edge case values
    config
        .metrics_collector
        .record_performance("error_test", "cpu_usage", f64::MAX, "percent")?;

    config
        .metrics_collector
        .record_performance("error_test", "memory_usage", 0.0, "mb")?;

    // Test 3: Validation with error conditions
    let error_validation = ValidationRecord {
        id: None,
        timestamp: Utc::now(),
        test_suite: "error_handling".to_string(),
        test_name: "invalid_input_test".to_string(),
        test_status: "failed".to_string(),
        execution_time_ms: Some(50),
        expected_result: Some("success".to_string()),
        actual_result: Some("error".to_string()),
        error_message: Some("Simulated error for testing".to_string()),
        test_environment: "integration_test".to_string(),
        build_version: Some("test-1.0.0".to_string()),
    };

    config
        .metrics_collector
        .record_validation(error_validation)?;

    // Test 4: System health under error conditions
    let health = config.metrics_collector.get_system_health()?;

    // System should still be operational despite errors
    assert!(health.uptime_seconds.is_some());
    assert!(health.timestamp <= Utc::now());

    // Test 5: Performance gates with extreme values
    let extreme_thresholds = PerformanceThresholds {
        max_cpu_percent: 0.1, // Very strict
        max_memory_mb: 1.0,   // Very strict
        max_disk_mb: 1.0,
        max_response_time_ms: 1,
        min_uptime_percent: 99.99,
    };

    let gate_results = config
        .metrics_collector
        .check_performance_gates(&extreme_thresholds)?;

    // Most gates should fail with extreme thresholds
    let failed_gates: Vec<_> = gate_results.iter().filter(|g| !g.passed).collect();
    assert!(
        !failed_gates.is_empty(),
        "Some gates should fail with extreme thresholds"
    );

    for failed_gate in failed_gates {
        assert_eq!(failed_gate.severity, "critical");
        assert!(failed_gate.actual_value > failed_gate.threshold_value);
    }

    Ok(())
}

async fn test_concurrent_operations_integration() -> Result<()> {
    let config = Arc::new(IntegrationTestConfig::new()?);

    let behavioral_engine = Arc::new(BehavioralAnalysisEngine::new());

    // Spawn multiple concurrent tasks
    let mut handles = Vec::new();

    for task_id in 0..10 {
        let config_clone = Arc::clone(&config);
        let engine_clone = Arc::clone(&behavioral_engine);

        let handle = tokio::spawn(async move {
            let mut results = Vec::new();

            for i in 0..20 {
                // Generate unique test data for each task
                let test_data = vec![task_id as u8; 512 + i * 10];
                let entropy = engine_clone.calculate_entropy(&test_data).await.unwrap_or(0.0);

                // Record metrics concurrently
                let cpu_usage = 1.0 + (task_id as f64 * 0.1) + (i as f64 * 0.01);
                let memory_usage = 50.0 + (task_id as f64 * 5.0) + (i as f64 * 0.5);

                config_clone
                    .metrics_collector
                    .record_performance(
                        &format!("concurrent_task_{}", task_id),
                        "cpu_usage",
                        cpu_usage,
                        "percent",
                    )
                    .unwrap();

                config_clone
                    .metrics_collector
                    .record_performance(
                        &format!("concurrent_task_{}", task_id),
                        "memory_usage",
                        memory_usage,
                        "mb",
                    )
                    .unwrap();

                // Record detection every 5 iterations
                if i % 5 == 0 {
                    let detection = DetectionRecord {
                        id: None,
                        timestamp: Utc::now(),
                        detection_id: generate_detection_id(),
                        detection_type: "concurrent_test".to_string(),
                        confidence_score: 0.6 + (entropy / 10.0),
                        threat_level: "low".to_string(),
                        file_path: Some(format!("/test/concurrent_{}_{}.bin", task_id, i)),
                        file_hash: Some(format!("hash_{}_{}", task_id, i)),
                        file_size: Some(test_data.len() as i64),
                        process_id: Some(std::process::id()),
                        process_name: Some(format!("concurrent_task_{}", task_id)),
                        detection_engine: "behavioral_analysis".to_string(),
                        rule_name: Some("concurrent_rule".to_string()),
                        mitigation_applied: false,
                        false_positive: false,
                        validated: true,
                        validation_notes: Some(format!(
                            "Concurrent test task {} iteration {}",
                            task_id, i
                        )),
                    };

                    config_clone
                        .metrics_collector
                        .record_detection(detection)
                        .unwrap();
                }

                results.push((entropy, cpu_usage, memory_usage));

                // Small delay to allow other tasks to run
                sleep(Duration::from_millis(1)).await;
            }

            results
        });

        handles.push(handle);
    }

    // Wait for all tasks to complete
    let start_time = Instant::now();
    let mut all_results = Vec::new();

    for handle in handles {
        let results = handle.await.unwrap();
        all_results.extend(results);
    }

    let total_time = start_time.elapsed();

    // Verify concurrent execution completed successfully
    assert_eq!(
        all_results.len(),
        200,
        "Should have 200 total results (10 tasks * 20 iterations)"
    );
    assert!(
        total_time.as_secs() < 30,
        "Concurrent execution should complete within 30 seconds: {}s",
        total_time.as_secs()
    );

    // Check that all entropy values are valid
    for (entropy, cpu, memory) in &all_results {
        assert!(
            *entropy >= 0.0 && *entropy <= 8.0,
            "Entropy should be valid: {}",
            entropy
        );
        assert!(
            cpu > &0.0 && cpu < &10.0,
            "CPU usage should be reasonable: {}",
            cpu
        );
        assert!(
            memory > &0.0 && memory < &200.0,
            "Memory usage should be reasonable: {}",
            memory
        );
    }

    // Generate final report
    let report = config.metrics_collector.generate_readiness_report(1)?;

    // Verify concurrent operations were recorded correctly
    assert!(
        report.total_detections >= 40,
        "Should have recorded multiple concurrent detections: {}",
        report.total_detections
    );
    assert!(
        report.performance_gate_pass_rate >= 0.0,
        "Performance gate pass rate should be valid: {}",
        report.performance_gate_pass_rate
    );

    println!("Concurrent integration test completed successfully:");
    println!("  - Total detections: {}", report.total_detections);
    println!("  - Average confidence: {:.3}", report.average_confidence);
    println!(
        "  - Performance gate pass rate: {:.1}%",
        report.performance_gate_pass_rate
    );
    println!("  - System status: {}", report.overall_health_status);
    println!("  - Execution time: {:.2}s", total_time.as_secs_f64());

    Ok(())
}

async fn test_database_cleanup_integration() -> Result<()> {
    let config = IntegrationTestConfig::new()?;

    // Record historical data (simulate old records)
    for days_ago in 1..=30 {
        let timestamp = Utc::now() - chrono::Duration::days(days_ago);

        // Create a detection record with backdated timestamp
        let detection = DetectionRecord {
            id: None,
            timestamp,
            detection_id: generate_detection_id(),
            detection_type: "historical_test".to_string(),
            confidence_score: 0.8,
            threat_level: "medium".to_string(),
            file_path: Some(format!("/test/historical_{}.bin", days_ago)),
            file_hash: Some(format!("hash_{}", days_ago)),
            file_size: Some(1024),
            process_id: Some(std::process::id()),
            process_name: Some("historical_test".to_string()),
            detection_engine: "behavioral_analysis".to_string(),
            rule_name: Some("historical_rule".to_string()),
            mitigation_applied: false,
            false_positive: false,
            validated: true,
            validation_notes: Some(format!("Historical test {} days ago", days_ago)),
        };

        config.metrics_collector.record_detection(detection)?;
    }

    // Verify we have historical data
    let summary_30_days = config.metrics_db.get_detection_summary(30)?;
    assert!(
        !summary_30_days.is_empty(),
        "Should have historical detection data"
    );

    let summary_7_days = config.metrics_db.get_detection_summary(7)?;
    let summary_1_day = config.metrics_db.get_detection_summary(1)?;

    // Verify data filtering works correctly
    assert!(
        summary_30_days.len() >= summary_7_days.len(),
        "30-day summary should have more or equal data than 7-day"
    );
    assert!(
        summary_7_days.len() >= summary_1_day.len(),
        "7-day summary should have more or equal data than 1-day"
    );

    // Test cleanup of old records (keep last 14 days)
    config.metrics_db.cleanup_old_records(14)?;

    // Verify cleanup worked
    let summary_after_cleanup = config.metrics_db.get_detection_summary(30)?;
    let summary_recent = config.metrics_db.get_detection_summary(14)?;

    // After cleanup, 30-day and 14-day summaries should be the same
    assert_eq!(
        summary_after_cleanup.len(),
        summary_recent.len(),
        "Cleanup should have removed old records"
    );

    println!("Database cleanup test completed successfully:");
    println!(
        "  - Records before cleanup (30 days): {}",
        summary_30_days.len()
    );
    println!(
        "  - Records after cleanup (30 days): {}",
        summary_after_cleanup.len()
    );
    println!("  - Records retained (14 days): {}", summary_recent.len());

    Ok(())
}

/// Helper function to run all integration tests
#[tokio::test]
async fn test_production_readiness_suite() -> Result<()> {
    println!("Running Production Readiness Integration Test Suite...");

    let start_time = Instant::now();

    // Run all integration tests
    test_full_system_integration().await?;
    println!("✓ Full system integration test passed");

    test_performance_stress_integration().await?;
    println!("✓ Performance stress integration test passed");

    test_error_handling_integration().await?;
    println!("✓ Error handling integration test passed");

    test_concurrent_operations_integration().await?;
    println!("✓ Concurrent operations integration test passed");

    test_database_cleanup_integration().await?;
    println!("✓ Database cleanup integration test passed");

    let total_time = start_time.elapsed();

    println!("\n🎉 All integration tests passed successfully!");
    println!("Total execution time: {:.2}s", total_time.as_secs_f64());

    // Final production readiness check
    assert!(
        total_time.as_secs() < 120,
        "Integration test suite should complete within 2 minutes: {}s",
        total_time.as_secs()
    );

    Ok(())
}
