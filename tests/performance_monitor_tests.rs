use erdps_agent::error::AgentError;
use erdps_agent::yara::performance_monitor::{OperationMetrics, OperationType, PerformanceMonitor};
use std::path::PathBuf;
use tempfile::tempdir;

#[tokio::test]
async fn test_performance_monitor_creation() {
    let temp_dir = tempdir().expect("Failed to create temp directory");
    let db_path = temp_dir.path().join("test.db");

    let monitor =
        PerformanceMonitor::new(db_path, 50).expect("Failed to create performance monitor");

    // Test that the monitor was created successfully
    assert!(monitor.start().is_ok());
}

#[tokio::test]
async fn test_record_and_collect_metrics() {
    let temp_dir = tempdir().expect("Failed to create temp directory");
    let db_path = temp_dir.path().join("test.db");

    let monitor =
        PerformanceMonitor::new(db_path, 50).expect("Failed to create performance monitor");

    monitor.start().expect("Failed to start monitor");

    // Record metrics below threshold
    let metrics1 = OperationMetrics {
        rule_id: "test_rule_1".to_string(),
        compile_time_ms: 30, // Below threshold of 50
    };

    // Record metrics above threshold
    let metrics2 = OperationMetrics {
        rule_id: "test_rule_2".to_string(),
        compile_time_ms: 80, // Above threshold of 50
    };

    assert!(monitor.record(metrics1).is_ok());
    assert!(monitor.record(metrics2).is_ok());

    // Collect all metrics
    let collected = monitor.collect().expect("Failed to collect metrics");

    // Verify we got both records
    assert_eq!(collected.len(), 2);

    // Verify the data is correct
    let rule_ids: Vec<String> = collected.iter().map(|m| m.rule_id.clone()).collect();
    assert!(rule_ids.contains(&"test_rule_1".to_string()));
    assert!(rule_ids.contains(&"test_rule_2".to_string()));
}

#[tokio::test]
async fn test_performance_stats() {
    let temp_dir = tempdir().expect("Failed to create temp directory");
    let db_path = temp_dir.path().join("test.db");

    let monitor =
        PerformanceMonitor::new(db_path, 50).expect("Failed to create performance monitor");

    monitor.start().expect("Failed to start monitor");

    // Record multiple metrics with different times
    let metrics = vec![
        OperationMetrics {
            rule_id: "rule_1".to_string(),
            compile_time_ms: 10,
        },
        OperationMetrics {
            rule_id: "rule_2".to_string(),
            compile_time_ms: 20,
        },
        OperationMetrics {
            rule_id: "rule_3".to_string(),
            compile_time_ms: 30,
        },
        OperationMetrics {
            rule_id: "rule_4".to_string(),
            compile_time_ms: 40,
        },
    ];

    for metric in metrics {
        monitor.record(metric).expect("Failed to record metric");
    }

    // Get performance stats
    let stats = monitor
        .get_performance_stats()
        .expect("Failed to get performance stats");

    // Verify stats
    assert_eq!(stats.total_operations, 4);
    assert_eq!(stats.average_time_ms, 25.0); // (10+20+30+40)/4 = 25
    assert_eq!(stats.max_time_ms, 40);
    assert_eq!(stats.min_time_ms, 10);
}

#[tokio::test]
async fn test_start_and_finish_operation() {
    let temp_dir = tempdir().expect("Failed to create temp directory");
    let db_path = temp_dir.path().join("test.db");

    let monitor =
        PerformanceMonitor::new(db_path, 50).expect("Failed to create performance monitor");

    monitor.start().expect("Failed to start monitor");

    // Test start and finish operation
    let scan_id = "test_scan_123";
    assert!(monitor
        .start_operation(scan_id.to_string(), OperationType::FileScanning)
        .is_ok());
    assert!(monitor.finish_operation(scan_id.to_string()).is_ok());
}

#[tokio::test]
async fn test_database_error_handling() {
    // Test with invalid database path to trigger database errors
    let invalid_path = PathBuf::from("/invalid/path/that/does/not/exist/test.db");

    let result = PerformanceMonitor::new(invalid_path, 50);

    // Should return an error for invalid path
    match result {
        Err(AgentError::Database { message, operation, .. }) => {
            // Just verify we got a database error with some message
            assert!(!message.is_empty());
            assert!(operation.is_some());
        }
        _ => panic!("Expected Database error"),
    }
}
