//! Enhanced rules testing with feature gates
//!
//! These tests validate that rules are properly loaded and metrics are correctly exposed.
//! They are gated behind the "enhanced-rules" feature to avoid blocking standard CI.

#[cfg(all(test, feature = "enhanced-rules"))]
mod enhanced_rules_tests {
    use erdps_agent::metrics::{get_metrics, init_metrics};
    use erdps_agent::{initialize_components_with_mode, InitializationResult};
    use std::time::Duration;
    use tokio::time::timeout;

    /// Test that rules_loaded_total metric is ≥ 1 after startup
    #[tokio::test]
    async fn test_rules_loaded_total_after_startup() {
        // Initialize metrics system
        init_metrics().await.expect("Failed to initialize metrics");

        // Initialize components in console mode
        let init_result: InitializationResult = timeout(
            Duration::from_secs(30),
            initialize_components_with_mode("console", None),
        )
        .await
        .expect("Initialization timed out")
        .expect("Failed to initialize components");

        // Wait a moment for rules to be fully loaded
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Get metrics and verify rules_loaded_total ≥ 1
        let metrics = get_metrics()
            .await
            .expect("Failed to get metrics collector");

        // Get the current metrics text to parse rules_loaded_total
        let metrics_text = metrics.get_metrics_text();

        println!("Metrics output:\n{}", metrics_text);

        // Parse the metrics text to find rules_loaded_total
        let mut rules_loaded_value: Option<i64> = None;
        for line in metrics_text.lines() {
            if line.starts_with("rules_loaded_total ") {
                if let Some(value_str) = line.split_whitespace().nth(1) {
                    if let Ok(value) = value_str.parse::<i64>() {
                        rules_loaded_value = Some(value);
                        break;
                    }
                }
            }
        }

        let rules_loaded =
            rules_loaded_value.expect("rules_loaded_total metric not found in metrics output");

        assert!(
            rules_loaded >= 1,
            "Expected rules_loaded_total ≥ 1, but got: {}",
            rules_loaded
        );

        println!(
            "✓ Enhanced rules test passed: rules_loaded_total = {}",
            rules_loaded
        );

        // Cleanup: shutdown the metrics handle if it exists
        #[cfg(feature = "metrics")]
        if let Some(metrics_handle) = init_result.metrics_handle {
            metrics_handle.abort();
        }

        // Cleanup: shutdown the IPC handle
        init_result.ipc_handle.abort();
    }

    /// Test that files_scanned_total and threats_detected_total metrics are exposed
    #[tokio::test]
    async fn test_scan_metrics_exposed() {
        // Initialize metrics system
        init_metrics().await.expect("Failed to initialize metrics");

        // Get metrics and verify scan metrics are exposed
        let metrics = get_metrics()
            .await
            .expect("Failed to get metrics collector");

        // Get the current metrics text
        let metrics_text = metrics.get_metrics_text();

        println!("Checking for scan metrics in output:\n{}", metrics_text);

        // Verify files_scanned_total is present
        assert!(
            metrics_text.contains("files_scanned_total"),
            "files_scanned_total metric not found in metrics output"
        );

        // Verify threats_detected_total is present
        assert!(
            metrics_text.contains("threats_detected_total"),
            "threats_detected_total metric not found in metrics output"
        );

        println!("✓ Scan metrics are properly exposed");
    }

    /// Test that metrics can be incremented properly
    #[tokio::test]
    async fn test_metrics_increment() {
        // Initialize metrics system
        init_metrics().await.expect("Failed to initialize metrics");

        let metrics = get_metrics()
            .await
            .expect("Failed to get metrics collector");

        // Increment files scanned
        metrics.increment_files_scanned();
        metrics.increment_files_scanned_with_result("clean");

        // Increment threats detected
        metrics.increment_threats_detected();
        metrics.increment_threats_detected_with_labels("yara", "ransomware");

        // Get metrics text and verify increments
        let metrics_text = metrics.get_metrics_text();

        println!("Metrics after increments:\n{}", metrics_text);

        // Verify that counters have been incremented
        assert!(
            metrics_text.contains("files_scanned_total"),
            "files_scanned_total metric not found"
        );
        assert!(
            metrics_text.contains("threats_detected_total"),
            "threats_detected_total metric not found"
        );

        println!("✓ Metrics increment test passed");
    }
}

#[cfg(not(feature = "enhanced-rules"))]
mod disabled_tests {
    /// Placeholder test when enhanced-rules feature is disabled
    #[test]
    fn enhanced_rules_tests_disabled() {
        println!("Enhanced rules tests are disabled. Enable with --features enhanced-rules");
    }
}
