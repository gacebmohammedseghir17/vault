//! Rules testing with feature gates
//!
//! These tests validate that rules are properly loaded and the rules_loaded_total metric is ≥ 1.
//! They are gated behind the "rules-testing" feature to avoid blocking standard CI.

#[cfg(all(test, feature = "rules-testing"))]
mod rules_testing_tests {
    use erdps_agent::metrics::{get_metrics, init_metrics};
    use erdps_agent::{initialize_components_with_mode, InitializationResult};
    use std::time::Duration;
    use tokio::time::timeout;

    /// Test that rules_loaded_total metric is ≥ 1 after startup
    /// This test ensures that the minimal safe rules bundle is properly loaded
    #[tokio::test]
    async fn test_rules_loaded_total_ge_one() {
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
        tokio::time::sleep(Duration::from_millis(1000)).await;

        // Get metrics and verify rules_loaded_total ≥ 1
        let metrics = get_metrics()
            .await
            .expect("Failed to get metrics collector");

        // Get the current metrics text to parse rules_loaded_total
        let metrics_text = metrics.get_metrics_text();

        println!("Metrics output for rules testing:\n{}", metrics_text);

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
            "Expected rules_loaded_total ≥ 1, but got: {}. This indicates that the minimal safe rules bundle is not properly loaded.",
            rules_loaded
        );

        println!(
            "✓ Rules testing passed: rules_loaded_total = {} (≥ 1)",
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

    /// Test that the minimal safe rules bundle contains expected rules
    #[tokio::test]
    async fn test_minimal_safe_rules_loaded() {
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

        // Wait for rules to be loaded
        tokio::time::sleep(Duration::from_millis(1000)).await;

        // Get metrics to verify rules are loaded
        let metrics = get_metrics()
            .await
            .expect("Failed to get metrics collector");

        let metrics_text = metrics.get_metrics_text();

        // Verify that rules_loaded_total exists and is > 0
        let rules_loaded_found = metrics_text.lines().any(|line| {
            if line.starts_with("rules_loaded_total ") {
                if let Some(value_str) = line.split_whitespace().nth(1) {
                    if let Ok(value) = value_str.parse::<i64>() {
                        return value > 0;
                    }
                }
            }
            false
        });

        assert!(
            rules_loaded_found,
            "Minimal safe rules bundle not properly loaded - rules_loaded_total should be > 0"
        );

        println!("✓ Minimal safe rules bundle validation passed");

        // Cleanup
        #[cfg(feature = "metrics")]
        if let Some(metrics_handle) = init_result.metrics_handle {
            metrics_handle.abort();
        }

        init_result.ipc_handle.abort();
    }
}

#[cfg(not(feature = "rules-testing"))]
mod disabled_tests {
    /// Placeholder test when rules-testing feature is disabled
    #[test]
    fn rules_testing_tests_disabled() {
        println!("Rules testing tests are disabled. Enable with --features rules-testing");
    }
}
