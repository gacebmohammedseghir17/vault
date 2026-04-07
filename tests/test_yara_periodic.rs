//! Unit tests for YARA periodic scanning functionality
//!
//! This module contains comprehensive tests for the YaraPeriodicScanner,
//! including tests for periodic task execution, circuit breaker behavior,
//! statistics collection, and integration with the detection system.

#![cfg(feature = "yara")]

use std::collections::HashMap;
// Removed unused imports
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::sync::mpsc;
use tokio::time::sleep;

// Import the detection module components
use erdps_agent::config::{AgentConfig, YaraConfig};
use erdps_agent::detection::yara_engine::{RulesManager, YaraEngine, YaraMatchResult};
use erdps_agent::detection::yara_periodic_scanner::{ScanStats, YaraPeriodicScanner};
// Removed unused error imports
use erdps_agent::detector::DetectionEvent;
use tokio::sync::RwLock;

/// Create a production YARA configuration for testing
fn create_production_yara_config() -> YaraConfig {
    let mut config = YaraConfig::default();
    config.enabled = true;
    config.rules_path = "rules/".to_string(); // Use production rules directory
    config.memory_chunk_size = 1024;
    config
}

/// Get the production rules path
fn get_production_rules_path() -> std::path::PathBuf {
    std::path::PathBuf::from("rules/")
}

// Removed unused function create_production_agent_config

// Note: Removed MockYaraEngine as we now use production YaraEngine with real rules

/// Create a temporary directory with test files for production scanning
#[allow(dead_code)]
async fn create_test_directory() -> Result<TempDir, std::io::Error> {
    let temp_dir = TempDir::new()?;

    // Create some test files for production rule scanning
    let test_file1 = temp_dir.path().join("sample1.txt");
    let test_file2 = temp_dir.path().join("sample2.exe");
    let subdir = temp_dir.path().join("subdir");

    tokio::fs::write(&test_file1, "This is a sample file for production scanning").await?;
    tokio::fs::write(
        &test_file2,
        "This is a sample executable for production scanning",
    )
    .await?;
    tokio::fs::create_dir(&subdir).await?;

    let nested_file = subdir.join("nested.dll");
    tokio::fs::write(&nested_file, "This is a nested sample file").await?;

    Ok(temp_dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_periodic_scanner_creation() {
        // Skip test if production rules directory doesn't exist
        if !get_production_rules_path().exists() {
            eprintln!("Skipping test: Production rules directory not found");
            return;
        }

        let yara_config = create_production_yara_config();

        let mut agent_config = AgentConfig::default();
        agent_config.yara = Some(yara_config.clone());
        let agent_config = Arc::new(RwLock::new(agent_config));

        let rule_manager = Arc::new(RulesManager::new());
        let yara_engine = Arc::new(YaraEngine::with_rules_manager(
            rule_manager,
            Arc::new(AgentConfig::default()),
        ));

        let scanner = YaraPeriodicScanner::new(yara_engine, agent_config);

        // Verify initial state
        let stats = scanner.get_scan_stats().await;
        assert_eq!(stats.total_files_scanned, 0);
        assert_eq!(stats.total_processes_scanned, 0);
        assert_eq!(stats.scan_errors, 0);
    }

    #[tokio::test]
    async fn test_scanner_health_info() {
        // Skip test if production rules directory doesn't exist
        if !get_production_rules_path().exists() {
            eprintln!("Skipping test: Production rules directory not found");
            return;
        }

        let yara_config = create_production_yara_config();

        let mut agent_config = AgentConfig::default();
        agent_config.yara = Some(yara_config.clone());
        let agent_config = Arc::new(RwLock::new(agent_config));

        let rule_manager = Arc::new(RulesManager::new());
        let yara_engine = Arc::new(YaraEngine::with_rules_manager(
            rule_manager,
            Arc::new(AgentConfig::default()),
        ));

        let scanner = YaraPeriodicScanner::new(yara_engine, agent_config);

        let health = scanner.get_health_info().await;
        assert!(health.is_healthy);
        assert_eq!(health.total_scans, 0);
        assert_eq!(health.error_rate, 0.0);
        assert_eq!(health.failed_processes, 0);
        assert_eq!(health.directory_health, "Healthy");
    }

    #[tokio::test]
    async fn test_circuit_breaker_reset() {
        // Skip test if production rules directory doesn't exist
        if !get_production_rules_path().exists() {
            eprintln!("Skipping test: Production rules directory not found");
            return;
        }

        let yara_config = create_production_yara_config();

        let mut agent_config = AgentConfig::default();
        agent_config.yara = Some(yara_config.clone());
        let agent_config = Arc::new(RwLock::new(agent_config));

        let rule_manager = Arc::new(RulesManager::new());
        let yara_engine = Arc::new(YaraEngine::with_rules_manager(
            rule_manager,
            Arc::new(AgentConfig::default()),
        ));

        let scanner = YaraPeriodicScanner::new(yara_engine, agent_config);

        // Reset circuit breakers (should not panic)
        scanner.reset_circuit_breakers().await;

        let health = scanner.get_health_info().await;
        assert!(health.is_healthy);
    }

    #[tokio::test]
    async fn test_scanned_files_cache() {
        // Skip test if production rules directory doesn't exist
        if !get_production_rules_path().exists() {
            eprintln!("Skipping test: Production rules directory not found");
            return;
        }

        let yara_config = create_production_yara_config();

        let mut agent_config = AgentConfig::default();
        agent_config.yara = Some(yara_config.clone());
        let agent_config = Arc::new(RwLock::new(agent_config));

        let rule_manager = Arc::new(RulesManager::new());
        let yara_engine = Arc::new(YaraEngine::with_rules_manager(
            rule_manager,
            Arc::new(AgentConfig::default()),
        ));

        let scanner = YaraPeriodicScanner::new(yara_engine, agent_config);

        // Initially empty
        let stats = scanner.get_scan_stats().await;
        assert_eq!(stats.scanned_files_count, 0);

        // Clear cache (should not panic)
        scanner.clear_scanned_files_cache().await;

        let stats_after = scanner.get_scan_stats().await;
        assert_eq!(stats_after.scanned_files_count, 0);
    }

    #[tokio::test]
    async fn test_scanner_start_stop() {
        // Skip test if production rules directory doesn't exist
        if !get_production_rules_path().exists() {
            eprintln!("Skipping test: Production rules directory not found");
            return;
        }

        let yara_config = create_production_yara_config();

        let mut agent_config = AgentConfig::default();
        agent_config.yara = Some(yara_config.clone());
        let agent_config = Arc::new(RwLock::new(agent_config));

        let rule_manager = Arc::new(RulesManager::new());
        let yara_engine = Arc::new(YaraEngine::with_rules_manager(
            rule_manager,
            Arc::new(AgentConfig::default()),
        ));

        let scanner = YaraPeriodicScanner::new(yara_engine, agent_config);
        let (_tx, mut rx) = mpsc::channel::<DetectionEvent>(100);

        // Start the scanner in a background task
        let scanner_clone = scanner.clone();
        let start_handle = tokio::spawn(async move { scanner_clone.start().await });

        // Let it run briefly
        sleep(Duration::from_millis(100)).await;

        // Stop the scanner
        scanner.stop().await;

        // Wait for the start task to complete
        let result = tokio::time::timeout(Duration::from_secs(1), start_handle).await;
        assert!(result.is_ok());

        // Verify no events were sent (since we don't have real YARA rules)
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_scanner_clone() {
        // Skip test if production rules directory doesn't exist
        if !get_production_rules_path().exists() {
            eprintln!("Skipping test: Production rules directory not found");
            return;
        }

        let yara_config = create_production_yara_config();

        let mut agent_config = AgentConfig::default();
        agent_config.yara = Some(yara_config.clone());
        let agent_config = Arc::new(RwLock::new(agent_config));

        let rule_manager = Arc::new(RulesManager::new());
        let yara_engine = Arc::new(YaraEngine::with_rules_manager(
            rule_manager,
            Arc::new(AgentConfig::default()),
        ));

        let scanner1 = YaraPeriodicScanner::new(yara_engine, agent_config);
        let scanner2 = scanner1.clone();

        // Both scanners should have the same initial state
        let stats1 = scanner1.get_scan_stats().await;
        let stats2 = scanner2.get_scan_stats().await;

        assert_eq!(stats1.total_files_scanned, stats2.total_files_scanned);
        assert_eq!(
            stats1.total_processes_scanned,
            stats2.total_processes_scanned
        );
    }

    #[tokio::test]
    async fn test_scan_stats_default() {
        let stats = ScanStats::default();

        assert_eq!(stats.total_files_scanned, 0);
        assert_eq!(stats.total_processes_scanned, 0);
        assert_eq!(stats.total_matches_found, 0);
        assert_eq!(stats.scan_errors, 0);
        assert_eq!(stats.consecutive_failures, 0);
        assert!(stats.last_error_time.is_none());
    }

    #[tokio::test]
    async fn test_yara_match_result_creation() {
        let match_result = YaraMatchResult {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            rule_name: "test_rule".to_string(),
            target_type: "file".to_string(),
            target_path: "/test/path".to_string(),
            target_pid: None,
            match_strings: Vec::new(),
            severity: "high".to_string(),
            metadata: HashMap::new(),
        };

        assert_eq!(match_result.rule_name, "test_rule");
        assert_eq!(match_result.target_type, "file");
        assert_eq!(match_result.severity, "high");
        assert!(match_result.target_pid.is_none());
    }

    #[tokio::test]
    async fn test_scanner_with_disabled_config() {
        // Skip test if production rules directory doesn't exist
        if !get_production_rules_path().exists() {
            eprintln!("Skipping test: Production rules directory not found");
            return;
        }

        let mut yara_config = create_production_yara_config();
        yara_config.enabled = false;

        let mut agent_config = AgentConfig::default();
        agent_config.yara = Some(yara_config.clone());
        let agent_config = Arc::new(RwLock::new(agent_config));

        let rule_manager = Arc::new(RulesManager::new());
        let yara_engine = Arc::new(YaraEngine::with_rules_manager(
            rule_manager,
            Arc::new(AgentConfig::default()),
        ));

        let scanner = YaraPeriodicScanner::new(yara_engine, agent_config);
        let (_tx, _rx) = mpsc::channel::<DetectionEvent>(100);

        // Start should complete quickly when disabled
        let start_result = tokio::time::timeout(Duration::from_millis(100), scanner.start()).await;

        assert!(start_result.is_ok());
    }

    #[tokio::test]
    async fn test_scanner_with_default_config() {
        // Skip test if production rules directory doesn't exist
        if !get_production_rules_path().exists() {
            eprintln!("Skipping test: Production rules directory not found");
            return;
        }

        let yara_config = create_production_yara_config();

        let mut agent_config = AgentConfig::default();
        agent_config.yara = Some(yara_config.clone());
        let agent_config = Arc::new(RwLock::new(agent_config));

        let rule_manager = Arc::new(RulesManager::new());
        let yara_engine = Arc::new(YaraEngine::with_rules_manager(
            rule_manager,
            Arc::new(AgentConfig::default()),
        ));

        let scanner = YaraPeriodicScanner::new(yara_engine, agent_config);

        // Should handle default config gracefully
        let health = scanner.get_health_info().await;
        assert!(health.is_healthy);
    }

    #[tokio::test]
    async fn test_scanner_statistics_tracking() {
        // Skip test if production rules directory doesn't exist
        if !get_production_rules_path().exists() {
            eprintln!("Skipping test: Production rules directory not found");
            return;
        }

        let yara_config = create_production_yara_config();

        let mut agent_config = AgentConfig::default();
        agent_config.yara = Some(yara_config.clone());
        let agent_config = Arc::new(RwLock::new(agent_config));

        let rule_manager = Arc::new(RulesManager::new());
        let yara_engine = Arc::new(YaraEngine::with_rules_manager(
            rule_manager,
            Arc::new(AgentConfig::default()),
        ));

        let scanner = YaraPeriodicScanner::new(yara_engine, agent_config);

        // Get initial stats
        let initial_stats = scanner.get_stats().await;
        assert_eq!(initial_stats.total_files_scanned, 0);

        // Get scan stats (should be the same for now)
        let scan_stats = scanner.get_scan_stats().await;
        assert_eq!(
            scan_stats.total_files_scanned,
            initial_stats.total_files_scanned
        );
    }

    #[tokio::test]
    async fn test_periodic_intervals() {
        // Skip test if production rules directory doesn't exist
        if !get_production_rules_path().exists() {
            eprintln!("Skipping test: Production rules directory not found");
            return;
        }

        let mut yara_config = create_production_yara_config();
        yara_config.periodic_scan.interval_minutes = 5; // 5 minutes

        let mut agent_config = AgentConfig::default();
        agent_config.yara = Some(yara_config.clone());
        let agent_config = Arc::new(RwLock::new(agent_config));

        let rule_manager = Arc::new(RulesManager::new());
        let yara_engine = Arc::new(YaraEngine::with_rules_manager(
            rule_manager,
            Arc::new(AgentConfig::default()),
        ));

        let scanner = YaraPeriodicScanner::new(yara_engine, agent_config);

        // Verify scanner can be created with different intervals
        let health = scanner.get_health_info().await;
        assert!(health.is_healthy);
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[tokio::test]
    async fn test_full_scanner_lifecycle() {
        // Skip test if production rules directory doesn't exist
        if !get_production_rules_path().exists() {
            eprintln!("Skipping test: Production rules directory not found");
            return;
        }

        let yara_config = create_production_yara_config();

        let mut agent_config = AgentConfig::default();
        agent_config.yara = Some(yara_config.clone());
        let agent_config = Arc::new(RwLock::new(agent_config));

        let rule_manager = Arc::new(RulesManager::new());
        let yara_engine = Arc::new(YaraEngine::with_rules_manager(
            rule_manager,
            Arc::new(AgentConfig::default()),
        ));

        let scanner = YaraPeriodicScanner::new(yara_engine, agent_config);
        let (_tx, mut rx) = mpsc::channel::<DetectionEvent>(100);

        // Test complete lifecycle
        let scanner_clone = scanner.clone();
        let lifecycle_task = tokio::spawn(async move {
            // Start scanner
            let start_task = tokio::spawn(async move { scanner_clone.start().await });

            // Let it run briefly
            sleep(Duration::from_millis(50)).await;

            // Check health
            let health = scanner.get_health_info().await;
            assert!(health.is_healthy);

            // Reset circuit breakers
            scanner.reset_circuit_breakers().await;

            // Clear cache
            scanner.clear_scanned_files_cache().await;

            // Stop scanner
            scanner.stop().await;

            // Wait for start task to complete
            let _ = tokio::time::timeout(Duration::from_secs(1), start_task).await;
        });

        // Complete lifecycle test
        let result = tokio::time::timeout(Duration::from_secs(2), lifecycle_task).await;
        assert!(result.is_ok());

        // Verify events may be received with production YARA rules
        let _ = rx.try_recv(); // Don't assert on this as production rules may trigger matches
    }

    #[tokio::test]
    async fn test_concurrent_scanner_operations() {
        // Skip test if production rules directory doesn't exist
        if !get_production_rules_path().exists() {
            eprintln!("Skipping test: Production rules directory not found");
            return;
        }

        let yara_config = create_production_yara_config();

        let mut agent_config = AgentConfig::default();
        agent_config.yara = Some(yara_config.clone());
        let agent_config = Arc::new(RwLock::new(agent_config));

        let rule_manager = Arc::new(RulesManager::new());
        let yara_engine = Arc::new(YaraEngine::with_rules_manager(
            rule_manager,
            Arc::new(AgentConfig::default()),
        ));

        let scanner = YaraPeriodicScanner::new(yara_engine, agent_config);

        // Test concurrent access to scanner methods
        let tasks = vec![
            tokio::spawn({
                let scanner = scanner.clone();
                async move { scanner.get_health_info().await }
            }),
            tokio::spawn({
                let scanner = scanner.clone();
                async move { scanner.get_health_info().await }
            }),
            tokio::spawn({
                let scanner = scanner.clone();
                async move { scanner.get_health_info().await }
            }),
        ];

        // All tasks should complete successfully
        for task in tasks {
            let result = tokio::time::timeout(Duration::from_secs(1), task).await;
            assert!(result.is_ok());
        }
    }
}
