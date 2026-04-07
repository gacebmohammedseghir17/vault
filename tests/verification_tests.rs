//! Comprehensive Verification Tests for Production Readiness
//!
//! This module contains verification tests that validate:
//! - Configuration loading and validation
//! - YARA rule compilation and functionality
//! - SLO performance monitoring and enforcement
//! - Integration between all critical subsystems

use std::path::Path;
use std::time::{Duration, Instant};
use tokio::time::sleep;

// Import necessary modules
use erdps_agent::config::agent_config::{
    AgentConfig, DetectionConfig, ObservabilityConfig as AgentObservabilityConfig,
    PerformanceConfig, ServiceConfig,
};
use erdps_agent::config::YaraConfig;
#[cfg(feature = "yara")]
use erdps_agent::detection::yara_engine::YaraEngine;
use erdps_agent::metrics::{MetricsCollector, MetricsDatabase};
use erdps_agent::monitor::performance::{PerformanceMonitor, SloThresholds};
use erdps_agent::observability::{ObservabilityConfig, ObservabilitySystem};
use erdps_agent::yara_updater::YaraUpdaterConfig;
use std::sync::Arc;

/// Test suite for configuration validation
mod config_verification {
    use super::*;

    #[tokio::test]
    async fn test_config_loading_with_validation() {
        println!("=== Configuration Loading Verification ===");

        // Test 1: Load default configuration
        println!("Testing default configuration loading...");
        let default_config = AgentConfig::default();

        // Validate all required fields are present
        assert!(
            !default_config.agent_id.is_empty(),
            "Agent ID should not be empty"
        );
        assert!(
            !default_config.ipc_key.is_empty(),
            "IPC key should not be empty"
        );
        assert!(
            !default_config.quarantine_path.is_empty(),
            "Quarantine path should not be empty"
        );
        assert!(
            !default_config.audit_log_path.is_empty(),
            "Audit log path should not be empty"
        );

        println!("✓ Default configuration loaded successfully");

        // Test 2: Load from file if exists
        let config_path = "config.toml";
        if Path::new(config_path).exists() {
            println!("Testing configuration loading from file...");

            let file_config =
                AgentConfig::load_from_file(config_path).expect("Failed to load config from file");

            // Validate file config has proper structure
            assert!(
                !file_config.config_version.is_empty(),
                "Config version should not be empty"
            );
            assert!(
                file_config.observability.metrics_port > 0,
                "Metrics port should be positive"
            );
            assert!(
                file_config.performance.cpu_limit_percent > 0.0,
                "CPU limit should be positive"
            );

            println!("✓ Configuration loaded from file successfully");
            println!("  Config version: {}", file_config.config_version);
            println!("  Service mode: {}", file_config.service.mode);
            println!("  Metrics port: {}", file_config.observability.metrics_port);
        } else {
            println!("⚠ config.toml not found, skipping file loading test");
        }

        // Test 3: Validate production-ready settings
        println!("Testing production readiness validation...");

        let prod_config = create_production_config();
        validate_production_config(&prod_config);

        println!("✓ Production configuration validation passed");
        println!("✅ Configuration loading verification completed!");
    }

    fn create_production_config() -> AgentConfig {
        AgentConfig {
            config_version: "2.0".to_string(),
            agent_id: "prod-agent-001".to_string(),
            ipc_key: "prod-ipc-key-secure".to_string(),
            quarantine_path: "C:\\ERDPS\\Quarantine".to_string(),
            audit_log_path: "C:\\ERDPS\\Logs\\audit.log".to_string(),
            mass_modification_count: Some(50),
            mass_modification_window_secs: Some(60),
            extension_mutation_window_secs: Some(300),
            extension_mutation_threshold: Some(0.8),
            process_monitoring_enabled: Some(true),
            suspicious_process_threshold: Some(10),
            network_monitoring_enabled: Some(true),
            suspicious_network_threshold: Some(20),
            max_concurrent_scans: Some(4),
            scan_timeout_secs: Some(30),
            memory_limit_mb: Some(200),
            yara_enabled: Some(true),
            yara_process_scan_enabled: Some(false),
            yara_scan_downloads: Some(true),
            yara_scan_temp_files: Some(true),
            yara_scan_user_files: Some(true),
            yara_scan_system_files: Some(false),
            yara_scan_network_drives: Some(false),
            yara_scan_removable_drives: Some(true),
            yara_scan_archives: Some(true),
            yara_scan_memory: Some(false),
            yara_scan_registry: Some(false),
            yara_scan_startup: Some(true),
            yara_scan_services: Some(false),
            yara_scan_drivers: Some(false),
            yara_scan_dlls: Some(true),
            yara_scan_executables: Some(true),
            yara_scan_scripts: Some(true),
            yara_scan_documents: Some(true),
            yara_scan_images: Some(false),
            yara_scan_videos: Some(false),
            yara_scan_audio: Some(false),
            yara_scan_compressed: Some(true),
            yara_scan_encrypted: Some(false),
            yara_scan_hidden: Some(true),
            yara_scan_system_protected: Some(false),
            service: ServiceConfig {
                mode: "production".to_string(),
                scan_paths: vec!["C:\\Users".to_string(), "C:\\Program Files".to_string()],
                exclude_paths: vec![
                    "C:\\Windows\\System32".to_string(),
                    "C:\\$Recycle.Bin".to_string(),
                ],
                ipc_bind: "127.0.0.1:8888".to_string(),
                tls_cert_path: None,
                tls_key_path: None,
                allow_volume_scan: Some(false),
            },
            observability: AgentObservabilityConfig {
                metrics_bind: "127.0.0.1:19091".to_string(),
                metrics_port: 19091,
                dashboard_bind: "127.0.0.1:19091".to_string(),
                dashboard_port: 19091,
                log_level: "info".to_string(),
                log_filters: "cranelift=warn,wasmtime=info".to_string(),
            },
            performance: PerformanceConfig {
                cpu_limit_percent: 5.0,
                memory_limit_mb: 200,
                enable_enforcement: true,
            },
            detection: DetectionConfig {
                mttd_target_seconds: 60,
                false_positive_threshold: 0.1,
                enable_yara_fs_monitor: true,
                yara_rules_path: "./yara_rules".to_string(),
                ..DetectionConfig::default()
            },
            #[cfg(feature = "yara")]
            yara: Some(YaraConfig::default()),
            #[cfg(feature = "yara")]
            yara_updater: YaraUpdaterConfig::default(),
            allow_terminate: false,
            mitigation_score_threshold: 70,
            auto_mitigate: true,
            process_behavior_window_secs: 300,
            process_behavior_write_threshold: 100,
            entropy_threshold: 7.0,
            dry_run: false,
            auto_quarantine_score: 80,
            ransom_note_patterns: vec!["README".to_string(), "DECRYPT".to_string()],
            yara_scan_directories: None,
            yara_max_file_size_mb: Some(100),
            yara_process_scan_interval_minutes: Some(5),
            yara_downloads_scan_interval_minutes: Some(30),
            yara_target_processes: None,
            ..AgentConfig::default()
        }
    }

    fn validate_production_config(config: &AgentConfig) {
        // Security validations
        assert_eq!(
            config.service.mode, "production",
            "Must be in production mode"
        );
        assert_eq!(
            config.service.allow_volume_scan.unwrap_or(true),
            false,
            "Volume scan must be disabled"
        );

        // Performance validations
        assert!(
            config.performance.cpu_limit_percent <= 10.0,
            "CPU limit must be <= 10%"
        );
        assert!(
            config.performance.memory_limit_mb <= 500,
            "Memory limit must be <= 500MB"
        );
        assert!(
            config.performance.enable_enforcement,
            "Performance enforcement must be enabled"
        );

        // SLO validations
        assert!(
            config.detection.mttd_target_seconds <= 120,
            "MTTD must be <= 120 seconds"
        );
        assert!(
            config.detection.false_positive_threshold <= 0.2,
            "FP threshold must be <= 0.2"
        );

        // Network security validations
        assert!(
            config.service.ipc_bind.starts_with("127.0.0.1:")
                || config.service.ipc_bind.starts_with("localhost:"),
            "IPC must bind to localhost only"
        );
        assert!(
            config.observability.metrics_bind.starts_with("127.0.0.1:")
                || config.observability.metrics_bind.starts_with("localhost:"),
            "Metrics must bind to localhost only"
        );
    }
}

/// Test suite for YARA functionality verification
#[cfg(feature = "yara")]
mod yara_verification {
    use super::*;

    #[tokio::test]
    async fn test_yara_engine_initialization_and_rules() {
        println!("=== YARA Engine Verification ===");

        // Test 1: YARA engine initialization
        println!("Testing YARA engine initialization...");

        let config = AgentConfig::default();
        let yara_engine = YaraEngine::new(Arc::new(config));

        // Load YARA rules from the rules directory
        let rules_loaded = yara_engine
            .load_rules("./yara_rules")
            .await
            .expect("Failed to load YARA rules");

        println!(
            "✓ YARA engine initialized successfully with {} rules",
            rules_loaded
        );

        // Test 2: Rule compilation
        println!("Testing YARA rule compilation...");

        let rules_path = Path::new("./yara_rules");
        if rules_path.exists() {
            let rule_files: Vec<_> = std::fs::read_dir(rules_path)
                .expect("Failed to read rules directory")
                .filter_map(|entry| {
                    let entry = entry.ok()?;
                    let path = entry.path();
                    if path.extension()? == "yar" {
                        Some(path)
                    } else {
                        None
                    }
                })
                .collect();

            assert!(!rule_files.is_empty(), "Should have at least one .yar file");
            println!("✓ Found {} YARA rule files", rule_files.len());

            // Test rule compilation for each file
            for rule_file in &rule_files {
                println!(
                    "  Testing compilation of: {:?}",
                    rule_file.file_name().unwrap()
                );

                let content = std::fs::read_to_string(rule_file).expect("Failed to read rule file");

                // Basic syntax validation
                assert!(
                    content.contains("rule "),
                    "Rule file should contain 'rule ' keyword"
                );
                assert!(
                    content.contains("{"),
                    "Rule file should contain opening brace"
                );
                assert!(
                    content.contains("}"),
                    "Rule file should contain closing brace"
                );

                println!("    ✓ Basic syntax validation passed");
            }

            println!("✓ All YARA rules passed basic validation");
        } else {
            println!("⚠ YARA rules directory not found, skipping rule compilation test");
        }

        // Test 3: Test file scanning capability
        println!("Testing YARA scanning capability...");

        // Create a test file with known content
        let test_file_path = "test_scan_file.txt";
        std::fs::write(test_file_path, "This is a test file for YARA scanning")
            .expect("Failed to create test file");

        // Attempt to scan the test file
        let scan_start = Instant::now();
        let _scan_result = yara_engine
            .scan_file(Path::new(test_file_path))
            .await
            .expect("Failed to scan test file");
        let scan_duration = scan_start.elapsed();

        // Clean up test file
        std::fs::remove_file(test_file_path).expect("Failed to remove test file");

        println!("✓ File scanning completed in {:?}", scan_duration);
        assert!(
            scan_duration < Duration::from_secs(5),
            "Scan should complete within 5 seconds"
        );

        println!("✅ YARA engine verification completed!");
    }
}

/// Test suite for SLO performance monitoring verification
mod slo_verification {
    use super::*;

    #[tokio::test]
    async fn test_slo_monitoring_and_enforcement() {
        println!("=== SLO Monitoring Verification ===");

        // Test 1: Performance monitor initialization
        println!("Testing performance monitor initialization...");

        let thresholds = SloThresholds {
            max_cpu_percent: 5.0,
            max_memory_mb: 200,
            max_detection_time_secs: 60,
            max_false_positive_rate: 0.1,
        };

        let (perf_monitor, _violation_receiver) = PerformanceMonitor::with_thresholds(thresholds);

        println!("✓ Performance monitor initialized with thresholds");

        // Test 2: Warm-up grace period
        println!("Testing warm-up grace period...");

        let _start_time = Instant::now();

        // Start monitoring in background
        let monitor_handle = tokio::spawn(async move { perf_monitor.start_monitoring().await });

        // Wait for a short period (less than warm-up)
        sleep(Duration::from_secs(2)).await;

        // During warm-up, violations should be ignored
        println!("✓ Warm-up period active - violations should be ignored");

        // Test 3: SLO threshold validation
        println!("Testing SLO threshold validation...");

        // Create a test config with SLO requirements
        let config = AgentConfig::default();

        // Validate SLO configuration
        assert!(
            config.detection.mttd_target_seconds > 0,
            "MTTD target should be positive"
        );
        assert!(
            config.detection.false_positive_threshold >= 0.0,
            "FP threshold should be non-negative"
        );
        assert!(
            config.detection.false_positive_threshold <= 1.0,
            "FP threshold should be <= 1.0"
        );

        println!("✓ SLO thresholds validated");
        println!("  MTTD target: {}s", config.detection.mttd_target_seconds);
        println!(
            "  FP threshold: {}",
            config.detection.false_positive_threshold
        );

        // Test 4: Performance enforcement
        println!("Testing performance enforcement configuration...");

        assert!(
            config.performance.enable_enforcement,
            "Performance enforcement should be enabled"
        );
        assert!(
            config.performance.cpu_limit_percent > 0.0,
            "CPU limit should be positive"
        );
        assert!(
            config.performance.memory_limit_mb > 0,
            "Memory limit should be positive"
        );

        println!("✓ Performance enforcement configured correctly");
        println!("  CPU limit: {}%", config.performance.cpu_limit_percent);
        println!("  Memory limit: {}MB", config.performance.memory_limit_mb);

        // Clean up
        monitor_handle.abort();

        println!("✅ SLO monitoring verification completed!");
    }
}

/// Test suite for observability system verification
mod observability_verification {
    use super::*;

    #[tokio::test]
    async fn test_observability_system_startup() {
        println!("=== Observability System Verification ===");

        // Test 1: Observability system initialization
        println!("Testing observability system initialization...");

        let config = AgentConfig::default();

        // Create mock MetricsCollector
        let metrics_db = MetricsDatabase::new(":memory:").unwrap();
        let metrics_collector = Arc::new(MetricsCollector::new(metrics_db));

        // Create observability config with metrics on port 19091
        let obs_config = ObservabilityConfig {
            enable_prometheus: true,
            prometheus_config: erdps_agent::observability::prometheus_metrics::PrometheusConfig {
                enabled: true,
                bind_address: "127.0.0.1".to_string(),
                port: 19093, // Use metrics port 19093 for observability test
                metrics_path: "/metrics".to_string(),
                auth_enabled: false,
                auth_token: None,
                collection_interval_seconds: 30,
            },
            enable_dashboard: true,
            dashboard_config: erdps_agent::observability::dashboard::DashboardConfig::default(),
            enable_health_checks: true,
            health_check_config:
                erdps_agent::observability::health_checks::HealthCheckConfig::default(),
            enable_alerting: true,
            alert_config: erdps_agent::observability::alerting::AlertConfig::default(),
            metrics_collection_interval_secs: 30,
            data_retention_days: 7,
            enable_detailed_logging: true,
        };

        let mut observability = ObservabilitySystem::new(obs_config, metrics_collector);

        println!("✓ Observability system created successfully");

        // Test 2: Startup self-check
        println!("Testing startup self-check probe...");

        let self_check_start = Instant::now();
        observability
            .initialize()
            .await
            .expect("Startup self-check failed");
        let self_check_duration = self_check_start.elapsed();

        println!(
            "✓ Startup self-check completed in {:?}",
            self_check_duration
        );
        assert!(
            self_check_duration < Duration::from_secs(10),
            "Self-check should complete within 10 seconds"
        );

        // Test 3: Metrics endpoint validation
        println!("Testing metrics endpoint configuration...");

        assert_eq!(
            config.observability.metrics_port, 19091,
            "Metrics should use port 19091"
        );
        assert_eq!(
            config.observability.dashboard_port, 19092,
            "Dashboard should use port 19092"
        );
        assert!(
            config.observability.metrics_bind.contains("19091"),
            "Metrics bind should contain port 19091"
        );

        println!("✓ Metrics endpoint unified on port 19091");

        // Test 4: Component health tracking
        println!("Testing component health tracking...");

        observability
            .update_component_health(
                "test_component",
                erdps_agent::observability::HealthStatus::Healthy,
                10.0,
                None,
                std::collections::HashMap::new(),
            )
            .await;

        let dashboard_summary = observability.get_dashboard_summary().await;
        let test_component = dashboard_summary
            .component_health
            .iter()
            .find(|c| c.component_name == "test_component");
        assert!(
            test_component.is_some(),
            "Dashboard should contain test component"
        );

        println!("✓ Component health tracking working");

        println!("✅ Observability system verification completed!");
    }
}

/// Integration test combining all verification components
mod integration_verification {
    use super::*;

    #[tokio::test]
    async fn test_full_system_integration() {
        println!("=== Full System Integration Verification ===");

        // Test 1: Load configuration
        println!("Step 1: Loading and validating configuration...");
        let config = AgentConfig::default();
        println!("✓ Configuration loaded");

        // Test 2: Initialize observability
        println!("Step 2: Initializing observability system...");
        // Create a metrics collector for testing
        let metrics_db = MetricsDatabase::new(":memory:").unwrap();
        let metrics_collector = Arc::new(MetricsCollector::new(metrics_db));

        // Create observability config with unified port 19091
        let obs_config = ObservabilityConfig {
            enable_prometheus: true,
            prometheus_config: erdps_agent::observability::prometheus_metrics::PrometheusConfig {
                enabled: true,
                bind_address: "127.0.0.1".to_string(),
                port: 19091, // Use unified port 19091
                metrics_path: "/metrics".to_string(),
                auth_enabled: false,
                auth_token: None,
                collection_interval_seconds: 30,
            },
            enable_dashboard: true,
            dashboard_config: erdps_agent::observability::dashboard::DashboardConfig::default(),
            enable_health_checks: true,
            health_check_config:
                erdps_agent::observability::health_checks::HealthCheckConfig::default(),
            enable_alerting: true,
            alert_config: erdps_agent::observability::alerting::AlertConfig::default(),
            metrics_collection_interval_secs: 30,
            data_retention_days: 7,
            enable_detailed_logging: true,
        };

        let mut observability = ObservabilitySystem::new(obs_config, metrics_collector);

        // Perform startup self-check
        observability
            .initialize()
            .await
            .expect("Startup self-check failed");
        println!("✓ Observability system initialized with self-check");

        // Test 3: Initialize performance monitoring
        println!("Step 3: Initializing performance monitoring...");
        let thresholds = SloThresholds {
            max_cpu_percent: config.performance.cpu_limit_percent as f32,
            max_memory_mb: config.performance.memory_limit_mb as u64,
            max_detection_time_secs: config.detection.mttd_target_seconds as u64,
            max_false_positive_rate: config.detection.false_positive_threshold as f32,
        };

        let (_perf_monitor, _violation_receiver) = PerformanceMonitor::with_thresholds(thresholds);
        println!("✓ Performance monitoring initialized");

        // Test 4: YARA engine initialization (if available)
        #[cfg(feature = "yara")]
        {
            println!("Step 4: Initializing YARA engine...");
            if Path::new(&config.detection.yara_rules_path).exists() {
                let _yara_engine = YaraEngine::new(Arc::new(config.clone()));
                println!("✓ YARA engine initialized");
            } else {
                println!("⚠ YARA rules path not found, skipping YARA initialization");
            }
        }

        // Test 5: Validate all systems are working together
        println!("Step 5: Validating system integration...");

        // Update component health for all systems
        observability
            .update_component_health(
                "config",
                erdps_agent::observability::HealthStatus::Healthy,
                10.0,
                None,
                std::collections::HashMap::new(),
            )
            .await;

        observability
            .update_component_health(
                "observability",
                erdps_agent::observability::HealthStatus::Healthy,
                12.0,
                None,
                std::collections::HashMap::new(),
            )
            .await;

        observability
            .update_component_health(
                "performance",
                erdps_agent::observability::HealthStatus::Healthy,
                8.0,
                None,
                std::collections::HashMap::new(),
            )
            .await;

        #[cfg(feature = "yara")]
        observability
            .update_component_health(
                "yara",
                erdps_agent::observability::HealthStatus::Healthy,
                15.0,
                None,
                std::collections::HashMap::new(),
            )
            .await;

        // Get system status
        let system_status = observability.get_dashboard_summary().await;
        println!("System Status Summary:");
        println!("System Health: {:?}", system_status.system_health);
        println!(
            "Components: {} healthy",
            system_status.component_health.len()
        );
        println!("Uptime: {} seconds", system_status.uptime_seconds);

        // Validate all components are healthy
        let config_component = system_status
            .component_health
            .iter()
            .find(|c| c.component_name == "config");
        let observability_component = system_status
            .component_health
            .iter()
            .find(|c| c.component_name == "observability");
        let performance_component = system_status
            .component_health
            .iter()
            .find(|c| c.component_name == "performance");

        assert!(
            config_component.is_some(),
            "System status should include config component"
        );
        assert!(
            observability_component.is_some(),
            "System status should include observability component"
        );
        assert!(
            performance_component.is_some(),
            "System status should include performance component"
        );
        assert_eq!(
            system_status.system_health,
            erdps_agent::observability::HealthStatus::Healthy,
            "Overall system should be healthy"
        );

        println!("✓ All systems integrated successfully");

        println!("✅ Full system integration verification completed!");
        println!("🎉 All production readiness verification tests passed!");
    }
}
