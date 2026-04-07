//! Configuration validation tests
//!
//! This module contains comprehensive tests to validate that config.toml
//! is parsed correctly and all values match the expected schema.

use super::agent_config::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_toml_schema_validation() {
        println!("Testing config.toml schema validation...");

        // Try multiple possible paths for config.toml
        let possible_paths = [
            "config.toml",
            "../config.toml",
            "./agent/config.toml",
            "d:\\projecttttttttts\\project-ransolution\\agent\\config.toml",
        ];

        let mut config = None;
        let mut used_path = "";

        for path in &possible_paths {
            if std::path::Path::new(path).exists() {
                match AgentConfig::load_from_file(path) {
                    Ok(cfg) => {
                        println!("✓ Successfully loaded config from {}", path);
                        config = Some(cfg);
                        used_path = path;
                        break;
                    }
                    Err(e) => {
                        println!("⚠ Failed to load config from {}: {}", path, e);
                        continue;
                    }
                }
            }
        }

        let config = config.expect("❌ Could not load config.toml from any expected location. This indicates a schema mismatch or missing file!");
        println!("Using config from: {}", used_path);

        // Validate service section
        println!("Validating [service] section...");
        assert_eq!(
            config.service.mode, "production",
            "Service mode should be 'production'"
        );
        assert!(
            !config.service.scan_paths.is_empty(),
            "scan_paths should not be empty"
        );
        assert!(
            config.service.scan_paths.contains(&"C:\\Users".to_string()),
            "scan_paths should include C:\\Users"
        );
        assert!(
            config
                .service
                .scan_paths
                .contains(&"C:\\Program Files".to_string()),
            "scan_paths should include C:\\Program Files"
        );

        assert!(
            !config.service.exclude_paths.is_empty(),
            "exclude_paths should not be empty"
        );
        assert!(
            config
                .service
                .exclude_paths
                .contains(&"C:\\Windows\\System32".to_string()),
            "exclude_paths should include C:\\Windows\\System32"
        );
        assert!(
            config
                .service
                .exclude_paths
                .contains(&"C:\\Windows\\SysWOW64".to_string()),
            "exclude_paths should include C:\\Windows\\SysWOW64"
        );

        assert_eq!(
            config.service.ipc_bind, "127.0.0.1:8888",
            "IPC bind should be on port 8888"
        );
        println!("✓ [service] section validated");

        // Validate observability section
        println!("Validating [observability] section...");
        assert_eq!(
            config.observability.metrics_bind, "127.0.0.1:19093",
            "Metrics should bind to port 19093"
        );
        assert_eq!(
            config.observability.dashboard_bind, "127.0.0.1:19094",
            "Dashboard should bind to port 19094"
        );
        assert_eq!(
            config.observability.log_level, "info",
            "Log level should be 'info'"
        );
        assert!(
            config.observability.log_filters.contains("cranelift=warn"),
            "Log filters should contain cranelift=warn"
        );
        println!("✓ [observability] section validated");

        // Validate performance section
        println!("Validating [performance] section...");
        assert_eq!(
            config.performance.cpu_limit_percent, 10.0,
            "CPU limit should be 10.0%"
        );
        assert_eq!(
            config.performance.memory_limit_mb, 200,
            "Memory limit should be 200MB"
        );
        assert!(
            config.performance.enable_enforcement,
            "Performance enforcement should be enabled"
        );
        println!("✓ [performance] section validated");

        // Validate detection section
        println!("Validating [detection] section...");
        assert_eq!(
            config.detection.mttd_target_seconds, 60,
            "MTTD target should be 60 seconds"
        );
        assert_eq!(
            config.detection.false_positive_threshold, 0.1,
            "FP threshold should be 0.1"
        );
        assert!(
            config.detection.enable_yara_fs_monitor,
            "YARA FS monitor should be enabled"
        );
        assert_eq!(
            config.detection.yara_rules_path, "./yara_rules",
            "YARA rules path should be './yara_rules'"
        );
        println!("✓ [detection] section validated");

        println!("✅ All config sections validated successfully!");

        // Print loaded values for verification
        println!("\n📋 Loaded configuration values:");
        println!("  Service mode: {}", config.service.mode);
        println!("  Scan paths: {:?}", config.service.scan_paths);
        println!("  Exclude paths: {:?}", config.service.exclude_paths);
        println!("  IPC bind: {}", config.service.ipc_bind);
        println!("  Metrics bind: {}", config.observability.metrics_bind);
        println!("  Dashboard bind: {}", config.observability.dashboard_bind);
        println!("  Log level: {}", config.observability.log_level);
        println!("  CPU limit: {}%", config.performance.cpu_limit_percent);
        println!("  Memory limit: {}MB", config.performance.memory_limit_mb);
        println!("  MTTD target: {}s", config.detection.mttd_target_seconds);
        println!(
            "  FP threshold: {}",
            config.detection.false_positive_threshold
        );
        println!("  YARA rules path: {}", config.detection.yara_rules_path);
    }

    #[test]
    fn test_config_load_or_default_behavior() {
        println!("Testing load_or_default behavior...");

        // Try to find config.toml in possible locations
        let possible_paths = [
            "config.toml",
            "../config.toml",
            "./agent/config.toml",
            "d:\\projecttttttttts\\project-ransolution\\agent\\config.toml",
        ];

        let mut found_config_path = None;
        for path in &possible_paths {
            if std::path::Path::new(path).exists() {
                found_config_path = Some(*path);
                break;
            }
        }

        if let Some(config_path) = found_config_path {
            // Test with existing config.toml
            let config = AgentConfig::load_or_default(config_path);

            // Verify it's not using all default values (which would indicate fallback)
            assert_eq!(
                config.service.ipc_bind, "127.0.0.1:8888",
                "Should load actual config, not default"
            );
            assert_eq!(
                config.observability.metrics_bind, "127.0.0.1:19093",
                "Should load actual config, not default"
            );

            println!(
                "✓ load_or_default correctly loads from file: {}",
                config_path
            );
        } else {
            println!("⚠ No config.toml found, skipping file load test");
        }

        // Test with non-existent file
        let default_config = AgentConfig::load_or_default("non_existent_config.toml");

        // Check that we get default values - let's check what the actual defaults are
        let expected_default = AgentConfig::default();
        assert_eq!(
            default_config.service.ipc_bind, expected_default.service.ipc_bind,
            "Should use default IPC bind"
        );
        assert_eq!(
            default_config.observability.metrics_bind, expected_default.observability.metrics_bind,
            "Should use default metrics bind"
        );

        println!("✓ load_or_default correctly falls back to defaults for missing file");
        println!("  Default IPC bind: {}", default_config.service.ipc_bind);
        println!(
            "  Default metrics bind: {}",
            default_config.observability.metrics_bind
        );
    }

    #[test]
    fn test_comprehensive_config_validation() {
        println!("Testing comprehensive config.toml validation with all required fields...");

        // Load the actual config.toml file
        let config_path = "config.toml";
        let config = AgentConfig::load_from_file(config_path)
            .expect("Failed to load config.toml - ensure file exists and has correct schema");

        println!("✓ Successfully loaded config.toml");

        // Validate config version field
        assert_eq!(config.config_version, "2.0", "Config version should be 2.0");
        println!("✓ Config version validated: {}", config.config_version);

        // Validate all bind addresses and ports
        assert_eq!(
            config.service.ipc_bind, "127.0.0.1:8888",
            "IPC should bind to port 8888"
        );
        assert_eq!(
            config.observability.metrics_bind, "127.0.0.1:19093",
            "Metrics should bind to port 19093"
        );
        assert_eq!(
            config.observability.dashboard_bind, "127.0.0.1:19094",
            "Dashboard should bind to port 19094"
        );
        println!("✓ All bind addresses validated");

        // Validate scan paths and exclusions
        assert!(
            !config.service.scan_paths.is_empty(),
            "Scan paths must not be empty"
        );
        assert!(
            config.service.scan_paths.len() >= 2,
            "Should have at least 2 scan paths"
        );
        assert!(
            !config.service.exclude_paths.is_empty(),
            "Exclude paths must not be empty"
        );
        assert!(
            config.service.exclude_paths.len() >= 2,
            "Should have at least 2 exclude paths"
        );
        println!("✓ Scan paths: {:?}", config.service.scan_paths);
        println!("✓ Exclude paths: {:?}", config.service.exclude_paths);

        // Validate SLO thresholds
        assert!(
            config.performance.cpu_limit_percent > 0.0
                && config.performance.cpu_limit_percent <= 100.0,
            "CPU limit should be between 0-100%"
        );
        assert!(
            config.performance.memory_limit_mb > 0,
            "Memory limit should be positive"
        );
        assert!(
            config.detection.mttd_target_seconds > 0,
            "MTTD target should be positive"
        );
        assert!(
            config.detection.false_positive_threshold >= 0.0
                && config.detection.false_positive_threshold <= 1.0,
            "FP threshold should be between 0.0-1.0"
        );
        println!(
            "✓ SLO thresholds - CPU: {}%, Memory: {}MB, MTTD: {}s, FP: {}",
            config.performance.cpu_limit_percent,
            config.performance.memory_limit_mb,
            config.detection.mttd_target_seconds,
            config.detection.false_positive_threshold
        );

        // Validate log filters
        assert!(
            !config.observability.log_filters.is_empty(),
            "Log filters should not be empty"
        );
        assert!(
            config.observability.log_filters.contains("warn"),
            "Log filters should contain warn level"
        );
        println!(
            "✓ Log filters validated: {}",
            config.observability.log_filters
        );

        // Validate legacy fields are present
        assert!(!config.agent_id.is_empty(), "Agent ID should not be empty");
        assert!(!config.ipc_key.is_empty(), "IPC key should not be empty");
        assert!(
            !config.quarantine_path.is_empty(),
            "Quarantine path should not be empty"
        );
        assert!(
            !config.audit_log_path.is_empty(),
            "Audit log path should not be empty"
        );
        println!("✓ Legacy fields validated - agent_id: {}", config.agent_id);

        // Validate YARA configuration
        assert!(
            !config.detection.yara_rules_path.is_empty(),
            "YARA rules path should not be empty"
        );
        assert!(
            config.detection.enable_yara_fs_monitor,
            "YARA FS monitor should be enabled"
        );
        println!(
            "✓ YARA config validated - rules_path: {}",
            config.detection.yara_rules_path
        );

        println!("✅ Comprehensive config validation completed successfully!");
    }

    #[test]
    fn test_baseline_config_generation() {
        println!("Testing baseline config generation...");

        let baseline_config = AgentConfig {
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
            observability: ObservabilityConfig {
                metrics_bind: "127.0.0.1:19091".to_string(),
                metrics_port: 19091,
                dashboard_bind: "127.0.0.1:19092".to_string(),
                dashboard_port: 19092,
                log_level: "debug".to_string(),
                log_filters: "test=debug".to_string(),
            },
            performance: PerformanceConfig {
                cpu_limit_percent: 10.0,
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
            ..AgentConfig::default()
        };

        // Test serialization
        let serialized =
            toml::to_string_pretty(&baseline_config).expect("Should serialize to TOML");
        assert!(
            serialized.contains("[service]"),
            "Should contain [service] section"
        );
        assert!(
            serialized.contains("[observability]"),
            "Should contain [observability] section"
        );
        assert!(
            serialized.contains("[performance]"),
            "Should contain [performance] section"
        );
        assert!(
            serialized.contains("[detection]"),
            "Should contain [detection] section"
        );

        // Test deserialization
        let deserialized: AgentConfig =
            toml::from_str(&serialized).expect("Should deserialize from TOML");
        assert_eq!(deserialized.service.mode, baseline_config.service.mode);
        assert_eq!(
            deserialized.observability.metrics_bind,
            baseline_config.observability.metrics_bind
        );

        println!("✓ Baseline config serialization/deserialization works correctly");
    }

    #[test]
    fn test_toml_round_trip_validation() {
        println!("Testing TOML round-trip serialization/deserialization...");

        // Create a comprehensive test config with all fields populated
        let mut test_config = AgentConfig::default();
        test_config.config_version = "2.0".to_string();
        test_config.agent_id = "test-agent-12345".to_string();
        test_config.ipc_key = "test-ipc-key-67890".to_string();
        test_config.quarantine_path = "C:\\Quarantine\\Test".to_string();
        test_config.audit_log_path = "C:\\Logs\\audit.log".to_string();
        test_config.mass_modification_count = Some(100);

        test_config.service.mode = "production".to_string();
        test_config.service.scan_paths = vec![
            "C:\\Users".to_string(),
            "C:\\Program Files".to_string(),
            "D:\\Data".to_string(),
        ];
        test_config.service.exclude_paths = vec![
            "C:\\Windows\\System32".to_string(),
            "C:\\$Recycle.Bin".to_string(),
            "C:\\Windows\\Temp".to_string(),
        ];
        test_config.service.ipc_bind = "127.0.0.1:8888".to_string();
        test_config.service.allow_volume_scan = Some(false);

        test_config.observability.metrics_bind = "127.0.0.1:19091".to_string();
        test_config.observability.metrics_port = 19091;
        test_config.observability.dashboard_bind = "127.0.0.1:19092".to_string();
        test_config.observability.dashboard_port = 19092;
        test_config.observability.log_level = "info".to_string();
        test_config.observability.log_filters = "cranelift=warn,wasmtime=info".to_string();

        test_config.performance.cpu_limit_percent = 6.0;
        test_config.performance.memory_limit_mb = 200;
        test_config.performance.enable_enforcement = true;

        test_config.detection.mttd_target_seconds = 60;
        test_config.detection.false_positive_threshold = 0.1;
        test_config.detection.enable_yara_fs_monitor = true;
        test_config.detection.yara_rules_path = "./yara_rules".to_string();

        // Serialize to TOML
        let toml_string =
            toml::to_string_pretty(&test_config).expect("Failed to serialize config to TOML");

        println!("✓ Config serialized to TOML successfully");

        // Verify TOML contains all expected sections
        assert!(
            toml_string.contains("[service]"),
            "TOML should contain [service] section"
        );
        assert!(
            toml_string.contains("[observability]"),
            "TOML should contain [observability] section"
        );
        assert!(
            toml_string.contains("[performance]"),
            "TOML should contain [performance] section"
        );
        assert!(
            toml_string.contains("[detection]"),
            "TOML should contain [detection] section"
        );

        // Verify specific values are present in TOML
        assert!(
            toml_string.contains("mode = \"production\""),
            "TOML should contain production mode"
        );
        assert!(
            toml_string.contains("metrics_bind = \"127.0.0.1:19091\""),
            "TOML should contain metrics bind"
        );
        assert!(
            toml_string.contains("cpu_limit_percent = 6.0"),
            "TOML should contain CPU limit"
        );
        assert!(
            toml_string.contains("mttd_target_seconds = 60"),
            "TOML should contain MTTD target"
        );

        println!("✓ TOML contains all expected sections and values");

        // Deserialize back from TOML
        let deserialized_config: AgentConfig =
            toml::from_str(&toml_string).expect("Failed to deserialize config from TOML");

        println!("✓ Config deserialized from TOML successfully");

        // Validate all fields match exactly
        assert_eq!(
            deserialized_config.config_version, test_config.config_version,
            "Config version mismatch"
        );
        assert_eq!(
            deserialized_config.agent_id, test_config.agent_id,
            "Agent ID mismatch"
        );
        assert_eq!(
            deserialized_config.ipc_key, test_config.ipc_key,
            "IPC key mismatch"
        );
        assert_eq!(
            deserialized_config.quarantine_path, test_config.quarantine_path,
            "Quarantine path mismatch"
        );
        assert_eq!(
            deserialized_config.audit_log_path, test_config.audit_log_path,
            "Audit log path mismatch"
        );
        assert_eq!(
            deserialized_config.mass_modification_count, test_config.mass_modification_count,
            "Mass modification count mismatch"
        );

        // Service section validation
        assert_eq!(
            deserialized_config.service.mode, test_config.service.mode,
            "Service mode mismatch"
        );
        assert_eq!(
            deserialized_config.service.scan_paths, test_config.service.scan_paths,
            "Scan paths mismatch"
        );
        assert_eq!(
            deserialized_config.service.exclude_paths, test_config.service.exclude_paths,
            "Exclude paths mismatch"
        );
        assert_eq!(
            deserialized_config.service.ipc_bind, test_config.service.ipc_bind,
            "IPC bind mismatch"
        );
        assert_eq!(
            deserialized_config.service.allow_volume_scan, test_config.service.allow_volume_scan,
            "Allow volume scan mismatch"
        );

        // Observability section validation
        assert_eq!(
            deserialized_config.observability.metrics_bind, test_config.observability.metrics_bind,
            "Metrics bind mismatch"
        );
        assert_eq!(
            deserialized_config.observability.metrics_port, test_config.observability.metrics_port,
            "Metrics port mismatch"
        );
        assert_eq!(
            deserialized_config.observability.dashboard_bind,
            test_config.observability.dashboard_bind,
            "Dashboard bind mismatch"
        );
        assert_eq!(
            deserialized_config.observability.dashboard_port,
            test_config.observability.dashboard_port,
            "Dashboard port mismatch"
        );
        assert_eq!(
            deserialized_config.observability.log_level, test_config.observability.log_level,
            "Log level mismatch"
        );
        assert_eq!(
            deserialized_config.observability.log_filters, test_config.observability.log_filters,
            "Log filters mismatch"
        );

        // Performance section validation
        assert_eq!(
            deserialized_config.performance.cpu_limit_percent,
            test_config.performance.cpu_limit_percent,
            "CPU limit mismatch"
        );
        assert_eq!(
            deserialized_config.performance.memory_limit_mb,
            test_config.performance.memory_limit_mb,
            "Memory limit mismatch"
        );
        assert_eq!(
            deserialized_config.performance.enable_enforcement,
            test_config.performance.enable_enforcement,
            "Enable enforcement mismatch"
        );

        // Detection section validation
        assert_eq!(
            deserialized_config.detection.mttd_target_seconds,
            test_config.detection.mttd_target_seconds,
            "MTTD target mismatch"
        );
        assert_eq!(
            deserialized_config.detection.false_positive_threshold,
            test_config.detection.false_positive_threshold,
            "FP threshold mismatch"
        );
        assert_eq!(
            deserialized_config.detection.enable_yara_fs_monitor,
            test_config.detection.enable_yara_fs_monitor,
            "YARA FS monitor mismatch"
        );
        assert_eq!(
            deserialized_config.detection.yara_rules_path, test_config.detection.yara_rules_path,
            "YARA rules path mismatch"
        );

        println!("✓ All fields validated - round-trip serialization successful");
        println!("✅ TOML round-trip validation completed successfully!");
    }

    #[test]
    fn test_config_edge_cases_and_validation() {
        println!("Testing config edge cases and validation rules...");

        // Test empty scan paths (should be handled gracefully)
        let mut config_with_empty_paths = AgentConfig::default();
        config_with_empty_paths.service.scan_paths = vec![];

        let serialized = toml::to_string_pretty(&config_with_empty_paths)
            .expect("Should serialize config with empty scan paths");
        let deserialized: AgentConfig =
            toml::from_str(&serialized).expect("Should deserialize config with empty scan paths");

        assert!(
            deserialized.service.scan_paths.is_empty(),
            "Empty scan paths should remain empty"
        );
        println!("✓ Empty scan paths handled correctly");

        // Test boundary values for performance limits
        let mut config_with_boundaries = AgentConfig::default();
        config_with_boundaries.performance.cpu_limit_percent = 0.1; // Very low
        config_with_boundaries.performance.memory_limit_mb = 1; // Very low
        config_with_boundaries.detection.false_positive_threshold = 0.0; // Minimum

        let serialized = toml::to_string_pretty(&config_with_boundaries)
            .expect("Should serialize config with boundary values");
        let deserialized: AgentConfig =
            toml::from_str(&serialized).expect("Should deserialize config with boundary values");

        assert_eq!(
            deserialized.performance.cpu_limit_percent, 0.1,
            "Boundary CPU limit should be preserved"
        );
        assert_eq!(
            deserialized.performance.memory_limit_mb, 1,
            "Boundary memory limit should be preserved"
        );
        assert_eq!(
            deserialized.detection.false_positive_threshold, 0.0,
            "Boundary FP threshold should be preserved"
        );
        println!("✓ Boundary values handled correctly");

        // Test optional fields
        let mut config_with_optionals = AgentConfig::default();
        config_with_optionals.service.allow_volume_scan = None; // Test None case
        config_with_optionals.mass_modification_count = None; // Test None case

        let serialized = toml::to_string_pretty(&config_with_optionals)
            .expect("Should serialize config with None optionals");
        let deserialized: AgentConfig =
            toml::from_str(&serialized).expect("Should deserialize config with None optionals");

        assert_eq!(
            deserialized.service.allow_volume_scan, None,
            "None optional should remain None"
        );
        assert_eq!(
            deserialized.mass_modification_count, None,
            "None optional should remain None"
        );
        println!("✓ Optional None fields handled correctly");

        // Test special characters in paths
        let mut config_with_special_chars = AgentConfig::default();
        config_with_special_chars.service.scan_paths = vec![
            "C:\\Users\\Test User".to_string(), // Space in path
            "D:\\Data & Files".to_string(),     // Ampersand
            "E:\\Files (Archive)".to_string(),  // Parentheses
        ];

        let serialized = toml::to_string_pretty(&config_with_special_chars)
            .expect("Should serialize config with special characters");
        let deserialized: AgentConfig =
            toml::from_str(&serialized).expect("Should deserialize config with special characters");

        assert_eq!(
            deserialized.service.scan_paths, config_with_special_chars.service.scan_paths,
            "Special characters in paths should be preserved"
        );
        println!("✓ Special characters in paths handled correctly");

        println!("✅ Edge cases and validation rules tested successfully!");
    }

    #[test]
    fn test_production_config_requirements() {
        println!("Testing production configuration requirements...");

        // Load actual config.toml if it exists
        let config_path = "config.toml";
        if !std::path::Path::new(config_path).exists() {
            println!("⚠ config.toml not found, skipping production requirements test");
            return;
        }

        let config = AgentConfig::load_from_file(config_path)
            .expect("Failed to load config.toml for production requirements test");

        // Production-specific validations
        assert_eq!(
            config.service.mode, "production",
            "Production config must have mode='production'"
        );

        // Security requirements
        assert_eq!(
            config.service.allow_volume_scan.unwrap_or(true),
            false,
            "Production should have allow_volume_scan=false for security"
        );
        assert!(
            !config.service.scan_paths.contains(&"C:\\".to_string()),
            "Production should not scan entire C: drive"
        );
        assert!(
            !config.service.scan_paths.contains(&"D:\\".to_string()),
            "Production should not scan entire D: drive"
        );

        // Performance requirements
        assert!(
            config.performance.cpu_limit_percent <= 10.0,
            "Production CPU limit should be <= 10%"
        );
        assert!(
            config.performance.memory_limit_mb <= 500,
            "Production memory limit should be <= 500MB"
        );
        assert!(
            config.performance.enable_enforcement,
            "Production must have performance enforcement enabled"
        );

        // SLO requirements
        assert!(
            config.detection.mttd_target_seconds <= 120,
            "Production MTTD should be <= 120 seconds"
        );
        assert!(
            config.detection.false_positive_threshold <= 0.2,
            "Production FP threshold should be <= 0.2"
        );

        // Logging requirements
        assert!(
            config.observability.log_level == "info" || config.observability.log_level == "warn",
            "Production log level should be 'info' or 'warn', not debug"
        );

        // Network binding requirements
        assert!(
            config.service.ipc_bind.starts_with("127.0.0.1:")
                || config.service.ipc_bind.starts_with("localhost:"),
            "Production IPC should bind to localhost only"
        );
        assert!(
            config.observability.metrics_bind.starts_with("127.0.0.1:")
                || config.observability.metrics_bind.starts_with("localhost:"),
            "Production metrics should bind to localhost only"
        );

        // Path validation requirements
        assert!(
            !config.quarantine_path.is_empty(),
            "Production must have quarantine path configured"
        );
        assert!(
            !config.audit_log_path.is_empty(),
            "Production must have audit log path configured"
        );
        assert!(
            !config.detection.yara_rules_path.is_empty(),
            "Production must have YARA rules path configured"
        );

        println!("✓ Production security requirements validated");
        println!("✓ Production performance requirements validated");
        println!("✓ Production SLO requirements validated");
        println!("✓ Production logging requirements validated");
        println!("✓ Production network binding requirements validated");
        println!("✓ Production path validation requirements validated");

        println!("✅ All production configuration requirements met!");
    }
}
