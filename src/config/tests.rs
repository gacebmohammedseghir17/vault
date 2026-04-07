use super::*;
use std::path::Path;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_toml_parsing() {
        // Load the actual config.toml file
        let config_path = "config.toml";
        assert!(
            Path::new(config_path).exists(),
            "config.toml file must exist"
        );

        let config = AgentConfig::load_from_file(config_path)
            .expect("Failed to load config.toml - check TOML schema alignment");

        // Assert parsed values for binds
        assert_eq!(
            config.service.ipc_bind, "127.0.0.1:8888",
            "IPC bind address mismatch"
        );

        // Assert parsed values for scan_paths
        let expected_scan_paths = vec!["C:\\Users".to_string(), "C:\\Program Files".to_string()];
        assert_eq!(
            config.service.scan_paths, expected_scan_paths,
            "Scan paths mismatch"
        );

        // Assert parsed values for exclusions
        let expected_exclude_paths = vec![
            "C:\\Windows\\System32".to_string(),
            "C:\\Windows\\SysWOW64".to_string(),
        ];
        assert_eq!(
            config.service.exclude_paths, expected_exclude_paths,
            "Exclude paths mismatch"
        );

        // Assert SLO thresholds
        assert_eq!(
            config.performance.cpu_limit_percent, 10.0,
            "CPU threshold mismatch"
        );
        assert_eq!(
            config.performance.memory_limit_mb, 200,
            "Memory threshold mismatch"
        );

        // Assert log filters
        assert_eq!(config.observability.log_level, "info", "Log level mismatch");
        assert_eq!(
            config.observability.metrics_port, 19093,
            "Metrics port mismatch"
        );
        assert_eq!(
            config.observability.dashboard_port, 19094,
            "Dashboard port mismatch"
        );

        // Assert volume scan safety setting
        assert_eq!(
            config.service.allow_volume_scan,
            Some(false),
            "Volume scan safety setting mismatch"
        );

        // Assert config version is present
        assert!(
            !config.config_version.is_empty(),
            "Config version must be present"
        );

        println!("✓ All config.toml values parsed correctly");
        println!("✓ Config version: {}", config.config_version);
        println!("✓ Scan paths: {:?}", config.service.scan_paths);
        println!("✓ Exclude paths: {:?}", config.service.exclude_paths);
        println!(
            "✓ Volume scan allowed: {:?}",
            config.service.allow_volume_scan
        );
    }

    #[test]
    fn test_no_silent_fallback_to_defaults() {
        // This test ensures that if config.toml exists, all sections are properly loaded
        // and no section silently falls back to defaults
        let config_path = "config.toml";

        if Path::new(config_path).exists() {
            let config = AgentConfig::load_from_file(config_path)
                .expect("Config file exists but failed to parse");

            // Verify that critical sections are not using default values
            // by checking they differ from a default config
            let default_config = AgentConfig::default();

            // Service config should not be default if config.toml exists
            assert_ne!(
                config.service.scan_paths, default_config.service.scan_paths,
                "Service scan_paths appears to be using defaults - check TOML parsing"
            );

            // Performance config should not be default if config.toml exists
            assert_ne!(
                config.performance.cpu_limit_percent, default_config.performance.cpu_limit_percent,
                "Performance config appears to be using defaults - check TOML parsing"
            );

            // Observability config should not be default if config.toml exists
            assert_ne!(
                config.observability.metrics_port, default_config.observability.metrics_port,
                "Observability config appears to be using defaults - check TOML parsing"
            );

            println!("✓ No silent fallback to defaults detected");
        } else {
            println!("⚠ config.toml not found - skipping silent fallback test");
        }
    }

    #[test]
    fn test_config_version_field() {
        let config = AgentConfig::load_or_default("config.toml");

        // Config version should be present and non-empty
        assert!(
            !config.config_version.is_empty(),
            "Config version field must be present"
        );

        // Should follow semantic versioning pattern
        let version_parts: Vec<&str> = config.config_version.split('.').collect();
        assert!(
            version_parts.len() >= 2,
            "Config version should follow semantic versioning (e.g., '1.0')"
        );

        println!(
            "✓ Config version validation passed: {}",
            config.config_version
        );
    }
}
