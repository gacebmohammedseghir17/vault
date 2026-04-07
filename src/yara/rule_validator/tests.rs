use super::*;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_yara_file(dir: &Path, filename: &str, content: &str) -> PathBuf {
        let file_path = dir.join(filename);
        fs::write(&file_path, content).expect("Failed to write test file");
        file_path
    }

    fn create_temp_db() -> (TempDir, PathBuf) {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let db_path = temp_dir.path().join("test.db");
        (temp_dir, db_path)
    }

    #[test]
    fn test_validation_status_enum() {
        // Test that ValidationStatus variants can be created
        let valid = ValidationStatus::Valid;
        let invalid = ValidationStatus::Invalid;
        let slow = ValidationStatus::Slow;
        let duplicate = ValidationStatus::Duplicate;

        // Basic enum functionality
        assert!(matches!(valid, ValidationStatus::Valid));
        assert!(matches!(invalid, ValidationStatus::Invalid));
        assert!(matches!(slow, ValidationStatus::Slow));
        assert!(matches!(duplicate, ValidationStatus::Duplicate));
    }

    #[test]
    fn test_validation_result_creation() {
        let result = ValidationResult {
            file_path: PathBuf::from("/test/rule.yar"),
            rule_name: "test_rule".to_string(),
            status: ValidationStatus::Valid,
            compilation_time_ms: 100,
            errors: vec![],
            warnings: vec![],
        };

        assert_eq!(result.file_path, PathBuf::from("/test/rule.yar"));
        assert_eq!(result.rule_name, "test_rule");
        assert!(matches!(result.status, ValidationStatus::Valid));
        assert_eq!(result.compilation_time_ms, 100);
        assert!(result.errors.is_empty());
        assert!(result.warnings.is_empty());
    }

    #[test]
    fn test_validation_summary_creation() {
        let summary = ValidationSummary {
            total_rules: 10,
            valid_rules: 8,
            invalid_rules: 1,
            slow_rules: 1,
            duplicate_rules: 0,
            total_time_ms: 5000,
        };

        assert_eq!(summary.total_rules, 10);
        assert_eq!(summary.valid_rules, 8);
        assert_eq!(summary.invalid_rules, 1);
        assert_eq!(summary.slow_rules, 1);
        assert_eq!(summary.duplicate_rules, 0);
        assert_eq!(summary.total_time_ms, 5000);
    }

    #[test]
    fn test_rule_validator_creation() {
        let (_temp_dir, db_path) = create_temp_db();
        let rules_path = PathBuf::from("/test/rules");

        let validator = RuleValidator::new(db_path.clone(), rules_path.clone());
        
        assert_eq!(validator.db_path, db_path);
        assert_eq!(validator.rules_base_path, rules_path);
        assert_eq!(validator.slow_threshold_ms, 500);
        assert!(!validator.strict_mode);
        assert!(!validator.performance_mode);
    }

    #[test]
    fn test_rule_validator_with_flags() {
        let validator = RuleValidator::new_with_flags(true, true);
        
        assert!(validator.strict_mode);
        assert!(validator.performance_mode);
        assert_eq!(validator.slow_threshold_ms, 100); // Performance mode threshold
    }

    #[test]
    fn test_yara_rule_validator_wrapper() {
        let validator = YaraRuleValidator::new(false, false);
        
        // Test that the wrapper can be created
        assert!(!validator.inner.strict_mode);
        assert!(!validator.inner.performance_mode);
    }

    #[test]
    fn test_validation_stats_creation() {
        let stats = ValidationStats {
            total_files_validated: 50,
            valid_files: 45,
            invalid_files: 3,
            slow_files: 2,
            duplicate_files: 0,
            total_validation_time: Duration::from_secs(30),
            average_validation_time: Duration::from_millis(600),
            error_distribution: std::collections::HashMap::new(),
            warning_distribution: std::collections::HashMap::new(),
        };

        assert_eq!(stats.total_files_validated, 50);
        assert_eq!(stats.valid_files, 45);
        assert_eq!(stats.invalid_files, 3);
        assert_eq!(stats.slow_files, 2);
        assert_eq!(stats.duplicate_files, 0);
        assert_eq!(stats.total_validation_time, Duration::from_secs(30));
        assert_eq!(stats.average_validation_time, Duration::from_millis(600));
    }

    #[test]
    fn test_summary_to_stats_conversion() {
        let summary = ValidationSummary {
            total_rules: 100,
            valid_rules: 90,
            invalid_rules: 5,
            slow_rules: 3,
            duplicate_rules: 2,
            total_time_ms: 10000,
        };

        let validator = YaraRuleValidator::new(false, false);
        let stats = validator.summary_to_stats(&summary);

        assert_eq!(stats.total_files_validated, 100);
        assert_eq!(stats.valid_files, 90);
        assert_eq!(stats.invalid_files, 5);
        assert_eq!(stats.slow_files, 3);
        assert_eq!(stats.duplicate_files, 2);
        assert_eq!(stats.total_validation_time, Duration::from_millis(10000));
        assert_eq!(stats.average_validation_time, Duration::from_millis(100));
    }

    #[tokio::test]
    async fn test_validate_directory_async() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let test_path = temp_dir.path().to_path_buf();
        
        // Create a simple test YARA file
        create_test_yara_file(
            &test_path,
            "test.yar",
            "rule test_rule { condition: true }"
        );

        let mut validator = YaraRuleValidator::new(false, false);
        let result = validator.validate_directory(&test_path).await;
        
        // Should return a ValidationSummary (even if empty due to our placeholder implementation)
        assert!(result.is_ok());
    }

    #[test]
    fn test_get_validation_results() {
        let validator = YaraRuleValidator::new(false, false);
        let results = validator.get_validation_results();
        
        // Currently returns empty vector as placeholder
        assert!(results.is_empty());
    }
}
