//! Unit tests for the rule validator

#[cfg(test)]
mod tests {
    use super::super::rule_validator::*;
    use std::path::PathBuf;
    use tempfile::TempDir;
    use tokio;

    #[tokio::test]
    async fn test_validate_valid_rule() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let rules_path = temp_dir.path().to_path_buf();
        
        let mut validator = RuleValidator::new(db_path, rules_path);
        
        // Create a simple valid YARA rule
        let rule_content = r#"
rule TestRule {
    meta:
        description = "Test rule"
    strings:
        $test = "hello"
    condition:
        $test
}
"#;
        
        let rule_file = temp_dir.path().join("test.yar");
        std::fs::write(&rule_file, rule_content).unwrap();
        
        let result = validator.validate_file(&rule_file).await;
        assert!(result.is_ok());
        
        let validation_result = result.unwrap();
        assert_eq!(validation_result.rule_name, "TestRule");
        assert!(matches!(validation_result.status, ValidationStatus::Valid));
        assert!(validation_result.errors.is_empty());
    }
    
    #[tokio::test]
    async fn test_validate_invalid_rule() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let rules_path = temp_dir.path().to_path_buf();
        
        let mut validator = RuleValidator::new(db_path, rules_path);
        
        // Create an invalid YARA rule
        let rule_content = r#"
rule InvalidRule {
    strings:
        $invalid = { FF ZZ }  // Invalid hex
    condition:
        invalid_function()    // Non-existent function
}
"#;
        
        let rule_file = temp_dir.path().join("invalid.yar");
        std::fs::write(&rule_file, rule_content).unwrap();
        
        let result = validator.validate_file(&rule_file).await;
        assert!(result.is_ok());
        
        let validation_result = result.unwrap();
        assert_eq!(validation_result.rule_name, "InvalidRule");
        assert!(matches!(validation_result.status, ValidationStatus::Invalid));
        assert!(!validation_result.errors.is_empty());
    }
    
    #[tokio::test]
    async fn test_validate_directory() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let rules_path = temp_dir.path().to_path_buf();
        
        let mut validator = RuleValidator::new(db_path, rules_path);
        
        // Create multiple rule files
        let valid_rule = r#"
rule ValidRule {
    strings:
        $test = "valid"
    condition:
        $test
}
"#;
        
        let invalid_rule = r#"
rule InvalidRule {
    strings:
        $bad = { FF ZZ }
    condition:
        bad_function()
}
"#;
        
        std::fs::write(temp_dir.path().join("valid.yar"), valid_rule).unwrap();
        std::fs::write(temp_dir.path().join("invalid.yar"), invalid_rule).unwrap();
        
        let result = validator.validate_directory(temp_dir.path()).await;
        assert!(result.is_ok());
        
        let summary = result.unwrap();
        assert_eq!(summary.total_rules, 2);
        assert_eq!(summary.valid_rules, 1);
        assert_eq!(summary.invalid_rules, 1);
    }
    
    #[test]
    fn test_validation_status_display() {
        assert_eq!(format!("{:?}", ValidationStatus::Valid), "Valid");
        assert_eq!(format!("{:?}", ValidationStatus::Invalid), "Invalid");
        assert_eq!(format!("{:?}", ValidationStatus::Slow), "Slow");
        assert_eq!(format!("{:?}", ValidationStatus::Duplicate), "Duplicate");
    }
    
    #[test]
    fn test_validation_error_creation() {
        let error = ValidationError {
            error_type: ValidationErrorType::SyntaxError,
            message: "Test error".to_string(),
            line_number: Some(10),
            column_number: Some(5),
        };
        
        assert_eq!(error.message, "Test error");
        assert_eq!(error.line_number, Some(10));
        assert_eq!(error.column_number, Some(5));
    }
    
    #[test]
    fn test_validation_warning_creation() {
        let warning = ValidationWarning {
            warning_type: ValidationWarningType::Performance,
            message: "Slow rule".to_string(),
            line_number: None,
        };
        
        assert_eq!(warning.message, "Slow rule");
        assert!(matches!(warning.warning_type, ValidationWarningType::Performance));
    }
}
