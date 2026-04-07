//! Simple test program for rule validator

use std::path::PathBuf;
use tokio;

mod src {
    pub mod yara {
        pub mod rule_validator;
    }
    pub mod error;
}

use src::yara::rule_validator::RuleValidator;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing YARA Rule Validator...");
    
    let db_path = PathBuf::from("test_validation.db");
    let rules_path = PathBuf::from("yara_rules");
    
    let mut validator = RuleValidator::new(db_path, rules_path);
    
    // Test with our test source directory
    let test_path = PathBuf::from("yara_rules/test_source");
    
    if !test_path.exists() {
        println!("Test directory does not exist: {:?}", test_path);
        return Ok(());
    }
    
    println!("Validating rules in: {:?}", test_path);
    
    match validator.validate_directory(&test_path).await {
        Ok(summary) => {
            println!("\nValidation Results:");
            println!("==================");
            println!("Total rules: {}", summary.total_rules);
            println!("Valid rules: {}", summary.valid_rules);
            println!("Invalid rules: {}", summary.invalid_rules);
            println!("Slow rules: {}", summary.slow_rules);
            println!("Duplicate rules: {}", summary.duplicate_rules);
            println!("Total time: {}ms", summary.total_time_ms);
            
            // Show validation results
            let results = validator.get_validation_results();
            for (file_path, result) in results {
                println!("\nFile: {:?}", file_path);
                println!("  Rule: {}", result.rule_name);
                println!("  Status: {:?}", result.status);
                println!("  Compilation time: {}ms", result.compilation_time_ms);
                
                if !result.errors.is_empty() {
                    println!("  Errors:");
                    for error in &result.errors {
                        println!("    - {}", error.message);
                    }
                }
                
                if !result.warnings.is_empty() {
                    println!("  Warnings:");
                    for warning in &result.warnings {
                        println!("    - {}", warning.message);
                    }
                }
            }
        }
        Err(e) => {
            println!("Validation failed: {}", e);
        }
    }
    
    Ok(())
}