//! Functional YARA Tests - Smoke Tests for Basic YARA Functionality
//! 
//! This module provides smoke tests to verify that basic YARA rule loading
//! and matching functionality works correctly with the yara-x API.

use yara_x::{Compiler, Scanner};
use std::error::Error;

/// Basic smoke test to verify YARA rule compilation and scanning
#[test]
fn test_yara_basic_functionality() -> Result<(), Box<dyn Error>> {
    // Create a simple YARA rule for testing
    let test_rule = r#"
        rule TestRule {
            strings:
                $test_string = "MALWARE_SIGNATURE"
            condition:
                $test_string
        }
    "#;
    
    // Test 1: Compiler::add_source - Load rule text
    let mut compiler = Compiler::new();
    compiler.add_source(test_rule)?;
    
    // Test 2: Compiler::build - Finalize rule set
    let rules = compiler.build();
    
    // Test 3: Scanner::scan - Perform in-memory scan with matching data
    let test_data_match = b"This contains MALWARE_SIGNATURE in the data";
    let mut scanner = Scanner::new(&rules);
    let scan_results = scanner.scan(test_data_match)?;
    
    // Verify that the rule matched
    assert!(scan_results.matching_rules().len() > 0, "Rule should match test data");
    
    // Test 4: Scanner::scan - Perform in-memory scan with non-matching data
    let test_data_no_match = b"This is clean data with no suspicious content";
    let mut scanner2 = Scanner::new(&rules);
    let scan_results2 = scanner2.scan(test_data_no_match)?;
    
    // Verify that the rule did not match
    assert_eq!(scan_results2.matching_rules().len(), 0, "Rule should not match clean data");
    
    Ok(())
}

/// Test YARA rule compilation with multiple rules
#[test]
fn test_yara_multiple_rules() -> Result<(), Box<dyn Error>> {
    let multi_rules = r#"
        rule Rule1 {
            strings:
                $s1 = "signature1"
            condition:
                $s1
        }
        
        rule Rule2 {
            strings:
                $s2 = "signature2"
            condition:
                $s2
        }
    "#;
    
    // Compile multiple rules
    let mut compiler = Compiler::new();
    compiler.add_source(multi_rules)?;
    let rules = compiler.build();
    
    // Test data that matches first rule
    let test_data1 = b"Contains signature1 here";
    let mut scanner1 = Scanner::new(&rules);
    let results1 = scanner1.scan(test_data1)?;
    assert_eq!(results1.matching_rules().len(), 1, "Should match exactly one rule");
    
    // Test data that matches second rule
    let test_data2 = b"Contains signature2 here";
    let mut scanner2 = Scanner::new(&rules);
    let results2 = scanner2.scan(test_data2)?;
    assert_eq!(results2.matching_rules().len(), 1, "Should match exactly one rule");
    
    // Test data that matches both rules
    let test_data_both = b"Contains signature1 and signature2 here";
    let mut scanner3 = Scanner::new(&rules);
    let results3 = scanner3.scan(test_data_both)?;
    assert_eq!(results3.matching_rules().len(), 2, "Should match both rules");
    
    Ok(())
}

/// Test YARA error handling for invalid rules
#[test]
fn test_yara_invalid_rule_handling() {
    let invalid_rule = r#"
        rule InvalidRule {
            strings:
                $invalid = "test
            condition:
                $invalid
        }
    "#;
    
    let mut compiler = Compiler::new();
    let result = compiler.add_source(invalid_rule);
    
    // Should fail to compile invalid rule
    assert!(result.is_err(), "Invalid rule should fail to compile");
}

/// Test YARA with empty rule set
#[test]
fn test_yara_empty_rules() -> Result<(), Box<dyn Error>> {
    let compiler = Compiler::new();
    let rules = compiler.build();
    
    let test_data = b"Any data here";
    let mut scanner = Scanner::new(&rules);
    let results = scanner.scan(test_data)?;
    
    // No rules should match
    assert_eq!(results.matching_rules().len(), 0, "No rules should match with empty rule set");
    
    Ok(())
}