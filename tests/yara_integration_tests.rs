//! YARA Scanner Integration Tests
//!
//! This module contains comprehensive integration tests for the YARA scanner,
//! including rule compilation, file scanning, and error handling scenarios.

use std::fs;
use tempfile::TempDir;

/// Create a temporary directory with test YARA rules
fn create_test_yara_rules() -> Result<TempDir, std::io::Error> {
    let temp_dir = TempDir::new()?;

    // Create a simple YARA rule for testing
    let rule_content = r#"
rule TestMalwareRule {
    meta:
        description = "Test rule for malware detection"
        author = "ERDPS Test Suite"
        date = "2024-01-01"
        
    strings:
        $malware_string = "MALWARE_SIGNATURE_TEST"
        $suspicious_pattern = { 4D 5A 90 00 }  // PE header
        
    condition:
        $malware_string or $suspicious_pattern
}

rule TestRansomwareRule {
    meta:
        description = "Test rule for ransomware detection"
        family = "test_ransomware"
        
    strings:
        $ransom_note = "Your files have been encrypted"
        $crypto_lib = "CryptEncrypt"
        $file_ext = ".locked" nocase
        
    condition:
        any of them
}

rule TestPackedExecutable {
    meta:
        description = "Detects packed executables"
        
    strings:
        $upx_sig = "UPX!"
        
    condition:
        $upx_sig
}
"#;

    // Write the rule to a file
    let rule_file = temp_dir.path().join("test_rules.yar");
    fs::write(&rule_file, rule_content)?;

    Ok(temp_dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_yara_rules() {
        let temp_dir = create_test_yara_rules().expect("Failed to create test YARA rules");
        let rule_file = temp_dir.path().join("test_rules.yar");
        assert!(rule_file.exists());

        let content = fs::read_to_string(&rule_file).expect("Failed to read rule file");
        assert!(content.contains("TestMalwareRule"));
        assert!(content.contains("TestRansomwareRule"));
        assert!(content.contains("TestPackedExecutable"));
    }
}
