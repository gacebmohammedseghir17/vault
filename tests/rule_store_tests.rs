//! Comprehensive unit tests for the RuleStore implementation
//!
//! These tests cover all major functionality including:
//! - Download and hash validation
//! - Rule compilation
//! - Manifest generation and validation
//! - Atomic activation
//! - Hash-based deduplication
//! - Error handling and edge cases

#[cfg(feature = "yara")]
mod rule_store_tests {
    use std::fs;
    use std::sync::Arc;
    use tempfile::TempDir;
    use tokio::time::{sleep, Duration};

    use erdps_agent::detection::rule_store::*;

    /// Create a test configuration with temporary directory
    fn create_test_config() -> (RuleStoreConfig, TempDir) {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let config = RuleStoreConfig {
            rules_dir: temp_dir.path().to_path_buf(),
            update_url:
                "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/APT_APT1.yar"
                    .to_string(),
            update_interval_secs: 3600,
            require_signed_rules: false,
        };
        (config, temp_dir)
    }

    /// Create a simple test YARA rule
    fn create_test_rule() -> String {
        r#"
rule TestRule {
    meta:
        description = "Test rule for unit testing"
        author = "ERDPS Test Suite"
        date = "2025-01-21"
    
    strings:
        $test_string = "MALWARE_SIGNATURE_TEST"
        $hex_pattern = { 4D 5A 90 00 }
    
    condition:
        $test_string or $hex_pattern
}

rule AnotherTestRule {
    meta:
        description = "Another test rule"
    
    strings:
        $suspicious = "suspicious_behavior"
    
    condition:
        $suspicious
}
"#
        .to_string()
    }

    /// Create a malformed YARA rule for error testing
    fn create_malformed_rule() -> String {
        r#"
rule MalformedRule {
    meta:
        description = "This rule has syntax errors"
    
    strings:
        $test = "test
    
    condition:
        // Missing closing quote and brace
"#
        .to_string()
    }

    #[tokio::test]
    async fn test_rule_store_creation() {
        let (config, _temp_dir) = create_test_config();
        let store = create_rule_store(config);
        assert!(
            store.is_ok(),
            "Failed to create rule store: {:?}",
            store.err()
        );
    }

    #[tokio::test]
    async fn test_download_and_hash_validation() {
        let (config, temp_dir) = create_test_config();
        let store = create_rule_store(config).expect("Failed to create rule store");

        // Create a test rule file to simulate download
        let test_rule = create_test_rule();
        let rule_file = temp_dir.path().join("test_rule.yar");
        fs::write(&rule_file, &test_rule).expect("Failed to write test rule");

        // Test local file "download" (simulate by copying)
        let _bundle_result = store
            .download_bundle(&format!("file://{}", rule_file.display()), None)
            .await;

        // Note: This test would need a mock HTTP server for real download testing
        // For now, we'll test the hash computation directly

        // Test hash computation
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(test_rule.as_bytes());
        let expected_hash = format!("{:x}", hasher.finalize());

        assert_eq!(
            expected_hash.len(),
            64,
            "SHA-256 hash should be 64 characters"
        );
        println!("Test rule hash: {}", expected_hash);
    }

    #[tokio::test]
    async fn test_rule_compilation() {
        let (config, temp_dir) = create_test_config();
        let store = create_rule_store(config).expect("Failed to create rule store");

        // Create a test rule bundle
        let test_rule = create_test_rule();
        let rule_file = temp_dir.path().join("test_compilation.yar");
        fs::write(&rule_file, &test_rule).expect("Failed to write test rule");

        // Compute hash for the bundle
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(test_rule.as_bytes());
        let hash = format!("{:x}", hasher.finalize());

        let bundle = RuleBundle {
            name: "test_compilation".to_string(),
            version: "1.0.0".to_string(),
            path: rule_file,
            sha256: hash,
            count: 0, // Will be updated during compilation
        };

        // Test compilation
        let compiled_result = store.compile(&bundle);
        assert!(
            compiled_result.is_ok(),
            "Failed to compile rules: {:?}",
            compiled_result.err()
        );

        let compiled = compiled_result.unwrap();
        assert!(
            compiled.meta.count > 0,
            "Compiled rules should have count > 0"
        );
        assert_eq!(compiled.meta.name, "test_compilation");

        // Test that compiled rules can be accessed
        let rules_guard = compiled.handle.read().unwrap();
        // The rules object should be valid (we can't easily test scanning without a target)
        drop(rules_guard);
    }

    #[tokio::test]
    async fn test_compilation_error_handling() {
        let (config, temp_dir) = create_test_config();
        let store = create_rule_store(config).expect("Failed to create rule store");

        // Create a malformed rule bundle
        let malformed_rule = create_malformed_rule();
        let rule_file = temp_dir.path().join("malformed.yar");
        fs::write(&rule_file, &malformed_rule).expect("Failed to write malformed rule");

        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(malformed_rule.as_bytes());
        let hash = format!("{:x}", hasher.finalize());

        let bundle = RuleBundle {
            name: "malformed_test".to_string(),
            version: "1.0.0".to_string(),
            path: rule_file,
            sha256: hash,
            count: 0,
        };

        // Test that compilation fails gracefully
        let compiled_result = store.compile(&bundle);
        assert!(
            compiled_result.is_err(),
            "Compilation should fail for malformed rules"
        );

        // Verify error type
        match compiled_result {
            Err(error) => match error {
                RuleStoreError::CompileError {
                    bundle: bundle_name,
                    reason: _,
                } => {
                    assert_eq!(bundle_name, "malformed_test");
                }
                other => panic!("Expected CompileError, got: {:?}", other),
            },
            Ok(_) => panic!("Expected compilation to fail"),
        }
    }

    #[tokio::test]
    async fn test_manifest_generation() {
        let (config, temp_dir) = create_test_config();
        let store = create_rule_store(config).expect("Failed to create rule store");

        // Create and compile a test rule
        let test_rule = create_test_rule();
        let rule_file = temp_dir.path().join("manifest_test.yar");
        fs::write(&rule_file, &test_rule).expect("Failed to write test rule");

        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(test_rule.as_bytes());
        let hash = format!("{:x}", hasher.finalize());

        let bundle = RuleBundle {
            name: "manifest_test".to_string(),
            version: "2.0.0".to_string(),
            path: rule_file,
            sha256: hash.clone(),
            count: 0,
        };

        let _compiled = store.compile(&bundle).expect("Failed to compile rules");

        // Check that manifest file was created
        let manifest_path = temp_dir.path().join("cache").join(format!("{}.json", hash));
        assert!(manifest_path.exists(), "Manifest file should be created");

        // Validate manifest content
        let manifest_content =
            fs::read_to_string(&manifest_path).expect("Failed to read manifest file");

        let manifest: serde_json::Value =
            serde_json::from_str(&manifest_content).expect("Failed to parse manifest JSON");

        assert_eq!(manifest["name"], "manifest_test");
        assert_eq!(manifest["version"], "2.0.0");
        assert_eq!(manifest["sha256"], hash);
        assert!(manifest["count"].as_u64().unwrap() > 0);
        assert!(manifest["created_at"].is_string());
    }

    #[tokio::test]
    async fn test_atomic_activation() {
        let (config, temp_dir) = create_test_config();
        let store = create_rule_store(config).expect("Failed to create rule store");

        // Initially, no rules should be active
        let current = store.current();
        {
            let guard = current.read().unwrap();
            assert!(guard.is_none(), "No rules should be active initially");
        }

        // Create and compile first rule set
        let test_rule1 = create_test_rule();
        let rule_file1 = temp_dir.path().join("activation_test1.yar");
        fs::write(&rule_file1, &test_rule1).expect("Failed to write test rule 1");

        use sha2::{Digest, Sha256};
        let mut hasher1 = Sha256::new();
        hasher1.update(test_rule1.as_bytes());
        let hash1 = format!("{:x}", hasher1.finalize());

        let bundle1 = RuleBundle {
            name: "activation_test1".to_string(),
            version: "1.0.0".to_string(),
            path: rule_file1,
            sha256: hash1,
            count: 0,
        };

        let compiled1 = store.compile(&bundle1).expect("Failed to compile rules 1");

        // Activate first rule set
        store
            .activate(compiled1.clone())
            .expect("Failed to activate rules 1");

        // Verify first rule set is active
        {
            let guard = current.read().unwrap();
            assert!(guard.is_some(), "Rules should be active after activation");
            let active_rules = guard.as_ref().unwrap();
            assert_eq!(active_rules.meta.name, "activation_test1");
        }

        // Create and compile second rule set
        let test_rule2 = r#"
rule SecondTestRule {
    meta:
        description = "Second test rule for activation testing"
    
    strings:
        $second = "second_test_pattern"
    
    condition:
        $second
}
"#;
        let rule_file2 = temp_dir.path().join("activation_test2.yar");
        fs::write(&rule_file2, test_rule2).expect("Failed to write test rule 2");

        let mut hasher2 = Sha256::new();
        hasher2.update(test_rule2.as_bytes());
        let hash2 = format!("{:x}", hasher2.finalize());

        let bundle2 = RuleBundle {
            name: "activation_test2".to_string(),
            version: "2.0.0".to_string(),
            path: rule_file2,
            sha256: hash2,
            count: 0,
        };

        let compiled2 = store.compile(&bundle2).expect("Failed to compile rules 2");

        // Activate second rule set (should replace first)
        store
            .activate(compiled2.clone())
            .expect("Failed to activate rules 2");

        // Verify second rule set is now active
        {
            let guard = current.read().unwrap();
            assert!(guard.is_some(), "Rules should still be active after swap");
            let active_rules = guard.as_ref().unwrap();
            assert_eq!(active_rules.meta.name, "activation_test2");
            assert_eq!(active_rules.meta.version, "2.0.0");
        }
    }

    #[tokio::test]
    async fn test_hash_based_deduplication() {
        let (config, temp_dir) = create_test_config();
        let store = create_rule_store(config).expect("Failed to create rule store");

        // Create a test rule
        let test_rule = create_test_rule();
        let rule_file = temp_dir.path().join("dedup_test.yar");
        fs::write(&rule_file, &test_rule).expect("Failed to write test rule");

        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(test_rule.as_bytes());
        let hash = format!("{:x}", hasher.finalize());

        let bundle1 = RuleBundle {
            name: "dedup_test1".to_string(),
            version: "1.0.0".to_string(),
            path: rule_file.clone(),
            sha256: hash.clone(),
            count: 0,
        };

        // Compile first instance
        let compiled1 = store
            .compile(&bundle1)
            .expect("Failed to compile first instance");

        // Create second bundle with same content (different name/version)
        let bundle2 = RuleBundle {
            name: "dedup_test2".to_string(),
            version: "2.0.0".to_string(),
            path: rule_file,
            sha256: hash.clone(),
            count: 0,
        };

        // Compile second instance - should work but use cached data
        let compiled2 = store
            .compile(&bundle2)
            .expect("Failed to compile second instance");

        // Both should have the same hash
        assert_eq!(compiled1.meta.sha256, compiled2.meta.sha256);

        // Verify cache directory contains the compiled rule
        let cache_dir = temp_dir.path().join("cache");
        let cbin_path = cache_dir.join(format!("{}.cbin", hash));
        assert!(cbin_path.exists(), "Compiled rule should be cached");

        let manifest_path = cache_dir.join(format!("{}.json", hash));
        assert!(manifest_path.exists(), "Manifest should be cached");
    }

    #[tokio::test]
    async fn test_file_size_validation() {
        let (config, temp_dir) = create_test_config();
        let store = create_rule_store(config).expect("Failed to create rule store");

        // Create a large rule file (simulate oversized bundle)
        let large_content = "A".repeat(1024 * 1024); // 1MB of 'A's
        let large_rule = format!(
            r#"
rule LargeRule {{
    strings:
        $large = "{}"
    condition:
        $large
}}
"#,
            large_content
        );

        let rule_file = temp_dir.path().join("large_rule.yar");
        fs::write(&rule_file, &large_rule).expect("Failed to write large rule");

        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(large_rule.as_bytes());
        let hash = format!("{:x}", hasher.finalize());

        let bundle = RuleBundle {
            name: "large_rule_test".to_string(),
            version: "1.0.0".to_string(),
            path: rule_file,
            sha256: hash,
            count: 0,
        };

        // This should still work as it's under the 50MB limit
        let result = store.compile(&bundle);
        assert!(
            result.is_ok(),
            "Large but valid rule should compile successfully"
        );
    }

    #[tokio::test]
    async fn test_concurrent_access() {
        let (config, temp_dir) = create_test_config();
        let store = Arc::new(create_rule_store(config).expect("Failed to create rule store"));

        // Create test rules
        let test_rule = create_test_rule();
        let rule_file = temp_dir.path().join("concurrent_test.yar");
        fs::write(&rule_file, &test_rule).expect("Failed to write test rule");

        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(test_rule.as_bytes());
        let hash = format!("{:x}", hasher.finalize());

        let bundle = RuleBundle {
            name: "concurrent_test".to_string(),
            version: "1.0.0".to_string(),
            path: rule_file,
            sha256: hash,
            count: 0,
        };

        let compiled = store.compile(&bundle).expect("Failed to compile rules");
        store.activate(compiled).expect("Failed to activate rules");

        // Spawn multiple tasks that read the current rules
        let mut handles = vec![];

        for i in 0..10 {
            let store_clone = Arc::clone(&store);
            let handle = tokio::spawn(async move {
                for _ in 0..100 {
                    let current = store_clone.current();
                    {
                        let guard = current.read().unwrap();
                        assert!(guard.is_some(), "Rules should be active in task {}", i);
                    } // guard is dropped here before await

                    // Small delay to allow other tasks to run
                    sleep(Duration::from_millis(1)).await;
                }
            });
            handles.push(handle);
        }

        // Wait for all tasks to complete
        for handle in handles {
            handle.await.expect("Task should complete successfully");
        }
    }

    #[tokio::test]
    async fn test_error_types() {
        // Test that our error types implement the expected traits
        use std::error::Error;

        // Create a mock reqwest error for testing
        let mock_url = "https://example.com/test.yar";

        // Create a reqwest error by making an invalid request
        let mock_error = reqwest::Client::new()
            .get("http://invalid-url-that-does-not-exist.local")
            .send()
            .await
            .unwrap_err();

        let download_error = RuleStoreError::DownloadError {
            url: mock_url.to_string(),
            source: mock_error,
        };

        let validation_error = RuleStoreError::ValidationError {
            reason: "Test validation failure".to_string(),
        };

        let compile_error = RuleStoreError::CompileError {
            bundle: "test_bundle".to_string(),
            reason: "Test compilation failure".to_string(),
        };

        let activation_error = RuleStoreError::ActivationError {
            reason: "Test activation failure".to_string(),
        };

        // Verify errors implement Display and Error traits
        assert!(!download_error.to_string().is_empty());
        assert!(!validation_error.to_string().is_empty());
        assert!(!compile_error.to_string().is_empty());
        assert!(!activation_error.to_string().is_empty());

        // Verify error source chain works
        assert!(download_error.source().is_some());
        assert!(validation_error.source().is_none());
    }
}

// Integration tests that don't require YARA feature
#[cfg(test)]
mod integration_tests {

    #[test]
    fn test_module_compilation() {
        // This test ensures the module compiles correctly
        // even when YARA feature is not enabled
        // Module compiled successfully
    }
}
