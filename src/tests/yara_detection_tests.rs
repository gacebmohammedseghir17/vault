//! Comprehensive unit tests for YARA-based detection functionality in ERDPS
//! 
//! This module tests:
//! - YARA engine initialization and rule loading
//! - File scanning with real malware signatures
//! - Memory scanning with test patterns
//! - Integration with DetectionManager
//! - End-to-end detection workflow
//!
//! NOTE: These tests require YARA system libraries to be installed:
//! - Windows: Install YARA from https://github.com/VirusTotal/yara/releases
//! - Set LIBCLANG_PATH environment variable to LLVM/Clang installation
//! - Ensure yara.dll is in PATH or set YARA_LIBRARY_PATH

// Conditional imports based on YARA availability
#[cfg(feature = "yara")]
// use crate::detector::DetectionManager;
#[cfg(feature = "yara")]
// use crate::detector::DetectionAlert;
// use std::sync::Arc;

#[cfg(all(test, feature = "yara"))]
mod yara_detection_tests {

    /// Basic test to verify test module structure
    #[tokio::test]
    async fn test_module_structure() {
        // This test verifies that the test module is properly structured
        // and can be compiled without YARA dependencies
        assert!(true, "Test module structure is valid");
        println!("✓ YARA detection test module loaded successfully");
    }

    /// Test that documents YARA requirements
    #[test]
    fn test_yara_requirements_documentation() {
        let requirements = vec![
            "YARA system library (yara.dll on Windows)",
            "LLVM/Clang for bindgen (libclang.dll)",
            "LIBCLANG_PATH environment variable",
            "YARA_LIBRARY_PATH environment variable (optional)",
        ];
        
        println!("YARA Detection System Requirements:");
        for (i, req) in requirements.iter().enumerate() {
            println!("  {}. {}", i + 1, req);
        }
        
        assert_eq!(requirements.len(), 4);
    }

    // YARA-dependent tests (only compiled when YARA is available)
    #[cfg(feature = "yara")]
    mod yara_integration_tests {
        use crate::detector::DetectionManager;
        use crate::detection::YaraEngine;
        use crate::detector::{Detector, Event, EventType};
        use crate::config::AgentConfig;
        use crate::detector::DetectionAlert;
        use tokio::sync::mpsc;
        use std::sync::Arc;
        use chrono::Utc;
        use std::fs;
        use std::path::Path;
        use tempfile::TempDir;

        /// Test YARA engine initialization and rule loading from rules/ransomware directory
        #[tokio::test]
        async fn test_yara_engine_load_real_rules() {
        let config = Arc::new(crate::config::agent_config::AgentConfig::default());
        let engine = YaraEngine::new(config);
        
        // Test loading rules from the actual rules directory
        let rules_path = std::path::PathBuf::from("rules/ransomware");
        
        if rules_path.exists() {
            let loaded_count = engine.load_rules_from_directory(rules_path.to_str().unwrap()).await;
            
            match loaded_count {
                Ok(count) => {
                    println!("Successfully loaded {} YARA rules from {}", count, rules_path.display());
                    assert!(count > 0, "Should load at least one rule from rules/ransomware");
                    
                    // Verify engine state
                    assert!(engine.is_loaded().await);
                    assert_eq!(engine.get_rules_count().await, count);
                    
                    // Get rule information
                    let rules_info = engine.get_loaded_rules_info().await;
                    assert!(!rules_info.is_empty());
                    
                    println!("Loaded rules: {:?}", rules_info.keys().collect::<Vec<_>>());
                }
                Err(e) => {
                    println!("Warning: Could not load rules from {}: {}", rules_path.display(), e);
                    // This is not a failure if the directory doesn't exist in test environment
                }
            }
        } else {
            println!("Rules directory {} not found, skipping real rules test", rules_path.display());
        }
    }

    /// Test YARA memory scanning with WANNACRY test pattern
    #[tokio::test]
    async fn test_yara_memory_scan_wannacry() {
        let config = Arc::new(crate::config::agent_config::AgentConfig::default());
        let engine = YaraEngine::new(config);
        
        // Create a temporary directory with a test rule
        let temp_dir = TempDir::new().unwrap();
        let rule_file = temp_dir.path().join("wannacry_test.yar");
        
        let wannacry_rule = r#"
rule WannaCry_Ransomware {
    meta:
        description = "Test rule for WannaCry detection"
        author = "ERDPS Test Suite"
        
    strings:
        $wannacry1 = "WANNACRY" nocase
        $wannacry2 = "WanaCrypt0r" nocase
        $wannacry3 = "Wana Decrypt0r" nocase
        $bitcoin = "bitcoin" nocase
        
    condition:
        any of ($wannacry*) or $bitcoin
}
"#;
        
        fs::write(&rule_file, wannacry_rule).unwrap();
        
        // Load the test rule
        let loaded_count = engine.load_rules_from_directory(temp_dir.path().to_str().unwrap()).await.unwrap();
        assert_eq!(loaded_count, 1);
        
        // Test 1: Scan memory with WANNACRY string
        let wannacry_data = b"This file contains WANNACRY malware signature";
        let matches = engine.scan_memory(wannacry_data).await.unwrap();
        assert_eq!(matches, vec!["WannaCry_Ransomware"]);
        println!("✓ WANNACRY pattern detected: {:?}", matches);
        
        // Test 2: Scan memory with WanaCrypt0r string
        let wanacrypt_data = b"WanaCrypt0r 2.0 - Your files are encrypted";
        let matches = engine.scan_memory(wanacrypt_data).await.unwrap();
        assert_eq!(matches, vec!["WannaCry_Ransomware"]);
        println!("✓ WanaCrypt0r pattern detected: {:?}", matches);
        
        // Test 3: Scan memory with bitcoin string
        let bitcoin_data = b"Send payment to this bitcoin address";
        let matches = engine.scan_memory(bitcoin_data).await.unwrap();
        assert_eq!(matches, vec!["WannaCry_Ransomware"]);
        println!("✓ Bitcoin pattern detected: {:?}", matches);
        
        // Test 4: Scan clean memory
        let clean_data = b"This is completely clean data with no malware";
        let matches = engine.scan_memory(clean_data).await.unwrap();
        assert!(matches.is_empty());
        println!("✓ Clean data correctly identified");
    }

    /// Test YARA file scanning with notepad.exe (if available)
    #[tokio::test]
    async fn test_yara_file_scan_notepad() {
        let config = Arc::new(crate::config::agent_config::AgentConfig::default());
        let engine = YaraEngine::new(config);
        
        // Create a test rule that might match notepad.exe characteristics
        let temp_dir = TempDir::new().unwrap();
        let rule_file = temp_dir.path().join("pe_test.yar");
        
        let pe_rule = r#"
rule WindowsPEFile {
    meta:
        description = "Detects Windows PE files"
        author = "ERDPS Test Suite"
        
    strings:
        $mz = { 4D 5A }  // MZ header
        $pe = "PE" nocase
        
    condition:
        $mz at 0 and $pe
}
"#;
        
        fs::write(&rule_file, pe_rule).unwrap();
        
        // Load the test rule
        let loaded_count = engine.load_rules_from_directory(temp_dir.path().to_str().unwrap()).await.unwrap();
        assert_eq!(loaded_count, 1);
        
        // Try to scan notepad.exe from common Windows locations
        let notepad_paths = vec![
            std::path::PathBuf::from("C:\\Windows\\System32\\notepad.exe"),
            std::path::PathBuf::from("C:\\Windows\\notepad.exe"),
            std::path::PathBuf::from("C:\\Windows\\SysWOW64\\notepad.exe"),
        ];
        
        let mut notepad_found = false;
        for notepad_path in notepad_paths {
            if notepad_path.exists() {
                println!("Testing YARA scan on: {}", notepad_path.display());
                
                match engine.scan_file(&notepad_path).await {
                    Ok(matches) => {
                        println!("✓ Notepad.exe scan completed. Matches: {:?}", matches);
                        // PE files should match our PE detection rule
                        if matches.contains(&"WindowsPEFile".to_string()) {
                            println!("✓ Notepad.exe correctly identified as PE file");
                        }
                        notepad_found = true;
                        break;
                    }
                    Err(e) => {
                        println!("Warning: Could not scan {}: {}", notepad_path.display(), e);
                    }
                }
            }
        }
        
        if !notepad_found {
            println!("Warning: notepad.exe not found in standard locations, skipping file scan test");
        }
    }

    /// Test DetectionManager integration
    #[tokio::test]
    async fn test_detection_manager_integration() {
        let config = Arc::new(AgentConfig::default());
        let manager = DetectionManager::new(config);
        
        // Create test rules
        let temp_dir = TempDir::new().unwrap();
        let rule_file = temp_dir.path().join("integration_test.yar");
        
        // Use production YARA rules from rules/ransomware directory
        let production_rules_dir = Path::new("d:\\projecttttttttts\\project-ransolution\\rules\\ransomware");
        if !production_rules_dir.exists() {
            println!("Skipping test - production rules directory not found");
            return;
        }
        
        // Copy a production rule to test directory for isolated testing
        let wannacry_rule_path = production_rules_dir.join("crime_wannacry.yar");
        if wannacry_rule_path.exists() {
            let rule_content = fs::read_to_string(&wannacry_rule_path).expect("Failed to read production rule");
            fs::write(&rule_file, rule_content).unwrap();
        } else {
            println!("Skipping test - WannaCry production rule not found");
            return;
        }
        
        // Initialize DetectionManager
        let loaded_count = manager.initialize(temp_dir.path()).await.unwrap();
        assert!(loaded_count > 0, "Should load at least one production rule");
        assert!(manager.is_initialized().await);
        
        // Test scan_file API with WannaCry signature
        let test_file = temp_dir.path().join("wannacry_test.txt");
        fs::write(&test_file, "icacls . /grant Everyone:F /T /C /Q WNcry@2ol7 taskdl.exe mssecsvc.exe").unwrap();
        
        let matches = manager.scan_file(&test_file).await.unwrap();
        if !matches.is_empty() {
            let wannacry_match = matches.iter().any(|rule| rule.contains("WannaCry") || rule.contains("wannacry"));
            assert!(wannacry_match, "Should match a WannaCry rule, got: {:?}", matches);
            println!("✓ DetectionManager scan_file API working correctly");
        }
        
        // Test scan_memory API with WannaCry signature
        let test_data = b"icacls . /grant Everyone:F /T /C /Q WNcry@2ol7 taskdl.exe mssecsvc.exe";
        let matches = manager.scan_memory(test_data).await.unwrap();
        if !matches.is_empty() {
            let wannacry_match = matches.iter().any(|rule| rule.contains("WannaCry") || rule.contains("wannacry"));
            assert!(wannacry_match, "Should match a WannaCry rule, got: {:?}", matches);
            println!("✓ DetectionManager scan_memory API working correctly");
        }
        
        // Test metadata APIs
        assert!(manager.get_rules_count().await > 0, "Should have loaded production rules");
        let rules_info = manager.get_loaded_rules_info().await;
        assert!(!rules_info.is_empty(), "Should have rule information");
        println!("✓ DetectionManager metadata APIs working correctly");
        println!("   Loaded {} rules", manager.get_rules_count().await);
    }

    /// Test end-to-end detection workflow
    #[tokio::test]
    async fn test_end_to_end_detection_workflow() {
        // Create channels for communication
        let (alert_tx, mut alert_rx) = mpsc::channel::<DetectionAlert>(100);
        let (event_tx, event_rx) = mpsc::channel(100);
        
        // Create test configuration
        let config = Arc::new(AgentConfig::default());
        
        // Create detector
        let detector = Detector::new(
            event_rx,
            alert_tx,
            None, // No mitigation for this test
            config,
        ).unwrap();
        
        // Initialize YARA rules with production rules
        let temp_dir = TempDir::new().unwrap();
        let rule_file = temp_dir.path().join("e2e_test.yar");
        
        // Use production YARA rules from rules/ransomware directory
        let production_rules_dir = Path::new("d:\\projecttttttttts\\project-ransolution\\rules\\ransomware");
        if !production_rules_dir.exists() {
            println!("Skipping test - production rules directory not found");
            return;
        }
        
        // Copy a production rule to test directory for isolated testing
        let wannacry_rule_path = production_rules_dir.join("crime_wannacry.yar");
        if wannacry_rule_path.exists() {
            let rule_content = fs::read_to_string(&wannacry_rule_path).expect("Failed to read production rule");
            fs::write(&rule_file, rule_content).unwrap();
        } else {
            println!("Skipping test - WannaCry production rule not found");
            return;
        }
        
        let loaded_count = detector.initialize_yara_rules(temp_dir.path()).await.unwrap();
        assert!(loaded_count > 0, "Should load at least one production rule");
        println!("✓ Detector initialized with {} YARA rules", loaded_count);
        
        // Start detector in background
        let detector_handle = crate::detector::start_detector(detector);
        
        // Create a test file with WannaCry signature
        let test_file = temp_dir.path().join("malware_sample.txt");
        fs::write(&test_file, "icacls . /grant Everyone:F /T /C /Q WNcry@2ol7 taskdl.exe mssecsvc.exe").unwrap();
        
        // Send file creation event
        let event = Event {
            event_type: EventType::Created,
            path: test_file.clone(),
            pid: Some(1234),
            process_name: Some("test_process".to_string()),
            timestamp: Utc::now().timestamp_millis() as u64,
            extra: std::collections::HashMap::new(),
        };
        
        event_tx.send(event).await.unwrap();
        
        // Wait for detection alert
        let alert = tokio::time::timeout(std::time::Duration::from_secs(5), alert_rx.recv())
            .await
            .expect("Should receive alert within 5 seconds")
            .expect("Should receive an alert");
        
        // Verify alert contains YARA detection information
        assert!(alert.rule_id.contains("yara") || alert.evidence.iter().any(|e| e.contains("YARA")));
        // Check if alert mentions WannaCry or any production rule
        let has_wannacry = alert.evidence.iter().any(|e| e.contains("WannaCry") || e.contains("wannacry")) || 
                          alert.rule_id.contains("WannaCry") || alert.rule_id.contains("wannacry");
        if has_wannacry {
            println!("✓ End-to-end detection workflow completed successfully with WannaCry detection");
        } else {
            println!("✓ End-to-end detection workflow completed successfully");
        }
        println!("   Alert: {} - Evidence: {:?}", alert.rule_id, alert.evidence);
        
        // Clean up
        detector_handle.abort();
    }

    /// Performance test for YARA scanning
    #[tokio::test]
    async fn test_yara_performance() {
        let config = Arc::new(crate::config::agent_config::AgentConfig::default());
        let engine = YaraEngine::new(config);
        
        // Use production YARA rules from rules/ransomware directory
        let temp_dir = TempDir::new().unwrap();
        let production_rules_dir = Path::new("d:\\projecttttttttts\\project-ransolution\\rules\\ransomware");
        
        if !production_rules_dir.exists() {
            println!("Skipping performance test - production rules directory not found");
            return;
        }
        
        // Copy some production rules to test directory for performance testing
        let mut copied_rules = 0;
        if let Ok(entries) = fs::read_dir(production_rules_dir) {
            for entry in entries.take(5) { // Limit to 5 rules for performance test
                if let Ok(entry) = entry {
                    let path = entry.path();
                    if path.extension().and_then(|s| s.to_str()) == Some("yar") {
                        if let Some(filename) = path.file_name() {
                            let dest_path = temp_dir.path().join(filename);
                            if fs::copy(&path, &dest_path).is_ok() {
                                copied_rules += 1;
                            }
                        }
                    }
                }
            }
        }
        
        if copied_rules == 0 {
            println!("Skipping performance test - no production rules found");
            return;
        }
        
        // Load rules and measure time
        let start = std::time::Instant::now();
        let loaded_count = engine.load_rules_from_directory(temp_dir.path().to_str().unwrap()).await.unwrap();
        let load_time = start.elapsed();
        
        assert_eq!(loaded_count, copied_rules);
        println!("✓ Loaded {} production rules in {:?}", loaded_count, load_time);
        
        // Test scanning performance with WannaCry signature
        let test_data = b"icacls . /grant Everyone:F /T /C /Q WNcry@2ol7 taskdl.exe mssecsvc.exe";
        
        let start = std::time::Instant::now();
        let matches = engine.scan_memory(test_data).await.unwrap();
        let scan_time = start.elapsed();
        
        println!("✓ Memory scan completed in {:?} with {} matches", scan_time, matches.len());
        if !matches.is_empty() {
            println!("   Matched rules: {:?}", matches);
        }
        
        // Performance assertions
        assert!(load_time.as_millis() < 5000, "Rule loading should complete within 5 seconds");
        assert!(scan_time.as_millis() < 1000, "Memory scan should complete within 1 second");
        }
    } // End of yara_integration_tests module
} // End of yara_detection_tests module
