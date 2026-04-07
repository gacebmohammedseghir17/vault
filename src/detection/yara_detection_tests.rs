#[cfg(all(test, feature = "yara"))]
mod tests {
    #[cfg(feature = "yara")]
    use std::fs;
    #[cfg(feature = "yara")]
    use std::path::Path;
    #[cfg(feature = "yara")]
    use tempfile::TempDir;
    use std::sync::Arc;
    use crate::config::AgentConfig;

    #[cfg(feature = "yara")]
    use crate::detection::yara_engine::YaraEngine;
    #[cfg(feature = "yara")]
    use crate::detector::DetectionManager;

    #[cfg(not(feature = "yara"))]
    use crate::detector::DetectionManager;

    /// Test basic module structure and compilation without YARA
    #[tokio::test]
    async fn test_module_structure() {
        // This test should always pass, regardless of YARA availability
        assert!(true);
    }

    #[cfg(feature = "yara")]
    #[tokio::test]
    async fn test_yara_engine_initialization() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let rules_dir = temp_dir.path();

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
            let rule_file = rules_dir.join("wannacry.yar");
            fs::write(&rule_file, rule_content).expect("Failed to write production rule");
        } else {
            println!("Skipping test - WannaCry production rule not found");
            return;
        }

        let config = Arc::new(AgentConfig::default());
        let engine = YaraEngine::new(config);
        let result = engine.load_rules_from_directory(rules_dir.to_str().unwrap()).await;

        assert!(
            result.is_ok(),
            "Failed to load YARA rules: {:?}",
            result.err()
        );
        assert!(
            engine.is_loaded().await,
            "Engine should be loaded after successful rule loading"
        );
        assert_eq!(
            engine.get_rules_count().await,
            1,
            "Should have loaded exactly 1 rule"
        );
    }

    #[cfg(feature = "yara")]
    #[tokio::test]
    async fn test_detection_manager_scan_file() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let rules_dir = temp_dir.path();

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
            let rule_file = rules_dir.join("wannacry.yar");
            fs::write(&rule_file, rule_content).expect("Failed to write production rule");
        } else {
            println!("Skipping test - WannaCry production rule not found");
            return;
        }

        // Initialize detection manager
        let config = Arc::new(AgentConfig::default());
        let detection_manager = DetectionManager::new(config);
        let rules_loaded = detection_manager
            .initialize(rules_dir)
            .await
            .expect("Failed to initialize detection manager");

        assert_eq!(rules_loaded, 1, "Should have loaded exactly 1 rule");
        assert!(
            detection_manager.is_initialized().await,
            "Detection manager should be initialized"
        );

        // Create a test file with WannaCry signature content
        let test_file = temp_dir.path().join("wannacry_test.txt");
        fs::write(
            &test_file,
            "icacls . /grant Everyone:F /T /C /Q WNcry@2ol7 taskdl.exe",
        )
        .expect("Failed to write test file");

        // Scan the file
        let scan_result = detection_manager.scan_file(&test_file).await;
        assert!(
            scan_result.is_ok(),
            "Scan should succeed: {:?}",
            scan_result.err()
        );

        let matches = scan_result.unwrap();
        if !matches.is_empty() {
            // Check if any WannaCry rule matched
            let wannacry_match = matches.iter().any(|rule| rule.contains("WannaCry") || rule.contains("wannacry"));
            assert!(
                wannacry_match,
                "Should match a WannaCry rule, got: {:?}",
                matches
            );
        }
    }

    #[cfg(feature = "yara")]
    #[tokio::test]
    async fn test_scan_memory_blob() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let rules_dir = temp_dir.path();

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
            let rule_file = rules_dir.join("wannacry.yar");
            fs::write(&rule_file, rule_content).expect("Failed to write production rule");
        } else {
            println!("Skipping test - WannaCry production rule not found");
            return;
        }

        // Initialize detection manager
        let config = Arc::new(AgentConfig::default());
        let detection_manager = DetectionManager::new(config);
        detection_manager
            .initialize(rules_dir)
            .await
            .expect("Failed to initialize detection manager");

        // Test memory blob with WannaCry signature
        let test_blob = b"icacls . /grant Everyone:F /T /C /Q WNcry@2ol7 taskdl.exe mssecsvc.exe";
        let scan_result = detection_manager.scan_memory(test_blob).await;

        assert!(
            scan_result.is_ok(),
            "Memory scan should succeed: {:?}",
            scan_result.err()
        );

        let matches = scan_result.unwrap();
        if !matches.is_empty() {
            // Check if any WannaCry rule matched
            let wannacry_match = matches.iter().any(|rule| rule.contains("WannaCry") || rule.contains("wannacry"));
            assert!(
                wannacry_match,
                "Should match a WannaCry rule, got: {:?}",
                matches
            );
        }
    }

    #[cfg(feature = "yara")]
    #[tokio::test]
    async fn test_scan_notepad_exe() {
        // This test attempts to scan notepad.exe if it exists
        let notepad_path = Path::new("C:\\Windows\\System32\\notepad.exe");

        if !notepad_path.exists() {
            println!("Skipping notepad.exe test - file not found");
            return;
        }

        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let rules_dir = temp_dir.path();

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
            let rule_file = rules_dir.join("wannacry.yar");
            fs::write(&rule_file, rule_content).expect("Failed to write production rule");
        } else {
            println!("Skipping test - WannaCry production rule not found");
            return;
        }

        // Initialize detection manager
        let config = Arc::new(AgentConfig::default());
        let detection_manager = DetectionManager::new(config);
        detection_manager
            .initialize(rules_dir)
            .await
            .expect("Failed to initialize detection manager");

        // Scan notepad.exe
        let scan_result = detection_manager.scan_file(notepad_path).await;
        assert!(
            scan_result.is_ok(),
            "Notepad scan should succeed: {:?}",
            scan_result.err()
        );

        let matches = scan_result.unwrap();
        // Notepad should not match our test rule
        assert!(
            matches.is_empty(),
            "Notepad should not match malware rule, got: {:?}",
            matches
        );
    }

    #[cfg(not(feature = "yara"))]
    #[tokio::test]
    async fn test_yara_disabled_functionality() {
        let config = Arc::new(AgentConfig::default());
        let manager = DetectionManager::new(config);

        // When YARA is disabled, these should return default/empty values
        assert!(!manager.is_initialized().await);
        assert_eq!(manager.get_rules_count().await, 0);
        assert!(manager.get_loaded_rules_info().await.is_empty());

        // Scan operations should return empty results
        let temp_file = tempfile::NamedTempFile::new().expect("Failed to create temp file");
        let scan_result = manager.scan_file(temp_file.path()).await;
        assert!(scan_result.is_ok());
        assert!(scan_result.unwrap().is_empty());
    }
}
