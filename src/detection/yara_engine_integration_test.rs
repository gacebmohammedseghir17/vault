#[cfg(all(test, feature = "yara"))]
mod integration_tests {
    use super::*;
    use crate::detection::yara_engine::YaraEngine;
    use crate::detection::yara_events::*;
    use std::collections::HashMap;
    use std::fs;
    use std::io::Write;
    use std::sync::{Arc, Mutex};
    use tempfile::NamedTempFile;

    // Mock IPC module for testing
    pub mod mock_ipc {
        use crate::ipc::DetectionAlert;
        use std::sync::{Arc, Mutex};

        lazy_static::lazy_static! {
            pub static ref SENT_ALERTS: Arc<Mutex<Vec<DetectionAlert>>> = Arc::new(Mutex::new(Vec::new()));
        }

        pub fn send_signed_alert(
            alert: DetectionAlert,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            SENT_ALERTS.lock().unwrap().push(alert);
            Ok(())
        }

        pub fn get_sent_alerts() -> Vec<DetectionAlert> {
            SENT_ALERTS.lock().unwrap().clone()
        }

        pub fn clear_alerts() {
            SENT_ALERTS.lock().unwrap().clear();
        }
    }

    fn create_test_yara_rule() -> String {
        r#"
        rule WannaCry_Ransomware {
            meta:
                author = "Security Team"
                description = "WannaCry Ransomware Detection"
                family = "ransomware"
                severity = "high"
            
            strings:
                $wannacry_sig = "WNcry@2ol7"
                $pe_header = { 4D 5A 90 00 }
            
            condition:
                $wannacry_sig or $pe_header
        }
        
        rule Petya_Ransomware {
            meta:
                author = "Security Team"
                description = "Petya Ransomware Detection"
                family = "ransomware"
                severity = "high"
            
            strings:
                $petya_marker = "PETYA_DETECTED"
            
            condition:
                $petya_marker
        }
        "#
        .to_string()
    }

    fn create_test_file_with_content(content: &str) -> NamedTempFile {
        let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
        temp_file
            .write_all(content.as_bytes())
            .expect("Failed to write to temp file");
        temp_file
    }

    #[test]
    fn test_yara_engine_file_detection_with_json_reporting() {
        // Clear any previous alerts
        mock_ipc::clear_alerts();

        // Create YARA engine with test rules
        let rules_content = create_test_yara_rule();
        let config = Arc::new(crate::config::agent_config::AgentConfig::default());
        let mut engine = YaraEngine::new(config);
        engine
            .load_rules_from_string(&rules_content)
            .expect("Failed to load rules");

        // Create test file with WannaCry signature
        let test_content = "This file contains WNcry@2ol7 for testing";
        let temp_file = create_test_file_with_content(test_content);
        let file_path = temp_file.path().to_str().unwrap();

        // Scan the file
        let matches = engine.scan_file(file_path).expect("Failed to scan file");

        // Verify matches were found
        assert!(!matches.is_empty(), "Expected to find YARA matches");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule, "WannaCry_Ransomware");

        // Verify JSON event was sent via IPC
        let sent_alerts = mock_ipc::get_sent_alerts();
        assert_eq!(
            sent_alerts.len(),
            1,
            "Expected one detection alert to be sent"
        );

        let alert = &sent_alerts[0];
        assert_eq!(alert.severity, 5);

        // Parse the JSON payload
        let event: YaraDetectionEvent =
            serde_json::from_str(&alert.json_data).expect("Failed to parse detection event JSON");

        // Verify event structure
        assert_eq!(event.severity, 5);
        assert_eq!(event.rules.len(), 1);
        assert_eq!(event.rules[0].rule, "WannaCry_Ransomware");

        match &event.target {
            Target::File { path } => {
                assert_eq!(path, file_path);
            }
            _ => panic!("Expected file target"),
        }

        // Verify timestamp format
        assert!(event.ts.contains('T'));
        assert!(event.ts.ends_with('Z'));

        // Verify agent version
        assert!(!event.agent_version.is_empty());
    }

    #[test]
    fn test_yara_engine_multiple_matches_json_reporting() {
        mock_ipc::clear_alerts();

        let rules_content = create_test_yara_rule();
        let config = Arc::new(crate::config::agent_config::AgentConfig::default());
        let mut engine = YaraEngine::new(config);
        engine
            .load_rules_from_string(&rules_content)
            .expect("Failed to load rules");

        // Create test file with multiple signatures
        let test_content = "WNcry@2ol7 and also PETYA_DETECTED in same file";
        let temp_file = create_test_file_with_content(test_content);
        let file_path = temp_file.path().to_str().unwrap();

        let matches = engine.scan_file(file_path).expect("Failed to scan file");

        // Should find both rules
        assert_eq!(matches.len(), 2);

        let sent_alerts = mock_ipc::get_sent_alerts();
        assert_eq!(
            sent_alerts.len(),
            1,
            "Expected one alert with multiple matches"
        );

        let event: YaraDetectionEvent = serde_json::from_str(&sent_alerts[0].json_data)
            .expect("Failed to parse detection event JSON");

        assert_eq!(event.rules.len(), 2);

        let rule_names: Vec<&str> = event.rules.iter().map(|r| r.rule.as_str()).collect();
        assert!(rule_names.contains(&"WannaCry_Ransomware"));
        assert!(rule_names.contains(&"Petya_Ransomware"));
    }

    #[test]
    fn test_yara_engine_no_matches_no_json_reporting() {
        mock_ipc::clear_alerts();

        let rules_content = create_test_yara_rule();
        let config = Arc::new(crate::config::agent_config::AgentConfig::default());
        let mut engine = YaraEngine::new(config);
        engine
            .load_rules_from_string(&rules_content)
            .expect("Failed to load rules");

        // Create test file with no malware signatures
        let test_content = "This is a clean file with no suspicious content";
        let temp_file = create_test_file_with_content(test_content);
        let file_path = temp_file.path().to_str().unwrap();

        let matches = engine.scan_file(file_path).expect("Failed to scan file");

        // Should find no matches
        assert!(matches.is_empty());

        // Should not send any alerts
        let sent_alerts = mock_ipc::get_sent_alerts();
        assert_eq!(sent_alerts.len(), 0, "Expected no alerts for clean file");
    }

    #[test]
    fn test_yara_engine_process_detection_json_reporting() {
        mock_ipc::clear_alerts();

        let rules_content = create_test_yara_rule();
        let config = Arc::new(crate::config::agent_config::AgentConfig::default());
        let mut engine = YaraEngine::new(config);
        engine
            .load_rules_from_string(&rules_content)
            .expect("Failed to load rules");

        // Get current process PID for testing
        let current_pid = std::process::id();

        // Note: This test might not find matches in the current process,
        // but we're testing the JSON reporting mechanism
        let result = engine.scan_process(current_pid);

        match result {
            Ok(matches) => {
                if !matches.is_empty() {
                    // If matches were found, verify JSON reporting
                    let sent_alerts = mock_ipc::get_sent_alerts();
                    assert!(
                        !sent_alerts.is_empty(),
                        "Expected detection alert for process matches"
                    );

                    let event: YaraDetectionEvent = serde_json::from_str(&sent_alerts[0].json_data)
                        .expect("Failed to parse process detection event JSON");

                    match &event.target {
                        Target::Process { pid, name: _ } => {
                            assert_eq!(*pid, current_pid);
                        }
                        _ => panic!("Expected process target"),
                    }
                } else {
                    // No matches found, should not send alerts
                    let sent_alerts = mock_ipc::get_sent_alerts();
                    assert_eq!(sent_alerts.len(), 0, "Expected no alerts for clean process");
                }
            }
            Err(_) => {
                // Process scanning might fail due to permissions, which is acceptable
                println!("Process scanning failed (likely due to permissions)");
            }
        }
    }

    #[test]
    fn test_json_structure_completeness() {
        mock_ipc::clear_alerts();

        let rules_content = create_test_yara_rule();
        let config = Arc::new(crate::config::agent_config::AgentConfig::default());
        let mut engine = YaraEngine::new(config);
        engine
            .load_rules_from_string(&rules_content)
            .expect("Failed to load rules");

        let test_content = "MALWARE_SIGNATURE detected";
        let temp_file = create_test_file_with_content(test_content);
        let file_path = temp_file.path().to_str().unwrap();

        engine.scan_file(file_path).expect("Failed to scan file");

        let sent_alerts = mock_ipc::get_sent_alerts();
        assert_eq!(sent_alerts.len(), 1);

        let json_data = &sent_alerts[0].json_data;
        let parsed: serde_json::Value =
            serde_json::from_str(json_data).expect("Invalid JSON structure");

        // Verify all required fields are present
        assert!(parsed["ts"].is_string(), "Missing or invalid timestamp");
        assert!(parsed["target"].is_object(), "Missing or invalid target");
        assert!(parsed["rules"].is_array(), "Missing or invalid rules array");
        assert!(
            parsed["severity"].is_number(),
            "Missing or invalid severity"
        );
        assert!(
            parsed["agent_version"].is_string(),
            "Missing or invalid agent_version"
        );

        // Verify target structure
        let target = &parsed["target"];
        assert!(target["File"].is_object(), "Invalid file target structure");
        assert!(target["File"]["path"].is_string(), "Missing file path");

        // Verify rules structure
        let rules = parsed["rules"].as_array().unwrap();
        assert!(!rules.is_empty(), "Rules array should not be empty");

        for rule in rules {
            assert!(rule["rule"].is_string(), "Missing rule name");
            assert!(rule["namespace"].is_string(), "Missing rule namespace");
            assert!(rule["tags"].is_array(), "Missing or invalid tags");
            assert!(rule["meta"].is_object(), "Missing or invalid meta");
            assert!(rule["strings"].is_array(), "Missing or invalid strings");
        }
    }

    #[test]
    fn test_error_handling_in_json_reporting() {
        mock_ipc::clear_alerts();

        let rules_content = create_test_yara_rule();
        let config = Arc::new(crate::config::agent_config::AgentConfig::default());
        let mut engine = YaraEngine::new(config);
        engine
            .load_rules_from_string(&rules_content)
            .expect("Failed to load rules");

        // Try to scan a non-existent file
        let result = engine.scan_file("/non/existent/file.exe");

        // Should return an error, not crash
        assert!(result.is_err(), "Expected error for non-existent file");

        // Should not send any alerts for failed scans
        let sent_alerts = mock_ipc::get_sent_alerts();
        assert_eq!(sent_alerts.len(), 0, "Expected no alerts for failed scan");
    }

    #[test]
    fn test_yara_match_metadata_preservation() {
        mock_ipc::clear_alerts();

        let rules_content = create_test_yara_rule();
        let config = Arc::new(crate::config::agent_config::AgentConfig::default());
        let mut engine = YaraEngine::new(config);
        engine
            .load_rules_from_string(&rules_content)
            .expect("Failed to load rules");

        let test_content = "MALWARE_SIGNATURE for metadata test";
        let temp_file = create_test_file_with_content(test_content);
        let file_path = temp_file.path().to_str().unwrap();

        engine.scan_file(file_path).expect("Failed to scan file");

        let sent_alerts = mock_ipc::get_sent_alerts();
        let event: YaraDetectionEvent = serde_json::from_str(&sent_alerts[0].json_data)
            .expect("Failed to parse detection event JSON");

        let rule = &event.rules[0];

        // Verify metadata is preserved
        assert_eq!(rule.meta.get("author"), Some(&"Test Author".to_string()));
        assert_eq!(
            rule.meta.get("description"),
            Some(&"Test malware detection rule".to_string())
        );
        assert_eq!(rule.meta.get("severity"), Some(&"high".to_string()));

        // Verify string matches are captured
        assert!(
            !rule.strings.is_empty(),
            "Expected string matches to be captured"
        );

        let string_match = &rule.strings[0];
        assert_eq!(string_match.identifier, "$test_string");
        assert!(string_match.offset >= 0);
        assert!(string_match.length > 0);
        assert_eq!(string_match.plaintext, "MALWARE_SIGNATURE");
    }
}
