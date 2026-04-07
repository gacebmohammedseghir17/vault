#[cfg(all(test, feature = "yara"))]
mod unit_tests {
    use super::*;
    use crate::detection::yara_events::*;
    use serde_json;
    use std::collections::HashMap;

    #[test]
    fn test_yara_match_serialization() {
        let mut meta = HashMap::new();
        meta.insert("author".to_string(), "test_author".to_string());
        meta.insert("description".to_string(), "test_description".to_string());

        let yara_match = YaraMatch {
            rule: "WannaCry_Ransomware".to_string(),
            namespace: "default".to_string(),
            tags: vec!["malware".to_string(), "ransomware".to_string()],
            meta,
            strings: vec![MatchString {
                identifier: "$wannacry_string".to_string(),
                offset: 1024,
                length: 16,
                plaintext: "WNcry@2ol7".to_string(),
            }],
        };

        let json = serde_json::to_string(&yara_match).expect("Failed to serialize YaraMatch");
        let parsed: YaraMatch =
            serde_json::from_str(&json).expect("Failed to deserialize YaraMatch");

        assert_eq!(parsed.rule, "WannaCry_Ransomware");
        assert_eq!(parsed.namespace, "default");
        assert_eq!(parsed.tags.len(), 2);
        assert_eq!(parsed.meta.get("author"), Some(&"test_author".to_string()));
        assert_eq!(parsed.strings.len(), 1);
        assert_eq!(parsed.strings[0].identifier, "$wannacry_string");
    }

    #[test]
    fn test_file_target_serialization() {
        let target = Target::File {
            path: "/path/to/file.exe".to_string(),
        };

        let json = serde_json::to_string(&target).expect("Failed to serialize Target::File");
        let parsed: Target =
            serde_json::from_str(&json).expect("Failed to deserialize Target::File");

        match parsed {
            Target::File { path } => {
                assert_eq!(path, "/path/to/file.exe");
            }
            _ => panic!("Expected Target::File"),
        }
    }

    #[test]
    fn test_process_target_serialization() {
        let target = Target::Process {
            pid: 1234,
            name: Some("test.exe".to_string()),
        };

        let json = serde_json::to_string(&target).expect("Failed to serialize Target::Process");
        let parsed: Target =
            serde_json::from_str(&json).expect("Failed to deserialize Target::Process");

        match parsed {
            Target::Process { pid, name } => {
                assert_eq!(pid, 1234);
                assert_eq!(name, Some("test.exe".to_string()));
            }
            _ => panic!("Expected Target::Process"),
        }
    }

    #[test]
    fn test_process_target_without_name() {
        let target = Target::Process {
            pid: 5678,
            name: None,
        };

        let json = serde_json::to_string(&target).expect("Failed to serialize Target::Process");
        let parsed: Target =
            serde_json::from_str(&json).expect("Failed to deserialize Target::Process");

        match parsed {
            Target::Process { pid, name } => {
                assert_eq!(pid, 5678);
                assert!(name.is_none());
            }
            _ => panic!("Expected Target::Process"),
        }
    }

    #[test]
    fn test_file_detection_event_creation() {
        let yara_matches = vec![YaraMatch {
            rule: "malware_rule".to_string(),
            namespace: "default".to_string(),
            tags: vec!["malware".to_string()],
            meta: HashMap::new(),
            strings: Vec::new(),
        }];

        let event = create_file_detection_event("/path/to/suspicious/file.exe", yara_matches);

        assert_eq!(event.severity, 5);
        assert_eq!(event.rules.len(), 1);
        assert_eq!(event.rules[0].rule, "malware_rule");

        match &event.target {
            Target::File { path } => {
                assert_eq!(path, "/path/to/suspicious/file.exe");
            }
            _ => panic!("Expected file target"),
        }

        // Verify timestamp format (ISO8601)
        assert!(event.ts.contains("T"));
        assert!(event.ts.ends_with("Z"));

        // Verify agent version is not empty
        assert!(!event.agent_version.is_empty());
    }

    #[test]
    fn test_process_detection_event_creation() {
        let yara_matches = vec![YaraMatch {
            rule: "process_injection_rule".to_string(),
            namespace: "default".to_string(),
            tags: vec!["injection".to_string(), "malware".to_string()],
            meta: HashMap::new(),
            strings: Vec::new(),
        }];

        let event =
            create_process_detection_event(1234, Some("malicious.exe".to_string()), yara_matches);

        assert_eq!(event.severity, 5);
        assert_eq!(event.rules.len(), 1);
        assert_eq!(event.rules[0].rule, "process_injection_rule");

        match &event.target {
            Target::Process { pid, name } => {
                assert_eq!(*pid, 1234);
                assert_eq!(name.as_ref().unwrap(), "malicious.exe");
            }
            _ => panic!("Expected process target"),
        }
    }

    #[test]
    fn test_detection_event_json_structure() {
        let yara_matches = vec![YaraMatch {
            rule: "WannaCry_Ransomware".to_string(),
            namespace: "default".to_string(),
            tags: vec!["ransomware".to_string()],
            meta: {
                let mut meta = HashMap::new();
                meta.insert("severity".to_string(), "high".to_string());
                meta
            },
            strings: vec![MatchString {
                identifier: "$wannacry_sig".to_string(),
                offset: 100,
                length: 10,
                plaintext: "WNcry@2ol7".to_string(),
            }],
        }];

        let event = create_file_detection_event("/test/path", yara_matches);
        let json = serde_json::to_string(&event).expect("Failed to serialize event");

        // Parse JSON to verify structure
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("Invalid JSON");

        // Verify required fields exist
        assert!(parsed["ts"].is_string());
        assert!(parsed["target"].is_object());
        assert!(parsed["rules"].is_array());
        assert!(parsed["severity"].is_number());
        assert!(parsed["agent_version"].is_string());

        // Verify target structure
        let target = &parsed["target"];
        assert!(target["File"].is_object());
        assert_eq!(target["File"]["path"], "/test/path");

        // Verify rules structure
        let rules = parsed["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 1);

        let rule = &rules[0];
        assert_eq!(rule["rule"], "WannaCry_Ransomware");
        assert_eq!(rule["namespace"], "default");
        assert!(rule["tags"].is_array());
        assert!(rule["meta"].is_object());
        assert!(rule["strings"].is_array());

        // Verify string match structure
        let strings = rule["strings"].as_array().unwrap();
        assert_eq!(strings.len(), 1);

        let string_match = &strings[0];
        assert_eq!(string_match["identifier"], "$wannacry_sig");
        assert_eq!(string_match["offset"], 100);
        assert_eq!(string_match["length"], 10);
        assert_eq!(string_match["plaintext"], "WNcry@2ol7");
    }

    #[test]
    fn test_iso8601_timestamp_format() {
        let timestamp = generate_iso8601_timestamp();

        // Basic format check: YYYY-MM-DDTHH:MM:SSZ
        assert!(timestamp.len() >= 19); // Minimum length for ISO8601
        assert!(timestamp.contains('T'));
        assert!(timestamp.ends_with('Z'));

        // Try to parse with chrono to verify it's valid ISO8601
        use chrono::{DateTime, Utc};
        let parsed: Result<DateTime<Utc>, _> = timestamp.parse();
        assert!(parsed.is_ok(), "Invalid ISO8601 timestamp: {}", timestamp);
    }

    #[test]
    fn test_agent_version_retrieval() {
        let version = get_agent_version();
        assert!(!version.is_empty());
        // Should contain version info
        assert_eq!(version, "0.1.0"); // Based on Cargo.toml
    }

    #[test]
    fn test_multiple_yara_matches() {
        let yara_matches = vec![
            YaraMatch {
                rule: "rule1".to_string(),
                namespace: "ns1".to_string(),
                tags: vec!["tag1".to_string()],
                meta: HashMap::new(),
                strings: Vec::new(),
            },
            YaraMatch {
                rule: "rule2".to_string(),
                namespace: "ns2".to_string(),
                tags: vec!["tag2".to_string(), "tag3".to_string()],
                meta: HashMap::new(),
                strings: Vec::new(),
            },
        ];

        let event = create_file_detection_event("/test/multi", yara_matches);
        assert_eq!(event.rules.len(), 2);
        assert_eq!(event.rules[0].rule, "rule1");
        assert_eq!(event.rules[1].rule, "rule2");
        assert_eq!(event.rules[1].tags.len(), 2);
    }

    #[test]
    fn test_empty_yara_matches() {
        let event = create_file_detection_event("/test/empty", Vec::new());
        assert_eq!(event.rules.len(), 0);
        assert_eq!(event.severity, 5); // Default severity should still be set
    }

    #[test]
    fn test_json_serialization_with_special_characters() {
        let yara_matches = vec![YaraMatch {
            rule: "rule_with_unicode_🦀".to_string(),
            namespace: "default".to_string(),
            tags: vec!["unicode".to_string()],
            meta: {
                let mut meta = HashMap::new();
                meta.insert(
                    "description".to_string(),
                    "Rule with special chars: \"quotes\" & <tags>".to_string(),
                );
                meta
            },
            strings: vec![MatchString {
                identifier: "$unicode_string".to_string(),
                offset: 0,
                length: 4,
                plaintext: "🦀🔥".to_string(),
            }],
        }];

        let event = create_file_detection_event("/path/with spaces/file.exe", yara_matches);

        // Should serialize without errors
        let json = serde_json::to_string(&event)
            .expect("Failed to serialize event with special characters");

        // Should deserialize back correctly
        let parsed: YaraDetectionEvent =
            serde_json::from_str(&json).expect("Failed to deserialize event");

        assert_eq!(parsed.rules[0].rule, "rule_with_unicode_🦀");
        assert_eq!(parsed.rules[0].strings[0].plaintext, "🦀🔥");

        match &parsed.target {
            Target::File { path } => {
                assert_eq!(path, "/path/with spaces/file.exe");
            }
            _ => panic!("Expected file target"),
        }
    }

    #[test]
    fn test_detection_event_to_json_method() {
        let yara_matches = vec![YaraMatch {
            rule: "WannaCry_Ransomware".to_string(),
            namespace: "default".to_string(),
            tags: Vec::new(),
            meta: HashMap::new(),
            strings: Vec::new(),
        }];

        let event = create_file_detection_event("/test/file", yara_matches);

        // Test the to_json method
        let json_result = event.to_json();
        assert!(json_result.is_ok(), "to_json should succeed");

        let json = json_result.unwrap();

        // Verify it's valid JSON
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("to_json should produce valid JSON");

        assert!(parsed["ts"].is_string());
        assert!(parsed["target"].is_object());
        assert!(parsed["rules"].is_array());
    }

    #[test]
    fn test_match_string_serialization() {
        let match_string = MatchString {
            identifier: "$hex_pattern".to_string(),
            offset: 2048,
            length: 32,
            plaintext: "4D5A9000".to_string(),
        };

        let json = serde_json::to_string(&match_string).expect("Failed to serialize MatchString");
        let parsed: MatchString =
            serde_json::from_str(&json).expect("Failed to deserialize MatchString");

        assert_eq!(parsed.identifier, "$hex_pattern");
        assert_eq!(parsed.offset, 2048);
        assert_eq!(parsed.length, 32);
        assert_eq!(parsed.plaintext, "4D5A9000");
    }
}
