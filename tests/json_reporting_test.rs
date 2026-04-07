//! Standalone tests for JSON reporting structures
//! These tests verify the JSON serialization without requiring YARA dependencies

use std::collections::HashMap;

// Copy the structures we need to test (without YARA dependencies)
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq)]
pub struct YaraMatch {
    pub rule: String,
    pub namespace: String,
    pub tags: Vec<String>,
    pub meta: HashMap<String, String>,
    pub strings: Vec<YaraString>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq)]
pub struct YaraString {
    pub identifier: String,
    pub matches: Vec<YaraStringMatch>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq)]
pub struct YaraStringMatch {
    pub offset: u64,
    pub match_length: usize,
    pub matched_data: Vec<u8>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq)]
pub enum Target {
    File { path: String },
    Process { pid: u32, name: Option<String> },
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq)]
pub struct YaraDetectionEvent {
    pub ts: String,
    pub target: Target,
    pub rules: Vec<YaraMatch>,
    pub severity: i32,
    pub agent_version: String,
}

impl YaraDetectionEvent {
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

// Helper functions
fn get_agent_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

fn get_current_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let duration = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let secs = duration.as_secs();
    let nanos = duration.subsec_nanos();

    // Convert to ISO8601 format manually
    let datetime = chrono::DateTime::from_timestamp(secs as i64, nanos).unwrap();
    datetime.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

fn create_file_detection_event(path: &str, matches: Vec<YaraMatch>) -> YaraDetectionEvent {
    YaraDetectionEvent {
        ts: get_current_timestamp(),
        target: Target::File {
            path: path.to_string(),
        },
        rules: matches,
        severity: 5,
        agent_version: get_agent_version(),
    }
}

fn create_process_detection_event(
    pid: u32,
    name: Option<String>,
    matches: Vec<YaraMatch>,
) -> YaraDetectionEvent {
    YaraDetectionEvent {
        ts: get_current_timestamp(),
        target: Target::Process { pid, name },
        rules: matches,
        severity: 5,
        agent_version: get_agent_version(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn create_test_yara_match() -> YaraMatch {
        let mut meta = HashMap::new();
        meta.insert("author".to_string(), "test".to_string());
        meta.insert("description".to_string(), "Test rule".to_string());

        YaraMatch {
            rule: "test_rule".to_string(),
            namespace: "default".to_string(),
            tags: vec!["malware".to_string(), "trojan".to_string()],
            meta,
            strings: vec![YaraString {
                identifier: "$test_string".to_string(),
                matches: vec![YaraStringMatch {
                    offset: 100,
                    match_length: 10,
                    matched_data: b"test_data".to_vec(),
                }],
            }],
        }
    }

    #[test]
    fn test_yara_match_serialization() {
        let yara_match = create_test_yara_match();
        let json = serde_json::to_string(&yara_match).unwrap();

        // Verify we can deserialize back
        let deserialized: YaraMatch = serde_json::from_str(&json).unwrap();
        assert_eq!(yara_match, deserialized);
    }

    #[test]
    fn test_file_target_serialization() {
        let target = Target::File {
            path: "/test/path/file.exe".to_string(),
        };
        let json = serde_json::to_string(&target).unwrap();

        let deserialized: Target = serde_json::from_str(&json).unwrap();
        assert_eq!(target, deserialized);
    }

    #[test]
    fn test_process_target_with_name_serialization() {
        let target = Target::Process {
            pid: 1234,
            name: Some("malware.exe".to_string()),
        };
        let json = serde_json::to_string(&target).unwrap();

        let deserialized: Target = serde_json::from_str(&json).unwrap();
        assert_eq!(target, deserialized);
    }

    #[test]
    fn test_process_target_without_name_serialization() {
        let target = Target::Process {
            pid: 5678,
            name: None,
        };
        let json = serde_json::to_string(&target).unwrap();

        let deserialized: Target = serde_json::from_str(&json).unwrap();
        assert_eq!(target, deserialized);
    }

    #[test]
    fn test_file_detection_event_creation() {
        let matches = vec![create_test_yara_match()];
        let event = create_file_detection_event("/test/malware.exe", matches.clone());

        assert_eq!(
            event.target,
            Target::File {
                path: "/test/malware.exe".to_string()
            }
        );
        assert_eq!(event.rules, matches);
        assert_eq!(event.severity, 5);
        assert_eq!(event.agent_version, env!("CARGO_PKG_VERSION"));
        assert!(!event.ts.is_empty());
    }

    #[test]
    fn test_process_detection_event_creation() {
        let matches = vec![create_test_yara_match()];
        let event =
            create_process_detection_event(1234, Some("malware.exe".to_string()), matches.clone());

        assert_eq!(
            event.target,
            Target::Process {
                pid: 1234,
                name: Some("malware.exe".to_string())
            }
        );
        assert_eq!(event.rules, matches);
        assert_eq!(event.severity, 5);
        assert_eq!(event.agent_version, env!("CARGO_PKG_VERSION"));
        assert!(!event.ts.is_empty());
    }

    #[test]
    fn test_detection_event_json_structure() {
        let matches = vec![create_test_yara_match()];
        let event = create_file_detection_event("/test/malware.exe", matches);

        let json = event.to_json().unwrap();
        let parsed: Value = serde_json::from_str(&json).unwrap();

        // Verify all required fields are present
        assert!(parsed["ts"].is_string());
        assert!(parsed["target"].is_object());
        assert!(parsed["rules"].is_array());
        assert!(parsed["severity"].is_number());
        assert!(parsed["agent_version"].is_string());

        // Verify target structure for file
        assert!(parsed["target"]["File"].is_object());
        assert_eq!(parsed["target"]["File"]["path"], "/test/malware.exe");

        // Verify rules array structure
        let rules = &parsed["rules"];
        assert_eq!(rules.as_array().unwrap().len(), 1);

        let rule = &rules[0];
        assert_eq!(rule["rule"], "test_rule");
        assert_eq!(rule["namespace"], "default");
        assert!(rule["tags"].is_array());
        assert!(rule["meta"].is_object());
        assert!(rule["strings"].is_array());
    }

    #[test]
    fn test_timestamp_format() {
        let timestamp = get_current_timestamp();

        // Should be in ISO8601 format: YYYY-MM-DDTHH:MM:SS.sssZ
        assert!(timestamp.contains('T'));
        assert!(timestamp.ends_with('Z'));
        assert!(timestamp.len() >= 20); // Minimum length for ISO8601
    }

    #[test]
    fn test_agent_version_retrieval() {
        let version = get_agent_version();
        assert!(!version.is_empty());
        assert_eq!(version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn test_multiple_yara_matches() {
        let mut matches = vec![];

        // Create multiple matches
        for i in 0..3 {
            let mut meta = HashMap::new();
            meta.insert("rule_id".to_string(), i.to_string());

            matches.push(YaraMatch {
                rule: format!("rule_{}", i),
                namespace: "test".to_string(),
                tags: vec![format!("tag_{}", i)],
                meta,
                strings: vec![],
            });
        }

        let event = create_file_detection_event("/test/file.exe", matches.clone());
        let json = event.to_json().unwrap();
        let parsed: Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["rules"].as_array().unwrap().len(), 3);

        // Verify each rule is properly serialized
        for (i, rule) in parsed["rules"].as_array().unwrap().iter().enumerate() {
            assert_eq!(rule["rule"], format!("rule_{}", i));
            assert_eq!(rule["namespace"], "test");
        }
    }

    #[test]
    fn test_empty_matches() {
        let event = create_file_detection_event("/test/clean.exe", vec![]);
        let json = event.to_json().unwrap();
        let parsed: Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["rules"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn test_special_characters_in_paths() {
        let special_path = r"C:\Users\Test User\Documents\file with spaces & symbols!@#.exe";
        let event = create_file_detection_event(special_path, vec![]);
        let json = event.to_json().unwrap();
        let parsed: Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["target"]["File"]["path"], special_path);
    }

    #[test]
    fn test_yara_detection_event_to_json() {
        let matches = vec![create_test_yara_match()];
        let event = create_process_detection_event(9999, None, matches);

        let json_result = event.to_json();
        assert!(json_result.is_ok());

        let json = json_result.unwrap();
        assert!(!json.is_empty());

        // Verify it's valid JSON
        let parsed: Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.is_object());
    }
}
