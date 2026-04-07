//! YARA detection event structures for JSON reporting via IPC

use crate::detection::yara_engine::YaraMatch;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

// #[cfg(test)]
// mod yara_events_test;

// #[cfg(test)]
// mod yara_events_unit_test;

/// Target of a YARA detection (file or process)
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(tag = "type", content = "data")]
pub enum Target {
    /// File target with path
    #[serde(rename = "file")]
    File { path: String },
    /// Process target with PID and optional name
    #[serde(rename = "process")]
    Process { pid: u32, name: Option<String> },
}

/// YARA detection event for JSON reporting
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct YaraDetectionEvent {
    /// ISO8601 timestamp of the detection
    pub ts: String,
    /// Target of the detection (file or process)
    pub target: Target,
    /// YARA rule matches
    pub rules: Vec<YaraMatch>,
    /// Severity level (default 5)
    pub severity: i32,
    /// Agent version information
    pub agent_version: String,
}

impl YaraDetectionEvent {
    /// Create a new YARA detection event for a file
    pub fn new_file_detection(
        file_path: &str,
        matches: Vec<YaraMatch>,
        severity: Option<i32>,
    ) -> Self {
        Self {
            ts: Self::generate_iso8601_timestamp(),
            target: Target::File {
                path: file_path.to_string(),
            },
            rules: matches,
            severity: severity.unwrap_or(5),
            agent_version: Self::get_agent_version(),
        }
    }

    /// Create a new YARA detection event for a process
    pub fn new_process_detection(
        pid: u32,
        process_name: Option<String>,
        matches: Vec<YaraMatch>,
        severity: Option<i32>,
    ) -> Self {
        Self {
            ts: Self::generate_iso8601_timestamp(),
            target: Target::Process {
                pid,
                name: process_name,
            },
            rules: matches,
            severity: severity.unwrap_or(5),
            agent_version: Self::get_agent_version(),
        }
    }

    /// Generate ISO8601 timestamp string
    fn generate_iso8601_timestamp() -> String {
        let now: DateTime<Utc> = SystemTime::now().into();
        now.to_rfc3339()
    }

    /// Get agent version information
    fn get_agent_version() -> String {
        // Use cargo package version if available, otherwise fallback
        env!("CARGO_PKG_VERSION").to_string()
    }

    /// Serialize the event to JSON string
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Serialize the event to pretty JSON string (for debugging)
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

/// Helper functions for creating detection events
pub mod helpers {
    use super::*;

    /// Create a file detection event with default severity
    pub fn create_file_detection_event(path: &str, matches: Vec<YaraMatch>) -> YaraDetectionEvent {
        YaraDetectionEvent::new_file_detection(path, matches, None)
    }

    /// Create a process detection event with default severity
    pub fn create_process_detection_event(
        pid: u32,
        name: Option<String>,
        matches: Vec<YaraMatch>,
    ) -> YaraDetectionEvent {
        YaraDetectionEvent::new_process_detection(pid, name, matches, None)
    }

    /// Create a file detection event with custom severity
    pub fn create_file_detection_event_with_severity(
        path: &str,
        matches: Vec<YaraMatch>,
        severity: i32,
    ) -> YaraDetectionEvent {
        YaraDetectionEvent::new_file_detection(path, matches, Some(severity))
    }

    /// Create a process detection event with custom severity
    pub fn create_process_detection_event_with_severity(
        pid: u32,
        name: Option<String>,
        matches: Vec<YaraMatch>,
        severity: i32,
    ) -> YaraDetectionEvent {
        YaraDetectionEvent::new_process_detection(pid, name, matches, Some(severity))
    }
}

#[cfg(all(test, feature = "yara"))]
mod tests {
    use super::*;
    use crate::detection::yara_engine::MatchString;

    fn create_test_yara_match() -> YaraMatch {
        use std::collections::HashMap;

        let mut meta = HashMap::new();
        meta.insert(
            "description".to_string(),
            "Test rule for detection events".to_string(),
        );
        meta.insert("family".to_string(), "ransomware".to_string());

        YaraMatch {
            rule: "WannaCry_Ransomware".to_string(),
            strings: vec![MatchString {
                identifier: "$test_string".to_string(),
                offset: 100,
                length: 10,
                data: "41424344".to_string(), // "ABCD" in hex
            }],
            meta,
        }
    }

    #[test]
    fn test_file_detection_event_creation() {
        let matches = vec![create_test_yara_match()];
        let event = YaraDetectionEvent::new_file_detection(
            "/path/to/malware.exe",
            matches.clone(),
            Some(8),
        );

        assert_eq!(event.severity, 8);
        assert_eq!(event.rules, matches);
        assert_eq!(event.agent_version, env!("CARGO_PKG_VERSION"));

        match event.target {
            Target::File { path } => assert_eq!(path, "/path/to/malware.exe"),
            _ => panic!("Expected file target"),
        }

        // Verify timestamp is valid ISO8601
        assert!(chrono::DateTime::parse_from_rfc3339(&event.ts).is_ok());
    }

    #[test]
    fn test_process_detection_event_creation() {
        let matches = vec![create_test_yara_match()];
        let event = YaraDetectionEvent::new_process_detection(
            1234,
            Some("malware.exe".to_string()),
            matches.clone(),
            None, // Use default severity
        );

        assert_eq!(event.severity, 5); // Default severity
        assert_eq!(event.rules, matches);

        match event.target {
            Target::Process { pid, name } => {
                assert_eq!(pid, 1234);
                assert_eq!(name, Some("malware.exe".to_string()));
            }
            _ => panic!("Expected process target"),
        }
    }

    #[test]
    fn test_json_serialization() {
        let matches = vec![create_test_yara_match()];
        let event = YaraDetectionEvent::new_file_detection("/test/file.exe", matches, Some(7));

        let json = event.to_json().expect("Failed to serialize to JSON");

        // Verify JSON contains expected fields
        assert!(json.contains("\"ts\":"));
        assert!(json.contains("\"target\":"));
        assert!(json.contains("\"rules\":"));
        assert!(json.contains("\"severity\":7"));
        assert!(json.contains("\"agent_version\":"));
        assert!(json.contains("\"/test/file.exe\""));

        // Verify we can deserialize back
        let deserialized: YaraDetectionEvent =
            serde_json::from_str(&json).expect("Failed to deserialize JSON");
        assert_eq!(deserialized.severity, event.severity);
        assert_eq!(deserialized.rules.len(), event.rules.len());
    }

    #[test]
    fn test_helper_functions() {
        let matches = vec![create_test_yara_match()];

        // Test file detection helper
        let file_event = helpers::create_file_detection_event("/test/path", matches.clone());
        assert_eq!(file_event.severity, 5); // Default

        // Test process detection helper
        let process_event = helpers::create_process_detection_event(
            9999,
            Some("test.exe".to_string()),
            matches.clone(),
        );
        assert_eq!(process_event.severity, 5); // Default

        // Test with custom severity
        let custom_event =
            helpers::create_file_detection_event_with_severity("/custom/path", matches, 9);
        assert_eq!(custom_event.severity, 9);
    }

    #[test]
    fn test_target_serialization() {
        // Test file target
        let file_target = Target::File {
            path: "/test/file.exe".to_string(),
        };
        let json = serde_json::to_string(&file_target).unwrap();
        assert!(json.contains("\"type\":\"file\""));
        assert!(json.contains("\"/test/file.exe\""));

        // Test process target
        let process_target = Target::Process {
            pid: 1234,
            name: Some("test.exe".to_string()),
        };
        let json = serde_json::to_string(&process_target).unwrap();
        assert!(json.contains("\"type\":\"process\""));
        assert!(json.contains("\"pid\":1234"));
        assert!(json.contains("\"test.exe\""));
    }
}
