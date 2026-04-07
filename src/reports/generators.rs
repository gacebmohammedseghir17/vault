//! Report generators module
//!
//! This module contains functionality for generating different types of reports
//! from scan data and system information.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde_json::Value;
use std::collections::HashMap;

/// Represents the data structure for a generated report
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReportData {
    pub id: String,
    pub report_type: String,
    pub timestamp: DateTime<Utc>,
    pub data: HashMap<String, Value>,
    pub metadata: HashMap<String, String>,
}

/// Report generator trait for different report types
pub trait ReportGenerator {
    /// Generate a report from the provided data
    fn generate(&self, data: &HashMap<String, Value>) -> Result<ReportData>;

    /// Get the report type identifier
    fn report_type(&self) -> &str;
}

/// Scan report generator
pub struct ScanReportGenerator;

impl ScanReportGenerator {
    pub fn new() -> Self {
        Self
    }
}

impl ReportGenerator for ScanReportGenerator {
    fn generate(&self, data: &HashMap<String, Value>) -> Result<ReportData> {
        let report_id = uuid::Uuid::new_v4().to_string();
        let timestamp = Utc::now();

        let mut metadata = HashMap::new();
        metadata.insert("generator".to_string(), "scan_report".to_string());
        metadata.insert("version".to_string(), "1.0".to_string());

        // Extract agent_id if available
        if let Some(agent_id) = data.get("agent_id").and_then(|v| v.as_str()) {
            metadata.insert("agent_id".to_string(), agent_id.to_string());
        }

        Ok(ReportData {
            id: report_id,
            report_type: "scan_report".to_string(),
            timestamp,
            data: data.clone(),
            metadata,
        })
    }

    fn report_type(&self) -> &str {
        "scan_report"
    }
}

/// System report generator
pub struct SystemReportGenerator;

impl SystemReportGenerator {
    pub fn new() -> Self {
        Self
    }
}

impl ReportGenerator for SystemReportGenerator {
    fn generate(&self, data: &HashMap<String, Value>) -> Result<ReportData> {
        let report_id = uuid::Uuid::new_v4().to_string();
        let timestamp = Utc::now();

        let mut metadata = HashMap::new();
        metadata.insert("generator".to_string(), "system_report".to_string());
        metadata.insert("version".to_string(), "1.0".to_string());

        Ok(ReportData {
            id: report_id,
            report_type: "system_report".to_string(),
            timestamp,
            data: data.clone(),
            metadata,
        })
    }

    fn report_type(&self) -> &str {
        "system_report"
    }
}

/// Threat report generator
pub struct ThreatReportGenerator;

impl ThreatReportGenerator {
    pub fn new() -> Self {
        Self
    }
}

impl ReportGenerator for ThreatReportGenerator {
    fn generate(&self, data: &HashMap<String, Value>) -> Result<ReportData> {
        let report_id = uuid::Uuid::new_v4().to_string();
        let timestamp = Utc::now();

        let mut metadata = HashMap::new();
        metadata.insert("generator".to_string(), "threat_report".to_string());
        metadata.insert("version".to_string(), "1.0".to_string());

        Ok(ReportData {
            id: report_id,
            report_type: "threat_report".to_string(),
            timestamp,
            data: data.clone(),
            metadata,
        })
    }

    fn report_type(&self) -> &str {
        "threat_report"
    }
}

#[cfg(all(test, feature = "advanced-reporting"))]
mod tests {
    use super::*;

    #[test]
    fn test_scan_report_generator() {
        let generator = ScanReportGenerator::new();
        let mut data = HashMap::new();
        data.insert(
            "test_key".to_string(),
            Value::String("test_value".to_string()),
        );

        let report = generator.generate(&data).unwrap();
        assert_eq!(report.report_type, "scan_report");
        assert!(report.data.contains_key("test_key"));
    }

    #[test]
    fn test_system_report_generator() {
        let generator = SystemReportGenerator::new();
        let data = HashMap::new();

        let report = generator.generate(&data).unwrap();
        assert_eq!(report.report_type, "system_report");
    }

    #[test]
    fn test_threat_report_generator() {
        let generator = ThreatReportGenerator::new();
        let data = HashMap::new();

        let report = generator.generate(&data).unwrap();
        assert_eq!(report.report_type, "threat_report");
    }
}
