//! Production Metrics Database Module
//!
//! This module provides a comprehensive interface for storing and retrieving
//! production metrics, validation results, and system health data using SQLite.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

/// Production metrics database manager
#[derive(Clone, Debug)]
pub struct MetricsDatabase {
    connection: Arc<Mutex<Connection>>,
}

/// Performance metric record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetric {
    pub id: Option<i64>,
    pub timestamp: DateTime<Utc>,
    pub metric_type: String,
    pub metric_value: f64,
    pub unit: String,
    pub component: String,
    pub process_id: Option<u32>,
    pub additional_context: Option<String>,
}

/// Detection result record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionRecord {
    pub id: Option<i64>,
    pub timestamp: DateTime<Utc>,
    pub detection_id: String,
    pub detection_type: String,
    pub confidence_score: f64,
    pub threat_level: String,
    pub file_path: Option<String>,
    pub file_hash: Option<String>,
    pub file_size: Option<i64>,
    pub process_id: Option<u32>,
    pub process_name: Option<String>,
    pub detection_engine: String,
    pub rule_name: Option<String>,
    pub mitigation_applied: bool,
    pub false_positive: bool,
    pub validated: bool,
    pub validation_notes: Option<String>,
}

/// Validation tracking record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationRecord {
    pub id: Option<i64>,
    pub timestamp: DateTime<Utc>,
    pub test_suite: String,
    pub test_name: String,
    pub test_status: String,
    pub execution_time_ms: Option<i64>,
    pub expected_result: Option<String>,
    pub actual_result: Option<String>,
    pub error_message: Option<String>,
    pub test_environment: String,
    pub build_version: Option<String>,
}

/// System health record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemHealthRecord {
    pub id: Option<i64>,
    pub timestamp: DateTime<Utc>,
    pub component: String,
    pub status: String,
    pub uptime_seconds: Option<i64>,
    pub error_count: i32,
    pub warning_count: i32,
    pub last_error_message: Option<String>,
    pub last_error_timestamp: Option<DateTime<Utc>>,
    pub memory_usage_mb: Option<f64>,
    pub cpu_usage_percent: Option<f64>,
    pub disk_usage_mb: Option<f64>,
}

/// Performance gate record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceGateRecord {
    pub id: Option<i64>,
    pub timestamp: DateTime<Utc>,
    pub gate_name: String,
    pub gate_type: String,
    pub threshold_value: f64,
    pub actual_value: f64,
    pub passed: bool,
    pub component: String,
    pub test_context: Option<String>,
    pub severity: String,
}

/// Audit log record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogRecord {
    pub id: Option<i64>,
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub user_id: Option<String>,
    pub component: String,
    pub action: String,
    pub resource_affected: Option<String>,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub session_id: Option<String>,
    pub success: bool,
    pub error_message: Option<String>,
}

impl MetricsDatabase {
    /// Create a new metrics database instance
    pub fn new<P: AsRef<Path>>(db_path: P) -> Result<Self> {
        let connection = Connection::open(db_path).context("Failed to open SQLite database")?;

        // Enable foreign keys and WAL mode for better performance
        connection
            .pragma_update(None, "foreign_keys", &"ON")
            .context("Failed to enable foreign keys")?;
        connection
            .pragma_update(None, "journal_mode", &"WAL")
            .context("Failed to enable WAL mode")?;
        connection
            .pragma_update(None, "synchronous", &"NORMAL")
            .context("Failed to set synchronous mode")?;

        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
        })
    }

    /// Initialize the database schema
    pub fn initialize_schema(&self) -> Result<()> {
        let schema_sql = include_str!("../../migrations/001_production_metrics_schema.sql");
        let conn = self.connection.lock().unwrap();
        conn.execute_batch(schema_sql)
            .context("Failed to initialize database schema")?;
        Ok(())
    }

    /// Record a performance metric
    pub fn record_performance_metric(&self, metric: &PerformanceMetric) -> Result<i64> {
        let conn = self.connection.lock().unwrap();
        let mut stmt = conn.prepare(
            "INSERT INTO performance_metrics 
             (timestamp, metric_type, metric_value, unit, component, process_id, additional_context) 
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"
        )?;

        let id = stmt.insert(params![
            metric.timestamp.format("%Y-%m-%d %H:%M:%S").to_string(),
            metric.metric_type,
            metric.metric_value,
            metric.unit,
            metric.component,
            metric.process_id,
            metric.additional_context
        ])?;

        Ok(id)
    }

    /// Record a detection result
    pub fn record_detection(&self, detection: &DetectionRecord) -> Result<i64> {
        let conn = self.connection.lock().unwrap();
        let mut stmt = conn.prepare(
            "INSERT INTO detection_results 
             (timestamp, detection_id, detection_type, confidence_score, threat_level, 
              file_path, file_hash, file_size, process_id, process_name, detection_engine, 
              rule_name, mitigation_applied, false_positive, validated, validation_notes) 
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
        )?;

        let id = stmt.insert(params![
            detection.timestamp.format("%Y-%m-%d %H:%M:%S").to_string(),
            detection.detection_id,
            detection.detection_type,
            detection.confidence_score,
            detection.threat_level,
            detection.file_path,
            detection.file_hash,
            detection.file_size,
            detection.process_id,
            detection.process_name,
            detection.detection_engine,
            detection.rule_name,
            detection.mitigation_applied,
            detection.false_positive,
            detection.validated,
            detection.validation_notes
        ])?;

        Ok(id)
    }

    /// Record a validation result
    pub fn record_validation(&self, validation: &ValidationRecord) -> Result<i64> {
        let conn = self.connection.lock().unwrap();
        let mut stmt = conn.prepare(
            "INSERT INTO validation_tracking 
             (timestamp, test_suite, test_name, test_status, execution_time_ms, 
              expected_result, actual_result, error_message, test_environment, build_version) 
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        )?;

        let id = stmt.insert(params![
            validation.timestamp.format("%Y-%m-%d %H:%M:%S").to_string(),
            validation.test_suite,
            validation.test_name,
            validation.test_status,
            validation.execution_time_ms,
            validation.expected_result,
            validation.actual_result,
            validation.error_message,
            validation.test_environment,
            validation.build_version
        ])?;

        Ok(id)
    }

    /// Record system health status
    pub fn record_system_health(&self, health: &SystemHealthRecord) -> Result<i64> {
        let conn = self.connection.lock().unwrap();
        let mut stmt = conn.prepare(
            "INSERT INTO system_health 
             (timestamp, component, status, uptime_seconds, error_count, warning_count, 
              last_error_message, last_error_timestamp, memory_usage_mb, cpu_usage_percent, disk_usage_mb) 
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)"
        )?;

        let last_error_ts = health
            .last_error_timestamp
            .map(|ts| ts.format("%Y-%m-%d %H:%M:%S").to_string());

        let id = stmt.insert(params![
            health.timestamp.format("%Y-%m-%d %H:%M:%S").to_string(),
            health.component,
            health.status,
            health.uptime_seconds,
            health.error_count,
            health.warning_count,
            health.last_error_message,
            last_error_ts,
            health.memory_usage_mb,
            health.cpu_usage_percent,
            health.disk_usage_mb
        ])?;

        Ok(id)
    }

    /// Record performance gate result
    pub fn record_performance_gate(&self, gate: &PerformanceGateRecord) -> Result<i64> {
        let conn = self.connection.lock().unwrap();
        let mut stmt = conn.prepare(
            "INSERT INTO performance_gates 
             (timestamp, gate_name, gate_type, threshold_value, actual_value, 
              passed, component, test_context, severity) 
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        )?;

        let id = stmt.insert(params![
            gate.timestamp.format("%Y-%m-%d %H:%M:%S").to_string(),
            gate.gate_name,
            gate.gate_type,
            gate.threshold_value,
            gate.actual_value,
            gate.passed,
            gate.component,
            gate.test_context,
            gate.severity
        ])?;

        Ok(id)
    }

    /// Record audit log entry
    pub fn record_audit_log(&self, audit: &AuditLogRecord) -> Result<i64> {
        let conn = self.connection.lock().unwrap();
        let mut stmt = conn.prepare(
            "INSERT INTO audit_log 
             (timestamp, event_type, user_id, component, action, resource_affected, 
              old_value, new_value, ip_address, user_agent, session_id, success, error_message) 
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        )?;

        let id = stmt.insert(params![
            audit.timestamp.format("%Y-%m-%d %H:%M:%S").to_string(),
            audit.event_type,
            audit.user_id,
            audit.component,
            audit.action,
            audit.resource_affected,
            audit.old_value,
            audit.new_value,
            audit.ip_address,
            audit.user_agent,
            audit.session_id,
            audit.success,
            audit.error_message
        ])?;

        Ok(id)
    }

    /// Get recent performance metrics
    pub fn get_recent_performance_metrics(
        &self,
        component: &str,
        hours: i64,
    ) -> Result<Vec<PerformanceMetric>> {
        let conn = self.connection.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, timestamp, metric_type, metric_value, unit, component, process_id, additional_context 
             FROM performance_metrics 
             WHERE component = ?1 AND timestamp >= datetime('now', '-' || ?2 || ' hours') 
             ORDER BY timestamp DESC"
        )?;

        let rows = stmt.query_map(params![component, hours], |row| {
            Ok(PerformanceMetric {
                id: Some(row.get(0)?),
                timestamp: chrono::DateTime::parse_from_str(
                    &row.get::<_, String>(1)?,
                    "%Y-%m-%d %H:%M:%S",
                )
                .unwrap_or_else(|_| Utc::now().into())
                .with_timezone(&Utc),
                metric_type: row.get(2)?,
                metric_value: row.get(3)?,
                unit: row.get(4)?,
                component: row.get(5)?,
                process_id: row.get(6)?,
                additional_context: row.get(7)?,
            })
        })?;

        let mut metrics = Vec::new();
        for row in rows {
            metrics.push(row?);
        }

        Ok(metrics)
    }

    /// Get detection summary for the last N days
    pub fn get_detection_summary(&self, days: i64) -> Result<Vec<(String, String, i64, f64)>> {
        let conn = self.connection.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT detection_type, detection_engine, COUNT(*) as count, AVG(confidence_score) as avg_confidence 
             FROM detection_results 
             WHERE timestamp >= datetime('now', '-' || ?1 || ' days') 
             GROUP BY detection_type, detection_engine 
             ORDER BY count DESC"
        )?;

        let rows = stmt.query_map(params![days], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, f64>(3)?,
            ))
        })?;

        let mut summary = Vec::new();
        for row in rows {
            summary.push(row?);
        }

        Ok(summary)
    }

    /// Get performance gate pass rates
    pub fn get_performance_gate_summary(
        &self,
        days: i64,
    ) -> Result<Vec<(String, String, i64, i64, f64)>> {
        let conn = self.connection.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT gate_name, component, COUNT(*) as total, 
                    SUM(CASE WHEN passed = 1 THEN 1 ELSE 0 END) as passed, 
                    ROUND(100.0 * SUM(CASE WHEN passed = 1 THEN 1 ELSE 0 END) / COUNT(*), 2) as pass_rate 
             FROM performance_gates 
             WHERE timestamp >= datetime('now', '-' || ?1 || ' days') 
             GROUP BY gate_name, component 
             ORDER BY pass_rate ASC"
        )?;

        let rows = stmt.query_map(params![days], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, f64>(4)?,
            ))
        })?;

        let mut summary = Vec::new();
        for row in rows {
            summary.push(row?);
        }

        Ok(summary)
    }

    /// Clean up old records (data retention)
    pub fn cleanup_old_records(&self, retention_days: i64) -> Result<()> {
        let conn = self.connection.lock().unwrap();

        let tables = vec![
            "performance_metrics",
            "detection_results",
            "validation_tracking",
            "system_health",
            "performance_gates",
            "audit_log",
        ];

        for table in tables {
            let sql = format!(
                "DELETE FROM {} WHERE timestamp < datetime('now', '-{} days')",
                table, retention_days
            );
            let deleted = conn.execute(&sql, [])?;
            if deleted > 0 {
                println!("Cleaned up {} old records from {}", deleted, table);
            }
        }

        // Vacuum to reclaim space
        conn.execute("VACUUM", [])?;

        Ok(())
    }
}

/// Helper function to create a new detection ID
pub fn generate_detection_id() -> String {
    Uuid::new_v4().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_database_creation_and_schema() {
        let temp_file = NamedTempFile::new().unwrap();
        let db = MetricsDatabase::new(temp_file.path()).unwrap();
        db.initialize_schema().unwrap();

        // Test basic functionality
        let metric = PerformanceMetric {
            id: None,
            timestamp: Utc::now(),
            metric_type: "cpu_usage".to_string(),
            metric_value: 25.5,
            unit: "percent".to_string(),
            component: "behavioral_engine".to_string(),
            process_id: Some(1234),
            additional_context: None,
        };

        let id = db.record_performance_metric(&metric).unwrap();
        assert!(id > 0);

        let metrics = db
            .get_recent_performance_metrics("behavioral_engine", 24)
            .unwrap();
        assert_eq!(metrics.len(), 1);
        assert_eq!(metrics[0].metric_value, 25.5);
    }

    #[test]
    fn test_detection_recording() {
        let temp_file = NamedTempFile::new().unwrap();
        let db = MetricsDatabase::new(temp_file.path()).unwrap();
        db.initialize_schema().unwrap();

        let detection = DetectionRecord {
            id: None,
            timestamp: Utc::now(),
            detection_id: generate_detection_id(),
            detection_type: "ransomware".to_string(),
            confidence_score: 0.95,
            threat_level: "high".to_string(),
            file_path: Some("/test/file.exe".to_string()),
            file_hash: Some("abc123".to_string()),
            file_size: Some(1024),
            process_id: Some(5678),
            process_name: Some("malware.exe".to_string()),
            detection_engine: "yara".to_string(),
            rule_name: Some("ransomware_rule".to_string()),
            mitigation_applied: false,
            false_positive: false,
            validated: false,
            validation_notes: None,
        };

        let id = db.record_detection(&detection).unwrap();
        assert!(id > 0);

        let summary = db.get_detection_summary(7).unwrap();
        assert_eq!(summary.len(), 1);
        assert_eq!(summary[0].0, "ransomware");
        assert_eq!(summary[0].1, "yara");
    }
}
