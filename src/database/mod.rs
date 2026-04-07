//! Database module for production metrics and validation tracking
//! Implements SQLite-based persistence for the Ransolution Security Engine

#[cfg(test)]
use chrono::Utc;
use rusqlite::{params, Connection, Result as SqliteResult};
use std::path::Path;
use std::sync::{Arc, Mutex};
// serde imports removed - not used
// uuid import removed - not used

pub mod models;

use models::*;

/// Database connection pool for thread-safe access
#[derive(Debug)]
pub struct DatabasePool {
    connection: Arc<Mutex<Connection>>,
}

impl DatabasePool {
    /// Initialize database with schema
    pub fn new<P: AsRef<Path>>(db_path: P) -> SqliteResult<Self> {
        let conn = Connection::open(db_path)?;

        // Enable foreign keys and WAL mode for better performance
        conn.pragma_update(None, "foreign_keys", &"ON")?;
        conn.pragma_update(None, "journal_mode", &"WAL")?;
        conn.pragma_update(None, "synchronous", &"NORMAL")?;

        // Execute schema creation
        let schema = include_str!("schema.sql");
        conn.execute_batch(schema)?;

        Ok(DatabasePool {
            connection: Arc::new(Mutex::new(conn)),
        })
    }

    /// Create a new detection scan record
    pub fn create_scan(&self, scan: &DetectionScan) -> SqliteResult<()> {
        let conn = self.connection.lock().unwrap();
        conn.execute(
            "INSERT INTO detection_scans (scan_id, target_path, scan_type, status, priority, created_at) 
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                scan.scan_id,
                scan.target_path,
                scan.scan_type,
                scan.status,
                scan.priority,
                scan.created_at.format("%Y-%m-%d %H:%M:%S").to_string()
            ],
        )?;
        Ok(())
    }

    /// Update scan completion status
    pub fn complete_scan(
        &self,
        scan_id: &str,
        duration_ms: i64,
        cpu_usage: f64,
        memory_mb: i64,
        files_scanned: i64,
    ) -> SqliteResult<()> {
        let conn = self.connection.lock().unwrap();
        conn.execute(
            "UPDATE detection_scans SET status = 'COMPLETED', completed_at = CURRENT_TIMESTAMP, 
             duration_ms = ?2, cpu_usage_percent = ?3, memory_usage_mb = ?4, files_scanned = ?5 
             WHERE scan_id = ?1",
            params![scan_id, duration_ms, cpu_usage, memory_mb, files_scanned],
        )?;
        Ok(())
    }

    /// Add malware sample to database
    pub fn add_malware_sample(&self, sample: &MalwareSample) -> SqliteResult<()> {
        let conn = self.connection.lock().unwrap();
        conn.execute(
            "INSERT INTO malware_samples (sample_id, sha256_hash, family_name, file_size, file_path, threat_level, added_at) 
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                sample.sample_id,
                sample.sha256_hash,
                sample.family_name,
                sample.file_size,
                sample.file_path,
                sample.threat_level,
                sample.added_at.format("%Y-%m-%d %H:%M:%S").to_string()
            ],
        )?;
        Ok(())
    }

    /// Get malware samples by family
    pub fn get_samples_by_family(&self, family_name: &str) -> SqliteResult<Vec<MalwareSample>> {
        let conn = self.connection.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT sample_id, sha256_hash, family_name, file_size, file_path, threat_level, 
             validation_status, added_at, last_validated 
             FROM malware_samples WHERE family_name = ?1",
        )?;

        let sample_iter = stmt.query_map([family_name], |row| {
            Ok(MalwareSample {
                sample_id: row.get(0)?,
                sha256_hash: row.get(1)?,
                family_name: row.get(2)?,
                file_size: row.get(3)?,
                file_path: row.get(4)?,
                threat_level: row.get(5)?,
                validation_status: row.get(6)?,
                added_at: chrono::NaiveDateTime::parse_from_str(
                    &row.get::<_, String>(7)?,
                    "%Y-%m-%d %H:%M:%S",
                )
                .unwrap()
                .and_utc(),
                last_validated: row.get::<_, Option<String>>(8)?.map(|s| {
                    chrono::NaiveDateTime::parse_from_str(&s, "%Y-%m-%d %H:%M:%S")
                        .unwrap()
                        .and_utc()
                }),
            })
        })?;

        let mut samples = Vec::new();
        for sample in sample_iter {
            samples.push(sample?);
        }
        Ok(samples)
    }

    /// Record validation run
    pub fn record_validation(&self, validation: &ValidationRun) -> SqliteResult<()> {
        let conn = self.connection.lock().unwrap();
        conn.execute(
            "INSERT INTO validation_runs (validation_id, sample_id, scan_id, mttd_seconds, 
             accuracy_score, detected, false_positive, isolation_config, run_at) 
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                validation.validation_id,
                validation.sample_id,
                validation.scan_id,
                validation.mttd_seconds,
                validation.accuracy_score,
                validation.detected,
                validation.false_positive,
                validation.isolation_config,
                validation.run_at.format("%Y-%m-%d %H:%M:%S").to_string()
            ],
        )?;
        Ok(())
    }

    /// Get validation statistics
    pub fn get_validation_stats(&self) -> SqliteResult<ValidationStats> {
        let conn = self.connection.lock().unwrap();

        let mut stmt = conn.prepare(
            "SELECT 
                COUNT(*) as total_runs,
                COUNT(CASE WHEN detected = 1 THEN 1 END) as detected_count,
                COUNT(CASE WHEN false_positive = 1 THEN 1 END) as false_positive_count,
                AVG(mttd_seconds) as avg_mttd,
                AVG(accuracy_score) as avg_accuracy
             FROM validation_runs",
        )?;

        let stats = stmt.query_row([], |row| {
            let total_runs: i64 = row.get(0)?;
            let detected_count: i64 = row.get(1)?;
            let false_positive_count: i64 = row.get(2)?;
            let avg_mttd: Option<f64> = row.get(3)?;
            let avg_accuracy: Option<f64> = row.get(4)?;

            let detection_rate = if total_runs > 0 {
                detected_count as f64 / total_runs as f64
            } else {
                0.0
            };

            let false_positive_rate = if total_runs > 0 {
                false_positive_count as f64 / total_runs as f64
            } else {
                0.0
            };

            Ok(ValidationStats {
                total_runs,
                detection_rate,
                false_positive_rate,
                avg_mttd: avg_mttd.unwrap_or(0.0),
                avg_accuracy: avg_accuracy.unwrap_or(0.0),
            })
        })?;

        Ok(stats)
    }

    /// Record system metrics
    pub fn record_system_metrics(&self, metrics: &SystemMetrics) -> SqliteResult<()> {
        let conn = self.connection.lock().unwrap();
        conn.execute(
            "INSERT INTO system_metrics (metric_id, cpu_usage_percent, memory_usage_mb, 
             disk_io_mbps, network_io_mbps, active_scans, queue_depth, recorded_at) 
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                metrics.metric_id,
                metrics.cpu_usage_percent,
                metrics.memory_usage_mb,
                metrics.disk_io_mbps,
                metrics.network_io_mbps,
                metrics.active_scans,
                metrics.queue_depth,
                metrics.recorded_at.format("%Y-%m-%d %H:%M:%S").to_string()
            ],
        )?;
        Ok(())
    }

    /// Get performance gates
    pub fn get_performance_gates(&self) -> SqliteResult<Vec<PerformanceGate>> {
        let conn = self.connection.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT gate_id, metric_type, threshold_value, enforcement_action, enabled 
             FROM performance_gates WHERE enabled = 1",
        )?;

        let gate_iter = stmt.query_map([], |row| {
            Ok(PerformanceGate {
                gate_id: row.get(0)?,
                metric_type: row.get(1)?,
                threshold_value: row.get(2)?,
                enforcement_action: row.get(3)?,
                enabled: row.get(4)?,
            })
        })?;

        let mut gates = Vec::new();
        for gate in gate_iter {
            gates.push(gate?);
        }
        Ok(gates)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_database_initialization() {
        let temp_file = NamedTempFile::new().unwrap();
        let db = DatabasePool::new(temp_file.path()).unwrap();

        // Test that we can get performance gates (should have defaults)
        let gates = db.get_performance_gates().unwrap();
        assert_eq!(gates.len(), 4); // CPU, Memory, MTTD, FP_Rate
    }

    #[test]
    fn test_malware_sample_operations() {
        let temp_file = NamedTempFile::new().unwrap();
        let db = DatabasePool::new(temp_file.path()).unwrap();

        let sample = MalwareSample {
            sample_id: "test_sample_001".to_string(),
            sha256_hash: "abcd1234".to_string(),
            family_name: "TestMalware".to_string(),
            file_size: 1024,
            file_path: "/tmp/test.exe".to_string(),
            threat_level: "HIGH".to_string(),
            validation_status: "PENDING".to_string(),
            added_at: Utc::now(),
            last_validated: None,
        };

        db.add_malware_sample(&sample).unwrap();
        let samples = db.get_samples_by_family("TestMalware").unwrap();
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].sample_id, "test_sample_001");
    }
}
