//! YARA Performance Monitoring Module
//!
//! This module provides performance monitoring capabilities for YARA rule compilation
//! and execution, tracking metrics in a SQLite database for analysis and optimization.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use log::{debug, info, warn};
use rusqlite::Connection;
use crate::error::AgentError;
use serde::Serialize;

/// Performance monitor for tracking YARA rule compilation metrics
#[derive(Debug, Clone)]
pub struct PerformanceMonitor {
    db_path: PathBuf,
    metrics_threshold_ms: u64,
    connection: Arc<Mutex<Connection>>,
}

/// Metrics for a single YARA rule operation
#[derive(Debug, Clone, Serialize)]
pub struct OperationMetrics {
    pub rule_id: String,
    pub compile_time_ms: u64,
}

impl PerformanceMonitor {
    /// Create a new performance monitor instance
    pub fn new(db_path: PathBuf, metrics_threshold_ms: u64) -> Result<Self, AgentError> {
        let connection = Connection::open(&db_path)
            .map_err(|e| AgentError::Database {
                message: format!("Failed to open database: {}", e),
                operation: Some("open_database".to_string()),
            context: None, transaction_id: None })?;
        
        let monitor = Self {
            db_path,
            metrics_threshold_ms,
            connection: Arc::new(Mutex::new(connection)),
        };
        
        // Initialize the database schema
        monitor.init_schema()?;
        
        Ok(monitor)
    }
    
    /// Initialize the database schema for performance metrics
    fn init_schema(&self) -> Result<(), AgentError> {
        let conn = self.connection.lock()
            .map_err(|e| AgentError::Database {
                message: format!("Failed to acquire database lock: {}", e),
                operation: Some("acquire_lock".to_string()),
            context: None, transaction_id: None })?;
        
        conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS operation_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id TEXT NOT NULL,
                compile_time_ms INTEGER NOT NULL,
                measured_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            "#,
            [],
        ).map_err(|e| AgentError::Database {
            message: format!("Failed to create operation_metrics table: {}", e),
            operation: Some("create_table".to_string()),
            context: None, transaction_id: None })?;
        
        Ok(())
    }
    
    /// Start the performance monitor
    pub fn start(&self) -> Result<(), AgentError> {
        info!("Starting YARA performance monitor with threshold: {}ms", self.metrics_threshold_ms);
        
        // Verify database connection and schema
        self.init_schema()?;
        
        info!("Performance monitor started successfully");
        Ok(())
    }
    
    /// Record performance metrics for a YARA rule operation
    pub fn record(&self, metrics: OperationMetrics) -> Result<(), AgentError> {
        debug!("Recording metrics for rule '{}': {}ms", metrics.rule_id, metrics.compile_time_ms);
        
        // Check if compile time exceeds threshold
        if metrics.compile_time_ms > self.metrics_threshold_ms {
            warn!(
                "Rule '{}' compilation time ({}ms) exceeds threshold ({}ms)",
                metrics.rule_id, metrics.compile_time_ms, self.metrics_threshold_ms
            );
        }
        
        // Insert metrics into database
        let conn = self.connection.lock()
            .map_err(|e| AgentError::Database {
                message: format!("Failed to acquire database lock: {}", e),
                operation: Some("acquire_lock".to_string()),
            context: None, transaction_id: None })?;
        
        conn.execute(
            "INSERT INTO operation_metrics (rule_id, compile_time_ms) VALUES (?1, ?2)",
            [&metrics.rule_id, &metrics.compile_time_ms.to_string()],
        ).map_err(|e| AgentError::Database {
            message: format!("Failed to insert metrics: {}", e),
            operation: Some("execute_insert".to_string()),
            context: None, transaction_id: None })?;
        
        debug!("Successfully recorded metrics for rule '{}'", metrics.rule_id);
        Ok(())
    }
    
    /// Collect all recorded performance metrics
    pub fn collect(&self) -> Result<Vec<OperationMetrics>, AgentError> {
        let conn = self.connection.lock()
            .map_err(|e| AgentError::Database {
                message: format!("Failed to acquire database lock: {}", e),
                operation: Some("acquire_lock".to_string()),
            context: None, transaction_id: None })?;
        
        let mut stmt = conn.prepare(
            "SELECT rule_id, compile_time_ms FROM operation_metrics ORDER BY measured_at DESC"
        ).map_err(|e| AgentError::Database {
            message: format!("Failed to prepare select statement: {}", e),
            operation: Some("prepare_select".to_string()),
            context: None, transaction_id: None })?;
        
        let metrics_iter = stmt.query_map([], |row| {
            Ok(OperationMetrics {
                rule_id: row.get(0)?,
                compile_time_ms: row.get(1)?,
            })
        }).map_err(|e| AgentError::Database {
            message: format!("Failed to execute select query: {}", e),
            operation: Some("execute_select".to_string()),
            context: None,
            transaction_id: None,
        })?;
        
        let mut metrics = Vec::new();
        for metric_result in metrics_iter {
            let metric = metric_result
                .map_err(|e| AgentError::Database {
                    message: format!("Failed to parse metric row: {}", e),
                    operation: Some("parse_row".to_string()),
                    context: None,
                    transaction_id: None,
                })?;
            metrics.push(metric);
        }
        
        debug!("Collected {} performance metrics", metrics.len());
        Ok(metrics)
    }
    
    /// Collect top N slowest rules
    pub fn collect_top_slowest(&self, limit: usize) -> Result<Vec<OperationMetrics>, AgentError> {
        let conn = self.connection.lock()
            .map_err(|e| AgentError::Database {
                message: format!("Failed to acquire database lock: {}", e),
                operation: Some("acquire_lock".to_string()),
            context: None, transaction_id: None })?;
        
        let mut stmt = conn.prepare(
            "SELECT rule_id, compile_time_ms FROM operation_metrics ORDER BY compile_time_ms DESC LIMIT ?1"
        ).map_err(|e| AgentError::Database {
            message: format!("Failed to prepare top slowest query: {}", e),
            operation: Some("prepare_top_select".to_string()),
            context: None,
            transaction_id: None,
        })?;
        
        let metrics_iter = stmt.query_map([limit], |row| {
            Ok(OperationMetrics {
                rule_id: row.get(0)?,
                compile_time_ms: row.get(1)?,
            })
        }).map_err(|e| AgentError::Database {
            message: format!("Failed to execute top slowest query: {}", e),
            operation: Some("execute_top_select".to_string()),
            context: None,
            transaction_id: None,
        })?;
        
        let mut metrics = Vec::new();
        for metric_result in metrics_iter {
            let metric = metric_result
                .map_err(|e| AgentError::Database {
                    message: format!("Failed to parse metric row: {}", e),
                    operation: Some("parse_top_row".to_string()),
            context: None, transaction_id: None })?;
            metrics.push(metric);
        }
        
        debug!("Collected top {} slowest rules", metrics.len());
        Ok(metrics)
    }
    
    /// Start monitoring an operation
    pub fn start_operation(&self, _scan_id: String, _operation_type: OperationType) -> Result<(), AgentError> {
        // For now, just return Ok - this could be extended to track operation starts
        Ok(())
    }

    /// Finish monitoring an operation
    pub fn finish_operation(&self, _scan_id: String) -> Result<(), AgentError> {
        // For now, just return Ok - this could be extended to track operation completion
        Ok(())
    }

    /// Get performance statistics
    pub fn get_performance_stats(&self) -> Result<PerformanceMetrics, AgentError> {
        let conn = self.connection.lock()
             .map_err(|e| AgentError::Database {
                 message: format!("Failed to acquire database lock: {}", e),
                 operation: Some("get_performance_stats".to_string()),
            context: None, transaction_id: None })?;

        let mut stmt = conn.prepare(
            "SELECT COUNT(*), AVG(compile_time_ms), MAX(compile_time_ms), MIN(compile_time_ms) FROM operation_metrics"
        ).map_err(|e| AgentError::Database {
             message: format!("Failed to prepare statement: {}", e),
             operation: Some("prepare_statement".to_string()),
             context: None,
             transaction_id: None,
         })?;

        let stats = stmt.query_row([], |row| {
            Ok(PerformanceMetrics {
                total_operations: row.get::<_, i64>(0)? as u64,
                average_time_ms: row.get::<_, Option<f64>>(1)?.unwrap_or(0.0),
                max_time_ms: row.get::<_, Option<i64>>(2)?.unwrap_or(0) as u64,
                min_time_ms: row.get::<_, Option<i64>>(3)?.unwrap_or(0) as u64,
            })
        }).map_err(|e| AgentError::Database {
             message: format!("Failed to query performance stats: {}", e),
             operation: Some("query_performance_stats".to_string()),
             context: None,
             transaction_id: None,
         })?;

        Ok(stats)
    }

    /// Get metrics with detailed information including timestamps
    pub fn collect_detailed(&self) -> Result<Vec<DetailedOperationMetrics>, AgentError> {
        let conn = self.connection.lock()
            .map_err(|e| AgentError::Database {
                message: format!("Failed to acquire database lock: {}", e),
                operation: Some("acquire_lock".to_string()),
            context: None, transaction_id: None })?;
        
        let mut stmt = conn.prepare(
            "SELECT rule_id, compile_time_ms, measured_at FROM operation_metrics ORDER BY measured_at DESC"
        ).map_err(|e| AgentError::Database {
            message: format!("Failed to prepare detailed select statement: {}", e),
            operation: Some("prepare_detailed_select".to_string()),
            context: None,
            transaction_id: None,
        })?;
        
        let metrics_iter = stmt.query_map([], |row| {
            Ok(DetailedOperationMetrics {
                rule_id: row.get(0)?,
                compile_time_ms: row.get(1)?,
                measured_at: row.get(2)?,
            })
        }).map_err(|e| AgentError::Database {
            message: format!("Failed to execute detailed select query: {}", e),
            operation: Some("execute_detailed_select".to_string()),
            context: None,
            transaction_id: None,
        })?;
        
        let mut metrics = Vec::new();
        for metric_result in metrics_iter {
            let metric = metric_result
                .map_err(|e| AgentError::Database {
                    message: format!("Failed to parse detailed metric row: {}", e),
                    operation: Some("parse_detailed_row".to_string()),
            context: None, transaction_id: None })?;
            metrics.push(metric);
        }
        
        debug!("Collected {} detailed performance metrics", metrics.len());
        Ok(metrics)
    }
}

/// Detailed metrics including timestamp information
#[derive(Debug, Clone, Serialize)]
pub struct DetailedOperationMetrics {
    pub rule_id: String,
    pub compile_time_ms: u64,
    pub measured_at: String,
}

/// Performance metrics for enhanced scanner
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PerformanceMetrics {
    pub total_operations: u64,
    pub average_time_ms: f64,
    pub max_time_ms: u64,
    pub min_time_ms: u64,
}

/// Operation types for performance monitoring
#[derive(Debug, Clone)]
pub enum OperationType {
    FileScanning,
    RuleCompilation,
    RuleOptimization,
}

impl Drop for PerformanceMonitor {
    fn drop(&mut self) {
        // Ensure database connection is properly closed
        if let Ok(_conn) = self.connection.lock() {
            // Connection will be dropped automatically when the lock is released
            info!("PerformanceMonitor database connection closed during drop");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    // Removed unused import: std::path::Path
    
    fn create_test_monitor() -> (PerformanceMonitor, tempfile::TempDir) {
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let db_path = temp_dir.path().join("test_metrics.db");
        let monitor = PerformanceMonitor::new(db_path, 50).expect("Failed to create monitor");
        (monitor, temp_dir)
    }
    
    #[test]
    fn test_monitor_creation() {
        let (monitor, _temp_dir) = create_test_monitor();
        assert_eq!(monitor.metrics_threshold_ms, 50);
    }
    
    #[test]
    fn test_start_monitor() {
        let (monitor, _temp_dir) = create_test_monitor();
        assert!(monitor.start().is_ok());
    }
    
    #[test]
    fn test_record_and_collect_metrics() {
        let (monitor, _temp_dir) = create_test_monitor();
        monitor.start().expect("Failed to start monitor");
        
        // Record some test metrics
        let metrics1 = OperationMetrics {
            rule_id: "test_rule_1".to_string(),
            compile_time_ms: 25,
        };
        let metrics2 = OperationMetrics {
            rule_id: "test_rule_2".to_string(),
            compile_time_ms: 75,
        };
        
        assert!(monitor.record(metrics1).is_ok());
        assert!(monitor.record(metrics2).is_ok());
        
        // Collect and verify metrics
        let collected = monitor.collect().expect("Failed to collect metrics");
        assert_eq!(collected.len(), 2);
        
        // Verify both metrics are present (order may vary)
        let rule_ids: Vec<String> = collected.iter().map(|m| m.rule_id.clone()).collect();
        assert!(rule_ids.contains(&"test_rule_1".to_string()));
        assert!(rule_ids.contains(&"test_rule_2".to_string()));
        
        // Verify compile times are correct
        let rule1_metrics = collected.iter().find(|m| m.rule_id == "test_rule_1").unwrap();
        let rule2_metrics = collected.iter().find(|m| m.rule_id == "test_rule_2").unwrap();
        assert_eq!(rule1_metrics.compile_time_ms, 25);
        assert_eq!(rule2_metrics.compile_time_ms, 75);
    }
    
    #[test]
    fn test_collect_top_slowest() {
        let (monitor, _temp_dir) = create_test_monitor();
        monitor.start().expect("Failed to start monitor");
        
        // Record metrics with different compile times
        let test_cases = vec![
            ("fast_rule", 10),
            ("medium_rule", 50),
            ("slow_rule", 100),
            ("very_slow_rule", 200),
        ];
        
        for (rule_id, compile_time) in test_cases {
            let metrics = OperationMetrics {
                rule_id: rule_id.to_string(),
                compile_time_ms: compile_time,
            };
            monitor.record(metrics).expect("Failed to record metrics");
        }
        
        // Get top 2 slowest rules
        let top_slowest = monitor.collect_top_slowest(2).expect("Failed to collect top slowest");
        assert_eq!(top_slowest.len(), 2);
        assert_eq!(top_slowest[0].rule_id, "very_slow_rule");
        assert_eq!(top_slowest[0].compile_time_ms, 200);
        assert_eq!(top_slowest[1].rule_id, "slow_rule");
        assert_eq!(top_slowest[1].compile_time_ms, 100);
    }
    
    #[test]
    fn test_detailed_metrics() {
        let (monitor, _temp_dir) = create_test_monitor();
        monitor.start().expect("Failed to start monitor");
        
        let metrics = OperationMetrics {
            rule_id: "detailed_test_rule".to_string(),
            compile_time_ms: 42,
        };
        
        monitor.record(metrics).expect("Failed to record metrics");
        
        let detailed = monitor.collect_detailed().expect("Failed to collect detailed metrics");
        assert_eq!(detailed.len(), 1);
        assert_eq!(detailed[0].rule_id, "detailed_test_rule");
        assert_eq!(detailed[0].compile_time_ms, 42);
        assert!(!detailed[0].measured_at.is_empty());
    }
}
