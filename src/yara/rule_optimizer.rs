//! YARA Rule Optimization Engine
//!
//! This module provides rule optimization capabilities including:
//! - Rule deduplication based on SHA-256 content hashing
//! - Performance scoring through compilation timing
//! - Database integration for rule management
//! - Parallel processing for efficient optimization

use crate::error::AgentError;
use crate::yara::performance_monitor::{PerformanceMonitor, OperationMetrics};
use log::{debug, info, warn};
use rayon::prelude::*;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use std::path::PathBuf;
use std::time::Instant;
use yara_x::Compiler;

/// Rule optimizer for YARA rules
#[derive(Debug, Clone)]
pub struct RuleOptimizer {
    /// Base directory containing YARA rules
    pub rules_base: PathBuf,
    /// Path to SQLite database
    pub db_path: PathBuf,
    performance_monitor: Option<PerformanceMonitor>,
}

/// Result of rule optimization process
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationResult {
    /// Unique identifier for the rule
    pub id: String,
    /// ID of the rule this is a duplicate of (if any)
    pub duplicate_of: Option<String>,
    /// Performance score (0.0 to 1.0)
    pub performance_score: f32,
}

/// Internal structure for rule data from database
#[derive(Debug, Clone)]
struct RuleData {
    id: String,
    file_path: String,
    content: String,
}

impl RuleOptimizer {
    /// Create a new rule optimizer
    pub fn new(rules_base: PathBuf, db_path: PathBuf) -> Result<Self, AgentError> {
        Ok(Self {
            rules_base,
            db_path: db_path.clone(),
            performance_monitor: Some(PerformanceMonitor::new(db_path, 100)?), // 100ms threshold
        })
    }

    /// Create a new RuleOptimizer instance with custom performance monitor
    pub fn with_performance_monitor(rules_base: PathBuf, db_path: PathBuf, monitor: Option<PerformanceMonitor>) -> Self {
        Self {
            rules_base,
            db_path,
            performance_monitor: monitor,
        }
    }

    /// Initialize the rules table in the database
    pub fn init_database(&self) -> Result<(), AgentError> {
        let conn = Connection::open(&self.db_path)
            .map_err(|e| AgentError::Database {
                message: format!("Failed to open database: {}", e),
                operation: Some("open_database".to_string()),
            context: None, transaction_id: None })?;

        conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS rules (
                id TEXT PRIMARY KEY,
                file_path TEXT NOT NULL,
                content TEXT NOT NULL,
                is_active BOOLEAN NOT NULL DEFAULT 1,
                performance_score REAL
            )
            "#,
            [],
        )
        .map_err(|e| AgentError::Database {
            message: format!("Failed to create rules table: {}", e),
            operation: Some("create_table".to_string()),
            context: None, transaction_id: None })?;

        Ok(())
    }

    /// Optimize all rules with deduplication and performance scoring
    pub fn optimize_all(
        &self,
        threshold: f32,
        dry_run: bool,
    ) -> Result<Vec<OptimizationResult>, AgentError> {
        info!("Starting rule optimization with threshold: {}ms, dry_run: {}", threshold, dry_run);

        // Read all active rules from database
        let rules = self.read_active_rules()?;
        info!("Found {} active rules to process", rules.len());

        // Process rules in parallel for deduplication and performance scoring
        let results: Result<Vec<_>, AgentError> = rules
            .par_iter()
            .enumerate()
            .map(|(index, rule)| {
                // Log progress every 50 rules
                if index % 50 == 0 {
                    info!("Processing rule {} of {}", index + 1, rules.len());
                }

                self.process_rule(rule, threshold, &rules)
            })
            .collect();

        let optimization_results = results?;

        // Update database if not dry run
        if !dry_run {
            self.update_database(&optimization_results)?;
        }

        info!(
            "Optimization completed. Processed {} rules, found {} duplicates",
            optimization_results.len(),
            optimization_results.iter().filter(|r| r.duplicate_of.is_some()).count()
        );

        Ok(optimization_results)
    }

    /// Read all active rules from the database
    fn read_active_rules(&self) -> Result<Vec<RuleData>, AgentError> {
        let conn = Connection::open(&self.db_path)
            .map_err(|e| AgentError::Database {
                message: format!("Failed to open database: {}", e),
                operation: Some("open_database".to_string()),
            context: None, transaction_id: None })?;

        let mut stmt = conn
            .prepare("SELECT id, file_path, content FROM rules WHERE is_active = 1")
            .map_err(|e| AgentError::Database {
                message: format!("Failed to prepare statement: {}", e),
                operation: Some("prepare_statement".to_string()),
            context: None, transaction_id: None })?;

        let rule_iter = stmt
            .query_map([], |row| {
                Ok(RuleData {
                    id: row.get(0)?,
                    file_path: row.get(1)?,
                    content: row.get(2)?,
                })
            })
            .map_err(|e| AgentError::Database {
                message: format!("Failed to query rules: {}", e),
                operation: Some("query_rules".to_string()),
            context: None, transaction_id: None })?;

        let mut rules = Vec::new();
        for rule in rule_iter {
            rules.push(rule.map_err(|e| AgentError::Database {
                message: format!("Failed to read rule row: {}", e),
                operation: Some("read_rule_row".to_string()),
            context: None, transaction_id: None })?);
        }

        Ok(rules)
    }

    /// Process a single rule for optimization
    fn process_rule(
        &self,
        rule: &RuleData,
        threshold: f32,
        all_rules: &[RuleData],
    ) -> Result<OptimizationResult, AgentError> {
        info!("Starting optimization for rule: {}", rule.id);

        // Calculate SHA-256 hash of rule content
        let content_hash = self.calculate_sha256(&rule.content);
        debug!("Calculated hash for rule {}: {}", rule.id, content_hash);

        // Check for duplicates
        let duplicate_of = self.find_duplicate(rule, all_rules, &content_hash);
        if let Some(ref dup_id) = duplicate_of {
            debug!("Rule {} is duplicate of {}", rule.id, dup_id);
        }

        // Measure compilation performance with monitoring
        let performance_score = self.measure_performance_with_monitoring(&rule.id, &rule.content, threshold)?;
        
        if performance_score < 0.5 {
            warn!("Rule {} has low performance score: {:.2}", rule.id, performance_score);
        }

        Ok(OptimizationResult {
            id: rule.id.clone(),
            duplicate_of,
            performance_score,
        })
    }

    /// Calculate SHA-256 hash of rule content
    fn calculate_sha256(&self, content: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Find duplicate rule based on content hash
    fn find_duplicate(
        &self,
        current_rule: &RuleData,
        all_rules: &[RuleData],
        current_hash: &str,
    ) -> Option<String> {
        for other_rule in all_rules {
            if other_rule.id != current_rule.id {
                let other_hash = self.calculate_sha256(&other_rule.content);
                if other_hash == current_hash {
                    // Return the ID of the first rule found with same hash
                    // (lexicographically smaller ID to ensure consistency)
                    if other_rule.id < current_rule.id {
                        return Some(other_rule.id.clone());
                    }
                }
            }
        }
        None
    }

    /// Measure rule compilation performance and calculate score
    fn measure_performance(&self, content: &str, threshold: f32) -> Result<f32, AgentError> {
        let start = Instant::now();
        
        // Compile the rule using yara_x
        let mut compiler = Compiler::new();
        let rules_result = compiler.add_source(content);
        if let Err(e) = rules_result {
            return Err(AgentError::SystemError(format!("Failed to add rule source: {}", e)));
        }
        
        let _rules = compiler.build();
        
        let duration_ms = start.elapsed().as_millis() as u64;
        
        if duration_ms as f32 > threshold {
            warn!("Rule compilation took {}ms, exceeding threshold of {}ms", duration_ms, threshold);
        }
        
        // Calculate performance score: max(0.0, 1.0 - duration_ms/threshold)
        let score = (1.0 - (duration_ms as f32 / threshold)).max(0.0);
        
        Ok(score)
    }

    /// Measure rule compilation performance with monitoring integration
    fn measure_performance_with_monitoring(&self, rule_id: &str, content: &str, threshold: f32) -> Result<f32, AgentError> {
        let start = Instant::now();
        
        // Compile the rule using yara_x
        let mut compiler = Compiler::new();
        let rules_result = compiler.add_source(content);
        if let Err(e) = rules_result {
            return Err(AgentError::SystemError(format!("Failed to add rule source: {}", e)));
        }
        
        let _rules = compiler.build();
        
        let duration_ms = start.elapsed().as_millis() as u64;
        
        // Record performance metrics if monitor is available
        if let Some(ref monitor) = self.performance_monitor {
            let metrics = OperationMetrics {
                rule_id: rule_id.to_string(),
                compile_time_ms: duration_ms,
            };
            if let Err(e) = monitor.record(metrics) {
                warn!("Failed to record performance metrics for rule {}: {}", rule_id, e);
            }
        }
        
        if duration_ms as f32 > threshold {
            warn!("Rule compilation took {}ms, exceeding threshold of {}ms", duration_ms, threshold);
        }
        
        // Calculate performance score: max(0.0, 1.0 - duration_ms/threshold)
        let score = (1.0 - (duration_ms as f32 / threshold)).max(0.0);
        
        Ok(score)
    }

    /// Update database with optimization results
    fn update_database(&self, results: &[OptimizationResult]) -> Result<(), AgentError> {
        let conn = Connection::open(&self.db_path)
            .map_err(|e| AgentError::Database {
                message: format!("Failed to open database: {}", e),
                operation: Some("open_database".to_string()),
            context: None, transaction_id: None })?;

        let tx = conn.unchecked_transaction()
            .map_err(|e| AgentError::Database {
                message: format!("Failed to start transaction: {}", e),
                operation: Some("start_transaction".to_string()),
            context: None, transaction_id: None })?;

        for result in results {
            // Set is_active = false for duplicates
            let is_active = result.duplicate_of.is_none();
            
            tx.execute(
                "UPDATE rules SET is_active = ?, performance_score = ? WHERE id = ?",
                params![is_active, result.performance_score, result.id],
            )
            .map_err(|e| AgentError::Database {
                message: format!("Failed to update rule {}: {}", result.id, e),
                operation: Some("update_rule".to_string()),
            context: None, transaction_id: None })?;
        }

        tx.commit()
            .map_err(|e| AgentError::Database {
                message: format!("Failed to commit transaction: {}", e),
                operation: Some("commit_transaction".to_string()),
            context: None, transaction_id: None })?;

        info!("Database updated with {} optimization results", results.len());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Removed unused imports: std::fs, tempfile::TempDir

    #[test]
    fn test_sha256_calculation() {
        let optimizer = RuleOptimizer::new(PathBuf::from("/tmp"), PathBuf::from("/tmp/test.db")).unwrap();
        
        let content1 = "rule test { condition: true }";
        let content2 = "rule test { condition: true }";
        let content3 = "rule different { condition: false }";
        
        let hash1 = optimizer.calculate_sha256(content1);
        let hash2 = optimizer.calculate_sha256(content2);
        let hash3 = optimizer.calculate_sha256(content3);
        
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_duplicate_detection() {
        let optimizer = RuleOptimizer::new(PathBuf::from("/tmp"), PathBuf::from("/tmp/test.db")).unwrap();
        
        let rules = vec![
            RuleData {
                id: "rule1".to_string(),
                file_path: "/path/rule1.yar".to_string(),
                content: "rule test { condition: true }".to_string(),
            },
            RuleData {
                id: "rule2".to_string(),
                file_path: "/path/rule2.yar".to_string(),
                content: "rule test { condition: true }".to_string(),
            },
            RuleData {
                id: "rule3".to_string(),
                file_path: "/path/rule3.yar".to_string(),
                content: "rule different { condition: false }".to_string(),
            },
        ];
        
        let hash = optimizer.calculate_sha256(&rules[1].content);
        let duplicate = optimizer.find_duplicate(&rules[1], &rules, &hash);
        
        assert_eq!(duplicate, Some("rule1".to_string()));
        
        let hash3 = optimizer.calculate_sha256(&rules[2].content);
        let no_duplicate = optimizer.find_duplicate(&rules[2], &rules, &hash3);
        
        assert_eq!(no_duplicate, None);
    }
}
