//! Advanced Correlation Engine for ERDPS Agent
//!
//! This module provides correlation analysis capabilities for LayeredScanResult data,
//! identifying patterns and relationships across multiple scans and detection layers.

use crate::error::{AgentError, AgentResult};
use crate::yara::multi_layer_scanner::LayeredScanResult;
use chrono::{DateTime, Utc};
use log::{debug, info, warn};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use uuid::Uuid;

/// Correlation Engine for analyzing LayeredScanResult data
#[derive(Debug)]
pub struct CorrelationEngine {
    /// Database path for storing correlation data
    db_path: PathBuf,
}

/// Correlated alert representing a pattern found across multiple scans/layers
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CorrelatedAlert {
    /// Unique alert identifier
    pub alert_id: String,
    /// Rule IDs that triggered this correlation
    pub rule_ids: Vec<String>,
    /// Confidence score (0.0 to 1.0)
    pub confidence: f32,
    /// Timestamp when correlation was detected
    pub timestamp: DateTime<Utc>,
    /// Number of overlapping layers
    pub overlap_layers: usize,
    /// Number of overlapping scans
    pub overlap_scans: usize,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Internal structure for tracking rule occurrences
#[derive(Debug, Clone)]
struct RuleOccurrence {
    rule_id: String,
    scan_index: usize,
    layers: HashSet<String>,
    confidence: f32,
    severity: String,
}

impl CorrelationEngine {
    /// Create a new correlation engine
    pub fn new(db_path: PathBuf) -> AgentResult<Self> {
        let engine = Self { db_path };

        engine.initialize_database()?;
        Ok(engine)
    }

    /// Initialize the database schema
    fn initialize_database(&self) -> AgentResult<()> {
        let conn = Connection::open(&self.db_path).map_err(|e| AgentError::Database {
            message: format!("Failed to open correlation database: {}", e),
            operation: Some("open".to_string()),
            context: None,
            transaction_id: None })?;

        conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS correlated_alerts (
                id TEXT PRIMARY KEY,
                rule_ids TEXT NOT NULL,
                confidence REAL NOT NULL,
                detected_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                overlap_layers INTEGER NOT NULL,
                overlap_scans INTEGER NOT NULL,
                metadata TEXT
            )
            "#,
            [],
        )
        .map_err(|e| AgentError::Database {
            message: format!("Failed to create correlated_alerts table: {}", e),
            operation: Some("create_table".to_string()),
            context: None, transaction_id: None })?;

        debug!("Correlation database initialized at: {:?}", self.db_path);
        Ok(())
    }

    /// Correlate scan results to find patterns across multiple scans and layers
    pub fn correlate(
        &self,
        results: &[LayeredScanResult],
        min_scans: usize,
        min_layers: usize,
    ) -> AgentResult<Vec<CorrelatedAlert>> {
        info!(
            "Starting correlation analysis for {} scan results",
            results.len()
        );

        if results.is_empty() {
            return Ok(Vec::new());
        }

        // Extract rule occurrences from all scan results
        let rule_occurrences = self.extract_rule_occurrences(results)?;

        // Group occurrences by rule ID
        let mut rule_groups: HashMap<String, Vec<RuleOccurrence>> = HashMap::new();
        for occurrence in rule_occurrences {
            rule_groups
                .entry(occurrence.rule_id.clone())
                .or_insert_with(Vec::new)
                .push(occurrence);
        }

        // Analyze correlations
        let mut correlated_alerts = Vec::new();

        for (rule_id, occurrences) in rule_groups {
            if let Some(alert) =
                self.analyze_rule_correlation(&rule_id, &occurrences, min_scans, min_layers)?
            {
                debug!(
                    "Candidate alert for rule {}: layers={}, scans={}, confidence={:.3}",
                    rule_id, alert.overlap_layers, alert.overlap_scans, alert.confidence
                );

                if alert.confidence < 0.5 {
                    warn!(
                        "Low confidence alert for rule {}: {:.3} < 0.5",
                        rule_id, alert.confidence
                    );
                }

                correlated_alerts.push(alert);
            }
        }

        info!(
            "Correlation analysis completed: {} alerts generated from {} results",
            correlated_alerts.len(),
            results.len()
        );

        Ok(correlated_alerts)
    }

    /// Extract rule occurrences from scan results
    fn extract_rule_occurrences(
        &self,
        results: &[LayeredScanResult],
    ) -> AgentResult<Vec<RuleOccurrence>> {
        let mut occurrences = Vec::new();

        for (scan_index, result) in results.iter().enumerate() {
            // Extract from file matches
            for rule_match in &result.file_matches {
                let mut layers = HashSet::new();
                layers.insert("file".to_string());

                occurrences.push(RuleOccurrence {
                    rule_id: rule_match.rule_name.clone(),
                    scan_index,
                    layers,
                    confidence: rule_match.confidence,
                    severity: rule_match.severity.clone(),
                });
            }

            // Extract from memory matches
            for rule_match in &result.memory_matches {
                let mut layers = HashSet::new();
                layers.insert("memory".to_string());

                occurrences.push(RuleOccurrence {
                    rule_id: rule_match.rule_name.clone(),
                    scan_index,
                    layers,
                    confidence: rule_match.confidence,
                    severity: rule_match.severity.clone(),
                });
            }

            // Extract from behavior matches
            for rule_match in &result.behavior_matches {
                let mut layers = HashSet::new();
                layers.insert("behavior".to_string());

                occurrences.push(RuleOccurrence {
                    rule_id: rule_match.rule_name.clone(),
                    scan_index,
                    layers,
                    confidence: rule_match.confidence,
                    severity: rule_match.severity.clone(),
                });
            }

            // Extract from network matches
            for rule_match in &result.network_matches {
                let mut layers = HashSet::new();
                layers.insert("network".to_string());

                occurrences.push(RuleOccurrence {
                    rule_id: rule_match.rule_name.clone(),
                    scan_index,
                    layers,
                    confidence: rule_match.confidence,
                    severity: rule_match.severity.clone(),
                });
            }
        }

        Ok(occurrences)
    }

    /// Analyze correlation for a specific rule
    fn analyze_rule_correlation(
        &self,
        rule_id: &str,
        occurrences: &[RuleOccurrence],
        min_scans: usize,
        min_layers: usize,
    ) -> AgentResult<Option<CorrelatedAlert>> {
        // Count unique scans and layers
        let unique_scans: HashSet<usize> = occurrences.iter().map(|o| o.scan_index).collect();
        let mut all_layers = HashSet::new();

        for occurrence in occurrences {
            all_layers.extend(occurrence.layers.iter().cloned());
        }

        let overlap_scans = unique_scans.len();
        let overlap_layers = all_layers.len();

        // Check if correlation criteria are met
        if overlap_scans < min_scans || overlap_layers < min_layers {
            return Ok(None);
        }

        // Calculate confidence score
        let base_confidence = 0.5;
        let layer_bonus = 0.25 * (overlap_layers.saturating_sub(1) as f32);
        let scan_bonus = 0.25 * (overlap_scans.saturating_sub(1) as f32);
        let confidence = (base_confidence + layer_bonus + scan_bonus).min(1.0);

        // Create metadata
        let mut metadata = HashMap::new();
        metadata.insert("rule_id".to_string(), rule_id.to_string());
        metadata.insert("unique_scans".to_string(), overlap_scans.to_string());
        metadata.insert("unique_layers".to_string(), overlap_layers.to_string());

        // Add severity information if available
        if let Some(first_occurrence) = occurrences.first() {
            metadata.insert("severity".to_string(), first_occurrence.severity.clone());
        }

        let alert = CorrelatedAlert {
            alert_id: Uuid::new_v4().to_string(),
            rule_ids: vec![rule_id.to_string()],
            confidence,
            timestamp: Utc::now(),
            overlap_layers,
            overlap_scans,
            metadata,
        };

        Ok(Some(alert))
    }

    /// Store correlated alerts in the database
    pub fn store_alerts(&self, alerts: &[CorrelatedAlert]) -> AgentResult<()> {
        if alerts.is_empty() {
            return Ok(());
        }

        info!("Storing {} correlated alerts to database", alerts.len());

        let conn = Connection::open(&self.db_path).map_err(|e| AgentError::Database {
            message: format!("Failed to open correlation database: {}", e),
            operation: Some("open".to_string()),
            context: None, transaction_id: None })?;

        let tx = conn
            .unchecked_transaction()
            .map_err(|e| AgentError::Database {
                message: format!("Failed to start transaction: {}", e),
                operation: Some("transaction".to_string()),
            context: None, transaction_id: None })?;

        for alert in alerts {
            let rule_ids_json =
                serde_json::to_string(&alert.rule_ids).map_err(|e| AgentError::Database {
                    message: format!("Failed to serialize rule IDs: {}", e),
                    operation: Some("serialize".to_string()),
            context: None, transaction_id: None })?;

            let metadata_json =
                serde_json::to_string(&alert.metadata).map_err(|e| AgentError::Database {
                    message: format!("Failed to serialize metadata: {}", e),
                    operation: Some("serialize".to_string()),
            context: None, transaction_id: None })?;

            tx.execute(
                r#"
                INSERT INTO correlated_alerts 
                (id, rule_ids, confidence, detected_at, overlap_layers, overlap_scans, metadata)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                "#,
                params![
                    alert.alert_id,
                    rule_ids_json,
                    alert.confidence,
                    alert.timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
                    alert.overlap_layers as i64,
                    alert.overlap_scans as i64,
                    metadata_json
                ],
            )
            .map_err(|e| AgentError::Database {
                message: format!("Failed to insert correlated alert: {}", e),
                operation: Some("insert".to_string()),
            context: None, transaction_id: None })?;
        }

        tx.commit().map_err(|e| AgentError::Database {
            message: format!("Failed to commit transaction: {}", e),
            operation: Some("commit".to_string()),
            context: None, transaction_id: None })?;

        info!("Successfully stored {} correlated alerts", alerts.len());
        Ok(())
    }

    /// Retrieve stored alerts from the database
    pub fn get_alerts(&self, limit: Option<usize>) -> AgentResult<Vec<CorrelatedAlert>> {
        let conn = Connection::open(&self.db_path).map_err(|e| AgentError::Database {
            message: format!("Failed to open correlation database: {}", e),
            operation: Some("open".to_string()),
            context: None, transaction_id: None })?;

        let query = if let Some(limit) = limit {
            format!(
                "SELECT id, rule_ids, confidence, detected_at, overlap_layers, overlap_scans, metadata 
                 FROM correlated_alerts ORDER BY detected_at DESC LIMIT {}",
                limit
            )
        } else {
            "SELECT id, rule_ids, confidence, detected_at, overlap_layers, overlap_scans, metadata 
             FROM correlated_alerts ORDER BY detected_at DESC"
                .to_string()
        };

        let mut stmt = conn.prepare(&query).map_err(|e| AgentError::Database {
            message: format!("Failed to prepare query: {}", e),
            operation: Some("prepare".to_string()),
            context: None, transaction_id: None })?;

        let alert_iter = stmt
            .query_map([], |row| {
                let rule_ids_json: String = row.get(1)?;
                let metadata_json: String = row.get(6)?;

                let rule_ids: Vec<String> = serde_json::from_str(&rule_ids_json).map_err(|_e| {
                    rusqlite::Error::InvalidColumnType(
                        1,
                        "rule_ids".to_string(),
                        rusqlite::types::Type::Text,
                    )
                })?;

                let metadata: HashMap<String, String> = serde_json::from_str(&metadata_json)
                    .map_err(|_e| {
                        rusqlite::Error::InvalidColumnType(
                            6,
                            "metadata".to_string(),
                            rusqlite::types::Type::Text,
                        )
                    })?;

                let timestamp_str: String = row.get(3)?;
                let timestamp = DateTime::parse_from_str(&timestamp_str, "%Y-%m-%d %H:%M:%S UTC")
                    .map_err(|_| {
                        rusqlite::Error::InvalidColumnType(
                            3,
                            "detected_at".to_string(),
                            rusqlite::types::Type::Text,
                        )
                    })?
                    .with_timezone(&Utc);

                Ok(CorrelatedAlert {
                    alert_id: row.get(0)?,
                    rule_ids,
                    confidence: row.get(2)?,
                    timestamp,
                    overlap_layers: row.get::<_, i64>(4)? as usize,
                    overlap_scans: row.get::<_, i64>(5)? as usize,
                    metadata,
                })
            })
            .map_err(|e| AgentError::Database {
                message: format!("Failed to execute query: {}", e),
                operation: Some("query".to_string()),
            context: None, transaction_id: None })?;

        let mut alerts = Vec::new();
        for alert_result in alert_iter {
            let alert = alert_result.map_err(|e| AgentError::Database {
                message: format!("Failed to parse alert from database: {}", e),
                operation: Some("parse".to_string()),
            context: None, transaction_id: None })?;
            alerts.push(alert);
        }

        Ok(alerts)
    }
}
