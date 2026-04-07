//! YARA Rule Storage Module
//!
//! This module provides SQLite-based storage for YARA rule metadata,
//! GitHub sources, performance metrics, and validation results.

use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
// use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::task;
use tracing::info;

use super::github_downloader::{DownloadStats, GitHubSource};
use super::rule_validator::ValidationResult;

/// Database schema version for migrations
const SCHEMA_VERSION: i32 = 2;

/// Rule metadata stored in database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredRuleMetadata {
    pub id: Option<i64>,
    pub file_path: PathBuf,
    pub rule_name: String,
    pub file_hash: String,
    pub file_size: u64,
    pub rule_count: usize,
    pub is_valid: bool,
    pub compilation_time_ms: u64,
    pub author: Option<String>,
    pub description: Option<String>,
    pub version: Option<String>,
    pub category: Option<String>,
    pub tags: Vec<String>,
    pub severity: Option<String>,
    pub confidence: Option<String>,
    pub source_repository: Option<String>,
    pub last_validated: SystemTime,
    pub created_at: SystemTime,
    pub updated_at: SystemTime,
}

/// GitHub repository information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredGitHubRepo {
    pub id: Option<i64>,
    pub name: String,
    pub url: String,
    pub branch: String,
    pub local_path: PathBuf,
    pub last_updated: SystemTime,
    pub total_rules: usize,
    pub valid_rules: usize,
    pub invalid_rules: usize,
    pub is_enabled: bool,
    pub created_at: SystemTime,
}

/// Performance metrics for scanning operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredPerformanceMetric {
    pub id: Option<i64>,
    pub operation_type: String,
    pub file_path: Option<PathBuf>,
    pub rule_count: usize,
    pub execution_time_ms: u64,
    pub memory_usage_mb: Option<f64>,
    pub cpu_usage_percent: Option<f64>,
    pub success: bool,
    pub error_message: Option<String>,
    pub timestamp: SystemTime,
}

/// Validation history entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredValidationHistory {
    pub id: Option<i64>,
    pub file_path: PathBuf,
    pub validation_result: String, // JSON serialized ValidationResult
    pub is_valid: bool,
    pub error_count: usize,
    pub warning_count: usize,
    pub validation_time_ms: u64,
    pub timestamp: SystemTime,
}

/// Storage statistics
#[derive(Debug, Clone, Default, Serialize)]
pub struct StorageStats {
    pub total_rules: usize,
    pub valid_rules: usize,
    pub invalid_rules: usize,
    pub total_repositories: usize,
    pub enabled_repositories: usize,
    pub total_validations: usize,
    pub recent_validations: usize,
    pub average_compilation_time: Duration,
    pub database_size_mb: f64,
    pub last_update: Option<SystemTime>,
}

/// SQLite storage manager for YARA rules
pub struct YaraStorage {
    db_path: PathBuf,
    connection: Option<Connection>,
}

impl YaraStorage {
    /// Create a new storage manager
    pub fn new<P: AsRef<Path>>(db_path: P) -> Self {
        Self {
            db_path: db_path.as_ref().to_path_buf(),
            connection: None,
        }
    }

    /// Get the database path
    pub fn get_db_path(&self) -> &Path {
        &self.db_path
    }

    /// Initialize the database and create tables
    pub async fn initialize(&mut self) -> Result<()> {
        info!("Initializing YARA storage database: {:?}", self.db_path);

        // Ensure parent directory exists
        if let Some(parent) = self.db_path.parent() {
            info!("Creating database directory: {:?}", parent);
            tokio::fs::create_dir_all(parent)
                .await
                .context("Failed to create database directory")?;
        }

        let db_path = self.db_path.clone();
        info!("Opening database connection to: {:?}", db_path);
        let connection = task::spawn_blocking(move || -> Result<Connection> {
            info!("Inside spawn_blocking, opening database: {:?}", db_path);
            let conn = Connection::open(&db_path)
                .with_context(|| format!("Failed to open database: {:?}", db_path))?;
            info!("Database opened successfully, setting pragmas...");

            // Enable foreign keys
            conn.execute("PRAGMA foreign_keys = ON", [])
                .context("Failed to enable foreign keys")?;
            info!("Foreign keys enabled");

            // Enable WAL mode for better concurrency (optional)
            match conn.execute("PRAGMA journal_mode = WAL", []) {
                Ok(_) => info!("WAL mode enabled"),
                Err(e) => {
                    info!(
                        "WAL mode failed, continuing with default journal mode: {}",
                        e
                    );
                    // Continue without WAL mode
                }
            }

            Ok(conn)
        })
        .await
        .context("spawn_blocking task failed")?
        .context("Database connection failed")?;

        self.connection = Some(connection);
        info!("Database connection established, creating tables...");
        self.create_tables()
            .await
            .context("Failed to create tables")?;
        info!("Tables created, migrating schema...");
        self.migrate_schema()
            .await
            .context("Failed to migrate schema")?;

        info!("YARA storage database initialized successfully");
        Ok(())
    }

    /// Create database tables
    async fn create_tables(&mut self) -> Result<()> {
        let conn = self
            .connection
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Database not initialized"))?;

        // Schema version table
        conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY,
                applied_at INTEGER NOT NULL
            )
            "#,
            [],
        )
        .context("Failed to create schema_version table")?;

        // GitHub repositories table
        conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS github_repositories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                url TEXT NOT NULL,
                branch TEXT NOT NULL DEFAULT 'main',
                local_path TEXT NOT NULL,
                last_updated INTEGER NOT NULL,
                total_rules INTEGER NOT NULL DEFAULT 0,
                valid_rules INTEGER NOT NULL DEFAULT 0,
                invalid_rules INTEGER NOT NULL DEFAULT 0,
                is_enabled BOOLEAN NOT NULL DEFAULT 1,
                created_at INTEGER NOT NULL,
                UNIQUE(name)
            )
            "#,
            [],
        )
        .context("Failed to create github_repositories table")?;

        // Rule metadata table
        conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS rule_metadata (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT NOT NULL,
                rule_name TEXT NOT NULL,
                file_hash TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                rule_count INTEGER NOT NULL,
                is_valid BOOLEAN NOT NULL,
                compilation_time_ms INTEGER NOT NULL,
                author TEXT,
                description TEXT,
                version TEXT,
                category TEXT,
                tags TEXT, -- JSON array
                severity TEXT,
                confidence TEXT,
                source_repository TEXT,
                last_validated INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                UNIQUE(file_path, rule_name)
            )
            "#,
            [],
        )
        .context("Failed to create rule_metadata table")?;

        // Performance metrics table
        conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS performance_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                operation_type TEXT NOT NULL,
                file_path TEXT,
                rule_count INTEGER NOT NULL,
                execution_time_ms INTEGER NOT NULL,
                memory_usage_mb REAL,
                cpu_usage_percent REAL,
                success BOOLEAN NOT NULL,
                error_message TEXT,
                timestamp INTEGER NOT NULL
            )
            "#,
            [],
        )
        .context("Failed to create performance_metrics table")?;

        // Validation history table
        conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS validation_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT NOT NULL,
                validation_result TEXT NOT NULL, -- JSON
                is_valid BOOLEAN NOT NULL,
                error_count INTEGER NOT NULL,
                warning_count INTEGER NOT NULL,
                validation_time_ms INTEGER NOT NULL,
                timestamp INTEGER NOT NULL
            )
            "#,
            [],
        )
        .context("Failed to create validation_history table")?;

        // Create indexes for better performance
        self.create_indexes().await?;

        Ok(())
    }

    /// Create database indexes
    async fn create_indexes(&mut self) -> Result<()> {
        let conn = self
            .connection
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Database not initialized"))?;

        let indexes = vec![
            "CREATE INDEX IF NOT EXISTS idx_rule_metadata_file_path ON rule_metadata(file_path)",
            "CREATE INDEX IF NOT EXISTS idx_rule_metadata_is_valid ON rule_metadata(is_valid)",
            "CREATE INDEX IF NOT EXISTS idx_rule_metadata_category ON rule_metadata(category)",
            "CREATE INDEX IF NOT EXISTS idx_rule_metadata_source_repo ON rule_metadata(source_repository)",
            "CREATE INDEX IF NOT EXISTS idx_performance_metrics_operation ON performance_metrics(operation_type)",
            "CREATE INDEX IF NOT EXISTS idx_performance_metrics_timestamp ON performance_metrics(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_validation_history_file_path ON validation_history(file_path)",
            "CREATE INDEX IF NOT EXISTS idx_validation_history_timestamp ON validation_history(timestamp)",
        ];

        for index_sql in indexes {
            conn.execute(index_sql, [])
                .with_context(|| format!("Failed to create index: {}", index_sql))?;
        }

        Ok(())
    }

    /// Migrate database schema if needed
    async fn migrate_schema(&mut self) -> Result<()> {
        let conn = self
            .connection
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Database not initialized"))?;

        // Check current schema version
        let current_version: i32 = conn
            .query_row(
                "SELECT version FROM schema_version ORDER BY version DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);

        if current_version < SCHEMA_VERSION {
            info!(
                "Migrating database schema from version {} to {}",
                current_version, SCHEMA_VERSION
            );

            // Apply EMBER detection schema if needed
            if current_version < 2 {
                // Apply EMBER schema inline to avoid borrow issues
                info!("Applying EMBER detection schema migration");
                let ember_schema_sql =
                    include_str!("../../migrations/002_ember_detection_schema.sql");
                conn.execute_batch(ember_schema_sql)
                    .context("Failed to apply EMBER detection schema")?;
                info!("EMBER detection schema applied successfully");
            }

            // Insert new schema version
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
            conn.execute(
                "INSERT INTO schema_version (version, applied_at) VALUES (?1, ?2)",
                params![SCHEMA_VERSION, now],
            )
            .context("Failed to update schema version")?;

            info!("Database schema migration completed");
        }

        Ok(())
    }

    /// Apply EMBER detection schema migration
    async fn apply_ember_schema(&mut self) -> Result<()> {
        let conn = self
            .connection
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Database not initialized"))?;

        info!("Applying EMBER detection schema migration");

        // Include the EMBER migration SQL
        let ember_schema_sql = include_str!("../../migrations/002_ember_detection_schema.sql");

        // Execute the migration SQL
        conn.execute_batch(ember_schema_sql)
            .context("Failed to apply EMBER detection schema")?;

        info!("EMBER detection schema applied successfully");
        Ok(())
    }

    /// Store GitHub repository information
    pub async fn store_github_repository(
        &mut self,
        repo: &GitHubSource,
        stats: &DownloadStats,
    ) -> Result<i64> {
        let conn = self
            .connection
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Database not initialized"))?;

        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
        let last_updated = stats.duration.as_secs() as i64;

        let _repo_id = conn.execute(
            r#"
            INSERT OR REPLACE INTO github_repositories 
            (name, url, branch, local_path, last_updated, total_rules, valid_rules, invalid_rules, is_enabled, created_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
            "#,
            params![
                repo.name,
                format!("https://github.com/{}.git", repo.repository), // Use repository field
                repo.branch,
                "/tmp/yara_rules", // Default local path
                last_updated,
                stats.downloaded,
                stats.total_files_found,
                0, // invalid_rules - not tracked in new structure
                repo.is_active,
                now
            ],
        ).context("Failed to store GitHub repository")?;

        Ok(conn.last_insert_rowid())
    }

    /// Store rule metadata from validation result
    pub async fn store_rule_metadata(
        &mut self,
        result: &ValidationResult,
        source_repo: Option<&str>,
    ) -> Result<i64> {
        let conn = self
            .connection
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Database not initialized"))?;

        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
        let last_validated = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs() as i64;
        let compilation_time_ms = result.validation_time.as_millis() as u64;

        // Calculate file hash (simple approach using file size and path)
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        result.rule_path.hash(&mut hasher);
        result.rule_path.to_string_lossy().hash(&mut hasher);
        let file_hash = format!("{:x}", hasher.finish());

        let tags_json = serde_json::to_string(&result.metadata.tags).unwrap_or_else(|_| "[]".to_string());

        // Extract rule name from path or use first rule name from metadata
        let rule_name = result.rule_path.file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown_rule");

        let _metadata_id = conn
            .execute(
                r#"
            INSERT OR REPLACE INTO rule_metadata 
            (file_path, rule_name, file_hash, file_size, rule_count, is_valid, compilation_time_ms,
             author, description, version, category, tags, severity, confidence, source_repository,
             last_validated, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)
            "#,
                params![
                    result.rule_path.to_string_lossy(),
                    rule_name,
                    file_hash,
                    result.file_size,
                    result.rule_count,
                    result.is_valid,
                    compilation_time_ms,
                    result.metadata.author.as_deref().unwrap_or("Unknown"),
                    result.metadata.description.as_deref().unwrap_or("YARA rule"),
                    result.metadata.version.as_deref().unwrap_or("1.0"),
                    "general".to_string(),   // category placeholder
                    tags_json,
                    "medium".to_string(), // severity placeholder
                    result.metadata.confidence.as_deref().unwrap_or("0.8"),
                    source_repo,
                    last_validated,
                    now,
                    now
                ],
            )
            .context("Failed to store rule metadata")?;

        Ok(conn.last_insert_rowid())
    }

    /// Store performance metrics
    pub async fn store_performance_metric(
        &mut self,
        metric: &StoredPerformanceMetric,
    ) -> Result<i64> {
        let conn = self
            .connection
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Database not initialized"))?;

        let timestamp = metric.timestamp.duration_since(UNIX_EPOCH)?.as_secs() as i64;
        let file_path = metric
            .file_path
            .as_ref()
            .map(|p| p.to_string_lossy().to_string());

        let _metric_id = conn
            .execute(
                r#"
            INSERT INTO performance_metrics 
            (operation_type, file_path, rule_count, execution_time_ms, memory_usage_mb, 
             cpu_usage_percent, success, error_message, timestamp)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            "#,
                params![
                    metric.operation_type,
                    file_path,
                    metric.rule_count,
                    metric.execution_time_ms,
                    metric.memory_usage_mb,
                    metric.cpu_usage_percent,
                    metric.success,
                    metric.error_message,
                    timestamp
                ],
            )
            .context("Failed to store performance metric")?;

        Ok(conn.last_insert_rowid())
    }

    /// Store validation history
    pub async fn store_validation_history(&mut self, result: &ValidationResult) -> Result<i64> {
        let conn = self
            .connection
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Database not initialized"))?;

        let timestamp = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs() as i64;
        let validation_time_ms = result.validation_time.as_millis() as u64;
        let validation_result_json =
            serde_json::to_string(result).context("Failed to serialize validation result")?;

        let _history_id = conn.execute(
            r#"
            INSERT INTO validation_history 
            (file_path, validation_result, is_valid, error_count, warning_count, validation_time_ms, timestamp)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            "#,
            params![
                result.rule_path.to_string_lossy(),
                validation_result_json,
                result.is_valid,
                if result.is_valid { 0 } else { 1 }, // error_count
                0, // warning_count (not used in current ValidationResult)
                validation_time_ms,
                timestamp
            ],
        ).context("Failed to store validation history")?;

        Ok(conn.last_insert_rowid())
    }

    /// Get all GitHub repositories
    pub async fn get_github_repositories(&mut self) -> Result<Vec<StoredGitHubRepo>> {
        let conn = self
            .connection
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Database not initialized"))?;

        let mut stmt = conn
            .prepare(
                r#"
            SELECT id, name, url, branch, local_path, last_updated, total_rules, 
                   valid_rules, invalid_rules, is_enabled, created_at
            FROM github_repositories
            ORDER BY name
            "#,
            )
            .context("Failed to prepare repository query")?;

        let repo_iter = stmt
            .query_map([], |row| {
                Ok(StoredGitHubRepo {
                    id: Some(row.get(0)?),
                    name: row.get(1)?,
                    url: row.get(2)?,
                    branch: row.get(3)?,
                    local_path: PathBuf::from(row.get::<_, String>(4)?),
                    last_updated: UNIX_EPOCH + Duration::from_secs(row.get::<_, i64>(5)? as u64),
                    total_rules: row.get::<_, i64>(6)? as usize,
                    valid_rules: row.get::<_, i64>(7)? as usize,
                    invalid_rules: row.get::<_, i64>(8)? as usize,
                    is_enabled: row.get(9)?,
                    created_at: UNIX_EPOCH + Duration::from_secs(row.get::<_, i64>(10)? as u64),
                })
            })
            .context("Failed to query repositories")?;

        let mut repositories = Vec::new();
        for repo in repo_iter {
            repositories.push(repo.context("Failed to parse repository row")?);
        }

        Ok(repositories)
    }

    /// Get rule metadata by file path
    pub async fn get_rule_metadata<P: AsRef<Path>>(
        &mut self,
        file_path: P,
    ) -> Result<Option<StoredRuleMetadata>> {
        let conn = self
            .connection
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Database not initialized"))?;

        let file_path_str = file_path.as_ref().to_string_lossy();

        let mut stmt = conn
            .prepare(
                r#"
            SELECT id, file_path, rule_name, file_hash, file_size, rule_count, is_valid,
                   compilation_time_ms, author, description, version, category, tags,
                   severity, confidence, source_repository, last_validated, created_at, updated_at
            FROM rule_metadata
            WHERE file_path = ?1
            ORDER BY updated_at DESC
            LIMIT 1
            "#,
            )
            .context("Failed to prepare metadata query")?;

        let result = stmt.query_row([file_path_str], |row| {
            let tags_json: String = row.get(12)?;
            let tags: Vec<String> = serde_json::from_str(&tags_json).unwrap_or_default();

            Ok(StoredRuleMetadata {
                id: Some(row.get(0)?),
                file_path: PathBuf::from(row.get::<_, String>(1)?),
                rule_name: row.get(2)?,
                file_hash: row.get(3)?,
                file_size: row.get::<_, i64>(4)? as u64,
                rule_count: row.get::<_, i64>(5)? as usize,
                is_valid: row.get(6)?,
                compilation_time_ms: row.get::<_, i64>(7)? as u64,
                author: row.get(8)?,
                description: row.get(9)?,
                version: row.get(10)?,
                category: row.get(11)?,
                tags,
                severity: row.get(13)?,
                confidence: row.get(14)?,
                source_repository: row.get(15)?,
                last_validated: UNIX_EPOCH + Duration::from_secs(row.get::<_, i64>(16)? as u64),
                created_at: UNIX_EPOCH + Duration::from_secs(row.get::<_, i64>(17)? as u64),
                updated_at: UNIX_EPOCH + Duration::from_secs(row.get::<_, i64>(18)? as u64),
            })
        });

        match result {
            Ok(metadata) => Ok(Some(metadata)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Get storage statistics
    pub async fn get_storage_stats(&mut self) -> Result<StorageStats> {
        let conn = self
            .connection
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Database not initialized"))?;

        let mut stats = StorageStats::default();

        // Rule statistics
        let (total_rules, valid_rules, invalid_rules): (i64, i64, i64) = conn.query_row(
            "SELECT COUNT(*), SUM(CASE WHEN is_valid THEN 1 ELSE 0 END), SUM(CASE WHEN NOT is_valid THEN 1 ELSE 0 END) FROM rule_metadata",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        ).unwrap_or((0, 0, 0));

        stats.total_rules = total_rules as usize;
        stats.valid_rules = valid_rules as usize;
        stats.invalid_rules = invalid_rules as usize;

        // Repository statistics
        let (total_repos, enabled_repos): (i64, i64) = conn.query_row(
            "SELECT COUNT(*), SUM(CASE WHEN is_enabled THEN 1 ELSE 0 END) FROM github_repositories",
            [],
            |row| Ok((row.get(0)?, row.get(1)?))
        ).unwrap_or((0, 0));

        stats.total_repositories = total_repos as usize;
        stats.enabled_repositories = enabled_repos as usize;

        // Validation statistics
        let total_validations: i64 = conn
            .query_row("SELECT COUNT(*) FROM validation_history", [], |row| {
                row.get(0)
            })
            .unwrap_or(0);

        stats.total_validations = total_validations as usize;

        // Recent validations (last 24 hours)
        let recent_threshold =
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64 - 86400; // 24 hours ago

        let recent_validations: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM validation_history WHERE timestamp > ?1",
                [recent_threshold],
                |row| row.get(0),
            )
            .unwrap_or(0);

        stats.recent_validations = recent_validations as usize;

        // Average compilation time
        let avg_compilation_ms: Option<f64> = conn
            .query_row(
                "SELECT AVG(compilation_time_ms) FROM rule_metadata WHERE is_valid = 1",
                [],
                |row| row.get(0),
            )
            .unwrap_or(None);

        if let Some(avg_ms) = avg_compilation_ms {
            stats.average_compilation_time = Duration::from_millis(avg_ms as u64);
        }

        // Database size (approximate)
        if let Ok(metadata) = std::fs::metadata(&self.db_path) {
            stats.database_size_mb = metadata.len() as f64 / 1024.0 / 1024.0;
        }

        // Last update time
        let last_update: Option<i64> = conn
            .query_row("SELECT MAX(updated_at) FROM rule_metadata", [], |row| {
                row.get(0)
            })
            .unwrap_or(None);

        if let Some(timestamp) = last_update {
            stats.last_update = Some(UNIX_EPOCH + Duration::from_secs(timestamp as u64));
        }

        Ok(stats)
    }

    /// Clean old validation history (keep last 1000 entries per file)
    pub async fn cleanup_validation_history(&mut self) -> Result<usize> {
        let conn = self
            .connection
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Database not initialized"))?;

        let deleted_count = conn
            .execute(
                r#"
            DELETE FROM validation_history 
            WHERE id NOT IN (
                SELECT id FROM validation_history 
                ORDER BY timestamp DESC 
                LIMIT 1000
            )
            "#,
                [],
            )
            .context("Failed to cleanup validation history")?;

        info!(
            "Cleaned up {} old validation history entries",
            deleted_count
        );
        Ok(deleted_count)
    }

    /// Close database connection
    pub async fn close(&mut self) -> Result<()> {
        if let Some(conn) = self.connection.take() {
            task::spawn_blocking(move || {
                drop(conn);
            })
            .await?;
            info!("Database connection closed");
        }
        Ok(())
    }
}

impl Drop for YaraStorage {
    fn drop(&mut self) {
        if let Some(conn) = self.connection.take() {
            // Use blocking drop since we can't use async in Drop
            std::thread::spawn(move || {
                drop(conn);
            });
            info!("YaraStorage database connection closed during drop");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_storage_initialization() {
        let temp_file = NamedTempFile::new().unwrap();
        let mut storage = YaraStorage::new(temp_file.path());

        storage.initialize().await.unwrap();

        // Verify tables were created
        let conn = storage.connection.as_ref().unwrap();
        let table_count: i32 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table'",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert!(table_count >= 5); // At least our 5 main tables
    }

    #[tokio::test]
    async fn test_storage_stats() {
        let temp_file = NamedTempFile::new().unwrap();
        let mut storage = YaraStorage::new(temp_file.path());
        storage.initialize().await.unwrap();

        let stats = storage.get_storage_stats().await.unwrap();
        assert_eq!(stats.total_rules, 0);
        assert_eq!(stats.total_repositories, 0);
    }
}
