//! Unit tests for YARA Rule Optimizer
//!
//! Tests the rule optimization engine including duplicate detection,
//! performance scoring, and database integration.

use anyhow::Result;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;
// Import the modules we need to test
use erdps_agent::yara::rule_optimizer::RuleOptimizer;
use erdps_agent::yara::storage::YaraStorage;

/// Test data: Two identical YARA rules
const DUPLICATE_RULE_1: &str = r#"rule TestDuplicate {
    meta:
        author = "Test Author"
        description = "Test duplicate rule"
    strings:
        $test = "malware_signature"
    condition:
        $test
}
"#;

const DUPLICATE_RULE_2: &str = r#"rule TestDuplicate {
    meta:
        author = "Test Author"
        description = "Test duplicate rule"
    strings:
        $test = "malware_signature"
    condition:
        $test
}
"#;

/// Test data: Unique YARA rule
const UNIQUE_RULE: &str = r#"rule TestUnique {
    meta:
        author = "Test Author"
        description = "Test unique rule"
    strings:
        $unique = "unique_signature"
    condition:
        $unique
}
"#;

/// Setup test environment with temporary directory and test rules
fn setup_test_env() -> Result<(TempDir, PathBuf, PathBuf)> {
    let temp_dir = TempDir::new()?;
    let rules_dir = temp_dir.path().join("rules");
    let db_path = temp_dir.path().join("test.db");

    // Create rules directory
    fs::create_dir_all(&rules_dir)?;

    // Create test rule files
    fs::write(rules_dir.join("duplicate1.yar"), DUPLICATE_RULE_1)?;
    fs::write(rules_dir.join("duplicate2.yar"), DUPLICATE_RULE_2)?;
    fs::write(rules_dir.join("unique.yar"), UNIQUE_RULE)?;

    Ok((temp_dir, rules_dir, db_path))
}

/// Initialize test database with rules table
async fn init_test_database(db_path: &PathBuf) -> Result<()> {
    let mut storage = YaraStorage::new(db_path);
    storage.initialize().await?;

    // Create the rules table that the optimizer expects
    let conn = rusqlite::Connection::open(db_path)?;
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
    )?;

    // Insert test data
    conn.execute(
        "INSERT INTO rules (id, file_path, content, is_active) VALUES (?, ?, ?, ?)",
        rusqlite::params!["rule1", "duplicate1.yar", DUPLICATE_RULE_1, true],
    )?;
    conn.execute(
        "INSERT INTO rules (id, file_path, content, is_active) VALUES (?, ?, ?, ?)",
        rusqlite::params!["rule2", "duplicate2.yar", DUPLICATE_RULE_2, true],
    )?;
    conn.execute(
        "INSERT INTO rules (id, file_path, content, is_active) VALUES (?, ?, ?, ?)",
        rusqlite::params!["rule3", "unique.yar", UNIQUE_RULE, true],
    )?;

    Ok(())
}

#[tokio::test]
async fn test_duplicate_detection() -> Result<()> {
    // Setup test environment
    let (_temp_dir, rules_dir, db_path) = setup_test_env()?;
    init_test_database(&db_path).await?;

    // Configure thread pool for determinism
    rayon::ThreadPoolBuilder::new()
        .num_threads(2)
        .build_global()
        .unwrap();

    // Create optimizer
    let optimizer = RuleOptimizer::new(rules_dir, db_path)?;

    // Run optimization in dry-run mode
    let results = optimizer.optimize_all(1000.0, true)?;

    // Verify results
    assert_eq!(results.len(), 3, "Should process all 3 rules");

    // Count duplicates and unique rules
    let duplicates: Vec<_> = results
        .iter()
        .filter(|r| r.duplicate_of.is_some())
        .collect();
    let unique_rules: Vec<_> = results
        .iter()
        .filter(|r| r.duplicate_of.is_none())
        .collect();

    assert_eq!(duplicates.len(), 1, "Should find 1 duplicate");
    assert_eq!(unique_rules.len(), 2, "Should find 2 unique rules");

    // Verify performance scores are in valid range
    for result in &results {
        assert!(
            result.performance_score >= 0.0 && result.performance_score <= 1.0,
            "Performance score should be between 0.0 and 1.0, got: {}",
            result.performance_score
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_performance_scoring() -> Result<()> {
    // Setup test environment
    let (_temp_dir, rules_dir, db_path) = setup_test_env()?;
    init_test_database(&db_path).await?;

    // Create optimizer
    let optimizer = RuleOptimizer::new(rules_dir, db_path)?;

    // Test with different thresholds
    let results_high_threshold = optimizer.optimize_all(10000.0, true)?;
    let results_low_threshold = optimizer.optimize_all(1.0, true)?;

    // With high threshold, performance scores should be higher
    let avg_score_high: f32 = results_high_threshold
        .iter()
        .map(|r| r.performance_score)
        .sum::<f32>()
        / results_high_threshold.len() as f32;

    let avg_score_low: f32 = results_low_threshold
        .iter()
        .map(|r| r.performance_score)
        .sum::<f32>()
        / results_low_threshold.len() as f32;

    assert!(
        avg_score_high >= avg_score_low,
        "Higher threshold should result in higher average performance scores"
    );

    Ok(())
}

#[tokio::test]
async fn test_dry_run_vs_live_mode() -> Result<()> {
    // Setup test environment
    let (_temp_dir, rules_dir, db_path) = setup_test_env()?;
    init_test_database(&db_path).await?;

    // Create optimizer
    let optimizer = RuleOptimizer::new(rules_dir.clone(), db_path.clone())?;

    // Run in dry-run mode first
    let dry_results = optimizer.optimize_all(1000.0, true)?;

    // Check database state before live run
    let conn = rusqlite::Connection::open(&db_path)?;
    let active_count_before: i32 = conn.query_row(
        "SELECT COUNT(*) FROM rules WHERE is_active = 1",
        [],
        |row| row.get(0),
    )?;

    // Run in live mode
    let live_results = optimizer.optimize_all(1000.0, false)?;

    // Check database state after live run
    let active_count_after: i32 = conn.query_row(
        "SELECT COUNT(*) FROM rules WHERE is_active = 1",
        [],
        |row| row.get(0),
    )?;

    // Verify results are the same
    assert_eq!(
        dry_results.len(),
        live_results.len(),
        "Results should be the same length"
    );

    // In live mode, duplicates should be deactivated
    let duplicate_count = live_results
        .iter()
        .filter(|r| r.duplicate_of.is_some())
        .count();
    if duplicate_count > 0 {
        assert!(
            active_count_after < active_count_before,
            "Live mode should deactivate duplicate rules"
        );
    }

    // Verify performance scores are updated
    let scores_updated: i32 = conn.query_row(
        "SELECT COUNT(*) FROM rules WHERE performance_score IS NOT NULL",
        [],
        |row| row.get(0),
    )?;

    assert_eq!(
        scores_updated, 3,
        "All rules should have performance scores updated"
    );

    Ok(())
}

#[tokio::test]
async fn test_sha256_calculation() -> Result<()> {
    // Setup test environment
    let (_temp_dir, rules_dir, db_path) = setup_test_env()?;
    init_test_database(&db_path).await?;

    // Create optimizer
    let optimizer = RuleOptimizer::new(rules_dir, db_path)?;

    // Run optimization
    let results = optimizer.optimize_all(1000.0, true)?;

    // Find the duplicate rules
    let duplicates: Vec<_> = results
        .iter()
        .filter(|r| r.duplicate_of.is_some())
        .collect();
    let unique_rules: Vec<_> = results
        .iter()
        .filter(|r| r.duplicate_of.is_none())
        .collect();

    // Verify that duplicate detection worked correctly
    assert_eq!(duplicates.len(), 1, "Should detect exactly 1 duplicate");
    assert_eq!(unique_rules.len(), 2, "Should have 2 unique rules");

    // The duplicate should reference one of the unique rules
    let duplicate = duplicates[0];
    let referenced_id = duplicate.duplicate_of.as_ref().unwrap();

    assert!(
        unique_rules.iter().any(|r| &r.id == referenced_id),
        "Duplicate should reference a unique rule ID"
    );

    Ok(())
}

#[tokio::test]
async fn test_empty_database() -> Result<()> {
    // Setup test environment with empty database
    let temp_dir = TempDir::new()?;
    let rules_dir = temp_dir.path().join("rules");
    let db_path = temp_dir.path().join("empty.db");

    fs::create_dir_all(&rules_dir)?;

    // Initialize empty database
    let mut storage = YaraStorage::new(&db_path);
    storage.initialize().await?;

    let conn = rusqlite::Connection::open(&db_path)?;
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
    )?;

    // Create optimizer
    let optimizer = RuleOptimizer::new(rules_dir, db_path)?;

    // Run optimization on empty database
    let results = optimizer.optimize_all(1000.0, true)?;

    // Should return empty results without error
    assert_eq!(results.len(), 0, "Empty database should return no results");

    Ok(())
}

#[tokio::test]
async fn test_error_handling() -> Result<()> {
    // Test with invalid database path
    let temp_dir = TempDir::new()?;
    let rules_dir = temp_dir.path().join("rules");
    let invalid_db_path = PathBuf::from("/invalid/path/database.db");

    fs::create_dir_all(&rules_dir)?;

    let optimizer_result = RuleOptimizer::new(rules_dir, invalid_db_path);

    // Should handle database connection errors gracefully
    let result = match optimizer_result {
        Ok(optimizer) => optimizer.optimize_all(1000.0, true),
        Err(e) => Err(e.into()),
    };
    assert!(
        result.is_err(),
        "Should return error for invalid database path"
    );

    Ok(())
}
