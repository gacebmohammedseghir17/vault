//! GitHub YARA Rules Downloader Module
//!
//! This module provides functionality to download YARA rules from GitHub repositories
//! using Git operations. It reads source configurations from a SQLite database and
//! manages rule updates based on configured schedules.

use anyhow::{Context, Result};
use git2::{FetchOptions, RemoteCallbacks, Repository};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::task;
use tracing::{debug, info, warn};

use crate::error::AgentError;

/// GitHub source configuration from database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubSource {
    pub name: String,
    pub repository: String,
    pub branch: String,
    pub rules_path: String,
    pub is_active: bool,
    pub update_frequency_hours: u32,
    pub last_update: Option<SystemTime>,
}

/// Download statistics for a single source
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadStats {
    pub source: String,
    pub downloaded: usize,
    pub duration: Duration,
    pub total_files_found: usize,
    pub timestamp: SystemTime,
}

/// GitHub YARA rules downloader
pub struct GitHubDownloader {
    db_path: PathBuf,
    rules_base_path: PathBuf,
}

impl GitHubDownloader {
    /// Create a new GitHubDownloader instance
    pub fn new<P: AsRef<Path>>(db_path: P, rules_base_path: P) -> Self {
        Self {
            db_path: db_path.as_ref().to_path_buf(),
            rules_base_path: rules_base_path.as_ref().to_path_buf(),
        }
    }

    /// Fetch rules from all active sources
    pub async fn fetch_all(&self, force: bool) -> Result<Vec<DownloadStats>, AgentError> {
        info!("Starting GitHub rules fetch operation (force: {})", force);

        let sources = self
            .get_active_sources()
            .await
            .map_err(|e| AgentError::Database {
                message: format!("Failed to get active sources: {}", e),
                operation: Some("get_active_sources".to_string()),
            })?;

        if sources.is_empty() {
            info!("No active GitHub sources found");
            return Ok(Vec::new());
        }

        let mut all_stats = Vec::new();

        for source in sources {
            match self.fetch_source(&source, force).await {
                Ok(stats) => {
                    info!(
                        "Successfully fetched {} rules from {}",
                        stats.downloaded, source.name
                    );
                    all_stats.push(stats);
                }
                Err(e) => {
                    warn!("Failed to fetch from source {}: {}", source.name, e);
                    // Continue with other sources even if one fails
                }
            }
        }

        info!(
            "Completed GitHub rules fetch operation. Processed {} sources",
            all_stats.len()
        );
        Ok(all_stats)
    }

    /// Fetch rules from a single source
    pub async fn fetch_source(&self, source: &GitHubSource, force: bool) -> Result<DownloadStats> {
        let start_time = SystemTime::now();
        info!("Fetching rules from source: {}", source.name);

        // Check if update is needed
        if !force && !self.should_update(source) {
            debug!("Skipping {} - not due for update", source.name);
            return Ok(DownloadStats {
                source: source.name.clone(),
                downloaded: 0,
                duration: Duration::from_secs(0),
                total_files_found: 0,
                timestamp: start_time,
            });
        }

        let repo_url = format!("https://github.com/{}.git", source.repository);
        let local_repo_path = self.rules_base_path.join("repos").join(&source.name);
        let target_rules_path = self.rules_base_path.join(&source.name);

        // Ensure directories exist
        fs::create_dir_all(&local_repo_path)
            .with_context(|| format!("Failed to create repo directory: {:?}", local_repo_path))?;
        fs::create_dir_all(&target_rules_path).with_context(|| {
            format!("Failed to create rules directory: {:?}", target_rules_path)
        })?;

        // Clone or fetch repository
        let repo = self
            .clone_or_fetch_repo(&repo_url, &local_repo_path, &source.branch)
            .await
            .with_context(|| format!("Failed to clone/fetch repository: {}", repo_url))?;

        // Copy YARA rules
        let stats = self
            .copy_yara_rules(&repo, source, &local_repo_path, &target_rules_path, force)
            .await
            .with_context(|| format!("Failed to copy YARA rules from {}", source.name))?;

        // Update last_update timestamp in database
        self.update_last_update(&source.name, start_time)
            .await
            .with_context(|| format!("Failed to update last_update for {}", source.name))?;

        let duration = start_time.elapsed().unwrap_or(Duration::from_secs(0));

        Ok(DownloadStats {
            source: source.name.clone(),
            downloaded: stats.downloaded,
            duration,
            total_files_found: stats.total_files_found,
            timestamp: start_time,
        })
    }

    /// Check if a source should be updated
    fn should_update(&self, source: &GitHubSource) -> bool {
        match source.last_update {
            Some(last_update) => {
                let update_interval =
                    Duration::from_secs(source.update_frequency_hours as u64 * 3600);
                match last_update.elapsed() {
                    Ok(elapsed) => elapsed >= update_interval,
                    Err(_) => true, // If we can't determine elapsed time, update anyway
                }
            }
            None => true, // Never updated, so update now
        }
    }

    /// Clone or fetch a Git repository
    async fn clone_or_fetch_repo(
        &self,
        url: &str,
        local_path: &Path,
        branch: &str,
    ) -> Result<Repository> {
        let url = url.to_string();
        let local_path = local_path.to_path_buf();
        let branch = branch.to_string();

        task::spawn_blocking(move || {
            if local_path.exists() && local_path.join(".git").exists() {
                debug!("Repository exists, fetching updates: {:?}", local_path);

                let repo = Repository::open(&local_path).with_context(|| {
                    format!("Failed to open existing repository: {:?}", local_path)
                })?;

                // Fetch updates
                {
                    let mut remote = repo
                        .find_remote("origin")
                        .with_context(|| "Failed to find origin remote")?;

                    let mut callbacks = RemoteCallbacks::new();
                    callbacks.update_tips(|refname, a, b| {
                        debug!("Updated ref {}: {} -> {}", refname, a, b);
                        true
                    });

                    let mut fetch_options = FetchOptions::new();
                    fetch_options.remote_callbacks(callbacks);

                    remote
                        .fetch(
                            &[&format!(
                                "refs/heads/{}:refs/remotes/origin/{}",
                                branch, branch
                            )],
                            Some(&mut fetch_options),
                            None,
                        )
                        .with_context(|| "Failed to fetch from remote")?;

                    // Checkout the specified branch
                    let branch_ref = format!("refs/remotes/origin/{}", branch);
                    let oid = repo
                        .refname_to_id(&branch_ref)
                        .with_context(|| format!("Failed to find branch: {}", branch))?;

                    let _commit = repo
                        .find_commit(oid)
                        .with_context(|| "Failed to find commit")?;

                    repo.set_head_detached(oid)
                        .with_context(|| "Failed to set HEAD to detached state")?;
                }

                repo.checkout_head(Some(git2::build::CheckoutBuilder::default().force()))
                    .with_context(|| "Failed to checkout HEAD")?;

                debug!("Successfully fetched and checked out branch: {}", branch);
                Ok(repo)
            } else {
                debug!("Cloning repository: {} to {:?}", url, local_path);

                let mut builder = git2::build::RepoBuilder::new();
                builder.branch(&branch);

                let repo = builder
                    .clone(&url, &local_path)
                    .with_context(|| format!("Failed to clone repository: {}", url))?;

                debug!("Successfully cloned repository: {}", url);
                Ok(repo)
            }
        })
        .await
        .with_context(|| "Git operation task failed")?
    }

    /// Copy YARA rules from repository to target directory
    async fn copy_yara_rules(
        &self,
        _repo: &Repository,
        source: &GitHubSource,
        repo_path: &Path,
        target_path: &Path,
        force: bool,
    ) -> Result<DownloadStats> {
        let source_rules_path = repo_path.join(&source.rules_path);

        if !source_rules_path.exists() {
            warn!("Rules path does not exist: {:?}", source_rules_path);
            return Ok(DownloadStats {
                source: source.name.clone(),
                downloaded: 0,
                duration: Duration::from_secs(0),
                total_files_found: 0,
                timestamp: SystemTime::now(),
            });
        }

        let mut total_files_found = 0;
        let mut downloaded = 0;

        self.copy_yara_files_recursive(
            &source_rules_path,
            target_path,
            force,
            &mut total_files_found,
            &mut downloaded,
        )
        .with_context(|| {
            format!(
                "Failed to copy YARA files from {:?} to {:?}",
                source_rules_path, target_path
            )
        })?;

        info!(
            "Copied {} YARA files from {} (found {} total files)",
            downloaded, source.name, total_files_found
        );

        Ok(DownloadStats {
            source: source.name.clone(),
            downloaded,
            duration: Duration::from_secs(0), // Will be set by caller
            total_files_found,
            timestamp: SystemTime::now(),
        })
    }

    /// Recursively copy YARA files
    fn copy_yara_files_recursive(
        &self,
        source_dir: &Path,
        target_dir: &Path,
        force: bool,
        total_files_found: &mut usize,
        downloaded: &mut usize,
    ) -> Result<()> {
        for entry in fs::read_dir(source_dir)
            .with_context(|| format!("Failed to read directory: {:?}", source_dir))?
        {
            let entry = entry.with_context(|| "Failed to read directory entry")?;
            let path = entry.path();

            if path.is_dir() {
                let target_subdir = target_dir.join(entry.file_name());
                fs::create_dir_all(&target_subdir).with_context(|| {
                    format!("Failed to create subdirectory: {:?}", target_subdir)
                })?;

                self.copy_yara_files_recursive(
                    &path,
                    &target_subdir,
                    force,
                    total_files_found,
                    downloaded,
                )?;
            } else if path.is_file() {
                *total_files_found += 1;

                if let Some(extension) = path.extension() {
                    let ext_str = extension.to_string_lossy().to_lowercase();
                    if ext_str == "yar" || ext_str == "yara" {
                        let target_file = target_dir.join(entry.file_name());

                        // Check if file exists and force is not set
                        if target_file.exists() && !force {
                            debug!(
                                "Skipping existing file: {:?} (use --force to overwrite)",
                                target_file
                            );
                            continue;
                        }

                        fs::copy(&path, &target_file).with_context(|| {
                            format!("Failed to copy file: {:?} -> {:?}", path, target_file)
                        })?;

                        debug!("Copied YARA file: {:?}", target_file);
                        *downloaded += 1;
                    }
                }
            }
        }

        Ok(())
    }

    /// Get active sources from database
    async fn get_active_sources(&self) -> Result<Vec<GitHubSource>> {
        let db_path = self.db_path.clone();

        task::spawn_blocking(move || {
            let conn = Connection::open(&db_path)
                .with_context(|| format!("Failed to open database: {:?}", db_path))?;

            // Create github_sources table if it doesn't exist
            conn.execute(
                r#"
                CREATE TABLE IF NOT EXISTS github_sources (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    repository TEXT NOT NULL,
                    branch TEXT NOT NULL DEFAULT 'main',
                    rules_path TEXT NOT NULL DEFAULT '',
                    is_active BOOLEAN NOT NULL DEFAULT 1,
                    update_frequency_hours INTEGER NOT NULL DEFAULT 24,
                    last_update INTEGER,
                    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
                    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
                )
                "#,
                [],"
            ).context("Failed to create github_sources table")?;

            // Insert default sources if table is empty
            let count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM github_sources",
                [],
                |row| row.get(0),
            ).unwrap_or(0);

            if count == 0 {
                info!("Inserting default GitHub sources");
                let default_sources = [
                    ("signature-base", "Neo23x0/signature-base", "master", "yara"),
                    ("yara-rules", "Yara-Rules/rules", "master", "."),
                    ("malware-ioc", "eset/malware-ioc", "master", "yara"),
                ];
                
                for (name, repo, branch, rules_path) in &default_sources {
                    conn.execute(
                        r#"
            "INSERT INTO github_sources (name, repository, branch, rules_path, is_active) VALUES ('test', 'test/repo', 'main', 'rules', 0)",
                        VALUES (?1, ?2, ?3, ?4, 1, 24)
                        "#,
                        params![name, repo, branch, rules_path],
                    ).with_context(|| format!("Failed to insert default source: {}", name))?
                }
            }

            let mut stmt = conn.prepare(
                r#"
                SELECT name, repository, branch, rules_path, is_active, update_frequency_hours, last_update
                FROM github_sources
                WHERE is_active = 1
                ORDER BY name
                "#
            ).context("Failed to prepare query")?;
            
            let source_iter = stmt.query_map([], |row| {
                let last_update_timestamp: Option<i64> = row.get(6)?;
                let last_update = last_update_timestamp.map(|ts| {
                    UNIX_EPOCH + Duration::from_secs(ts as u64)
                });
                
                Ok(GitHubSource {
                    name: row.get(0)?,
                    repository: row.get(1)?,
                    branch: row.get(2)?,
                    rules_path: row.get(3)?,
                    is_active: row.get(4)?,
                    update_frequency_hours: row.get(5)?,
                    last_update,
                })
            }).context("Failed to query sources")?;

            let mut sources = Vec::new();
            for source in source_iter {
                sources.push(source.context("Failed to parse source row")?);
            }

            Ok(sources)
        }).await
        .with_context(|| "Database task failed")?
    }

    /// Update last_update timestamp for a source
    async fn update_last_update(&self, source_name: &str, timestamp: SystemTime) -> Result<()> {
        let db_path = self.db_path.clone();
        let source_name = source_name.to_string();

        task::spawn_blocking(move || {
            let conn = Connection::open(&db_path)
                .with_context(|| format!("Failed to open database: {:?}", db_path))?;

            let timestamp_secs = timestamp.duration_since(UNIX_EPOCH)?.as_secs() as i64;

            conn.execute(
                "UPDATE github_sources SET last_update = ?1, updated_at = ?1 WHERE name = ?2",
                params![timestamp_secs, source_name],
            )
            .with_context(|| format!("Failed to update last_update for source: {}", source_name))?;

            Ok(())
        })
        .await
        .with_context(|| "Database update task failed")?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_github_downloader_creation() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let rules_path = temp_dir.path().join("rules");

        let downloader = GitHubDownloader::new(&db_path, &rules_path);
        assert_eq!(downloader.db_path, db_path);
        assert_eq!(downloader.rules_base_path, rules_path);
    }

    #[tokio::test]
    async fn test_get_active_sources_empty_db() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let rules_path = temp_dir.path().join("rules");

        let downloader = GitHubDownloader::new(&db_path, &rules_path);
        let sources = downloader.get_active_sources().await.unwrap();

        // Should have default sources
        assert!(!sources.is_empty());
        assert!(sources.iter().any(|s| s.name == "signature-base"));
    }

    #[tokio::test]
    async fn test_should_update_logic() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let rules_path = temp_dir.path().join("rules");

        let downloader = GitHubDownloader::new(&db_path, &rules_path);

        // Source with no last_update should be updated
        let source_never_updated = GitHubSource {
            name: "test".to_string(),
            repository: "test/repo".to_string(),
            branch: "main".to_string(),
            rules_path: "rules".to_string(),
            is_active: true,
            update_frequency_hours: 24,
            last_update: None,
        };

        assert!(downloader.should_update(&source_never_updated));

        // Source updated recently should not be updated
        let source_recent = GitHubSource {
            name: "test".to_string(),
            repository: "test/repo".to_string(),
            branch: "main".to_string(),
            rules_path: "rules".to_string(),
            is_active: true,
            update_frequency_hours: 24,
            last_update: Some(SystemTime::now()),
        };

        assert!(!downloader.should_update(&source_recent));
    }

    #[tokio::test]
    async fn test_copy_yara_files_recursive() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let rules_path = temp_dir.path().join("rules");

        // Create test source directory with YARA files
        let source_dir = temp_dir.path().join("source");
        fs::create_dir_all(&source_dir).unwrap();

        // Create test YARA files
        let mut yara_file1 = fs::File::create(source_dir.join("test1.yar")).unwrap();
        writeln!(yara_file1, "rule test1 {{ condition: true }}").unwrap();

        let mut yara_file2 = fs::File::create(source_dir.join("test2.yara")).unwrap();
        writeln!(yara_file2, "rule test2 {{ condition: true }}").unwrap();

        // Create non-YARA file (should be ignored)
        let mut txt_file = fs::File::create(source_dir.join("readme.txt")).unwrap();
        writeln!(txt_file, "This is a readme file").unwrap();

        // Create target directory
        let target_dir = temp_dir.path().join("target");
        fs::create_dir_all(&target_dir).unwrap();

        let downloader = GitHubDownloader::new(&db_path, &rules_path);
        let mut total_files_found = 0;
        let mut downloaded = 0;

        downloader
            .copy_yara_files_recursive(
                &source_dir,
                &target_dir,
                false,
                &mut total_files_found,
                &mut downloaded,
            )
            .unwrap();

        assert_eq!(total_files_found, 3); // 2 YARA files + 1 txt file
        assert_eq!(downloaded, 2); // Only YARA files should be copied

        // Verify files were copied
        assert!(target_dir.join("test1.yar").exists());
        assert!(target_dir.join("test2.yara").exists());
        assert!(!target_dir.join("readme.txt").exists());
    }

    #[tokio::test]
    async fn test_fetch_all_no_sources() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let rules_path = temp_dir.path().join("rules");

        // Create database with no active sources
        let conn = Connection::open(&db_path).unwrap();
        conn.execute(
            r#"
            CREATE TABLE github_sources (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                repository TEXT NOT NULL,
                branch TEXT NOT NULL DEFAULT 'main',
                rules_path TEXT NOT NULL DEFAULT '',
                is_active BOOLEAN NOT NULL DEFAULT 1,
                update_frequency_hours INTEGER NOT NULL DEFAULT 24,
                last_update INTEGER,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
                updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
            )
            "#,
            [],
        )
        .unwrap();

        // Insert inactive source
        conn.execute(
            "INSERT INTO github_sources (name, repository, branch, rules_path, is_active) VALUES ('test', 'test/repo', 'main', 'rules', 0)",
            [],
        ).unwrap();

        drop(conn);

        let downloader = GitHubDownloader::new(&db_path, &rules_path);
        let stats = downloader.fetch_all(false).await.unwrap();

        // Should return empty stats since no active sources
        assert!(stats.is_empty());
    }
}
