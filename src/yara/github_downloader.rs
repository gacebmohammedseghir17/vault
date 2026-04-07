use anyhow::Result;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use crate::error::AgentError;

#[derive(Debug, Clone)]
pub struct GitHubSource {
    pub name: String,
    pub repository: String,
    pub branch: String,
    pub rules_path: String,
    pub is_active: bool,
    pub update_frequency_hours: u32,
    pub last_update: Option<SystemTime>,
}

#[derive(Debug, Clone)]
pub struct DownloadStats {
    pub source: String,
    pub downloaded: usize,
    pub duration: Duration,
    pub total_files_found: usize,
    pub timestamp: SystemTime,
}

#[derive(Debug)]
pub struct GitHubDownloader {
    pub db_path: PathBuf,
    pub rules_base_path: PathBuf,
}

impl GitHubDownloader {
    pub fn new(db_path: &Path, rules_base_path: &Path) -> Self {
        Self {
            db_path: db_path.to_path_buf(),
            rules_base_path: rules_base_path.to_path_buf(),
        }
    }

    pub async fn get_active_sources(&self) -> Result<Vec<GitHubSource>> {
        // Return default sources for now
        Ok(vec![GitHubSource {
            name: "signature-base".to_string(),
            repository: "Neo23x0/signature-base".to_string(),
            branch: "master".to_string(),
            rules_path: "yara".to_string(),
            is_active: true,
            update_frequency_hours: 24,
            last_update: None,
        }])
    }

    pub fn should_update(&self, _source: &GitHubSource) -> bool {
        true
    }

    pub async fn fetch_all(&self, _force: bool) -> Result<Vec<DownloadStats>, AgentError> {
        Ok(vec![])
    }

    pub async fn fetch_source(&self, source: &GitHubSource, _force: bool) -> Result<DownloadStats> {
        Ok(DownloadStats {
            source: source.name.clone(),
            downloaded: 0,
            duration: Duration::from_secs(0),
            total_files_found: 0,
            timestamp: SystemTime::now(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

        assert!(!sources.is_empty());
        assert!(sources.iter().any(|s| s.name == "signature-base"));
    }
}
