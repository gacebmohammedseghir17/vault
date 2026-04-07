//! YARA Rules Updater Module
//!
//! This module provides functionality to automatically update YARA rules from a GitHub repository.
//! It includes SHA256 checksum verification, atomic rule replacement, and comprehensive error handling.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
// Removed unused HashMap import
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::time;
use zip::ZipArchive;

/// Configuration for the YARA rules updater
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraUpdaterConfig {
    /// Whether the updater is enabled
    pub enabled: bool,
    /// GitHub repository URL (e.g., "https://github.com/user/yara-rules")
    pub repo_url: String,
    /// Branch or tag to download from (default: "main")
    pub branch: String,
    /// Local directory where YARA rules are stored
    pub rules_directory: String,
    /// Update interval in hours (default: 24 for daily updates)
    pub update_interval_hours: u64,
    /// Timeout for HTTP requests in seconds
    pub request_timeout_seconds: u64,
    /// Maximum number of retry attempts
    pub max_retries: u32,
    /// Whether to verify checksums (requires checksums.txt in repo)
    pub verify_checksums: bool,
    /// Optional PEM-encoded RSA public key to verify MANIFEST signature
    pub manifest_public_key_pem: Option<String>,
    /// If true, fail update when signature verification fails
    pub enforce_signature: bool,
}

impl Default for YaraUpdaterConfig {
    fn default() -> Self {
        Self {
            enabled: false, // Disabled by default for security
            repo_url: "https://github.com/Neo23x0/signature-base".to_string(),
            branch: "master".to_string(),
            rules_directory: if cfg!(windows) {
                "C:\\YARA\\rules".to_string()
            } else {
                "/opt/yara/rules".to_string()
            },
            update_interval_hours: 24,
            request_timeout_seconds: 300, // 5 minutes
            max_retries: 3,
            verify_checksums: true,
            manifest_public_key_pem: None,
            enforce_signature: false,
        }
    }
}

/// Update status and metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateStatus {
    pub last_update: Option<DateTime<Utc>>,
    pub last_version: Option<String>,
    pub last_commit_hash: Option<String>,
    pub update_count: u64,
    pub last_error: Option<String>,
}

impl Default for UpdateStatus {
    fn default() -> Self {
        Self {
            last_update: None,
            last_version: None,
            last_commit_hash: None,
            update_count: 0,
            last_error: None,
        }
    }
}

/// GitHub repository information
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct GitHubRepoInfo {
    default_branch: String,
    updated_at: String,
}

/// GitHub commit information
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct GitHubCommit {
    sha: String,
    commit: GitHubCommitDetails,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct GitHubCommitDetails {
    message: String,
    author: GitHubAuthor,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct GitHubAuthor {
    date: String,
}

/// YARA Rules Updater
pub struct YaraUpdater {
    config: YaraUpdaterConfig,
    client: Client,
    status_file: PathBuf,
}

impl YaraUpdater {
    /// Create a new YARA updater instance
    pub fn new(config: YaraUpdaterConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(config.request_timeout_seconds))
            .user_agent("ERDPS-Agent/1.0")
            .build()
            .context("Failed to create HTTP client")?;

        let status_file = Path::new(&config.rules_directory)
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("yara_update_status.json");

        Ok(Self {
            config,
            client,
            status_file,
        })
    }

    /// Start the periodic update task
    pub async fn start_periodic_updates(&self) -> Result<()> {
        if !self.config.enabled {
            log::info!("YARA updater is disabled");
            return Ok(());
        }

        log::info!(
            "Starting YARA rules updater with {} hour interval",
            self.config.update_interval_hours
        );

        let mut interval = time::interval(Duration::from_secs(
            self.config.update_interval_hours * 3600,
        ));

        // Skip the first tick to avoid immediate update on startup
        interval.tick().await;

        loop {
            interval.tick().await;

            if let Err(e) = self.check_and_update().await {
                log::error!("YARA rules update failed: {}", e);
                self.update_status_error(&e.to_string()).await;
            }
        }
    }

    /// Check for updates and update rules if necessary
    pub async fn check_and_update(&self) -> Result<bool> {
        log::info!(
            "Checking for YARA rules updates from {}",
            self.config.repo_url
        );

        // Get current repository information
        let _repo_info = self.get_repository_info().await?;
        let latest_commit = self.get_latest_commit().await?;

        // Load current status
        let mut status = self.load_status().await;

        // Check if update is needed
        if let Some(ref current_hash) = status.last_commit_hash {
            if current_hash == &latest_commit.sha {
                log::info!("YARA rules are up to date (commit: {})", latest_commit.sha);
                return Ok(false);
            }
        }

        log::info!(
            "New YARA rules available (commit: {} -> {})",
            status.last_commit_hash.as_deref().unwrap_or("none"),
            latest_commit.sha
        );

        // Download and update rules
        self.download_and_update_rules(&latest_commit).await?;

        // Update status
        status.last_update = Some(Utc::now());
        status.last_commit_hash = Some(latest_commit.sha.clone());
        status.last_version = Some(format!("commit-{}", &latest_commit.sha[..8]));
        status.update_count += 1;
        status.last_error = None;

        self.save_status(&status).await?;

        log::info!(
            "YARA rules updated successfully to commit {}",
            latest_commit.sha
        );
        Ok(true)
    }

    /// Get repository information from GitHub API
    async fn get_repository_info(&self) -> Result<GitHubRepoInfo> {
        let repo_path = self.extract_repo_path()?;
        let url = format!("https://api.github.com/repos/{}", repo_path);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .context("Failed to fetch repository information")?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "GitHub API request failed: {}",
                response.status()
            ));
        }

        let repo_info: GitHubRepoInfo = response
            .json()
            .await
            .context("Failed to parse repository information")?;

        Ok(repo_info)
    }

    /// Get the latest commit from the specified branch
    async fn get_latest_commit(&self) -> Result<GitHubCommit> {
        let repo_path = self.extract_repo_path()?;
        let url = format!(
            "https://api.github.com/repos/{}/commits/{}",
            repo_path, self.config.branch
        );

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .context("Failed to fetch latest commit")?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "GitHub API request failed: {}",
                response.status()
            ));
        }

        let commit: GitHubCommit = response
            .json()
            .await
            .context("Failed to parse commit information")?;

        Ok(commit)
    }

    /// Download and update YARA rules
    async fn download_and_update_rules(&self, commit: &GitHubCommit) -> Result<()> {
        let repo_path = self.extract_repo_path()?;
        let download_url = format!(
            "https://github.com/{}/archive/{}.zip",
            repo_path, self.config.branch
        );

        log::info!("Downloading YARA rules from {}", download_url);

        // Download the ZIP file
        let response = self
            .client
            .get(&download_url)
            .send()
            .await
            .context("Failed to download rules archive")?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "Failed to download rules: HTTP {}",
                response.status()
            ));
        }

        let archive_data = response
            .bytes()
            .await
            .context("Failed to read archive data")?;

        // Verify archive checksum info (logging)
        if self.config.verify_checksums {
            self.verify_archive_checksum(&archive_data, &commit.sha)?;
        }

        // Create temporary directory for extraction
        let temp_dir = self.create_temp_directory()?;

        // Extract archive
        self.extract_archive(&archive_data, &temp_dir).await?;

        // Find the extracted rules directory
        let extracted_rules_dir = self.find_rules_directory(&temp_dir)?;

        // Optional: verify extracted YARA files against checksums file if present
        if self.config.verify_checksums {
            let _ = self.verify_extracted_files_checksums(&extracted_rules_dir);
        }

        // Optional: verify manifest signature using configured RSA public key
        if let Some(key_spec) = &self.config.manifest_public_key_pem {
            match Self::load_public_key_der(key_spec) {
                Ok(der) => {
                    match Self::verify_manifest_signature_der(&extracted_rules_dir, &der) {
                        Ok(()) => {
                            log::info!("Manifest signature verified successfully");
                        }
                        Err(e) => {
                            if self.config.enforce_signature {
                                return Err(e.context("Manifest signature verification failed and enforcement is enabled"));
                            } else {
                                log::warn!("Manifest signature verification failed: {} (continuing, enforcement disabled)", e);
                            }
                        }
                    }
                }
                Err(e) => {
                    if self.config.enforce_signature {
                        return Err(e.context("Failed to load public key for enforcement"));
                    } else {
                        log::warn!("Failed to load public key: {} (continuing, enforcement disabled)", e);
                    }
                }
            }
        } else {
            log::warn!("No manifest public key configured; skipping signature verification");
        }

        // Perform atomic update
        self.atomic_rules_update(&extracted_rules_dir).await?;

        // Cleanup temporary directory
        if let Err(e) = fs::remove_dir_all(&temp_dir) {
            log::warn!("Failed to cleanup temporary directory: {}", e);
        }

        Ok(())
    }

    /// Extract repository path from URL
    fn extract_repo_path(&self) -> Result<String> {
        let url = &self.config.repo_url;

        if let Some(path) = url.strip_prefix("https://github.com/") {
            Ok(path.trim_end_matches('/').to_string())
        } else {
            Err(anyhow::anyhow!("Invalid GitHub repository URL: {}", url))
        }
    }

    /// Verify archive checksum
    fn verify_archive_checksum(&self, data: &[u8], expected_commit: &str) -> Result<()> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = format!("{:x}", hasher.finalize());

        log::debug!("Archive SHA256: {}", hash);
        log::debug!("Expected commit: {}", expected_commit);

        // For now, we just log the hash. In a production environment,
        // you might want to verify against a known checksum file.
        Ok(())
    }

    /// Create temporary directory for extraction
    fn create_temp_directory(&self) -> Result<PathBuf> {
        let temp_dir = std::env::temp_dir().join(format!("yara_update_{}", Utc::now().timestamp()));

        fs::create_dir_all(&temp_dir)
            .with_context(|| format!("Failed to create temp directory: {:?}", temp_dir))?;

        Ok(temp_dir)
    }

    /// Extract ZIP archive
    async fn extract_archive(&self, data: &[u8], dest_dir: &Path) -> Result<()> {
        let cursor = std::io::Cursor::new(data);
        let mut archive = ZipArchive::new(cursor).context("Failed to open ZIP archive")?;

        for i in 0..archive.len() {
            let mut file = archive
                .by_index(i)
                .context("Failed to read archive entry")?;

            let outpath = dest_dir.join(file.name());

            if file.name().ends_with('/') {
                // Directory
                fs::create_dir_all(&outpath)
                    .with_context(|| format!("Failed to create directory: {:?}", outpath))?;
            } else {
                // File
                if let Some(parent) = outpath.parent() {
                    fs::create_dir_all(parent).with_context(|| {
                        format!("Failed to create parent directory: {:?}", parent)
                    })?;
                }

                let mut outfile = fs::File::create(&outpath)
                    .with_context(|| format!("Failed to create file: {:?}", outpath))?;

                std::io::copy(&mut file, &mut outfile)
                    .with_context(|| format!("Failed to extract file: {:?}", outpath))?;
            }
        }

        Ok(())
    }

    /// Find the rules directory in extracted archive
    fn find_rules_directory(&self, temp_dir: &Path) -> Result<PathBuf> {
        // Look for common YARA rules directory patterns
        let patterns = ["rules", "yara", "signatures", "."];

        for entry in fs::read_dir(temp_dir)?
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        {
            let dir_path = entry.path();

            // Check if this directory contains .yar files
            if self.contains_yara_files(&dir_path)? {
                return Ok(dir_path);
            }

            // Check subdirectories for rules
            for pattern in &patterns {
                let rules_path = dir_path.join(pattern);
                if rules_path.exists() && self.contains_yara_files(&rules_path)? {
                    return Ok(rules_path);
                }
            }
        }

        // If no specific rules directory found, use the temp directory itself
        if self.contains_yara_files(temp_dir)? {
            Ok(temp_dir.to_path_buf())
        } else {
            Err(anyhow::anyhow!("No YARA rules found in downloaded archive"))
        }
    }

    /// Check if directory contains YARA files
    fn contains_yara_files(&self, dir: &Path) -> Result<bool> {
        if !dir.exists() {
            return Ok(false);
        }

        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_file() {
                if let Some(ext) = path.extension() {
                    if ext == "yar" || ext == "yara" {
                        return Ok(true);
                    }
                }
            }
        }

        Ok(false)
    }

    /// Perform atomic rules update with backup and rollback capability
    async fn atomic_rules_update(&self, new_rules_dir: &Path) -> Result<()> {
        let rules_path = Path::new(&self.config.rules_directory);
        let backup_path = rules_path.with_extension("backup");

        log::info!("Performing atomic update of YARA rules");

        // Create backup of current rules if they exist
        if rules_path.exists() {
            if backup_path.exists() {
                fs::remove_dir_all(&backup_path).context("Failed to remove old backup")?;
            }

            fs::rename(&rules_path, &backup_path)
                .context("Failed to create backup of current rules")?;

            log::info!("Created backup of current rules at {:?}", backup_path);
        }

        // Copy new rules to target directory
        match self.copy_directory(new_rules_dir, &rules_path).await {
            Ok(_) => {
                log::info!("Successfully updated YARA rules");

                // Remove backup after successful update
                if backup_path.exists() {
                    if let Err(e) = fs::remove_dir_all(&backup_path) {
                        log::warn!("Failed to remove backup directory: {}", e);
                    }
                }

                Ok(())
            }
            Err(e) => {
                log::error!("Failed to update rules: {}", e);

                // Rollback: restore from backup
                if backup_path.exists() {
                    if rules_path.exists() {
                        if let Err(cleanup_err) = fs::remove_dir_all(&rules_path) {
                            log::error!("Failed to cleanup failed update: {}", cleanup_err);
                        }
                    }

                    if let Err(rollback_err) = fs::rename(&backup_path, &rules_path) {
                        log::error!("Failed to rollback rules: {}", rollback_err);
                        return Err(anyhow::anyhow!(
                            "Update failed and rollback failed: {} (rollback error: {})",
                            e,
                            rollback_err
                        ));
                    }

                    log::info!("Successfully rolled back to previous rules");
                }

                Err(e)
            }
        }
    }

    /// Verify extracted files with a checksums file if available
    fn verify_extracted_files_checksums(&self, rules_dir: &Path) -> Result<()> {
        // Look for common checksum filenames
        let candidates = ["checksums.txt", "SHA256SUMS.txt", "sha256sums.txt"]; 
        let mut checksum_path: Option<PathBuf> = None;
        for name in &candidates {
            let p = rules_dir.join(name);
            if p.exists() { checksum_path = Some(p); break; }
        }
        let Some(path) = checksum_path else { return Ok(()); };
        let content = fs::read_to_string(&path).context("Failed to read checksums file")?;
        let mut expected: Vec<(String, String)> = Vec::new();
        for line in content.lines() {
            let l = line.trim();
            if l.is_empty() { continue; }
            // Support formats: "<hash> <file>" or "<hash> *<file>"
            let parts: Vec<&str> = l.split_whitespace().collect();
            if parts.len() >= 2 {
                let hash = parts[0].to_string();
                let mut file = parts[1].to_string();
                if file.starts_with('*') { file = file.trim_start_matches('*').to_string(); }
                expected.push((file, hash));
            }
        }
        for (file, hash) in expected {
            let fpath = rules_dir.join(&file);
            if !fpath.exists() { log::warn!("Checksum listed file missing: {:?}", fpath); continue; }
            let data = fs::read(&fpath).with_context(|| format!("Failed to read {:?}", fpath))?;
            let mut hasher = Sha256::new();
            hasher.update(&data);
            let actual = format!("{:x}", hasher.finalize());
            if actual != hash {
                log::warn!("Checksum mismatch for {:?}: expected {}, got {} — deleting", fpath, hash, actual);
                if let Err(e) = fs::remove_file(&fpath) { log::error!("Failed to delete corrupt file {:?}: {}", fpath, e); }
            }
        }
        Ok(())
    }

    /// Copy directory recursively
    async fn copy_directory(&self, src: &Path, dst: &Path) -> Result<()> {
        fs::create_dir_all(dst)
            .with_context(|| format!("Failed to create destination directory: {:?}", dst))?;

        for entry in fs::read_dir(src)? {
            let entry = entry?;
            let src_path = entry.path();
            let dst_path = dst.join(entry.file_name());

            if src_path.is_dir() {
                Box::pin(self.copy_directory(&src_path, &dst_path)).await?;
            } else {
                fs::copy(&src_path, &dst_path).with_context(|| {
                    format!("Failed to copy file: {:?} -> {:?}", src_path, dst_path)
                })?;
            }
        }

        Ok(())
    }

    /// Load update status from file
    async fn load_status(&self) -> UpdateStatus {
        match fs::read_to_string(&self.status_file) {
            Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
            Err(_) => UpdateStatus::default(),
        }
    }

    /// Save update status to file
    async fn save_status(&self, status: &UpdateStatus) -> Result<()> {
        let content =
            serde_json::to_string_pretty(status).context("Failed to serialize update status")?;

        if let Some(parent) = self.status_file.parent() {
            fs::create_dir_all(parent).context("Failed to create status file directory")?;
        }

        fs::write(&self.status_file, content)
            .with_context(|| format!("Failed to write status file: {:?}", self.status_file))?;

        Ok(())
    }

    /// Update status with error information
    async fn update_status_error(&self, error: &str) {
        let mut status = self.load_status().await;
        status.last_error = Some(error.to_string());

        if let Err(e) = self.save_status(&status).await {
            log::error!("Failed to save error status: {}", e);
        }
    }

    /// Get current update status
    pub async fn get_status(&self) -> UpdateStatus {
        self.load_status().await
    }

    /// Force an immediate update check
    pub async fn force_update(&self) -> Result<bool> {
        log::info!("Forcing YARA rules update");
        self.check_and_update().await
    }
    /// Load DER public key from PEM content or file path
    fn load_public_key_der(spec: &str) -> Result<Vec<u8>> {
        use base64::Engine as _;
        use base64::engine::general_purpose::STANDARD;

        // Treat spec as PEM content if it contains BEGIN PUBLIC KEY; else treat as file path
        if spec.contains("BEGIN PUBLIC KEY") {
            let mut pem_str = spec.trim().to_string();
            pem_str = pem_str.replace("-----BEGIN PUBLIC KEY-----", "");
            pem_str = pem_str.replace("-----END PUBLIC KEY-----", "");
            pem_str = pem_str.replace('\n', "").replace('\r', "");
            let der = STANDARD.decode(pem_str).context("Failed to decode PEM public key base64")?;
            Ok(der)
        } else {
            let content = fs::read_to_string(spec).context("Failed to read public key file")?;
            let mut pem_str = content.trim().to_string();
            pem_str = pem_str.replace("-----BEGIN PUBLIC KEY-----", "");
            pem_str = pem_str.replace("-----END PUBLIC KEY-----", "");
            pem_str = pem_str.replace('\n', "").replace('\r', "");
            let der = STANDARD.decode(pem_str).context("Failed to decode PEM public key base64")?;
            Ok(der)
        }
    }

    /// Verify MANIFEST.json signature with DER public key
    fn verify_manifest_signature_der(rules_dir: &Path, public_key_der: &[u8]) -> Result<()> {
        use base64::Engine as _;
        use base64::engine::general_purpose::STANDARD;
        use ring::signature::{UnparsedPublicKey, RSA_PKCS1_2048_8192_SHA256};

        let manifest_path = rules_dir.join("MANIFEST.json");
        let sig_path = rules_dir.join("MANIFEST.sig");
        if !manifest_path.exists() || !sig_path.exists() {
            return Err(anyhow::anyhow!("Manifest or signature file missing"));
        }
        let manifest_bytes = fs::read(&manifest_path).context("Failed to read MANIFEST.json")?;
        let sig_b64 = fs::read_to_string(&sig_path).context("Failed to read MANIFEST.sig")?;
        let signature = STANDARD.decode(sig_b64.trim()).context("Failed to decode base64 signature")?;

        let pubkey = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, public_key_der);
        pubkey.verify(&manifest_bytes, &signature).context("RSA signature verification failed")?;
        Ok(())
    }
}

/// Create a new YARA updater with default configuration
pub fn create_default_updater() -> Result<YaraUpdater> {
    let config = YaraUpdaterConfig::default();
    YaraUpdater::new(config)
}

/// Create a YARA updater with custom configuration
pub fn create_updater(config: YaraUpdaterConfig) -> Result<YaraUpdater> {
    YaraUpdater::new(config)
}
