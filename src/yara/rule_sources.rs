use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::fs;
use tracing::{debug, error, info, warn};
use reqwest;
use zip::ZipArchive;
use std::io::Cursor;

/// Configuration for different YARA rule sources
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSourceConfig {
    pub name: String,
    pub url: String,
    pub source_type: SourceType,
    pub enabled: bool,
    pub update_frequency: UpdateFrequency,
    pub quality_threshold: f64,
    pub categories: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SourceType {
    KaggleDataset,
    GitHubRepository,
    DirectDownload,
    ApiEndpoint,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UpdateFrequency {
    Daily,
    Weekly,
    Monthly,
    Manual,
}

/// Manages downloading and updating YARA rules from multiple sources
pub struct RuleSourceManager {
    sources: HashMap<String, RuleSourceConfig>,
    download_path: PathBuf,
    client: reqwest::Client,
}

impl RuleSourceManager {
    pub fn new<P: AsRef<Path>>(download_path: P) -> Self {
        let client = reqwest::Client::builder()
            .user_agent("ERDPS-Agent/1.0 (https://github.com/erdps/erdps-agent)")
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");
            
        let mut manager = Self {
            sources: HashMap::new(),
            download_path: download_path.as_ref().to_path_buf(),
            client,
        };
        
        manager.initialize_default_sources();
        manager
    }

    fn initialize_default_sources(&mut self) {
        // Add Kaggle YARA Rules Dataset (700+ rules with 350 ransomware-focused)
        self.sources.insert("kaggle-yara-rules".to_string(), RuleSourceConfig {
            name: "Kaggle YARA Rules Dataset".to_string(),
            url: "https://www.kaggle.com/datasets/xwolf12/yaraify-yara-rules".to_string(),
            source_type: SourceType::KaggleDataset,
            enabled: true,
            update_frequency: UpdateFrequency::Weekly,
            quality_threshold: 0.9,
            categories: vec!["ransomware".to_string(), "malware".to_string(), "trojan".to_string()],
        });

        // Add ReversingLabs Open Source Rules
        self.sources.insert("reversinglabs-rules".to_string(), RuleSourceConfig {
            name: "ReversingLabs Open Source Rules".to_string(),
            url: "https://api.github.com/repos/reversinglabs/reversinglabs-yara-rules/zipball/develop".to_string(),
            source_type: SourceType::DirectDownload,
            enabled: true,
            update_frequency: UpdateFrequency::Weekly,
            quality_threshold: 0.95,
            categories: vec!["malware".to_string(), "ransomware".to_string(), "exploit".to_string()],
        });

        // Add YARA-Rules Community Repository
        self.sources.insert("yara-rules".to_string(), RuleSourceConfig {
            name: "YARA-Rules Community".to_string(),
            url: "https://api.github.com/repos/Yara-Rules/rules/zipball/master".to_string(),
            source_type: SourceType::DirectDownload,
            enabled: true,
            update_frequency: UpdateFrequency::Weekly,
            quality_threshold: 0.8,
            categories: vec!["malware".to_string(), "ransomware".to_string()],
        });

        // Add YARA Forge Core Rules
        self.sources.insert("yara-forge-core".to_string(), RuleSourceConfig {
            name: "YARA Forge Core Rules".to_string(),
            url: "https://yaraforge.com/api/rules/core".to_string(),
            source_type: SourceType::ApiEndpoint,
            enabled: true,
            update_frequency: UpdateFrequency::Daily,
            quality_threshold: 0.9,
            categories: vec!["malware".to_string(), "ransomware".to_string(), "apt".to_string()],
        });

        // Add YARA Forge Extended Rules
        self.sources.insert("yara-forge-extended".to_string(), RuleSourceConfig {
            name: "YARA Forge Extended Rules".to_string(),
            url: "https://yaraforge.com/api/rules/extended".to_string(),
            source_type: SourceType::ApiEndpoint,
            enabled: true,
            update_frequency: UpdateFrequency::Daily,
            quality_threshold: 0.85,
            categories: vec!["malware".to_string(), "ransomware".to_string(), "trojan".to_string(), "backdoor".to_string()],
        });

        // Add Awesome-YARA Curated Collections
        self.sources.insert("awesome-yara".to_string(), RuleSourceConfig {
            name: "Awesome-YARA Collections".to_string(),
            url: "https://api.github.com/repos/InQuest/awesome-yara/zipball/master".to_string(),
            source_type: SourceType::DirectDownload,
            enabled: true,
            update_frequency: UpdateFrequency::Monthly,
            quality_threshold: 0.8,
            categories: vec!["malware".to_string(), "ransomware".to_string(), "apt".to_string()],
        });

        // Add YARAify Public Rules
        self.sources.insert("yaraify-rules".to_string(), RuleSourceConfig {
            name: "YARAify Public Rules".to_string(),
            url: "https://yaraify.abuse.ch/yarahub/yaraify-rules.zip".to_string(),
            source_type: SourceType::DirectDownload,
            enabled: true,
            update_frequency: UpdateFrequency::Daily,
            quality_threshold: 0.9,
            categories: vec!["malware".to_string(), "ransomware".to_string()],
        });

        // Add Malpedia YARA Rules
        self.sources.insert("malpedia-rules".to_string(), RuleSourceConfig {
            name: "Malpedia YARA Rules".to_string(),
            url: "https://malpedia.caad.fkie.fraunhofer.de/api/get/yara/zip".to_string(),
            source_type: SourceType::DirectDownload,
            enabled: true,
            update_frequency: UpdateFrequency::Weekly,
            quality_threshold: 0.95,
            categories: vec!["malware".to_string(), "ransomware".to_string(), "apt".to_string()],
        });

        // Add Ransomware.live Group-Specific Rules
        self.sources.insert("ransomware-live".to_string(), RuleSourceConfig {
            name: "Ransomware.live Rules".to_string(),
            url: "https://api.github.com/repos/joshuabrown3/ransomware-live-yara/zipball/main".to_string(),
            source_type: SourceType::DirectDownload,
            enabled: true,
            update_frequency: UpdateFrequency::Daily,
            quality_threshold: 0.9,
            categories: vec!["ransomware".to_string()],
        });

        // Add Neo23x0's Signature Base (High-quality rules)
        self.sources.insert("signature-base".to_string(), RuleSourceConfig {
            name: "Neo23x0 Signature Base".to_string(),
            url: "https://api.github.com/repos/Neo23x0/signature-base/zipball/master".to_string(),
            source_type: SourceType::DirectDownload,
            enabled: true,
            update_frequency: UpdateFrequency::Weekly,
            quality_threshold: 0.95,
            categories: vec!["malware".to_string(), "ransomware".to_string(), "apt".to_string()],
        });
    }

    /// Download rules from all enabled sources
    pub async fn download_all_sources(&self) -> Result<Vec<DownloadResult>> {
        let mut results = Vec::new();
        
        for (source_id, config) in &self.sources {
            if config.enabled {
                info!("Downloading rules from source: {}", config.name);
                match self.download_source(source_id, config).await {
                    Ok(result) => {
                        info!("Successfully downloaded {} rules from {}", result.rule_count, config.name);
                        results.push(result);
                    }
                    Err(e) => {
                        error!("Failed to download from {}: {}", config.name, e);
                        results.push(DownloadResult {
                            source_id: source_id.clone(),
                            source_name: config.name.clone(),
                            success: false,
                            rule_count: 0,
                            download_path: None,
                            error_message: Some(e.to_string()),
                        });
                    }
                }
            }
        }
        
        Ok(results)
    }

    /// Download from a specific source by ID
    pub async fn download_from_source_id(&self, source_id: &str, force: bool) -> Result<DownloadResult> {
        if let Some(config) = self.sources.get(source_id) {
            if !config.enabled {
                return Ok(DownloadResult {
                    source_id: source_id.to_string(),
                    source_name: config.name.clone(),
                    success: false,
                    rule_count: 0,
                    download_path: None,
                    error_message: Some("Source is disabled".to_string()),
                });
            }
            
            // Check if we should skip download based on force flag and existing files
            let target_dir = self.download_path.join(source_id);
            if !force && target_dir.exists() {
                // Count existing rules
                let rule_count = self.count_yara_files(&target_dir).await?;
                if rule_count > 0 {
                    info!("Skipping download from {} - {} rules already exist (use --force to override)", 
                          config.name, rule_count);
                    return Ok(DownloadResult {
                        source_id: source_id.to_string(),
                        source_name: config.name.clone(),
                        success: true,
                        rule_count,
                        download_path: Some(target_dir),
                        error_message: None,
                    });
                }
            }
            
            self.download_source(source_id, config).await
        } else {
            Err(anyhow::anyhow!("Source '{}' not found", source_id))
        }
    }

    /// Count YARA files in a directory
    fn count_yara_files<'a>(&'a self, dir: &'a Path) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<usize>> + Send + 'a>> {
        Box::pin(async move {
            let mut count = 0;
            if dir.exists() {
                let mut entries = fs::read_dir(dir).await?;
                while let Some(entry) = entries.next_entry().await? {
                    let path = entry.path();
                    if path.is_file() {
                        if let Some(ext) = path.extension() {
                            if ext == "yar" || ext == "yara" {
                                count += 1;
                            }
                        }
                    } else if path.is_dir() {
                        count += self.count_yara_files(&path).await?;
                    }
                }
            }
            Ok(count)
        })
    }

    /// Download rules from a specific source
    async fn download_source(&self, source_id: &str, config: &RuleSourceConfig) -> Result<DownloadResult> {
        let source_dir = self.download_path.join(source_id);
        fs::create_dir_all(&source_dir).await
            .context("Failed to create source directory")?;

        match config.source_type {
            SourceType::GitHubRepository => {
                self.download_github_repository(source_id, config, &source_dir).await
            }
            SourceType::KaggleDataset => {
                self.download_kaggle_dataset(source_id, config, &source_dir).await
            }
            SourceType::DirectDownload => {
                self.download_direct(source_id, config, &source_dir).await
            }
            SourceType::ApiEndpoint => {
                self.download_api_endpoint(source_id, config, &source_dir).await
            }
        }
    }

    /// Download from GitHub repository
    async fn download_github_repository(&self, source_id: &str, config: &RuleSourceConfig, target_dir: &Path) -> Result<DownloadResult> {
        let archive_url = format!("{}/archive/refs/heads/main.zip", config.url);
        
        debug!("Downloading GitHub repository: {}", archive_url);
        let response = self.client.get(&archive_url).send().await
            .context("Failed to download GitHub repository")?;
        
        if !response.status().is_success() {
            return Err(anyhow::anyhow!("HTTP error: {}", response.status()));
        }

        let content = response.bytes().await
            .context("Failed to read response content")?;
        
        // Extract ZIP archive
        let cursor = Cursor::new(content);
        let mut archive = ZipArchive::new(cursor)
            .context("Failed to open ZIP archive")?;
        
        let mut rule_count = 0;
        
        for i in 0..archive.len() {
            let mut file = archive.by_index(i)
                .context("Failed to read file from archive")?;
            
            if file.name().ends_with(".yar") || file.name().ends_with(".yara") {
                let file_name = Path::new(file.name()).file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown.yara");
                
                let target_path = target_dir.join(file_name);
                
                let mut content = Vec::new();
                std::io::copy(&mut file, &mut content)
                    .context("Failed to read file content")?;
                
                fs::write(&target_path, content).await
                    .context("Failed to write rule file")?;
                
                rule_count += 1;
                debug!("Extracted rule file: {}", target_path.display());
            }
        }
        
        Ok(DownloadResult {
            source_id: source_id.to_string(),
            source_name: config.name.clone(),
            success: true,
            rule_count,
            download_path: Some(target_dir.to_path_buf()),
            error_message: None,
        })
    }

    /// Download Kaggle dataset (requires manual download for now)
    async fn download_kaggle_dataset(&self, source_id: &str, config: &RuleSourceConfig, target_dir: &Path) -> Result<DownloadResult> {
        warn!("Kaggle dataset download requires manual setup. Please download the dataset manually and place it in: {}", target_dir.display());
        
        // Check if manually downloaded files exist
        let mut rule_count = 0;
        if target_dir.exists() {
            let mut entries = fs::read_dir(target_dir).await
                .context("Failed to read target directory")?;
            
            while let Some(entry) = entries.next_entry().await? {
                let path = entry.path();
                if path.extension().map_or(false, |ext| ext == "yar" || ext == "yara") {
                    rule_count += 1;
                }
            }
        }
        
        if rule_count > 0 {
            Ok(DownloadResult {
                source_id: source_id.to_string(),
                source_name: config.name.clone(),
                success: true,
                rule_count,
                download_path: Some(target_dir.to_path_buf()),
                error_message: None,
            })
        } else {
            Ok(DownloadResult {
                source_id: source_id.to_string(),
                source_name: config.name.clone(),
                success: false,
                rule_count: 0,
                download_path: Some(target_dir.to_path_buf()),
                error_message: Some("No YARA rules found. Please download Kaggle dataset manually.".to_string()),
            })
        }
    }

    /// Download from direct URL
    async fn download_direct(&self, source_id: &str, config: &RuleSourceConfig, target_dir: &Path) -> Result<DownloadResult> {
        debug!("Downloading from direct URL: {}", config.url);
        let response = self.client.get(&config.url).send().await
            .context("Failed to download from direct URL")?;
        
        if !response.status().is_success() {
            return Err(anyhow::anyhow!("HTTP error: {}", response.status()));
        }

        let content = response.bytes().await
            .context("Failed to read response content")?;
        
        // Check if this is a ZIP file (GitHub API zipball or other ZIP downloads)
        if config.url.contains("zipball") || config.url.ends_with(".zip") || 
           (content.len() >= 4 && &content[0..4] == b"PK\x03\x04") {
            // Handle ZIP archive
            let cursor = Cursor::new(content);
            let mut archive = ZipArchive::new(cursor)
                .context("Failed to open ZIP archive")?;
            
            let mut rule_count = 0;
            
            for i in 0..archive.len() {
                let mut file = archive.by_index(i)
                    .context("Failed to read file from archive")?;
                
                if file.name().ends_with(".yar") || file.name().ends_with(".yara") {
                    let file_name = Path::new(file.name()).file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown.yara");
                    
                    let target_path = target_dir.join(file_name);
                    
                    let mut content = Vec::new();
                    std::io::copy(&mut file, &mut content)
                        .context("Failed to read file content")?;
                    
                    fs::write(&target_path, content).await
                        .context("Failed to write rule file")?;
                    
                    rule_count += 1;
                    debug!("Extracted rule file: {}", target_path.display());
                }
            }
            
            Ok(DownloadResult {
                source_id: source_id.to_string(),
                source_name: config.name.clone(),
                success: true,
                rule_count,
                download_path: Some(target_dir.to_path_buf()),
                error_message: None,
            })
        } else {
            // Handle single file download
            let content_str = String::from_utf8(content.to_vec())
                .context("Failed to convert content to string")?;
            
            let file_name = format!("{}.yara", source_id);
            let target_path = target_dir.join(file_name);
            
            fs::write(&target_path, content_str).await
                .context("Failed to write rule file")?;
            
            Ok(DownloadResult {
                source_id: source_id.to_string(),
                source_name: config.name.clone(),
                success: true,
                rule_count: 1,
                download_path: Some(target_dir.to_path_buf()),
                error_message: None,
            })
        }
    }

    /// Download from API endpoint
    async fn download_api_endpoint(&self, source_id: &str, config: &RuleSourceConfig, target_dir: &Path) -> Result<DownloadResult> {
        debug!("Downloading from API endpoint: {}", config.url);
        
        match source_id {
            "yara_forge" => self.download_yara_forge(source_id, config, target_dir).await,
            "yaraify" => self.download_yaraify(source_id, config, target_dir).await,
            _ => Err(anyhow::anyhow!("Unknown API endpoint: {}", source_id)),
        }
    }

    /// Download from YARA Forge API
    async fn download_yara_forge(&self, source_id: &str, config: &RuleSourceConfig, target_dir: &Path) -> Result<DownloadResult> {
        // YARA Forge API implementation would go here
        // For now, return a placeholder
        warn!("YARA Forge API integration not yet implemented");
        
        Ok(DownloadResult {
            source_id: source_id.to_string(),
            source_name: config.name.clone(),
            success: false,
            rule_count: 0,
            download_path: Some(target_dir.to_path_buf()),
            error_message: Some("YARA Forge API integration not yet implemented".to_string()),
        })
    }

    /// Download from YARAify API
    async fn download_yaraify(&self, source_id: &str, config: &RuleSourceConfig, target_dir: &Path) -> Result<DownloadResult> {
        // YARAify API implementation would go here
        // For now, return a placeholder
        warn!("YARAify API integration not yet implemented");
        
        Ok(DownloadResult {
            source_id: source_id.to_string(),
            source_name: config.name.clone(),
            success: false,
            rule_count: 0,
            download_path: Some(target_dir.to_path_buf()),
            error_message: Some("YARAify API integration not yet implemented".to_string()),
        })
    }

    /// Get configuration for a specific source
    pub fn get_source_config(&self, source_id: &str) -> Option<&RuleSourceConfig> {
        self.sources.get(source_id)
    }

    /// Enable or disable a source
    pub fn set_source_enabled(&mut self, source_id: &str, enabled: bool) -> Result<()> {
        if let Some(config) = self.sources.get_mut(source_id) {
            config.enabled = enabled;
            Ok(())
        } else {
            Err(anyhow::anyhow!("Source not found: {}", source_id))
        }
    }

    /// List all available sources
    pub fn list_sources(&self) -> Vec<(&String, &RuleSourceConfig)> {
        self.sources.iter().collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadResult {
    pub source_id: String,
    pub source_name: String,
    pub success: bool,
    pub rule_count: usize,
    pub download_path: Option<PathBuf>,
    pub error_message: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_rule_source_manager_creation() {
        let temp_dir = TempDir::new().unwrap();
        let manager = RuleSourceManager::new(temp_dir.path());
        
        assert!(!manager.sources.is_empty());
        assert!(manager.sources.contains_key("kaggle-yara-rules"));
        assert!(manager.sources.contains_key("reversinglabs-rules"));
    }

    #[test]
    fn test_source_configuration() {
        let temp_dir = TempDir::new().unwrap();
        let mut manager = RuleSourceManager::new(temp_dir.path());
        
        // Test enabling/disabling sources
        assert!(manager.set_source_enabled("kaggle-yara-rules", false).is_ok());
        assert!(!manager.get_source_config("kaggle-yara-rules").unwrap().enabled);
        
        // Test invalid source
        assert!(manager.set_source_enabled("invalid_source", true).is_err());
    }
}
