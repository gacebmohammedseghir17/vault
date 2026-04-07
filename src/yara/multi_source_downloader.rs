//! Multi-Source YARA Rule Downloader
//!
//! This module provides comprehensive downloading capabilities for YARA rules
//! from multiple high-quality sources including Kaggle, ReversingLabs, 
//! YARA Forge, and community repositories.

use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::{Duration, SystemTime};
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tracing::{debug, error, info};
use zip::ZipArchive;



/// Configuration for a rule source
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSource {
    pub name: String,
    pub source_type: SourceType,
    pub url: String,
    pub branch: Option<String>,
    pub rules_path: Option<String>,
    pub api_key: Option<String>,
    pub is_active: bool,
    pub update_frequency_hours: u32,
    pub last_update: Option<SystemTime>,
    pub priority: u8, // 1-10, higher is better quality
    pub tags: Vec<String>,
}

/// Types of rule sources supported
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SourceType {
    GitHub,
    Kaggle,
    DirectDownload,
    YaraForge,
    Community,
}

impl std::fmt::Display for SourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SourceType::GitHub => write!(f, "GitHub"),
            SourceType::Kaggle => write!(f, "Kaggle"),
            SourceType::DirectDownload => write!(f, "DirectDownload"),
            SourceType::YaraForge => write!(f, "YaraForge"),
            SourceType::Community => write!(f, "Community"),
        }
    }
}

/// Download statistics for a source
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceDownloadStats {
    pub source_name: String,
    pub source_type: SourceType,
    pub files_downloaded: usize,
    pub rules_extracted: usize,
    pub bytes_downloaded: u64,
    pub download_time: Duration,
    pub validation_passed: usize,
    pub validation_failed: usize,
    pub timestamp: SystemTime,
    pub last_error: Option<String>,
}

/// Summary of download operation for CLI interface
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadSummary {
    pub total_files: usize,
    pub total_size: u64,
    pub source_stats: HashMap<String, SourceSummary>,
}

/// Summary for individual source
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceSummary {
    pub success: bool,
    pub files_downloaded: usize,
    pub size_downloaded: u64,
    pub error: Option<String>,
}

/// Kaggle dataset information
#[derive(Debug, Deserialize)]
struct KaggleDatasetInfo {
    pub title: String,
    pub size: u64,
    pub download_count: u64,
    pub last_updated: String,
}

/// GitHub repository information
#[derive(Debug, Deserialize)]
struct GitHubRepoInfo {
    pub name: String,
    pub full_name: String,
    pub description: Option<String>,
    pub updated_at: String,
    pub size: u64,
    pub stargazers_count: u32,
}

/// Multi-source YARA rule downloader
pub struct MultiSourceDownloader {
    client: Client,
    rules_base_path: PathBuf,
    cache_path: PathBuf,
    sources: HashMap<String, RuleSource>,
}

impl MultiSourceDownloader {
    /// Create a new multi-source downloader
    pub fn new<P: AsRef<Path>>(rules_base_path: P, cache_path: P) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(300))
            .user_agent("ERDPS-Agent/1.0")
            .build()
            .context("Failed to create HTTP client")?;

        Ok(Self {
            client,
            rules_base_path: rules_base_path.as_ref().to_path_buf(),
            cache_path: cache_path.as_ref().to_path_buf(),
            sources: HashMap::new(),
        })
    }

    /// Initialize with default high-quality sources
    pub async fn initialize_default_sources(&mut self) -> Result<()> {
        info!("Initializing default YARA rule sources");

        // Kaggle YARA Rules Dataset (700+ rules, 350 ransomware-focused)
        self.add_source(RuleSource {
            name: "kaggle-yara-rules".to_string(),
            source_type: SourceType::Kaggle,
            url: "https://www.kaggle.com/datasets/cyberprince/yara-rules-dataset".to_string(),
            branch: None,
            rules_path: None,
            api_key: None,
            is_active: true,
            update_frequency_hours: 168, // Weekly
            last_update: None,
            priority: 9,
            tags: vec!["ransomware".to_string(), "malware".to_string(), "comprehensive".to_string()],
        });

        // ReversingLabs Open Source YARA Rules
        self.add_source(RuleSource {
            name: "reversinglabs-yara".to_string(),
            source_type: SourceType::GitHub,
            url: "https://github.com/reversinglabs/reversinglabs-yara-rules".to_string(),
            branch: Some("develop".to_string()),
            rules_path: Some("yara".to_string()),
            api_key: None,
            is_active: true,
            update_frequency_hours: 24,
            last_update: None,
            priority: 10,
            tags: vec!["high-quality".to_string(), "tested".to_string(), "commercial-grade".to_string()],
        });

        // YARA-Rules Community Repository
        self.add_source(RuleSource {
            name: "yara-rules-community".to_string(),
            source_type: SourceType::GitHub,
            url: "https://github.com/Yara-Rules/rules".to_string(),
            branch: Some("master".to_string()),
            rules_path: None,
            api_key: None,
            is_active: true,
            update_frequency_hours: 12,
            last_update: None,
            priority: 8,
            tags: vec!["community".to_string(), "diverse".to_string(), "malware".to_string()],
        });

        // Neo23x0 Signature Base (High-quality APT and malware rules)
        self.add_source(RuleSource {
            name: "signature-base".to_string(),
            source_type: SourceType::GitHub,
            url: "https://github.com/Neo23x0/signature-base".to_string(),
            branch: Some("master".to_string()),
            rules_path: Some("yara".to_string()),
            api_key: None,
            is_active: true,
            update_frequency_hours: 24,
            last_update: None,
            priority: 9,
            tags: vec!["apt".to_string(), "malware".to_string(), "florian-roth".to_string()],
        });

        // YARA Forge Core Rules
        self.add_source(RuleSource {
            name: "yara-forge-core".to_string(),
            source_type: SourceType::YaraForge,
            url: "https://yarahq.github.io/core".to_string(),
            branch: None,
            rules_path: None,
            api_key: None,
            is_active: true,
            update_frequency_hours: 48,
            last_update: None,
            priority: 8,
            tags: vec!["curated".to_string(), "optimized".to_string(), "performance".to_string()],
        });

        // YARA Forge Extended Rules
        self.add_source(RuleSource {
            name: "yara-forge-extended".to_string(),
            source_type: SourceType::YaraForge,
            url: "https://yarahq.github.io/extended".to_string(),
            branch: None,
            rules_path: None,
            api_key: None,
            is_active: true,
            update_frequency_hours: 48,
            last_update: None,
            priority: 7,
            tags: vec!["extended".to_string(), "comprehensive".to_string(), "curated".to_string()],
        });

        // YARA Forge Full Rules
        self.add_source(RuleSource {
            name: "yara-forge-full".to_string(),
            source_type: SourceType::YaraForge,
            url: "https://yarahq.github.io/full".to_string(),
            branch: None,
            rules_path: None,
            api_key: None,
            is_active: false, // Disabled by default due to size
            update_frequency_hours: 72,
            last_update: None,
            priority: 6,
            tags: vec!["complete".to_string(), "large".to_string(), "comprehensive".to_string()],
        });

        // Veeam Ransomware Rules
        self.add_source(RuleSource {
            name: "veeam-ransomware".to_string(),
            source_type: SourceType::DirectDownload,
            url: "https://community.veeam.com/yara-and-script-library-67/featured-yara-rule-top-10-ransomware-threats-6267".to_string(),
            branch: None,
            rules_path: None,
            api_key: None,
            is_active: true,
            update_frequency_hours: 72,
            last_update: None,
            priority: 7,
            tags: vec!["ransomware".to_string(), "top-threats".to_string(), "veeam".to_string()],
        });

        // Awesome YARA Collection
        self.add_source(RuleSource {
            name: "awesome-yara".to_string(),
            source_type: SourceType::GitHub,
            url: "https://github.com/InQuest/awesome-yara".to_string(),
            branch: Some("master".to_string()),
            rules_path: Some("rules".to_string()),
            api_key: None,
            is_active: true,
            update_frequency_hours: 48,
            last_update: None,
            priority: 6,
            tags: vec!["collection".to_string(), "diverse".to_string(), "community".to_string()],
        });

        // YARAify Community Rules (Alternative to blocked community repo)
        self.add_source(RuleSource {
            name: "yaraify-rules".to_string(),
            source_type: SourceType::DirectDownload,
            url: "https://yaraify.abuse.ch/yarahub/".to_string(),
            branch: None,
            rules_path: None,
            api_key: None,
            is_active: true,
            update_frequency_hours: 24,
            last_update: None,
            priority: 8,
            tags: vec!["yaraify".to_string(), "abuse-ch".to_string(), "malware".to_string()],
        });

        // Malpedia YARA Rules
        self.add_source(RuleSource {
            name: "malpedia-yara".to_string(),
            source_type: SourceType::DirectDownload,
            url: "https://malpedia.caad.fkie.fraunhofer.de/api/get/yara".to_string(),
            branch: None,
            rules_path: None,
            api_key: None,
            is_active: false, // Disabled due to 404 error
            update_frequency_hours: 48,
            last_update: None,
            priority: 9,
            tags: vec!["malpedia".to_string(), "research".to_string(), "high-quality".to_string()],
        });

        // Ransomware.live Group-Specific Rules
        self.add_source(RuleSource {
            name: "ransomware-live".to_string(),
            source_type: SourceType::GitHub,
            url: "https://github.com/joshuabrown3/ransomware-live-yara".to_string(),
            branch: Some("main".to_string()),
            rules_path: None,
            api_key: None,
            is_active: false, // Disabled due to 404 error
            update_frequency_hours: 12,
            last_update: None,
            priority: 8,
            tags: vec!["ransomware".to_string(), "live-tracking".to_string(), "group-specific".to_string()],
        });

        // ESET Malware IoCs (Additional high-quality source)
        self.add_source(RuleSource {
            name: "eset-malware-iocs".to_string(),
            source_type: SourceType::GitHub,
            url: "https://github.com/eset/malware-ioc".to_string(),
            branch: Some("master".to_string()),
            rules_path: Some("yara".to_string()),
            api_key: None,
            is_active: true,
            update_frequency_hours: 48,
            last_update: None,
            priority: 9,
            tags: vec!["eset".to_string(), "commercial-grade".to_string(), "iocs".to_string()],
        });

        // Elastic Security Rules (Additional enterprise-grade source)
        self.add_source(RuleSource {
            name: "elastic-security".to_string(),
            source_type: SourceType::GitHub,
            url: "https://github.com/elastic/protections-artifacts".to_string(),
            branch: Some("main".to_string()),
            rules_path: Some("yara".to_string()),
            api_key: None,
            is_active: true,
            update_frequency_hours: 24,
            last_update: None,
            priority: 9,
            tags: vec!["elastic".to_string(), "enterprise".to_string(), "security".to_string()],
        });

        // Kaggle YARA Rules Dataset (700+ rules with 350 ransomware-focused)
        self.add_source(RuleSource {
            name: "kaggle-yara-extended".to_string(),
            source_type: SourceType::GitHub,
            url: "https://github.com/cyberprince/yara-rules-dataset".to_string(),
            branch: Some("main".to_string()),
            rules_path: None,
            api_key: None,
            is_active: true,
            update_frequency_hours: 168,
            last_update: None,
            priority: 8,
            tags: vec!["kaggle".to_string(), "ransomware".to_string(), "extended".to_string()],
        });

        // Awesome YARA curated collections
        self.add_source(RuleSource {
            name: "awesome-yara-curated".to_string(),
            source_type: SourceType::GitHub,
            url: "https://github.com/InQuest/awesome-yara".to_string(),
            branch: Some("master".to_string()),
            rules_path: Some("rules".to_string()),
            api_key: None,
            is_active: true,
            update_frequency_hours: 48,
            last_update: None,
            priority: 7,
            tags: vec!["curated".to_string(), "collection".to_string(), "community".to_string()],
        });

        // Additional high-quality ransomware-focused sources
        self.add_source(RuleSource {
            name: "ransomware-yara-rules".to_string(),
            source_type: SourceType::GitHub,
            url: "https://github.com/Yara-Rules/ransomware".to_string(),
            branch: Some("master".to_string()),
            rules_path: None,
            api_key: None,
            is_active: true,
            update_frequency_hours: 24,
            last_update: None,
            priority: 8,
            tags: vec!["ransomware".to_string(), "specialized".to_string(), "community".to_string()],
        });

        // Malware analysis YARA rules
        self.add_source(RuleSource {
            name: "malware-analysis-yara".to_string(),
            source_type: SourceType::GitHub,
            url: "https://github.com/Yara-Rules/malware".to_string(),
            branch: Some("master".to_string()),
            rules_path: None,
            api_key: None,
            is_active: true,
            update_frequency_hours: 24,
            last_update: None,
            priority: 8,
            tags: vec!["malware".to_string(), "analysis".to_string(), "community".to_string()],
        });

        // Community-driven YARA rules for APT detection
        self.add_source(RuleSource {
            name: "apt-yara-rules".to_string(),
            source_type: SourceType::GitHub,
            url: "https://github.com/advanced-threat-research/Yara-Rules".to_string(),
            branch: Some("master".to_string()),
            rules_path: None,
            api_key: None,
            is_active: true,
            update_frequency_hours: 48,
            last_update: None,
            priority: 8,
            tags: vec!["apt".to_string(), "advanced-threats".to_string(), "research".to_string()],
        });

        info!("Initialized {} default rule sources", self.sources.len());
        Ok(())
    }

    /// Add a new rule source
    pub fn add_source(&mut self, source: RuleSource) {
        info!("Adding rule source: {} ({})", source.name, source.url);
        self.sources.insert(source.name.clone(), source);
    }

    /// Remove a rule source
    pub fn remove_source(&mut self, name: &str) -> Option<RuleSource> {
        info!("Removing rule source: {}", name);
        self.sources.remove(name)
    }

    /// Get all configured sources as a vector
    pub async fn get_sources(&self) -> Result<Vec<RuleSource>> {
        Ok(self.sources.values().cloned().collect())
    }

    /// Get active sources only
    pub fn get_active_sources(&self) -> Vec<&RuleSource> {
        self.sources.values().filter(|s| s.is_active).collect()
    }

    /// Check if a source needs updating
    pub fn should_update(&self, source: &RuleSource) -> bool {
        match source.last_update {
            Some(last_update) => {
                let elapsed = SystemTime::now()
                    .duration_since(last_update)
                    .unwrap_or(Duration::from_secs(0));
                elapsed.as_secs() > (source.update_frequency_hours as u64 * 3600)
            }
            None => true, // Never updated
        }
    }

    /// Download rules from all active sources
    pub async fn download_all_sources(&mut self, force: bool) -> Result<Vec<SourceDownloadStats>> {
        info!("Starting download from all active sources (force: {})", force);
        let mut all_stats = Vec::new();

        let active_sources: Vec<RuleSource> = self.get_active_sources().into_iter().cloned().collect();
        
        for source in active_sources {
            if force || self.should_update(&source) {
                match self.download_from_source(&source, force).await {
                    Ok(stats) => {
                        info!("Successfully downloaded from {}: {} files, {} rules", 
                              stats.source_name, stats.files_downloaded, stats.rules_extracted);
                        all_stats.push(stats);
                        
                        // Update last_update timestamp
                        if let Some(mut_source) = self.sources.get_mut(&source.name) {
                            mut_source.last_update = Some(SystemTime::now());
                        }
                    }
                    Err(e) => {
                        error!("Failed to download from {}: {}", source.name, e);
                        all_stats.push(SourceDownloadStats {
                            source_name: source.name.clone(),
                            source_type: source.source_type.clone(),
                            files_downloaded: 0,
                            rules_extracted: 0,
                            bytes_downloaded: 0,
                            download_time: Duration::from_secs(0),
                            validation_passed: 0,
                            validation_failed: 0,
                            timestamp: SystemTime::now(),
                            last_error: Some(e.to_string()),
                        });
                    }
                }
            } else {
                debug!("Skipping {} - not due for update", source.name);
            }
        }

        info!("Completed download from {} sources", all_stats.len());
        Ok(all_stats)
    }

    /// Download all sources with summary result - compatible with CLI interface
    pub async fn download_all(&mut self, force: bool, _detailed: bool) -> Result<DownloadSummary> {
        let stats = self.download_all_sources(force).await?;
        
        let mut summary = DownloadSummary {
            total_files: 0,
            total_size: 0,
            source_stats: HashMap::new(),
        };
        
        for stat in stats {
            summary.total_files += stat.files_downloaded;
            summary.total_size += stat.bytes_downloaded;
            
            let source_summary = SourceSummary {
                success: stat.last_error.is_none(),
                files_downloaded: stat.files_downloaded,
                size_downloaded: stat.bytes_downloaded,
                error: stat.last_error,
            };
            
            summary.source_stats.insert(stat.source_name, source_summary);
        }
        
        Ok(summary)
    }

    /// Download rules from a specific source
    pub async fn download_from_source(&self, source: &RuleSource, _force: bool) -> Result<SourceDownloadStats> {
        let start_time = SystemTime::now();
        info!("Downloading rules from source: {} ({})", source.name, source.source_type);

        let mut stats = match source.source_type {
            SourceType::GitHub => self.download_github_source(source).await?,
            SourceType::Kaggle => self.download_kaggle_source(source).await?,
            SourceType::DirectDownload => self.download_direct_source(source).await?,
            SourceType::YaraForge => self.download_yara_forge_source(source).await?,
            SourceType::Community => self.download_community_source(source).await?,
        };

        // Update stats with timing information
        if let Ok(duration) = start_time.elapsed() {
            stats.download_time = duration;
        }
        stats.timestamp = SystemTime::now();

        info!("Completed download from {}: {} files in {:?}", 
              source.name, stats.files_downloaded, stats.download_time);

        Ok(stats)
    }

    /// Download from GitHub repository
    async fn download_github_source(&self, source: &RuleSource) -> Result<SourceDownloadStats> {
        let repo_url = &source.url;
        let branch = source.branch.as_deref().unwrap_or("main");
        
        // Extract owner/repo from URL
        let repo_path = repo_url.trim_start_matches("https://github.com/");
        let download_url = format!("https://github.com/{}/archive/{}.zip", repo_path, branch);
        
        info!("Downloading GitHub repository: {}", download_url);
        
        let response = self.client.get(&download_url).send().await
            .context("Failed to download GitHub repository")?;
        
        if !response.status().is_success() {
            return Err(anyhow::anyhow!("GitHub download failed with status: {}", response.status()));
        }
        
        let content = response.bytes().await
            .context("Failed to read GitHub repository content")?;
        
        // Save to cache
        let cache_file = self.cache_path.join(format!("{}.zip", source.name));
        fs::create_dir_all(&self.cache_path).await?;
        fs::write(&cache_file, &content).await?;
        
        // Extract and process
        self.extract_and_process_zip(&cache_file, source).await
    }

    /// Download from Kaggle dataset
    async fn download_kaggle_source(&self, source: &RuleSource) -> Result<SourceDownloadStats> {
        info!("Downloading from Kaggle source: {}", source.name);
        let start_time = SystemTime::now();
        
        // Kaggle dataset URL format: https://www.kaggle.com/datasets/{username}/{dataset-name}
        // For direct download, we need to use the API or construct the download URL
        let dataset_url = if source.url.contains("kaggle.com/datasets/") {
            // Extract dataset identifier from URL
            let parts: Vec<&str> = source.url.split('/').collect();
            if parts.len() >= 6 {
                let username = parts[4];
                let dataset = parts[5];
                format!("https://www.kaggle.com/api/v1/datasets/download/{}/{}", username, dataset)
            } else {
                return Err(anyhow::anyhow!("Invalid Kaggle dataset URL format"));
            }
        } else {
            source.url.clone()
        };

        // Create cache file path
        let cache_file = self.cache_path.join(format!("{}.zip", source.name));
        
        // Download the dataset
        let mut response = self.client
            .get(&dataset_url)
            .header("User-Agent", "ERDPS-Agent/1.0")
            .send()
            .await
            .context("Failed to send request to Kaggle")?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!("Failed to download from Kaggle: HTTP {}", response.status()));
        }

        // Write to cache file
        let mut file = fs::File::create(&cache_file).await
            .context("Failed to create cache file")?;
        
        while let Some(chunk) = response.chunk().await? {
            file.write_all(&chunk).await?;
        }
        
        file.flush().await?;
        drop(file);

        // Extract and process the downloaded file
        let mut stats = self.extract_and_process_zip(&cache_file, source).await?;
        stats.download_time = start_time.elapsed().unwrap_or(Duration::from_secs(0));
        
        info!("Downloaded from {} in {:?}: {} files, {} rules", 
              source.name, stats.download_time, stats.files_downloaded, stats.rules_extracted);

        Ok(stats)
    }

    /// Download from direct URL
    async fn download_direct_source(&self, source: &RuleSource) -> Result<SourceDownloadStats> {
        info!("Downloading from direct URL: {}", source.url);
        
        let response = self.client.get(&source.url).send().await
            .context("Failed to download from direct URL")?;
        
        if !response.status().is_success() {
            return Err(anyhow::anyhow!("Direct download failed with status: {}", response.status()));
        }
        
        let content = response.bytes().await
            .context("Failed to read direct download content")?;
        
        // Determine file type and handle accordingly
        let cache_file = if source.url.ends_with(".zip") {
            let cache_file = self.cache_path.join(format!("{}.zip", source.name));
            fs::create_dir_all(&self.cache_path).await?;
            fs::write(&cache_file, &content).await?;
            cache_file
        } else {
            // Assume it's a single YARA file
            let rules_dir = self.rules_base_path.join(&source.name);
            fs::create_dir_all(&rules_dir).await?;
            let rule_file = rules_dir.join("rules.yar");
            fs::write(&rule_file, &content).await?;
            
            return Ok(SourceDownloadStats {
                source_name: source.name.clone(),
                source_type: source.source_type.clone(),
                files_downloaded: 1,
                rules_extracted: 1, // Would need to parse to get actual count
                bytes_downloaded: content.len() as u64,
                download_time: Duration::from_secs(0),
                validation_passed: 0,
                validation_failed: 0,
                timestamp: SystemTime::now(),
                last_error: None,
            });
        };
        
        self.extract_and_process_zip(&cache_file, source).await
    }

    /// Download from YARA Forge
    async fn download_yara_forge_source(&self, source: &RuleSource) -> Result<SourceDownloadStats> {
        info!("Downloading from YARA Forge source: {}", source.name);
        let start_time = SystemTime::now();
        
        // YARA Forge provides different rule sets: Core, Extended, Full
        // Use the GitHub releases API to get the latest release assets
        let forge_url = if source.url.contains("yarahq.github.io") {
            // Map to the correct GitHub release asset URLs based on the actual asset names
            if source.url.contains("/core") {
                "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip"
            } else if source.url.contains("/extended") {
                "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-extended.zip"
            } else if source.url.contains("/full") {
                "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-full.zip"
            } else {
                // Default to core package
                "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip"
            }
        } else {
            &source.url
        };

        // Create cache file path
        let cache_file = self.cache_path.join(format!("{}.zip", source.name));
        
        // Download the rule set
        let mut response = self.client
            .get(forge_url)
            .header("User-Agent", "ERDPS-Agent/1.0")
            .send()
            .await
            .context("Failed to send request to YARA Forge")?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!("Failed to download from YARA Forge: HTTP {}", response.status()));
        }

        // Write to cache file
        let mut file = fs::File::create(&cache_file).await
            .context("Failed to create cache file")?;
        
        let mut total_bytes = 0;
        while let Some(chunk) = response.chunk().await? {
            file.write_all(&chunk).await?;
            total_bytes += chunk.len();
        }
        
        file.flush().await?;
        drop(file);

        // Extract and process the downloaded file
        let mut stats = self.extract_and_process_zip(&cache_file, source).await?;
        stats.download_time = start_time.elapsed().unwrap_or(Duration::from_secs(0));
        stats.bytes_downloaded = total_bytes as u64;
        
        info!("Downloaded from {} in {:?}: {} files, {} rules, {} bytes", 
              source.name, stats.download_time, stats.files_downloaded, 
              stats.rules_extracted, stats.bytes_downloaded);

        Ok(stats)
    }

    /// Download from community source
    async fn download_community_source(&self, source: &RuleSource) -> Result<SourceDownloadStats> {
        // Community sources are typically GitHub repositories
        self.download_github_source(source).await
    }

    /// Extract ZIP file and process YARA rules
    async fn extract_and_process_zip(&self, zip_path: &Path, source: &RuleSource) -> Result<SourceDownloadStats> {
        info!("Extracting and processing ZIP file: {:?}", zip_path);
        
        let file = std::fs::File::open(zip_path)?;
        let mut archive = ZipArchive::new(file)?;
        
        let extract_dir = self.cache_path.join(format!("{}_extracted", source.name));
        fs::create_dir_all(&extract_dir).await?;
        
        let mut files_extracted = 0;
        let mut total_size = 0u64;
        
        for i in 0..archive.len() {
            let mut file = archive.by_index(i)?;
            let file_path = extract_dir.join(file.mangled_name());
            
            if file.is_dir() {
                fs::create_dir_all(&file_path).await?;
            } else {
                if let Some(parent) = file_path.parent() {
                    fs::create_dir_all(parent).await?;
                }
                
                let mut output_file = fs::File::create(&file_path).await?;
                let mut buffer = Vec::new();
                std::io::Read::read_to_end(&mut file, &mut buffer)?;
                output_file.write_all(&buffer).await?;
                
                total_size += buffer.len() as u64;
                files_extracted += 1;
            }
        }
        
        // Process extracted YARA files
        let rules_extracted = self.process_extracted_rules(&extract_dir, source).await?;
        
        Ok(SourceDownloadStats {
            source_name: source.name.clone(),
            source_type: source.source_type.clone(),
            files_downloaded: files_extracted,
            rules_extracted,
            bytes_downloaded: total_size,
            download_time: Duration::from_secs(0),
            validation_passed: 0,
            validation_failed: 0,
            timestamp: SystemTime::now(),
            last_error: None,
        })
    }

    /// Process extracted YARA rule files
    async fn process_extracted_rules(&self, extract_dir: &Path, source: &RuleSource) -> Result<usize> {
        let rules_dir = self.rules_base_path.join(&source.name);
        fs::create_dir_all(&rules_dir).await?;
        
        let mut rules_count = 0;
        
        // Find and copy YARA files
        let mut entries = fs::read_dir(extract_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.is_dir() {
                rules_count += self.copy_yara_files_recursive(&path, &rules_dir).await?;
            } else if self.is_yara_file(&path) {
                let dest_path = rules_dir.join(path.file_name().unwrap());
                fs::copy(&path, &dest_path).await?;
                rules_count += 1;
            }
        }
        
        info!("Processed {} YARA rule files from {}", rules_count, source.name);
        Ok(rules_count)
    }

    /// Recursively copy YARA files
    fn copy_yara_files_recursive<'a>(&'a self, src_dir: &'a Path, dest_dir: &'a Path) -> Pin<Box<dyn Future<Output = Result<usize>> + Send + 'a>> {
        Box::pin(async move {
        let mut count = 0;
        let mut entries = fs::read_dir(src_dir).await?;
        
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.is_dir() {
                let sub_dest = dest_dir.join(path.file_name().unwrap());
                fs::create_dir_all(&sub_dest).await?;
                count += self.copy_yara_files_recursive(&path, &sub_dest).await?;
            } else if self.is_yara_file(&path) {
                let dest_path = dest_dir.join(path.file_name().unwrap());
                fs::copy(&path, &dest_path).await?;
                count += 1;
            }
        }
        
        Ok(count)
        })
    }

    /// Check if a file is a YARA rule file
    fn is_yara_file(&self, path: &Path) -> bool {
        if let Some(extension) = path.extension() {
            matches!(extension.to_str(), Some("yar") | Some("yara") | Some("rule"))
        } else {
            false
        }
    }

    /// Get download statistics summary
    pub fn get_download_summary(&self, stats: &[SourceDownloadStats]) -> String {
        let total_files: usize = stats.iter().map(|s| s.files_downloaded).sum();
        let total_rules: usize = stats.iter().map(|s| s.rules_extracted).sum();
        let total_size: u64 = stats.iter().map(|s| s.bytes_downloaded).sum();
        let successful_sources = stats.iter().filter(|s| s.last_error.is_none()).count();
        
        format!(
            "Download Summary: {} sources processed, {} successful, {} files downloaded, {} rules extracted, {:.2} MB total",
            stats.len(),
            successful_sources,
            total_files,
            total_rules,
            total_size as f64 / 1024.0 / 1024.0
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_multi_source_downloader_creation() {
        let temp_dir = TempDir::new().unwrap();
        let rules_path = temp_dir.path().join("rules");
        let cache_path = temp_dir.path().join("cache");

        let downloader = MultiSourceDownloader::new(&rules_path, &cache_path).unwrap();
        assert_eq!(downloader.rules_base_path, rules_path);
        assert_eq!(downloader.cache_path, cache_path);
    }

    #[tokio::test]
    async fn test_initialize_default_sources() {
        let temp_dir = TempDir::new().unwrap();
        let rules_path = temp_dir.path().join("rules");
        let cache_path = temp_dir.path().join("cache");

        let mut downloader = MultiSourceDownloader::new(&rules_path, &cache_path).unwrap();
        downloader.initialize_default_sources().await.unwrap();

        assert!(!downloader.sources.is_empty());
        assert!(downloader.sources.contains_key("kaggle-yara-rules"));
        assert!(downloader.sources.contains_key("reversinglabs-yara"));
        assert!(downloader.sources.contains_key("signature-base"));
    }

    #[test]
    fn test_should_update() {
        let temp_dir = TempDir::new().unwrap();
        let rules_path = temp_dir.path().join("rules");
        let cache_path = temp_dir.path().join("cache");

        let downloader = MultiSourceDownloader::new(&rules_path, &cache_path).unwrap();
        
        let source = RuleSource {
            name: "test".to_string(),
            source_type: SourceType::GitHub,
            url: "https://example.com".to_string(),
            branch: None,
            rules_path: None,
            api_key: None,
            is_active: true,
            update_frequency_hours: 24,
            last_update: None,
            priority: 5,
            tags: vec![],
        };

        // Should update when never updated
        assert!(downloader.should_update(&source));

        // Should not update when recently updated
        let mut recent_source = source.clone();
        recent_source.last_update = Some(SystemTime::now());
        assert!(!downloader.should_update(&recent_source));
    }
}
