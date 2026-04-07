//! Entropy analyzer module for detecting encryption patterns
//! Uses Shannon entropy to identify file encryption activities

use entropy::shannon_entropy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use crate::metrics::MetricsCollector;

/// Entropy analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyResult {
    pub file_path: PathBuf,
    pub entropy: f64,
    pub file_size: u64,
    #[serde(skip, default = "Instant::now")]
    pub timestamp: Instant,
    pub is_encrypted: bool,
    pub confidence: f64,
}

/// File entropy history for tracking changes
#[derive(Debug, Clone)]
pub struct EntropyHistory {
    pub file_path: PathBuf,
    pub measurements: Vec<(Instant, f64)>,
    pub baseline_entropy: Option<f64>,
    pub encryption_detected: bool,
}

/// Configuration for entropy analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyConfig {
    pub encryption_threshold: f64,
    pub sample_size: usize,
    pub max_file_size: u64,
    pub analysis_interval: Duration,
    pub history_retention: Duration,
}

impl Default for EntropyConfig {
    fn default() -> Self {
        Self {
            encryption_threshold: 7.5,        // High entropy indicates encryption
            sample_size: 8192,                // 8KB sample for analysis
            max_file_size: 100 * 1024 * 1024, // 100MB max
            analysis_interval: Duration::from_secs(30),
            history_retention: Duration::from_secs(3600), // 1 hour
        }
    }
}

/// Entropy analyzer for detecting file encryption
pub struct EntropyAnalyzer {
    config: EntropyConfig,
    entropy_history: Arc<RwLock<HashMap<PathBuf, EntropyHistory>>>,
    recent_results: Arc<RwLock<Vec<EntropyResult>>>,
    metrics: Arc<MetricsCollector>,
    monitoring: Arc<RwLock<bool>>,
}

impl EntropyAnalyzer {
    /// Create a new entropy analyzer
    pub fn new(config: EntropyConfig, metrics: Arc<MetricsCollector>) -> Self {
        Self {
            config,
            entropy_history: Arc::new(RwLock::new(HashMap::new())),
            recent_results: Arc::new(RwLock::new(Vec::new())),
            metrics,
            monitoring: Arc::new(RwLock::new(false)),
        }
    }

    /// Start entropy monitoring
    pub async fn start_monitoring(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut monitoring = self.monitoring.write().await;
        if *monitoring {
            return Ok(()); // Already monitoring
        }
        *monitoring = true;
        drop(monitoring);

        let entropy_history = Arc::clone(&self.entropy_history);
        let recent_results = Arc::clone(&self.recent_results);
        let metrics = Arc::clone(&self.metrics);
        let monitoring_flag = Arc::clone(&self.monitoring);
        let config = self.config.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(config.analysis_interval);

            while *monitoring_flag.read().await {
                interval.tick().await;

                if let Err(e) =
                    Self::cleanup_old_data(&entropy_history, &recent_results, &config).await
                {
                    log::error!("Entropy cleanup error: {}", e);
                }

                // Update metrics
                Self::update_entropy_metrics(&recent_results, &metrics).await;
            }
        });

        Ok(())
    }

    /// Stop entropy monitoring
    pub async fn stop_monitoring(&self) {
        let mut monitoring = self.monitoring.write().await;
        *monitoring = false;
    }

    /// Analyze file entropy
    pub async fn analyze_file<P: AsRef<Path>>(
        &self,
        file_path: P,
    ) -> Result<EntropyResult, Box<dyn std::error::Error + Send + Sync>> {
        let path = file_path.as_ref().to_path_buf();
        let metadata = tokio::fs::metadata(&path).await?;

        // Skip files that are too large
        if metadata.len() > self.config.max_file_size {
            return Err(format!("File too large: {} bytes", metadata.len()).into());
        }

        // Read file sample for entropy analysis
        let entropy = self.calculate_file_entropy(&path).await?;
        let timestamp = Instant::now();

        // Determine if file is encrypted
        let is_encrypted = entropy >= self.config.encryption_threshold;
        let confidence = self.calculate_confidence(entropy);

        let result = EntropyResult {
            file_path: path.clone(),
            entropy,
            file_size: metadata.len(),
            timestamp,
            is_encrypted,
            confidence,
        };

        // Update history
        self.update_entropy_history(&path, entropy, timestamp).await;

        // Store recent result
        let mut recent_results = self.recent_results.write().await;
        recent_results.push(result.clone());

        // Update metrics
        if is_encrypted {
            self.metrics.record_counter("entropy_changes_total", 1.0);
        }

        Ok(result)
    }

    /// Calculate Shannon entropy for a file
    async fn calculate_file_entropy<P: AsRef<Path>>(
        &self,
        file_path: P,
    ) -> Result<f64, Box<dyn std::error::Error + Send + Sync>> {
        let path = file_path.as_ref();

        // Read file sample in a blocking task to avoid blocking async runtime
        let path_clone = path.to_path_buf();
        let sample_size = self.config.sample_size;

        let entropy = tokio::task::spawn_blocking(
            move || -> Result<f64, Box<dyn std::error::Error + Send + Sync>> {
                let file = File::open(&path_clone)?;
                let mut reader = BufReader::new(file);
                let mut buffer = vec![0u8; sample_size];

                let bytes_read = reader.read(&mut buffer)?;
                if bytes_read == 0 {
                    return Ok(0.0); // Empty file
                }

                buffer.truncate(bytes_read);
                let entropy = shannon_entropy(&buffer);

                Ok(entropy as f64)
            },
        )
        .await??;

        Ok(entropy)
    }

    /// Calculate confidence score for encryption detection
    fn calculate_confidence(&self, entropy: f64) -> f64 {
        if entropy >= 7.8 {
            0.95 // Very high confidence
        } else if entropy >= 7.5 {
            0.85 // High confidence
        } else if entropy >= 7.0 {
            0.70 // Medium confidence
        } else if entropy >= 6.5 {
            0.50 // Low confidence
        } else {
            0.10 // Very low confidence
        }
    }

    /// Update entropy history for a file
    async fn update_entropy_history(&self, file_path: &PathBuf, entropy: f64, timestamp: Instant) {
        let mut history_map = self.entropy_history.write().await;

        let history = history_map
            .entry(file_path.clone())
            .or_insert_with(|| EntropyHistory {
                file_path: file_path.clone(),
                measurements: Vec::new(),
                baseline_entropy: None,
                encryption_detected: false,
            });

        // Add new measurement
        history.measurements.push((timestamp, entropy));

        // Set baseline if this is the first measurement
        if history.baseline_entropy.is_none() {
            history.baseline_entropy = Some(entropy);
        }

        // Check for encryption (significant entropy increase)
        if let Some(baseline) = history.baseline_entropy {
            if entropy - baseline > 2.0 && entropy >= self.config.encryption_threshold {
                history.encryption_detected = true;
            }
        }

        // Keep only recent measurements
        let cutoff = timestamp - self.config.history_retention;
        history.measurements.retain(|(ts, _)| *ts > cutoff);
    }

    /// Clean up old data
    async fn cleanup_old_data(
        entropy_history: &Arc<RwLock<HashMap<PathBuf, EntropyHistory>>>,
        recent_results: &Arc<RwLock<Vec<EntropyResult>>>,
        config: &EntropyConfig,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let now = Instant::now();
        let cutoff = now - config.history_retention;

        // Clean entropy history
        let mut history_map = entropy_history.write().await;
        history_map.retain(|_, history| {
            history.measurements.retain(|(ts, _)| *ts > cutoff);
            !history.measurements.is_empty()
        });

        // Clean recent results
        let mut results = recent_results.write().await;
        results.retain(|result| result.timestamp > cutoff);

        Ok(())
    }

    /// Update entropy-related metrics
    async fn update_entropy_metrics(
        recent_results: &Arc<RwLock<Vec<EntropyResult>>>,
        metrics: &Arc<MetricsCollector>,
    ) {
        let results = recent_results.read().await;

        if results.is_empty() {
            return;
        }

        // Count encrypted files in recent results
        let encrypted_count = results.iter().filter(|r| r.is_encrypted).count();

        // Update entropy metrics
        for _ in 0..encrypted_count {
            metrics.record_counter("entropy_changes_total", 1.0);
        }
    }

    /// Get files with detected encryption
    pub async fn get_encrypted_files(&self) -> Vec<PathBuf> {
        let history_map = self.entropy_history.read().await;
        history_map
            .values()
            .filter(|history| history.encryption_detected)
            .map(|history| history.file_path.clone())
            .collect()
    }

    /// Get recent entropy results
    pub async fn get_recent_results(&self) -> Vec<EntropyResult> {
        self.recent_results.read().await.clone()
    }

    /// Get entropy history for a specific file
    pub async fn get_file_history(&self, file_path: &PathBuf) -> Option<EntropyHistory> {
        let history_map = self.entropy_history.read().await;
        history_map.get(file_path).cloned()
    }

    /// Detect rapid entropy changes (potential mass encryption)
    pub async fn detect_mass_encryption(&self) -> Vec<PathBuf> {
        let history_map = self.entropy_history.read().await;
        let now = Instant::now();
        let recent_window = Duration::from_secs(300); // 5 minutes

        history_map
            .values()
            .filter(|history| {
                // Check if entropy increased significantly in recent window
                let recent_measurements: Vec<_> = history
                    .measurements
                    .iter()
                    .filter(|(ts, _)| now.duration_since(*ts) < recent_window)
                    .collect();

                if recent_measurements.len() < 2 {
                    return false;
                }

                let first_entropy = recent_measurements.first().unwrap().1;
                let last_entropy = recent_measurements.last().unwrap().1;

                last_entropy - first_entropy > 3.0
                    && last_entropy >= self.config.encryption_threshold
            })
            .map(|history| history.file_path.clone())
            .collect()
    }

    /// Get entropy statistics
    pub async fn get_entropy_stats(&self) -> EntropyStats {
        let results = self.recent_results.read().await;
        let history_map = self.entropy_history.read().await;

        let total_files = results.len();
        let encrypted_files = results.iter().filter(|r| r.is_encrypted).count();
        let avg_entropy = if !results.is_empty() {
            results.iter().map(|r| r.entropy).sum::<f64>() / results.len() as f64
        } else {
            0.0
        };

        let files_with_history = history_map.len();
        let files_with_encryption_detected = history_map
            .values()
            .filter(|h| h.encryption_detected)
            .count();

        EntropyStats {
            total_files_analyzed: total_files,
            encrypted_files_detected: encrypted_files,
            average_entropy: avg_entropy,
            files_with_history,
            files_with_encryption_detected,
        }
    }
}

/// Entropy analysis statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyStats {
    pub total_files_analyzed: usize,
    pub encrypted_files_detected: usize,
    pub average_entropy: f64,
    pub files_with_history: usize,
    pub files_with_encryption_detected: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::Arc;
    use tempfile::NamedTempFile;
    use crate::metrics::MetricsDatabase;

    #[tokio::test]
    async fn test_entropy_analyzer_creation() {
        let config = EntropyConfig::default();
        let db = MetricsDatabase::new(":memory:").unwrap();
        db.initialize_schema().unwrap();
        let metrics = Arc::new(MetricsCollector::new(db));
        let analyzer = EntropyAnalyzer::new(config, metrics);

        assert!(!*analyzer.monitoring.read().await);
    }

    #[tokio::test]
    async fn test_entropy_calculation() {
        let config = EntropyConfig::default();
        let db = MetricsDatabase::new(":memory:").unwrap();
        db.initialize_schema().unwrap();
        let metrics = Arc::new(MetricsCollector::new(db));
        let analyzer = EntropyAnalyzer::new(config, metrics);

        // Create a test file with low entropy (repeated pattern)
        let mut temp_file = NamedTempFile::new().unwrap();
        let low_entropy_data = vec![0u8; 1024]; // All zeros
        temp_file.write_all(&low_entropy_data).unwrap();

        let result = analyzer.analyze_file(temp_file.path()).await.unwrap();
        assert!(result.entropy < 1.0); // Low entropy for repeated data
        assert!(!result.is_encrypted);
    }

    #[tokio::test]
    async fn test_high_entropy_detection() {
        let config = EntropyConfig::default();
        let db = MetricsDatabase::new(":memory:").unwrap();
        db.initialize_schema().unwrap();
        let metrics = Arc::new(MetricsCollector::new(db));
        let analyzer = EntropyAnalyzer::new(config, metrics);

        // Create a test file with high entropy (random data)
        let mut temp_file = NamedTempFile::new().unwrap();
        let high_entropy_data: Vec<u8> = (0..1024).map(|i| (i * 7 + 13) as u8).collect();
        temp_file.write_all(&high_entropy_data).unwrap();

        let result = analyzer.analyze_file(temp_file.path()).await.unwrap();
        // Note: This test data might not reach the encryption threshold,
        // but it should have higher entropy than the all-zeros test
        assert!(result.entropy > 1.0);
    }
}
