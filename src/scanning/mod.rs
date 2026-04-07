//! Malware Scanning Module
//!
//! This module provides a modular and extensible framework for malware detection
//! using various scanning engines. It implements a trait-based architecture that
//! allows for easy integration of different scanning technologies.

pub mod detection_event;
pub mod manager;
pub mod traits;
pub mod yara_scanner;

#[cfg(test)]
pub mod tests;

// Re-export main types for convenience
pub use detection_event::{DetectionEvent, ScanResult, Severity};
pub use manager::{ScanningManager, ScanningStats};
pub use traits::{BatchScanner, MalwareScanner, RealtimeScanner, ScanConfig, ScanError, ScanStats};
pub use yara_scanner::{YaraScanner, YaraScannerConfig};

use std::sync::Arc;
use tokio::sync::RwLock;

/// Scanner registry for managing multiple scanner instances
#[derive(Clone)]
pub struct ScannerRegistry {
    scanners: Arc<RwLock<std::collections::HashMap<String, Arc<dyn MalwareScanner>>>>,
}

impl ScannerRegistry {
    /// Create a new scanner registry
    pub fn new() -> Self {
        Self {
            scanners: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    /// Register a scanner with a given name
    pub async fn register_scanner<S>(&self, name: String, scanner: S)
    where
        S: MalwareScanner + 'static,
    {
        let mut scanners = self.scanners.write().await;
        scanners.insert(name, Arc::new(scanner));
    }

    /// Get a scanner by name
    pub async fn get_scanner(&self, name: &str) -> Option<Arc<dyn MalwareScanner>> {
        let scanners = self.scanners.read().await;
        scanners.get(name).cloned()
    }

    /// List all registered scanner names
    pub async fn list_scanners(&self) -> Vec<String> {
        let scanners = self.scanners.read().await;
        scanners.keys().cloned().collect()
    }

    /// Remove a scanner from the registry
    pub async fn unregister_scanner(&self, name: &str) -> Option<Arc<dyn MalwareScanner>> {
        let mut scanners = self.scanners.write().await;
        scanners.remove(name)
    }

    /// Scan a file with all registered scanners
    pub async fn scan_with_all<P: AsRef<std::path::Path> + Send + Clone>(
        &self,
        file_path: P,
    ) -> Result<Vec<ScanResult>, ScanError> {
        let scanners = self.scanners.read().await;
        let mut results = Vec::new();

        for scanner in scanners.values() {
            match scanner.scan_file(file_path.as_ref()).await {
                Ok(result) => results.push(result),
                Err(e) => {
                    // Log error but continue with other scanners
                    log::warn!("Scanner {} failed: {}", scanner.get_engine_name(), e);
                }
            }
        }

        Ok(results)
    }

    /// Get combined statistics from all scanners
    pub async fn get_combined_stats(&self) -> ScanStats {
        let scanners = self.scanners.read().await;
        let mut combined = ScanStats::default();

        for scanner in scanners.values() {
            let stats = scanner.get_stats();
            combined.files_scanned += stats.files_scanned;
            combined.directories_processed += stats.directories_processed;
            combined.files_skipped += stats.files_skipped;
            combined.scan_errors += stats.scan_errors;
            combined.total_scan_time_ms += stats.total_scan_time_ms;
            combined.detections_found += stats.detections_found;
        }

        // Recalculate average
        if combined.files_scanned > 0 {
            combined.avg_scan_time_ms =
                combined.total_scan_time_ms as f64 / combined.files_scanned as f64;
        }

        combined
    }
}

impl Default for ScannerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Utility functions for scanning operations
pub mod utils {
    use super::{ScanConfig, ScanError};
    use std::path::Path;
    use tokio::fs;

    /// Check if a file should be scanned based on configuration
    pub async fn should_scan_file<P: AsRef<Path>>(
        file_path: P,
        config: &ScanConfig,
    ) -> Result<bool, ScanError> {
        let path = file_path.as_ref();

        // Check if file exists
        if !path.exists() {
            return Ok(false);
        }

        // Check file extension
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if config.excluded_extensions.contains(&ext.to_lowercase()) {
                return Ok(false);
            }
        }

        // Check file size
        let metadata = fs::metadata(path).await.map_err(ScanError::Io)?;
        let size_mb = metadata.len() / (1024 * 1024);
        if size_mb > config.max_file_size_mb {
            return Ok(false);
        }

        // Check if it's a directory (shouldn't happen, but be safe)
        if metadata.is_dir() {
            return Ok(false);
        }

        Ok(true)
    }

    /// Calculate SHA256 hash of a file
    pub async fn calculate_file_hash<P: AsRef<Path>>(file_path: P) -> Result<String, ScanError> {
        use sha2::{Digest, Sha256};
        use tokio::io::AsyncReadExt;

        let mut file = fs::File::open(file_path).await.map_err(ScanError::Io)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 8192];

        loop {
            let bytes_read = file.read(&mut buffer).await.map_err(ScanError::Io)?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }

        Ok(format!("{:x}", hasher.finalize()))
    }

    /// Detect MIME type of a file
    pub async fn detect_mime_type<P: AsRef<Path>>(file_path: P) -> Result<String, ScanError> {
        use tokio::io::AsyncReadExt;

        let path_ref = file_path.as_ref();
        let mut file = fs::File::open(path_ref).await.map_err(ScanError::Io)?;
        let mut buffer = [0u8; 512]; // Read first 512 bytes for magic number detection
        let bytes_read = file.read(&mut buffer).await.map_err(ScanError::Io)?;

        // Simple MIME type detection based on magic numbers
        let mime_type = match &buffer[..bytes_read.min(4)] {
            [0x50, 0x4B, 0x03, 0x04] | [0x50, 0x4B, 0x05, 0x06] | [0x50, 0x4B, 0x07, 0x08] => {
                "application/zip"
            }
            [0x4D, 0x5A, ..] => "application/x-executable", // PE executable
            [0x7F, 0x45, 0x4C, 0x46] => "application/x-executable", // ELF executable
            [0xFF, 0xD8, 0xFF, ..] => "image/jpeg",
            [0x89, 0x50, 0x4E, 0x47] => "image/png",
            [0x47, 0x49, 0x46, 0x38] => "image/gif",
            [0x25, 0x50, 0x44, 0x46] => "application/pdf",
            _ => {
                // Try to detect based on file extension as fallback
                if let Some(path_str) = path_ref.to_str() {
                    if path_str.ends_with(".txt") {
                        "text/plain"
                    } else if path_str.ends_with(".html") || path_str.ends_with(".htm") {
                        "text/html"
                    } else if path_str.ends_with(".js") {
                        "application/javascript"
                    } else if path_str.ends_with(".json") {
                        "application/json"
                    } else {
                        "application/octet-stream"
                    }
                } else {
                    "application/octet-stream"
                }
            }
        };

        Ok(mime_type.to_string())
    }

    /// Recursively collect files from a directory
    pub async fn collect_files_recursive<P: AsRef<Path>>(
        dir_path: P,
        config: &ScanConfig,
        max_depth: Option<u32>,
    ) -> Result<Vec<std::path::PathBuf>, ScanError> {
        use tokio::fs;

        let mut files = Vec::new();
        let mut dirs_to_process = vec![(dir_path.as_ref().to_path_buf(), 0u32)];

        while let Some((current_dir, depth)) = dirs_to_process.pop() {
            // Check depth limit
            if let Some(max_depth) = max_depth {
                if depth >= max_depth {
                    continue;
                }
            }

            // Check if directory should be excluded
            if let Some(dir_name) = current_dir.file_name().and_then(|n| n.to_str()) {
                if config.excluded_directories.contains(&dir_name.to_string()) {
                    continue;
                }
            }

            let mut entries = match fs::read_dir(&current_dir).await {
                Ok(entries) => entries,
                Err(e) => {
                    log::warn!("Failed to read directory {:?}: {}", current_dir, e);
                    continue;
                }
            };

            while let Some(entry) = entries.next_entry().await.map_err(ScanError::Io)? {
                let path = entry.path();
                let metadata = match entry.metadata().await {
                    Ok(metadata) => metadata,
                    Err(e) => {
                        log::warn!("Failed to get metadata for {:?}: {}", path, e);
                        continue;
                    }
                };

                if metadata.is_dir() {
                    if config.follow_symlinks || !metadata.file_type().is_symlink() {
                        dirs_to_process.push((path, depth + 1));
                    }
                } else if metadata.is_file() && should_scan_file(&path, config).await? {
                    files.push(path);
                }
            }
        }

        Ok(files)
    }
}
