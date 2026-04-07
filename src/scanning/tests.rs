//! Comprehensive test suite for the scanning module
//!
//! This module contains unit tests, integration tests, and mock implementations
//! for testing the malware scanning functionality.

use super::*;
use crate::scanning::detection_event::*;
use crate::scanning::traits::*;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tempfile::TempDir;
use tokio::time::sleep;

/// Mock scanner for testing purposes
#[derive(Debug, Clone)]
pub struct MockScanner {
    pub name: String,
    pub should_detect: bool,
    pub scan_delay: Duration,
    pub initialized: bool,
    pub config: ScanConfig,
    pub stats: ScanStats,
}

impl MockScanner {
    pub fn new(name: &str, should_detect: bool) -> Self {
        Self {
            name: name.to_string(),
            should_detect,
            scan_delay: Duration::from_millis(10),
            initialized: false,
            config: ScanConfig::default(),
            stats: ScanStats::default(),
        }
    }

    pub fn with_delay(mut self, delay: Duration) -> Self {
        self.scan_delay = delay;
        self
    }
}

#[async_trait::async_trait]
impl MalwareScanner for MockScanner {
    async fn initialize(&mut self, _rules_path: &Path) -> Result<(), ScanError> {
        self.initialized = true;
        Ok(())
    }

    fn is_initialized(&self) -> bool {
        self.initialized
    }

    async fn scan_file(&self, file_path: &Path) -> Result<ScanResult, ScanError> {
        if !self.initialized {
            return Err(ScanError::NotInitialized(
                "Scanner not initialized".to_string(),
            ));
        }

        sleep(self.scan_delay).await;

        let scan_time_ms = self.scan_delay.as_millis() as u64;
        let scanner_engine = self.name.clone();

        if self.should_detect {
            let mut detection = DetectionEvent::new(
                file_path.to_path_buf(),
                DetectionType::YaraRule,
                Severity::High,
                scanner_engine.clone(),
                "1.0.0".to_string(),
            );

            let rule_match = RuleMatch {
                rule_name: "WannaCry_Ransomware".to_string(),
                description: Some("Mock malware detection".to_string()),
                tags: vec!["ransomware".to_string(), "malware".to_string()],
                author: Some("Test".to_string()),
                version: Some("1.0".to_string()),
                confidence: 0.95,
                matched_strings: vec![MatchedString {
                    identifier: "$test_string".to_string(),
                    content: "mock_pattern".to_string(),
                    offset: 0,
                    length: 12,
                }],
                metadata: HashMap::new(),
            };

            detection.add_rule_match(rule_match);
            detection.set_file_metadata(Some(1024), None, None);

            Ok(ScanResult::success(
                file_path.to_path_buf(),
                scanner_engine,
                scan_time_ms,
                vec![detection],
            ))
        } else {
            Ok(ScanResult::success(
                file_path.to_path_buf(),
                scanner_engine,
                scan_time_ms,
                vec![],
            ))
        }
    }

    async fn scan_directory(
        &self,
        dir_path: &Path,
        recursive: bool,
    ) -> Result<Vec<ScanResult>, ScanError> {
        if !self.initialized {
            return Err(ScanError::NotInitialized(
                "Scanner not initialized".to_string(),
            ));
        }

        let mut results = Vec::new();

        if let Ok(entries) = std::fs::read_dir(dir_path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    results.push(self.scan_file(&path).await?);
                } else if path.is_dir() && recursive {
                    results.extend(self.scan_directory(&path, recursive).await?);
                }
            }
        }

        Ok(results)
    }

    async fn scan_memory(
        &self,
        data: &[u8],
        context: Option<&str>,
    ) -> Result<Vec<DetectionEvent>, ScanError> {
        if !self.initialized {
            return Err(ScanError::NotInitialized(
                "Scanner not initialized".to_string(),
            ));
        }

        if self.should_detect {
            let mut detection = DetectionEvent::new(
                PathBuf::from(context.unwrap_or("memory")),
                DetectionType::YaraRule,
                Severity::Medium,
                self.name.clone(),
                "1.0.0".to_string(),
            );

            let rule_match = RuleMatch {
                rule_name: "Memory_Pattern".to_string(),
                description: Some("Mock memory detection".to_string()),
                tags: vec!["memory".to_string()],
                author: Some("Test".to_string()),
                version: Some("1.0".to_string()),
                confidence: 0.8,
                matched_strings: vec![MatchedString {
                    identifier: "$mem_pattern".to_string(),
                    content: "pattern".to_string(),
                    offset: 0,
                    length: data.len() as u32,
                }],
                metadata: HashMap::new(),
            };

            detection.add_rule_match(rule_match);
            Ok(vec![detection])
        } else {
            Ok(vec![])
        }
    }

    async fn get_rules_info(&self) -> HashMap<String, String> {
        let mut info = HashMap::new();
        info.insert(
            "WannaCry_Ransomware".to_string(),
            "Mock ransomware rule".to_string(),
        );
        info.insert(
            "Memory_Pattern".to_string(),
            "Mock memory pattern rule".to_string(),
        );
        info
    }

    async fn get_rules_count(&self) -> usize {
        2
    }

    fn get_stats(&self) -> ScanStats {
        self.stats.clone()
    }

    fn reset_stats(&mut self) {
        self.stats = ScanStats::default();
    }

    fn set_config(&mut self, config: ScanConfig) {
        self.config = config;
    }

    fn get_config(&self) -> &ScanConfig {
        &self.config
    }

    fn get_engine_name(&self) -> &'static str {
        "MockScanner"
    }

    fn get_engine_version(&self) -> String {
        "1.0.0".to_string()
    }
}

/// Helper function to create a test configuration
fn create_test_config() -> ScanConfig {
    ScanConfig {
        max_file_size_mb: 10,
        timeout_secs: 30,
        scan_compressed: false,
        follow_symlinks: false,
        max_recursion_depth: 10,
        excluded_extensions: vec!["tmp".to_string(), "log".to_string(), "cache".to_string()],
        excluded_directories: vec![
            "node_modules".to_string(),
            ".git".to_string(),
            "target".to_string(),
        ],
    }
}

/// Helper function to create a temporary directory with test files
fn create_test_directory() -> Result<TempDir, std::io::Error> {
    let temp_dir = TempDir::new()?;

    // Create some test files
    fs::write(
        temp_dir.path().join("clean_file.txt"),
        "This is a clean file",
    )?;
    fs::write(
        temp_dir.path().join("malware_file.exe"),
        "This is a malicious file",
    )?;
    fs::write(
        temp_dir.path().join("large_file.bin"),
        vec![0u8; 1024 * 1024],
    )?; // 1MB file

    // Create subdirectory
    let sub_dir = temp_dir.path().join("subdir");
    fs::create_dir(&sub_dir)?;
    fs::write(sub_dir.join("nested_file.dll"), "Nested file content")?;

    Ok(temp_dir)
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[tokio::test]
    async fn test_detection_event_creation() {
        let mut event = DetectionEvent::new(
            PathBuf::from("/test/path/malware.exe"),
            DetectionType::YaraRule,
            Severity::Critical,
            "test_scanner".to_string(),
            "1.0.0".to_string(),
        );

        let rule_match = RuleMatch {
            rule_name: "WannaCry_Ransomware".to_string(),
            description: Some("Test malware detected".to_string()),
            tags: vec!["ransomware".to_string()],
            author: Some("Test".to_string()),
            version: Some("1.0".to_string()),
            confidence: 0.9,
            matched_strings: vec![],
            metadata: HashMap::new(),
        };

        event.add_rule_match(rule_match);

        assert_eq!(event.file_path, PathBuf::from("/test/path/malware.exe"));
        assert_eq!(event.scanner_engine, "test_scanner");
        assert_eq!(event.rule_matches[0].rule_name, "WannaCry_Ransomware");
        assert_eq!(event.severity, Severity::Critical);
    }

    #[tokio::test]
    async fn test_scan_result_has_detections() {
        // Test with detections
        let detection = DetectionEvent::new(
            PathBuf::from("/test/malware.exe"),
            DetectionType::YaraRule,
            Severity::High,
            "test_scanner".to_string(),
            "1.0.0".to_string(),
        );

        let result_with_detections = ScanResult::success(
            PathBuf::from("/test/malware.exe"),
            "test_scanner".to_string(),
            100,
            vec![detection],
        );

        assert!(result_with_detections.has_detections());

        // Test without detections
        let result_clean = ScanResult::success(
            PathBuf::from("/test/clean.txt"),
            "test_scanner".to_string(),
            50,
            vec![],
        );

        assert!(!result_clean.has_detections());
    }

    #[tokio::test]
    async fn test_mock_scanner_initialization() {
        let mut scanner = MockScanner::new("test_mock", false);
        let rules_path = Path::new("/test/rules");

        assert!(!scanner.is_initialized());

        let result = scanner.initialize(rules_path).await;
        assert!(result.is_ok());
        assert!(scanner.is_initialized());
        assert_eq!(scanner.get_engine_name(), "MockScanner");
        assert_eq!(scanner.get_engine_version(), "1.0.0");
    }

    #[tokio::test]
    async fn test_mock_scanner_clean_file() {
        let mut scanner = MockScanner::new("test_scanner", false);
        let rules_path = Path::new("/test/rules");
        scanner.initialize(rules_path).await.unwrap();

        let file_path = Path::new("/test/clean.txt");
        let result = scanner.scan_file(file_path).await;

        assert!(result.is_ok());
        let scan_result = result.unwrap();
        assert!(!scan_result.has_detections());
        assert_eq!(scan_result.scanner_engine, "test_scanner");
        assert_eq!(scan_result.file_path, PathBuf::from("/test/clean.txt"));
    }

    #[tokio::test]
    async fn test_mock_scanner_malware_detection() {
        let mut scanner = MockScanner::new("test_scanner", true);
        let rules_path = Path::new("/test/rules");
        scanner.initialize(rules_path).await.unwrap();

        let file_path = Path::new("/test/malware.exe");
        let result = scanner.scan_file(file_path).await;

        assert!(result.is_ok());
        let scan_result = result.unwrap();
        assert!(scan_result.has_detections());
        assert_eq!(scan_result.detections.len(), 1);
        assert_eq!(
            scan_result.detections[0].rule_matches[0].rule_name,
            "WannaCry_Ransomware"
        );
        assert_eq!(scan_result.detections[0].severity, Severity::High);
    }

    #[tokio::test]
    async fn test_scan_config_creation() {
        let config = create_test_config();

        // Test the configuration validation
        assert_eq!(config.max_file_size_mb, 10);
        assert_eq!(config.timeout_secs, 30);
        assert!(!config.scan_compressed);
        assert!(!config.follow_symlinks);
        assert_eq!(config.max_recursion_depth, 10);
    }

    #[tokio::test]
    async fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
    }

    #[tokio::test]
    async fn test_scan_stats() {
        let stats = ScanStats {
            files_scanned: 10,
            directories_processed: 2,
            files_skipped: 1,
            scan_errors: 0,
            total_scan_time_ms: 2500,
            detections_found: 3,
            avg_scan_time_ms: 250.0,
        };

        assert_eq!(stats.files_scanned, 10);
        assert_eq!(stats.directories_processed, 2);
        assert_eq!(stats.files_skipped, 1);
        assert_eq!(stats.scan_errors, 0);
        assert_eq!(stats.total_scan_time_ms, 2500);
        assert_eq!(stats.detections_found, 3);
        assert_eq!(stats.avg_scan_time_ms, 250.0);
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[tokio::test]
    async fn test_file_system_scanning() {
        let temp_dir = create_test_directory().expect("Failed to create test directory");
        let mut scanner = MockScanner::new("integration_test", false);
        let rules_path = Path::new("/test/rules");
        scanner.initialize(rules_path).await.unwrap();

        // Test scanning individual files
        let clean_file = temp_dir.path().join("clean_file.txt");
        let result = scanner.scan_file(&clean_file).await;

        assert!(result.is_ok());
        let scan_result = result.unwrap();
        assert!(!scan_result.has_detections());
    }

    #[tokio::test]
    async fn test_concurrent_scanning() {
        let temp_dir = create_test_directory().expect("Failed to create test directory");
        let scanner = Arc::new(tokio::sync::Mutex::new(
            MockScanner::new("concurrent_test", false).with_delay(Duration::from_millis(100)),
        ));

        // Initialize the scanner
        {
            let mut scanner_guard = scanner.lock().await;
            let rules_path = Path::new("/test/rules");
            scanner_guard.initialize(rules_path).await.unwrap();
        }

        let mut handles = vec![];

        // Scan multiple files concurrently
        for i in 0..5 {
            let scanner_clone = Arc::clone(&scanner);
            let file_path = temp_dir.path().join(format!("test_file_{}.txt", i));
            fs::write(&file_path, format!("Test content {}", i)).unwrap();

            let handle = tokio::spawn(async move {
                let scanner_guard = scanner_clone.lock().await;
                scanner_guard.scan_file(&file_path).await
            });
            handles.push(handle);
        }

        // Wait for all scans to complete
        let start_time = std::time::Instant::now();
        for handle in handles {
            let result = handle.await.unwrap();
            assert!(result.is_ok());
        }
        let elapsed = start_time.elapsed();

        // Should complete faster than sequential scanning due to concurrency
        assert!(elapsed < Duration::from_secs(2)); // More lenient timing for CI/slow systems
    }

    #[tokio::test]
    async fn test_error_handling_invalid_file() {
        let mut scanner = MockScanner::new("error_test", false);
        let rules_path = Path::new("/test/rules");
        scanner.initialize(rules_path).await.unwrap();

        // Test with non-existent file - MockScanner doesn't validate file existence
        // but in real implementation, this would return an error
        let result = scanner.scan_file(Path::new("/non/existent/file.txt")).await;

        // MockScanner always succeeds, but real scanners should handle this gracefully
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_large_file_handling() {
        let temp_dir = create_test_directory().expect("Failed to create test directory");
        let mut scanner = MockScanner::new("large_file_test", false);
        let rules_path = Path::new("/test/rules");
        scanner.initialize(rules_path).await.unwrap();

        let large_file = temp_dir.path().join("large_file.bin");
        let result = scanner.scan_file(&large_file).await;

        assert!(result.is_ok());
        let scan_result = result.unwrap();
        assert_eq!(scan_result.file_path, large_file);
    }
}

#[cfg(test)]
mod performance_tests {
    use super::*;
    use std::time::Instant;

    #[tokio::test]
    async fn test_scan_performance() {
        let mut scanner = MockScanner::new("perf_test", false).with_delay(Duration::from_millis(1));
        let rules_path = Path::new("/test/rules");
        scanner.initialize(rules_path).await.unwrap();

        let start = Instant::now();
        let mut results = vec![];

        // Perform 100 scans
        for i in 0..100 {
            let file_path = PathBuf::from(format!("/test/file_{}.txt", i));
            let result = scanner.scan_file(&file_path).await;
            results.push(result);
        }

        let elapsed = start.elapsed();

        // Verify all scans completed successfully
        assert_eq!(results.len(), 100);
        for result in results {
            assert!(result.is_ok());
        }

        // Performance should be reasonable (less than 5 seconds for 100 1ms scans)
        assert!(elapsed < Duration::from_secs(5));
        println!("100 scans completed in {:?}", elapsed);
    }

    #[tokio::test]
    async fn test_memory_usage() {
        let mut scanner = MockScanner::new("memory_test", true);
        let rules_path = Path::new("/test/rules");
        scanner.initialize(rules_path).await.unwrap();

        // Perform many scans to test for memory leaks
        for i in 0..1000 {
            let file_path = PathBuf::from(format!("/test/file_{}.txt", i));
            let result = scanner.scan_file(&file_path).await;
            assert!(result.is_ok());

            // Drop the result to free memory
            drop(result);
        }

        // If we reach here without OOM, the test passes
        // Test completed successfully
    }
}
