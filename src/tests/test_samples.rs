//! Test Malware Samples Module
//!
//! This module provides safe test samples that mimic real malware signatures
//! without containing actual malicious code. These samples are designed to
//! trigger YARA rules for testing purposes only.
//!
//! IMPORTANT: These are NOT real malware samples - they are safe test data
//! that contains signature patterns for detection testing.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

/// Safe test sample that mimics WannaCry ransomware signatures
pub struct WannaCryTestSample {
    pub content: Vec<u8>,
    pub filename: String,
    pub expected_detections: Vec<String>,
}

impl WannaCryTestSample {
    pub fn new() -> Self {
        let content = b"\x4d\x5a\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\
                       This file has been encrypted by WannaCry ransomware.\n\
                       Your files are encrypted with RSA-2048 encryption.\n\
                       To decrypt your files you need to pay 300 USD in Bitcoin.\n\
                       Send payment to bitcoin address: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n\
                       After payment, download Tor browser and visit our payment site.\n\
                       WARNING: Do not rename encrypted files or you will lose them forever.\n\
                       DECRYPT_INSTRUCTION.txt\n\
                       WanaCrypt0r 2.0 - Your files are encrypted!\n\
                       Wana Decrypt0r - File Recovery Software".to_vec();
        
        Self {
            content,
            filename: "wannacry_test_sample.exe".to_string(),
            expected_detections: vec![
                "WannaCry_Ransomware".to_string(),
                "Generic_Ransomware_Indicators".to_string(),
            ],
        }
    }
}

/// Safe test sample that mimics Locky ransomware signatures
pub struct LockyTestSample {
    pub content: Vec<u8>,
    pub filename: String,
    pub expected_detections: Vec<String>,
}

impl LockyTestSample {
    pub fn new() -> Self {
        let content = b"\x4d\x5a\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\
                       Your files have been encrypted by Locky ransomware.\n\
                       All your important files have been encrypted with strong encryption.\n\
                       To decrypt your files, you need to purchase the Locky Decryptor.\n\
                       Download Tor browser from: https://www.torproject.org/\n\
                       Visit our payment site in Tor browser for instructions.\n\
                       Your personal identification ID: ABCD-1234-EFGH-5678\n\
                       LOCKY_RECOVER_INSTRUCTIONS.txt\n\
                       Time is running out! Pay now or lose your files forever!".to_vec();
        
        Self {
            content,
            filename: "locky_test_sample.exe".to_string(),
            expected_detections: vec![
                "Locky_Ransomware".to_string(),
                "Generic_Ransomware_Indicators".to_string(),
            ],
        }
    }
}

/// Safe test sample that mimics Petya ransomware signatures
pub struct PetyaTestSample {
    pub content: Vec<u8>,
    pub filename: String,
    pub expected_detections: Vec<String>,
}

impl PetyaTestSample {
    pub fn new() -> Self {
        let content = b"\x4d\x5a\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\
                       Petya ransomware has encrypted your hard drive.\n\
                       Your hard disk has been encrypted with military-grade encryption.\n\
                       Pay ransom to decrypt your files and restore access.\n\
                       Payment must be made in Bitcoin within 72 hours.\n\
                       After this time, the decryption key will be destroyed.\n\
                       Visit our payment portal for instructions.\n\
                       PETYA_RECOVERY_KEY.txt\n\
                       System files encrypted - Reboot required for decryption".to_vec();
        
        Self {
            content,
            filename: "petya_test_sample.exe".to_string(),
            expected_detections: vec![
                "Petya_Ransomware".to_string(),
                "Generic_Ransomware_Indicators".to_string(),
            ],
        }
    }
}

/// Safe test sample that should NOT trigger malware detection
pub struct CleanTestSample {
    pub content: Vec<u8>,
    pub filename: String,
    pub expected_detections: Vec<String>,
}

impl CleanTestSample {
    pub fn new() -> Self {
        let content = b"This is a completely normal and clean text file.\n\
                       It contains no malicious content whatsoever.\n\
                       This file is used for testing false positive rates.\n\
                       Normal business document with standard content.\n\
                       Copyright 2024 - All rights reserved.\n\
                       Contact: support@company.com\n\
                       Version: 1.0.0\n\
                       Last modified: 2024-01-01".to_vec();
        
        Self {
            content,
            filename: "clean_test_sample.txt".to_string(),
            expected_detections: vec![], // Should not trigger any detections
        }
    }
}

/// Test sample that mimics a Windows PE executable
pub struct PETestSample {
    pub content: Vec<u8>,
    pub filename: String,
    pub expected_detections: Vec<String>,
}

impl PETestSample {
    pub fn new() -> Self {
        // Create a minimal PE-like structure (not a real executable)
        let mut content = Vec::new();
        
        // MZ header
        content.extend_from_slice(b"\x4d\x5a"); // MZ signature
        content.extend_from_slice(&[0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00]);
        content.extend_from_slice(&[0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0xb8, 0x00]);
        
        // Add some padding
        content.resize(0x3c, 0);
        
        // PE offset (pointing to PE signature)
        content.extend_from_slice(&[0x80, 0x00, 0x00, 0x00]);
        
        // More padding to PE signature location
        content.resize(0x80, 0);
        
        // PE signature
        content.extend_from_slice(b"PE\x00\x00");
        
        // Add some more PE-like data
        content.extend_from_slice(&[0x4c, 0x01, 0x03, 0x00]); // Machine type and sections
        
        Self {
            content,
            filename: "pe_test_sample.exe".to_string(),
            expected_detections: vec![
                "PE_File_Detection".to_string(),
            ],
        }
    }
}

/// Collection of all test samples
pub struct TestSampleCollection {
    pub wannacry: WannaCryTestSample,
    pub locky: LockyTestSample,
    pub petya: PetyaTestSample,
    pub clean: CleanTestSample,
    pub pe_file: PETestSample,
}

impl TestSampleCollection {
    pub fn new() -> Self {
        Self {
            wannacry: WannaCryTestSample::new(),
            locky: LockyTestSample::new(),
            petya: PetyaTestSample::new(),
            clean: CleanTestSample::new(),
            pe_file: PETestSample::new(),
        }
    }
    
    /// Write all test samples to a directory
    pub fn write_to_directory(&self, dir: &Path) -> Result<HashMap<String, PathBuf>, std::io::Error> {
        let mut file_paths = HashMap::new();
        
        // Write WannaCry sample
        let wannacry_path = dir.join(&self.wannacry.filename);
        fs::write(&wannacry_path, &self.wannacry.content)?;
        file_paths.insert("wannacry".to_string(), wannacry_path);
        
        // Write Locky sample
        let locky_path = dir.join(&self.locky.filename);
        fs::write(&locky_path, &self.locky.content)?;
        file_paths.insert("locky".to_string(), locky_path);
        
        // Write Petya sample
        let petya_path = dir.join(&self.petya.filename);
        fs::write(&petya_path, &self.petya.content)?;
        file_paths.insert("petya".to_string(), petya_path);
        
        // Write clean sample
        let clean_path = dir.join(&self.clean.filename);
        fs::write(&clean_path, &self.clean.content)?;
        file_paths.insert("clean".to_string(), clean_path);
        
        // Write PE sample
        let pe_path = dir.join(&self.pe_file.filename);
        fs::write(&pe_path, &self.pe_file.content)?;
        file_paths.insert("pe_file".to_string(), pe_path);
        
        Ok(file_paths)
    }
    
    /// Get all samples as a vector for batch processing
    pub fn get_all_samples(&self) -> Vec<(&str, &[u8], &str, &[String])> {
        vec![
            ("wannacry", &self.wannacry.content, &self.wannacry.filename, &self.wannacry.expected_detections),
            ("locky", &self.locky.content, &self.locky.filename, &self.locky.expected_detections),
            ("petya", &self.petya.content, &self.petya.filename, &self.petya.expected_detections),
            ("clean", &self.clean.content, &self.clean.filename, &self.clean.expected_detections),
            ("pe_file", &self.pe_file.content, &self.pe_file.filename, &self.pe_file.expected_detections),
        ]
    }
}

/// Performance test data generator
pub struct PerformanceTestData {
    pub small_files: Vec<Vec<u8>>,
    pub medium_files: Vec<Vec<u8>>,
    pub large_files: Vec<Vec<u8>>,
}

impl PerformanceTestData {
    pub fn new() -> Self {
        let mut small_files = Vec::new();
        let mut medium_files = Vec::new();
        let mut large_files = Vec::new();
        
        // Generate small files (1KB - 10KB)
        for i in 0..10 {
            let size = 1024 + (i * 1024); // 1KB to 10KB
            let mut content = vec![b'A'; size];
            
            // Add some malware-like content to some files
            if i % 3 == 0 {
                content.extend_from_slice(b"WANNACRY RANSOMWARE DETECTED");
            } else if i % 3 == 1 {
                content.extend_from_slice(b"LOCKY ENCRYPTION ACTIVE");
            }
            
            small_files.push(content);
        }
        
        // Generate medium files (100KB - 1MB)
        for i in 0..5 {
            let size = 100 * 1024 + (i * 200 * 1024); // 100KB to 1MB
            let mut content = vec![b'B'; size];
            
            // Add malware signatures at different positions
            if i % 2 == 0 {
                let pos = size / 2;
                content[pos..pos+20].copy_from_slice(b"PETYA RANSOMWARE HIT");
            }
            
            medium_files.push(content);
        }
        
        // Generate large files (5MB - 10MB)
        for i in 0..3 {
            let size = 5 * 1024 * 1024 + (i * 2 * 1024 * 1024); // 5MB to 10MB
            let mut content = vec![b'C'; size];
            
            // Add signature near the end
            let pos = size - 100;
            content[pos..pos+25].copy_from_slice(b"BITCOIN PAYMENT REQUIRED!");
            
            large_files.push(content);
        }
        
        Self {
            small_files,
            medium_files,
            large_files,
        }
    }
    
    /// Write performance test files to directory
    pub fn write_to_directory(&self, dir: &Path) -> Result<Vec<PathBuf>, std::io::Error> {
        let mut file_paths = Vec::new();
        
        // Write small files
        for (i, content) in self.small_files.iter().enumerate() {
            let path = dir.join(format!("small_test_{}.bin", i));
            fs::write(&path, content)?;
            file_paths.push(path);
        }
        
        // Write medium files
        for (i, content) in self.medium_files.iter().enumerate() {
            let path = dir.join(format!("medium_test_{}.bin", i));
            fs::write(&path, content)?;
            file_paths.push(path);
        }
        
        // Write large files
        for (i, content) in self.large_files.iter().enumerate() {
            let path = dir.join(format!("large_test_{}.bin", i));
            fs::write(&path, content)?;
            file_paths.push(path);
        }
        
        Ok(file_paths)
    }
    
    /// Get total number of test files
    pub fn total_files(&self) -> usize {
        self.small_files.len() + self.medium_files.len() + self.large_files.len()
    }
    
    /// Get expected number of detections (files with malware signatures)
    pub fn expected_detections(&self) -> usize {
        // Count files that have malware signatures
        let small_detections = (0..self.small_files.len()).filter(|i| i % 3 != 2).count();
        let medium_detections = (0..self.medium_files.len()).filter(|i| i % 2 == 0).count();
        let large_detections = self.large_files.len(); // All large files have signatures
        
        small_detections + medium_detections + large_detections
    }
}

/// Utility functions for test sample management
pub mod utils {
    use super::*;
    
    /// Create a temporary directory with all test samples
    pub fn create_test_sample_directory() -> Result<(TempDir, HashMap<String, PathBuf>), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let samples = TestSampleCollection::new();
        let file_paths = samples.write_to_directory(temp_dir.path())?;
        
        Ok((temp_dir, file_paths))
    }
    
    /// Create a temporary directory with performance test files
    pub fn create_performance_test_directory() -> Result<(TempDir, Vec<PathBuf>), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let perf_data = PerformanceTestData::new();
        let file_paths = perf_data.write_to_directory(temp_dir.path())?;
        
        Ok((temp_dir, file_paths))
    }
    
    /// Verify that a detection result matches expected patterns
    pub fn verify_detection_results(
        _sample_name: &str,
        expected_detections: &[String],
        actual_detections: &[String],
    ) -> bool {
        if expected_detections.is_empty() {
            // For clean samples, ensure no malware detections
            return actual_detections.is_empty() || 
                   !actual_detections.iter().any(|d| d.contains("Ransomware") || d.contains("Malware"));
        }
        
        // For malware samples, check if at least one expected detection occurred
        expected_detections.iter().any(|expected| {
            actual_detections.iter().any(|actual| actual.contains(expected))
        })
    }
    
    /// Generate a summary report of test results
    pub fn generate_test_summary(
        total_files: usize,
        successful_scans: usize,
        total_detections: usize,
        expected_detections: usize,
        scan_duration: std::time::Duration,
    ) -> String {
        let success_rate = (successful_scans as f64 / total_files as f64) * 100.0;
        let detection_accuracy = if expected_detections > 0 {
            (total_detections.min(expected_detections) as f64 / expected_detections as f64) * 100.0
        } else {
            100.0
        };
        let avg_scan_time = scan_duration / total_files as u32;
        
        format!(
            "\n📊 Test Summary Report:\n\
             ========================\n\
             Total files scanned: {}\n\
             Successful scans: {} ({:.1}%)\n\
             Total detections: {}\n\
             Expected detections: {}\n\
             Detection accuracy: {:.1}%\n\
             Total scan time: {:?}\n\
             Average per file: {:?}\n\
             Scans per second: {:.2}\n",
            total_files,
            successful_scans,
            success_rate,
            total_detections,
            expected_detections,
            detection_accuracy,
            scan_duration,
            avg_scan_time,
            total_files as f64 / scan_duration.as_secs_f64()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_sample_creation() {
        let samples = TestSampleCollection::new();
        
        // Verify samples have content
        assert!(!samples.wannacry.content.is_empty());
        assert!(!samples.locky.content.is_empty());
        assert!(!samples.petya.content.is_empty());
        assert!(!samples.clean.content.is_empty());
        assert!(!samples.pe_file.content.is_empty());
        
        // Verify expected detections
        assert!(!samples.wannacry.expected_detections.is_empty());
        assert!(!samples.locky.expected_detections.is_empty());
        assert!(!samples.petya.expected_detections.is_empty());
        assert!(samples.clean.expected_detections.is_empty()); // Clean should have no expected detections
        assert!(!samples.pe_file.expected_detections.is_empty());
    }
    
    #[test]
    fn test_performance_data_generation() {
        let perf_data = PerformanceTestData::new();
        
        assert_eq!(perf_data.small_files.len(), 10);
        assert_eq!(perf_data.medium_files.len(), 5);
        assert_eq!(perf_data.large_files.len(), 3);
        assert_eq!(perf_data.total_files(), 18);
        
        // Verify file sizes
        assert!(perf_data.small_files[0].len() >= 1024);
        assert!(perf_data.medium_files[0].len() >= 100 * 1024);
        assert!(perf_data.large_files[0].len() >= 5 * 1024 * 1024);
    }
}
