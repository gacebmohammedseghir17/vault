//! Integrity Verification Module
//!
//! Handles checksum calculation and verification for exported report files
//! to ensure data integrity and detect tampering.

use anyhow::{Context, Result};
use md5;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use tokio::fs;

/// Checksum algorithm enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ChecksumAlgorithm {
    Md5,
    Sha1,
    Sha256,
}

/// Checksum result structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChecksumResult {
    pub algorithm: ChecksumAlgorithm,
    pub hash: String,
    pub file_size: u64,
    pub calculated_at: chrono::DateTime<chrono::Utc>,
}

/// Integrity verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub is_valid: bool,
    pub expected_hash: String,
    pub actual_hash: String,
    pub algorithm: ChecksumAlgorithm,
    pub error_message: Option<String>,
}

/// Checksum calculator utility
pub struct ChecksumCalculator;

impl ChecksumCalculator {
    /// Calculate MD5 checksum for a file
    pub async fn calculate_md5(file_path: &Path) -> Result<String> {
        let file = File::open(file_path).context("Failed to open file for MD5 calculation")?;
        let mut reader = BufReader::new(file);
        let mut context = md5::Context::new();
        let mut buffer = [0u8; 8192];

        loop {
            let bytes_read = reader
                .read(&mut buffer)
                .context("Failed to read file for MD5 calculation")?;

            if bytes_read == 0 {
                break;
            }

            context.consume(&buffer[..bytes_read]);
        }

        let digest = context.compute();
        Ok(format!("{:x}", digest))
    }

    /// Calculate SHA1 checksum for a file
    pub async fn calculate_sha1(file_path: &Path) -> Result<String> {
        let file = File::open(file_path).context("Failed to open file for SHA1 calculation")?;
        let mut reader = BufReader::new(file);
        let mut hasher = Sha1::new();
        let mut buffer = [0u8; 8192];

        loop {
            let bytes_read = reader
                .read(&mut buffer)
                .context("Failed to read file for SHA1 calculation")?;

            if bytes_read == 0 {
                break;
            }

            Digest::update(&mut hasher, &buffer[..bytes_read]);
        }

        Ok(format!("{:x}", Digest::finalize(hasher)))
    }

    /// Calculate SHA256 checksum for a file
    pub async fn calculate_sha256(file_path: &Path) -> Result<String> {
        let file = File::open(file_path).context("Failed to open file for SHA256 calculation")?;
        let mut reader = BufReader::new(file);
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 8192];

        loop {
            let bytes_read = reader
                .read(&mut buffer)
                .context("Failed to read file for SHA256 calculation")?;

            if bytes_read == 0 {
                break;
            }

            Digest::update(&mut hasher, &buffer[..bytes_read]);
        }

        Ok(format!("{:x}", Digest::finalize(hasher)))
    }

    /// Calculate checksum using specified algorithm
    pub async fn calculate_checksum(
        file_path: &Path,
        algorithm: ChecksumAlgorithm,
    ) -> Result<ChecksumResult> {
        let file_size = fs::metadata(file_path)
            .await
            .context("Failed to get file metadata")?
            .len();

        let hash = match algorithm {
            ChecksumAlgorithm::Md5 => Self::calculate_md5(file_path).await?,
            ChecksumAlgorithm::Sha1 => Self::calculate_sha1(file_path).await?,
            ChecksumAlgorithm::Sha256 => Self::calculate_sha256(file_path).await?,
        };

        Ok(ChecksumResult {
            algorithm,
            hash,
            file_size,
            calculated_at: chrono::Utc::now(),
        })
    }

    /// Verify file integrity against expected checksum
    pub async fn verify_integrity(
        file_path: &Path,
        expected_hash: &str,
        algorithm: ChecksumAlgorithm,
    ) -> Result<VerificationResult> {
        let actual_hash = match algorithm {
            ChecksumAlgorithm::Md5 => Self::calculate_md5(file_path).await,
            ChecksumAlgorithm::Sha1 => Self::calculate_sha1(file_path).await,
            ChecksumAlgorithm::Sha256 => Self::calculate_sha256(file_path).await,
        };

        match actual_hash {
            Ok(hash) => {
                let is_valid = hash.eq_ignore_ascii_case(expected_hash);
                Ok(VerificationResult {
                    is_valid,
                    expected_hash: expected_hash.to_string(),
                    actual_hash: hash,
                    algorithm,
                    error_message: None,
                })
            }
            Err(e) => Ok(VerificationResult {
                is_valid: false,
                expected_hash: expected_hash.to_string(),
                actual_hash: String::new(),
                algorithm,
                error_message: Some(e.to_string()),
            }),
        }
    }
}

/// Integrity manifest for tracking multiple files
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityManifest {
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub version: String,
    pub files: Vec<FileIntegrityInfo>,
}

/// File integrity information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileIntegrityInfo {
    pub file_path: String,
    pub file_name: String,
    pub file_size: u64,
    pub checksums: Vec<ChecksumResult>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl IntegrityManifest {
    /// Create a new integrity manifest
    pub fn new() -> Self {
        Self {
            created_at: chrono::Utc::now(),
            version: "1.0".to_string(),
            files: Vec::new(),
        }
    }

    /// Add file to manifest with checksums
    pub async fn add_file(&mut self, file_path: &Path) -> Result<()> {
        let file_name = file_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("unknown")
            .to_string();

        let file_size = fs::metadata(file_path)
            .await
            .context("Failed to get file metadata")?
            .len();

        // Calculate multiple checksums for better security
        let mut checksums = Vec::new();

        // SHA256 (primary)
        checksums.push(
            ChecksumCalculator::calculate_checksum(file_path, ChecksumAlgorithm::Sha256).await?,
        );

        // MD5 (for compatibility)
        checksums
            .push(ChecksumCalculator::calculate_checksum(file_path, ChecksumAlgorithm::Md5).await?);

        let file_info = FileIntegrityInfo {
            file_path: file_path.to_string_lossy().to_string(),
            file_name,
            file_size,
            checksums,
            created_at: chrono::Utc::now(),
        };

        self.files.push(file_info);
        Ok(())
    }

    /// Save manifest to file
    pub async fn save_to_file(&self, manifest_path: &Path) -> Result<()> {
        let json_content =
            serde_json::to_string_pretty(self).context("Failed to serialize integrity manifest")?;

        fs::write(manifest_path, json_content)
            .await
            .context("Failed to write integrity manifest file")?;

        Ok(())
    }

    /// Load manifest from file
    pub async fn load_from_file(manifest_path: &Path) -> Result<Self> {
        let json_content = fs::read_to_string(manifest_path)
            .await
            .context("Failed to read integrity manifest file")?;

        let manifest: IntegrityManifest =
            serde_json::from_str(&json_content).context("Failed to parse integrity manifest")?;

        Ok(manifest)
    }

    /// Verify all files in the manifest
    pub async fn verify_all_files(&self) -> Result<Vec<(String, VerificationResult)>> {
        let mut results = Vec::new();

        for file_info in &self.files {
            let file_path = Path::new(&file_info.file_path);

            // Use SHA256 checksum for verification (primary)
            if let Some(sha256_checksum) = file_info
                .checksums
                .iter()
                .find(|c| c.algorithm == ChecksumAlgorithm::Sha256)
            {
                let verification = ChecksumCalculator::verify_integrity(
                    file_path,
                    &sha256_checksum.hash,
                    ChecksumAlgorithm::Sha256,
                )
                .await?;

                results.push((file_info.file_name.clone(), verification));
            }
        }

        Ok(results)
    }
}

#[cfg(all(test, feature = "advanced-reporting"))]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_checksum_calculation() {
        // Create a temporary file with known content
        let mut temp_file = NamedTempFile::new().unwrap();
        let test_content = b"Hello, World!";
        temp_file.write_all(test_content).unwrap();
        temp_file.flush().unwrap();

        // Calculate checksums
        let md5_hash = ChecksumCalculator::calculate_md5(temp_file.path())
            .await
            .unwrap();
        let sha1_hash = ChecksumCalculator::calculate_sha1(temp_file.path())
            .await
            .unwrap();
        let sha256_hash = ChecksumCalculator::calculate_sha256(temp_file.path())
            .await
            .unwrap();

        // Verify known hashes for "Hello, World!"
        assert_eq!(md5_hash, "65a8e27d8879283831b664bd8b7f0ad4");
        assert_eq!(sha1_hash, "0a0a9f2a6772942557ab5355d76af442f8f65e01");
        assert_eq!(
            sha256_hash,
            "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"
        );
    }

    #[tokio::test]
    async fn test_integrity_verification() {
        // Create a temporary file
        let mut temp_file = NamedTempFile::new().unwrap();
        let test_content = b"Test content for verification";
        temp_file.write_all(test_content).unwrap();
        temp_file.flush().unwrap();

        // Calculate expected hash
        let expected_hash = ChecksumCalculator::calculate_sha256(temp_file.path())
            .await
            .unwrap();

        // Verify with correct hash
        let result = ChecksumCalculator::verify_integrity(
            temp_file.path(),
            &expected_hash,
            ChecksumAlgorithm::Sha256,
        )
        .await
        .unwrap();

        assert!(result.is_valid);
        assert_eq!(result.expected_hash, expected_hash);
        assert_eq!(result.actual_hash, expected_hash);

        // Verify with incorrect hash
        let wrong_hash = "0000000000000000000000000000000000000000000000000000000000000000";
        let result = ChecksumCalculator::verify_integrity(
            temp_file.path(),
            wrong_hash,
            ChecksumAlgorithm::Sha256,
        )
        .await
        .unwrap();

        assert!(!result.is_valid);
        assert_eq!(result.expected_hash, wrong_hash);
        assert_ne!(result.actual_hash, wrong_hash);
    }

    #[tokio::test]
    async fn test_integrity_manifest() {
        // Create temporary files
        let mut temp_file1 = NamedTempFile::new().unwrap();
        temp_file1.write_all(b"File 1 content").unwrap();
        temp_file1.flush().unwrap();

        let mut temp_file2 = NamedTempFile::new().unwrap();
        temp_file2.write_all(b"File 2 content").unwrap();
        temp_file2.flush().unwrap();

        // Create manifest
        let mut manifest = IntegrityManifest::new();
        manifest.add_file(temp_file1.path()).await.unwrap();
        manifest.add_file(temp_file2.path()).await.unwrap();

        assert_eq!(manifest.files.len(), 2);

        // Verify all files
        let verification_results = manifest.verify_all_files().await.unwrap();
        assert_eq!(verification_results.len(), 2);

        for (_, result) in verification_results {
            assert!(result.is_valid);
        }
    }
}
