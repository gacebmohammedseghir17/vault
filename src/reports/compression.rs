//! Compression Module
//!
//! Handles compression of exported report files using ZIP and GZIP formats.

use anyhow::{Context, Result};
use flate2::write::GzEncoder;
use flate2::Compression;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use tokio::fs;
use zip::write::{FileOptions, ZipWriter};
use zip::CompressionMethod;

/// Trait for compression implementations
#[async_trait::async_trait]
pub trait Compressor {
    async fn compress(&self, file_path: &Path) -> Result<PathBuf>;
}

/// ZIP compression implementation
pub struct ZipCompressor;

impl ZipCompressor {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl Compressor for ZipCompressor {
    async fn compress(&self, file_path: &Path) -> Result<PathBuf> {
        let output_path = file_path.with_extension(format!(
            "{}.zip",
            file_path
                .extension()
                .and_then(|ext| ext.to_str())
                .unwrap_or("dat")
        ));

        // Read the input file
        let input_file =
            File::open(file_path).context("Failed to open input file for compression")?;
        let mut reader = BufReader::new(input_file);

        // Create ZIP file
        let output_file = File::create(&output_path).context("Failed to create ZIP output file")?;
        let mut zip_writer = ZipWriter::new(BufWriter::new(output_file));

        // Get the filename for the ZIP entry
        let filename = file_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("export_file");

        // Configure compression options
        let options = FileOptions::default()
            .compression_method(CompressionMethod::Deflated)
            .unix_permissions(0o644);

        // Start file entry in ZIP
        zip_writer
            .start_file(filename, options)
            .context("Failed to start ZIP file entry")?;

        // Copy file content to ZIP
        let mut buffer = Vec::new();
        reader
            .read_to_end(&mut buffer)
            .context("Failed to read input file content")?;

        zip_writer
            .write_all(&buffer)
            .context("Failed to write content to ZIP")?;

        // Finish ZIP file
        zip_writer.finish().context("Failed to finalize ZIP file")?;

        Ok(output_path)
    }
}

/// GZIP compression implementation
pub struct GzipCompressor;

impl GzipCompressor {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl Compressor for GzipCompressor {
    async fn compress(&self, file_path: &Path) -> Result<PathBuf> {
        let output_path = file_path.with_extension(format!(
            "{}.gz",
            file_path
                .extension()
                .and_then(|ext| ext.to_str())
                .unwrap_or("dat")
        ));

        // Read the input file
        let input_file =
            File::open(file_path).context("Failed to open input file for compression")?;
        let mut reader = BufReader::new(input_file);

        // Create GZIP encoder
        let output_file =
            File::create(&output_path).context("Failed to create GZIP output file")?;
        let mut encoder = GzEncoder::new(BufWriter::new(output_file), Compression::default());

        // Copy and compress data
        let mut buffer = [0u8; 8192]; // 8KB buffer
        loop {
            let bytes_read = reader
                .read(&mut buffer)
                .context("Failed to read from input file")?;

            if bytes_read == 0 {
                break;
            }

            encoder
                .write_all(&buffer[..bytes_read])
                .context("Failed to write compressed data")?;
        }

        // Finish compression
        encoder
            .finish()
            .context("Failed to finalize GZIP compression")?;

        Ok(output_path)
    }
}

/// Compression utility functions
pub struct CompressionUtils;

impl CompressionUtils {
    /// Get compression ratio for a compressed file
    pub async fn get_compression_ratio(
        original_path: &Path,
        compressed_path: &Path,
    ) -> Result<f64> {
        let original_size = fs::metadata(original_path)
            .await
            .context("Failed to get original file metadata")?
            .len();

        let compressed_size = fs::metadata(compressed_path)
            .await
            .context("Failed to get compressed file metadata")?
            .len();

        if original_size == 0 {
            return Ok(0.0);
        }

        Ok(compressed_size as f64 / original_size as f64)
    }

    /// Estimate compression time based on file size
    pub fn estimate_compression_time(file_size: u64) -> std::time::Duration {
        // Rough estimate: 1MB per second for compression
        let seconds = (file_size as f64 / (1024.0 * 1024.0)).ceil() as u64;
        std::time::Duration::from_secs(seconds.max(1))
    }

    /// Check if compression is beneficial for the file type
    pub fn should_compress(file_path: &Path) -> bool {
        if let Some(extension) = file_path.extension().and_then(|ext| ext.to_str()) {
            match extension.to_lowercase().as_str() {
                // Already compressed formats
                "zip" | "gz" | "bz2" | "xz" | "7z" => false,
                // Image formats (already compressed)
                "jpg" | "jpeg" | "png" | "gif" | "webp" => false,
                // Video formats (already compressed)
                "mp4" | "avi" | "mkv" | "mov" => false,
                // Audio formats (already compressed)
                "mp3" | "aac" | "ogg" | "flac" => false,
                // Text and data formats (good for compression)
                "txt" | "csv" | "json" | "xml" | "pdf" | "log" => true,
                // Default: compress
                _ => true,
            }
        } else {
            // No extension: assume it's worth compressing
            true
        }
    }
}

#[cfg(all(test, feature = "advanced-reporting"))]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_zip_compression() {
        // Create a temporary file with test content
        let mut temp_file = NamedTempFile::new().unwrap();
        let test_content = "This is a test file for ZIP compression. ".repeat(100);
        temp_file.write_all(test_content.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let compressor = ZipCompressor::new();
        let compressed_path = compressor.compress(temp_file.path()).await.unwrap();

        // Verify compressed file exists and is smaller
        assert!(compressed_path.exists());
        let original_size = std::fs::metadata(temp_file.path()).unwrap().len();
        let compressed_size = std::fs::metadata(&compressed_path).unwrap().len();
        assert!(compressed_size < original_size);

        // Clean up
        std::fs::remove_file(&compressed_path).unwrap();
    }

    #[tokio::test]
    async fn test_gzip_compression() {
        // Create a temporary file with test content
        let mut temp_file = NamedTempFile::new().unwrap();
        let test_content = "This is a test file for GZIP compression. ".repeat(100);
        temp_file.write_all(test_content.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let compressor = GzipCompressor::new();
        let compressed_path = compressor.compress(temp_file.path()).await.unwrap();

        // Verify compressed file exists and is smaller
        assert!(compressed_path.exists());
        let original_size = std::fs::metadata(temp_file.path()).unwrap().len();
        let compressed_size = std::fs::metadata(&compressed_path).unwrap().len();
        assert!(compressed_size < original_size);

        // Clean up
        std::fs::remove_file(&compressed_path).unwrap();
    }

    #[test]
    fn test_should_compress() {
        assert!(CompressionUtils::should_compress(Path::new("test.txt")));
        assert!(CompressionUtils::should_compress(Path::new("data.csv")));
        assert!(CompressionUtils::should_compress(Path::new("report.json")));
        assert!(CompressionUtils::should_compress(Path::new("export.xml")));

        assert!(!CompressionUtils::should_compress(Path::new("archive.zip")));
        assert!(!CompressionUtils::should_compress(Path::new("image.jpg")));
        assert!(!CompressionUtils::should_compress(Path::new("video.mp4")));
        assert!(!CompressionUtils::should_compress(Path::new("audio.mp3")));
    }
}
