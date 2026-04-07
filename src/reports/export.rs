//! Report Export Module
//!
//! Handles exporting reports in various formats (PDF, CSV, JSON, XML)
//! with optional compression (ZIP, GZIP) and integrity verification.

use crate::reports::rbac::{AccessResult, ReportRBAC, SecurityAuditor, UserIdentity};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::fs;
use uuid::Uuid;

// Re-export modules
// use crate::reports::generators; // Will be used when implementing specific export functionality
// Module imports will be used when implementing specific export functionality
// use crate::reports::formats;
// use crate::reports::compression;
// use crate::reports::integrity;

// Import specific types we need
use crate::reports::compression::{Compressor, GzipCompressor, ZipCompressor};
use crate::reports::formats::{
    CsvExporter, FormatExporter, JsonExporter, PdfExporter, XmlExporter,
};
use crate::reports::integrity::ChecksumCalculator;


/// Export format enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ExportFormat {
    Pdf,
    Csv,
    Json,
    Xml,
}

/// Compression type enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum CompressionType {
    None,
    Zip,
    Gzip,
}

/// Export request structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportRequest {
    pub report_ids: Vec<String>,
    pub format: ExportFormat,
    pub compression: CompressionType,
    pub output_path: PathBuf,
    pub include_metadata: bool,
}

/// Export result structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportResult {
    pub success: bool,
    pub file_path: Option<PathBuf>,
    pub checksum: Option<String>,
    pub file_size: u64,
    pub error_message: Option<String>,
    pub status_code: ExportStatusCode,
}

/// Export status codes
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ExportStatusCode {
    Success,
    PermissionDenied,
    ExportFailed,
    DiskFull,
    InvalidFormat,
    ReportNotFound,
}

/// Report data structure for export
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportData {
    pub id: String,
    pub report_type: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub data: serde_json::Value,
    pub metadata: HashMap<String, String>,
}

/// Main export manager
#[derive(Debug, Clone)]
pub struct ExportManager {
    export_directory: PathBuf,
    #[allow(dead_code)]
    max_file_size: u64,
    rbac: ReportRBAC,
    auditor: SecurityAuditor,
}

impl ExportManager {
    /// Create a new export manager
    pub fn new(export_directory: PathBuf, max_file_size: u64) -> Self {
        Self {
            export_directory,
            max_file_size,
            rbac: ReportRBAC::new(),
            auditor: SecurityAuditor::new(),
        }
    }

    /// Export reports based on the request
    pub async fn export_reports(&self, request: ExportRequest) -> Result<ExportResult> {
        // Validate export directory permissions
        if let Err(e) = self.validate_export_directory().await {
            return Ok(ExportResult {
                success: false,
                file_path: None,
                checksum: None,
                file_size: 0,
                error_message: Some(e.to_string()),
                status_code: ExportStatusCode::PermissionDenied,
            });
        }

        // Load report data
        let reports = match self.load_reports(&request.report_ids).await {
            Ok(reports) => reports,
            Err(e) => {
                return Ok(ExportResult {
                    success: false,
                    file_path: None,
                    checksum: None,
                    file_size: 0,
                    error_message: Some(e.to_string()),
                    status_code: ExportStatusCode::ReportNotFound,
                });
            }
        };

        // Generate unique filename
        let filename = self.generate_filename(&request.format, &request.compression);
        let output_path = request.output_path.join(&filename);

        // Export to specified format
        let export_result = match request.format {
            ExportFormat::Pdf => self.export_to_pdf(&reports, &output_path).await,
            ExportFormat::Csv => self.export_to_csv(&reports, &output_path).await,
            ExportFormat::Json => self.export_to_json(&reports, &output_path).await,
            ExportFormat::Xml => self.export_to_xml(&reports, &output_path).await,
        };

        let final_path = match export_result {
            Ok(path) => path,
            Err(e) => {
                return Ok(ExportResult {
                    success: false,
                    file_path: None,
                    checksum: None,
                    file_size: 0,
                    error_message: Some(e.to_string()),
                    status_code: ExportStatusCode::ExportFailed,
                });
            }
        };

        // Apply compression if requested
        let compressed_path = if request.compression != CompressionType::None {
            match self.compress_file(&final_path, &request.compression).await {
                Ok(path) => {
                    // Remove uncompressed file
                    let _ = fs::remove_file(&final_path).await;
                    path
                }
                Err(e) => {
                    return Ok(ExportResult {
                        success: false,
                        file_path: Some(final_path),
                        checksum: None,
                        file_size: 0,
                        error_message: Some(format!("Compression failed: {}", e)),
                        status_code: ExportStatusCode::ExportFailed,
                    });
                }
            }
        } else {
            final_path
        };

        // Calculate file size and checksum
        let file_size = match fs::metadata(&compressed_path).await {
            Ok(metadata) => metadata.len(),
            Err(_) => 0,
        };

        let checksum = match self.calculate_checksum(&compressed_path).await {
            Ok(checksum) => Some(checksum),
            Err(_) => None,
        };

        Ok(ExportResult {
            success: true,
            file_path: Some(compressed_path),
            checksum,
            file_size,
            error_message: None,
            status_code: ExportStatusCode::Success,
        })
    }

    /// Validate export directory permissions
    async fn validate_export_directory(&self) -> Result<()> {
        // Check if directory exists and is writable
        if !self.export_directory.exists() {
            fs::create_dir_all(&self.export_directory)
                .await
                .context("Failed to create export directory")?;
        }

        // Test write permissions by creating a temporary file
        let test_file = self.export_directory.join(".write_test");
        fs::write(&test_file, b"test")
            .await
            .context("No write permission to export directory")?;
        fs::remove_file(&test_file)
            .await
            .context("Failed to clean up test file")?;

        Ok(())
    }

    /// Load report data from storage
    async fn load_reports(&self, report_ids: &[String]) -> Result<Vec<ReportData>> {
        let mut reports = Vec::new();

        for report_id in report_ids {
            // This would typically load from a database or file system
            // For now, we'll create mock data
            let report = ReportData {
                id: report_id.clone(),
                report_type: "security_scan".to_string(),
                timestamp: chrono::Utc::now(),
                data: serde_json::json!({
                    "scan_results": {
                        "threats_detected": 0,
                        "files_scanned": 1000,
                        "scan_duration": "00:05:30"
                    }
                }),
                metadata: {
                    let mut meta = HashMap::new();
                    meta.insert("version".to_string(), "1.0".to_string());
                    meta.insert("agent_id".to_string(), "agent-001".to_string());
                    meta
                },
            };
            reports.push(report);
        }

        Ok(reports)
    }

    /// Generate unique filename for export
    fn generate_filename(&self, format: &ExportFormat, compression: &CompressionType) -> String {
        let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
        let uuid = Uuid::new_v4().to_string()[..8].to_string();

        let extension = match format {
            ExportFormat::Pdf => "pdf",
            ExportFormat::Csv => "csv",
            ExportFormat::Json => "json",
            ExportFormat::Xml => "xml",
        };

        let final_extension = match compression {
            CompressionType::Zip => format!("{}.zip", extension),
            CompressionType::Gzip => format!("{}.gz", extension),
            CompressionType::None => extension.to_string(),
        };

        format!("erdps_export_{}_{}.{}", timestamp, uuid, final_extension)
    }

    /// Export reports to PDF format
    async fn export_to_pdf(&self, reports: &[ReportData], output_path: &Path) -> Result<PathBuf> {
        PdfExporter::new().export(reports, output_path).await
    }

    /// Export reports to CSV format
    async fn export_to_csv(&self, reports: &[ReportData], output_path: &Path) -> Result<PathBuf> {
        CsvExporter::new().export(reports, output_path).await
    }

    /// Export reports to JSON format
    async fn export_to_json(&self, reports: &[ReportData], output_path: &Path) -> Result<PathBuf> {
        JsonExporter::new().export(reports, output_path).await
    }

    /// Export reports to XML format
    async fn export_to_xml(&self, reports: &[ReportData], output_path: &Path) -> Result<PathBuf> {
        XmlExporter::new().export(reports, output_path).await
    }

    /// Compress exported file
    async fn compress_file(
        &self,
        file_path: &Path,
        compression: &CompressionType,
    ) -> Result<PathBuf> {
        match compression {
            CompressionType::Zip => ZipCompressor::new().compress(file_path).await,
            CompressionType::Gzip => GzipCompressor::new().compress(file_path).await,
            CompressionType::None => Ok(file_path.to_path_buf()),
        }
    }

    /// Calculate file checksum for integrity verification
    async fn calculate_checksum(&self, file_path: &Path) -> Result<String> {
        ChecksumCalculator::calculate_checksum(
            file_path,
            crate::reports::integrity::ChecksumAlgorithm::Sha256,
        )
        .await
        .map(|result| result.hash)
    }

    /// Export a single report (admin-only)
    pub async fn export_single(
        &mut self,
        identity: &UserIdentity,
        report_data: &ReportData,
        format: ExportFormat,
        compression: Option<CompressionType>,
    ) -> Result<ExportResult> {
        // Validate admin access
        if let Err(e) = self.rbac.validate_access(identity, "export_reports") {
            self.auditor.log_access(
                &identity.username,
                "export_single",
                &format!("{:?}", report_data.report_type),
                AccessResult::Denied(e.to_string()),
                None,
                None,
            );
            return Err(e);
        }

        // Create export request for single report
        let request = ExportRequest {
            report_ids: vec![report_data.id.clone()],
            format,
            compression: compression.unwrap_or(CompressionType::None),
            output_path: self.export_directory.clone(),
            include_metadata: true,
        };

        let result = self.export_reports(request).await?;

        self.auditor.log_access(
            &identity.username,
            "export_single",
            &format!("{:?}", report_data.report_type),
            AccessResult::Granted,
            None,
            None,
        );

        Ok(result)
    }

    /// Export multiple reports (admin-only)
    pub async fn export_multiple(
        &mut self,
        identity: &UserIdentity,
        report_data: Vec<&ReportData>,
        format: ExportFormat,
        compression: Option<CompressionType>,
    ) -> Result<Vec<ExportResult>> {
        // Validate admin access
        if let Err(e) = self.rbac.validate_access(identity, "export_reports") {
            self.auditor.log_access(
                &identity.username,
                "export_multiple",
                &format!("bulk_export_{}_reports", report_data.len()),
                AccessResult::Denied(e.to_string()),
                None,
                None,
            );
            return Err(e);
        }

        let mut results = Vec::new();

        for report in report_data {
            let result = self
                .export_single(identity, report, format.clone(), compression.clone())
                .await?;
            results.push(result);
        }

        self.auditor.log_access(
            &identity.username,
            "export_multiple",
            &format!("bulk_export_{}_reports", results.len()),
            AccessResult::Granted,
            None,
            None,
        );

        Ok(results)
    }
}
