//! IPC Interface for Reports Export
//!
//! Handles communication between Qt Dashboard and Rust Agent
//! for report export operations, scheduling, and integrations.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

// use crate::ipc::{IpcMessage, IpcResponse}; // These don't exist yet
use super::export::ExportRequest;
use super::{CompressionType, ExportFormat, ExportManager, ExportResult, ExportStatusCode};

/// IPC request types for export operations
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum ExportIpcRequest {
    /// Export selected reports
    ExportReports {
        report_ids: Vec<String>,
        format: ExportFormat,
        compression: CompressionType,
        output_path: PathBuf,
        include_metadata: bool,
    },
    /// Export all reports
    ExportAllReports {
        format: ExportFormat,
        compression: CompressionType,
        output_path: PathBuf,
        include_metadata: bool,
    },
    /// Purge old reports
    PurgeOldReports { older_than_days: u32 },
    /// Get export status
    GetExportStatus { export_id: String },
    /// Cancel export operation
    CancelExport { export_id: String },
    /// List available reports
    ListReports { filter: Option<ReportFilter> },
}

/// IPC response types for export operations
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum ExportIpcResponse {
    /// Export operation started
    ExportStarted {
        export_id: String,
        estimated_duration: Option<u64>, // seconds
    },
    /// Export operation completed
    ExportCompleted {
        export_id: String,
        result: ExportResult,
    },
    /// Export operation failed
    ExportFailed {
        export_id: String,
        error: String,
        status_code: ExportStatusCode,
    },
    /// Export progress update
    ExportProgress {
        export_id: String,
        progress_percent: f32,
        current_file: Option<String>,
        files_completed: u32,
        total_files: u32,
    },
    /// Purge operation completed
    PurgeCompleted {
        files_removed: u32,
        space_freed: u64, // bytes
    },
    /// Export status information
    ExportStatus {
        export_id: String,
        status: ExportOperationStatus,
    },
    /// List of available reports
    ReportsList {
        reports: Vec<ReportInfo>,
        total_count: u32,
    },
    /// Generic error response
    Error { message: String, code: String },
}

/// Export operation status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExportOperationStatus {
    Pending,
    InProgress {
        progress_percent: f32,
        current_file: Option<String>,
    },
    Completed {
        result: ExportResult,
    },
    Failed {
        error: String,
        status_code: ExportStatusCode,
    },
    Cancelled,
}

/// Report filter for listing operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportFilter {
    pub report_type: Option<String>,
    pub date_from: Option<DateTime<Utc>>,
    pub date_to: Option<DateTime<Utc>>,
    pub min_size: Option<u64>,
    pub max_size: Option<u64>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

/// Report information for listing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportInfo {
    pub id: String,
    pub report_type: String,
    pub title: String,
    pub created_at: DateTime<Utc>,
    pub file_size: u64,
    pub file_path: PathBuf,
    pub metadata: HashMap<String, String>,
}

/// Export operation tracking
#[derive(Debug)]
struct ExportOperation {
    #[allow(dead_code)]
    pub id: String,
    pub status: ExportOperationStatus,
    pub created_at: DateTime<Utc>,
    #[allow(dead_code)]
    pub progress_sender: Option<mpsc::UnboundedSender<ExportProgress>>,
    pub cancel_sender: Option<oneshot::Sender<()>>,
}

/// Export progress information
#[derive(Debug, Clone)]
pub struct ExportProgress {
    pub export_id: String,
    pub progress_percent: f32,
    pub current_file: Option<String>,
    pub files_completed: u32,
    pub total_files: u32,
}

/// Export IPC handler
pub struct ExportIpcHandler {
    export_manager: ExportManager,
    active_operations: HashMap<String, ExportOperation>,
    progress_sender: mpsc::UnboundedSender<ExportIpcResponse>,
}

impl ExportIpcHandler {
    /// Create a new export IPC handler
    pub fn new(progress_sender: mpsc::UnboundedSender<ExportIpcResponse>) -> Self {
        let export_dir = PathBuf::from("/tmp/exports"); // Default export directory
        let max_file_size = 1024 * 1024 * 1024; // 1GB max file size

        Self {
            export_manager: ExportManager::new(export_dir, max_file_size),
            active_operations: HashMap::new(),
            progress_sender,
        }
    }

    /// Handle incoming IPC request
    pub async fn handle_request(&mut self, request: ExportIpcRequest) -> Result<ExportIpcResponse> {
        match request {
            ExportIpcRequest::ExportReports {
                report_ids,
                format,
                compression,
                output_path,
                include_metadata,
            } => {
                self.handle_export_reports(
                    report_ids,
                    format,
                    compression,
                    output_path,
                    include_metadata,
                )
                .await
            }

            ExportIpcRequest::ExportAllReports {
                format,
                compression,
                output_path,
                include_metadata,
            } => {
                // Get all available report IDs
                let all_report_ids = self.get_all_report_ids().await?;
                self.handle_export_reports(
                    all_report_ids,
                    format,
                    compression,
                    output_path,
                    include_metadata,
                )
                .await
            }

            ExportIpcRequest::PurgeOldReports { older_than_days } => {
                self.handle_purge_old_reports(older_than_days).await
            }

            ExportIpcRequest::GetExportStatus { export_id } => {
                self.handle_get_export_status(export_id).await
            }

            ExportIpcRequest::CancelExport { export_id } => {
                self.handle_cancel_export(export_id).await
            }

            ExportIpcRequest::ListReports { filter } => self.handle_list_reports(filter).await,
        }
    }

    /// Handle export reports request
    async fn handle_export_reports(
        &mut self,
        report_ids: Vec<String>,
        format: ExportFormat,
        compression: CompressionType,
        output_path: PathBuf,
        include_metadata: bool,
    ) -> Result<ExportIpcResponse> {
        let export_id = Uuid::new_v4().to_string();

        // Create progress channel
        let (progress_tx, mut progress_rx) = mpsc::unbounded_channel();
        let (cancel_tx, cancel_rx) = oneshot::channel();

        // Create export operation tracking
        let operation = ExportOperation {
            id: export_id.clone(),
            status: ExportOperationStatus::Pending,
            created_at: Utc::now(),
            progress_sender: Some(progress_tx),
            cancel_sender: Some(cancel_tx),
        };

        self.active_operations.insert(export_id.clone(), operation);

        // Create export request
        let export_request = ExportRequest {
            report_ids: report_ids.clone(),
            format,
            compression,
            output_path,
            include_metadata,
        };

        // Start export operation in background
        let export_manager = self.export_manager.clone();
        let export_id_clone = export_id.clone();
        let response_sender = self.progress_sender.clone();

        tokio::spawn(async move {
            // Clone sender for progress updates
            let progress_sender = response_sender.clone();

            // Handle progress updates
            let progress_task = tokio::spawn(async move {
                while let Some(progress) = progress_rx.recv().await {
                    let response = ExportIpcResponse::ExportProgress {
                        export_id: progress.export_id.clone(),
                        progress_percent: progress.progress_percent,
                        current_file: progress.current_file.clone(),
                        files_completed: progress.files_completed,
                        total_files: progress.total_files,
                    };

                    let _ = progress_sender.send(response);
                }
            });

            // Perform export operation
            let result = tokio::select! {
                result = export_manager.export_reports(export_request) => result,
                _ = cancel_rx => {
                    let response = ExportIpcResponse::ExportStatus {
                        export_id: export_id_clone.clone(),
                        status: ExportOperationStatus::Cancelled,
                    };
                    let _ = response_sender.send(response);
                    return;
                }
            };

            // Send completion response
            let response = match result {
                Ok(export_result) => ExportIpcResponse::ExportCompleted {
                    export_id: export_id_clone.clone(),
                    result: export_result,
                },
                Err(e) => ExportIpcResponse::ExportFailed {
                    export_id: export_id_clone.clone(),
                    error: e.to_string(),
                    status_code: ExportStatusCode::ExportFailed,
                },
            };

            let _ = response_sender.send(response);
            progress_task.abort();
        });

        // Estimate duration based on number of reports
        let estimated_duration = Some((report_ids.len() as u64) * 2); // 2 seconds per report estimate

        Ok(ExportIpcResponse::ExportStarted {
            export_id,
            estimated_duration,
        })
    }

    /// Handle purge old reports request
    async fn handle_purge_old_reports(
        &mut self,
        _older_than_days: u32,
    ) -> Result<ExportIpcResponse> {
        // Mock implementation - in real system, this would interact with report storage
        let files_removed = 5; // Mock value
        let space_freed = 1024 * 1024 * 50; // 50MB mock value

        Ok(ExportIpcResponse::PurgeCompleted {
            files_removed,
            space_freed,
        })
    }

    /// Handle get export status request
    async fn handle_get_export_status(&self, export_id: String) -> Result<ExportIpcResponse> {
        if let Some(operation) = self.active_operations.get(&export_id) {
            Ok(ExportIpcResponse::ExportStatus {
                export_id,
                status: operation.status.clone(),
            })
        } else {
            Ok(ExportIpcResponse::Error {
                message: "Export operation not found".to_string(),
                code: "EXPORT_NOT_FOUND".to_string(),
            })
        }
    }

    /// Handle cancel export request
    async fn handle_cancel_export(&mut self, export_id: String) -> Result<ExportIpcResponse> {
        if let Some(mut operation) = self.active_operations.remove(&export_id) {
            if let Some(cancel_sender) = operation.cancel_sender.take() {
                let _ = cancel_sender.send(());
            }

            Ok(ExportIpcResponse::ExportStatus {
                export_id,
                status: ExportOperationStatus::Cancelled,
            })
        } else {
            Ok(ExportIpcResponse::Error {
                message: "Export operation not found".to_string(),
                code: "EXPORT_NOT_FOUND".to_string(),
            })
        }
    }

    /// Handle list reports request
    async fn handle_list_reports(
        &self,
        _filter: Option<ReportFilter>,
    ) -> Result<ExportIpcResponse> {
        // Mock implementation - in real system, this would query the report database
        let reports = vec![
            ReportInfo {
                id: "report_001".to_string(),
                report_type: "Security Scan".to_string(),
                title: "Daily Security Scan Report".to_string(),
                created_at: Utc::now() - chrono::Duration::hours(2),
                file_size: 1024 * 512, // 512KB
                file_path: PathBuf::from("/reports/security_scan_001.json"),
                metadata: HashMap::new(),
            },
            ReportInfo {
                id: "report_002".to_string(),
                report_type: "Threat Detection".to_string(),
                title: "Threat Detection Summary".to_string(),
                created_at: Utc::now() - chrono::Duration::hours(6),
                file_size: 1024 * 256, // 256KB
                file_path: PathBuf::from("/reports/threat_detection_002.json"),
                metadata: HashMap::new(),
            },
        ];

        Ok(ExportIpcResponse::ReportsList {
            total_count: reports.len() as u32,
            reports,
        })
    }

    /// Get all available report IDs
    async fn get_all_report_ids(&self) -> Result<Vec<String>> {
        // Mock implementation - in real system, this would query the report database
        Ok(vec![
            "report_001".to_string(),
            "report_002".to_string(),
            "report_003".to_string(),
        ])
    }

    /// Clean up completed operations
    pub fn cleanup_completed_operations(&mut self) {
        let cutoff_time = Utc::now() - chrono::Duration::hours(1);

        self.active_operations.retain(|_, operation| {
            match &operation.status {
                ExportOperationStatus::Completed { .. }
                | ExportOperationStatus::Failed { .. }
                | ExportOperationStatus::Cancelled => operation.created_at > cutoff_time,
                _ => true, // Keep pending and in-progress operations
            }
        });
    }
}

#[cfg(all(test, feature = "advanced-reporting"))]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_export_ipc_handler_creation() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let handler = ExportIpcHandler::new(tx);

        assert_eq!(handler.active_operations.len(), 0);
    }

    #[tokio::test]
    async fn test_list_reports_request() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut handler = ExportIpcHandler::new(tx);

        let request = ExportIpcRequest::ListReports { filter: None };
        let response = handler.handle_request(request).await.unwrap();

        match response {
            ExportIpcResponse::ReportsList {
                reports,
                total_count,
            } => {
                assert_eq!(total_count, 2);
                assert_eq!(reports.len(), 2);
            }
            _ => panic!("Expected ReportsList response"),
        }
    }

    #[tokio::test]
    async fn test_export_operation_tracking() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut handler = ExportIpcHandler::new(tx);

        let request = ExportIpcRequest::ExportReports {
            report_ids: vec!["test_report".to_string()],
            format: ExportFormat::Json,
            compression: CompressionType::None,
            output_path: PathBuf::from("/tmp/export"),
            include_metadata: false,
        };

        let response = handler.handle_request(request).await.unwrap();

        match response {
            ExportIpcResponse::ExportStarted { export_id, .. } => {
                assert!(handler.active_operations.contains_key(&export_id));
            }
            _ => panic!("Expected ExportStarted response"),
        }
    }
}
