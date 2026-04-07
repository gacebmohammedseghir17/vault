use super::*;
use crate::reports::rbac::{UserIdentity, UserRole};
use std::path::PathBuf;
use tempfile::TempDir;

#[cfg(test)]
mod tests {
    use super::*;

    fn create_admin_identity() -> UserIdentity {
        UserIdentity {
            username: "admin".to_string(),
            role: UserRole::Administrator,
        }
    }

    fn create_user_identity() -> UserIdentity {
        UserIdentity {
            username: "user".to_string(),
            role: UserRole::User,
        }
    }

    fn create_test_manager() -> ExportManager {
        let temp_dir = TempDir::new().unwrap();
        ExportManager::new(temp_dir.path().to_path_buf(), 1000)
    }

    fn create_test_report_data() -> ReportData {
        use std::collections::HashMap;
        ReportData {
            id: "test_report_001".to_string(),
            report_type: "security_scan".to_string(),
            timestamp: chrono::Utc::now(),
            data: serde_json::json!({
                "scan_results": {
                    "threats_detected": 0,
                    "files_scanned": 1000
                }
            }),
            metadata: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn test_export_manager_creation() {
        let export_dir = PathBuf::from("/tmp/exports");
        let manager = ExportManager::new(export_dir.clone(), 1000);
        
        // Manager should be created successfully - just verify it was created
        drop(manager); // Ensure manager is used
    }

    #[tokio::test]
    async fn test_single_report_export() {
        let mut manager = create_test_manager();
        let admin = create_admin_identity();
        let report_data = create_test_report_data();
        
        let result = manager.export_single(
            &admin,
            &report_data,
            ExportFormat::Pdf,
            Some(CompressionType::None),
        ).await;
        
        assert!(result.is_ok());
        let export_result = result.unwrap();
        assert!(export_result.success);
        assert!(export_result.file_path.is_some());
    }

    #[tokio::test]
    async fn test_single_report_export_unauthorized() {
        let mut manager = create_test_manager();
        let user = create_user_identity();
        let report_data = create_test_report_data();
        
        let result = manager.export_single(
            &user,
            &report_data,
            ExportFormat::Pdf,
            Some(CompressionType::None),
        ).await;
        
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_multiple_reports_export() {
        let mut manager = create_test_manager();
        let admin = create_admin_identity();
        
        let reports = vec![
            create_test_report_data(),
            ReportData {
                id: "test_report_002".to_string(),
                report_type: "vulnerability_scan".to_string(),
                timestamp: chrono::Utc::now(),
                data: serde_json::json!({"vulnerabilities": []}),
                metadata: std::collections::HashMap::new(),
            },
        ];
        
        let report_refs: Vec<&ReportData> = reports.iter().collect();
        
        let result = manager.export_multiple(
            &admin,
            report_refs,
            ExportFormat::Json,
            Some(CompressionType::Zip),
        ).await;
        
        assert!(result.is_ok());
        let export_results = result.unwrap();
        assert_eq!(export_results.len(), 2);
        for export_result in export_results {
            assert!(export_result.success);
        }
    }

    #[tokio::test]
    async fn test_export_with_compression() {
        let mut manager = create_test_manager();
        let admin = create_admin_identity();
        let report_data = create_test_report_data();
        
        let result = manager.export_single(
            &admin,
            &report_data,
            ExportFormat::Csv,
            Some(CompressionType::Gzip),
        ).await;
        
        assert!(result.is_ok());
        let export_result = result.unwrap();
        assert!(export_result.success);
        assert!(export_result.file_path.is_some());
    }

    #[tokio::test]
    async fn test_export_format_conversion() {
        let mut manager = create_test_manager();
        let admin = create_admin_identity();
        let report_data = create_test_report_data();
        
        let formats = vec![
            ExportFormat::Pdf,
            ExportFormat::Csv,
            ExportFormat::Json,
            ExportFormat::Xml,
        ];
        
        for format in formats {
            let result = manager.export_single(
                &admin,
                &report_data,
                format,
                Some(CompressionType::None),
            ).await;
            
            assert!(result.is_ok(), "Export with format {:?} should succeed", format);
        }
    }

    #[tokio::test]
    async fn test_export_checksum_generation() {
        let mut manager = create_test_manager();
        let admin = create_admin_identity();
        let report_data = create_test_report_data();
        
        let result = manager.export_single(
            &admin,
            &report_data,
            ExportFormat::Json,
            Some(CompressionType::None),
        ).await;
        
        assert!(result.is_ok());
        let export_result = result.unwrap();
        assert!(export_result.success);
        assert!(export_result.checksum.is_some());
        assert!(!export_result.checksum.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_export_reports_async() {
        let manager = create_test_manager();
        let temp_dir = TempDir::new().unwrap();
        
        let request = ExportRequest {
            report_ids: vec!["report_001".to_string(), "report_002".to_string()],
            format: ExportFormat::Json,
            compression: CompressionType::None,
            output_path: temp_dir.path().to_path_buf(),
            include_metadata: true,
        };
        
        let result = manager.export_reports(request).await;
        
        assert!(result.is_ok());
        let export_result = result.unwrap();
        assert!(export_result.success);
        assert!(export_result.file_path.is_some());
    }

    #[tokio::test]
    async fn test_streaming_export_large_files() {
        let manager = create_test_manager();
        let temp_dir = TempDir::new().unwrap();
        
        // Simulate large file export
        let request = ExportRequest {
            report_ids: (0..100).map(|i| format!("large_report_{:03}", i)).collect(),
            format: ExportFormat::Csv,
            compression: CompressionType::Zip,
            output_path: temp_dir.path().to_path_buf(),
            include_metadata: false,
        };
        
        let result = manager.export_reports(request).await;
        
        assert!(result.is_ok());
        let export_result = result.unwrap();
        assert!(export_result.success);
        assert!(export_result.file_size > 0);
    }
}
