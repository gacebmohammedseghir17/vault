use super::*;
use crate::reports::export::{CompressionType, ExportFormat};
use crate::reports::integrations::IntegrationType;
use crate::reports::rbac::{UserIdentity, UserRole};
use crate::reports::scheduling::ScheduleFrequency;
use std::collections::HashMap;
use std::path::PathBuf;
// use std::time::SystemTime; // Unused import

#[cfg(test)]
mod tests {
    use super::*;

    fn create_admin_identity() -> UserIdentity {
        UserIdentity {
            username: "admin_test".to_string(),
            role: UserRole::Administrator,
            permissions: vec![
                ReportPermission::ViewReports,
                ReportPermission::ExportReports,
                ReportPermission::DeleteReports,
                ReportPermission::ManageSchedules,
                ReportPermission::ConfigureIntegrations,
                ReportPermission::PurgeReports,
                ReportPermission::ViewStatistics,
            ],
        }
    }

    fn create_user_identity() -> UserIdentity {
        UserIdentity {
            username: "user_test".to_string(),
            role: UserRole::User, // Regular user role
            permissions: vec![ReportPermission::ViewReports],
        }
    }

    async fn create_test_reports_manager() -> ReportsManager {
        let config = ReportsConfig {
            export_directory: PathBuf::from("/tmp/test_exports"),
            max_concurrent_exports: 3,
            retention_days: 30,
            enable_compression: true,
            enable_checksums: true,
        };
        ReportsManager::new(config, ":memory:").await.unwrap()
    }

    #[tokio::test]
    async fn test_reports_manager_creation() {
        let _manager = create_test_reports_manager().await;
        // Manager should be created successfully
        // No specific assertions needed for creation
    }

    #[tokio::test]
    async fn test_export_single_report_as_admin() {
        let mut manager = create_test_reports_manager().await;
        let admin = create_admin_identity();

        let export_request = ExportRequest {
            report_ids: vec!["report_001".to_string()],
            format: ExportFormat::Pdf,
            compress: true,
            output_path: Some(PathBuf::from("/tmp/test_export.pdf")),
            requester: admin.clone(),
        };

        let result = manager.export_reports(export_request);

        // Should succeed for admin user
        match result {
            Ok(export_result) => {
                assert!(!export_result.export_id.is_empty());
                assert_eq!(export_result.status, ExportStatus::InProgress);
            }
            Err(e) => panic!("Export should succeed for admin: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_export_reports_as_user_denied() {
        let mut manager = create_test_reports_manager().await;
        let user = create_user_identity();

        let export_request = ExportRequest {
            report_ids: vec!["report_001".to_string()],
            format: ExportFormat::Csv,
            compress: false,
            output_path: Some(PathBuf::from("/tmp/test_export")),
            requester: user.clone(),
        };

        let result = manager.export_reports(export_request);

        // Should fail for regular user
        match result {
            Ok(_) => panic!("Export should be denied for regular user"),
            Err(ReportsError::PermissionDenied) => {
                // Expected result
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_export_multiple_reports() {
        let mut manager = create_test_reports_manager().await;
        let admin = create_admin_identity();

        let export_request = ExportRequest {
            report_ids: vec![
                "report_001".to_string(),
                "report_002".to_string(),
                "report_003".to_string(),
            ],
            format: ExportFormat::Json,
            compress: true,
            output_path: Some(PathBuf::from("/tmp/multi_export.zip")),
            requester: admin.clone(),
        };

        let result = manager.export_reports(export_request);

        match result {
            Ok(export_result) => {
                assert!(!export_result.export_id.is_empty());
                assert_eq!(export_result.status, ExportStatus::InProgress);
            }
            Err(e) => panic!("Multi-report export should succeed: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_create_schedule_as_admin() {
        let mut manager = create_test_reports_manager().await;
        let admin = create_admin_identity();

        let schedule_request = ScheduleRequest {
            requester: admin.clone(),
            name: "Daily Security Report".to_string(),
            description: Some("Daily security report".to_string()),
            frequency: ScheduleFrequency::Daily,
            time_of_day: "02:00".to_string(),
            export_format: ExportFormat::Pdf,
            compression: Some(CompressionType::Gzip),
            report_types: vec!["security".to_string()],
            filters: HashMap::new(),
            output_directory: PathBuf::from("/tmp/exports"),
            retention_days: Some(30),
            enabled: true,
        };

        let result = manager.create_schedule(schedule_request);

        match result {
            Ok(schedule_id) => {
                assert!(!schedule_id.is_empty());
            }
            Err(e) => panic!("Schedule creation should succeed for admin: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_create_schedule_as_user_denied() {
        let mut manager = create_test_reports_manager().await;
        let user = create_user_identity();

        let schedule_request = ScheduleRequest {
            requester: user.clone(),
            name: "Unauthorized Schedule".to_string(),
            description: Some("Unauthorized schedule".to_string()),
            frequency: ScheduleFrequency::Weekly,
            time_of_day: "10:00".to_string(),
            export_format: ExportFormat::Csv,
            compression: None,
            report_types: vec![],
            filters: HashMap::new(),
            output_directory: PathBuf::from("/tmp/exports"),
            retention_days: Some(30),
            enabled: true,
        };

        let result = manager.create_schedule(schedule_request);

        match result {
            Ok(_) => panic!("Schedule creation should be denied for regular user"),
            Err(ReportsError::PermissionDenied) => {
                // Expected result
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_add_integration_as_admin() {
        let mut manager = create_test_reports_manager().await;
        let admin = create_admin_identity();

        let integration_request = IntegrationRequest {
            name: "Test SIEM".to_string(),
            integration_type: IntegrationType::Syslog,
            endpoint: "syslog://192.168.1.100:514".to_string(),
            credentials: Some("test_credentials".to_string()),
            format: ExportFormat::Json,
            enabled: true,
            requester: admin.clone(),
        };

        let result = manager.add_integration(integration_request);

        match result {
            Ok(integration_id) => {
                assert!(!integration_id.is_empty());
            }
            Err(e) => panic!("Integration creation should succeed for admin: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_add_integration_as_user_denied() {
        let mut manager = create_test_reports_manager().await;
        let user = create_user_identity();

        let integration_request = IntegrationRequest {
            name: "Unauthorized Integration".to_string(),
            integration_type: IntegrationType::Sftp,
            endpoint: "sftp://example.com".to_string(),
            credentials: None,
            format: ExportFormat::Xml,
            enabled: true,
            requester: user.clone(),
        };

        let result = manager.add_integration(integration_request);

        match result {
            Ok(_) => panic!("Integration creation should be denied for regular user"),
            Err(ReportsError::PermissionDenied) => {
                // Expected result
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_purge_old_reports_as_admin() {
        let mut manager = create_test_reports_manager().await;
        let admin = create_admin_identity();

        let result = manager.purge_old_reports(&admin, 7); // Purge reports older than 7 days

        match result {
            Ok(purged_count) => {
                // Should succeed, count can be 0 if no old reports
                assert!(purged_count >= 0);
            }
            Err(e) => panic!("Purge should succeed for admin: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_purge_old_reports_as_user_denied() {
        let mut manager = create_test_reports_manager().await;
        let user = create_user_identity();

        let result = manager.purge_old_reports(&user, 30);

        match result {
            Ok(_) => panic!("Purge should be denied for regular user"),
            Err(ReportsError::PermissionDenied) => {
                // Expected result
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_get_export_status() {
        let mut manager = create_test_reports_manager().await;
        let admin = create_admin_identity();

        // First create an export
        let export_request = ExportRequest {
            report_ids: vec!["report_status_test".to_string()],
            format: ExportFormat::Pdf,
            compress: false,
            output_path: None,
            requester: admin.clone(),
        };

        let export_result = manager.export_reports(export_request).unwrap();
        let export_id = export_result.export_id;

        // Check status
        let status_result = manager.get_export_status(&export_id);

        match status_result {
            Ok(status) => {
                // Status should be valid (InProgress, Completed, or Failed)
                match status {
                    ExportStatus::InProgress | ExportStatus::Completed | ExportStatus::Failed => {
                        // All valid states
                    }
                }
            }
            Err(e) => panic!("Getting export status should succeed: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_get_export_status_invalid_id() {
        let manager = create_test_reports_manager().await;

        let result = manager.get_export_status("invalid_export_id");

        match result {
            Ok(_) => panic!("Should fail for invalid export ID"),
            Err(ReportsError::ExportNotFound) => {
                // Expected result
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_list_schedules_as_admin() {
        let mut manager = create_test_reports_manager().await;
        let admin = create_admin_identity();

        // Create a schedule first
        let schedule_request = ScheduleRequest {
            requester: admin.clone(),
            name: "List Test Schedule".to_string(),
            description: Some("Test schedule for listing".to_string()),
            frequency: ScheduleFrequency::Monthly,
            time_of_day: "03:00".to_string(),
            report_types: vec!["audit".to_string()],
            export_format: ExportFormat::Csv,
            compression: Some(CompressionType::Gzip),
            filters: HashMap::new(),
            output_directory: PathBuf::from("/tmp/exports"),
            retention_days: Some(30),
            enabled: true,
        };

        let _schedule_id = manager.create_schedule(schedule_request).unwrap();

        // List schedules
        let result = manager.list_schedules(&admin).await;

        match result {
            Ok(schedules) => {
                assert!(schedules.len() >= 1, "Should have at least one schedule");
            }
            Err(e) => panic!("Listing schedules should succeed for admin: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_list_schedules_as_user_denied() {
        let mut manager = create_test_reports_manager().await;
        let user = create_user_identity();

        let result = manager.list_schedules(&user).await;

        match result {
            Ok(_) => panic!("Listing schedules should be denied for regular user"),
            Err(ReportsError::PermissionDenied) => {
                // Expected result
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_list_integrations_as_admin() {
        let mut manager = create_test_reports_manager().await;
        let admin = create_admin_identity();

        // Create an integration first
        let integration_request = IntegrationRequest {
            name: "List Test Integration".to_string(),
            integration_type: IntegrationType::HttpsPost,
            endpoint: "https://api.example.com/reports".to_string(),
            credentials: Some("api_key_123".to_string()),
            format: ExportFormat::Json,
            enabled: true,
            requester: admin.clone(),
        };

        let _integration_id = manager.add_integration(integration_request).unwrap();

        // List integrations
        let result = manager.list_integrations(&admin);

        match result {
            Ok(integrations) => {
                assert!(
                    integrations.len() >= 1,
                    "Should have at least one integration"
                );
            }
            Err(e) => panic!("Listing integrations should succeed for admin: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_list_integrations_as_user_denied() {
        let mut manager = create_test_reports_manager().await;
        let user = create_user_identity();

        let result = manager.list_integrations(&user);

        match result {
            Ok(_) => panic!("Listing integrations should be denied for regular user"),
            Err(ReportsError::PermissionDenied) => {
                // Expected result
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_get_audit_logs_as_admin() {
        let mut manager = create_test_reports_manager().await;
        let admin = create_admin_identity();

        // Perform some operations to generate audit logs
        let export_request = ExportRequest {
            report_ids: vec!["audit_test_report".to_string()],
            format: ExportFormat::Pdf,
            compress: false,
            output_path: None,
            requester: admin.clone(),
        };

        let _export_result = manager.export_reports(export_request);

        // Get audit logs
        let result = manager.get_audit_logs(&admin, 10);

        match result {
            Ok(logs) => {
                assert!(logs.len() >= 1, "Should have at least one audit log entry");
            }
            Err(e) => panic!("Getting audit logs should succeed for admin: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_get_audit_logs_as_user_denied() {
        let manager = create_test_reports_manager().await;
        let user = create_user_identity();

        let result = manager.get_audit_logs(&user, 5);

        match result {
            Ok(_) => panic!("Getting audit logs should be denied for regular user"),
            Err(ReportsError::PermissionDenied) => {
                // Expected result
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_different_export_formats() {
        let mut manager = create_test_reports_manager().await;
        let admin = create_admin_identity();

        let formats = vec![
            ExportFormat::Pdf,
            ExportFormat::Csv,
            ExportFormat::Json,
            ExportFormat::Xml,
        ];

        for format in formats {
            let export_request = ExportRequest {
                report_ids: vec![format!("report_format_{:?}", format)],
                format: format.clone(),
                compress: false,
                output_path: None,
                requester: admin.clone(),
            };

            let result = manager.export_reports(export_request);

            match result {
                Ok(export_result) => {
                    assert!(!export_result.export_id.is_empty());
                }
                Err(e) => panic!("Export with format {:?} should succeed: {:?}", format, e),
            }
        }
    }

    #[tokio::test]
    async fn test_schedule_frequencies() {
        let mut manager = create_test_reports_manager().await;
        let admin = create_admin_identity();

        let frequencies = vec![
            ScheduleFrequency::Daily,
            ScheduleFrequency::Weekly,
            ScheduleFrequency::Monthly,
        ];

        for (i, frequency) in frequencies.iter().enumerate() {
            let schedule_request = ScheduleRequest {
                requester: admin.clone(),
                name: format!("Schedule {:?} {}", frequency, i),
                description: Some("Test schedule".to_string()),
                frequency: frequency.clone(),
                time_of_day: "04:00".to_string(),
                export_format: ExportFormat::Json,
                compression: None,
                report_types: vec![],
                filters: HashMap::new(),
                output_directory: PathBuf::from("/tmp/exports"),
                retention_days: Some(30),
                enabled: true,
            };

            let result = manager.create_schedule(schedule_request);

            match result {
                Ok(schedule_id) => {
                    assert!(!schedule_id.is_empty());
                }
                Err(e) => panic!(
                    "Schedule with frequency {:?} should succeed: {:?}",
                    frequency, e
                ),
            }
        }
    }

    #[tokio::test]
    async fn test_integration_types() {
        let mut manager = create_test_reports_manager().await;
        let admin = create_admin_identity();

        let integration_types = vec![
            (IntegrationType::Syslog, "syslog://localhost:514"),
            (
                IntegrationType::HttpsPost,
                "https://api.example.com/reports",
            ),
            (IntegrationType::Sftp, "sftp://files.example.com/reports"),
        ];

        for (i, (integration_type, endpoint)) in integration_types.iter().enumerate() {
            let integration_request = IntegrationRequest {
                name: format!("Integration {:?} {}", integration_type, i),
                integration_type: integration_type.clone(),
                endpoint: endpoint.to_string(),
                credentials: Some("test_creds".to_string()),
                format: ExportFormat::Json,
                enabled: true,
                requester: admin.clone(),
            };

            let result = manager.add_integration(integration_request);

            match result {
                Ok(integration_id) => {
                    assert!(!integration_id.is_empty());
                }
                Err(e) => panic!(
                    "Integration with type {:?} should succeed: {:?}",
                    integration_type, e
                ),
            }
        }
    }

    #[tokio::test]
    async fn test_reports_manager_configuration() {
        let config = ReportsConfig {
            export_directory: PathBuf::from("/custom/export/path"),
            max_concurrent_exports: 5,
            retention_days: 60,
            enable_compression: false,
            enable_checksums: false,
        };

        let _manager = ReportsManager::new(config, ":memory:").await.unwrap();

        // Manager should be created with custom configuration
        // No specific assertions needed for creation with custom config
    }

    #[tokio::test]
    async fn test_concurrent_export_limit() {
        let mut manager = create_test_reports_manager().await;
        let admin = create_admin_identity();

        // Try to create multiple exports (up to the limit)
        let mut export_ids = Vec::new();

        for i in 0..3 {
            // Max concurrent is 3 in test config
            let export_request = ExportRequest {
                report_ids: vec![format!("concurrent_report_{}", i)],
                format: ExportFormat::Pdf,
                compress: false,
                output_path: None,
                requester: admin.clone(),
            };

            let result = manager.export_reports(export_request);

            match result {
                Ok(export_result) => {
                    export_ids.push(export_result.export_id);
                }
                Err(e) => panic!("Export {} should succeed: {:?}", i, e),
            }
        }

        assert_eq!(
            export_ids.len(),
            3,
            "Should have created 3 concurrent exports"
        );
    }

    #[tokio::test]
    async fn test_error_handling() {
        let mut manager = create_test_reports_manager().await;

        // Test various error conditions

        // Invalid export ID
        let status_result = manager.get_export_status("nonexistent_id");
        assert!(matches!(status_result, Err(ReportsError::ExportNotFound)));

        // Empty report IDs
        let admin = create_admin_identity();
        let export_request = ExportRequest {
            report_ids: vec![], // Empty list
            format: ExportFormat::Pdf,
            compress: false,
            output_path: None,
            requester: admin.clone(),
        };

        let result = manager.export_reports(export_request);
        assert!(result.is_err(), "Export with empty report IDs should fail");
    }
}
