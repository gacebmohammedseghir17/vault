use super::*;
use std::time::SystemTime;

#[cfg(test)]
mod tests {
    use super::*;

    fn create_admin_identity() -> UserIdentity {
        UserIdentity {
            username: "admin_user".to_string(),
            role: UserRole::Administrator,
        }
    }

    fn create_user_identity() -> UserIdentity {
        UserIdentity {
            username: "regular_user".to_string(),
            role: UserRole::User,
        }
    }

    fn create_rbac() -> ReportRBAC {
        ReportRBAC::new()
    }

    fn create_auditor() -> SecurityAuditor {
        SecurityAuditor::new()
    }

    #[test]
    fn test_rbac_creation() {
        let rbac = create_rbac();
        // RBAC should be created successfully
        // No specific assertions needed for creation
    }

    #[test]
    fn test_admin_has_all_permissions() {
        let rbac = create_rbac();
        let admin = create_admin_identity();
        
        let permissions = vec![
            ReportPermission::Export,
            ReportPermission::ManageSchedules,
            ReportPermission::ConfigureIntegrations,
            ReportPermission::PurgeReports,
            ReportPermission::ViewReports,
        ];

        for permission in permissions {
            assert!(rbac.has_permission(&admin, permission), 
                   "Admin should have {:?} permission", permission);
        }
    }

    #[test]
    fn test_user_has_limited_permissions() {
        let rbac = create_rbac();
        let user = create_user_identity();
        
        // Users should only have view permission
        assert!(rbac.has_permission(&user, ReportPermission::ViewReports));
        
        // Users should NOT have admin permissions
        let admin_permissions = vec![
            ReportPermission::Export,
            ReportPermission::ManageSchedules,
            ReportPermission::ConfigureIntegrations,
            ReportPermission::PurgeReports,
        ];

        for permission in admin_permissions {
            assert!(!rbac.has_permission(&user, permission), 
                   "Regular user should NOT have {:?} permission", permission);
        }
    }

    #[test]
    fn test_validate_access_admin_granted() {
        let rbac = create_rbac();
        let admin = create_admin_identity();
        
        let admin_permissions = vec![
            ReportPermission::Export,
            ReportPermission::ManageSchedules,
            ReportPermission::ConfigureIntegrations,
            ReportPermission::PurgeReports,
            ReportPermission::ViewReports,
        ];

        for permission in admin_permissions {
            let result = rbac.validate_access(&admin, permission);
            assert_eq!(result, AccessResult::Granted, 
                      "Admin access should be granted for {:?}", permission);
        }
    }

    #[test]
    fn test_validate_access_user_denied() {
        let rbac = create_rbac();
        let user = create_user_identity();
        
        let admin_permissions = vec![
            ReportPermission::Export,
            ReportPermission::ManageSchedules,
            ReportPermission::ConfigureIntegrations,
            ReportPermission::PurgeReports,
        ];

        for permission in admin_permissions {
            let result = rbac.validate_access(&user, permission);
            assert_eq!(result, AccessResult::Denied, 
                      "User access should be denied for {:?}", permission);
        }
    }

    #[test]
    fn test_validate_access_user_view_granted() {
        let rbac = create_rbac();
        let user = create_user_identity();
        
        let result = rbac.validate_access(&user, ReportPermission::ViewReports);
        assert_eq!(result, AccessResult::Granted, 
                  "User should have view permission");
    }

    #[test]
    fn test_can_export_permissions() {
        let rbac = create_rbac();
        let admin = create_admin_identity();
        let user = create_user_identity();
        
        assert!(rbac.can_export(&admin), "Admin should be able to export");
        assert!(!rbac.can_export(&user), "Regular user should not be able to export");
    }

    #[test]
    fn test_can_manage_schedules_permissions() {
        let rbac = create_rbac();
        let admin = create_admin_identity();
        let user = create_user_identity();
        
        assert!(rbac.can_manage_schedules(&admin), "Admin should be able to manage schedules");
        assert!(!rbac.can_manage_schedules(&user), "Regular user should not be able to manage schedules");
    }

    #[test]
    fn test_can_configure_integrations_permissions() {
        let rbac = create_rbac();
        let admin = create_admin_identity();
        let user = create_user_identity();
        
        assert!(rbac.can_configure_integrations(&admin), "Admin should be able to configure integrations");
        assert!(!rbac.can_configure_integrations(&user), "Regular user should not be able to configure integrations");
    }

    #[test]
    fn test_can_purge_reports_permissions() {
        let rbac = create_rbac();
        let admin = create_admin_identity();
        let user = create_user_identity();
        
        assert!(rbac.can_purge_reports(&admin), "Admin should be able to purge reports");
        assert!(!rbac.can_purge_reports(&user), "Regular user should not be able to purge reports");
    }

    #[test]
    fn test_security_auditor_creation() {
        let auditor = create_auditor();
        // Auditor should be created successfully
        // No specific assertions needed for creation
    }

    #[test]
    fn test_log_access_attempt() {
        let mut auditor = create_auditor();
        let admin = create_admin_identity();
        
        let result = auditor.log_access(
            &admin,
            ReportPermission::Export,
            AccessResult::Granted,
            "export_reports",
        );
        
        assert!(result.is_ok(), "Logging access attempt should succeed");
    }

    #[test]
    fn test_log_multiple_access_attempts() {
        let mut auditor = create_auditor();
        let admin = create_admin_identity();
        let user = create_user_identity();
        
        // Log successful admin access
        let result1 = auditor.log_access(
            &admin,
            ReportPermission::Export,
            AccessResult::Granted,
            "export_selected_reports",
        );
        assert!(result1.is_ok());
        
        // Log denied user access
        let result2 = auditor.log_access(
            &user,
            ReportPermission::Export,
            AccessResult::Denied,
            "export_selected_reports",
        );
        assert!(result2.is_ok());
        
        // Log admin schedule management
        let result3 = auditor.log_access(
            &admin,
            ReportPermission::ManageSchedules,
            AccessResult::Granted,
            "create_schedule",
        );
        assert!(result3.is_ok());
    }

    #[test]
    fn test_get_audit_logs() {
        let mut auditor = create_auditor();
        let admin = create_admin_identity();
        let user = create_user_identity();
        
        // Log some access attempts
        auditor.log_access(
            &admin,
            ReportPermission::Export,
            AccessResult::Granted,
            "export_reports",
        ).unwrap();
        
        auditor.log_access(
            &user,
            ReportPermission::ConfigureIntegrations,
            AccessResult::Denied,
            "add_integration",
        ).unwrap();
        
        // Retrieve audit logs
        let logs = auditor.get_audit_logs(10).unwrap();
        assert_eq!(logs.len(), 2, "Should have 2 audit log entries");
        
        // Check first log (most recent)
        let recent_log = &logs[0];
        assert_eq!(recent_log.username, "regular_user");
        assert_eq!(recent_log.permission, ReportPermission::ConfigureIntegrations);
        assert_eq!(recent_log.result, AccessResult::Denied);
        assert_eq!(recent_log.action, "add_integration");
        
        // Check second log
        let older_log = &logs[1];
        assert_eq!(older_log.username, "admin_user");
        assert_eq!(older_log.permission, ReportPermission::Export);
        assert_eq!(older_log.result, AccessResult::Granted);
        assert_eq!(older_log.action, "export_reports");
    }

    #[test]
    fn test_get_audit_logs_with_limit() {
        let mut auditor = create_auditor();
        let admin = create_admin_identity();
        
        // Log multiple access attempts
        for i in 0..5 {
            auditor.log_access(
                &admin,
                ReportPermission::ViewReports,
                AccessResult::Granted,
                &format!("view_report_{}", i),
            ).unwrap();
        }
        
        // Test different limits
        let logs_3 = auditor.get_audit_logs(3).unwrap();
        assert_eq!(logs_3.len(), 3, "Should return exactly 3 logs when limit is 3");
        
        let logs_10 = auditor.get_audit_logs(10).unwrap();
        assert_eq!(logs_10.len(), 5, "Should return all 5 logs when limit is higher");
        
        let logs_1 = auditor.get_audit_logs(1).unwrap();
        assert_eq!(logs_1.len(), 1, "Should return exactly 1 log when limit is 1");
    }

    #[test]
    fn test_audit_log_timestamps() {
        let mut auditor = create_auditor();
        let admin = create_admin_identity();
        
        let before_log = SystemTime::now();
        
        auditor.log_access(
            &admin,
            ReportPermission::Export,
            AccessResult::Granted,
            "timestamp_test",
        ).unwrap();
        
        let after_log = SystemTime::now();
        
        let logs = auditor.get_audit_logs(1).unwrap();
        assert_eq!(logs.len(), 1);
        
        let log_timestamp = logs[0].timestamp;
        assert!(log_timestamp >= before_log, "Log timestamp should be after the before timestamp");
        assert!(log_timestamp <= after_log, "Log timestamp should be before the after timestamp");
    }

    #[test]
    fn test_different_user_roles() {
        let rbac = create_rbac();
        
        // Test different user roles
        let admin = UserIdentity {
            username: "admin".to_string(),
            role: UserRole::Administrator,
        };
        
        let user = UserIdentity {
            username: "user".to_string(),
            role: UserRole::User,
        };
        
        // Admin should have export permission
        assert_eq!(rbac.validate_access(&admin, ReportPermission::Export), AccessResult::Granted);
        
        // User should not have export permission
        assert_eq!(rbac.validate_access(&user, ReportPermission::Export), AccessResult::Denied);
    }

    #[test]
    fn test_permission_enum_completeness() {
        let rbac = create_rbac();
        let admin = create_admin_identity();
        
        // Ensure all permission variants are tested
        let all_permissions = vec![
            ReportPermission::ViewReports,
            ReportPermission::Export,
            ReportPermission::ManageSchedules,
            ReportPermission::ConfigureIntegrations,
            ReportPermission::PurgeReports,
        ];
        
        for permission in all_permissions {
            // Admin should have all permissions
            assert_eq!(rbac.validate_access(&admin, permission), AccessResult::Granted,
                      "Admin should have {:?} permission", permission);
        }
    }

    #[test]
    fn test_access_result_enum() {
        // Test AccessResult enum variants
        assert_eq!(AccessResult::Granted, AccessResult::Granted);
        assert_eq!(AccessResult::Denied, AccessResult::Denied);
        assert_ne!(AccessResult::Granted, AccessResult::Denied);
    }

    #[test]
    fn test_user_role_enum() {
        // Test UserRole enum variants
        assert_eq!(UserRole::Administrator, UserRole::Administrator);
        assert_eq!(UserRole::User, UserRole::User);
        assert_ne!(UserRole::Administrator, UserRole::User);
    }

    #[test]
    fn test_security_audit_log_fields() {
        let mut auditor = create_auditor();
        let admin = create_admin_identity();
        
        auditor.log_access(
            &admin,
            ReportPermission::PurgeReports,
            AccessResult::Granted,
            "purge_old_reports",
        ).unwrap();
        
        let logs = auditor.get_audit_logs(1).unwrap();
        let log = &logs[0];
        
        // Verify all fields are properly set
        assert!(!log.id.is_empty(), "Log ID should not be empty");
        assert_eq!(log.username, "admin_user");
        assert_eq!(log.permission, ReportPermission::PurgeReports);
        assert_eq!(log.result, AccessResult::Granted);
        assert_eq!(log.action, "purge_old_reports");
        assert!(log.timestamp <= SystemTime::now(), "Timestamp should be valid");
    }

    #[test]
    fn test_rbac_integration_with_auditor() {
        let rbac = create_rbac();
        let mut auditor = create_auditor();
        let user = create_user_identity();
        
        // Simulate a complete access check with auditing
        let permission = ReportPermission::ConfigureIntegrations;
        let action = "add_siem_integration";
        
        // Check permission
        let access_result = rbac.validate_access(&user, permission);
        
        // Log the access attempt
        let log_result = auditor.log_access(&user, permission, access_result, action);
        
        // Verify both operations succeeded
        assert_eq!(access_result, AccessResult::Denied);
        assert!(log_result.is_ok());
        
        // Verify the log was recorded
        let logs = auditor.get_audit_logs(1).unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].result, AccessResult::Denied);
    }

    #[test]
    fn test_empty_audit_logs() {
        let auditor = create_auditor();
        
        // Get logs when none exist
        let logs = auditor.get_audit_logs(10).unwrap();
        assert_eq!(logs.len(), 0, "Should return empty vector when no logs exist");
    }

    #[test]
    fn test_audit_log_ordering() {
        let mut auditor = create_auditor();
        let admin = create_admin_identity();
        
        // Log multiple entries with slight delays to ensure different timestamps
        auditor.log_access(
            &admin,
            ReportPermission::ViewReports,
            AccessResult::Granted,
            "first_action",
        ).unwrap();
        
        std::thread::sleep(std::time::Duration::from_millis(1));
        
        auditor.log_access(
            &admin,
            ReportPermission::Export,
            AccessResult::Granted,
            "second_action",
        ).unwrap();
        
        std::thread::sleep(std::time::Duration::from_millis(1));
        
        auditor.log_access(
            &admin,
            ReportPermission::ManageSchedules,
            AccessResult::Granted,
            "third_action",
        ).unwrap();
        
        let logs = auditor.get_audit_logs(3).unwrap();
        assert_eq!(logs.len(), 3);
        
        // Logs should be ordered by timestamp (most recent first)
        assert_eq!(logs[0].action, "third_action");
        assert_eq!(logs[1].action, "second_action");
        assert_eq!(logs[2].action, "first_action");
        
        // Verify timestamp ordering
        assert!(logs[0].timestamp >= logs[1].timestamp);
        assert!(logs[1].timestamp >= logs[2].timestamp);
    }
}
