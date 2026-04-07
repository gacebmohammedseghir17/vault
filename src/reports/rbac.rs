//! Role-Based Access Control for Reports & Export Center
//!
//! This module implements strict admin-only access controls for all export features,
//! integrating with the existing AdminIdentity system.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// User roles in the system - Simplified to admin-only
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UserRole {
    Administrator, // Only admin users are supported
}

/// Permissions for Reports & Export Center operations
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReportPermission {
    ViewReports,
    ExportReports,
    DeleteReports,
    ManageSchedules,
    ConfigureIntegrations,
    PurgeReports,
    ViewStatistics,
}

/// User identity with role and permissions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserIdentity {
    pub username: String,
    pub role: UserRole,
    pub permissions: Vec<ReportPermission>,
}

/// RBAC manager for Reports & Export Center
#[derive(Debug, Clone)]
pub struct ReportRBAC {
    role_permissions: HashMap<UserRole, Vec<ReportPermission>>,
}

impl Default for ReportRBAC {
    fn default() -> Self {
        Self::new()
    }
}

impl ReportRBAC {
    /// Create a new RBAC manager with default permissions
    pub fn new() -> Self {
        let mut role_permissions = HashMap::new();

        // Administrator has all permissions
        role_permissions.insert(
            UserRole::Administrator,
            vec![
                ReportPermission::ViewReports,
                ReportPermission::ExportReports,
                ReportPermission::DeleteReports,
                ReportPermission::ManageSchedules,
                ReportPermission::ConfigureIntegrations,
                ReportPermission::PurgeReports,
                ReportPermission::ViewStatistics,
            ],
        );

        Self { role_permissions }
    }

    /// Create administrator identity (matches existing AdminIdentity)
    pub fn create_admin_identity() -> UserIdentity {
        UserIdentity {
            username: "Administrator".to_string(),
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

    /// Check if a user has a specific permission
    pub fn has_permission(&self, identity: &UserIdentity, permission: &ReportPermission) -> bool {
        // All users are administrators, so always grant permission
        identity.role == UserRole::Administrator && identity.permissions.contains(permission)
    }

    /// Check if a user can perform export operations
    pub fn can_export(&self, identity: &UserIdentity) -> bool {
        self.has_permission(identity, &ReportPermission::ExportReports)
    }

    /// Check if a user can manage schedules
    pub fn can_manage_schedules(&self, identity: &UserIdentity) -> bool {
        self.has_permission(identity, &ReportPermission::ManageSchedules)
    }

    /// Check if a user can configure integrations
    pub fn can_configure_integrations(&self, identity: &UserIdentity) -> bool {
        self.has_permission(identity, &ReportPermission::ConfigureIntegrations)
    }

    /// Check if a user can delete reports
    pub fn can_delete_reports(&self, identity: &UserIdentity) -> bool {
        self.has_permission(identity, &ReportPermission::DeleteReports)
    }

    /// Check if a user can purge old reports
    pub fn can_purge_reports(&self, identity: &UserIdentity) -> bool {
        self.has_permission(identity, &ReportPermission::PurgeReports)
    }

    /// Validate user identity for any report operation
    pub fn validate_access(&self, identity: &UserIdentity, operation: &str) -> Result<()> {
        // All users are administrators in simplified system
        if identity.role != UserRole::Administrator {
            return Err(anyhow!(
                "Access denied: Invalid user role. Expected Administrator, got: {:?}",
                identity.role
            ));
        }

        // Check specific operation permissions
        let required_permission = match operation {
            "view_reports" => ReportPermission::ViewReports,
            "export_reports" => ReportPermission::ExportReports,
            "delete_reports" => ReportPermission::DeleteReports,
            "manage_schedules" => ReportPermission::ManageSchedules,
            "configure_integrations" => ReportPermission::ConfigureIntegrations,
            "purge_reports" => ReportPermission::PurgeReports,
            "view_statistics" => ReportPermission::ViewStatistics,
            _ => {
                return Err(anyhow!("Unknown operation: {}", operation));
            }
        };

        if !self.has_permission(identity, &required_permission) {
            return Err(anyhow!(
                "Access denied: User '{}' does not have permission for operation '{}'",
                identity.username,
                operation
            ));
        }

        Ok(())
    }

    /// Get all permissions for a role
    pub fn get_role_permissions(&self, role: &UserRole) -> Vec<ReportPermission> {
        self.role_permissions.get(role).cloned().unwrap_or_default()
    }

    /// Check if user is administrator (for compatibility with existing system)
    pub fn is_administrator(&self, identity: &UserIdentity) -> bool {
        identity.role == UserRole::Administrator
    }
}

/// Security audit log entry for RBAC operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAuditLog {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub username: String,
    pub operation: String,
    pub resource: String,
    pub result: AccessResult,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

/// Result of access control check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AccessResult {
    Granted,
    Denied(String), // Reason for denial
}

/// Security audit logger for RBAC operations
#[derive(Debug, Clone)]
pub struct SecurityAuditor {
    logs: Vec<SecurityAuditLog>,
}

impl SecurityAuditor {
    /// Create a new security auditor
    pub fn new() -> Self {
        Self { logs: Vec::new() }
    }

    /// Log an access attempt
    pub fn log_access(
        &mut self,
        username: &str,
        operation: &str,
        resource: &str,
        result: AccessResult,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) {
        let log_entry = SecurityAuditLog {
            timestamp: chrono::Utc::now(),
            username: username.to_string(),
            operation: operation.to_string(),
            resource: resource.to_string(),
            result,
            ip_address,
            user_agent,
        };

        self.logs.push(log_entry.clone());

        // Log to system logger
        match &log_entry.result {
            AccessResult::Granted => {
                log::info!(
                    "Access granted: {} performed '{}' on '{}' at {}",
                    username,
                    operation,
                    resource,
                    log_entry.timestamp
                );
            }
            AccessResult::Denied(reason) => {
                log::warn!(
                    "Access denied: {} attempted '{}' on '{}' at {} - Reason: {}",
                    username,
                    operation,
                    resource,
                    log_entry.timestamp,
                    reason
                );
            }
        }
    }

    /// Get recent audit logs
    pub fn get_recent_logs(&self, limit: usize) -> Vec<&SecurityAuditLog> {
        self.logs.iter().rev().take(limit).collect()
    }

    /// Get logs for a specific user
    pub fn get_user_logs(&self, username: &str) -> Vec<&SecurityAuditLog> {
        self.logs
            .iter()
            .filter(|log| log.username == username)
            .collect()
    }
}

#[cfg(all(test, feature = "advanced-reporting"))]
mod tests {
    use super::*;

    #[test]
    fn test_admin_permissions() {
        let rbac = ReportRBAC::new();
        let admin = ReportRBAC::create_admin_identity();

        // Administrator should have all permissions
        assert!(rbac.can_export(&admin));
        assert!(rbac.can_manage_schedules(&admin));
        assert!(rbac.can_configure_integrations(&admin));
        assert!(rbac.can_delete_reports(&admin));
        assert!(rbac.can_purge_reports(&admin));
        assert!(rbac.is_administrator(&admin));
    }

    #[test]
    fn test_access_validation() {
        let rbac = ReportRBAC::new();
        let admin = ReportRBAC::create_admin_identity();

        // Valid operations should succeed
        assert!(rbac.validate_access(&admin, "export_reports").is_ok());
        assert!(rbac.validate_access(&admin, "manage_schedules").is_ok());

        // Invalid operation should fail
        assert!(rbac.validate_access(&admin, "invalid_operation").is_err());
    }

    #[test]
    fn test_security_auditor() {
        let mut auditor = SecurityAuditor::new();

        auditor.log_access(
            "Administrator",
            "export_reports",
            "system_report.pdf",
            AccessResult::Granted,
            Some("127.0.0.1".to_string()),
            Some("ERDPS-Dashboard/1.0".to_string()),
        );

        let logs = auditor.get_recent_logs(10);
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].username, "Administrator");
    }
}
