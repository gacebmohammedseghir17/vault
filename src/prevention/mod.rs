//! Prevention module for the Enhanced ERDPS Agent
//!
//! This module provides active prevention mechanisms including:
//! - Process termination and suspension
//! - File system protection
//! - Registry protection
//! - Network blocking
//! - Memory protection
//! - Real-time threat response
//!
//! Key Components:
//! - Active Prevention: Process/Network blocking
//! - Quarantine: Secure file isolation
//! - Rollback: VSS-based system restoration
//! - Honeyfile: Deception and trap files
//! - VSS: Volume Shadow Copy Service integration

pub mod active;
pub mod quarantine;
pub mod rollback;
pub mod honeyfile;
pub mod vss;

use crate::core::error::Result;
use crate::core::types::*;
use crate::prevention::quarantine::QuarantineStatistics;
use crate::prevention::active::{PreventionAction, PreventionResult, PreventionStatistics, PreventionRule};
use async_trait::async_trait;

/// Prevention engine trait for active threat response
#[async_trait]
pub trait PreventionEngine: Send + Sync {
    /// Initialize the prevention engine
    async fn initialize(&self) -> Result<()>;
    
    /// Start prevention monitoring
    async fn start(&self) -> Result<()>;
    
    /// Stop prevention monitoring
    async fn stop(&self) -> Result<()>;
    
    /// Execute prevention action
    async fn execute_action(&self, action: &PreventionAction) -> Result<PreventionResult>;
    
    /// Check if action is allowed
    async fn is_action_allowed(&self, action: &PreventionAction) -> Result<bool>;
    
    /// Get prevention statistics
    async fn get_statistics(&self) -> Result<PreventionStatistics>;
    
    /// Update prevention rules
    async fn update_rules(&self, rules: Vec<PreventionRule>) -> Result<()>;
}

/// Quarantine manager trait for secure file isolation
#[async_trait]
pub trait QuarantineManager: Send + Sync {
    /// Initialize the quarantine system
    async fn initialize(&self) -> Result<()>;
    
    /// Quarantine a file
    async fn quarantine_file(&self, file_path: &str, metadata: QuarantineMetadata) -> Result<QuarantineEntry>;
    
    /// Restore a quarantined file
    async fn restore_file(&self, quarantine_id: &QuarantineId) -> Result<RestoreResult>;
    
    /// Delete a quarantined file permanently
    async fn delete_quarantined(&self, quarantine_id: &QuarantineId) -> Result<()>;
    
    /// List quarantined files
    async fn list_quarantined(&self) -> Result<Vec<QuarantineEntry>>;
    
    /// Get quarantine statistics
    async fn get_statistics(&self) -> Result<QuarantineStatistics>;
    
    /// Verify quarantine integrity
    async fn verify_integrity(&self) -> Result<bool>;
}

use crate::prevention::rollback::{
    RestorePointId, RestorePoint, RestoreResult, RestorePointType, RollbackStatistics,
    RollbackScope, RollbackResult, RollbackId, RollbackStatus
};

/// Rollback engine trait for system restoration
#[async_trait]
pub trait RollbackEngine: Send + Sync {
    /// Initialize the rollback system
    async fn initialize(&self) -> Result<()>;
    
    /// Create a system restore point
    async fn create_restore_point(&self, name: String, description: String, restore_type: RestorePointType) -> Result<RestorePointId>;
    
    /// Restore from a restore point
    async fn restore_from_point(&self, restore_id: &RestorePointId) -> Result<RestoreResult>;
    
    /// List available restore points
    async fn list_restore_points(&self) -> Result<Vec<RestorePoint>>;
    
    /// Delete a restore point
    async fn delete_restore_point(&self, restore_id: &RestorePointId) -> Result<()>;
    
    /// Get rollback statistics
    async fn get_statistics(&self) -> Result<RollbackStatistics>;
    
    /// Verify restore point integrity
    async fn verify_restore_point(&self, restore_id: &RestorePointId) -> Result<bool>;

    /// Verify overall system integrity
    async fn verify_integrity(&self) -> Result<bool>;

    /// Rollback to a specific point with scope
    async fn rollback_to_point(
        &self,
        restore_point_id: &RestorePointId,
        scope: Option<RollbackScope>,
    ) -> Result<RollbackResult>;

    /// Get status of a rollback operation
    async fn get_rollback_status(&self, rollback_id: &RollbackId) -> Result<RollbackStatus>;

    /// Cancel an active rollback
    async fn cancel_rollback(&self, rollback_id: &RollbackId) -> Result<()>;
}
