use super::*;
use crate::reports::rbac::{UserIdentity, UserRole};
use std::collections::HashMap;
use std::path::PathBuf;
use tempfile::tempdir;
use uuid::Uuid;

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

    async fn create_test_scheduler() -> ReportScheduler {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test_scheduler.db");
        let db_url = format!("sqlite:{}", db_path.display());
        
        ReportScheduler::new(&db_url).await.unwrap()
    }

    fn create_test_schedule() -> ScheduledExport {
        ScheduledExport {
            id: Uuid::new_v4(),
            name: "Test Schedule".to_string(),
            description: Some("Test scheduled export".to_string()),
            frequency: ScheduleFrequency::Daily,
            time_of_day: "08:00".to_string(),
            export_format: ExportFormat::Pdf,
            compression: Some(CompressionType::Zip),
            report_types: vec!["security".to_string(), "vulnerability".to_string()],
            filters: HashMap::new(),
            output_directory: PathBuf::from("/tmp/exports"),
            retention_days: Some(30),
            enabled: true,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            last_run: None,
            next_run: None,
        }
    }

    #[tokio::test]
    async fn test_scheduler_creation() {
        let scheduler = create_test_scheduler().await;
        
        // Scheduler should be created successfully
        let stats = scheduler.get_statistics().await.unwrap();
        assert_eq!(stats.total_schedules, 0);
        assert_eq!(stats.active_schedules, 0);
    }

    #[tokio::test]
    async fn test_create_schedule_success() {
        let mut scheduler = create_test_scheduler().await;
        let admin = create_admin_identity();
        let schedule = create_test_schedule();
        
        let result = scheduler.create_schedule(&admin, schedule.clone()).await;
        
        assert!(result.is_ok());
        let schedule_id = result.unwrap();
        
        let retrieved = scheduler.get_schedule(schedule_id).await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().name, schedule.name);
    }

    #[tokio::test]
    async fn test_create_schedule_unauthorized() {
        let mut scheduler = create_test_scheduler().await;
        let user = create_user_identity();
        let schedule = create_test_schedule();
        
        let result = scheduler.create_schedule(&user, schedule).await;
        
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_schedule_frequencies() {
        let mut scheduler = create_test_scheduler().await;
        let admin = create_admin_identity();
        
        let frequencies = vec![
            ScheduleFrequency::Daily,
            ScheduleFrequency::Weekly,
            ScheduleFrequency::Monthly,
            ScheduleFrequency::Custom("0 12 * * 1-5".to_string()), // Weekdays at noon
        ];
        
        for frequency in frequencies {
            let mut schedule = create_test_schedule();
            schedule.frequency = frequency.clone();
            schedule.name = format!("Test {:?} Schedule", frequency);
            
            let result = scheduler.create_schedule(&admin, schedule).await;
            assert!(result.is_ok(), "Failed to create {:?} schedule", frequency);
        }
    }

    #[tokio::test]
    async fn test_update_schedule() {
        let mut scheduler = create_test_scheduler().await;
        let admin = create_admin_identity();
        let schedule = create_test_schedule();
        
        let schedule_id = scheduler.create_schedule(&admin, schedule).await.unwrap();
        
        let mut updated_schedule = scheduler.get_schedule(schedule_id).await.unwrap();
        updated_schedule.name = "Updated Schedule Name".to_string();
        updated_schedule.frequency = ScheduleFrequency::Weekly;
        
        let result = scheduler.update_schedule(updated_schedule.clone()).await;
        assert!(result.is_ok());
        
        let retrieved = scheduler.get_schedule(schedule_id).await.unwrap();
        assert_eq!(retrieved.name, "Updated Schedule Name");
        assert_eq!(retrieved.frequency, ScheduleFrequency::Weekly);
    }

    #[tokio::test]
    async fn test_remove_schedule_success() {
        let mut scheduler = create_test_scheduler().await;
        let admin = create_admin_identity();
        let schedule = create_test_schedule();
        
        let schedule_id = scheduler.create_schedule(&admin, schedule).await.unwrap();
        
        let result = scheduler.remove_schedule(&admin, schedule_id).await;
        assert!(result.is_ok());
        
        let retrieved = scheduler.get_schedule(schedule_id).await;
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_remove_schedule_unauthorized() {
        let mut scheduler = create_test_scheduler().await;
        let admin = create_admin_identity();
        let user = create_user_identity();
        let schedule = create_test_schedule();
        
        let schedule_id = scheduler.create_schedule(&admin, schedule).await.unwrap();
        
        let result = scheduler.remove_schedule(&user, schedule_id).await;
        assert!(result.is_err());
        
        // Schedule should still exist
        let retrieved = scheduler.get_schedule(schedule_id).await;
        assert!(retrieved.is_some());
    }

    #[tokio::test]
    async fn test_get_all_schedules() {
        let mut scheduler = create_test_scheduler().await;
        let admin = create_admin_identity();
        
        // Create multiple schedules
        for i in 0..3 {
            let mut schedule = create_test_schedule();
            schedule.name = format!("Schedule {}", i);
            scheduler.create_schedule(&admin, schedule).await.unwrap();
        }
        
        let schedules = scheduler.get_schedules().await;
        assert_eq!(schedules.len(), 3);
    }

    #[tokio::test]
    async fn test_schedule_execution_trigger() {
        let mut scheduler = create_test_scheduler().await;
        let admin = create_admin_identity();
        let schedule = create_test_schedule();
        
        let schedule_id = scheduler.create_schedule(&admin, schedule).await.unwrap();
        
        // Start the scheduler
        let result = scheduler.start().await;
        assert!(result.is_ok());
        
        // Stop the scheduler
        let result = scheduler.stop().await;
        assert!(result.is_ok());
        
        // Verify schedule still exists
        let retrieved = scheduler.get_schedule(schedule_id).await;
        assert!(retrieved.is_some());
    }

    #[tokio::test]
    async fn test_schedule_persistence() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("persistence_test.db");
        let db_url = format!("sqlite:{}", db_path.display());
        
        let schedule_id = {
            let mut scheduler = ReportScheduler::new(&db_url).await.unwrap();
            let admin = create_admin_identity();
            let schedule = create_test_schedule();
            
            scheduler.create_schedule(&admin, schedule).await.unwrap()
        };
        
        // Create a new scheduler instance with the same database
        let scheduler2 = ReportScheduler::new(&db_url).await.unwrap();
        
        // Schedule should be loaded from database
        let retrieved = scheduler2.get_schedule(schedule_id).await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().name, "Test Schedule");
    }

    #[tokio::test]
    async fn test_schedule_retention_policy() {
        let mut scheduler = create_test_scheduler().await;
        let admin = create_admin_identity();
        
        let mut schedule = create_test_schedule();
        schedule.retention_days = Some(7); // 7 days retention
        
        let schedule_id = scheduler.create_schedule(&admin, schedule).await.unwrap();
        
        let retrieved = scheduler.get_schedule(schedule_id).await.unwrap();
        assert_eq!(retrieved.retention_days, Some(7));
    }

    #[tokio::test]
    async fn test_schedule_statistics() {
        let mut scheduler = create_test_scheduler().await;
        let admin = create_admin_identity();
        
        // Initially no schedules
        let stats = scheduler.get_statistics().await.unwrap();
        assert_eq!(stats.total_schedules, 0);
        assert_eq!(stats.active_schedules, 0);
        
        // Create some schedules
        for i in 0..3 {
            let mut schedule = create_test_schedule();
            schedule.name = format!("Schedule {}", i);
            schedule.enabled = i < 2; // Only first 2 are enabled
            scheduler.create_schedule(&admin, schedule).await.unwrap();
        }
        
        let stats = scheduler.get_statistics().await.unwrap();
        assert_eq!(stats.total_schedules, 3);
        assert_eq!(stats.active_schedules, 2);
    }

    #[tokio::test]
    async fn test_cron_expression_building() {
        let scheduler = create_test_scheduler().await;
        
        // Test daily schedule
        let daily_cron = scheduler.build_cron_expression(
            &ScheduleFrequency::Daily,
            "14:30"
        ).unwrap();
        assert_eq!(daily_cron, "30 14 * * *");
        
        // Test weekly schedule
        let weekly_cron = scheduler.build_cron_expression(
            &ScheduleFrequency::Weekly,
            "09:00"
        ).unwrap();
        assert_eq!(weekly_cron, "0 9 * * 1");
        
        // Test monthly schedule
        let monthly_cron = scheduler.build_cron_expression(
            &ScheduleFrequency::Monthly,
            "12:15"
        ).unwrap();
        assert_eq!(monthly_cron, "15 12 1 * *");
        
        // Test custom schedule
        let custom_expr = "0 */2 * * *"; // Every 2 hours
        let custom_cron = scheduler.build_cron_expression(
            &ScheduleFrequency::Custom(custom_expr.to_string()),
            "00:00" // Should be ignored for custom
        ).unwrap();
        assert_eq!(custom_cron, custom_expr);
    }

    #[tokio::test]
    async fn test_next_run_calculation() {
        let scheduler = create_test_scheduler().await;
        
        // Test daily schedule
        let next_run = scheduler.calculate_next_run(
            &ScheduleFrequency::Daily,
            "08:00"
        ).unwrap();
        assert!(next_run.is_some());
        
        // Test weekly schedule
        let next_run = scheduler.calculate_next_run(
            &ScheduleFrequency::Weekly,
            "10:30"
        ).unwrap();
        assert!(next_run.is_some());
        
        // Test monthly schedule
        let next_run = scheduler.calculate_next_run(
            &ScheduleFrequency::Monthly,
            "15:45"
        ).unwrap();
        assert!(next_run.is_some());
    }
}
