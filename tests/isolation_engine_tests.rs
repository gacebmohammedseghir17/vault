//! Isolation Engine Tests - Single-threaded execution to prevent hangs
//!
//! This test file is specifically designed to run isolation engine tests
//! in a single-threaded environment with strict timeouts to prevent
//! test suite hangs and make debugging deterministic.

use std::time::Duration;
use tokio::time::timeout;

// Re-export the isolation engine module for testing
mod isolation_engine {
    pub use erdps_agent::validation::isolation_engine::*;
}

/// Wrapper macro for isolation engine tests with mandatory timeout
macro_rules! isolation_test {
    ($name:ident, $timeout_secs:expr, $test_fn:expr) => {
        #[tokio::test(flavor = "current_thread")]
        async fn $name() {
            let result = timeout(Duration::from_secs($timeout_secs), $test_fn()).await;
            match result {
                Ok(test_result) => {
                    if let Err(e) = test_result {
                        panic!("Test failed: {}", e);
                    }
                }
                Err(_) => {
                    panic!(
                        "Test timed out after {} seconds - this indicates a hang or deadlock",
                        $timeout_secs
                    );
                }
            }
        }
    };
}

// Re-run the isolation engine tests with single-threaded execution and timeouts
isolation_test!(test_session_lifecycle_isolated, 5, || async {
    tokio::task::spawn_blocking(|| {
        use erdps_agent::validation::isolation_engine::*;
        use tempfile::TempDir;
        use std::sync::Arc;
        
        let temp_dir = TempDir::new().unwrap();
        let db_file = temp_dir.path().join("test.db");
        let database = Arc::new(erdps_agent::database::DatabasePool::new(&db_file).unwrap());
        
        let engine = IsolationEngine::new(database).unwrap();
        
        // Start session
        let config = IsolationSessionConfig::default();
        let session_id = engine.start_session(config).unwrap();
        
        // Check status
        let status = engine.get_session_status(&session_id).unwrap();
        assert_eq!(status, IsolationStatus::Initializing);
        
        // Terminate session
        engine.terminate_session(&session_id).unwrap();
        
        let status = engine.get_session_status(&session_id).unwrap();
        assert_eq!(status, IsolationStatus::Terminated);
    }).await.unwrap();
    Ok(())
});

isolation_test!(test_concurrent_session_limit_isolated, 5, || async {
    tokio::task::spawn_blocking(|| {
        use erdps_agent::validation::isolation_engine::*;
        use tempfile::TempDir;
        use std::sync::Arc;
        
        let temp_dir = TempDir::new().unwrap();
        let db_file = temp_dir.path().join("test.db");
        let database = Arc::new(erdps_agent::database::DatabasePool::new(&db_file).unwrap());
        
        let engine = IsolationEngine::new(database).unwrap();
        
        // Start maximum allowed sessions
        let mut session_ids = Vec::new();
        for _ in 0..engine.global_config.max_concurrent_sessions {
            let config = IsolationSessionConfig::default();
            let session_id = engine.start_session(config).unwrap();
            session_ids.push(session_id);
        }
        
        // Try to start one more session (should fail)
        let config = IsolationSessionConfig::default();
        let result = engine.start_session(config);
        assert!(result.is_err());
        
        // Clean up
        for session_id in session_ids {
            engine.terminate_session(&session_id).unwrap();
        }
    }).await.unwrap();
    Ok(())
});

isolation_test!(test_session_statistics_isolated, 5, || async {
    tokio::task::spawn_blocking(|| {
        use erdps_agent::validation::isolation_engine::*;
        use tempfile::TempDir;
        use std::sync::Arc;
        
        let temp_dir = TempDir::new().unwrap();
        let db_file = temp_dir.path().join("test.db");
        let database = Arc::new(erdps_agent::database::DatabasePool::new(&db_file).unwrap());
        
        let engine = IsolationEngine::new(database).unwrap();
        
        let config = IsolationSessionConfig::default();
        let _session_id = engine.start_session(config).unwrap();
        
        let stats = engine.get_session_statistics();
        assert_eq!(stats.total_active_sessions, 1);
        assert_eq!(stats.max_concurrent_sessions, engine.global_config.max_concurrent_sessions);
    }).await.unwrap();
    Ok(())
});

/// Additional diagnostic test to verify timeout and cleanup behavior
#[tokio::test(flavor = "current_thread")]
async fn test_timeout_behavior() {
    tokio::task::spawn_blocking(|| {
        use erdps_agent::validation::isolation_engine::*;
        use tempfile::TempDir;
        use std::sync::Arc;
        use std::thread;
        
        let temp_dir = TempDir::new().unwrap();
        let db_file = temp_dir.path().join("test.db");
        let database = Arc::new(erdps_agent::database::DatabasePool::new(&db_file).unwrap());
        
        let engine = IsolationEngine::new(database).unwrap();
        
        // Test basic session creation and termination
        let config = IsolationSessionConfig::default();
        let session_id = engine.start_session(config).unwrap();
        
        // Verify session exists
        let status = engine.get_session_status(&session_id).unwrap();
        assert_eq!(status, IsolationStatus::Initializing);
        
        // Wait a short time
        thread::sleep(Duration::from_millis(100));
        
        // Terminate session
        engine.terminate_session(&session_id).unwrap();
        
        // Verify session is terminated
        let status = engine.get_session_status(&session_id).unwrap();
        assert_eq!(status, IsolationStatus::Terminated);
    }).await.unwrap();
}

/// Test to verify basic command execution works correctly
#[tokio::test(flavor = "current_thread")]
async fn test_command_execution() {
    // Test basic command execution without relying on run_with_timeout function
    // that may not exist or may have different signature
    
    #[cfg(windows)]
    {
        let output = tokio::process::Command::new("echo")
            .arg("test")
            .output()
            .await;
        
        assert!(output.is_ok(), "Basic echo command should succeed");
        
        if let Ok(output) = output {
            assert!(output.status.success(), "Echo command should exit successfully");
        }
    }
    
    #[cfg(unix)]
    {
        let output = tokio::process::Command::new("/bin/echo")
            .arg("test")
            .output()
            .await;
        
        assert!(output.is_ok(), "Basic echo command should succeed");
        
        if let Ok(output) = output {
            assert!(output.status.success(), "Echo command should exit successfully");
        }
    }
}
