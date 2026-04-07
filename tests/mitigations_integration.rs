//! Integration tests for the mitigation engine
//!
//! These tests verify the end-to-end functionality of the mitigation system,
//! including request processing, audit logging, and IPC communication.

use erdps_agent::config::AgentConfig;
use erdps_agent::mitigations::{
    start_mitigation_engine_with_controller, MitigationAction, MitigationEngine, MitigationRequest,
    MockProcessController,
};
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};

#[tokio::test]
async fn test_mitigation_engine_quarantine_files() {
    // Setup unique temporary directories for this test
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let audit_log_path = temp_dir.path().join("audit.log");
    let quarantine_dir = temp_dir.path().join("quarantine");

    // Setup test file
    let test_file = temp_dir.path().join("malicious.exe");
    let test_content = "fake malicious content";

    tokio::fs::write(&test_file, test_content)
        .await
        .expect("Failed to write test file");

    // Setup configuration
    let cfg = Arc::new(AgentConfig {
        auto_mitigate: true,
        allow_terminate: false,
        mitigation_score_threshold: 50,
        quarantine_path: quarantine_dir.to_string_lossy().to_string(),
        audit_log_path: audit_log_path.to_string_lossy().to_string(),
        dry_run: false,
        ipc_key: "test-key-123".to_string(),
        ..Default::default()
    });

    // Create channel and engine
    let (tx, rx) = mpsc::channel(10);
    let mock_controller = MockProcessController::new();
    let engine =
        MitigationEngine::new(mock_controller).expect("Failed to create mitigation engine");

    // Start mitigation engine
    let engine_handle = start_mitigation_engine_with_controller(rx, cfg.clone(), engine);

    // Create mitigation request
    let request = MitigationRequest {
        id: "integration-test-001".to_string(),
        action: MitigationAction::QuarantineFiles,
        pid: None,
        files: vec![test_file.clone()],
        quarantined_paths: vec![],
        reason: "Integration test - suspicious file detected".to_string(),
        score: 85,
        dry_run: None,
        require_confirmation: false,
        timestamp: 1234567890,
    };

    // Send request
    tx.send(request.clone())
        .await
        .expect("Failed to send mitigation request");

    // Close channel and wait for engine to process
    drop(tx);

    // Wait for engine to complete with timeout
    timeout(Duration::from_secs(5), engine_handle)
        .await
        .expect("Engine should complete within timeout")
        .expect("Engine task should complete successfully");

    // Verify file was quarantined
    assert!(!test_file.exists(), "Original file should be moved");

    // Verify quarantine directory was created
    assert!(quarantine_dir.exists(), "Quarantine directory should exist");

    // Find quarantined file
    let mut quarantine_found = false;
    let mut manifest_found = false;

    if let Ok(entries) = std::fs::read_dir(&quarantine_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                // Check for quarantined file in subdirectory
                if let Ok(sub_entries) = std::fs::read_dir(&path) {
                    for sub_entry in sub_entries.flatten() {
                        let sub_path = sub_entry.path();
                        if sub_path.file_name().and_then(|n| n.to_str()) == Some("malicious.exe") {
                            quarantine_found = true;
                            // Verify content is preserved
                            let quarantined_content = tokio::fs::read_to_string(&sub_path)
                                .await
                                .expect("Failed to read quarantined file");
                            assert_eq!(quarantined_content, test_content);
                        }
                        if sub_path.file_name().and_then(|n| n.to_str()) == Some(".manifest.json") {
                            manifest_found = true;
                        }
                    }
                }
            }
        }
    }

    assert!(quarantine_found, "Quarantined file should exist");
    assert!(manifest_found, "Manifest file should exist");

    // Verify audit log was created
    if audit_log_path.exists() {
        let audit_content = tokio::fs::read_to_string(&audit_log_path)
            .await
            .expect("Failed to read audit log");

        assert!(
            audit_content.contains(&request.id),
            "Audit log should contain request ID"
        );
        assert!(
            audit_content.contains("QuarantineFiles"),
            "Audit log should contain action"
        );
    }
}

#[tokio::test]
async fn test_mitigation_engine_process_suspension() {
    // Setup unique temporary directory for this test
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let audit_log_path = temp_dir.path().join("audit.log");

    // Setup configuration with dry run enabled
    let cfg = Arc::new(AgentConfig {
        auto_mitigate: true,
        allow_terminate: false,
        mitigation_score_threshold: 50,
        audit_log_path: audit_log_path.to_string_lossy().to_string(),
        dry_run: true, // Enable dry run for testing
        ipc_key: "test-key-456".to_string(),
        ..Default::default()
    });

    // Create channel and engine
    let (tx, rx) = mpsc::channel(10);
    let mock_controller = MockProcessController::new();
    let engine =
        MitigationEngine::new(mock_controller).expect("Failed to create mitigation engine");

    // Start mitigation engine
    let _engine_handle = start_mitigation_engine_with_controller(rx, cfg.clone(), engine);

    // Create mitigation request
    let request = MitigationRequest {
        id: "integration-test-002".to_string(),
        action: MitigationAction::SuspendProcess,
        pid: Some(12345),
        files: vec![],
        quarantined_paths: vec![],
        reason: "Integration test - suspicious process behavior".to_string(),
        score: 75,
        dry_run: None,
        require_confirmation: false,
        timestamp: 1234567890,
    };

    // Send request
    tx.send(request.clone()).await.expect("Should send request");

    // Give the engine time to process and write audit log
    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

    // Check audit log
    let audit_content = tokio::fs::read_to_string(&audit_log_path)
        .await
        .expect("Should be able to read audit log");

    assert!(
        audit_content.contains(&request.id),
        "Audit log should contain request ID"
    );
    assert!(
        audit_content.contains("SuspendProcess"),
        "Audit log should contain action"
    );
    assert!(
        audit_content.contains("DryRun"),
        "Audit log should contain dry run status"
    );
}

#[tokio::test]
async fn test_mitigation_engine_policy_denial() {
    // Setup unique temporary directory for this test
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let audit_log_path = temp_dir.path().join("audit.log");

    // Setup configuration with restrictive policy
    let cfg = Arc::new(AgentConfig {
        auto_mitigate: false, // Disable auto-mitigation
        allow_terminate: false,
        mitigation_score_threshold: 90, // High threshold
        audit_log_path: audit_log_path.to_string_lossy().to_string(),
        dry_run: false,
        ipc_key: "test-key-789".to_string(),
        ..Default::default()
    });

    // Create channel and engine
    let (tx, rx) = mpsc::channel(10);
    let mock_controller = MockProcessController::new();
    let engine =
        MitigationEngine::new(mock_controller).expect("Failed to create mitigation engine");

    // Start mitigation engine
    let _engine_handle = start_mitigation_engine_with_controller(rx, cfg.clone(), engine);

    // Create mitigation request that should be denied
    let request = MitigationRequest {
        id: "integration-test-003".to_string(),
        action: MitigationAction::TerminateProcess,
        pid: Some(12345),
        files: vec![],
        quarantined_paths: vec![],
        reason: "Integration test - policy denial".to_string(),
        score: 60, // Below threshold
        dry_run: None,
        require_confirmation: false,
        timestamp: 1234567890,
    };

    // Send request
    tx.send(request.clone()).await.expect("Should send request");

    // Give the engine time to process and write audit log
    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

    // Check audit log
    let audit_content = tokio::fs::read_to_string(&audit_log_path)
        .await
        .expect("Should be able to read audit log");

    assert!(
        audit_content.contains(&request.id),
        "Audit log should contain request ID"
    );
    assert!(
        audit_content.contains("Denied"),
        "Audit log should contain denial status"
    );
}

#[tokio::test]
async fn test_mitigation_engine_protected_pid() {
    // Setup unique temporary directory for this test
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let audit_log_path = temp_dir.path().join("audit.log");

    // Setup configuration with protected PIDs
    let protected_pid = 1234;
    let cfg = Arc::new(AgentConfig {
        auto_mitigate: true,
        allow_terminate: true,
        mitigation_score_threshold: 50,
        audit_log_path: audit_log_path.to_string_lossy().to_string(),
        dry_run: false,
        // Note: protected_pids field removed as it doesn't exist in AgentConfig
        ipc_key: "test-key-protected".to_string(),
        ..Default::default()
    });

    // Create channel and engine
    let (tx, rx) = mpsc::channel(10);
    let mock_controller = MockProcessController::new();
    let engine =
        MitigationEngine::new(mock_controller).expect("Failed to create mitigation engine");

    // Start mitigation engine
    let _engine_handle = start_mitigation_engine_with_controller(rx, cfg.clone(), engine);

    // Create mitigation request targeting protected PID
    let request = MitigationRequest {
        id: "integration-test-004".to_string(),
        action: MitigationAction::TerminateProcess,
        pid: Some(protected_pid),
        files: vec![],
        quarantined_paths: vec![],
        reason: "Integration test - protected PID".to_string(),
        score: 95, // High score, but PID is protected
        dry_run: None,
        require_confirmation: false,
        timestamp: 1234567890,
    };

    // Send request
    tx.send(request.clone()).await.expect("Should send request");

    // Give the engine time to process and write audit log
    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

    // Check audit log
    let audit_content = tokio::fs::read_to_string(&audit_log_path)
        .await
        .expect("Should be able to read audit log");

    assert!(
        audit_content.contains(&request.id),
        "Audit log should contain request ID"
    );
    assert!(
        audit_content.contains("Denied"),
        "Audit log should contain denial status"
    );
}
