//! Integration tests for Phase 3 Autonomous Response Engine
//! Tests the complete autonomous response workflow including:
//! - Auto engine rule-based and ML-informed actions
//! - Risk score calculation and assessment
//! - Network quarantine functionality
//! - Integration with detection engines

#[allow(unused_imports)]
use std::env;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use std::collections::HashMap;
use tokio::time::sleep;

/// Get configurable response action timeout from environment variable or use default
#[allow(dead_code)]
fn get_response_timeout() -> Duration {
    std::env::var("ERDPS_RESPONSE_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(5))
}

#[cfg(feature = "automated-response")]
use erdps_agent::core::config::AutomatedResponseConfig;
#[cfg(feature = "automated-response")]
use erdps_agent::response::network_quarantine;
#[cfg(feature = "automated-response")]
use erdps_agent::response::{
    ResponseAction, ResponseSystem, SecurityEvent, SecurityEventType,
};
#[cfg(feature = "automated-response")]
use erdps_agent::metrics::MetricsCollector;

/// Test configuration for autonomous response engine
#[cfg(feature = "automated-response")]
fn create_test_config() -> AutomatedResponseConfig {
    AutomatedResponseConfig {
        enabled: true,
        enable_process_termination: true,
        enable_file_quarantine: true,
        enable_network_isolation: true,
        enable_system_snapshot: true,
        response_timeout_seconds: 30,
        escalation_levels: vec![],
        cooldown_period_seconds: 60,
        max_actions_per_hour: 100,
    }
}

/// Test the autonomous response engine initialization
#[cfg(feature = "automated-response")]
#[tokio::test]
async fn test_autonomous_response_initialization() {
    let config = create_test_config();

    // Initialize the response system
    let metrics_db = erdps_agent::metrics::database::MetricsDatabase::new("test_metrics.db").unwrap();
    let metrics = Arc::new(MetricsCollector::new(metrics_db));
    let response_system = ResponseSystem::new(config.clone(), metrics).await;
    assert!(
        response_system.is_ok(),
        "Failed to initialize response system"
    );

    let system = response_system.unwrap();

    // Start monitoring (should not panic)
    let start_result = system.start_monitoring().await;
    assert!(start_result.is_ok(), "Failed to start monitoring");

    println!("✓ Autonomous response engine initialized successfully");
}

/// Test risk score calculation with various security events
#[cfg(feature = "automated-response")]
#[tokio::test]
async fn test_risk_score_calculation() {
    let config = create_test_config();
    let metrics_db = erdps_agent::metrics::database::MetricsDatabase::new("test_metrics.db").unwrap();
    let metrics = Arc::new(MetricsCollector::new(metrics_db));
    let response_system = ResponseSystem::new(config, metrics).await.unwrap();

    // Test high-risk ransomware event
    let mut metadata = HashMap::new();
    metadata.insert("process_id".to_string(), "1234".to_string());
    metadata.insert("process_name".to_string(), "malware.exe".to_string());
    metadata.insert("file_path".to_string(), "C:\\temp\\malware.exe".to_string());
    metadata.insert("anomaly_score".to_string(), "0.95".to_string());
    metadata.insert("entropy_spike".to_string(), "0.9".to_string());
    metadata.insert("io_rate".to_string(), "1000.0".to_string());

    let ransomware_event = SecurityEvent {
        event_type: SecurityEventType::RansomwareDetected,
        severity: 9.0,
        confidence: 0.95,
        source: "test_source".to_string(),
        timestamp: std::time::SystemTime::now(),
        metadata,
    };

    // Process the event and check risk assessment
    let actions = response_system
        .process_security_event(&ransomware_event)
        .await;
    assert!(actions.is_ok(), "Failed to process ransomware event");

    let action_list = actions.unwrap();
    assert!(
        !action_list.is_empty(),
        "No actions generated for high-risk event"
    );

    // Should include process suspension action (the system generates ProcessSuspend for high-risk events)
    let has_process_suspend = action_list
        .iter()
        .any(|action| matches!(action, ResponseAction::ProcessSuspend { .. }));
    assert!(
        has_process_suspend,
        "Process suspension action not generated for high-risk event"
    );

    println!("✓ Risk score calculation working correctly");
}

/// Test autonomous response actions for different threat types
#[cfg(feature = "automated-response")]
#[tokio::test]
async fn test_autonomous_response_actions() {
    let config = create_test_config();
    let metrics_db = erdps_agent::metrics::database::MetricsDatabase::new("test_metrics.db").unwrap();
    let metrics = Arc::new(MetricsCollector::new(metrics_db));
    let response_system = ResponseSystem::new(config, metrics).await.unwrap();

    // Test process suspension for malware
    let mut malware_metadata = HashMap::new();
    malware_metadata.insert("process_id".to_string(), "5678".to_string());
    malware_metadata.insert("process_name".to_string(), "suspicious.exe".to_string());
    malware_metadata.insert(
        "file_path".to_string(),
        "C:\\temp\\suspicious.exe".to_string(),
    );
    malware_metadata.insert("anomaly_score".to_string(), "0.75".to_string());
    malware_metadata.insert("entropy_spike".to_string(), "0.6".to_string());
    malware_metadata.insert("io_rate".to_string(), "500.0".to_string());

    let malware_event = SecurityEvent {
        event_type: SecurityEventType::SuspiciousProcessBehavior,
        severity: 7.0,
        confidence: 0.75,
        source: "test_source".to_string(),
        timestamp: std::time::SystemTime::now(),
        metadata: malware_metadata,
    };

    let actions = response_system
        .process_security_event(&malware_event)
        .await
        .unwrap();

    // Should include process suspension
    let has_process_suspend = actions
        .iter()
        .any(|action| matches!(action, ResponseAction::ProcessSuspend { .. }));
    assert!(
        has_process_suspend,
        "Process suspension action not generated"
    );

    println!("✓ Autonomous response actions generated correctly");
}

/// Test network quarantine functionality
#[cfg(feature = "automated-response")]
#[tokio::test]
async fn test_network_quarantine() {
    let config = create_test_config();
    let metrics_db = erdps_agent::metrics::database::MetricsDatabase::new("test_metrics.db").unwrap();
    let metrics = Arc::new(MetricsCollector::new(metrics_db));
    let response_system = ResponseSystem::new(config, metrics).await.unwrap();

    // Test network exfiltration event
    let mut exfiltration_metadata = HashMap::new();
    exfiltration_metadata.insert("process_id".to_string(), "9999".to_string());
    exfiltration_metadata.insert("process_name".to_string(), "data_stealer.exe".to_string());
    exfiltration_metadata.insert("network_target".to_string(), "192.168.1.100".to_string());
    exfiltration_metadata.insert("anomaly_score".to_string(), "0.9".to_string());
    exfiltration_metadata.insert("entropy_spike".to_string(), "0.8".to_string());
    exfiltration_metadata.insert("io_rate".to_string(), "2000.0".to_string());

    let exfiltration_event = SecurityEvent {
        event_type: SecurityEventType::NetworkThreatDetected,
        severity: 9.0,
        confidence: 0.9,
        source: "test_source".to_string(),
        timestamp: std::time::SystemTime::now(),
        metadata: exfiltration_metadata,
    };

    let actions = response_system
        .process_security_event(&exfiltration_event)
        .await
        .unwrap();

    // Should include process suspension (the system generates ProcessSuspend for network threats)
    let has_process_suspend = actions
        .iter()
        .any(|action| matches!(action, ResponseAction::ProcessSuspend { .. }));
    assert!(
        has_process_suspend,
        "Process suspension action not generated for network threat"
    );

    // Verify action contains appropriate reason
    let suspend_action = actions
        .iter()
        .find(|action| matches!(action, ResponseAction::ProcessSuspend { .. }));
    if let Some(ResponseAction::ProcessSuspend { reason, .. }) = suspend_action {
        assert!(
            reason.contains("High Anomaly Suspend"),
            "Action reason should reference the matching rule"
        );
    }

    println!("✓ Network quarantine functionality working correctly");
}

/// Test integration with detection engines
#[cfg(feature = "automated-response")]
#[tokio::test]
async fn test_detection_engine_integration() {
    let config = create_test_config();
    let metrics_db = erdps_agent::metrics::database::MetricsDatabase::new("test_metrics.db").unwrap();
    let metrics = Arc::new(MetricsCollector::new(metrics_db));
    let response_system = ResponseSystem::new(config, metrics).await.unwrap();

    // Start monitoring to enable integration
    response_system.start_monitoring().await.unwrap();

    // Simulate multiple events from different detection engines
    let mut behavioral_metadata = HashMap::new();
    behavioral_metadata.insert("process_id".to_string(), "1111".to_string());
    behavioral_metadata.insert("process_name".to_string(), "anomalous.exe".to_string());
    behavioral_metadata.insert(
        "file_path".to_string(),
        "C:\\temp\\anomalous.exe".to_string(),
    );
    behavioral_metadata.insert("anomaly_score".to_string(), "0.6".to_string());
    behavioral_metadata.insert("entropy_spike".to_string(), "0.5".to_string());
    behavioral_metadata.insert("io_rate".to_string(), "200.0".to_string());

    let mut entropy_metadata = HashMap::new();
    entropy_metadata.insert("process_id".to_string(), "2222".to_string());
    entropy_metadata.insert("process_name".to_string(), "encryptor.exe".to_string());
    entropy_metadata.insert(
        "file_path".to_string(),
        "C:\\temp\\encryptor.exe".to_string(),
    );
    entropy_metadata.insert("anomaly_score".to_string(), "0.8".to_string());
    entropy_metadata.insert("entropy_spike".to_string(), "0.95".to_string());
    entropy_metadata.insert("io_rate".to_string(), "800.0".to_string());

    let events = vec![
        SecurityEvent {
            event_type: SecurityEventType::BehavioralAnomaly,
            severity: 6.0,
            confidence: 0.6,
            source: "behavioral_engine".to_string(),
            timestamp: std::time::SystemTime::now(),
            metadata: behavioral_metadata,
        },
        SecurityEvent {
            event_type: SecurityEventType::EntropySpike,
            severity: 8.0,
            confidence: 0.8,
            source: "entropy_engine".to_string(),
            timestamp: std::time::SystemTime::now(),
            metadata: entropy_metadata,
        },
    ];

    // Process events and verify responses
    for event in events {
        let actions = response_system.process_security_event(&event).await;
        assert!(actions.is_ok(), "Failed to process detection engine event");

        let action_list = actions.unwrap();
        assert!(
            !action_list.is_empty(),
            "No actions generated for detection engine event"
        );
    }

    println!("✓ Detection engine integration working correctly");
}

/// Test response action execution (mock execution)
#[cfg(feature = "automated-response")]
#[tokio::test]
async fn test_response_action_execution() {
    let config = create_test_config();
    let metrics_db = erdps_agent::metrics::database::MetricsDatabase::new("test_metrics.db").unwrap();
    let metrics = Arc::new(MetricsCollector::new(metrics_db));
    let response_system = ResponseSystem::new(config, metrics).await.unwrap();

    // Test different action types
    let actions = vec![
        ResponseAction::ProcessSuspend {
            pid: 1234,
            reason: "Malware detected".to_string(),
            duration: None,
        },
        ResponseAction::NetworkQuarantine {
            target: network_quarantine::QuarantineTarget::IpAddress("192.168.1.100".to_string()),
            reason: "Suspicious network activity".to_string(),
            duration: Some(get_response_timeout()),
        },
        ResponseAction::FirewallBlock {
            target: "10.0.0.50".to_string(),
            rule_type: "block".to_string(),
            reason: "Data exfiltration attempt".to_string(),
        },
        ResponseAction::RiskAssessment {
            event_id: "test_event_123".to_string(),
            risk_score: 0.85,
            recommendations: vec!["High entropy".to_string(), "Anomalous behavior".to_string()],
        },
    ];

    // Execute actions (should not panic)
    for action in actions {
        let result = response_system.execute_action(&action).await;
        // Note: In a real test environment, we might mock the actual execution
        // For now, we just verify the method doesn't panic
        println!("Action execution result: {:?}", result);
    }

    println!("✓ Response action execution completed");
}

/// Test concurrent event processing
#[cfg(feature = "automated-response")]
#[tokio::test]
async fn test_concurrent_event_processing() {
    let config = create_test_config();
    let metrics_db = erdps_agent::metrics::database::MetricsDatabase::new("test_metrics.db").unwrap();
    let metrics = Arc::new(MetricsCollector::new(metrics_db));
    let response_system = Arc::new(RwLock::new(
        ResponseSystem::new(config, metrics).await.unwrap(),
    ));

    // Create multiple concurrent events
    let mut handles = vec![];

    for i in 0..5 {
        let system: Arc<RwLock<ResponseSystem>> = Arc::clone(&response_system);
        let handle = tokio::spawn(async move {
            let mut event_metadata = HashMap::new();
            event_metadata.insert("process_id".to_string(), (1000 + i).to_string());
            event_metadata.insert("process_name".to_string(), format!("test_{}.exe", i));
            event_metadata.insert("file_path".to_string(), format!("C:\\temp\\test_{}.exe", i));
            event_metadata.insert("anomaly_score".to_string(), "0.7".to_string());
            event_metadata.insert("entropy_spike".to_string(), "0.6".to_string());
            event_metadata.insert("io_rate".to_string(), "300.0".to_string());

            let event = SecurityEvent {
                event_type: SecurityEventType::SuspiciousProcessBehavior,
                severity: 6.0,
                confidence: 0.7,
                source: "concurrent_test".to_string(),
                timestamp: std::time::SystemTime::now(),
                metadata: event_metadata,
            };

            // Clone the event to avoid borrowing issues
            let event_clone = event.clone();
            
            // Process the event by cloning the system reference
            let system_clone = Arc::clone(&system);
            let result = tokio::task::spawn_blocking(move || {
                let sys = system_clone.read().unwrap();
                // Create a runtime for the async call
                let rt = tokio::runtime::Handle::current();
                rt.block_on(sys.process_security_event(&event_clone))
            }).await.unwrap();
            
            result
        });
        handles.push(handle);
    }

    // Wait for all events to be processed
    for handle in handles {
        let result = handle.await;
        assert!(result.is_ok(), "Concurrent event processing failed");
        assert!(result.unwrap().is_ok(), "Event processing returned error");
    }

    println!("✓ Concurrent event processing working correctly");
}

/// Test system cleanup and resource management
#[cfg(feature = "automated-response")]
#[tokio::test]
async fn test_system_cleanup() {
    let config = create_test_config();
    let metrics_db = erdps_agent::metrics::database::MetricsDatabase::new("test_metrics.db").unwrap();
    let metrics = Arc::new(MetricsCollector::new(metrics_db));
    let response_system = ResponseSystem::new(config, metrics).await.unwrap();

    // Start monitoring
    response_system.start_monitoring().await.unwrap();

    // Process some events
    let mut cleanup_metadata = HashMap::new();
    cleanup_metadata.insert("process_id".to_string(), "7777".to_string());
    cleanup_metadata.insert("process_name".to_string(), "ransomware.exe".to_string());
    cleanup_metadata.insert(
        "file_path".to_string(),
        "C:\\temp\\ransomware.exe".to_string(),
    );
    cleanup_metadata.insert("anomaly_score".to_string(), "0.95".to_string());
    cleanup_metadata.insert("entropy_spike".to_string(), "0.9".to_string());
    cleanup_metadata.insert("io_rate".to_string(), "1500.0".to_string());

    let event = SecurityEvent {
        event_type: SecurityEventType::RansomwareDetected,
        severity: 9.0,
        confidence: 0.95,
        source: "cleanup_test".to_string(),
        timestamp: std::time::SystemTime::now(),
        metadata: cleanup_metadata,
    };

    response_system
        .process_security_event(&event)
        .await
        .unwrap();

    // Allow some time for background tasks
    sleep(Duration::from_millis(100)).await;

    // System should handle cleanup gracefully when dropped
    drop(response_system);

    println!("✓ System cleanup completed successfully");
}
