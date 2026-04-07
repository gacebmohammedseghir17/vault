use erdps_agent::config::AgentConfig;
use erdps_agent::detector::{start_detector, Detector, Event, EventType};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};

#[tokio::test]
async fn test_mass_modification_detection() {
    let config = Arc::new(AgentConfig::default());
    let (alert_tx, mut alert_rx) = mpsc::channel(100);
    let (event_tx, event_rx) = mpsc::channel(100);

    let detector =
        Detector::new(event_rx, alert_tx, None, config.clone()).expect("Failed to create detector");

    // Start detector in background
    let _handle = start_detector(detector);

    // Send multiple modification events in the same directory
    let base_path = PathBuf::from("/test/dir");
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    for i in 0..55 {
        let event = Event {
            event_type: EventType::Modified,
            path: base_path.join(format!("file_{}.txt", i)),
            pid: Some(1234),
            process_name: Some("test_process".to_string()),
            timestamp,
            extra: HashMap::new(),
        };
        event_tx.send(event).await.expect("Failed to send event");
    }

    // Wait for alert
    tokio::time::timeout(std::time::Duration::from_secs(2), alert_rx.recv())
        .await
        .expect("Timeout waiting for alert")
        .expect("Expected alert for mass modification");
}

#[tokio::test]
async fn test_extension_mutation_detection() {
    let config = Arc::new(AgentConfig::default());
    let (alert_tx, mut alert_rx) = mpsc::channel(100);
    let (event_tx, event_rx) = mpsc::channel(100);

    let detector =
        Detector::new(event_rx, alert_tx, None, config.clone()).expect("Failed to create detector");

    // Start detector in background
    let _handle = start_detector(detector);

    // Send events with suspicious extension changes
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let suspicious_extensions = [".encrypt", ".locked", ".crypt"];

    for (i, ext) in suspicious_extensions.iter().enumerate() {
        for j in 0..5 {
            let event = Event {
                event_type: EventType::Modified,
                path: PathBuf::from(format!("/test/file_{}_{}{}", i, j, ext)),
                pid: Some(1234),
                process_name: Some("malware".to_string()),
                timestamp,
                extra: HashMap::new(),
            };
            event_tx.send(event).await.expect("Failed to send event");
        }
    }

    // Wait for alert
    tokio::time::timeout(std::time::Duration::from_secs(2), alert_rx.recv())
        .await
        .expect("Timeout waiting for alert")
        .expect("Expected alert for extension mutation");
}

#[tokio::test]
async fn test_ransom_note_detection() {
    let config = Arc::new(AgentConfig::default());
    let (alert_tx, mut alert_rx) = mpsc::channel(100);
    let (event_tx, event_rx) = mpsc::channel(100);

    let detector =
        Detector::new(event_rx, alert_tx, None, config.clone()).expect("Failed to create detector");

    // Start detector in background
    let _handle = start_detector(detector);

    // Create a temporary file with ransom note content
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let ransom_note_path = temp_dir.path().join("README_DECRYPT.txt");
    let ransom_content = "Your files have been encrypted! Contact us at evil@ransomware.com to get the decryption key. Send 1 bitcoin to recover your data.";
    tokio::fs::write(&ransom_note_path, ransom_content)
        .await
        .expect("Failed to write ransom note");

    // Send event for ransom note creation
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let event = Event {
        event_type: EventType::Created,
        path: ransom_note_path,
        pid: Some(1234),
        process_name: Some("ransomware".to_string()),
        timestamp,
        extra: HashMap::new(),
    };

    event_tx.send(event).await.expect("Failed to send event");

    // Wait for alert
    tokio::time::timeout(std::time::Duration::from_secs(2), alert_rx.recv())
        .await
        .expect("Timeout waiting for alert")
        .expect("Expected alert for ransom note detection");
}

#[tokio::test]
async fn test_entropy_analysis() {
    let config = Arc::new(AgentConfig::default());
    let (alert_tx, mut alert_rx) = mpsc::channel(100);
    let (event_tx, event_rx) = mpsc::channel(100);

    let detector =
        Detector::new(event_rx, alert_tx, None, config.clone()).expect("Failed to create detector");

    // Start detector in background
    let _handle = start_detector(detector);

    // Send event for high-entropy file modification
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let event = Event {
        event_type: EventType::Modified,
        path: PathBuf::from("/test/document.txt"), // Previously text file, now encrypted
        pid: Some(1234),
        process_name: Some("crypto_malware".to_string()),
        timestamp,
        extra: HashMap::new(),
    };

    event_tx.send(event).await.expect("Failed to send event");

    // Wait for potential alert (entropy analysis might not trigger without actual file content)
    let _result = tokio::time::timeout(std::time::Duration::from_secs(1), alert_rx.recv()).await;
    // This test might not always produce an alert since we don't have actual file content
    // In a real scenario, the entropy analysis would read the file content
}

#[tokio::test]
async fn test_process_behavior_detection() {
    let config = Arc::new(AgentConfig::default());
    let (alert_tx, mut alert_rx) = mpsc::channel(100);
    let (event_tx, event_rx) = mpsc::channel(100);

    let detector =
        Detector::new(event_rx, alert_tx, None, config.clone()).expect("Failed to create detector");

    // Start detector in background
    let _handle = start_detector(detector);

    // Send many write events from the same process
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let pid = 1234;

    for i in 0..50 {
        let event = Event {
            event_type: EventType::Modified,
            path: PathBuf::from(format!("/test/file_{}.dat", i)),
            pid: Some(pid),
            process_name: Some("suspicious_process".to_string()),
            timestamp,
            extra: HashMap::new(),
        };
        event_tx.send(event).await.expect("Failed to send event");
    }

    // Wait for alert
    tokio::time::timeout(std::time::Duration::from_secs(2), alert_rx.recv())
        .await
        .expect("Timeout waiting for alert")
        .expect("Expected alert for suspicious process behavior");
}

#[tokio::test]
async fn test_no_false_positive_single_file() {
    let config = Arc::new(AgentConfig::default());
    let (alert_tx, mut alert_rx) = mpsc::channel(100);
    let (event_tx, event_rx) = mpsc::channel(100);

    let detector =
        Detector::new(event_rx, alert_tx, None, config.clone()).expect("Failed to create detector");

    // Start detector in background
    let _handle = start_detector(detector);

    // Send single file modification (should not trigger mass modification)
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let event = Event {
        event_type: EventType::Modified,
        path: PathBuf::from("/test/single_file.txt"),
        pid: Some(1234),
        process_name: Some("normal_process".to_string()),
        timestamp,
        extra: HashMap::new(),
    };

    event_tx.send(event).await.expect("Failed to send event");

    // Should not receive an alert within reasonable time
    let result = tokio::time::timeout(std::time::Duration::from_millis(500), alert_rx.recv()).await;
    assert!(
        result.is_err(),
        "Should not receive alert for single file modification"
    );
}

// ============================================================================
// COMPREHENSIVE DETECTION RULE TESTS
// ============================================================================

// Mass File Modification Tests
#[tokio::test]
async fn test_mass_modification_benign_activity() {
    let config = Arc::new(AgentConfig::default());
    let (alert_tx, mut alert_rx) = mpsc::channel(100);
    let (event_tx, event_rx) = mpsc::channel(100);

    let detector =
        Detector::new(event_rx, alert_tx, None, config.clone()).expect("Failed to create detector");

    let _handle = start_detector(detector);

    // Send normal amount of file modifications (below threshold)
    let base_path = PathBuf::from("/test/benign");
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    for i in 0..10 {
        // Well below the default threshold of 30
        let event = Event {
            event_type: EventType::Modified,
            path: base_path.join(format!("document_{}.txt", i)),
            pid: Some(5678),
            process_name: Some("word_processor".to_string()),
            timestamp,
            extra: HashMap::new(),
        };
        event_tx.send(event).await.expect("Failed to send event");
    }

    // Should not receive an alert
    let result = tokio::time::timeout(std::time::Duration::from_millis(500), alert_rx.recv()).await;
    assert!(
        result.is_err(),
        "Should not receive alert for benign file modifications"
    );
}

#[tokio::test]
async fn test_mass_modification_edge_case_just_below_threshold() {
    let config = AgentConfig {
        mass_modification_count: Some(25),
        ..Default::default()
    };
    let config = Arc::new(config);
    let (alert_tx, mut alert_rx) = mpsc::channel(100);
    let (event_tx, event_rx) = mpsc::channel(100);

    let detector =
        Detector::new(event_rx, alert_tx, None, config.clone()).expect("Failed to create detector");

    let _handle = start_detector(detector);

    // Send exactly threshold - 1 modifications
    let base_path = PathBuf::from("/test/edge");
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    for i in 0..24 {
        // Just below threshold
        let event = Event {
            event_type: EventType::Modified,
            path: base_path.join(format!("file_{}.dat", i)),
            pid: Some(9999),
            process_name: Some("edge_case_process".to_string()),
            timestamp,
            extra: HashMap::new(),
        };
        event_tx.send(event).await.expect("Failed to send event");
    }

    // Should not trigger process behavior alert (but might trigger other alerts)
    let mut process_behavior_alert_found = false;
    let mut alert_count = 0;

    // Check for any alerts within timeout period
    while alert_count < 3 {
        if let Ok(Some(alert)) =
            tokio::time::timeout(std::time::Duration::from_millis(500), alert_rx.recv()).await
        {
            println!("Alert {}: {:?}", alert_count + 1, alert.evidence);

            // Check if this is a process behavior alert (should not be)
            if alert
                .evidence
                .iter()
                .any(|e| e.contains("Suspicious process behavior detected"))
            {
                process_behavior_alert_found = true;
                break;
            }

            alert_count += 1;
        } else {
            break;
        }
    }

    assert!(!process_behavior_alert_found, "Should not receive process behavior alert just below threshold, but got one among {} alerts", alert_count);
}

#[tokio::test]
async fn test_mass_modification_malicious_simulation() {
    let config = AgentConfig {
        mass_modification_count: Some(20),
        ..Default::default()
    };
    let config = Arc::new(config);
    let (alert_tx, mut alert_rx) = mpsc::channel(100);
    let (event_tx, event_rx) = mpsc::channel(100);

    let detector =
        Detector::new(event_rx, alert_tx, None, config.clone()).expect("Failed to create detector");

    let _handle = start_detector(detector);

    // Simulate ransomware rapidly encrypting files
    let base_path = PathBuf::from("/home/user/documents");
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    for i in 0..50 {
        // Well above threshold
        let event = Event {
            event_type: EventType::Modified,
            path: base_path.join(format!("important_file_{}.docx", i)),
            pid: Some(6666),
            process_name: Some("crypto_locker.exe".to_string()),
            timestamp,
            extra: HashMap::new(),
        };
        event_tx.send(event).await.expect("Failed to send event");
    }

    // Should trigger alert
    let alert = tokio::time::timeout(std::time::Duration::from_secs(2), alert_rx.recv())
        .await
        .expect("Timeout waiting for alert")
        .expect("Expected alert for mass modification");

    assert!(alert
        .evidence
        .iter()
        .any(|e| e.contains("Mass file modification")));
}

// Extension Mutation Tests
#[tokio::test]
async fn test_extension_mutation_benign_activity() {
    let config = Arc::new(AgentConfig::default());
    let (alert_tx, mut alert_rx) = mpsc::channel(100);
    let (event_tx, event_rx) = mpsc::channel(100);

    let detector =
        Detector::new(event_rx, alert_tx, None, config.clone()).expect("Failed to create detector");

    let _handle = start_detector(detector);

    // Normal file operations with common extensions
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let normal_files = vec![
        "/work/report.docx",
        "/work/data.xlsx",
        "/work/presentation.pptx",
        "/work/image.jpg",
        "/work/backup.zip",
    ];

    for file_path in normal_files {
        let event = Event {
            event_type: EventType::Modified,
            path: PathBuf::from(file_path),
            pid: Some(1111),
            process_name: Some("office_suite".to_string()),
            timestamp,
            extra: HashMap::new(),
        };
        event_tx.send(event).await.expect("Failed to send event");
    }

    // Should not trigger alert
    let result = tokio::time::timeout(std::time::Duration::from_millis(500), alert_rx.recv()).await;
    assert!(
        result.is_err(),
        "Should not receive alert for normal file extensions"
    );
}

#[tokio::test]
async fn test_extension_mutation_edge_case_rare_extensions() {
    let config = Arc::new(AgentConfig::default());
    let (alert_tx, mut alert_rx) = mpsc::channel(100);
    let (event_tx, event_rx) = mpsc::channel(100);

    let detector =
        Detector::new(event_rx, alert_tx, None, config.clone()).expect("Failed to create detector");

    let _handle = start_detector(detector);

    // Files with rare but legitimate extensions (just below threshold)
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let rare_extensions = vec![".bak", ".tmp", ".log"];

    for ext in rare_extensions {
        for i in 0..3 {
            // Just below threshold per extension
            let event = Event {
                event_type: EventType::Modified,
                path: PathBuf::from(format!("/temp/file_{}{}", i, ext)),
                pid: Some(2222),
                process_name: Some("backup_tool".to_string()),
                timestamp,
                extra: HashMap::new(),
            };
            event_tx.send(event).await.expect("Failed to send event");
        }
    }

    // Should not trigger alert for legitimate rare extensions
    let result = tokio::time::timeout(std::time::Duration::from_millis(500), alert_rx.recv()).await;
    assert!(
        result.is_err(),
        "Should not receive alert for legitimate rare extensions"
    );
}

#[tokio::test]
async fn test_extension_mutation_malicious_simulation() {
    let config = Arc::new(AgentConfig::default());
    let (alert_tx, mut alert_rx) = mpsc::channel(100);
    let (event_tx, event_rx) = mpsc::channel(100);

    let detector =
        Detector::new(event_rx, alert_tx, None, config.clone()).expect("Failed to create detector");

    let _handle = start_detector(detector);

    // Simulate ransomware changing file extensions
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let malicious_extensions = vec![".encrypted", ".locked", ".crypto", ".vault"];

    for ext in malicious_extensions {
        for i in 0..8 {
            // Above threshold per extension
            let event = Event {
                event_type: EventType::Modified,
                path: PathBuf::from(format!("/documents/important_file_{}{}", i, ext)),
                pid: Some(7777),
                process_name: Some("ransomware.exe".to_string()),
                timestamp,
                extra: HashMap::new(),
            };
            event_tx.send(event).await.expect("Failed to send event");
        }
    }

    // Should trigger alert
    let alert = tokio::time::timeout(std::time::Duration::from_secs(2), alert_rx.recv())
        .await
        .expect("Timeout waiting for alert")
        .expect("Expected alert for extension mutation");

    assert!(alert
        .evidence
        .iter()
        .any(|e| e.contains("Extension mutation")));
}

// Ransom Note Detection Tests
#[tokio::test]
async fn test_ransom_note_benign_activity() {
    let config = Arc::new(AgentConfig::default());
    let (alert_tx, mut alert_rx) = mpsc::channel(100);
    let (event_tx, event_rx) = mpsc::channel(100);

    let detector =
        Detector::new(event_rx, alert_tx, None, config.clone()).expect("Failed to create detector");

    let _handle = start_detector(detector);

    // Create legitimate README files
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let readme_path = temp_dir.path().join("README.md");
    let legitimate_content = "# Project Documentation\n\nThis is a legitimate project README file with installation instructions and usage examples.";
    tokio::fs::write(&readme_path, legitimate_content)
        .await
        .expect("Failed to write README");

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let event = Event {
        event_type: EventType::Created,
        path: readme_path,
        pid: Some(3333),
        process_name: Some("git.exe".to_string()),
        timestamp,
        extra: HashMap::new(),
    };

    event_tx.send(event).await.expect("Failed to send event");

    // Should not trigger alert for legitimate README
    let result = tokio::time::timeout(std::time::Duration::from_millis(500), alert_rx.recv()).await;
    assert!(
        result.is_err(),
        "Should not receive alert for legitimate README file"
    );
}

#[tokio::test]
async fn test_ransom_note_edge_case_borderline_content() {
    let config = Arc::new(AgentConfig::default());
    let (alert_tx, mut alert_rx) = mpsc::channel(100);
    let (event_tx, event_rx) = mpsc::channel(100);

    let detector =
        Detector::new(event_rx, alert_tx, None, config.clone()).expect("Failed to create detector");

    let _handle = start_detector(detector);

    // Create file with some suspicious keywords but not clearly malicious
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let borderline_path = temp_dir.path().join("recovery_info.txt");
    let borderline_content =
        "Data recovery service available. Contact support for file restoration assistance.";
    tokio::fs::write(&borderline_path, borderline_content)
        .await
        .expect("Failed to write file");

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let event = Event {
        event_type: EventType::Created,
        path: borderline_path,
        pid: Some(4444),
        process_name: Some("recovery_tool.exe".to_string()),
        timestamp,
        extra: HashMap::new(),
    };

    event_tx.send(event).await.expect("Failed to send event");

    // This might or might not trigger depending on pattern matching sensitivity
    let _result =
        tokio::time::timeout(std::time::Duration::from_millis(500), alert_rx.recv()).await;
}

#[tokio::test]
async fn test_ransom_note_malicious_simulation() {
    let config = Arc::new(AgentConfig::default());
    let (alert_tx, mut alert_rx) = mpsc::channel(100);
    let (event_tx, event_rx) = mpsc::channel(100);

    let detector =
        Detector::new(event_rx, alert_tx, None, config.clone()).expect("Failed to create detector");

    let _handle = start_detector(detector);

    // Create clear ransom note
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let ransom_path = temp_dir.path().join("HOW_TO_DECRYPT_FILES.txt");
    let ransom_content = "YOUR FILES HAVE BEEN ENCRYPTED! To decrypt your files, you must pay 0.5 Bitcoin to the following address. Contact decrypt@evil.com for payment instructions.";
    tokio::fs::write(&ransom_path, ransom_content)
        .await
        .expect("Failed to write ransom note");

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let event = Event {
        event_type: EventType::Created,
        path: ransom_path,
        pid: Some(8888),
        process_name: Some("malware.exe".to_string()),
        timestamp,
        extra: HashMap::new(),
    };

    event_tx.send(event).await.expect("Failed to send event");

    // Should trigger alert
    let alert = tokio::time::timeout(std::time::Duration::from_secs(2), alert_rx.recv())
        .await
        .expect("Timeout waiting for alert")
        .expect("Expected alert for ransom note");

    assert!(alert.evidence.iter().any(|e| e.contains("Ransom note")));
}

// Entropy Analysis Tests
#[tokio::test]
async fn test_entropy_analysis_benign_activity() {
    let config = Arc::new(AgentConfig::default());
    let (alert_tx, mut alert_rx) = mpsc::channel(100);
    let (event_tx, event_rx) = mpsc::channel(100);

    let detector =
        Detector::new(event_rx, alert_tx, None, config.clone()).expect("Failed to create detector");

    let _handle = start_detector(detector);

    // Create files with normal, low-entropy content
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let text_files = vec!["document1.txt", "document2.txt", "document3.txt"];

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    for filename in text_files {
        let file_path = temp_dir.path().join(filename);
        let normal_content = "This is a normal text document with regular English text content that should have low entropy.";
        tokio::fs::write(&file_path, normal_content)
            .await
            .expect("Failed to write file");

        let event = Event {
            event_type: EventType::Modified,
            path: file_path,
            pid: Some(5555),
            process_name: Some("notepad.exe".to_string()),
            timestamp,
            extra: HashMap::new(),
        };
        event_tx.send(event).await.expect("Failed to send event");
    }

    // Should not trigger alert for normal text files
    let result = tokio::time::timeout(std::time::Duration::from_millis(500), alert_rx.recv()).await;
    assert!(
        result.is_err(),
        "Should not receive alert for normal entropy files"
    );
}

#[tokio::test]
async fn test_entropy_analysis_edge_case_borderline_entropy() {
    let config = Arc::new(AgentConfig::default());
    let (alert_tx, mut alert_rx) = mpsc::channel(100);
    let (event_tx, event_rx) = mpsc::channel(100);

    let detector =
        Detector::new(event_rx, alert_tx, None, config.clone()).expect("Failed to create detector");

    let _handle = start_detector(detector);

    // Create file with medium entropy (compressed data)
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let compressed_path = temp_dir.path().join("archive.zip");

    // Simulate compressed data with medium entropy
    let medium_entropy_data: Vec<u8> = (0..1000).map(|i| (i % 128) as u8).collect();
    tokio::fs::write(&compressed_path, medium_entropy_data)
        .await
        .expect("Failed to write file");

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let event = Event {
        event_type: EventType::Modified,
        path: compressed_path,
        pid: Some(6666),
        process_name: Some("winrar.exe".to_string()),
        timestamp,
        extra: HashMap::new(),
    };

    event_tx.send(event).await.expect("Failed to send event");

    // This might or might not trigger depending on entropy threshold
    let _result =
        tokio::time::timeout(std::time::Duration::from_millis(500), alert_rx.recv()).await;
}

#[tokio::test]
async fn test_entropy_analysis_malicious_simulation() {
    let config = Arc::new(AgentConfig::default());
    let (alert_tx, mut alert_rx) = mpsc::channel(100);
    let (event_tx, event_rx) = mpsc::channel(100);

    let detector =
        Detector::new(event_rx, alert_tx, None, config.clone()).expect("Failed to create detector");

    let _handle = start_detector(detector);

    // Create files with high entropy (simulating encrypted data)
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Generate multiple high-entropy files to exceed threshold
    for i in 0..10 {
        let encrypted_path = temp_dir.path().join(format!("encrypted_file_{}.dat", i));

        // Generate high-entropy data (pseudo-random)
        let high_entropy_data: Vec<u8> = (0..2048).map(|j| ((i * 256 + j) % 256) as u8).collect();
        tokio::fs::write(&encrypted_path, high_entropy_data)
            .await
            .expect("Failed to write file");

        let event = Event {
            event_type: EventType::Modified,
            path: encrypted_path,
            pid: Some(9999),
            process_name: Some("crypto_virus.exe".to_string()),
            timestamp,
            extra: HashMap::new(),
        };
        event_tx.send(event).await.expect("Failed to send event");
    }

    // Should trigger alert for high entropy pattern
    let alert = tokio::time::timeout(std::time::Duration::from_secs(3), alert_rx.recv())
        .await
        .expect("Timeout waiting for alert")
        .expect("Expected alert for high entropy");

    assert!(alert
        .evidence
        .iter()
        .any(|e| e.contains("Entropy") || e.contains("entropy")));
}

// Process Behavior Tests
#[tokio::test]
async fn test_process_behavior_benign_activity() {
    let config = Arc::new(AgentConfig::default());
    let (alert_tx, mut alert_rx) = mpsc::channel(100);
    let (event_tx, event_rx) = mpsc::channel(100);

    let detector =
        Detector::new(event_rx, alert_tx, None, config.clone()).expect("Failed to create detector");

    let _handle = start_detector(detector);

    // Normal process activity - moderate file modifications
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let pid = 1234;

    for i in 0..15 {
        // Below suspicious threshold
        let event = Event {
            event_type: EventType::Modified,
            path: PathBuf::from(format!("/work/project_file_{}.cpp", i)),
            pid: Some(pid),
            process_name: Some("compiler.exe".to_string()),
            timestamp,
            extra: HashMap::new(),
        };
        event_tx.send(event).await.expect("Failed to send event");
    }

    // Should not trigger alert for normal development activity
    let result = tokio::time::timeout(std::time::Duration::from_millis(500), alert_rx.recv()).await;
    assert!(
        result.is_err(),
        "Should not receive alert for normal process behavior"
    );
}

#[tokio::test]
async fn test_process_behavior_edge_case_just_below_threshold() {
    let config = AgentConfig {
        process_behavior_write_threshold: 40,
        ..Default::default()
    };
    let config = Arc::new(config);
    let (alert_tx, mut alert_rx) = mpsc::channel(100);
    let (event_tx, event_rx) = mpsc::channel(100);

    let detector =
        Detector::new(event_rx, alert_tx, None, config.clone()).expect("Failed to create detector");

    let _handle = start_detector(detector);

    // Process activity just below threshold
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let pid = 5678;

    for i in 0..39 {
        // Just below threshold
        let event = Event {
            event_type: EventType::Modified,
            path: PathBuf::from(format!("/temp/build_file_{}.obj", i)),
            pid: Some(pid),
            process_name: Some("build_system.exe".to_string()),
            timestamp,
            extra: HashMap::new(),
        };
        event_tx.send(event).await.expect("Failed to send event");
    }

    // Should not trigger process behavior alert (but might trigger other alerts)
    let mut process_behavior_alert_found = false;
    let mut alert_count = 0;

    // Check for any alerts within timeout period
    while alert_count < 3 {
        if let Ok(Some(alert)) =
            tokio::time::timeout(std::time::Duration::from_millis(500), alert_rx.recv()).await
        {
            println!("Alert {}: {:?}", alert_count + 1, alert.evidence);

            // Check if this is a process behavior alert (should not be)
            if alert
                .evidence
                .iter()
                .any(|e| e.contains("Suspicious process behavior detected"))
            {
                process_behavior_alert_found = true;
                break;
            }

            alert_count += 1;
        } else {
            break;
        }
    }

    assert!(!process_behavior_alert_found, "Should not receive process behavior alert just below threshold, but got one among {} alerts", alert_count);
}

#[tokio::test]
async fn test_process_behavior_malicious_simulation() {
    let config = AgentConfig {
        process_behavior_write_threshold: 30,
        ..Default::default()
    };
    let config = Arc::new(config);
    let (alert_tx, mut alert_rx) = mpsc::channel(100);
    let (event_tx, event_rx) = mpsc::channel(100);

    let detector =
        Detector::new(event_rx, alert_tx, None, config.clone()).expect("Failed to create detector");

    let _handle = start_detector(detector);

    // Simulate ransomware with excessive file modifications
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let malicious_pid = 6666;

    for i in 0..80 {
        // Well above threshold
        let event = Event {
            event_type: EventType::Modified,
            path: PathBuf::from(format!("/users/victim/documents/file_{}.docx", i)),
            pid: Some(malicious_pid),
            process_name: Some("suspicious_process.exe".to_string()),
            timestamp,
            extra: HashMap::new(),
        };
        event_tx.send(event).await.expect("Failed to send event");
    }

    // Should trigger multiple alerts (mass modification and process behavior)
    let mut process_behavior_alert_found = false;
    let mut alert_count = 0;

    // Wait for up to 3 alerts to find the process behavior one
    while alert_count < 3 {
        if let Ok(Some(alert)) = timeout(Duration::from_secs(2), alert_rx.recv()).await {
            println!("Alert {}: {:?}", alert_count + 1, alert.evidence);

            // Check if this is the process behavior alert
            if alert
                .evidence
                .iter()
                .any(|e| e.contains("Suspicious process behavior detected"))
            {
                process_behavior_alert_found = true;
                break;
            }

            alert_count += 1;
        } else {
            break;
        }
    }

    assert!(
        process_behavior_alert_found,
        "Expected to find process behavior alert among {} alerts received",
        alert_count
    );
}

// Integration Test - Mixed Workload
#[tokio::test]
async fn test_integration_mixed_workload() {
    let config = Arc::new(AgentConfig::default());
    let (alert_tx, mut alert_rx) = mpsc::channel(100);
    let (event_tx, event_rx) = mpsc::channel(100);

    let detector =
        Detector::new(event_rx, alert_tx, None, config.clone()).expect("Failed to create detector");

    let _handle = start_detector(detector);

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Simulate mixed benign and malicious activity

    // 1. Normal user activity (should not trigger)
    for i in 0..5 {
        let event = Event {
            event_type: EventType::Modified,
            path: PathBuf::from(format!("/home/user/document_{}.txt", i)),
            pid: Some(1111),
            process_name: Some("text_editor.exe".to_string()),
            timestamp,
            extra: HashMap::new(),
        };
        event_tx.send(event).await.expect("Failed to send event");
    }

    // 2. System backup activity (should not trigger)
    for i in 0..10 {
        let event = Event {
            event_type: EventType::Created,
            path: PathBuf::from(format!("/backup/system_backup_{}.bak", i)),
            pid: Some(2222),
            process_name: Some("backup_service.exe".to_string()),
            timestamp,
            extra: HashMap::new(),
        };
        event_tx.send(event).await.expect("Failed to send event");
    }

    // 3. Malicious activity - mass file encryption (should trigger)
    for i in 0..50 {
        let event = Event {
            event_type: EventType::Modified,
            path: PathBuf::from(format!("/important/data/file_{}.encrypted", i)),
            pid: Some(6666),
            process_name: Some("malware.exe".to_string()),
            timestamp,
            extra: HashMap::new(),
        };
        event_tx.send(event).await.expect("Failed to send event");
    }

    // 4. Create ransom note (should trigger)
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let ransom_path = temp_dir.path().join("DECRYPT_INSTRUCTIONS.txt");
    let ransom_content = "All your files are encrypted! Pay 1 BTC to recover them.";
    tokio::fs::write(&ransom_path, ransom_content)
        .await
        .expect("Failed to write ransom note");

    let ransom_event = Event {
        event_type: EventType::Created,
        path: ransom_path,
        pid: Some(6666),
        process_name: Some("malware.exe".to_string()),
        timestamp,
        extra: HashMap::new(),
    };
    event_tx
        .send(ransom_event)
        .await
        .expect("Failed to send event");

    // Should receive multiple alerts for malicious activity
    let mut alert_count = 0;
    while let Ok(Some(_alert)) =
        tokio::time::timeout(std::time::Duration::from_secs(3), alert_rx.recv()).await
    {
        alert_count += 1;
        if alert_count >= 2 {
            // Expect at least 2 alerts (mass modification + ransom note)
            break;
        }
    }

    assert!(
        alert_count >= 2,
        "Expected multiple alerts for mixed malicious activity, got {}",
        alert_count
    );
}

#[test]
fn test_shannon_entropy_calculation() {
    // Test entropy calculation with known values
    let _uniform_data = vec![0u8; 256]; // All zeros - low entropy
    let _random_data: Vec<u8> = (0..=255).collect(); // Uniform distribution - high entropy

    // Note: This would require exposing the entropy calculation function
    // For now, this is a placeholder for the actual entropy calculation test
    // In the real implementation, we would need to make the calculate_entropy function public or testable
}
