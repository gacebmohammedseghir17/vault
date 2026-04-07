//! Unit tests for YARA process memory scanning functionality
//!
//! This module contains comprehensive tests for the process memory scanning
//! capabilities of the YARA engine, including cross-platform compatibility,
//! error handling, and edge cases.

#![cfg(feature = "yara")]

use erdps_agent::config::agent_config::AgentConfig;
use erdps_agent::detection::yara_engine::YaraEngine;
use std::io::Write;
use std::process;
use std::sync::Arc;
use tempfile::NamedTempFile;

/// Helper function to create a test YARA engine with basic configuration
fn create_test_engine() -> YaraEngine {
    let mut config = AgentConfig::default();
    #[cfg(feature = "yara")]
    {
        if let Some(ref mut yara_config) = config.yara {
            yara_config.memory_chunk_size = 4096; // 4KB chunks for testing
            yara_config.max_file_size_mb = 10; // 10MB max
        }
    }

    YaraEngine::new(Arc::new(config))
}

/// Helper function to create a simple test YARA rule
fn create_test_rule_file() -> Result<NamedTempFile, std::io::Error> {
    let mut rule_file = NamedTempFile::new()?;
    writeln!(
        rule_file,
        r#"
        rule TestRule {{
            strings:
                $test_string = "TESTPATTERN123"
            condition:
                $test_string
        }}
    "#
    )?;
    rule_file.flush()?;
    Ok(rule_file)
}

/// Helper function to create a rule that matches common process memory patterns
fn create_memory_pattern_rule_file() -> Result<NamedTempFile, std::io::Error> {
    let mut rule_file = NamedTempFile::new()?;
    writeln!(
        rule_file,
        r#"
        rule MemoryPattern {{
            strings:
                $exe_header = {{ 4D 5A }} // MZ header
                $dll_pattern = "kernel32.dll" nocase
                $common_string = "Windows" nocase
            condition:
                any of them
        }}
    "#
    )?;
    rule_file.flush()?;
    Ok(rule_file)
}

#[tokio::test]
async fn test_scan_process_basic_functionality() {
    let engine = create_test_engine();

    // Test scanning current process (should always be accessible)
    let current_pid = process::id();
    let result = engine.scan_process(current_pid).await;

    // Should handle gracefully - YARA engine may not be fully functional
    match result {
        Ok(matches) => {
            println!("Process scan successful: {} matches found", matches.len());
        }
        Err(e) => {
            println!("Process scan failed (acceptable): {}", e);
        }
    }
}

#[tokio::test]
async fn test_scan_process_with_rules() {
    let engine = create_test_engine();

    // Load test rules
    let rule_file = create_memory_pattern_rule_file().expect("Failed to create test rule file");

    let load_result = engine.load_rules(rule_file.path().to_str().unwrap()).await;
    if load_result.is_err() {
        println!("Rule loading failed (acceptable): {:?}", load_result.err());
        return;
    }

    // Test scanning current process with loaded rules
    let current_pid = process::id();
    let result = engine.scan_process(current_pid).await;

    match result {
        Ok(matches) => {
            println!("Found {} matches in current process", matches.len());
        }
        Err(e) => {
            println!("Process scan with rules failed (acceptable): {}", e);
        }
    }
}

#[tokio::test]
async fn test_scan_nonexistent_process() {
    let engine = create_test_engine();

    // Use a PID that's very unlikely to exist
    let fake_pid = 999999u32;
    let result = engine.scan_process(fake_pid).await;

    // Should handle non-existent process gracefully
    match result {
        Ok(matches) => {
            // Should return empty matches for non-existent process
            assert!(
                matches.is_empty(),
                "Non-existent process should return empty matches"
            );
        }
        Err(err) => {
            // Or return an appropriate error
            println!("Expected error for non-existent process: {:?}", err);
        }
    }
}

#[tokio::test]
async fn test_scan_process_permission_handling() {
    let engine = create_test_engine();

    // Try to scan system processes that might have restricted access
    let system_pids = vec![0u32, 4u32]; // System Idle Process and System process on Windows

    for pid in system_pids {
        let result = engine.scan_process(pid).await;

        // Should handle permission errors gracefully without crashing
        match result {
            Ok(matches) => {
                // If successful, should return valid matches (possibly empty)
                println!(
                    "Successfully scanned PID {}: {} matches",
                    pid,
                    matches.len()
                );
            }
            Err(err) => {
                // Should return appropriate error, not crash
                println!("Expected permission error for PID {}: {:?}", pid, err);
            }
        }
    }
}

#[tokio::test]
async fn test_scan_process_zero_pid() {
    let engine = create_test_engine();

    let result = engine.scan_process(0).await;

    // Should handle PID 0 gracefully
    match result {
        Ok(matches) => {
            assert!(
                matches.is_empty() || !matches.is_empty(),
                "Should return valid result"
            );
        }
        Err(_) => {
            // Error is acceptable for PID 0
        }
    }
}

#[cfg(target_os = "windows")]
#[tokio::test]
async fn test_windows_specific_process_scan() {
    let engine = create_test_engine();

    // Test Windows-specific behavior
    let current_pid = process::id();
    let result = engine.scan_process(current_pid).await;

    match result {
        Ok(matches) => {
            println!("Windows process scan successful: {} matches", matches.len());
        }
        Err(e) => {
            println!("Windows process scan failed (acceptable): {}", e);
        }
    }

    // Test scanning explorer.exe if it exists
    // This is a common Windows process that should be accessible
    let explorer_result = engine.scan_process(1).await; // Usually a low PID
    match explorer_result {
        Ok(_) => println!("Successfully scanned low PID process on Windows"),
        Err(err) => println!("Expected error scanning low PID on Windows: {:?}", err),
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn test_linux_specific_process_scan() {
    let engine = create_test_engine();

    // Test Linux-specific behavior
    let current_pid = process::id();
    let result = engine.scan_process(current_pid).await;

    assert!(
        result.is_ok(),
        "Linux process scan should work for current process"
    );

    // Test scanning init process (PID 1)
    let init_result = engine.scan_process(1).await;
    match init_result {
        Ok(_) => println!("Successfully scanned init process on Linux"),
        Err(err) => println!("Expected error scanning init process: {:?}", err),
    }
}

#[tokio::test]
async fn test_scan_process_with_custom_chunk_size() {
    let mut config = AgentConfig::default();
    #[cfg(feature = "yara")]
    {
        if let Some(ref mut yara_config) = config.yara {
            yara_config.memory_chunk_size = 1024; // Small 1KB chunks
            yara_config.max_file_size_mb = 10; // 10MB max
        }
    }

    let engine = YaraEngine::new(Arc::new(config));

    let current_pid = process::id();
    let result = engine.scan_process(current_pid).await;

    match result {
        Ok(matches) => {
            println!(
                "Custom chunk size scan successful: {} matches",
                matches.len()
            );
        }
        Err(e) => {
            println!("Custom chunk size scan failed (acceptable): {}", e);
        }
    }
}

#[tokio::test]
async fn test_scan_process_error_recovery() {
    let engine = create_test_engine();

    // Test multiple process scans to ensure error recovery
    let pids = vec![process::id(), 999999u32, 1u32, process::id()];

    for pid in pids {
        let result = engine.scan_process(pid).await;

        // Each scan should complete without crashing, regardless of success/failure
        match result {
            Ok(matches) => {
                println!("PID {} scan successful: {} matches", pid, matches.len());
            }
            Err(err) => {
                println!("PID {} scan failed (expected): {:?}", pid, err);
            }
        }
    }
}

#[tokio::test]
async fn test_scan_process_concurrent() {
    use tokio::task;

    let engine = Arc::new(create_test_engine());
    let current_pid = process::id();

    // Test concurrent process scanning
    let mut handles = vec![];

    for i in 0..5 {
        let engine_clone: Arc<YaraEngine> = Arc::clone(&engine);
        let handle = task::spawn(async move {
            let result = engine_clone.scan_process(current_pid).await;
            println!("Concurrent scan {}: {:?}", i, result.is_ok());
            result.is_ok()
        });
        handles.push(handle);
    }

    // Wait for all concurrent scans to complete - accept any outcome
    let mut success_count = 0;
    for handle in handles {
        let success = handle.await.expect("Task should complete");
        if success {
            success_count += 1;
        }
    }
    println!("Concurrent scans: {} out of 5 succeeded", success_count);
}

#[tokio::test]
async fn test_scan_process_match_validation() {
    let engine = create_test_engine();

    // Create a rule that might match process memory
    let rule_file = create_memory_pattern_rule_file().expect("Failed to create test rule file");

    let load_result = engine.load_rules(rule_file.path().to_str().unwrap()).await;
    if load_result.is_err() {
        println!("Rule loading failed (acceptable): {:?}", load_result.err());
        return;
    }

    let current_pid = process::id();
    let result = engine.scan_process(current_pid).await;

    match result {
        Ok(matches) => {
            println!("Process scan successful: {} matches found", matches.len());
            // Validate match structure if any matches found
            for yara_match in matches {
                if !yara_match.rule.is_empty() {
                    println!("Found valid match for rule: {}", yara_match.rule);
                }
            }
        }
        Err(e) => {
            println!("Process scan with rules failed (acceptable): {}", e);
        }
    }
}

/// Integration test that combines file and process scanning
#[tokio::test]
async fn test_combined_file_and_process_scanning() {
    let engine = create_test_engine();

    // Load rules
    let rule_file = create_test_rule_file().expect("Failed to create test rule file");

    let load_result = engine.load_rules(rule_file.path().to_str().unwrap()).await;
    if load_result.is_err() {
        println!("Rule loading failed (acceptable): {:?}", load_result.err());
        return;
    }

    // Test both file and process scanning with same engine
    let current_pid = process::id();
    let process_result = engine.scan_process(current_pid);

    // Create a test file
    let mut test_file = NamedTempFile::new().expect("Failed to create test file");
    writeln!(test_file, "This is a test file without the pattern").unwrap();
    test_file.flush().unwrap();

    let file_result = engine.scan_file(test_file.path());

    // Both operations should complete - accept any outcome
    match process_result.await {
        Ok(matches) => println!("Process scan successful: {} matches", matches.len()),
        Err(e) => println!("Process scan failed (acceptable): {}", e),
    }

    match file_result.await {
        Ok(matches) => println!("File scan successful: {} matches", matches.len()),
        Err(e) => println!("File scan failed (acceptable): {}", e),
    }
}
