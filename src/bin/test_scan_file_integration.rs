//! Integration test for scan_file IPC functionality
//!
//! This test verifies that the agent can:
//! 1. Start an IPC server in test mode
//! 2. Accept scan_file requests
//! 3. Return either yara_match or error(yara_scan) JSON responses

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use erdps_agent::config::AgentConfig;
use erdps_agent::ipc::{sign, RequestMessage};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Test configuration
const TEST_IPC_ADDRESS: &str = "127.0.0.1:8889";
const TEST_TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging for test
    env_logger::init();

    println!("Starting scan_file integration test...");

    // Load the same config that the server will use
    let config = Arc::new(AgentConfig::load_or_default("config/agent.toml"));

    // Start the IPC server in a background task
    let server_handle = tokio::spawn(async move {
        // Start IPC server in background
        let server_result = erdps_agent::ipc::start_ipc_server(TEST_IPC_ADDRESS, config).await;

        if let Err(e) = server_result {
            eprintln!("IPC server failed: {}", e);
        }
    });

    // Give the server time to start
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Test cases
    let test_cases = vec![
        TestCase {
            name: "Valid file - no detection",
            path: "config/agent.toml", // Use existing file
            expected_event_type: "scan_complete",
            should_succeed: true,
        },
        TestCase {
            name: "Valid file - malware detection",
            path: "wannacry_sample.exe", // Contains WannaCry ransomware patterns
            expected_event_type: "yara_match",
            should_succeed: true,
        },
        TestCase {
            name: "Non-existent file",
            path: "non_existent_file.txt",
            expected_event_type: "error",
            should_succeed: false,
        },
    ];

    let mut passed = 0;
    let mut failed = 0;

    for test_case in test_cases {
        println!("\nRunning test: {}", test_case.name);

        match run_test_case(&test_case).await {
            Ok(_) => {
                println!("✓ Test passed: {}", test_case.name);
                passed += 1;
            }
            Err(e) => {
                println!("✗ Test failed: {} - {}", test_case.name, e);
                failed += 1;
            }
        }
    }

    // Clean up
    server_handle.abort();

    println!("\n=== Test Results ===");
    println!("Passed: {}", passed);
    println!("Failed: {}", failed);

    if failed == 0 {
        println!("All tests passed! ✓");
        Ok(())
    } else {
        anyhow::bail!("Some tests failed")
    }
}

#[derive(Debug)]
struct TestCase {
    name: &'static str,
    path: &'static str,
    expected_event_type: &'static str,
    should_succeed: bool,
}

async fn run_test_case(test_case: &TestCase) -> Result<()> {
    // Connect to IPC server
    let mut stream = timeout(TEST_TIMEOUT, TcpStream::connect(TEST_IPC_ADDRESS))
        .await
        .context("Timeout connecting to IPC server")?
        .context("Failed to connect to IPC server")?;

    // Load config to get IPC key
    let config = AgentConfig::load_or_default("config/agent.toml");
    let ipc_key = BASE64
        .decode(&config.ipc_key)
        .context("Failed to decode IPC key")?;

    // Create scan_file request payload
    let payload = json!({
        "path": test_case.path
    });

    // Create properly formatted RequestMessage
    let mut request = RequestMessage {
        nonce: generate_test_nonce(),
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64,
        command: "scan_file".to_string(),
        payload,
        signature: String::new(), // Will be filled by sign function
    };

    // Sign the request
    request.signature = sign(
        &request.command,
        request.timestamp,
        &request.nonce,
        &request.payload,
        &ipc_key,
    )
    .context("Failed to sign request")?;

    // Serialize and send request
    let request_json = serde_json::to_vec(&request).context("Failed to serialize request")?;

    // Write length-prefixed message
    let length = request_json.len() as u32;
    stream
        .write_all(&length.to_be_bytes())
        .await
        .context("Failed to write request length")?;
    stream
        .write_all(&request_json)
        .await
        .context("Failed to write request")?;
    stream.flush().await.context("Failed to flush request")?;

    // Read response
    let mut length_bytes = [0u8; 4];
    timeout(TEST_TIMEOUT, stream.read_exact(&mut length_bytes))
        .await
        .context("Timeout reading response length")?
        .context("Failed to read response length")?;

    let response_length = u32::from_be_bytes(length_bytes) as usize;
    if response_length > 1024 * 1024 {
        // 1MB limit
        anyhow::bail!("Response too large: {} bytes", response_length);
    }

    let mut response_bytes = vec![0u8; response_length];
    timeout(TEST_TIMEOUT, stream.read_exact(&mut response_bytes))
        .await
        .context("Timeout reading response")?
        .context("Failed to read response")?;

    let response_json = String::from_utf8(response_bytes).context("Invalid UTF-8 in response")?;

    let response: Value =
        serde_json::from_str(&response_json).context("Failed to parse response JSON")?;

    // Validate response structure
    validate_response(&response, test_case).context("Response validation failed")?;

    Ok(())
}

fn validate_response(response: &Value, test_case: &TestCase) -> Result<()> {
    // Check if response has expected structure (ResponseMessage format)
    let status = response
        .get("status")
        .and_then(|s| s.as_str())
        .context("Missing or invalid 'status' field")?;

    let expected_status = if test_case.should_succeed {
        "success"
    } else {
        "error"
    };
    if status != expected_status {
        anyhow::bail!(
            "Expected status='{}', got status='{}'",
            expected_status,
            status
        );
    }

    let payload = response
        .get("payload")
        .context("Missing 'payload' field in response")?;

    let event_type = payload
        .get("event_type")
        .and_then(|et| et.as_str())
        .context("Missing or invalid 'event_type' in payload")?;

    if event_type != test_case.expected_event_type {
        anyhow::bail!(
            "Expected event_type='{}', got event_type='{}'",
            test_case.expected_event_type,
            event_type
        );
    }

    // Additional validation based on event type
    match event_type {
        "yara_match" => {
            // Should have file, matches, timestamp
            payload
                .get("file")
                .context("Missing 'file' field in yara_match event")?;
            payload
                .get("matches")
                .context("Missing 'matches' field in yara_match event")?;
            payload
                .get("timestamp")
                .context("Missing 'timestamp' field in yara_match event")?;
        }
        "error" => {
            // Should have context="yara_scan", msg, timestamp
            let context = payload
                .get("context")
                .and_then(|c| c.as_str())
                .context("Missing 'context' field in error event")?;

            if context != "yara_scan" {
                anyhow::bail!("Expected context='yara_scan', got context='{}'", context);
            }

            payload
                .get("msg")
                .context("Missing 'msg' field in error event")?;
            payload
                .get("timestamp")
                .context("Missing 'timestamp' field in error event")?;
        }
        "scan_complete" => {
            // Should have file, matches_found, timestamp
            payload
                .get("file")
                .context("Missing 'file' field in scan_complete event")?;
            payload
                .get("matches_found")
                .context("Missing 'matches_found' field in scan_complete event")?;
            payload
                .get("timestamp")
                .context("Missing 'timestamp' field in scan_complete event")?;
        }
        _ => {
            anyhow::bail!("Unexpected event_type: {}", event_type);
        }
    }

    println!("Response validation passed for event_type: {}", event_type);
    Ok(())
}

fn generate_test_nonce() -> String {
    use rand::Rng;

    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..16).map(|_| rng.gen::<u8>()).collect();
    hex::encode(bytes)
}
