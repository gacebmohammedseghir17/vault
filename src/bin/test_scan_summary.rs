//! Test scan_summary IPC command functionality
//! This test verifies that the scan_summary command returns proper telemetry data

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use erdps_agent::config::AgentConfig;
use erdps_agent::ipc::{sign, RequestMessage, ResponseMessage};
use rand::{Rng, RngCore};
use serde_json::json;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, Duration};

const TEST_IPC_ADDRESS: &str = "127.0.0.1:8081";

/// Create a test configuration with a random IPC key
fn create_test_config() -> AgentConfig {
    let mut rng = rand::thread_rng();
    let key_bytes: [u8; 32] = rng.gen();
    let ipc_key = BASE64.encode(key_bytes);

    AgentConfig {
        ipc_key,
        ..AgentConfig::default()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    env_logger::init();

    println!("Starting scan_summary IPC integration test...");

    // Create test configuration
    let config = Arc::new(create_test_config());

    // Start the IPC server in a background task
    let server_config = Arc::clone(&config);
    let server_handle = tokio::spawn(async move {
        let server_result =
            erdps_agent::ipc::start_ipc_server(TEST_IPC_ADDRESS, server_config).await;

        if let Err(e) = server_result {
            eprintln!("IPC server failed: {}", e);
        }
    });

    // Give the server time to start
    sleep(Duration::from_millis(500)).await;

    // Test scan_summary command
    match test_scan_summary_command(&config).await {
        Ok(_) => println!("✓ scan_summary command test passed"),
        Err(e) => {
            eprintln!("✗ scan_summary command test failed: {}", e);
            server_handle.abort();
            return Err(e);
        }
    }

    println!("All scan_summary IPC tests passed successfully!");

    // Clean shutdown
    server_handle.abort();
    Ok(())
}

/// Test the scan_summary IPC command
async fn test_scan_summary_command(config: &AgentConfig) -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing scan_summary command...");

    // Connect to the IPC server
    let mut stream = TcpStream::connect(TEST_IPC_ADDRESS).await?;

    // Generate a random nonce
    let mut nonce_bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = BASE64.encode(nonce_bytes);

    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    let command = "scan_summary";
    let payload = json!({});

    // Sign the request
    let ipc_key = BASE64.decode(&config.ipc_key)?;
    let signature = sign(command, timestamp, &nonce, &payload, &ipc_key)?;

    // Create scan_summary request
    let request = RequestMessage {
        nonce,
        timestamp,
        command: command.to_string(),
        payload,
        signature,
    };

    // Serialize and send request using length-prefixed framing
    let request_json = serde_json::to_vec(&request)?;

    // Write 4-byte big-endian length prefix
    let length = request_json.len() as u32;
    stream.write_all(&length.to_be_bytes()).await?;

    // Write message body
    stream.write_all(&request_json).await?;
    stream.flush().await?;

    // Read response using length-prefixed framing
    // Read 4-byte big-endian length prefix
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let message_length = u32::from_be_bytes(len_buf) as usize;

    // Sanity check: prevent excessive memory allocation
    if message_length > 1024 * 1024 {
        return Err(format!("Message too large: {} bytes", message_length).into());
    }

    // Read message body
    let mut response_bytes = vec![0u8; message_length];
    stream.read_exact(&mut response_bytes).await?;

    let response: ResponseMessage = serde_json::from_slice(&response_bytes)?;

    // Verify response structure
    if response.status != "success" {
        return Err(format!("Expected success status, got: {}", response.status).into());
    }

    // Verify scan_summary payload structure
    let payload = &response.payload;

    // Check required fields
    let required_fields = [
        "event_type",
        "timestamp",
        "total_scans",
        "total_matches",
        "total_errors",
        "scans_per_second",
        "median_scan_latency_ms",
        "queue_depth",
        "active_scan_threads",
        "scan_throughput_mbps",
        "dedup_hits",
        "dedup_misses",
        "cache_hit_rate",
        "file_size_distribution",
        "total_bytes_scanned",
        "average_file_size",
        "latency_histogram",
        "io_wait_time_ms",
        "actual_scan_time_ms",
        "peak_memory_usage_mb",
        "rules_loaded",
        "rules_compilation_time_ms",
    ];

    for field in &required_fields {
        if !payload.as_object().unwrap().contains_key(*field) {
            return Err(format!("Missing required field in scan_summary: {}", field).into());
        }
    }

    // Verify event_type
    if payload["event_type"] != "scan_summary" {
        return Err(format!(
            "Expected event_type 'scan_summary', got: {}",
            payload["event_type"]
        )
        .into());
    }

    // Verify latency_histogram structure
    let histogram = &payload["latency_histogram"];
    let histogram_fields = [
        "p50",
        "p90",
        "p95",
        "p99",
        "min",
        "max",
        "mean",
        "sample_count",
    ];

    for field in &histogram_fields {
        if !histogram.as_object().unwrap().contains_key(*field) {
            return Err(format!("Missing histogram field: {}", field).into());
        }
    }

    println!("✓ scan_summary response structure is valid");
    println!("✓ Total scans: {}", payload["total_scans"]);
    println!("✓ Total matches: {}", payload["total_matches"]);
    println!("✓ Scans per second: {}", payload["scans_per_second"]);
    println!("✓ Queue depth: {}", payload["queue_depth"]);

    Ok(())
}
