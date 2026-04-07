//! IPC Integration Tests
//!
//! These tests verify the complete IPC functionality by spawning a real server
//! and connecting with a test client to perform authenticated message exchanges.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rand::Rng;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use erdps_agent::config::AgentConfig;
use erdps_agent::ipc::{sign, start_ipc_server, RequestMessage, ResponseMessage};

/// Generate a random base64-encoded nonce
fn generate_nonce() -> String {
    let mut rng = rand::thread_rng();
    let nonce_bytes: [u8; 16] = rng.gen();
    BASE64.encode(nonce_bytes)
}

/// Read a length-prefixed message from a TCP stream
async fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>> {
    // Read 4-byte big-endian length prefix
    let mut length_buf = [0u8; 4];
    stream
        .read_exact(&mut length_buf)
        .await
        .context("Failed to read message length")?;

    let message_length = u32::from_be_bytes(length_buf) as usize;

    // Sanity check: prevent excessive memory allocation
    if message_length > 1024 * 1024 {
        // 1MB limit
        return Err(anyhow!("Message too large: {} bytes", message_length));
    }

    // Read message body
    let mut message_buf = vec![0u8; message_length];
    stream
        .read_exact(&mut message_buf)
        .await
        .context("Failed to read message body")?;

    Ok(message_buf)
}

/// Write a length-prefixed message to a TCP stream
async fn write_frame(stream: &mut TcpStream, message: &[u8]) -> Result<()> {
    // Write 4-byte big-endian length prefix
    let length = message.len() as u32;
    stream
        .write_all(&length.to_be_bytes())
        .await
        .context("Failed to write message length")?;

    // Write message body
    stream
        .write_all(message)
        .await
        .context("Failed to write message body")?;

    stream.flush().await.context("Failed to flush stream")?;

    Ok(())
}

/// Find an available port for testing
async fn find_available_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .context("Failed to bind to ephemeral port")?;

    let port = listener
        .local_addr()
        .context("Failed to get local address")?
        .port();

    drop(listener);
    Ok(port)
}

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

/// Verify a response message signature
fn verify_response_signature(
    response: &ResponseMessage,
    expected_nonce: &str,
    key: &[u8],
) -> Result<()> {
    // Check that nonce matches the request
    if response.nonce != expected_nonce {
        return Err(anyhow!(
            "Nonce mismatch: expected '{}', got '{}'",
            expected_nonce,
            response.nonce
        ));
    }

    // Verify the response signature
    let expected_signature = sign(
        "response",
        response.timestamp,
        &response.nonce,
        &response.payload,
        key,
    )
    .context("Failed to generate expected response signature")?;

    if response.signature != expected_signature {
        return Err(anyhow!("Response signature verification failed"));
    }

    Ok(())
}

#[tokio::test]
async fn test_ipc_getstatus_roundtrip() -> Result<()> {
    // Create test configuration
    let config = Arc::new(create_test_config());
    let ipc_key = BASE64
        .decode(&config.ipc_key)
        .context("Failed to decode IPC key")?;

    // Find available port
    let port = find_available_port()
        .await
        .context("Failed to find available port")?;

    let bind_addr = format!("127.0.0.1:{}", port);

    // Start IPC server in background
    let server_config = Arc::clone(&config);
    let server_bind_addr = bind_addr.clone();
    let server_handle =
        tokio::spawn(async move { start_ipc_server(&server_bind_addr, server_config).await });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect to server
    let mut stream = timeout(Duration::from_secs(5), TcpStream::connect(&bind_addr))
        .await
        .context("Timeout connecting to server")?
        .context("Failed to connect to server")?;

    // Prepare getStatus request
    let nonce = generate_nonce();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("Failed to get current timestamp")?
        .as_secs() as i64;

    let command = "getStatus";
    let payload = json!({});

    // Sign the request
    let signature =
        sign(command, timestamp, &nonce, &payload, &ipc_key).context("Failed to sign request")?;

    let request = RequestMessage {
        nonce: nonce.clone(),
        timestamp,
        command: command.to_string(),
        payload,
        signature,
    };

    // Send the request
    let request_json = serde_json::to_vec(&request).context("Failed to serialize request")?;

    write_frame(&mut stream, &request_json)
        .await
        .context("Failed to send request")?;

    // Read the response with timeout
    let response_bytes = timeout(Duration::from_secs(5), read_frame(&mut stream))
        .await
        .context("Timeout reading response")?
        .context("Failed to read response")?;

    let response: ResponseMessage =
        serde_json::from_slice(&response_bytes).context("Failed to parse response JSON")?;

    // Verify the response
    assert_eq!(response.status, "success", "Expected successful response");
    verify_response_signature(&response, &nonce, &ipc_key)
        .context("Response signature verification failed")?;

    // Verify response contains expected fields
    assert!(
        response.payload.get("agent_version").is_some(),
        "Response should contain agent_version"
    );
    assert!(
        response.payload.get("status").is_some(),
        "Response should contain status"
    );
    assert!(
        response.payload.get("threats_detected").is_some(),
        "Response should contain threats_detected"
    );
    assert!(
        response.payload.get("quarantined_files").is_some(),
        "Response should contain quarantined_files"
    );

    // Clean shutdown
    drop(stream);
    server_handle.abort();

    Ok(())
}

#[tokio::test]
async fn test_ipc_invalid_signature_rejection() -> Result<()> {
    // Create test configuration
    let config = Arc::new(create_test_config());
    let _ipc_key = BASE64
        .decode(&config.ipc_key)
        .context("Failed to decode IPC key")?;

    // Find available port
    let port = find_available_port()
        .await
        .context("Failed to find available port")?;

    let bind_addr = format!("127.0.0.1:{}", port);

    // Start IPC server in background
    let server_config = Arc::clone(&config);
    let server_bind_addr = bind_addr.clone();
    let server_handle =
        tokio::spawn(async move { start_ipc_server(&server_bind_addr, server_config).await });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect to server
    let mut stream = timeout(Duration::from_secs(5), TcpStream::connect(&bind_addr))
        .await
        .context("Timeout connecting to server")?
        .context("Failed to connect to server")?;

    // Prepare request with invalid signature
    let nonce = generate_nonce();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("Failed to get current timestamp")?
        .as_secs() as i64;

    let command = "getStatus";
    let payload = json!({});

    let request = RequestMessage {
        nonce: nonce.clone(),
        timestamp,
        command: command.to_string(),
        payload,
        signature: "invalid_signature".to_string(), // Invalid signature
    };

    // Send the request
    let request_json = serde_json::to_vec(&request).context("Failed to serialize request")?;

    write_frame(&mut stream, &request_json)
        .await
        .context("Failed to send request")?;

    // Server should close connection due to invalid signature
    // Try to read response - should fail or get connection closed
    let result = timeout(Duration::from_secs(2), read_frame(&mut stream)).await;

    // We expect either a timeout or connection closed error
    assert!(
        result.is_err() || result.unwrap().is_err(),
        "Server should reject invalid signature and close connection"
    );

    // Clean shutdown
    drop(stream);
    server_handle.abort();

    Ok(())
}

#[tokio::test]
async fn test_ipc_replay_attack_prevention() -> Result<()> {
    // Create test configuration
    let config = Arc::new(create_test_config());
    let ipc_key = BASE64
        .decode(&config.ipc_key)
        .context("Failed to decode IPC key")?;

    // Find available port
    let port = find_available_port()
        .await
        .context("Failed to find available port")?;

    let bind_addr = format!("127.0.0.1:{}", port);

    // Start IPC server in background
    let server_config = Arc::clone(&config);
    let server_bind_addr = bind_addr.clone();
    let server_handle =
        tokio::spawn(async move { start_ipc_server(&server_bind_addr, server_config).await });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect to server
    let mut stream = timeout(Duration::from_secs(5), TcpStream::connect(&bind_addr))
        .await
        .context("Timeout connecting to server")?
        .context("Failed to connect to server")?;

    // Prepare valid request
    let nonce = generate_nonce();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("Failed to get current timestamp")?
        .as_secs() as i64;

    let command = "getStatus";
    let payload = json!({});

    let signature =
        sign(command, timestamp, &nonce, &payload, &ipc_key).context("Failed to sign request")?;

    let request = RequestMessage {
        nonce: nonce.clone(),
        timestamp,
        command: command.to_string(),
        payload,
        signature,
    };

    let request_json = serde_json::to_vec(&request).context("Failed to serialize request")?;

    // Send the request first time - should succeed
    write_frame(&mut stream, &request_json)
        .await
        .context("Failed to send first request")?;

    let response_bytes = timeout(Duration::from_secs(5), read_frame(&mut stream))
        .await
        .context("Timeout reading first response")?
        .context("Failed to read first response")?;

    let response: ResponseMessage =
        serde_json::from_slice(&response_bytes).context("Failed to parse first response JSON")?;

    assert_eq!(response.status, "success", "First request should succeed");

    // Send the same request again - should be rejected due to nonce replay
    write_frame(&mut stream, &request_json)
        .await
        .context("Failed to send second request")?;

    // Server should close connection due to replay attack
    let result = timeout(Duration::from_secs(2), read_frame(&mut stream)).await;

    // We expect either a timeout or connection closed error
    assert!(
        result.is_err() || result.unwrap().is_err(),
        "Server should reject replay attack and close connection"
    );

    // Clean shutdown
    drop(stream);
    server_handle.abort();

    Ok(())
}
