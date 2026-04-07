use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use erdps_agent::config::agent_config::AgentConfig;
use erdps_agent::ipc::{sign, RequestMessage, ResponseMessage};
use rand::RngCore;
use serde_json::json;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

fn load_config_and_key(
) -> Result<(String, Vec<u8>), Box<dyn std::error::Error>> {
    // Load config.toml using the same helper as ipc_client
    let config = AgentConfig::load_or_default("config.toml");
    let server_addr = config.service.ipc_bind.clone();
    let key_b64 = config.ipc_key.clone();
    let key = BASE64
        .decode(&key_b64)
        .map_err(|e| format!("Failed to decode IPC key: {}", e))?;
    println!("Loaded IPC key ({} bytes)", key.len());
    Ok((server_addr, key))
}

fn generate_nonce_base64() -> String {
    let mut nonce = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce);
    BASE64.encode(nonce)
}

fn create_signed_request(
    key: &[u8],
    command: &str,
) -> Result<RequestMessage, Box<dyn std::error::Error>> {
    let nonce = generate_nonce_base64();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;
    let payload = json!({});

    let signature = sign(command, timestamp, &nonce, &payload, key)?;

    Ok(RequestMessage {
        nonce,
        timestamp,
        command: command.to_string(),
        payload,
        signature,
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting simple IPC test...");

    // Load configuration and IPC key
    let (server_addr, ipc_key) = load_config_and_key()?;

    // Connect to IPC server
    println!("Connecting to IPC server at {}...", server_addr);
    let mut stream = TcpStream::connect(&server_addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    println!("Connected successfully!");

    // Create and send getStatus request
    let request = create_signed_request(&ipc_key, "getStatus")?;
    println!("Sending getStatus request...");

    // Serialize request and send with length-prefixed framing
    let request_json = serde_json::to_vec(&request)?;
    let length = request_json.len() as u32;
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(&request_json)?;
    stream.flush()?;
    println!("Request sent ({} bytes)", request_json.len());

    // Read the response (length-prefixed framing)
    let mut length_buf = [0u8; 4];
    stream.read_exact(&mut length_buf)?;
    let response_length = u32::from_be_bytes(length_buf) as usize;
    let mut response_buf = vec![0u8; response_length];
    stream.read_exact(&mut response_buf)?;

    let response: ResponseMessage = serde_json::from_slice(&response_buf)?;
    println!("Response status: {}", response.status);
    println!(
        "Response payload: {}",
        serde_json::to_string_pretty(&response.payload)?
    );

    // Verify response signature
    let expected_sig = sign(
        "response",
        response.timestamp,
        &response.nonce,
        &response.payload,
        &ipc_key,
    )?;
    if response.signature == expected_sig {
        println!("✓ Response signature verified successfully!");
    } else {
        println!("✗ Response signature mismatch");
    }

    println!("IPC test completed.");
    Ok(())
}
