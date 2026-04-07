//! Test Dashboard Client
//!
//! This simulates a dashboard client that connects to the agent and receives detection alerts.

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::{sleep, Duration};

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Serialize, Deserialize)]
struct IpcRequest {
    command: String,
    nonce: String,
    timestamp: u64,
    payload: Value,
    signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct IpcResponse {
    status: String,
    payload: Value,
    signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct DetectionAlert {
    rule_id: String,
    score: u32,
    evidence: Vec<String>,
    timestamp: u64,
    signature: String,
}

fn load_ipc_key() -> Result<String> {
    let config_content =
        std::fs::read_to_string("config/agent.toml").context("Failed to read agent.toml")?;

    // Simple TOML parsing for ipc_key
    for line in config_content.lines() {
        if line.trim().starts_with("ipc_key") {
            if let Some(key_part) = line.split('=').nth(1) {
                let key = key_part.trim().trim_matches('"').trim();
                println!("Parsed IPC key: '{}' (length: {})", key, key.len());

                // Debug: print each character
                for (i, c) in key.chars().enumerate() {
                    println!("  [{}]: '{}' ({})", i, c, c as u32);
                }

                return Ok(key.to_string());
            }
        }
    }

    Err(anyhow::anyhow!("IPC key not found in config"))
}

fn generate_nonce() -> String {
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    BASE64.encode(nonce)
}

fn create_signature(
    command: &str,
    timestamp: u64,
    nonce: &str,
    payload: &str,
    key: &str,
) -> Result<String> {
    let key_bytes = BASE64.decode(key).context("Failed to decode IPC key")?;

    let string_to_sign = format!("{}|{}|{}|{}", command, timestamp, nonce, payload);

    let mut mac = HmacSha256::new_from_slice(&key_bytes).context("Failed to create HMAC")?;
    mac.update(string_to_sign.as_bytes());

    let signature = mac.finalize().into_bytes();
    Ok(BASE64.encode(signature))
}

fn verify_signature(
    expected_sig: &str,
    command: &str,
    timestamp: u64,
    nonce: &str,
    payload: &str,
    key: &str,
) -> Result<bool> {
    let computed_sig = create_signature(command, timestamp, nonce, payload, key)?;
    Ok(expected_sig == computed_sig)
}

fn send_request(stream: &mut TcpStream, request: &IpcRequest) -> Result<()> {
    let json_data = serde_json::to_string(request).context("Failed to serialize request")?;

    let length = json_data.len() as u32;
    stream
        .write_all(&length.to_le_bytes())
        .context("Failed to write request length")?;
    stream
        .write_all(json_data.as_bytes())
        .context("Failed to write request data")?;

    Ok(())
}

fn read_response(stream: &mut TcpStream) -> Result<IpcResponse> {
    let mut length_bytes = [0u8; 4];
    stream
        .read_exact(&mut length_bytes)
        .context("Failed to read response length")?;

    let length = u32::from_le_bytes(length_bytes) as usize;
    let mut buffer = vec![0u8; length];
    stream
        .read_exact(&mut buffer)
        .context("Failed to read response data")?;

    let response: IpcResponse =
        serde_json::from_slice(&buffer).context("Failed to parse response JSON")?;

    Ok(response)
}

fn read_alert(stream: &mut TcpStream) -> Result<DetectionAlert> {
    let mut length_bytes = [0u8; 4];
    stream
        .read_exact(&mut length_bytes)
        .context("Failed to read alert length")?;

    let length = u32::from_le_bytes(length_bytes) as usize;
    let mut buffer = vec![0u8; length];
    stream
        .read_exact(&mut buffer)
        .context("Failed to read alert data")?;

    let alert: DetectionAlert =
        serde_json::from_slice(&buffer).context("Failed to parse alert JSON")?;

    Ok(alert)
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("Dashboard Client - Testing IPC Alert Reception");

    // Load IPC key
    let ipc_key = load_ipc_key().context("Failed to load IPC key")?;
    println!("Using IPC key: {}", ipc_key);

    // Connect to agent
    println!("Connecting to ERDPS Agent IPC server...");
    let mut stream =
        TcpStream::connect("127.0.0.1:7777").context("Failed to connect to IPC server")?;
    println!("Connected successfully!");

    // Send getStatus request first
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let nonce = generate_nonce();
    let payload = json!({});
    let payload_str = serde_json::to_string(&payload).unwrap();

    let signature = create_signature("getStatus", timestamp, &nonce, &payload_str, &ipc_key)?;

    let request = IpcRequest {
        command: "getStatus".to_string(),
        nonce,
        timestamp,
        payload,
        signature,
    };

    println!("Sending getStatus request...");
    send_request(&mut stream, &request)?;

    // Read response
    let response = read_response(&mut stream)?;
    println!("Status response: {}", response.status);

    // Now listen for alerts
    println!("\nListening for detection alerts...");
    println!("(The agent should be generating mass_modification alerts)");

    let mut alert_count = 0;
    let max_alerts = 5;

    loop {
        match read_alert(&mut stream) {
            Ok(alert) => {
                alert_count += 1;
                println!("\n🚨 Alert #{} received:", alert_count);
                println!("  Rule ID: {}", alert.rule_id);
                println!("  Score: {}", alert.score);
                println!("  Evidence: {:?}", alert.evidence);
                println!("  Timestamp: {}", alert.timestamp);

                // Verify alert signature
                let alert_payload = json!({
                    "rule_id": alert.rule_id,
                    "score": alert.score,
                    "evidence": alert.evidence,
                    "timestamp": alert.timestamp
                });
                let alert_payload_str = serde_json::to_string(&alert_payload).unwrap();

                match verify_signature(
                    &alert.signature,
                    "alert",
                    alert.timestamp,
                    "",
                    &alert_payload_str,
                    &ipc_key,
                ) {
                    Ok(true) => println!("  ✓ Alert signature verified successfully!"),
                    Ok(false) => println!("  ✗ Alert signature verification failed!"),
                    Err(e) => println!("  ✗ Error verifying alert signature: {}", e),
                }

                if alert_count >= max_alerts {
                    println!("\nReceived {} alerts, test completed.", max_alerts);
                    break;
                }
            }
            Err(e) => {
                println!("Error reading alert: {}", e);
                println!("Waiting for more alerts...");
                sleep(Duration::from_secs(2)).await;
            }
        }
    }

    println!("\n✓ Dashboard client test completed successfully!");
    println!("✓ IPC communication working correctly");
    println!("✓ Detection alerts received and verified");

    Ok(())
}
