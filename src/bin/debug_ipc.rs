//! Debug IPC Signature Tool
//!
//! This tool helps debug IPC signature generation and verification issues.

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use erdps_agent::config::agent_config::AgentConfig;
use erdps_agent::ipc::{sign, RequestMessage};
use rand::Rng;
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

/// Generate a random nonce for request uniqueness
fn generate_nonce() -> String {
    let mut rng = rand::thread_rng();
    (0..16)
        .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
        .collect()
}

#[tokio::main]
async fn main() -> Result<()> {
    // Load configuration to get IPC key
    let config = AgentConfig::load_or_default("config.toml");
    
    println!("=== IPC Signature Debug Tool ===");
    println!("IPC Key (base64): {}", config.ipc_key);
    
    // Decode the IPC key
    let ipc_key = BASE64
        .decode(&config.ipc_key)
        .context("Failed to decode IPC key")?;
    
    println!("IPC Key length: {} bytes", ipc_key.len());
    
    // Create a test request
    let nonce = generate_nonce();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let command = "getStatus";
    let payload = json!({});
    
    println!("\n=== Test Request ===");
    println!("Command: {}", command);
    println!("Timestamp: {}", timestamp);
    println!("Nonce: {}", nonce);
    println!("Payload: {}", serde_json::to_string_pretty(&payload)?);
    
    // Generate signature
    let signature = sign(command, timestamp, &nonce, &payload, &ipc_key)
        .context("Failed to sign request")?;
    
    println!("Generated signature: {}", signature);
    
    // Create full request message
    let request = RequestMessage {
        nonce: nonce.clone(),
        timestamp,
        command: command.to_string(),
        payload: payload.clone(),
        signature: signature.clone(),
    };
    
    println!("\n=== Full Request JSON ===");
    println!("{}", serde_json::to_string_pretty(&request)?);
    
    // Verify signature manually
    let expected_signature = sign(command, timestamp, &nonce, &payload, &ipc_key)
        .context("Failed to generate expected signature")?;
    
    println!("\n=== Signature Verification ===");
    println!("Original signature:  {}", signature);
    println!("Expected signature:  {}", expected_signature);
    println!("Signatures match: {}", signature == expected_signature);
    
    Ok(())
}