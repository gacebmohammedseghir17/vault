use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use erdps_agent::ipc::sign;
use serde_json::json;

fn main() -> Result<()> {
    println!("=== Rust Signature Generation Test ===");

    // Test values from the logs (same as Node.js)
    let command = "getStatus";
    let timestamp = 1756553120i64;
    let nonce = "82f12ca6058e2b0a88a8c6707b598a17";
    let payload = json!({});

    // IPC key from config (base64 encoded)
    let ipc_key_base64 = "dGVzdC1pcGMta2V5LTEyMzQ1Njc4OTAtYWJjZGVmZ2hpams=";

    println!("Rust Debug:");
    println!("  Command: {}", command);
    println!("  Timestamp: {}", timestamp);
    println!("  Nonce: {}", nonce);
    println!("  Payload: {}", payload);
    println!("  Key (base64): {}", ipc_key_base64);

    // Decode the base64 key
    let ipc_key = BASE64
        .decode(ipc_key_base64)
        .context("Failed to decode IPC key")?;

    println!("  Key (hex): {}", hex::encode(&ipc_key));

    // Generate signature using the same function as the agent
    let signature = sign(command, timestamp, nonce, &payload, &ipc_key)
        .context("Failed to generate signature")?;

    println!("\nFinal Rust signature: {}", signature);

    Ok(())
}
