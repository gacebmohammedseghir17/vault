//! Test signature generation to debug IPC authentication issues

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use erdps_agent::ipc::sign;
use serde_json::json;

fn main() -> Result<()> {
    // Use the same IPC key as the backend test
    let ipc_key_b64 = "dGVzdF9pcGNfa2V5XzEyMzQ1Njc4OTBhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5eg==";
    let ipc_key = BASE64.decode(ipc_key_b64)?;

    println!("IPC key length: {}", ipc_key.len());
    println!("IPC key (hex): {}", hex::encode(&ipc_key));

    // Test with the same fixed values as Node.js test
    let command = "getStatus";
    let timestamp = 1700000000i64;
    let nonce = "test_nonce_123";
    let payload = json!({});

    println!("\n=== Rust Signature Generation Debug ===");
    println!("Command: {}", command);
    println!("Timestamp: {}", timestamp);
    println!("Nonce: {}", nonce);
    println!("Payload: {}", payload);

    let signature = sign(command, timestamp, nonce, &payload, &ipc_key)?;
    println!("Generated signature: {}", signature);
    println!("=========================================\n");

    // Test with different payloads to match Node.js tests
    println!("Testing with different payloads:");

    // Test 1: Empty object
    let sig1 = sign("getStatus", timestamp, nonce, &json!({}), &ipc_key)?;
    println!("Empty object signature: {}", sig1);

    // Test 2: Simple object
    let sig2 = sign(
        "scan_file",
        timestamp,
        nonce,
        &json!({"path": "/test/file.txt"}),
        &ipc_key,
    )?;
    println!("Simple object signature: {}", sig2);

    // Test 3: Complex object
    let sig3 = sign(
        "quarantine_file",
        timestamp,
        nonce,
        &json!({
            "file_path": "/test/malware.exe",
            "reason": "YARA detection",
            "rule_id": "test_rule"
        }),
        &ipc_key,
    )?;
    println!("Complex object signature: {}", sig3);

    Ok(())
}
