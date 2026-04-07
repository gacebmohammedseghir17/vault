use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use erdps_agent::ipc::{canonicalize, sign};
use serde_json::json;
use std::fs;

fn main() -> Result<()> {
    println!("=== Rust Canonicalization Test ===");

    // Load IPC key from file
    let ipc_key_base64 = fs::read_to_string("../ipc.key")?.trim().to_string();
    let key_bytes = BASE64.decode(&ipc_key_base64)?;

    println!("IPC Key: {}", ipc_key_base64);
    println!("Key decoded length: {}", key_bytes.len());
    println!();

    // Test with empty object
    let empty_obj = json!({});
    let canonical_empty = canonicalize(&empty_obj);
    let compact_empty = serde_json::to_string(&canonical_empty)?;

    println!("Rust canonicalization:");
    println!("Empty object canonical: {}", compact_empty);
    println!();

    // Test signature generation with same parameters as Node.js
    let command = "getStatus";
    let timestamp = 1756514000i64;
    let nonce = "test_nonce_123";
    let payload = json!({});

    let signature = sign(command, timestamp, nonce, &payload, &key_bytes)?;

    println!("Rust signature generation:");
    println!("Command: {}", command);
    println!("Timestamp: {}", timestamp);
    println!("Nonce: {}", nonce);
    println!("Canonical payload: {}", compact_empty);
    println!(
        "String-to-sign: {}|{}|{}|{}",
        command, timestamp, nonce, compact_empty
    );
    println!("Generated signature: {}", signature);

    println!();
    println!("Expected Node.js signature: Xf9RRFaGEhs18Y3z/tMb8skZyW8sQx42y4ttS2gwPUc=");
    println!("Actual Rust signature:     {}", signature);
    println!(
        "Signatures match: {}",
        signature == "Xf9RRFaGEhs18Y3z/tMb8skZyW8sQx42y4ttS2gwPUc="
    );

    Ok(())
}
