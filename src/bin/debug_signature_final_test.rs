//! Final signature debugging test to match Node.js exactly

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use erdps_agent::ipc::{canonicalize, sign};
use serde_json::json;
use std::fs;

fn main() -> Result<()> {
    println!("=== Rust Final Signature Test ===");

    // Load the exact same IPC key file as Node.js
    let ipc_key_base64 = fs::read_to_string("../ipc.key")?.trim().to_string();
    println!("🔑 IPC Key loaded: {}", ipc_key_base64);
    println!("🔑 IPC Key length: {}", ipc_key_base64.len());

    let key_bytes = BASE64.decode(&ipc_key_base64)?;
    println!("🔑 Key bytes length: {}", key_bytes.len());
    println!("🔑 Key bytes (hex): {}", hex::encode(&key_bytes));

    // Test values - these should match the Node.js output exactly
    let command = "getStatus";
    let timestamp = 1756553379; // Exact timestamp from Node.js test
    let nonce = "b3f00252b3b930e60b62f3d447f28221"; // Exact nonce from Node.js test
    let payload = json!({});

    println!("\nCommand: {}", command);
    println!("Timestamp: {}", timestamp);
    println!("Nonce: {}", nonce);
    println!("Payload: {}", payload);

    // Test canonicalization
    println!("\n=== Testing Canonicalization ===");
    let canonical_payload = canonicalize(&payload);
    let compact_payload = serde_json::to_string(&canonical_payload)?;
    println!("📝 Canonical payload: {}", canonical_payload);
    println!("📝 Compact payload: {}", compact_payload);

    // Create sign string
    let sign_string = format!("{}|{}|{}|{}", command, timestamp, nonce, compact_payload);
    println!("📝 Sign string: {}", sign_string);
    println!("📝 Sign string length: {}", sign_string.len());

    // Generate signature
    let signature = sign(command, timestamp, nonce, &payload, &key_bytes)?;
    println!("\n🔐 Generated Signature: {}", signature);

    // Test with different payload variations
    println!("\n=== Testing Empty Payload Variations ===");
    let empty_payloads = [json!({}), json!(null)];

    for (i, test_payload) in empty_payloads.iter().enumerate() {
        let test_sig = sign(command, timestamp, nonce, test_payload, &key_bytes)?;
        println!("Empty payload {} ({}): {}", i, test_payload, test_sig);
    }

    // Test canonicalization specifically
    println!("\n=== Testing Canonicalization ===");
    let test_objects = vec![
        json!({}),
        json!({ "b": 2, "a": 1 }),
        json!({ "nested": { "z": 3, "a": 1 } }),
        json!(null),
    ];

    for obj in test_objects {
        let canonical = canonicalize(&obj);
        let json_str = serde_json::to_string(&canonical)?;
        println!("Original: {} -> Canonical: {}", obj, json_str);
    }

    println!("\n=== Test Complete ===");
    println!("Compare this signature with Node.js output:");
    println!("Command: {}", command);
    println!("Timestamp: {}", timestamp);
    println!("Nonce: {}", nonce);
    println!("Rust Signature: {}", signature);

    Ok(())
}
