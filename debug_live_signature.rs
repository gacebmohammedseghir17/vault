use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use hmac::{Hmac, Mac};
use serde_json::{Map, Value};
use sha2::Sha256;
use std::collections::BTreeMap;

type HmacSha256 = Hmac<Sha256>;

/// Convert a JSON Value to canonical form with sorted keys
pub fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            // Use BTreeMap to sort keys, then create a new Map with sorted insertion
            let btree_map: BTreeMap<String, Value> = map
                .iter()
                .map(|(k, v)| (k.clone(), canonicalize(v)))
                .collect();

            // Create a new Map and insert in sorted order to preserve ordering
            let mut sorted_map = Map::new();
            for (key, value) in btree_map {
                sorted_map.insert(key, value);
            }
            Value::Object(sorted_map)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(canonicalize).collect()),
        _ => value.clone(),
    }
}

/// Generate HMAC-SHA256 signature for a message
pub fn sign(
    command: &str,
    timestamp: i64,
    nonce: &str,
    payload: &Value,
    key: &[u8],
) -> Result<String, Box<dyn std::error::Error>> {
    // Canonicalize the payload for deterministic signing
    let canonical_payload = canonicalize(payload);
    let compact_payload = serde_json::to_string(&canonical_payload)?;

    // Create string-to-sign: command|timestamp|nonce|compact_payload
    let string_to_sign = format!("{command}|{timestamp}|{nonce}|{compact_payload}");

    println!("Rust signing:");
    println!("  Command: {}", command);
    println!("  Timestamp: {}", timestamp);
    println!("  Nonce: {}", nonce);
    println!("  Canonical payload: {}", compact_payload);
    println!("  String-to-sign: {}", string_to_sign);
    println!(
        "  String-to-sign (hex): {}",
        hex::encode(string_to_sign.as_bytes())
    );

    // Generate HMAC-SHA256 signature
    let mut mac = HmacSha256::new_from_slice(key)?;
    mac.update(string_to_sign.as_bytes());
    let signature_bytes = mac.finalize().into_bytes();

    // Encode signature as base64
    let signature = BASE64.encode(signature_bytes);
    println!("  Generated signature: {}", signature);
    Ok(signature)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Rust Live Signature Debug Analysis ===\n");

    // Load the IPC key
    let ipc_key = "XoSXdy9+65cFxMY7LTnJyl2mjLOpnQJSw12UO50ZChk=";
    let key_buffer = BASE64.decode(ipc_key)?;

    println!("IPC Key: {}", ipc_key);
    println!("Key Buffer (hex): {}", hex::encode(&key_buffer));
    println!("Key length: {} bytes", key_buffer.len());
    println!();

    // Test cases from live logs
    let test_cases = vec![
        (
            "getStatus",
            1756553540i64,
            "2438d680a0095a0f7131b03fa13f978a",
            Value::Object(Map::new()),
            "sW+WF1FnrxX5wOnoN4gTVY9r77PvDGtQ1F54HRxtdpg=", // Node.js
            "r7JxX1eW49R9BdhwnlyhwCcBcY9/LKPm5+3AMThLwWo=", // Expected by Rust
        ),
        (
            "getMetrics",
            1756553541i64,
            "b68e7e3dae30dda21f78a460370f2e42",
            Value::Object(Map::new()),
            "WvrMuSSTRlGVnZROrCdE04hlRH5cSS+oVKCWpRX19Rk=", // Node.js
            "k/vgsCfaVqg6zeq0fjeRV1i/7YpuP/QpXrJHQHRQhUw=", // Expected by Rust
        ),
        (
            "getAlerts",
            1756553543i64,
            "f0ac1e44c8a4e0fa0246f45c3ad6c440",
            Value::Object(Map::new()),
            "iFOuqr8Mq5go+eHE8AFeC6G3fucPDL3SERcrI7Z8Lw0=", // Node.js
            "O/GJIjNB3s5hmeaNdcU/t7AjmSw3rvodq5ySwP4P8gQ=", // Expected by Rust
        ),
    ];

    for (command, timestamp, nonce, payload, expected_nodejs, expected_rust) in test_cases {
        println!("Command: {}", command);
        println!("Timestamp: {}", timestamp);
        println!("Nonce: {}", nonce);
        println!("Payload: {}", serde_json::to_string(&payload)?);

        let signature = sign(command, timestamp, nonce, &payload, &key_buffer)?;

        println!("Expected Node.js: {}", expected_nodejs);
        println!("Expected Rust:    {}", expected_rust);
        println!("Matches Node.js: {}", signature == expected_nodejs);
        println!("Matches Rust:    {}", signature == expected_rust);
        println!("---");
    }

    // Test with simple HMAC
    println!("\n=== Simple HMAC Test ===");
    let test_string = "test";
    let mut mac = HmacSha256::new_from_slice(&key_buffer)?;
    mac.update(test_string.as_bytes());
    let test_signature = BASE64.encode(mac.finalize().into_bytes());
    println!("HMAC of '{}': {}", test_string, test_signature);

    Ok(())
}
