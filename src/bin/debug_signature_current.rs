use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use hmac::{Hmac, Mac};
use serde_json::{Map, Value};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::fs;

type HmacSha256 = Hmac<Sha256>;

/// Convert a JSON Value to canonical form with sorted keys
fn canonicalize(value: &Value) -> Value {
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
fn sign(
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

    println!("📝 Rust String-to-sign: {}", string_to_sign);
    println!("📝 Rust String-to-sign length: {}", string_to_sign.len());
    println!(
        "📝 Rust String-to-sign bytes: {}",
        hex::encode(string_to_sign.as_bytes())
    );

    // Generate HMAC-SHA256 signature
    let mut mac = HmacSha256::new_from_slice(key)?;
    mac.update(string_to_sign.as_bytes());
    let signature_bytes = mac.finalize().into_bytes();

    // Encode signature as base64
    let signature = BASE64.encode(signature_bytes);
    println!("🔐 Rust Generated signature: {}", signature);
    Ok(signature)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🦀 Rust Signature Debug Tool");

    // Load the IPC key from the same file
    let ipc_key_path = "../ipc.key";
    let ipc_key = fs::read_to_string(ipc_key_path)?.trim().to_string();
    println!("🔑 IPC Key: {}", ipc_key);
    println!("🔑 IPC Key length: {}", ipc_key.len());

    // Decode the base64 key
    let key_buffer = BASE64.decode(&ipc_key)?;
    println!("🔑 Key buffer length: {}", key_buffer.len());
    println!("🔑 Key buffer (hex): {}", hex::encode(&key_buffer));

    // Test with the exact same values from the logs
    let test_cases = vec![
        (
            "Current API Log Case",
            "getStatus",
            1756574189i64,
            "b7bd48853f6dda0c48cfae71cb3ec3dd",
            serde_json::json!({}),
            "dKRXKDmd08EeDPppogv489G8hOrDZPDwVPpMsf7bl3E=", // Node.js generated (corrected)
            "2tPEKJhIoeBRSy6hKx85mPf7/ZXrUaUwTcPniObaoRM=", // Agent expected
        ),
        (
            "Another API Log Case",
            "getAlerts",
            1756574191i64,
            "c8e111d821618fb7fc7fcfab94b8a3c6",
            serde_json::json!({}),
            "k/tXEAa765HSjhVm86MF6sLlRdPUl+VVRhbFRwba5TU=", // Node.js generated (corrected)
            "unknown",                                      // Agent expected
        ),
    ];

    for (name, command, timestamp, nonce, payload, nodejs_sig, agent_expected) in test_cases {
        println!("\n=== {} ===", name);
        println!("Command: {}", command);
        println!("Timestamp: {}", timestamp);
        println!("Nonce: {}", nonce);
        println!("Payload: {}", serde_json::to_string(&payload)?);

        let rust_signature = sign(command, timestamp, nonce, &payload, &key_buffer)?;

        println!("🔐 Node.js generated: {}", nodejs_sig);
        println!("🔐 Agent expected: {}", agent_expected);
        println!("🔐 Rust generated: {}", rust_signature);

        println!("✅ Rust matches Node.js: {}", rust_signature == nodejs_sig);
        println!(
            "✅ Rust matches Agent: {}",
            rust_signature == agent_expected
        );
        println!("✅ Node.js matches Agent: {}", nodejs_sig == agent_expected);
    }

    // Test with different key loading methods
    println!("\n=== Key Loading Test ===");

    // Try loading from config.toml
    let config_path = "config.toml";
    if let Ok(config_content) = fs::read_to_string(config_path) {
        println!("📄 Config file content (first 200 chars):");
        println!("{}", &config_content[..config_content.len().min(200)]);

        // Extract ipc_key from config
        for line in config_content.lines() {
            if line.trim().starts_with("ipc_key") {
                println!("🔑 Config ipc_key line: {}", line.trim());
                if let Some(key_part) = line.split('=').nth(1) {
                    let config_key = key_part.trim().trim_matches('"');
                    println!("🔑 Config key: {}", config_key);
                    println!("🔑 Keys match: {}", config_key == ipc_key);
                }
            }
        }
    }

    Ok(())
}
