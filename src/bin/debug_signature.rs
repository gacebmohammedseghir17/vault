use base64::{engine::general_purpose, Engine as _};
use hmac::{Hmac, Mac};
use serde_json::{Map, Value};
use sha2::Sha256;
use std::collections::BTreeMap;

type HmacSha256 = Hmac<Sha256>;

// Same canonicalization logic as in ipc.rs
fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut sorted_map = BTreeMap::new();
            for (k, v) in map {
                sorted_map.insert(k.clone(), canonicalize(v));
            }
            Value::Object(Map::from_iter(sorted_map))
        }
        Value::Array(arr) => Value::Array(arr.iter().map(canonicalize).collect()),
        _ => value.clone(),
    }
}

// Same signature generation logic as in ipc.rs
fn sign(
    key: &[u8],
    command: &str,
    timestamp: u64,
    nonce: &str,
    payload: &Value,
) -> Result<String, Box<dyn std::error::Error>> {
    let canonical_payload = canonicalize(payload);
    let compact_payload = serde_json::to_string(&canonical_payload)?;
    let string_to_sign = format!("{}|{}|{}|{}", command, timestamp, nonce, compact_payload);

    println!("Rust signing:");
    println!("  Command: {}", command);
    println!("  Timestamp: {}", timestamp);
    println!("  Nonce: {}", nonce);
    println!("  Canonical payload: {}", compact_payload);
    println!("  String-to-sign: {}", string_to_sign);

    let mut mac = HmacSha256::new_from_slice(key)?;
    mac.update(string_to_sign.as_bytes());
    let result = mac.finalize();
    let signature = general_purpose::STANDARD.encode(result.into_bytes());

    println!("  Generated signature: {}", signature);
    Ok(signature)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Same values as Node.js test
    let ipc_key = "XoSXdy9+65cFxMY7LTnJyl2mjLOpnQJSw12UO50ZChk=";
    let key_bytes = general_purpose::STANDARD.decode(ipc_key)?;

    let command = "getStatus";
    let timestamp = 1756552840u64;
    let nonce = "RsZlTJMH3Iws++05pndnjw==";
    let payload = Value::Object(Map::new()); // Empty object {}

    let signature = sign(&key_bytes, command, timestamp, nonce, &payload)?;

    println!("\n=== Test Results ===");
    println!("Command: {}", command);
    println!("Timestamp: {}", timestamp);
    println!("Nonce: {}", nonce);
    println!("Payload: {}", serde_json::to_string(&payload)?);
    println!("Signature: {}", signature);

    Ok(())
}
