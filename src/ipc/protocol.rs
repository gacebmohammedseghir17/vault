use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::Sha256;
use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

/// Maximum allowed timestamp skew in seconds (±15 seconds)
const MAX_TIMESTAMP_SKEW_SECS: i64 = 15;

/// Nonce cache TTL in seconds (5 minutes)
const NONCE_CACHE_TTL_SECS: u64 = 300;

/// Request message structure for IPC communication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestMessage {
    /// Base64-encoded random nonce (16 bytes)
    pub nonce: String,
    /// Unix timestamp in seconds
    pub timestamp: i64,
    /// Command to execute (e.g., "getStatus")
    pub command: String,
    /// Command payload as JSON object
    pub payload: Value,
    /// Base64-encoded HMAC-SHA256 signature
    pub signature: String,
}

/// Response message structure for IPC communication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseMessage {
    /// Echoed nonce from the request
    pub nonce: String,
    /// Unix timestamp when response was generated
    pub timestamp: i64,
    /// Response status ("success" or "error")
    pub status: String,
    /// Response payload as JSON object
    pub payload: Value,
    /// Base64-encoded HMAC-SHA256 signature
    pub signature: String,
}

/// Nonce store for replay attack prevention
#[derive(Debug)]
pub struct NonceStore {
    /// Map of nonce -> insertion timestamp
    nonces: HashMap<String, Instant>,
    /// TTL for nonce entries
    ttl: Duration,
}

impl Default for NonceStore {
    fn default() -> Self {
        Self::new()
    }
}

impl NonceStore {
    /// Create a new nonce store with default TTL
    pub fn new() -> Self {
        Self {
            nonces: HashMap::new(),
            ttl: Duration::from_secs(NONCE_CACHE_TTL_SECS),
        }
    }

    /// Check if a nonce has been used before and mark it as used
    pub fn check_and_insert(&mut self, nonce: &str) -> bool {
        self.cleanup_expired();

        if self.nonces.contains_key(nonce) {
            false // Nonce already used (replay attack)
        } else {
            self.nonces.insert(nonce.to_string(), Instant::now());
            true // Nonce is new and valid
        }
    }

    /// Remove expired nonces from the cache
    fn cleanup_expired(&mut self) {
        let now = Instant::now();
        self.nonces
            .retain(|_, &mut timestamp| now.duration_since(timestamp) < self.ttl);
    }
}

/// Convert a JSON Value to canonical form with sorted keys
/// This ensures deterministic serialization for signature verification
pub fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut btree_map = BTreeMap::new();
            for (k, v) in map {
                btree_map.insert(k.clone(), canonicalize(v));
            }
            Value::Object(Map::from_iter(btree_map))
        }
        Value::Array(arr) => Value::Array(arr.iter().map(canonicalize).collect()),
        _ => value.clone(),
    }
}

pub fn normalized_payload(
    context: &str,
    event_type: &str,
    data: Option<Value>,
    msg: Option<&str>,
    code: Option<&str>,
) -> Value {
    let mut root = Map::new();
    root.insert("context".to_string(), Value::String(context.to_string()));
    root.insert("event_type".to_string(), Value::String(event_type.to_string()));
    if let Some(m) = msg {
        root.insert("msg".to_string(), Value::String(m.to_string()));
    }
    if let Some(c) = code {
        root.insert("code".to_string(), Value::String(c.to_string()));
    }
    if let Some(d) = data {
        root.insert("data".to_string(), d);
    }
    Value::Object(root)
}

/// Generate HMAC-SHA256 signature for a message
pub fn sign(
    command: &str,
    timestamp: i64,
    nonce: &str,
    payload: &Value,
    key: &[u8],
) -> Result<String> {
    // Canonicalize the payload for deterministic signing
    let canonical_payload = canonicalize(payload);
    let compact_payload = serde_json::to_string(&canonical_payload)
        .context("Failed to serialize canonical payload")?;

    // Create string-to-sign: command|timestamp|nonce|compact_payload
    let string_to_sign = format!("{command}|{timestamp}|{nonce}|{compact_payload}");

    // Generate HMAC-SHA256 signature
    let mut mac =
        HmacSha256::new_from_slice(key).map_err(|e| anyhow!("Invalid HMAC key: {}", e))?;
    mac.update(string_to_sign.as_bytes());
    let signature_bytes = mac.finalize().into_bytes();

    // Encode signature as base64
    Ok(BASE64.encode(signature_bytes))
}

/// Verify HMAC-SHA256 signature and message constraints
pub fn verify(
    req: &RequestMessage,
    key: &[u8],
    max_skew_secs: i64,
    nonce_store: &mut NonceStore,
) -> Result<()> {
    // Check timestamp skew
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as i64;

    let time_diff = (now - req.timestamp).abs();
    if time_diff > max_skew_secs {
        return Err(anyhow!(
            "Timestamp skew too large: {}s (max: {}s)",
            time_diff,
            max_skew_secs
        ));
    }

    // Check nonce for replay protection
    if !nonce_store.check_and_insert(&req.nonce) {
        return Err(anyhow!("Nonce replay detected: {}", req.nonce));
    }

    // Verify signature
    let expected_signature = sign(&req.command, req.timestamp, &req.nonce, &req.payload, key)
        .context("Failed to generate expected signature")?;

    if req.signature != expected_signature {
        return Err(anyhow!("Signature verification failed"));
    }

    Ok(())
}
