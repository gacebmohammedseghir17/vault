use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

fn main() {
    // Load the same key both systems are using
    let base64_key = "dGVzdF9pcGNfa2V5XzEyMzQ1Njc4OTBhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5eg==";
    let key_bytes = BASE64
        .decode(base64_key)
        .expect("Failed to decode base64 key");

    println!("Base64 key: {}", base64_key);
    println!("Key buffer length: {}", key_bytes.len());
    println!("Key buffer hex: {}", hex::encode(&key_bytes));
    println!(
        "Key buffer as string: {}",
        String::from_utf8_lossy(&key_bytes)
    );

    // Test the exact same signature generation as the logs show
    let command = "getStatus";
    let timestamp = 1756471314i64;
    let nonce = "bdeg78RB87SmAe43M0SfbQ==";
    let payload = "{}";

    let string_to_sign = format!("{command}|{timestamp}|{nonce}|{payload}");
    println!("\nString-to-sign: {}", string_to_sign);

    // Generate signature using Rust crypto
    let mut mac = HmacSha256::new_from_slice(&key_bytes).expect("Invalid HMAC key");
    mac.update(string_to_sign.as_bytes());
    let signature_bytes = mac.finalize().into_bytes();
    let signature = BASE64.encode(signature_bytes);

    println!("Generated signature: {}", signature);
    println!("Expected from logs: NQHoOiUZqUFm3s16kYUnZlOpu9zIbM+T0LiZqaeF38c=");
    println!(
        "Match: {}",
        signature == "NQHoOiUZqUFm3s16kYUnZlOpu9zIbM+T0LiZqaeF38c="
    );
}
