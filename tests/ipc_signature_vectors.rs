use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use erdps_agent::ipc::sign;
use serde_json::json;

#[test]
fn request_signature_matches_test_vector() {
    // Test vector from docs/ipc_signature_conformance.md
    let key_b64 = "od0p9IX+JvQMUsIVa+MNlSD6A//IA8O8H8kEDreaB48=";
    let key = BASE64.decode(key_b64).expect("decode key");

    let command = "getStatus";
    let timestamp = 1762466140i64;
    let nonce = "afbcd7ba6e091d9fe5748ee9b1fcc6a8"; // server accepts arbitrary string
    let payload = json!({});

    let sig = sign(command, timestamp, nonce, &payload, &key).expect("sign");
    assert_eq!(sig, "vy9QnxCS3bHauld/orHp6v3RsBwCJgEcDLAv3ZCU9gE=");
}