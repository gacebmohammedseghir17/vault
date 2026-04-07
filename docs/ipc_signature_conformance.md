# IPC Signature Conformance

This document standardizes the IPC signing, canonicalization, and framing across clients.

## Protocol Basics
- Algorithm: `HMAC-SHA256`
- Key: Base64 string from `config.toml` → `ipc_key` (32 bytes recommended)
- Nonce: Prefer Base64-encoded 16 random bytes; server accepts any string
- Timestamp: Unix seconds (`i64`)
- Canonical JSON: Sort object keys recursively prior to signing
- String-to-sign: `"{command}|{timestamp}|{nonce}|{canonical_payload}"`
- Framing: TCP with 4-byte big-endian length prefix followed by UTF-8 JSON

## Canonicalization
- Objects: keys sorted lexicographically; values canonicalized recursively
- Arrays: elements canonicalized in order
- Primitives: unchanged

## Test Vector (Observed on running agent)
- Agent address: `127.0.0.1:8888`
- Key (base64): `od0p9IX+JvQMUsIVa+MNlSD6A//IA8O8H8kEDreaB48=`
- Command: `getStatus`
- Timestamp: `1762466140`
- Nonce (hex string): `afbcd7ba6e091d9fe5748ee9b1fcc6a8`
- Payload: `{}`
- Expected signature (base64): `vy9QnxCS3bHauld/orHp6v3RsBwCJgEcDLAv3ZCU9gE=`

Note: While the nonce above is a hex string, the server accepts it as-is. For consistency, prefer a Base64-encoded 16-byte nonce, e.g., `AAAAAAAAAAAAAAAAAAAAAA==` for zero bytes.

## Reference Implementations
- Rust: `erdps_agent::ipc::{canonicalize, sign}` and length-prefixed framing helpers
- Examples: `src/bin/ipc_client.rs`, `src/bin/simple_ipc_test.rs`, `src/bin/test_alert_delivery.rs`

## Validation
- Unit test in `tests/ipc_signature_vectors.rs` asserts the request signature matches the expected value above.