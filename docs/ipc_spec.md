# ERDPS Agent IPC Specification

This document describes the secure JSON-based Inter-Process Communication (IPC) protocol used by the ERDPS Agent for communication with external clients such as dashboards and management tools.

## Overview

The IPC protocol provides secure, authenticated communication using:
- **HMAC-SHA256** for message integrity and authentication
- **Replay protection** using nonces and timestamps
- **Deterministic JSON canonicalization** for consistent signing
- **Length-prefixed TCP framing** for reliable message delivery

## Security Features

### Authentication
- All messages are signed using HMAC-SHA256
- Shared secret key (`ipc_key`) loaded from encrypted agent configuration
- Base64-encoded signatures for transport

### Replay Protection
- Each request includes a unique 16-byte base64-encoded nonce
- Timestamps must be within ±15 seconds of server time (configurable)
- Server maintains a nonce cache to reject duplicate requests
- Nonces are automatically cleaned up after expiration

### Message Integrity
- Deterministic JSON canonicalization ensures consistent signing
- Object keys are sorted recursively using BTreeMap
- Signature covers command, timestamp, nonce, and payload

## Transport Protocol

### TCP Framing
Messages are sent over TCP using length-prefixed framing:

```
+------------------+------------------+
| Length (4 bytes) | JSON Message     |
| Big-Endian u32   | (Length bytes)   |
+------------------+------------------+
```

### Connection Handling
- Server listens on `127.0.0.1:7777` by default
- Each client connection is handled in a separate async task
- Connections are closed immediately on verification failures
- Server logs all authentication and verification events

## Message Format

### Request Message
```json
{
  "nonce": "base64-encoded-16-bytes",
  "timestamp": 1234567890,
  "command": "getStatus",
  "payload": {
    // Command-specific data
  },
  "signature": "base64-encoded-hmac-sha256"
}
```

### Response Message
```json
{
  "status": "success",
  "nonce": "echoed-request-nonce",
  "timestamp": 1234567890,
  "payload": {
    // Response data
  },
  "signature": "base64-encoded-hmac-sha256"
}
```

## Signature Generation

### String-to-Sign Format
The signature is computed over a deterministic string constructed as:

```
string_to_sign = "{command}|{timestamp}|{nonce}|{compact_payload}"
```

Where:
- `command`: The command name (e.g., "getStatus")
- `timestamp`: Unix timestamp as i64
- `nonce`: Base64-encoded nonce
- `compact_payload`: Canonicalized JSON string of the payload

### Canonicalization Rules

1. **Object Key Sorting**: All JSON object keys are sorted lexicographically
2. **Recursive Processing**: Sorting is applied recursively to nested objects
3. **Array Preservation**: Array order is preserved (not sorted)
4. **Compact Format**: No extra whitespace in the canonical JSON string

#### Example Canonicalization

**Original JSON:**
```json
{
  "zebra": "value",
  "alpha": {
    "charlie": "c",
    "bravo": "b"
  }
}
```

**Canonicalized JSON:**
```json
{"alpha":{"bravo":"b","charlie":"c"},"zebra":"value"}
```

### HMAC Computation

```rust
let signature = HMAC-SHA256(key=base64_decode(ipc_key), data=string_to_sign)
let signature_b64 = base64_encode(signature)
```

## Supported Commands

### getStatus

Retrieves the current status of the ERDPS Agent.

**Request Payload:**
```json
{}
```

**Response Payload:**
```json
{
  "agent_version": "1.0.0",
  "status": "active",
  "threats_detected": 0,
  "quarantined_files": 0,
  "last_scan": "2024-01-15T10:30:00Z",
  "rules_enabled": true,
  "quarantine_path": "/var/quarantine"
}
```

## Error Handling

### Verification Failures
When message verification fails, the server:
1. Logs the failure reason with client IP and timestamp
2. Immediately closes the TCP connection
3. Does not send any response to prevent information leakage

### Common Failure Reasons
- Invalid signature
- Timestamp outside allowed skew window
- Nonce replay (duplicate nonce)
- Malformed JSON
- Missing required fields

### Client Error Handling
Clients should:
- Handle connection closures gracefully
- Implement exponential backoff for reconnection
- Log verification failures for debugging
- Ensure system clocks are synchronized

## Security Considerations

### Key Management
- The `ipc_key` is stored encrypted in the agent configuration
- Keys should be rotated periodically
- Use cryptographically secure random generation for keys

### Network Security
- IPC server binds to localhost only by default
- Consider using TLS for remote connections
- Implement IP-based access controls if needed

### Timing Attacks
- Signature verification uses constant-time comparison
- All verification failures result in connection closure
- No timing information is leaked to attackers

### Replay Protection
- Nonce cache prevents replay attacks within the time window
- Timestamp validation prevents long-term replay attacks
- Cache cleanup prevents memory exhaustion

## Implementation Notes

### Performance
- Signature verification is computationally expensive
- Consider rate limiting to prevent DoS attacks
- Nonce cache uses efficient HashMap with TTL cleanup

### Compatibility
- JSON canonicalization ensures cross-platform compatibility
- Base64 encoding handles binary data transport
- Big-endian length prefix is network byte order standard

### Testing
- Unit tests verify signature generation and verification
- Integration tests validate full client-server communication
- Test client demonstrates proper implementation patterns

## Example Client Implementation

See `bin/ipc_client.rs` for a complete example of:
- Configuration loading
- Message signing
- TCP communication
- Response verification

## Troubleshooting

### Common Issues

1. **Clock Skew**: Ensure client and server clocks are synchronized
2. **Key Mismatch**: Verify both sides use the same `ipc_key`
3. **JSON Formatting**: Use the canonical JSON format for signing
4. **Network Issues**: Check firewall and binding configuration

### Debug Logging

Enable debug logging to see:
- Signature generation details
- Verification step failures
- Nonce cache operations
- Connection handling events

```bash
RUST_LOG=debug ./erdps_agent
```