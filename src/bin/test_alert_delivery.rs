use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use erdps_agent::config::agent_config::AgentConfig;
use erdps_agent::ipc::{sign, RequestMessage, ResponseMessage};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

// Use shared RequestMessage/ResponseMessage from ipc module

#[derive(Debug, Serialize, Deserialize)]
struct DetectionAlert {
    rule_id: String,
    score: u32,
    evidence: Vec<String>,
    timestamp: String,
    signature: String,
}

fn load_config_and_key() -> Result<(String, Vec<u8>), Box<dyn std::error::Error>> {
    let config = AgentConfig::load_or_default("config.toml");
    let server_addr = config.service.ipc_bind.clone();
    let key = BASE64
        .decode(&config.ipc_key)
        .map_err(|e| format!("Failed to decode IPC key: {}", e))?;
    Ok((server_addr, key))
}

fn generate_nonce() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..16).map(|_| rng.gen::<u8>()).collect();
    hex::encode(bytes)
}

fn sign_message(
    command: &str,
    timestamp: i64,
    nonce: &str,
    payload: &serde_json::Value,
    key: &[u8],
) -> Result<String, Box<dyn std::error::Error>> {
    Ok(sign(command, timestamp, nonce, payload, key)?)
}

// Canonicalization is handled by the shared ipc::sign

fn send_request(
    stream: &mut TcpStream,
    request: &RequestMessage,
) -> Result<(), Box<dyn std::error::Error>> {
    let json_data = serde_json::to_vec(request)?;
    let length = json_data.len() as u32;
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(&json_data)?;
    stream.flush()?;
    println!("Sent request: {}", String::from_utf8_lossy(&json_data));
    Ok(())
}

fn read_message(stream: &mut TcpStream) -> Result<String, Box<dyn std::error::Error>> {
    // Read length prefix (4 bytes)
    let mut length_bytes = [0u8; 4];
    stream.read_exact(&mut length_bytes)?;
    let length = u32::from_be_bytes(length_bytes) as usize;

    // Read JSON data
    let mut buffer = vec![0u8; length];
    stream.read_exact(&mut buffer)?;

    Ok(String::from_utf8(buffer)?)
}

fn test_status_request(
    stream: &mut TcpStream,
    _key: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Testing Status Request ===");

    let nonce = generate_nonce();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let command = "getStatus";
    let payload = serde_json::json!({});

    let signature = sign_message(command, timestamp, &nonce, &payload, _key)?;

    let request = RequestMessage {
        nonce,
        timestamp,
        command: command.to_string(),
        payload,
        signature,
    };

    send_request(stream, &request)?;

    // Read response
    let response_json = read_message(stream)?;
    println!("Received response: {}", response_json);

    let response: ResponseMessage = serde_json::from_str(&response_json)?;

    println!("✓ Status request successful: {}", response.status);
    println!("   Response payload: {}", response.payload);

    Ok(())
}

fn listen_for_alerts(
    stream: &mut TcpStream,
    _key: &[u8],
    duration_secs: u64,
) -> Result<Vec<DetectionAlert>, Box<dyn std::error::Error>> {
    println!(
        "\n=== Listening for Detection Alerts ({} seconds) ===",
        duration_secs
    );

    let start_time = Instant::now();
    let timeout_duration = Duration::from_secs(duration_secs);
    let mut alerts = Vec::new();

    // Set read timeout
    stream.set_read_timeout(Some(Duration::from_secs(1)))?;

    while start_time.elapsed() < timeout_duration {
        match read_message(stream) {
            Ok(message_json) => {
                println!("Received message: {}", message_json);

                // Try to parse as detection alert
                if let Ok(alert) = serde_json::from_str::<DetectionAlert>(&message_json) {
                    println!("📢 Detection Alert Received:");
                    println!("   Rule ID: {}", alert.rule_id);
                    println!("   Score: {}", alert.score);
                    println!("   Evidence: {:?}", alert.evidence);
                    println!("   Timestamp: {}", alert.timestamp);

                    // For now, accept all alerts (signature verification can be added later)
                    println!("   ✓ Alert received and processed");
                    alerts.push(alert);
                } else {
                    // Might be a regular IPC response
                    if let Ok(response) = serde_json::from_str::<ResponseMessage>(&message_json) {
                        println!("📨 IPC Response: status={}", response.status);
                    } else {
                        println!("📄 Unknown message format");
                    }
                }
            }
            Err(e) => {
                // Check if it's a timeout (expected)
                if let Some(io_err) = e.downcast_ref::<std::io::Error>() {
                    if io_err.kind() == std::io::ErrorKind::TimedOut
                        || io_err.kind() == std::io::ErrorKind::WouldBlock
                    {
                        // Continue listening
                        continue;
                    }
                }
                println!("Error reading message: {}", e);
                break;
            }
        }
    }

    // Reset timeout
    stream.set_read_timeout(None)?;

    Ok(alerts)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 Starting Alert Delivery Test Client");

    // Load config and IPC key
    let (server_addr, key) = load_config_and_key()?;
    println!("✓ IPC key loaded successfully");

    // Connect to agent
    println!("🔌 Connecting to agent at {}...", server_addr);
    let mut stream = TcpStream::connect(&server_addr)?;
    println!("✓ Connected to agent");

    // Test status request first
    test_status_request(&mut stream, &key)?;

    // Listen for alerts
    let alerts = listen_for_alerts(&mut stream, &key, 30)?;

    // Summary
    println!("\n=== Test Results ===");
    println!("Total alerts received: {}", alerts.len());

    if !alerts.is_empty() {
        println!("\n📊 Alert Summary:");
        let mut rule_counts: HashMap<String, u32> = HashMap::new();
        for alert in &alerts {
            *rule_counts.entry(alert.rule_id.clone()).or_insert(0) += 1;
        }

        for (rule_id, count) in rule_counts {
            println!("   {}: {} alerts", rule_id, count);
        }

        println!("\n✅ Alert delivery test PASSED - Alerts are being delivered successfully!");
    } else {
        println!("\n⚠️  No alerts received during test period");
        println!("   This could mean:");
        println!("   - No detection events occurred");
        println!("   - Alert delivery mechanism has issues");
        println!("   - Agent is not generating alerts");
    }

    Ok(())
}
