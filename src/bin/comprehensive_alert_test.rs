//! Comprehensive Alert Delivery Test
//!
//! This test program verifies the complete alert delivery mechanism:
//! 1. Starts a fresh agent instance without YARA features
//! 2. Creates an IPC client that connects to the agent
//! 3. Implements proper message framing protocol
//! 4. Polls for alerts using the getAlerts command
//! 5. Triggers file system activity to generate detection events
//! 6. Confirms alerts are delivered via IPC polling
//! 7. Tests the complete agent-to-dashboard communication workflow

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Serialize, Deserialize)]
struct RequestMessage {
    nonce: String,
    timestamp: i64,
    command: String,
    payload: Value,
    signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ResponseMessage {
    nonce: String,
    timestamp: i64,
    status: String,
    payload: Value,
    signature: String,
}

#[derive(Debug, Deserialize)]
struct AlertData {
    rule_id: String,
    score: u32,
    evidence: String,
    timestamp: u64,
}

struct IPCClient {
    stream: TcpStream,
    ipc_key: Vec<u8>,
}

impl IPCClient {
    fn connect(addr: &str) -> Result<Self> {
        println!("Connecting to IPC server at {}", addr);
        let stream = TcpStream::connect(addr).context("Failed to connect to IPC server")?;

        // Use a test key for demonstration (should match agent's key from config/agent.toml)
        let ipc_key = BASE64
            .decode("dGVzdF9pcGNfa2V5XzEyMzQ1Njc4OTBhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5eg==")
            .context("Failed to decode IPC key")?;

        println!("Successfully connected to IPC server");
        Ok(IPCClient { stream, ipc_key })
    }

    fn generate_nonce(&self) -> String {
        let mut nonce = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut nonce);
        hex::encode(nonce)
    }

    /// Convert a JSON Value to canonical form with sorted keys
    #[allow(clippy::only_used_in_recursion)]
    fn canonicalize(&self, value: &Value) -> Value {
        match value {
            Value::Object(map) => {
                let mut btree_map = BTreeMap::new();
                for (k, v) in map {
                    btree_map.insert(k.clone(), self.canonicalize(v));
                }
                Value::Object(Map::from_iter(btree_map))
            }
            Value::Array(arr) => Value::Array(arr.iter().map(|v| self.canonicalize(v)).collect()),
            _ => value.clone(),
        }
    }

    /// Generate HMAC-SHA256 signature for a message
    fn sign(&self, command: &str, timestamp: i64, nonce: &str, payload: &Value) -> Result<String> {
        // Canonicalize the payload for deterministic signing
        let canonical_payload = self.canonicalize(payload);
        let compact_payload = serde_json::to_string(&canonical_payload)
            .context("Failed to serialize canonical payload")?;

        // Create string-to-sign: command|timestamp|nonce|compact_payload
        let string_to_sign = format!("{command}|{timestamp}|{nonce}|{compact_payload}");

        println!("Client signing:");
        println!("  Command: {}", command);
        println!("  Timestamp: {}", timestamp);
        println!("  Nonce: {}", nonce);
        println!("  Canonical payload: {}", compact_payload);
        println!("  String-to-sign: {}", string_to_sign);

        // Generate HMAC-SHA256 signature
        let mut mac = HmacSha256::new_from_slice(&self.ipc_key)
            .map_err(|e| anyhow::anyhow!("Invalid HMAC key: {}", e))?;
        mac.update(string_to_sign.as_bytes());
        let signature_bytes = mac.finalize().into_bytes();

        // Encode signature as base64
        let signature = BASE64.encode(signature_bytes);
        println!("  Generated signature: {}", signature);
        Ok(signature)
    }

    fn send_request(&mut self, command: &str, payload: Value) -> Result<ResponseMessage> {
        let nonce = self.generate_nonce();
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;

        let signature = self.sign(command, timestamp, &nonce, &payload)?;

        let request = RequestMessage {
            nonce: nonce.clone(),
            timestamp,
            command: command.to_string(),
            payload,
            signature,
        };

        let request_json =
            serde_json::to_string(&request).context("Failed to serialize request")?;

        println!("Sending request: {}", command);

        // Send length-prefixed message (big-endian to match agent protocol)
        let message_len = request_json.len() as u32;
        self.stream
            .write_all(&message_len.to_be_bytes())
            .context("Failed to write message length")?;
        self.stream
            .write_all(request_json.as_bytes())
            .context("Failed to write message")?;
        self.stream.flush().context("Failed to flush stream")?;

        // Read response (big-endian to match agent protocol)
        let mut len_bytes = [0u8; 4];
        self.stream
            .read_exact(&mut len_bytes)
            .context("Failed to read response length")?;
        let response_len = u32::from_be_bytes(len_bytes) as usize;

        let mut response_bytes = vec![0u8; response_len];
        self.stream
            .read_exact(&mut response_bytes)
            .context("Failed to read response")?;

        let response_json =
            String::from_utf8(response_bytes).context("Invalid UTF-8 in response")?;

        let response: ResponseMessage =
            serde_json::from_str(&response_json).context("Failed to deserialize response")?;

        println!("Received response: status={}", response.status);
        Ok(response)
    }

    fn get_status(&mut self) -> Result<Value> {
        let response = self.send_request("getStatus", Value::Null)?;
        if response.status == "success" {
            Ok(response.payload)
        } else {
            Err(anyhow::anyhow!(
                "Status request failed: {:?}",
                response.payload
            ))
        }
    }

    fn get_alerts(&mut self) -> Result<Vec<AlertData>> {
        let response = self.send_request("getAlerts", Value::Null)?;
        if response.status == "success" {
            let empty_vec = vec![];
            let alerts_array = response
                .payload
                .get("alerts")
                .and_then(|v| v.as_array())
                .unwrap_or(&empty_vec);

            let mut alerts = Vec::new();
            for alert_value in alerts_array {
                if let Ok(alert) = serde_json::from_value::<AlertData>(alert_value.clone()) {
                    alerts.push(alert);
                }
            }
            Ok(alerts)
        } else {
            Err(anyhow::anyhow!(
                "Get alerts request failed: {:?}",
                response.payload
            ))
        }
    }
}

struct AgentProcess {
    child: Child,
}

impl AgentProcess {
    fn start() -> Result<Self> {
        println!("Starting agent process without YARA features...");

        let child = Command::new("cargo")
            .args(["run", "--bin", "erdps-agent", "--no-default-features"])
            .spawn()
            .context("Failed to start agent process")?;

        println!("Agent process started with PID: {}", child.id());

        // Wait for agent to compile and initialize (longer wait for first run)
        println!("Waiting for agent to compile and start up...");
        thread::sleep(Duration::from_secs(15));

        Ok(AgentProcess { child })
    }
}

impl Drop for AgentProcess {
    fn drop(&mut self) {
        println!("Terminating agent process...");
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn trigger_mass_modification_event() -> Result<()> {
    println!("Triggering mass modification event...");

    let test_dir = Path::new("./alert_test_files");
    if test_dir.exists() {
        fs::remove_dir_all(test_dir).context("Failed to clean test directory")?;
    }
    fs::create_dir_all(test_dir).context("Failed to create test directory")?;

    // Create 60 files to exceed the mass modification threshold (50)
    for i in 0..60 {
        let file_path = test_dir.join(format!("test_file_{}.txt", i));
        fs::write(&file_path, format!("Test content {}", i))
            .context("Failed to write test file")?;
    }

    println!("Created 60 test files to trigger mass modification detection");

    // Wait a moment for the agent to detect the changes
    thread::sleep(Duration::from_secs(2));

    // Modify all files to trigger more events
    for i in 0..60 {
        let file_path = test_dir.join(format!("test_file_{}.txt", i));
        fs::write(&file_path, format!("Modified content {}", i))
            .context("Failed to modify test file")?;
    }

    println!("Modified all 60 test files");

    // Wait for detection
    thread::sleep(Duration::from_secs(3));

    Ok(())
}

fn cleanup_test_files() -> Result<()> {
    let test_dir = Path::new("./alert_test_files");
    if test_dir.exists() {
        fs::remove_dir_all(test_dir).context("Failed to clean test directory")?;
        println!("Cleaned up test files");
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("=== Comprehensive Alert Delivery Test ===");
    println!();

    // Clean up any existing test files
    let _ = cleanup_test_files();

    // Step 1: Start agent process
    let _agent = AgentProcess::start()?;

    // Step 2: Connect to IPC server
    let mut client = IPCClient::connect("127.0.0.1:8888")?;

    // Step 3: Verify agent status
    println!("\n=== Testing Agent Status ===");
    let status = client.get_status()?;
    println!("Agent status: {}", serde_json::to_string_pretty(&status)?);

    // Step 4: Check initial alerts (should be empty)
    println!("\n=== Checking Initial Alerts ===");
    let initial_alerts = client.get_alerts()?;
    println!("Initial alerts count: {}", initial_alerts.len());
    for alert in &initial_alerts {
        println!(
            "  Alert: {} (score: {}, evidence: {})",
            alert.rule_id, alert.score, alert.evidence
        );
    }

    // Step 5: Trigger detection events
    println!("\n=== Triggering Detection Events ===");
    trigger_mass_modification_event()?;

    // Step 6: Poll for alerts multiple times
    println!("\n=== Polling for Alerts ===");
    let mut total_alerts_received = 0;
    let max_polls = 10;

    for poll_count in 1..=max_polls {
        println!("\nPoll #{}: Checking for alerts...", poll_count);

        let alerts = client.get_alerts()?;
        if !alerts.is_empty() {
            println!("Received {} alerts:", alerts.len());
            for (i, alert) in alerts.iter().enumerate() {
                println!(
                    "  Alert {}: {} (score: {}, evidence: {}, timestamp: {})",
                    i + 1,
                    alert.rule_id,
                    alert.score,
                    alert.evidence,
                    alert.timestamp
                );
            }
            total_alerts_received += alerts.len();
        } else {
            println!("No alerts received in this poll");
        }

        // Wait before next poll
        if poll_count < max_polls {
            thread::sleep(Duration::from_secs(2));
        }
    }

    // Step 7: Final summary
    println!("\n=== Test Summary ===");
    println!("Total alerts received: {}", total_alerts_received);

    if total_alerts_received > 0 {
        println!("✅ SUCCESS: Alert delivery mechanism is working!");
        println!("   - Agent successfully detected file system events");
        println!("   - Alerts were properly queued and delivered via IPC");
        println!("   - Client successfully received and parsed alerts");
    } else {
        println!("❌ FAILURE: No alerts were received");
        println!("   - Check if agent is generating detection events");
        println!("   - Verify IPC communication is working");
        println!("   - Ensure alert queue mechanism is functioning");
    }

    // Cleanup
    cleanup_test_files()?;

    println!("\n=== Test Complete ===");
    Ok(())
}
