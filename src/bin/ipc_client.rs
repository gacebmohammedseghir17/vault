//! IPC Client Test Utility
//!
//! This is a test client for secure communication with the ERDPS Agent IPC server.
//! It demonstrates the complete IPC protocol including:
//! - Secure message signing with HMAC-SHA256
//! - Nonce-based replay protection
//! - Timestamp validation
//! - JSON payload handling

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use erdps_agent::config::agent_config::AgentConfig;
use erdps_agent::ipc::{sign, RequestMessage, ResponseMessage};
use rand::Rng;
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Generate a random nonce for request uniqueness
fn generate_nonce() -> String {
    let mut rng = rand::thread_rng();
    (0..16)
        .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
        .collect()
}

/// Read a length-prefixed message from the stream
async fn read_length_prefixed_message(stream: &mut TcpStream) -> Result<Vec<u8>> {
    // Read 4-byte length prefix
    let mut length_bytes = [0u8; 4];
    stream
        .read_exact(&mut length_bytes)
        .await
        .context("Failed to read message length")?;

    let length = u32::from_be_bytes(length_bytes) as usize;

    // Read the actual message
    let mut buffer = vec![0u8; length];
    stream
        .read_exact(&mut buffer)
        .await
        .context("Failed to read message data")?;

    Ok(buffer)
}

/// Write a length-prefixed message to the stream
async fn write_length_prefixed_message(stream: &mut TcpStream, data: &[u8]) -> Result<()> {
    // Write 4-byte length prefix
    let length = data.len() as u32;
    stream
        .write_all(&length.to_be_bytes())
        .await
        .context("Failed to write message length")?;

    // Write the actual message
    stream
        .write_all(data)
        .await
        .context("Failed to write message data")?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Basic CLI parsing: supports --config <path>, --server <addr>, and commands
    let args: Vec<String> = std::env::args().collect();

    // Find optional --config override
    let mut config_path: Option<String> = None;
    let mut server_override: Option<String> = None;
    let mut model_override: Option<String> = None;
    let mut flag_json: bool = false;
    let mut flag_summary: bool = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--config" => {
                if i + 1 < args.len() { config_path = Some(args[i + 1].clone()); i += 2; continue; }
            }
            "--server" => {
                if i + 1 < args.len() { server_override = Some(args[i + 1].clone()); i += 2; continue; }
            }
            "--model" => {
                if i + 1 < args.len() { model_override = Some(args[i + 1].clone()); i += 2; continue; }
            }
            "--json" => { flag_json = true; i += 1; continue; }
            "--summary" => { flag_summary = true; i += 1; continue; }
            _ => {}
        }
        i += 1;
    }

    // Load configuration (default or overridden path)
    let config = match config_path {
        Some(p) => AgentConfig::load_or_default(&p),
        None => AgentConfig::load_or_default("config.toml"),
    };

    // Determine server address precedence: CLI override > config
    let agent_address = server_override
        .as_deref()
        .unwrap_or_else(|| config.service.ipc_bind.as_str());

    // Use the IPC key from the loaded configuration
    let ipc_key_to_use = &config.ipc_key;

    println!("Connecting to ERDPS Agent IPC server at {}...", agent_address);
    println!("Config shows IPC bind: {}", config.service.ipc_bind);
    println!("Using IPC key: {} (length: {} bytes)",
             ipc_key_to_use,
             BASE64.decode(ipc_key_to_use).unwrap_or_default().len());

    // Connect to IPC server using the agent's actual address
    let mut stream = TcpStream::connect(agent_address)
        .await
        .context("Failed to connect to IPC server")?;

    println!("Connected successfully!");

    // Subcommand parsing: default getStatus; support 'quarantine <path>' and 'scan <path>'
    let (command, payload) = {
        // Build positional args (skip known flags and their values)
        let mut positional: Vec<String> = Vec::new();
        let mut j = 1;
        while j < args.len() {
            match args[j].as_str() {
                "--config" | "--server" => { j += 2; continue; }
                arg if arg.starts_with("--") => { j += 1; continue; }
                _ => {
                    positional.push(args[j].clone());
                    j += 1;
                }
            }
        }

        if let Some(cmd) = positional.get(0) {
            match cmd.as_str() {
                "quarantine" => {
                    if positional.len() < 2 {
                        eprintln!("Usage: ipc_client [--server <addr>] [--config <path>] quarantine <file_path>");
                        std::process::exit(1);
                    }
                    let file_path = &positional[1];
                    (
                        "quarantineFiles".to_string(),
                        json!({ "files": [file_path] }),
                    )
                }
                "scan" => {
                    if positional.len() < 2 {
                        eprintln!("Usage: ipc_client [--server <addr>] [--config <path>] scan <file_path>");
                        std::process::exit(1);
                    }
                    let file_path = &positional[1];
                    (
                        "scan_file".to_string(),
                        json!({ "path": file_path }),
                    )
                }
                "llm_scan" => {
                    if positional.len() < 2 {
                        eprintln!("Usage: ipc_client [--server <addr>] [--config <path>] llm_scan <file_path> [--model <ollama_model>]");
                        std::process::exit(1);
                    }
                    let file_path = &positional[1];
                    let mut p = json!({ "path": file_path, "disassembly": true });
                    if let Some(m) = model_override.as_ref() {
                        p["llm_model"] = json!(m);
                    }
                    (
                        "scan_file".to_string(),
                        p,
                    )
                }
                "getStatus" => ("getStatus".to_string(), json!({})),
                "start_scan" => {
                    if positional.len() < 2 {
                        eprintln!("Usage: ipc_client [--server <addr>] start_scan <path|dir> [<path2> ...]");
                        std::process::exit(1);
                    }
                    let paths: Vec<String> = positional[1..].to_vec();
                    (
                        "start_scan".to_string(),
                        json!({ "paths": paths })
                    )
                }
                "get_job_status" => {
                    if positional.len() < 2 {
                        eprintln!("Usage: ipc_client [--server <addr>] get_job_status <job_id>");
                        std::process::exit(1);
                    }
                    let job_id = &positional[1];
                    (
                        "get_job_status".to_string(),
                        json!({ "job_id": job_id })
                    )
                }
                "stop_scan" => {
                    if positional.len() < 2 {
                        eprintln!("Usage: ipc_client [--server <addr>] stop_scan <job_id>");
                        std::process::exit(1);
                    }
                    let job_id = &positional[1];
                    (
                        "stop_scan".to_string(),
                        json!({ "job_id": job_id })
                    )
                }
                other => {
                    eprintln!("Unknown command '{}'. Supported: getStatus | quarantine <file> | scan <file> | start_scan <paths...> | get_job_status <job_id> | stop_scan <job_id>", other);
                    std::process::exit(1);
                }
            }
        } else {
            ("getStatus".to_string(), json!({}))
        }
    };

    // Send request
    let mut request = RequestMessage {
        nonce: generate_nonce(),
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64,
        command: command.clone(),
        payload: payload.clone(),
        signature: String::new(), // Will be filled by sign function
    };

    // Sign the request using the loaded IPC key
    let ipc_key = BASE64
        .decode(ipc_key_to_use)
        .context("Failed to decode IPC key")?;
    request.signature = sign(
        &request.command,
        request.timestamp,
        &request.nonce,
        &request.payload,
        &ipc_key,
    )
    .context("Failed to sign request")?;

    println!("Sending {} request...", command);

    // Serialize and send request
    let request_json = serde_json::to_vec(&request).context("Failed to serialize request")?;

    write_length_prefixed_message(&mut stream, &request_json)
        .await
        .context("Failed to send request")?;

    println!("Request sent, waiting for response...");

    // Read response
    let response_data = read_length_prefixed_message(&mut stream)
        .await
        .context("Failed to read response")?;

    // Parse response
    let response: ResponseMessage =
        serde_json::from_slice(&response_data).context("Failed to parse response")?;

    if flag_json {
        let pretty = serde_json::to_string_pretty(&response.payload)?;
        println!("{}", pretty);
    } else {
        println!("Response received:");
        println!("  Status: {}", response.status);
        let pretty = serde_json::to_string_pretty(&response.payload)?;
        println!("  Payload: {}", pretty);
    }

    if flag_summary || !flag_json {
        if let Some(ctx) = response.payload.get("context").and_then(|v| v.as_str()) {
            if ctx == "yara_scan" {
                if let Some(data) = response.payload.get("data") {
                    if let Some(disassembly) = data.get("disassembly") {
                        if let Some(llm) = disassembly.get("llm") {
                            if !llm.is_null() {
                                let classification = llm.get("classification").and_then(|v| v.as_str()).unwrap_or("unknown");
                                let confidence = llm.get("confidence").and_then(|v| v.as_f64()).unwrap_or(0.0);
                                let model_used = llm.get("model_used").and_then(|v| v.as_str()).unwrap_or("unknown");
                                println!("\nLLM Classification Summary:\n  Model: {}\n  Verdict: {} (confidence {:.2})", model_used, classification, confidence);
                            }
                        }
                    }
                }
            }
        }
    }

    // Verify response signature
    let expected_signature = sign(
        "response",
        response.timestamp,
        &response.nonce,
        &response.payload,
        &ipc_key,
    )
    .context("Failed to generate expected signature")?;

    if response.signature == expected_signature {
        println!("✓ Response signature verified successfully!");
        
        // HYBRID ANALYSIS LOGIC
        // If this was a standard scan and we got a "Suspicious" but not "Critical" result, escalate to LLM
        if command == "scan_file" {
             let is_llm_scan = payload.get("disassembly").and_then(|v| v.as_bool()).unwrap_or(false);
             if !is_llm_scan {
                 // Check matches
                 let matches = response.payload.get("matches").and_then(|v| v.as_array());
                 if let Some(match_list) = matches {
                     // Check if we have matches that are NOT Critical (e.g. generic Suspicious)
                     // For testing/thesis: Escalate ALL matches to LLM to get the "Verdict"
                     if !match_list.is_empty() {
                         println!("\n🔍 YARA detection triggers Hybrid Analysis. Escalating to LLM...");
                         
                         let llm_payload = json!({ 
                             "path": payload["path"], 
                             "disassembly": true,
                             "llm_model": "deepseek-coder:6.7b" // Default to strong model
                         });
                         
                         let mut llm_request = RequestMessage {
                            nonce: generate_nonce(),
                            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64,
                            command: "scan_file".to_string(),
                            payload: llm_payload,
                            signature: String::new(),
                        };
                        
                        llm_request.signature = sign(
                            &llm_request.command,
                            llm_request.timestamp,
                            &llm_request.nonce,
                            &llm_request.payload,
                            &ipc_key,
                        ).context("Failed to sign LLM request")?;
                        
                        let llm_req_json = serde_json::to_vec(&llm_request)?;
                        write_length_prefixed_message(&mut stream, &llm_req_json).await?;
                        
                        println!("LLM Request sent, waiting for deep analysis...");
                        let llm_resp_data = read_length_prefixed_message(&mut stream).await?;
                        let llm_response: ResponseMessage = serde_json::from_slice(&llm_resp_data)?;
                        
                        println!("🧠 Deep Analysis Result:");
                        println!("{}", serde_json::to_string_pretty(&llm_response.payload)?);
                     }
                 }
             }
        }

    } else {
        println!("✗ Response signature verification failed!");
        println!("  Expected: {}", expected_signature);
        println!("  Received: {}", response.signature);
    }

    println!("IPC client test completed.");
    Ok(())
}
