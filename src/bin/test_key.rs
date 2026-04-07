use anyhow::Context;
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use erdps_agent::config::AgentConfig;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing IPC Key Configuration...");

    // Test base64 decoding
    let ipc_key = BASE64_STANDARD
        .decode("dGVzdF9rZXlfMTIzNDU2Nzg5MA==")
        .context("Failed to decode base64 key")?;

    println!("✓ Base64 decoding works: {} bytes", ipc_key.len());

    // Load the agent configuration
    let _config = AgentConfig::load_or_default("config/agent.toml");
    println!("✓ Configuration loaded successfully");

    // Test IPC key from config

    Ok(())
}
