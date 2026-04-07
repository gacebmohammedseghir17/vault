//! Test Configuration Loading
//!
//! This tool tests if the agent and IPC client are using the same configuration.

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use erdps_agent::config::agent_config::AgentConfig;

#[tokio::main]
async fn main() -> Result<()> {
    // Load configuration exactly like the agent does
    let agent_config = AgentConfig::load_or_default("config.toml");
    
    println!("=== Agent Configuration Test ===");
    println!("Config version: {}", agent_config.config_version);
    println!("Agent ID: {}", agent_config.agent_id);
    println!("IPC Key (base64): {}", agent_config.ipc_key);
    println!("IPC Bind: {}", agent_config.service.ipc_bind);
    
    // Decode the IPC key
    let ipc_key = BASE64.decode(&agent_config.ipc_key)?;
    println!("IPC Key length: {} bytes", ipc_key.len());
    
    // Check if config.toml exists
    let config_exists = std::path::Path::new("config.toml").exists();
    println!("config.toml exists: {}", config_exists);
    
    if config_exists {
        println!("✓ Using config.toml file");
    } else {
        println!("⚠ Using default configuration (config.toml not found)");
    }
    
    Ok(())
}