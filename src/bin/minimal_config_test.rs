use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MinimalConfig {
    pub ipc_key: String,
    pub quarantine_path: String,
    pub audit_log_path: String,
}

fn main() {
    println!("Minimal TOML Configuration Test");

    let content =
        fs::read_to_string("config_minimal.toml").expect("Failed to read config_minimal.toml");

    println!("✓ Successfully read config.toml");
    println!("Content length: {} bytes", content.len());

    match toml::from_str::<MinimalConfig>(&content) {
        Ok(config) => {
            println!("✓ Successfully parsed minimal TOML!");
            println!("Config: {:#?}", config);
        }
        Err(e) => {
            println!("✗ Failed to parse minimal TOML: {}", e);
            println!("Error details: {:?}", e);
        }
    }
}
