use erdps_agent::config::AgentConfig;
use std::fs;

fn main() {
    println!("Debug TOML Configuration Parsing");

    // Read the raw TOML content
    match fs::read_to_string("config.toml") {
        Ok(content) => {
            println!("✓ Successfully read config.toml");
            println!("Content length: {} bytes", content.len());

            // Try to parse as TOML
            match toml::from_str::<AgentConfig>(&content) {
                Ok(config) => {
                    println!("✓ Successfully parsed TOML");
                    #[cfg(feature = "yara")]
                    {
                        if let Some(ref yara_config) = config.yara {
                            println!(
                                "✓ YARA config found - enabled: {}, rules_path: {}",
                                yara_config.enabled, yara_config.rules_path
                            );
                        } else {
                            println!("✗ No YARA config found");
                        }
                    }
                    #[cfg(not(feature = "yara"))]
                    {
                        let _ = config; // Suppress unused variable warning
                        println!("YARA feature not enabled in this build");
                    }
                }
                Err(e) => {
                    println!("✗ Failed to parse TOML: {}", e);
                    println!("Error details: {:?}", e);
                }
            }
        }
        Err(e) => {
            println!("✗ Failed to read config.toml: {}", e);
        }
    }
}
