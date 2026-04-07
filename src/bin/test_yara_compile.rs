use erdps_agent::config::AgentConfig;
use erdps_agent::detection::yara_engine::YaraEngine;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("YARA Compile Test: attempting to load rules from ./rules (recursive)");

    // Load default agent config (not strictly needed for compile, but consistent with engine usage)
    let config = AgentConfig::load_or_default("config/agent.toml");
    let engine = YaraEngine::new(Arc::new(config));

    let rules_dir = "rules";
    if let Err(e) = engine.load_rules(rules_dir).await {
        eprintln!("✗ Failed to compile YARA rules from '{}': {}", rules_dir, e);
        // Provide a hint for common issues
        eprintln!("Hint: Check for unsupported constructs or syntax errors in nested directories.");
        // Exit with non-zero code to signal failure without type mismatches
        std::process::exit(1);
    }

    // If we got here, compilation succeeded
    let count = engine.get_rules_count().await;
    println!("✓ Successfully compiled YARA rules: {} total", count);
    println!("✓ Engine loaded: {}", engine.is_loaded().await);

    // Show basic metrics/info
    let info = engine.get_loaded_rules_info().await;
    println!("Loaded rules info:");
    for (k, v) in info {
        println!("  - {}: {}", k, v);
    }

    Ok(())
}
