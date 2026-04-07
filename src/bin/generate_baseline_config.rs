use erdps_agent::config::agent_config::AgentConfig;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Generating baseline config from AgentConfig::default()");

    let default_config = AgentConfig::default();

    // Serialize to TOML
    let toml_string = toml::to_string_pretty(&default_config)?;

    println!("Generated TOML:");
    println!("{}", toml_string);

    // Save to file
    fs::write("baseline_config.toml", &toml_string)?;
    println!("\n✓ Saved baseline config to baseline_config.toml");

    // Try to load it back
    println!("\nTesting round-trip parsing...");
    let loaded_config: AgentConfig = toml::from_str(&toml_string)?;
    println!("✓ Successfully loaded config back from TOML");

    // Compare key values
    println!("\nKey values:");
    println!("  ipc_bind: {}", loaded_config.service.ipc_bind);
    println!(
        "  metrics_bind: {}",
        loaded_config.observability.metrics_bind
    );
    println!(
        "  dashboard_bind: {}",
        loaded_config.observability.dashboard_bind
    );
    println!(
        "  mttd_target_seconds: {}",
        loaded_config.detection.mttd_target_seconds
    );
    println!(
        "  yara_rules_path: {}",
        loaded_config.detection.yara_rules_path
    );
    println!("  agent_id: {}", loaded_config.agent_id);
    println!("  ipc_key: {}", loaded_config.ipc_key);
    println!("  quarantine_path: {}", loaded_config.quarantine_path);

    Ok(())
}
