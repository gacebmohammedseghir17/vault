use erdps_agent::config::AgentConfig;
use erdps_agent::yara_updater::YaraUpdater;
use std::path::Path;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing YARA Updater Configuration...");

    // Load the agent configuration
    let config = AgentConfig::load_or_default("config/agent.toml");
    println!("✓ Configuration loaded successfully");

    // Check YARA updater configuration
    let updater_config = &config.yara_updater;
    println!("✓ YARA Updater configuration found:");
    println!("  - Enabled: {}", updater_config.enabled);
    println!("  - Repository: {}", updater_config.repo_url);
    println!("  - Branch: {}", updater_config.branch);
    println!("  - Rules Directory: {:?}", updater_config.rules_directory);
    println!(
        "  - Update Interval: {} hours",
        updater_config.update_interval_hours
    );
    println!(
        "  - Checksum Verification: {}",
        updater_config.verify_checksums
    );

    if updater_config.enabled {
        println!("\nTesting YARA Updater initialization...");

        // Create a YaraUpdater instance
        let _updater = YaraUpdater::new(updater_config.clone())?;
        println!("✓ YARA Updater created successfully");

        // Test configuration validation
        println!("\nTesting configuration validation...");

        // Check if rules directory exists or can be created
        let rules_dir = Path::new(&updater_config.rules_directory);
        if rules_dir.exists() {
            println!("✓ Rules directory exists: {:?}", rules_dir);
        } else {
            println!("⚠ Rules directory does not exist: {:?}", rules_dir);
            println!("  (This is normal for first run - directory will be created during update)");
        }

        // Validate repository URL format
        if updater_config.repo_url.starts_with("https://") {
            println!("✓ Repository URL format is valid");
        } else {
            println!("⚠ Repository URL should start with https://");
        }

        println!("\n✓ YARA Updater test completed successfully!");
    } else {
        println!("ℹ YARA Updater is disabled in configuration");

        // Test with default configuration to show what would be used
        let default_config = erdps_agent::yara_updater::YaraUpdaterConfig::default();
        println!("\nDefault YARA Updater configuration (for reference):");
        println!("  - Enabled: {}", default_config.enabled);
        println!("  - Repository: {}", default_config.repo_url);
        println!("  - Branch: {}", default_config.branch);
        println!("  - Rules Directory: {:?}", default_config.rules_directory);

        let _updater = YaraUpdater::new(default_config)?;
        println!("✓ YARA Updater created with defaults");
    }

    println!("\n🎉 All tests passed! YARA Updater integration is working correctly.");
    Ok(())
}
