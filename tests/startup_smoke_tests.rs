//! Log-only smoke tests for ERDPS Agent startup validation
//!
//! These tests validate the exact startup summary format without HTTP dependencies.
//! They guard the message contract and ensure proper log parsing.

use erdps_agent::testing::allocate_test_port;
use std::process::{Command, Stdio};
use std::time::Duration;

/// Test that validates the exact startup summary format without HTTP
/// Guards the message contract: 'metrics.port=<PORT>, rules_loaded=<N>, drives=[...], mode=console'
/// Followed by: 'Metrics server starting on port <PORT>'
#[tokio::test]
async fn test_startup_summary_format() {
    // Allocate a unique port for this test
    let _port = allocate_test_port()
        .await
        .expect("Failed to allocate test port");
    let port_num = _port.port();

    // Build the agent binary first
    let build_output = Command::new("cargo")
        .args(["build", "--bin", "erdps-agent"])
        .current_dir(".")
        .output()
        .expect("Failed to build agent binary");

    assert!(
        build_output.status.success(),
        "Failed to build agent: {}",
        String::from_utf8_lossy(&build_output.stderr)
    );

    // Run the agent with a timeout to capture startup logs
    let mut child = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "erdps-agent",
            "--",
            "--metrics-port",
            &port_num.to_string(),
        ])
        .current_dir(".")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start agent");

    // Give the agent time to start up and log the summary
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Kill the process
    let _ = child.kill();
    let output = child
        .wait_with_output()
        .expect("Failed to read agent output");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined_output = format!("{}{}", stdout, stderr);

    println!("Agent output:\n{}", combined_output);

    // Validate the startup summary format with custom port
    let startup_summary_regex = regex::Regex::new(&format!(
        r"metrics\.port={}, rules_loaded=\d+, drives=\[.*\], mode=console",
        port_num
    ))
    .expect("Invalid regex");

    assert!(
        startup_summary_regex.is_match(&combined_output),
        "Startup summary format mismatch. Expected: 'metrics.port={}, rules_loaded=<N>, drives=[...], mode=console'\nActual output: {}",
        port_num,
        combined_output
    );

    // Validate the metrics server startup message
    assert!(
        combined_output.contains(&format!("Metrics server starting on port {}", port_num)),
        "Missing metrics server startup message. Expected: 'Metrics server starting on port {}'\nActual output: {}",
        port_num,
        combined_output
    );
}

/// Test startup summary with different port configuration
#[tokio::test]
async fn test_startup_summary_custom_port() {
    // Allocate a unique port for this test
    let _port = allocate_test_port()
        .await
        .expect("Failed to allocate test port");
    let custom_port = _port.port();

    // Build the agent binary first
    let build_output = Command::new("cargo")
        .args(["build", "--bin", "erdps-agent"])
        .current_dir(".")
        .output()
        .expect("Failed to build agent binary");

    assert!(
        build_output.status.success(),
        "Failed to build agent: {}",
        String::from_utf8_lossy(&build_output.stderr)
    );

    // Run the agent with custom port
    let mut child = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "erdps-agent",
            "--",
            "--metrics-port",
            &custom_port.to_string(),
        ])
        .current_dir(".")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start agent");

    // Give the agent time to start up and log the summary
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Kill the process
    let _ = child.kill();
    let output = child
        .wait_with_output()
        .expect("Failed to read agent output");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined_output = format!("{}{}", stdout, stderr);

    println!("Agent output (custom port):\n{}", combined_output);

    // Validate the startup summary format with custom port
    let startup_summary_regex = regex::Regex::new(&format!(
        r"metrics\.port={}, rules_loaded=\d+, drives=\[.*\], mode=console",
        custom_port
    ))
    .expect("Invalid regex");

    assert!(
        startup_summary_regex.is_match(&combined_output),
        "Startup summary format mismatch with custom port. Expected: 'metrics.port={}, rules_loaded=<N>, drives=[...], mode=console'\nActual output: {}",
        custom_port,
        combined_output
    );

    // Validate the metrics server startup message with custom port
    assert!(
        combined_output.contains(&format!("Metrics server starting on port {}", custom_port)),
        "Missing metrics server startup message with custom port. Expected: 'Metrics server starting on port {}'\nActual output: {}",
        custom_port,
        combined_output
    );
}

/// Test that validates rules_loaded count is reasonable (>= 0)
#[tokio::test]
async fn test_rules_loaded_count_validation() {
    // Allocate a unique port for this test
    let _port = allocate_test_port()
        .await
        .expect("Failed to allocate test port");
    let port_num = _port.port();

    // Build the agent binary first
    let build_output = Command::new("cargo")
        .args(["build", "--bin", "erdps-agent"])
        .current_dir(".")
        .output()
        .expect("Failed to build agent binary");

    assert!(
        build_output.status.success(),
        "Failed to build agent: {}",
        String::from_utf8_lossy(&build_output.stderr)
    );

    // Run the agent
    let mut child = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "erdps-agent",
            "--",
            "--metrics-port",
            &port_num.to_string(),
        ])
        .current_dir(".")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start agent");

    // Give the agent time to start up and log the summary
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Kill the process
    let _ = child.kill();
    let output = child
        .wait_with_output()
        .expect("Failed to read agent output");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined_output = format!("{}{}", stdout, stderr);

    // Extract rules_loaded count from the output
    let rules_regex = regex::Regex::new(r"rules_loaded=(\d+)").expect("Invalid regex");

    if let Some(captures) = rules_regex.captures(&combined_output) {
        let rules_count: usize = captures[1].parse().expect("Failed to parse rules count");

        // Validate that rules_loaded is a reasonable number (>= 0, < 10000)
        assert!(
            rules_count < 10000,
            "Rules loaded count seems unreasonably high: {}. This might indicate a parsing error.",
            rules_count
        );

        println!("Rules loaded count validated: {}", rules_count);
    } else {
        panic!(
            "Could not find rules_loaded count in output: {}",
            combined_output
        );
    }
}
