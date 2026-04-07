use std::{fs, thread, time::Duration};

// Validate flexi_logger rotation by forcing second-based rotation via env var
#[test]
fn logs_rotate_quickly_when_test_env_enabled() {
    // Force fast rotation for tests
    std::env::set_var("ERDPS_LOG_ROTATION_TEST", "1");

    // Initialize logger
    let _ = erdps_agent::logger::init_logger();

    // Write first log line
    log::info!("rotation test: first");

    // Wait over one second to trigger age-based rotation
    thread::sleep(Duration::from_millis(1200));

    // Write second log line to create a new file and rotate the previous one
    log::info!("rotation test: second");

    // Inspect logs directory for multiple files with the expected basename
    let entries = fs::read_dir("logs").expect("logs directory should exist");
    let mut count = 0;
    for entry in entries {
        let name = entry.unwrap().file_name();
        let n = name.to_string_lossy().to_string();
        if n.starts_with("erdps_agent") && n.ends_with(".log") {
            count += 1;
        }
    }

    assert!(count >= 2, "expected at least 2 log files after rotation, found {}", count);
}