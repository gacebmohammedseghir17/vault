use std::fs::OpenOptions;
use std::io::Write;
use chrono::Local;

pub fn log_alert(pid: u32, process_name: &str, reason_code: u32, target_file: &str) {
    let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    
    // Map the reason code to a human-readable string
    let reason_str = match reason_code {
        3 => "MASS_RENAME/DELETE",
        4 => "ENCRYPTION_LOOP",
        5 => "MBR_WRITE",
        6 => "ZERO_TRUST_EXECUTION",
        7 => "BYOVD_DRIVER_LOAD",
        _ => "UNKNOWN_THREAT",
    };

    let log_entry = format!(
        "[{}] [CRITICAL ALERT] PID: {} | Process: {} | Reason: {} | Target: {}\n",
        timestamp, pid, process_name, reason_str, target_file
    );

    // Open the log file in append mode (Creates it if it doesn't exist)
    let mut file = match OpenOptions::new()
        .create(true)
        .append(true)
        .open("C:\\ERDPS_Vault\\erdps_alerts.log")
    {
        Ok(f) => f,
        Err(e) => {
            println!("\x1b[31m[!] Failed to open alert log: {}\x1b[0m", e);
            return;
        }
    };

    // Write the log entry in microseconds
    if let Err(e) = file.write_all(log_entry.as_bytes()) {
        println!("\x1b[31m[!] Failed to write to alert log: {}\x1b[0m", e);
    }
}
