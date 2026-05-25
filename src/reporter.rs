use std::fs::OpenOptions;
use std::io::Write;
use chrono::Local;
use serde_json::json;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};

// A local copy of the global atomic flag if needed, but since reporter is a module
// it can import from crate::SENTINEL_UI_ACTIVE if available, but reporter is sometimes 
// compiled as part of a lib or bin. Let's just use `crate::SENTINEL_UI_ACTIVE` if we 
// ensure it's exported in the lib, or just safely print.

pub fn log_alert(pid: u32, process_name: &str, reason_code: u32, target_file: &str) {
    let now = Local::now();
    let timestamp = now.format("%Y-%m-%d %H:%M:%S").to_string();
    let date_str = now.format("%Y-%m-%d").to_string();
    
    // Map the reason code to a human-readable string and MITRE tactic
    let (reason_str, mitre_tactic) = match reason_code {
        1 => ("HONEYPOT_TRIGGER", "T1114"),
        2 => ("SUSPICIOUS_ACCESS", "T1083"),
        3 => ("MASS_RENAME/DELETE", "T1485"),
        4 => ("ENCRYPTION_LOOP", "T1486"),
        5 => ("MBR_WRITE", "T1561.002"),
        6 => ("ZERO_TRUST_EXECUTION", "T1204"),
        7 => ("BYOVD_DRIVER_LOAD", "T1068"),
        8 => ("CANARY_TAMPERING", "T1562.001"),
        _ => ("UNKNOWN_THREAT", "T1000"),
    };

    let log_obj = json!({
        "timestamp": timestamp,
        "level": "CRITICAL",
        "event": reason_str,
        "pid": pid,
        "process": process_name,
        "target": target_file,
        "mitre_tactic": mitre_tactic
    });

    let mut log_entry = log_obj.to_string();
    log_entry.push('\n');

    let log_filename = format!("C:\\ERDPS_Vault\\erdps_alerts_{}.log", date_str);

    // Open the log file in append mode (Creates it if it doesn't exist)
    let mut file = match OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_filename)
    {
        Ok(f) => f,
        Err(_) => {
            return;
        }
    };

    // Write the log entry in microseconds
    let _ = file.write_all(log_entry.as_bytes());

    // Host Isolation logic is MOVED to MitigationExecutor (ActionPlan::Contain)
    // We no longer trigger firewall rules or VSS rollback directly from the reporter.
}
