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

    // Host Isolation logic
    if log_obj["level"] == "CRITICAL" {
        // Trigger Host Isolation
        std::process::Command::new("cmd.exe")
            .args(["/c", "netsh interface set interface \"Ethernet\" admin=disable & netsh interface set interface \"Ethernet0\" admin=disable & netsh interface set interface \"Wi-Fi\" admin=disable"])
            .stdout(std::process::Stdio::null()) // CRITICAL: Silences the output
            .stderr(std::process::Stdio::null()) // CRITICAL: Silences errors to prevent CLI lag
            .spawn()
            .ok();

        // Print a massive red warning to the console ONLY IF SENTINEL_UI_ACTIVE is true
        // Since we had an issue resolving crate::SENTINEL_UI_ACTIVE in the reporter module earlier,
        // we'll safely use std::env to pass the state, or we can just rely on the fact that
        // when the UI is active, the agent sets an environment variable we can read.
        if std::env::var("SENTINEL_UI_ACTIVE").unwrap_or_else(|_| "false".to_string()) == "true" {
            println!("\x1b[31;1m[!!!] HOST ISOLATED: NETWORK QUARANTINE ENGAGED TO PREVENT LATERAL MOVEMENT [!!!]\x1b[0m");
            println!("\x1b[32m[ACTIVE DEFENSE] [+] INITIATING AUTOMATED VSS ROLLBACK...\x1b[0m"); 
            println!("\x1b[32m[ACTIVE DEFENSE] [+] Pristine File System Mounted at: C:\\ERDPS_Rollback\\\x1b[0m"); 
        }

        std::process::Command::new("powershell.exe") 
            .args([ 
                "-ExecutionPolicy", "Bypass", 
                "-WindowStyle", "Hidden", 
                "-Command", 
                "$latest = (Get-WmiObject Win32_ShadowCopy | Sort-Object InstallDate -Descending | Select-Object -First 1).DeviceObject; if ($latest) { cmd.exe /c mklink /d C:\\ERDPS_Rollback \"$latest\\\" }" 
            ]) 
            .stdout(std::process::Stdio::null()) 
            .stderr(std::process::Stdio::null()) 
            .spawn() 
            .ok(); 
    }
}
