use std::process::Command;
use std::thread;
use std::time::Duration;
use console::style;
use crate::utils::{process_killer, quarantine};
use crate::security::whitelist;
use std::sync::atomic::Ordering;

pub fn start_monitor() {
    // Ensure vault exists
    quarantine::setup_quarantine();
    
    thread::spawn(|| {
        println!("[NET] Starting Network Behavior Monitor (Interval: 3s)...");
        loop {
            check_connections();
            check_blacklisted_processes();
            check_process_whitelist();
            thread::sleep(Duration::from_secs(3));
        }
    });
}

fn check_process_whitelist() {
    // Check all running processes against whitelist
    // NOTE: This is resource intensive, in production we would use WMI events or Driver Callbacks
    
    // Get list of all processes with paths
    // wmic process get ProcessId,ExecutablePath /FORMAT:CSV
    // But tasklist is faster for just checking existence, wmic is better for paths.
    // Let's use wmic for full paths.
    let output = Command::new("wmic")
        .args(&["process", "get", "ProcessId,ExecutablePath", "/FORMAT:CSV"])
        .output();

    if let Ok(o) = output {
        let stdout = String::from_utf8_lossy(&o.stdout);
        for line in stdout.lines() {
            let parts: Vec<&str> = line.split(',').collect();
            // Node,ExecutablePath,ProcessId
            if parts.len() >= 3 {
                let path = parts[1].trim();
                let pid_str = parts[2].trim();
                
                if path.is_empty() || path.eq_ignore_ascii_case("ExecutablePath") { continue; }
                
                // Whitelist Check
                if !whitelist::is_trusted(path) {
                    // Check Mode
                    if crate::GLOBAL_INSTALL_MODE.load(Ordering::SeqCst) {
                        // Learning Mode
                        println!("{}", style(format!("[+] LEARNING: Whitelisted {}", path)).green());
                        whitelist::add_to_whitelist(path);
                    } else {
                        // Lock Mode (Enforcement)
                        // Ignore System Processes to avoid crashing
                        if path.to_lowercase().contains("windows\\system32") || path.to_lowercase().contains("windows\\explorer.exe") {
                             continue;
                        }

                        println!("{}", style(format!("[!] UNTRUSTED PROCESS DETECTED: {} (PID: {})", path, pid_str)).red().bold());
                        println!("{}", style("    [BLOCKED] Process killed by Application Whitelist.").red());
                        
                        if let Ok(pid) = pid_str.parse::<u32>() {
                             process_killer::kill_pid(pid);
                        }
                    }
                }
            }
        }
    }
}

fn check_blacklisted_processes() {
    // List all processes
    let output = Command::new("tasklist")
        .args(&["/FO", "CSV", "/NH"])
        .output();

    if let Ok(o) = output {
        let stdout = String::from_utf8_lossy(&o.stdout);
        for line in stdout.lines() {
            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() >= 2 {
                let name = parts[0].trim_matches('"');
                let pid_str = parts[1].trim_matches('"');
                
                // Blacklist: vssadmin (Shadow Copies), wbadmin (Backup), bcdedit (Boot Config), wmic (ShadowCopy Delete)
                let blacklist = ["vssadmin.exe", "wbadmin.exe", "bcdedit.exe", "wmic.exe"];
                
                if blacklist.iter().any(|&b| b.eq_ignore_ascii_case(name)) {
                     println!("{}", style(format!("[!!!] RANSOMWARE TACTIC DETECTED: Attempted to delete Backups via {}. Terminated.", name)).red().bold().blink());
                     
                     if let Ok(pid) = pid_str.parse::<u32>() {
                         process_killer::kill_pid(pid);
                     }
                }
            }
        }
    }
}

fn check_connections() {
    // 1. Run netstat -ano to get established connections
    // Output format: Proto  Local Address  Foreign Address  State  PID
    let output = Command::new("netstat")
        .args(&["-ano"])
        .output();

    if let Ok(o) = output {
        let stdout = String::from_utf8_lossy(&o.stdout);
        for line in stdout.lines() {
            if line.contains("ESTABLISHED") {
                parse_and_check(line);
            }
        }
    }
}

fn parse_and_check(line: &str) {
    let parts: Vec<&str> = line.split_whitespace().collect();
    // Parts: [Proto, Local, Foreign, State, PID]
    if parts.len() < 5 { return; }

    let foreign_ip = parts[2];
    let pid_str = parts[4];
    
    // Ignore Localhost and Private IPs (Simplified)
    if foreign_ip.starts_with("127.0.0.1") || foreign_ip.starts_with("192.168.") || foreign_ip.starts_with("[::1]") {
        return;
    }

    // Resolve PID to Name
    let process_name = get_process_name(pid_str);
    let pid_u32: u32 = pid_str.parse().unwrap_or(0);

    // Rule 1: System Tools making Network Connections
    let critical_tools = ["powershell.exe", "cmd.exe", "cscript.exe", "wscript.exe"];
    if critical_tools.contains(&process_name.as_str()) {
        println!("[!] NET ALERT: {} (PID: {}) -> {} {}", 
            style(&process_name).red().bold(), 
            pid_str, 
            style(foreign_ip).yellow(),
            style("[CRITICAL: System Tool Network Activity]").red().blink()
        );
        
        // ACTIVE DEFENSE: KILL ONLY (System File)
        process_killer::kill_pid(pid_u32);
        println!("{}", style(format!("    [+] ACTIVE DEFENSE: Terminated {}", process_name)).red().bold());
        return;
    }

    // Rule 2: Unknown Process talking to Public IP
    // Whitelist common browsers
    let browser_whitelist = ["chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "erdps-agent.exe"];
    if !browser_whitelist.contains(&process_name.as_str()) {
        println!("[!] NET WARNING: {} (PID: {}) -> {}", 
            style(&process_name).yellow(), 
            pid_str, 
            foreign_ip
        );
        
        // ACTIVE DEFENSE: KILL + QUARANTINE
        // Get full path before killing
        let full_path = get_process_path(pid_str);
        
        // Kill
        process_killer::kill_pid(pid_u32);
        println!("{}", style(format!("    [+] ACTIVE DEFENSE: Terminated {}", process_name)).red().bold());
        
        // Quarantine if we have a path and it's not a system path
        if !full_path.is_empty() && !full_path.to_lowercase().contains("windows\\system32") {
             quarantine::isolate_file(&full_path);
        }
    }
}

fn get_process_path(pid: &str) -> String {
    // wmic process where "ProcessId=<PID>" get ExecutablePath
    let output = Command::new("wmic")
        .args(&["process", "where", &format!("ProcessId={}", pid), "get", "ExecutablePath"])
        .output();
        
    if let Ok(o) = output {
        let stdout = String::from_utf8_lossy(&o.stdout);
        // Skip header lines
        for line in stdout.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() && trimmed.contains(":") {
                return trimmed.to_string();
            }
        }
    }
    "".to_string()
}

fn get_process_name(pid: &str) -> String {
    // Run tasklist /FI "PID eq <PID>" /FO CSV /NH
    // Output: "image_name","pid",...
    let output = Command::new("tasklist")
        .args(&["/FI", &format!("PID eq {}", pid), "/FO", "CSV", "/NH"])
        .output();

    if let Ok(o) = output {
        let stdout = String::from_utf8_lossy(&o.stdout);
        if let Some(first_line) = stdout.lines().next() {
            let parts: Vec<&str> = first_line.split(',').collect();
            if !parts.is_empty() {
                return parts[0].trim_matches('"').to_string();
            }
        }
    }
    "Unknown".to_string()
}
