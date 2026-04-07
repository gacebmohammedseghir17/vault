pub mod process_freeze;
pub mod honeypots;

use std::process::Command;
use crate::active_defense::process_freeze::ProcessFreezer;

pub struct ActiveDefense;

impl ActiveDefense {
    /// Kills the malicious process immediately
    pub fn engage_kill_switch(pid: u32) {
        println!("\x1b[31m[ACTIVE DEFENSE] ⚡ ENGAGING KILL SWITCH for PID: {}\x1b[0m", pid);
        
        let output = Command::new("taskkill")
            .args(&["/F", "/PID", &pid.to_string()])
            .output();

        match output {
            Ok(o) => {
                if o.status.success() {
                    println!("\x1b[32m[+] THREAT NEUTRALIZED (PID: {}). Process Terminated.\x1b[0m", pid);
                } else {
                    let err = String::from_utf8_lossy(&o.stderr);
                    println!("\x1b[31m[!] FAILED to kill process: {}\x1b[0m", err.trim());
                }
            },
            Err(e) => println!("\x1b[31m[!] Failed to execute taskkill: {}\x1b[0m", e),
        }
    }

    /// Suspends the process threads (Freezes it)
    pub fn engage_suspend(pid: u32) {
        println!("\x1b[33m[ACTIVE DEFENSE] ❄️ FREEZING PROCESS PID: {}\x1b[0m", pid);
        ProcessFreezer::freeze(pid);
    }

    /// Isolates the process from the network using Windows Firewall
    pub fn engage_network_isolation(pid: u32, exe_path: &str) {
        println!("\x1b[33m[ACTIVE DEFENSE] 🛡️ ISOLATING NETWORK for PID: {}\x1b[0m", pid);
        
        let rule_name = format!("ERDPS_BLOCK_PID_{}", pid);
        
        // Block outbound traffic for this specific program
        let output = Command::new("netsh")
            .args(&[
                "advfirewall", "firewall", "add", "rule",
                &format!("name={}", rule_name),
                "dir=out",
                "action=block",
                &format!("program=\"{}\"", exe_path),
                "enable=yes",
                "profile=any"
            ])
            .output();

        match output {
            Ok(o) => {
                if o.status.success() {
                    println!("\x1b[32m[+] NETWORK ISOLATION ACTIVE: {} (PID: {})\x1b[0m", exe_path, pid);
                } else {
                    let err = String::from_utf8_lossy(&o.stderr);
                    println!("\x1b[31m[!] ISOLATION FAILED: {}\x1b[0m", err.trim());
                }
            },
            Err(e) => println!("\x1b[31m[!] Failed to execute netsh: {}\x1b[0m", e),
        }
    }

    /// Creates a Volume Shadow Copy to enable file recovery
    pub fn create_snapshot() {
        println!("\x1b[33m[ACTIVE DEFENSE] 📸 Creating Shadow Copy Snapshot...\x1b[0m");
        
        // Use vssadmin to create a shadow copy of C:
        let output = Command::new("vssadmin")
            .args(&["create", "shadow", "/for=C:"])
            .output();

        match output {
            Ok(o) => {
                if o.status.success() {
                    println!("\x1b[32m[+] SNAPSHOT CREATED. Files protected.\x1b[0m");
                } else {
                    // vssadmin might fail if not admin or disabled, just log it.
                    let err = String::from_utf8_lossy(&o.stdout); // vssadmin writes error to stdout sometimes
                    println!("\x1b[31m[!] Snapshot creation failed (Is Admin?): {}\x1b[0m", err.trim());
                }
            },
            Err(e) => println!("\x1b[31m[!] Failed to execute vssadmin: {}\x1b[0m", e),
        }
    }

    /// Checks if a process name is a known ransomware tool (Chaos v4 Vector)
    pub fn is_ransomware_tool(process_name: &str) -> bool {
        let name = process_name.to_lowercase();
        name == "vssadmin.exe" || 
        name == "wbadmin.exe" || 
        name == "bcdedit.exe" || 
        name == "cipher.exe" || 
        name == "net.exe" // sometimes used to stop services
    }
}
