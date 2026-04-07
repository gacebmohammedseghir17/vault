use std::process::Command;
use std::io::{Result, Error, ErrorKind};
use console::style;

pub struct NetworkIsolation;

impl NetworkIsolation {
    /// ENGAGE LOCKDOWN: Blocks all outbound network traffic immediately.
    /// Uses Windows Advanced Firewall to create a high-priority block rule.
    pub fn engage() -> Result<()> {
        println!("{}", style("[*] INITIATING NETWORK ISOLATION...").red().bold());

        // 1. Ensure Firewall is ON
        let status = Command::new("netsh")
            .args(&["advfirewall", "set", "allprofiles", "state", "on"])
            .output()?;

        if !status.status.success() {
            return Err(Error::new(ErrorKind::Other, "Failed to enable firewall service"));
        }

        // 2. Create Block Rule (Blocks everything outbound)
        // Rule Name: ERDPS_QUARANTINE
        let output = Command::new("netsh")
            .args(&[
                "advfirewall", "firewall", "add", "rule",
                "name=ERDPS_QUARANTINE",
                "dir=out",
                "action=block",
                "enable=yes",
                "profile=any"
            ])
            .output()?;

        if output.status.success() {
            println!("{}", style("[+] NETWORK ISOLATION SUCCESSFUL. System is offline.").green().bold());
            Ok(())
        } else {
            let err_msg = String::from_utf8_lossy(&output.stderr);
            println!("{}", style(format!("[!] ISOLATION FAILED: {}", err_msg)).red());
            Err(Error::new(ErrorKind::Other, "Failed to create block rule"))
        }
    }

    /// ISOLATE PROCESS: Blocks network access for a specific PID/Executable.
    pub fn isolate_process(pid: u32, exe_path: &str) -> Result<()> {
        println!("{}", style(format!("[*] ISOLATING PROCESS PID: {}...", pid)).red().bold());
        
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
            .output()?;

        if output.status.success() {
            println!("{}", style(format!("[+] PROCESS ISOLATED: {} (PID: {})", exe_path, pid)).green().bold());
            Ok(())
        } else {
             let err_msg = String::from_utf8_lossy(&output.stderr);
             println!("{}", style(format!("[!] PROCESS ISOLATION FAILED: {}", err_msg)).red());
             Err(Error::new(ErrorKind::Other, "Failed to create process block rule"))
        }
    }

    /// LIFT LOCKDOWN: Removes the block rule, restoring internet access.
    pub fn lift() -> Result<()> {
        println!("{}", style("[*] RESTORING NETWORK CONNECTIVITY...").yellow().bold());

        let output = Command::new("netsh")
            .args(&[
                "advfirewall", "firewall", "delete", "rule",
                "name=ERDPS_QUARANTINE"
            ])
            .output()?;

        // It might fail if the rule doesn't exist, which is fine.
        // Also check stdout for "No rules match"
        let stdout = String::from_utf8_lossy(&output.stdout);
        
        if output.status.success() || stdout.contains("No rules match") {
            println!("{}", style("[+] NETWORK CONNECTIVITY RESTORED.").green().bold());
            Ok(())
        } else {
            let err_msg = String::from_utf8_lossy(&output.stderr);
            println!("{}", style(format!("[!] RESTORATION FAILED: {}", err_msg)).red());
            Err(Error::new(ErrorKind::Other, "Failed to remove block rule"))
        }
    }
}
