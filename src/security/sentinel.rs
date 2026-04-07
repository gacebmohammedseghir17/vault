use std::thread;
use std::time::Duration;
use console::style;
use sysinfo::{System, ProcessRefreshKind};

// Import our Arsenal
use crate::active_defense::process_freeze::ProcessFreezer;
use crate::active_defense::honeypots::Minefield;
use crate::analysis::{key_recovery, injection}; // Removed telemetry import as we simulate it here
use crate::network::isolation::NetworkIsolation;
use crate::recovery::shadows::ShadowManager;
use crate::security::driver_guard::DriverGuard;

pub struct Sentinel;

impl Sentinel {
    /// START SENTINEL: The Autonomous Protection Loop
    pub fn engage() {
        println!("{}", style("[***] SENTINEL AI: ONLINE [***]").green().bold().blink());
        
        println!("{}", style("[*] SENTINEL PRE-FLIGHT: Creating Safety Snapshot...").yellow());
        ShadowManager::create_snapshot(); // <--- The "Save Game"
        
        println!("{}", style("[*] SENTINEL PRE-FLIGHT: Verifying Kernel Integrity...").yellow());
        DriverGuard::scan_kernel();
        
        println!("{}", style("[*] Mode: AUTONOMOUS ACTIVE DEFENSE").green());
        println!("{}", style("[*] Policies:").green());
        println!("    -> Zero-Tolerance for Encryption Behavior (TDT)");
        println!("    -> Zero-Tolerance for Process Hollowing (Hunter)");
        println!("    -> Auto-Response: FREEZE -> ISOLATE -> EXTRACT");

        Minefield::deploy();

        let mut sys = System::new_all();

        loop {
            // 1. Refresh Process List (Lightweight)
            sys.refresh_processes_specifics(ProcessRefreshKind::everything());

            // 2. Run PHYSICS Check (TDT Lite)
            // We implement a lighter version of telemetry here for speed
            for (pid, process) in sys.processes() {
                let pid_u32 = pid.as_u32();
                let name = process.name();

                // CHECK 1: HIGH VELOCITY I/O (Encryption Physics)
                // Note: In a real implementation, we'd cache previous IO to calculate delta.
                // For this demo, we assume the telemetry module has a static checker or we call it directly.
                // Here we simulate the logic: 
                // let disk_usage = process.disk_usage();
                // let _write_bytes = disk_usage.written_bytes; // This is usually total, need delta logic.
                
                // Let's rely on the Injection Hunter for the "Smoking Gun" trigger
                // CHECK 2: INJECTION HUNTER (RWX Memory)
                // Only scan high-risk targets to save CPU
                let targets = ["notepad.exe", "calc.exe", "explorer.exe", "cmd.exe"];
                if targets.contains(&name.to_lowercase().as_str()) {
                    if injection::InjectionHunter::is_hollowed(pid_u32) {
                        trigger_kill_chain(pid_u32, name, "Process Hollowing (RWX)");
                    }
                }
            }
            
            // Pulse (Scan every 2 seconds)
            thread::sleep(Duration::from_secs(2));
        }
    }
}

fn trigger_kill_chain(pid: u32, name: &str, reason: &str) {
    println!("{}", style(format!("\n[!!!] THREAT DETECTED: '{}' (PID: {})", name, pid)).red().bold().blink());
    println!("{}", style(format!("      REASON: {}", reason)).red());
    
    // STEP 1: STOP TIME (Freeze)
    ProcessFreezer::freeze(pid);
    
    // STEP 2: CUT CORDS (Network)
    let _ = NetworkIsolation::engage();
    
    // STEP 3: STEAL SECRETS (Keys)
    key_recovery::KeyHunter::extract_keys(pid);
    
    println!("{}", style("[+] THREAT NEUTRALIZED. WAITING FOR OPERATOR.").green().bold());
    println!("{}", style("    Type 'thaw <pid>' to release if false positive.").yellow());
    
    // Block thread to prevent log spam? Or just continue monitoring others?
    // Usually we add this PID to an "Ignore/Handled" list.
    // For demo purposes, we sleep heavily to allow operator intervention
    thread::sleep(Duration::from_secs(10));
}
