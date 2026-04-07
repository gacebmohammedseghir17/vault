use sysinfo::System;
use crate::utils::process_killer;
use std::{thread, time};

pub fn start_behavior_monitor() {
    thread::spawn(|| {
        let mut sys = System::new_all();
        let dangerous_bins = vec!["vssadmin.exe", "wbadmin.exe", "bcdedit.exe", "taskkill.exe"];

        loop {
            sys.refresh_processes();
            for (pid, process) in sys.processes() {
                // In sysinfo 0.30+, name() returns &str
                let name = process.name().to_lowercase();
                
                for bad_bin in &dangerous_bins {
                    if name == *bad_bin {
                        // CHECK: Is it running with arguments like "delete shadows"?
                        // (Simplified for demo: Kill ANY use of these admin tools while Agent is active)
                        println!("\n[!] SUSPICIOUS ADMIN TOOL DETECTED: {}", name);
                        process_killer::kill_pid(pid.as_u32());
                    }
                }
            }
            thread::sleep(time::Duration::from_millis(500)); // Check 2x per second
        }
    });
}
