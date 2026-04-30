use sysinfo::{System, ProcessRefreshKind, UpdateKind};
use std::{thread, time};
use crate::active_defense::policy::{Signal, ActionPlan, PolicyGate, MitigationExecutor};
use crate::{CURRENT_PROFILE, Profile};

pub fn start_behavior_monitor() {
    thread::spawn(|| {
        println!("\x1b[35m[PROCESS] Hunter actively monitoring...\x1b[0m");
        let mut sys = System::new_with_specifics(
            sysinfo::RefreshKind::new().with_processes(
                ProcessRefreshKind::new().with_cmd(UpdateKind::Always)
            )
        );
        let dangerous_bins = vec!["vssadmin.exe", "wbadmin.exe", "bcdedit.exe", "taskkill.exe"];

        loop {
            sys.refresh_processes_specifics(ProcessRefreshKind::new().with_cmd(UpdateKind::Always));
            for (pid, process) in sys.processes() {
                let name = process.name().to_lowercase();
                let cmd = process.cmd().join(" ").to_lowercase();
                
                for bad_bin in &dangerous_bins {
                    if name == *bad_bin {
                        // CHECK: Is it running with arguments like "delete shadows"?
                        if cmd.contains("delete") || cmd.contains("shadows") || cmd.is_empty() {
                            println!("\n\x1b[31m[!] SUSPICIOUS ADMIN TOOL DETECTED: {} (CMD: {})\x1b[0m", name, cmd);
                            let sig1 = Signal { source: "Behavior", pid: pid.as_u32(), reason: 6, file_path: cmd.clone(), metadata: Some("Suspicious Admin Tool".to_string()) };
                            MitigationExecutor::execute(PolicyGate::decide(&sig1, ActionPlan::Kill), &sig1);
                            
                            // Task 1: Fix the Admin Tool Whac-A-Mole
                            if let Some(ppid) = process.parent() {
                                println!("\x1b[31;1m[CRITICAL] Admin Tool launched by PID {}. Executing Storyline Kill on Parent Process!\x1b[0m", ppid.as_u32());
                                let sig2 = Signal { source: "Behavior", pid: ppid.as_u32(), reason: 6, file_path: cmd.clone(), metadata: Some("Admin Tool Launched".to_string()) };
                                MitigationExecutor::execute(PolicyGate::decide(&sig2, ActionPlan::StorylineKill), &sig2);
                            }
                        }
                    }
                }
            }
            // Poll interval depends on profile
            let profile = CURRENT_PROFILE.lock().unwrap().clone();
            let sleep_ms = if profile == Profile::Lab { 10 } else { 100 };
            thread::sleep(time::Duration::from_millis(sleep_ms)); 
        }
    });
}
