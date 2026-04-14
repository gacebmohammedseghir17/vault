use sysinfo::{System, ProcessRefreshKind, UpdateKind};
use erdps_agent::utils::process_killer;
use std::{thread, time};

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
                            process_killer::kill_pid(pid.as_u32());
                        }
                    }
                }
            }
            // Poll very fast to catch short-lived processes (10ms instead of 100ms)
            thread::sleep(time::Duration::from_millis(10)); 
        }
    });
}
