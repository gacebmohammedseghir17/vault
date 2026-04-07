use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::winnt::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, IO_COUNTERS};
use winapi::um::handleapi::CloseHandle;
use winapi::um::winbase::GetProcessIoCounters;
use winapi::shared::minwindef::FALSE;
use sysinfo::{System, ProcessRefreshKind};
use console::style;
use std::collections::HashMap;
use std::thread;
use std::time::Duration;

// Thresholds for "Ransomware-like" behavior
const WRITE_THRESHOLD_BPS: u64 = 50 * 1024 * 1024; // 50 MB/s
const SUSPICIOUS_WRITE_BPS: u64 = 10 * 1024 * 1024; // 10 MB/s

pub struct TelemetryGuard;

impl TelemetryGuard {
    pub fn start_monitor() {
        println!("[*] INITIALIZING SILICON SHIELD (Heuristic Telemetry)...");
        println!("[*] Baseline: Monitoring Process I/O > 10MB/s");

        let mut sys = System::new_all();
        let mut prev_io: HashMap<u32, u64> = HashMap::new();

        // Run as a background loop (in a real agent, this would be a spawned thread)
        // For CLI demo, we run 15 iterations
        for _ in 0..15 {
            sys.refresh_processes_specifics(ProcessRefreshKind::everything());

            for (pid, process) in sys.processes() {
                let pid_u32 = pid.as_u32();
                
                // 1. Get Low-Level IO Counters
                if let Some(current_writes) = get_io_writes(pid_u32) {
                    // Calculate Delta (Speed)
                    let last_writes = *prev_io.get(&pid_u32).unwrap_or(&current_writes);
                    let delta = current_writes.saturating_sub(last_writes);
                    
                    // Update History
                    prev_io.insert(pid_u32, current_writes);

                    // 2. The "Physics" Check
                    if delta > SUSPICIOUS_WRITE_BPS {
                        let mb_s = delta as f64 / 1024.0 / 1024.0;
                        let name = process.name();
                        
                        if delta > WRITE_THRESHOLD_BPS {
                            println!("{}", style(format!("[!] CRITICAL IO SPIKE: '{}' (PID: {}) writing @ {:.2} MB/s", name, pid_u32, mb_s)).red().bold().blink());
                            println!("{}", style("    -> BEHAVIOR: Massive Data Encryption detected.").red());
                            // In fully auto mode, we would calling freeze(pid) here
                        } else {
                            println!("{}", style(format!("[!] SUSPICIOUS ACTIVITY: '{}' (PID: {}) writing @ {:.2} MB/s", name, pid_u32, mb_s)).yellow());
                        }
                    }
                }
            }
            thread::sleep(Duration::from_secs(1));
        }
        println!("[*] Telemetry Cycle Complete.");
    }
}

// Helper to call Native Windows API for IO Counters
fn get_io_writes(pid: u32) -> Option<u64> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if handle.is_null() { return None; }

        let mut counters: IO_COUNTERS = std::mem::zeroed();
        let result = GetProcessIoCounters(handle, &mut counters);
        CloseHandle(handle);

        if result != 0 {
            Some(counters.WriteTransferCount)
        } else {
            None
        }
    }
}
