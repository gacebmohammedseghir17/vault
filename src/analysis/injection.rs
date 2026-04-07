use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::memoryapi::VirtualQueryEx;
use winapi::um::winnt::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY};
use winapi::um::handleapi::CloseHandle;
use sysinfo::{System, ProcessRefreshKind};
use console::style;
use winapi::ctypes::c_void;

pub struct InjectionHunter;

impl InjectionHunter {
    pub fn scan_system() {
        println!("[*] INITIATING DEEP MEMORY SCAN (Injection Hunter)...");
        println!("[*] Hunting for RWX (Read-Write-Execute) Anomalies...");

        let mut sys = System::new_all();
        sys.refresh_processes_specifics(ProcessRefreshKind::everything());

        let mut anomaly_count = 0;

        for (pid, process) in sys.processes() {
            let pid_u32 = pid.as_u32();
            let name = process.name();

            // We focus on common targets for Hollowing
            let targets = ["notepad.exe", "calc.exe", "explorer.exe", "svchost.exe", "cmd.exe"];
            
            // Check if this process is a likely target OR if we just want to scan everything
            // For "Genius" mode, we scan unsuspecting apps specifically.
            if targets.contains(&name.to_lowercase().as_str()) {
                if is_hollowed(pid_u32) {
                    println!("{}", style(format!("[!] PROCESS HOLLOWING DETECTED: '{}' (PID: {})", name, pid_u32)).red().bold().blink());
                    println!("{}", style("    -> EVIDENCE: Found RWX (Read-Write-Execute) Memory Page").red());
                    println!("{}", style("    -> DIAGNOSIS: Process is likely hosting injected malware.").red());
                    anomaly_count += 1;
                    
                    // In Full Auto Mode, we would freeze(pid) here immediately.
                }
            }
        }

        if anomaly_count == 0 {
            println!("{}", style("[+] System appears clean. No RWX anomalies in target processes.").green());
        } else {
            println!("{}", style(format!("[!] ALERT: {} Injection Anomalies Detected!", anomaly_count)).red().bold());
        }
    }

    pub fn is_hollowed(pid: u32) -> bool {
        is_hollowed(pid)
    }
}

fn is_hollowed(pid: u32) -> bool {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
        if handle.is_null() { return false; }

        let mut address = 0 as *mut c_void;
        let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
        let mut found_rwx = false;

        while VirtualQueryEx(handle, address as *const c_void, &mut mbi, std::mem::size_of::<MEMORY_BASIC_INFORMATION>()) != 0 {
            // Check for MEM_COMMIT (In use)
            if mbi.State == MEM_COMMIT {
                // The "Smoking Gun": PAGE_EXECUTE_READWRITE (0x40)
                // Malware needs this to write code and then run it.
                // Legitimate apps almost NEVER use this (they use XR for code, RW for data).
                if mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_WRITECOPY {
                    // Filter: JIT Compilers (Browsers/Java) use RWX.
                    // But Notepad/Calc/Svchost SHOULD NOT have it.
                    found_rwx = true;
                    break;
                }
            }
            address = (address as usize + mbi.RegionSize) as *mut c_void;
        }

        CloseHandle(handle);
        found_rwx
    }
}
