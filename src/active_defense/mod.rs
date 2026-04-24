pub mod process_freeze;
pub mod honeypots;

use std::process::Command;
use crate::active_defense::process_freeze::ProcessFreezer;
use sysinfo::{System, Pid};
use winapi::um::processthreadsapi::{OpenProcess, TerminateProcess};
use winapi::um::handleapi::CloseHandle;
use winapi::um::winnt::{PROCESS_TERMINATE, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, GENERIC_WRITE, GENERIC_READ, FILE_SHARE_READ, FILE_ATTRIBUTE_NORMAL};
use std::fs;
use windows::Win32::System::Diagnostics::Debug::{MiniDumpWriteDump, MiniDumpWithFullMemory, MiniDumpWithFullMemoryInfo, MINIDUMP_TYPE};
use windows::Win32::Foundation::HANDLE;
use winapi::um::fileapi::{CreateFileW, CREATE_ALWAYS};

pub struct ActiveDefense;

impl ActiveDefense {
    /// Creates a full memory dump of the process
    pub fn create_memory_dump(pid: u32, process_name: &str) -> bool {
        let dump_dir = "C:\\ERDPS_Vault\\Dumps";
        if let Err(_) = fs::create_dir_all(dump_dir) {
            return false;
        }

        let dump_path = format!("{}\\{}_{}.dmp", dump_dir, process_name, pid);
        let wide_path: Vec<u16> = dump_path.encode_utf16().chain(std::iter::once(0)).collect();

        unsafe {
            let process_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
            if process_handle.is_null() {
                return false;
            }

            let file_handle = CreateFileW(
                wide_path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ,
                std::ptr::null_mut(),
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut()
            );

            if file_handle == winapi::um::handleapi::INVALID_HANDLE_VALUE {
                CloseHandle(process_handle);
                return false;
            }

            // Convert raw handles to windows crate HANDLEs
            let win_process_handle = HANDLE(process_handle as isize);
            let win_file_handle = HANDLE(file_handle as isize);

            let dump_flags = MINIDUMP_TYPE(MiniDumpWithFullMemory.0 | MiniDumpWithFullMemoryInfo.0);

            let result = MiniDumpWriteDump(
                win_process_handle,
                pid,
                win_file_handle,
                dump_flags,
                None,
                None,
                None,
            );

            CloseHandle(process_handle);
            CloseHandle(file_handle);

            if result.is_ok() {
                if std::env::var("SENTINEL_UI_ACTIVE").unwrap_or_else(|_| "false".to_string()) == "true" {
                    println!("\x1b[32m[+] Memory Dump Preserved: {}\x1b[0m", dump_path);
                }
                return true;
            }
        }
        false
    }

    /// Kills the malicious process immediately
    pub fn engage_kill_switch(pid: u32) {
        println!("\x1b[31m[ACTIVE DEFENSE] ⚡ ENGAGING KILL SWITCH for PID: {}\x1b[0m", pid);

        let mut sys = System::new_all();
        sys.refresh_processes();

        let whitelist = [
            "erdps-agent.exe", "cmd.exe", "conhost.exe", "svchost.exe", 
            "csrss.exe", "smss.exe", "wininit.exe", "services.exe", 
            "lsass.exe", "winlogon.exe", "explorer.exe", "powershell.exe",
            "taskhostw.exe", "searchapp.exe", "sppsvc.exe"
        ];

        let mut process_name_for_dump = format!("Unknown_{}", pid);
        if let Some(process) = sys.process(Pid::from(pid as usize)) {
            let process_name = process.name().to_lowercase();
            process_name_for_dump = process_name.clone();
            for protected_name in whitelist.iter() {
                if process_name == *protected_name {
                    println!("\x1b[33m[!] CRITICAL SYSTEM PROCESS ({}) BYPASSED TERMINATION.\x1b[0m", process_name);
                    return; 
                }
            }
        }

        // CRITICAL: Freeze -> Dump -> Kill pipeline
        // This ensures the dump completes successfully before the process is terminated
        println!("\x1b[33m[ACTIVE DEFENSE] ❄️ FREEZING PROCESS PID: {} for Memory Dump\x1b[0m", pid);
        ProcessFreezer::freeze(pid);

        Self::create_memory_dump(pid, &process_name_for_dump);

        unsafe {
            let handle = OpenProcess(PROCESS_TERMINATE, 0, pid);
            if !handle.is_null() {
                let result = TerminateProcess(handle, 1);
                CloseHandle(handle);
                if result != 0 {
                    println!("\x1b[32m[+] THREAT NEUTRALIZED (PID: {}). Process Terminated.\x1b[0m", pid);
                    return;
                }
            }
            println!("\x1b[31m[!] FAILED to kill process: {} via TerminateProcess.\x1b[0m", pid);
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
        
        // Use wmic to create a shadow copy of C:
        let output = Command::new("wmic")
            .args(&["shadowcopy", "call", "create", "Volume=C:\\"])
            .output();

        match output {
            Ok(o) => {
                if o.status.success() {
                    println!("\x1b[32m[+] SNAPSHOT CREATED. Files protected.\x1b[0m");
                } else {
                    let err = String::from_utf8_lossy(&o.stdout);
                    println!("\x1b[31m[!] Snapshot creation failed (Is Admin?): {}\x1b[0m", err.trim());
                }
            },
            Err(e) => println!("\x1b[31m[!] Failed to execute wmic: {}\x1b[0m", e),
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
