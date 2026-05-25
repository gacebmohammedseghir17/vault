pub mod process_freeze;
pub mod honeypots;
pub mod honeypot;
pub mod rollback;
pub mod policy;

use std::process::Command;
use crate::active_defense::process_freeze::ProcessFreezer;
use sysinfo::{System, Pid};
use std::fs;
use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE};
use windows::Win32::Storage::FileSystem::{CreateFileW, FILE_SHARE_READ, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::Security::{AdjustTokenPrivileges, LookupPrivilegeValueW, TOKEN_PRIVILEGES, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_QUERY};
use windows::core::PCWSTR;

pub fn harden_agent_process() {
    if std::env::var("ERDPS_IMMORTALITY").unwrap_or_else(|_| "0".to_string()) != "1" {
        return;
    }
    
    println!("\x1b[35m[IMMORTALITY] 🛡️ HARDENING EDR PROCESS (Setting Critical Status)...\x1b[0m");

    unsafe {
        // 1. Enable SeDebugPrivilege
        let mut token_handle = windows::Win32::Foundation::HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token_handle).is_ok() {
            let mut luid = windows::Win32::Foundation::LUID::default();
            let priv_name: Vec<u16> = "SeDebugPrivilege".encode_utf16().chain(std::iter::once(0)).collect();
            
            if LookupPrivilegeValueW(PCWSTR::null(), PCWSTR(priv_name.as_ptr()), &mut luid).is_ok() {
                let mut tp = TOKEN_PRIVILEGES {
                    PrivilegeCount: 1,
                    Privileges: [LUID_AND_ATTRIBUTES {
                        Luid: luid,
                        Attributes: SE_PRIVILEGE_ENABLED,
                    }],
                };
                
                let _ = AdjustTokenPrivileges(token_handle, false, Some(&mut tp), 0, None, None);
            }
            windows::Win32::Foundation::CloseHandle(token_handle);
        }

        // 2. Call RtlSetProcessIsCritical (Undocumented NTAPI)
        type RtlSetProcessIsCriticalFn = unsafe extern "system" fn(u8, *mut u8, u8) -> i32;
        let ntdll = winapi::um::libloaderapi::GetModuleHandleA(b"ntdll.dll\0".as_ptr() as *const i8);
        if !ntdll.is_null() {
            let func_ptr = winapi::um::libloaderapi::GetProcAddress(ntdll, b"RtlSetProcessIsCritical\0".as_ptr() as *const i8);
            if !func_ptr.is_null() {
                let set_critical: RtlSetProcessIsCriticalFn = std::mem::transmute(func_ptr);
                let status = set_critical(1, std::ptr::null_mut(), 0);
                if status == 0 {
                    println!("\x1b[32m[+] EDR PROCESS IMMORTALIZED. (Termination will cause BSOD)\x1b[0m");
                } else {
                    println!("\x1b[31m[!] Failed to set critical process status (NTSTATUS: {:X}). Ensure Admin/SYSTEM rights.\x1b[0m", status);
                }
            }
        }
    }
}

pub fn unharden_agent_process() {
    unsafe {
        let ntdll = winapi::um::libloaderapi::GetModuleHandleA(b"ntdll.dll\0".as_ptr() as *const i8);
        if !ntdll.is_null() {
            let proc_addr = winapi::um::libloaderapi::GetProcAddress(ntdll, b"RtlSetProcessIsCritical\0".as_ptr() as *const i8);
            if !proc_addr.is_null() {
                // Signature: RtlSetProcessIsCritical(Boolean NewValue, PBoolean OldValue, Boolean CheckFlag)
                let rtl_set_process_is_critical: extern "system" fn(u32, *mut u32, u32) -> i32 = std::mem::transmute(proc_addr);
                let mut is_critical: u32 = 0;
                
                // Pass 0 (FALSE) to remove the critical status
                rtl_set_process_is_critical(0, &mut is_critical, 0);
                println!("\x1b[32m[+] Agent Immortality safely removed. OS is safe.\x1b[0m");
            }
        }
    }
}

pub struct ActiveDefense;

impl ActiveDefense {
    /// Kills the malicious process immediately
    pub fn engage_kill_switch(pid: u32, reason: &str) {
        println!("\x1b[31m[ACTIVE DEFENSE] ⚡ ENGAGING KILL SWITCH for PID: {}\x1b[0m", pid);

        let mut sys = System::new_all();
        sys.refresh_processes();

        let whitelist = [
            "erdps-agent.exe", "conhost.exe", "svchost.exe", 
            "csrss.exe", "smss.exe", "wininit.exe", "services.exe", 
            "lsass.exe", "winlogon.exe", "explorer.exe",
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

        unsafe {
            match OpenProcess(PROCESS_TERMINATE, false, pid) {
                Ok(handle) => {
                    let result = TerminateProcess(handle, 1);
                    let _ = CloseHandle(handle);
                    if result.is_ok() {
                        println!("\x1b[32m[+] THREAT NEUTRALIZED (PID: {}). Process Terminated.\x1b[0m", pid);
                        
                        // Generate the standalone HTML incident report (without dump)
                        crate::forensic::incident_report::IncidentReport::generate(
                            pid,
                            &process_name_for_dump,
                            reason,
                            "N/A"
                        );
                        
                        return;
                    }
                    println!("\x1b[31m[!] FAILED to kill process: {} via TerminateProcess.\x1b[0m", pid);
                }
                Err(_) => {
                    println!("\x1b[31m[!] FAILED to OpenProcess: {}.\x1b[0m", pid);
                }
            }
        }
    }

    /// Suspends the process threads (Freezes it)
    pub fn engage_suspend(pid: u32) {
        println!("\x1b[33m[ACTIVE DEFENSE] ❄️ FREEZING PROCESS PID: {}\x1b[0m", pid);
        ProcessFreezer::freeze(pid);
    }

    /// Engages a Storyline Kill: Terminates the target, its parent, and siblings.
    pub fn engage_storyline_kill(target_pid: u32, reason: &str) {
        let mut sys = System::new_all();
        sys.refresh_processes();
        
        // The Boundary Limit: If the malware's parent is one of these, do NOT kill siblings!
        let safe_parents = [
            "explorer.exe", "svchost.exe", "services.exe", "wininit.exe",
            "smss.exe", "csrss.exe", "lsass.exe", "winlogon.exe", "cmd.exe", "powershell.exe"
        ];

        if let Some(target_process) = sys.process(Pid::from(target_pid as usize)) {
            if let Some(parent_pid) = target_process.parent() {
                if let Some(parent_process) = sys.process(parent_pid) {
                    let parent_name = parent_process.name().to_lowercase();
                    
                    if safe_parents.contains(&parent_name.as_str()) {
                        println!("\x1b[33m[!] Storyline Boundary Hit: Parent is {}. Aborting full tree eradication to prevent OS crash.\x1b[0m", parent_name);
                        // Just kill the target, leave the parent and siblings alone
                        Self::engage_kill_switch(target_pid, "Target Only (Protected Parent)");
                        return;
                    }
                }
            }
        }

        println!("\x1b[31;1m[CRITICAL] STORYLINE KILL ENGAGED: Entire process tree eradicated.\x1b[0m");
        
        let mut pids_to_kill = std::collections::HashSet::new();
        pids_to_kill.insert(target_pid);
        
        if let Some(target_process) = sys.process(Pid::from(target_pid as usize)) {
            if let Some(ppid) = target_process.parent() {
                let ppid_u32 = ppid.as_u32();
                pids_to_kill.insert(ppid_u32);
                
                // Find siblings (other children of PPID)
                for (pid, process) in sys.processes() {
                    if let Some(parent) = process.parent() {
                        if parent.as_u32() == ppid_u32 {
                            pids_to_kill.insert(pid.as_u32());
                        }
                    }
                }
            }
        }
        
        for pid in &pids_to_kill {
            Self::engage_kill_switch(*pid, reason);
        }
        
        // Phase 4: Autonomous Rollback
        crate::active_defense::rollback::execute_rollback(target_pid);
        
        crate::siem::siem_forwarder::push_alert(
            "CRITICAL",
            "STORYLINE_KILL_ENGAGED",
            &format!("Storyline kill eradicated entire process tree. Target PID: {}. Reason: {}", target_pid, reason),
            pids_to_kill.iter().map(|p| p.to_string()).collect(),
        );
    }

    /// Isolates the process from the network using Windows Firewall
    pub fn engage_network_isolation(pid: u32, exe_path: &str) {
        println!("\x1b[33m[ACTIVE DEFENSE] 🛡️ Micro-Segmentation Active. Skipping global network isolation for PID: {}\x1b[0m", pid);
    }

    /// Blocks a specific malicious IP address using Micro-Segmentation
    pub fn block_specific_ip(ip_address: &str) {
        println!("\x1b[33m[ACTIVE DEFENSE] 🛡️ MICRO-SEGMENTATION: Blocking IP {}\x1b[0m", ip_address);
        
        let rule_name = format!("ERDPS_AI_BLOCK_{}", ip_address);
        
        let output = Command::new("netsh")
            .args(&[
                "advfirewall", "firewall", "add", "rule",
                &format!("name={}", rule_name),
                "dir=out",
                "action=block",
                &format!("remoteip={}", ip_address)
            ])
            .output();

        match output {
            Ok(o) => {
                if o.status.success() {
                    println!("\x1b[32m[+] SURGICAL BLOCK ACTIVE: Severed connection to {}\x1b[0m", ip_address);
                } else {
                    let err = String::from_utf8_lossy(&o.stderr);
                    println!("\x1b[31m[!] MICRO-SEGMENTATION FAILED: {}\x1b[0m", err.trim());
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
