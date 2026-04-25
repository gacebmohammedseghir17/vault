use sysinfo::{System, Pid};
use ntapi::ntexapi::{SystemHandleInformation, SYSTEM_HANDLE_INFORMATION, SYSTEM_HANDLE_TABLE_ENTRY_INFO, NtQuerySystemInformation};
use std::collections::{HashSet};
use std::mem::size_of;
use winapi::shared::minwindef::ULONG;
use winapi::shared::ntdef::PVOID;
use winapi::shared::ntstatus::STATUS_INFO_LENGTH_MISMATCH;

pub struct RootkitHunter;

impl RootkitHunter {
    // 🕵️ COMMAND: rootkit
    pub fn scan() {
        println!("\x1b[35m[ROOTKIT] 👁️ INITIATING CROSS-VIEW DKOM ANALYSIS...\x1b[0m");
        
        // 1. PERCEPTION (The Lie)
        // What does the OS *say* is running?
        let mut sys = System::new_all();
        sys.refresh_all();
        
        let mut visible_pids: HashSet<u32> = HashSet::new();
        for (pid, _) in sys.processes() {
            visible_pids.insert(pid.as_u32());
        }
        println!("\x1b[36m   |-- [SNAPSHOT] Found {} visible processes.\x1b[0m", visible_pids.len());

        // 2. TRUTH (The Reality)
        // We scan the Kernel Handle Table. Malware cannot hide from this
        // because the CPU needs these handles to schedule threads.
        let hidden_pids = Self::get_deep_process_list(&visible_pids);

        // 3. VERDICT
        if hidden_pids.is_empty() {
            println!("\x1b[32m[ROOTKIT] ✅ SYSTEM CLEAN. No unlinked processes detected.\x1b[0m");
        } else {
            println!("\n\x1b[41;37m[ROOTKIT] 🚨 CRITICAL: DETECTED {} HIDDEN PROCESSES (DKOM)!\x1b[0m", hidden_pids.len());
            for pid in hidden_pids {
                println!("\x1b[31m   |-> 💀 HIDDEN PID: {} (Unlinked from ActiveProcessLinks)\x1b[0m", pid);
                // AUTO-KILL (Active Defense)
                crate::active_defense::ActiveDefense::engage_kill_switch(pid, "Hidden Rootkit Process Detected (Evasion)");
            }
        }
    }

    // 🛡️ THE LOW-LEVEL MAGIC
    fn get_deep_process_list(visible: &HashSet<u32>) -> Vec<u32> {
        let mut hidden = Vec::new();
        let mut buffer_size: ULONG = 1024 * 1024; // Start with 1MB
        let mut buffer: Vec<u8> = vec![0; buffer_size as usize];
        let mut return_length: ULONG = 0;

        unsafe {
            // Brute-force query the SystemHandleInformation (Undocumented API)
            loop {
                let status = NtQuerySystemInformation(
                    SystemHandleInformation,
                    buffer.as_mut_ptr() as PVOID,
                    buffer_size,
                    &mut return_length,
                );

                if status == STATUS_INFO_LENGTH_MISMATCH {
                    buffer_size = return_length + 1024;
                    buffer.resize(buffer_size as usize, 0);
                    continue;
                } else if status >= 0 {
                    break;
                } else {
                    println!("\x1b[31m   |-> [ERROR] Failed to query Kernel Handles (Status: 0x{:x})\x1b[0m", status);
                    return vec![];
                }
            }

            // Parse the Raw Memory
            let info = buffer.as_ptr() as *const SYSTEM_HANDLE_INFORMATION;
            let count = (*info).NumberOfHandles;
            let entry_ptr = buffer.as_ptr().offset(size_of::<ULONG>() as isize) as *const SYSTEM_HANDLE_TABLE_ENTRY_INFO;
            
            let entries = std::slice::from_raw_parts(entry_ptr, count as usize);
            let mut deep_pids: HashSet<u32> = HashSet::new();

            for entry in entries {
                let pid = entry.UniqueProcessId as u32;
                deep_pids.insert(pid);
            }

            println!("\x1b[36m   |-- [DEEP SCAN] Verified {} active kernel handles.\x1b[0m", deep_pids.len());

            // Compare Truth vs Perception
            for pid in deep_pids {
                // Filter out PID 0 (Idle) and 4 (System) which are special
                if pid > 4 && !visible.contains(&pid) {
                    hidden.push(pid);
                }
            }
        }
        hidden
    }
}
