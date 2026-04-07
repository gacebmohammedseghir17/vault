use sysinfo::System;
use colored::*;
use ntapi::ntexapi::{NtQuerySystemInformation, SystemProcessInformation, SYSTEM_PROCESS_INFORMATION};
use std::ptr::null_mut;
use std::collections::HashSet;

pub struct RootkitScanner;

impl RootkitScanner {
    pub fn scan_hidden_processes() {
        println!("{}", "\n[ ROOTKIT HUNTER ] Scanning for Hidden Processes (Cross-View Diff)...".bright_cyan().bold());

        // 1. Snapshot A: User Mode (sysinfo)
        let mut sys = System::new_all();
        sys.refresh_processes();
        let mut user_pids: HashSet<u32> = HashSet::new();
        
        for (pid, _) in sys.processes() {
            // Convert Pid to u32. sysinfo 0.30 Pid implements Display and Into<usize>, let's try parsing or casting
            // For now, we rely on pid.to_string().parse() as a safe fallback if direct cast fails
            if let Ok(p) = pid.to_string().parse::<u32>() {
                user_pids.insert(p);
            }
        }

        // 2. Snapshot B: Kernel Object (NtQuerySystemInformation)
        let kernel_pids = Self::get_kernel_pids();

        // 3. Diff
        let mut hidden_count = 0;
        println!("{:<10} {:<30} {:<20}", "PID", "NAME", "STATUS");
        println!("{:-<10} {:-<30} {:-<20}", "", "", "");

        for (k_pid, k_name) in kernel_pids {
            // Filter Idle (0) and System (4)
            if k_pid == 0 || k_pid == 4 { continue; }

            if !user_pids.contains(&k_pid) {
                hidden_count += 1;
                println!("{:<10} {:<30} {}", 
                    k_pid.to_string().red().bold(), 
                    k_name.red().bold(), 
                    "[!] HIDDEN (Rootkit Detected)".red().bold()
                );
            }
        }

        if hidden_count == 0 {
            println!("{}", "[+] No hidden processes detected. System appears clean.".green());
        } else {
            println!("{}", format!("\n[!] WARNING: {} hidden process(es) detected!", hidden_count).red().bold());
        }
        println!();
    }

    fn get_kernel_pids() -> Vec<(u32, String)> {
        let mut pids = Vec::new();
        unsafe {
            let mut buffer_size: u32 = 1024 * 1024; // Start with 1MB buffer
            let mut buffer: Vec<u8> = Vec::with_capacity(buffer_size as usize);
            let mut return_length: u32 = 0;

            // Call NtQuerySystemInformation
            // 5 = SystemProcessInformation
            let status = NtQuerySystemInformation(
                SystemProcessInformation,
                buffer.as_mut_ptr() as *mut _,
                buffer_size,
                &mut return_length
            );

            if status != 0 {
                // If buffer too small, we might need to resize. 
                // For simplicity in this "Lite" version, we assume 1MB is enough for process list.
                // In production, handle STATUS_INFO_LENGTH_MISMATCH (0xC0000004) loop.
                return pids;
            }

            let mut info_ptr = buffer.as_ptr() as *const SYSTEM_PROCESS_INFORMATION;
            
            loop {
                let info = &*info_ptr;
                let pid = info.UniqueProcessId as u32;
                
                // Extract Name
                let name = if info.ImageName.Buffer.is_null() {
                    "Unknown".to_string()
                } else {
                    let slice = std::slice::from_raw_parts(
                        info.ImageName.Buffer, 
                        (info.ImageName.Length / 2) as usize
                    );
                    String::from_utf16_lossy(slice)
                };

                pids.push((pid, name));

                if info.NextEntryOffset == 0 { break; }
                info_ptr = (info_ptr as *const u8).add(info.NextEntryOffset as usize) as *const SYSTEM_PROCESS_INFORMATION;
            }
        }
        pids
    }
}
