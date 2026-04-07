use sysinfo::{System, Pid};
use winapi::um::sysinfoapi::{GetSystemInfo, SYSTEM_INFO};
use winapi::um::memoryapi::{VirtualQueryEx, ReadProcessMemory};
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::winnt::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_READ};
use winapi::shared::minwindef::{LPCVOID, LPVOID};
use std::ptr::null_mut;
use crate::pipeline::ForensicPipeline;
use colored::*;

pub struct MemoryHunter;

impl MemoryHunter {
    // 🕵️ COMMAND: memscan
    pub fn scan_process(pid: u32, pipeline: &mut ForensicPipeline) {
        println!("{}", format!("[MEMORY] Scanning PID: {} for Injected Code...", pid).bright_cyan());

        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
            if handle.is_null() { 
                println!("[!] Failed to open process. Access Denied?");
                return; 
            }

            let mut sys_info: SYSTEM_INFO = std::mem::zeroed();
            GetSystemInfo(&mut sys_info);

            let mut address = sys_info.lpMinimumApplicationAddress;
            let max_address = sys_info.lpMaximumApplicationAddress;
            let mut found_threats = 0;

            while address < max_address {
                let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
                let size = VirtualQueryEx(
                    handle,
                    address,
                    &mut mbi,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                );

                if size == 0 { break; }

                // FILTER: Look for Executable Memory (RWX or RX) that is Committed
                if mbi.State == MEM_COMMIT && 
                   (mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_READ) {
                    
                    let region_size = mbi.RegionSize;
                    let mut buffer = vec![0u8; region_size];
                    let mut bytes_read = 0;

                    let success = ReadProcessMemory(
                        handle,
                        mbi.BaseAddress,
                        buffer.as_mut_ptr() as LPVOID,
                        region_size,
                        &mut bytes_read
                    );

                    if success != 0 && bytes_read > 0 {
                        // ANALYZE WITH GOD MODE PIPELINE
                        // We give it a fake name like "PID_1234_Mem_0x7FFF..."
                        let name = format!("PID_{}_Mem_0x{:X}", pid, mbi.BaseAddress as usize);
                        
                        if let Ok(ctx) = pipeline.analyze_buffer(&buffer[..bytes_read], &name) {
                            if ctx.verdict == "MALICIOUS" {
                                println!("{}", format!("\n[!] THREAT DETECTED IN MEMORY AT 0x{:X}", mbi.BaseAddress as usize).red().bold());
                                println!("    -> Entropy:    {:.4}", ctx.entropy);
                                println!("    -> Neural:     {:.4}", ctx.ml_score);
                                println!("    -> YARA:       {:?}", ctx.yara_matches);
                                found_threats += 1;
                            }
                        }
                    }
                }

                address = (mbi.BaseAddress as usize + mbi.RegionSize) as LPVOID;
            }
            
            winapi::um::handleapi::CloseHandle(handle);
            
            if found_threats == 0 {
                println!("{}", "[+] Memory Scan Clean.".green());
            } else {
                println!("{}", format!("[!] Found {} malicious memory regions!", found_threats).red().bold());
            }
        }
    }
}
