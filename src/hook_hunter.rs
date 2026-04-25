use std::fs::File;
use std::io::Read;
use std::path::Path;
use memmap2::Mmap;
use goblin::pe::PE;
use winapi::um::processthreadsapi::{OpenProcess, GetCurrentProcessId};
use winapi::um::memoryapi::ReadProcessMemory;
use winapi::um::winnt::{PROCESS_VM_READ, PROCESS_QUERY_INFORMATION};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::psapi::{EnumProcessModules, GetModuleBaseNameA};
use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS};
use winapi::shared::minwindef::{HMODULE, DWORD};
use std::ptr::null_mut;
use std::ffi::CStr;
use crate::active_defense::ActiveDefense;
use crate::reporter;

pub struct HookHunter;

impl HookHunter {
    /// 🎣 STARGATE: Scans all processes for Inline API Hooks in ntdll.dll
    pub fn scan_system() {
        // 1. Map Clean ntdll.dll from Disk (ONCE)
        let disk_path = "C:\\Windows\\System32\\ntdll.dll";
        let file = match File::open(disk_path) {
            Ok(f) => f,
            Err(_) => return, 
        };
        
        let mmap = unsafe { 
            match Mmap::map(&file) {
                Ok(m) => m,
                Err(_) => return,
            }
        };

        // 2. Parse Clean PE Headers (Goblin)
        let pe = match PE::parse(&mmap) {
            Ok(p) => p,
            Err(_) => return,
        };

        // 3. Iterate Processes
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snapshot == INVALID_HANDLE_VALUE { return; }

            let mut entry: PROCESSENTRY32 = std::mem::zeroed();
            entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

            if Process32First(snapshot, &mut entry) != 0 {
                let my_pid = GetCurrentProcessId();
                loop {
                    let pid = entry.th32ProcessID;
                    if pid != my_pid && pid > 4 { 
                        Self::check_pid(pid, &pe, &mmap);
                    }
                    if Process32Next(snapshot, &mut entry) == 0 { break; }
                }
            }
            CloseHandle(snapshot);
        }
    }

    /// Internal check for a specific PID using the pre-loaded clean DLL
    fn check_pid(pid: u32, pe: &PE, mmap: &Mmap) {
        // Get Remote Module Base
        let remote_base = match Self::get_remote_module_base(pid, "ntdll.dll") {
            Some(addr) => addr,
            None => return, 
        };

        let handle = unsafe { OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, pid) };
        if handle.is_null() { return; }

        let critical_apis = vec![
            "NtWriteVirtualMemory",
            "NtProtectVirtualMemory",
            "NtAllocateVirtualMemory",
            "NtCreateThreadEx",
            "NtMapViewOfSection",
            "NtQueueApcThread",
            "NtSetContextThread"
        ];

        for api_name in critical_apis {
            if let Some(export) = pe.exports.iter().find(|e| e.name.unwrap_or("") == api_name) {
                let rva = export.rva;
                let file_offset = export.offset.unwrap_or(0);
                if file_offset == 0 || file_offset + 32 > mmap.len() { continue; }

                let clean_bytes = &mmap[file_offset..file_offset + 32];
                let mut dirty_bytes = [0u8; 32];
                let mut bytes_read = 0;
                let remote_addr = (remote_base as u64 + rva as u64) as *mut _;

                let success = unsafe {
                    ReadProcessMemory(
                        handle,
                        remote_addr,
                        dirty_bytes.as_mut_ptr() as *mut _,
                        32,
                        &mut bytes_read
                    )
                };

                if success != 0 && bytes_read == 32 {
                    // HEURISTIC: Check for Inline Hook (JMP 0xE9)
                    if dirty_bytes[0] == 0xE9 && clean_bytes[0] != 0xE9 {
                        println!("\x1b[41;37m[STARGATE] 🎣 DETECTED INLINE HOOK in PID: {}\x1b[0m", pid);
                        println!("\x1b[31m   |-> API: {} (Tampered)\x1b[0m", api_name);
                        println!("\x1b[31m   |-> Disk: {:02X} {:02X} {:02X}...\x1b[0m", clean_bytes[0], clean_bytes[1], clean_bytes[2]);
                        println!("\x1b[31m   |-> Mem : {:02X} {:02X} {:02X}... (JMP Detected)\x1b[0m", dirty_bytes[0], dirty_bytes[1], dirty_bytes[2]);
                        
                        println!("\x1b[31m[STARGATE] ⚡ EVASION DETECTED. NEUTRALIZING THREAT.\x1b[0m");
                        ActiveDefense::engage_kill_switch(pid, "API Hooking Detected (Evasion)");
                        reporter::log_alert(pid, "Unknown", 0, "ntdll.dll");
                        break; 
                    }
                }
            }
        }
        unsafe { CloseHandle(handle) };
    }

    fn get_remote_module_base(pid: u32, module_name: &str) -> Option<usize> {
        unsafe {
            let handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, pid);
            if handle.is_null() { return None; }

            let mut modules = [null_mut(); 1024];
            let mut cb_needed = 0;

            if EnumProcessModules(handle, modules.as_mut_ptr(), std::mem::size_of_val(&modules) as u32, &mut cb_needed) != 0 {
                let count = cb_needed as usize / std::mem::size_of::<HMODULE>();
                for i in 0..count {
                    let mut name_buf = [0i8; 64];
                    if GetModuleBaseNameA(handle, modules[i], name_buf.as_mut_ptr(), 64) != 0 {
                        let name = CStr::from_ptr(name_buf.as_ptr()).to_string_lossy();
                        if name.eq_ignore_ascii_case(module_name) {
                            CloseHandle(handle);
                            return Some(modules[i] as usize);
                        }
                    }
                }
            }
            CloseHandle(handle);
        }
        None
    }
}
