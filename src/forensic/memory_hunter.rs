use std::ffi::c_void;
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
use windows::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READWRITE};
use windows::Win32::Foundation::{CloseHandle, HANDLE};

pub fn scan_process_memory(pid: u32) -> Option<String> {
    unsafe {
        let handle = match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) {
            Ok(h) => h,
            Err(_) => return None,
        };

        let mut current_address = 0 as *const c_void;
        let mut mbi = std::mem::zeroed::<MEMORY_BASIC_INFORMATION>();
        let mut found_rwx = false;

        while VirtualQueryEx(
            handle,
            Some(current_address),
            &mut mbi,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        ) > 0
        {
            if mbi.Protect == PAGE_EXECUTE_READWRITE {
                found_rwx = true;
                break;
            }
            
            let next_addr = (mbi.BaseAddress as usize + mbi.RegionSize) as *const c_void;
            // Prevent infinite loop if overflow occurs
            if next_addr <= current_address {
                break;
            }
            current_address = next_addr;
        }

        let _ = CloseHandle(handle);

        if found_rwx {
            Some(format!("\x1b[31m[CRITICAL] Unbacked RWX memory detected in PID {}. Highly indicative of Process Injection/Shellcode!\x1b[0m", pid))
        } else {
            Some(format!("\x1b[32m[+] Memory scan complete for PID {}. No RWX pages found. Memory appears clean.\x1b[0m", pid))
        }
    }
}