use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, THREADENTRY32, TH32CS_SNAPTHREAD,
    Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS
};
use winapi::um::processthreadsapi::{OpenThread, GetThreadContext, GetCurrentProcessId};
use winapi::um::winnt::{
    HANDLE, THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION, CONTEXT, CONTEXT_DEBUG_REGISTERS,
    CONTEXT_FULL // Sometimes needed for alignment
};
use winapi::um::handleapi::CloseHandle;
use std::mem;
use std::collections::HashSet;
use crate::active_defense::ActiveDefense;
use crate::reporter;

pub struct GhostHunter;

impl GhostHunter {
    /// 👻 GHOST HUNT: Scans all threads for hardware breakpoints (Dr0-Dr3).
    /// Returns a list of PIDs that were terminated.
    pub fn scan_system() -> Vec<u32> {
        let mut killed_pids = Vec::new();
        let my_pid = unsafe { GetCurrentProcessId() };

        // 1. Snapshot all threads
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
        if snapshot == winapi::um::handleapi::INVALID_HANDLE_VALUE {
            return killed_pids;
        }

        let mut thread_entry: THREADENTRY32 = unsafe { mem::zeroed() };
        thread_entry.dwSize = mem::size_of::<THREADENTRY32>() as u32;

        if unsafe { Thread32First(snapshot, &mut thread_entry) } == 0 {
            unsafe { CloseHandle(snapshot) };
            return killed_pids;
        }

        // Cache safe PIDs (e.g., debuggers) to avoid killing them repeatedly
        let mut safe_pids = HashSet::new();
        let mut checked_pids = HashSet::new();

        loop {
            let pid = thread_entry.th32OwnerProcessID;
            let tid = thread_entry.th32ThreadID;

            // Skip self and already killed/checked
            if pid != my_pid && !killed_pids.contains(&pid) && !safe_pids.contains(&pid) {
                
                // Optional: Whitelist check (expensive, so only do once per PID)
                if !checked_pids.contains(&pid) {
                    if Self::is_whitelisted_debugger(pid) {
                        safe_pids.insert(pid);
                        checked_pids.insert(pid);
                        continue;
                    }
                    checked_pids.insert(pid);
                }

                if !safe_pids.contains(&pid) {
                    if Self::check_thread_for_hardware_breakpoints(tid) {
                        println!("\x1b[41;37m[GHOST] 👻 Hardware Breakpoint Detected in PID: {} (TID: {})\x1b[0m", pid, tid);
                        println!("\x1b[31m[GHOST] ⚡ EVASION ATTEMPT DETECTED. ENGAGING KILL SWITCH.\x1b[0m");
                        
                        // Kill the Ghost
                        ActiveDefense::engage_kill_switch(pid, "Hardware Breakpoint Detected (Evasion)");
                        reporter::log_alert(pid, "Unknown", 0, "Hardware_Breakpoint");
                        killed_pids.push(pid);
                    }
                }
            }

            if unsafe { Thread32Next(snapshot, &mut thread_entry) } == 0 {
                break;
            }
        }

        unsafe { CloseHandle(snapshot) };
        killed_pids
    }

    /// Checks a specific thread for active Dr0-Dr3 registers
    fn check_thread_for_hardware_breakpoints(tid: u32) -> bool {
        unsafe {
            let thread_handle = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, 0, tid);
            if thread_handle.is_null() {
                return false;
            }

            // Align context structure (Critical for GetThreadContext)
            let mut context: CONTEXT = mem::zeroed();
            context.ContextFlags = CONTEXT_DEBUG_REGISTERS;

            if GetThreadContext(thread_handle, &mut context) != 0 {
                CloseHandle(thread_handle);

                // Check Debug Registers
                if context.Dr0 != 0 || context.Dr1 != 0 || context.Dr2 != 0 || context.Dr3 != 0 {
                    // Hardware breakpoint is ACTIVE
                    return true;
                }
            } else {
                CloseHandle(thread_handle);
            }
        }
        false
    }

    /// Whitelist legitimate debuggers (Visual Studio, Windbg, x64dbg)
    /// We don't want to kill the developer's tools.
    fn is_whitelisted_debugger(pid: u32) -> bool {
        let name = Self::get_process_name(pid).to_lowercase();
        matches!(name.as_str(), 
            "devenv.exe" | 
            "windbg.exe" | 
            "x64dbg.exe" | 
            "x32dbg.exe" | 
            "qtcreator.exe" |
            "vscode.exe" | 
            "code.exe"
        )
    }

    fn get_process_name(pid: u32) -> String {
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snapshot == winapi::um::handleapi::INVALID_HANDLE_VALUE {
                return "Unknown".to_string();
            }

            let mut entry: PROCESSENTRY32 = mem::zeroed();
            entry.dwSize = mem::size_of::<PROCESSENTRY32>() as u32;

            if Process32First(snapshot, &mut entry) != 0 {
                loop {
                    if entry.th32ProcessID == pid {
                        let name = std::ffi::CStr::from_ptr(entry.szExeFile.as_ptr() as *const i8)
                            .to_string_lossy()
                            .into_owned();
                        CloseHandle(snapshot);
                        return name;
                    }
                    if Process32Next(snapshot, &mut entry) == 0 {
                        break;
                    }
                }
            }
            CloseHandle(snapshot);
        }
        "Unknown".to_string()
    }
}
