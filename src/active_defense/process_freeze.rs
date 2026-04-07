use std::ffi::CString;
use winapi::shared::minwindef::FALSE;
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::winnt::{PROCESS_SUSPEND_RESUME, HANDLE};
use winapi::um::handleapi::CloseHandle;
use console::style;

// Native API Function Signatures (Undocumented Windows APIs)
type NtSuspendProcess = unsafe extern "system" fn(process_handle: HANDLE) -> i32;
type NtResumeProcess = unsafe extern "system" fn(process_handle: HANDLE) -> i32;

pub struct ProcessFreezer;

impl ProcessFreezer {
    /// FREEZE: Atomically suspends all threads in the target process.
    /// Uses NtSuspendProcess (Native API) to bypass standard user-mode hooks.
    pub fn freeze(pid: u32) {
        println!("[*] Initiating CRYO-STASIS on PID: {}...", pid);

        unsafe {
            // 1. Get Handle to ntdll.dll (The core Windows Kernel Interface)
            let ntdll_name = CString::new("ntdll.dll").unwrap();
            let ntdll_handle = GetModuleHandleA(ntdll_name.as_ptr());

            if ntdll_handle.is_null() {
                println!("{}", style("[!] CRITICAL: Failed to load ntdll.dll").red().bold());
                return;
            }

            // 2. Load the undocumented 'NtSuspendProcess' function
            let func_name = CString::new("NtSuspendProcess").unwrap();
            let func_ptr = GetProcAddress(ntdll_handle, func_name.as_ptr());

            if func_ptr.is_null() {
                println!("{}", style("[!] ERROR: Could not find NtSuspendProcess entry point.").red());
                return;
            }

            // 3. Transmute the pointer to a callable function
            let nt_suspend_process: NtSuspendProcess = std::mem::transmute(func_ptr);

            // 4. Open the Target Process
            let process_handle = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
            
            if process_handle.is_null() {
                println!("{}", style("[!] ACCESS DENIED: Cannot open target process.").red());
                return;
            }

            // 5. EXECUTE FREEZE
            let status = nt_suspend_process(process_handle);
            CloseHandle(process_handle);

            if status == 0 { // STATUS_SUCCESS
                println!("{}", style(format!("[+] TARGET FROZEN (PID: {}). Execution halted.", pid)).green().bold());
                println!("{}", style("    -> Threads: SUSPENDED").green());
                println!("{}", style("    -> Network: SILENT").green());
                println!("{}", style("    -> Watchdogs: BLOCKED").green());
            } else {
                println!("{}", style(format!("[!] FREEZE FAILED with NTSTATUS: {}", status)).red());
            }
        }
    }

    /// RESUME: Thaws the process (useful for forensics or if false positive).
    pub fn resume(pid: u32) {
        println!("[*] Thawing process PID: {}...", pid);

        unsafe {
            let ntdll_name = CString::new("ntdll.dll").unwrap();
            let ntdll_handle = GetModuleHandleA(ntdll_name.as_ptr());
            let func_name = CString::new("NtResumeProcess").unwrap();
            let func_ptr = GetProcAddress(ntdll_handle, func_name.as_ptr());

            if func_ptr.is_null() { return; }

            let nt_resume_process: NtResumeProcess = std::mem::transmute(func_ptr);
            let process_handle = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);

            if process_handle.is_null() {
                println!("{}", style("[!] Failed to open process.").red());
                return;
            }

            let status = nt_resume_process(process_handle);
            CloseHandle(process_handle);

            if status == 0 {
                println!("{}", style("[+] TARGET RESUMED. Execution continuing.").green().bold());
            } else {
                println!("{}", style("[!] RESUME FAILED.").red());
            }
        }
    }
}
