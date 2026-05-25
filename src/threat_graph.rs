use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

pub fn execute_guillotine(pid: u32) {
    println!("\x1b[41;37m[CRITICAL] USER-MODE DETECTION -> TERMINATING PID {}\x1b[0m", pid);
    
    // Call the rollback logic to clean up any files written before the block
    crate::micro_rollback::trigger_micro_rollback(pid);

    unsafe {
        match OpenProcess(PROCESS_TERMINATE, false, pid) {
            Ok(handle) => {
                if let Err(e) = TerminateProcess(handle, 1) {
                    let err_code = e.code().0 & 0xFFFF;
                    println!("\x1b[31m[!] Failed to TerminateProcess for PID {}. Error Code: {}\x1b[0m", pid, err_code);
                    if err_code == 5 {
                        println!("\x1b[31;1m[!] ACCESS DENIED: Ransomware has injected into a system-protected process or escalated privileges above the EDR!\x1b[0m");
                    }
                }
                let _ = CloseHandle(handle);
            }
            Err(e) => {
                let err_code = e.code().0 & 0xFFFF;
                println!("\x1b[31m[!] Failed to OpenProcess for PID {}. Error Code: {}\x1b[0m", pid, err_code);
                if err_code == 5 {
                    println!("\x1b[31;1m[!] ACCESS DENIED: Ransomware has injected into a system-protected process or escalated privileges above the EDR!\x1b[0m");
                }
            }
        }
    }
}
