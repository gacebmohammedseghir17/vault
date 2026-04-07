use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
use windows::Win32::Foundation::CloseHandle;
use console::style;

pub fn kill_pid(pid: u32) -> bool {
    unsafe {
        // 1. Get a Handle to the Process with "Terminate" rights
        let handle = OpenProcess(PROCESS_TERMINATE, false, pid);
        
        match handle {
            Ok(h) => {
                // 2. Execute the Kill Order
                if TerminateProcess(h, 1).is_ok() {
                    println!("{}", style(format!("    [☠️] THREAT ELIMINATED (PID: {})", pid)).red().on_white().bold());
                    let _ = CloseHandle(h);
                    return true;
                }
                let _ = CloseHandle(h);
            },
            Err(_) => println!("    [!] Failed to open process {}", pid),
        }
    }
    false
}
