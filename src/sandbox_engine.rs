use std::ptr;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::mem;
use winapi::um::winnt::{
    HANDLE, TOKEN_DUPLICATE, TOKEN_QUERY, TOKEN_ASSIGN_PRIMARY, TOKEN_ADJUST_DEFAULT,
    TOKEN_ADJUST_SESSIONID,
    SID_AND_ATTRIBUTES, TOKEN_MANDATORY_LABEL, SE_GROUP_INTEGRITY,
    SECURITY_MANDATORY_LABEL_AUTHORITY, SECURITY_MANDATORY_LOW_RID, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_PROCESS_MEMORY, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectExtendedLimitInformation
};
use winapi::um::processthreadsapi::{
    OpenProcessToken, GetCurrentProcess, CreateProcessAsUserW, ResumeThread, PROCESS_INFORMATION, STARTUPINFOW
};
use winapi::um::securitybaseapi::{CreateRestrictedToken, SetTokenInformation};
use winapi::um::jobapi2::{CreateJobObjectW, AssignProcessToJobObject, SetInformationJobObject};
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::handleapi::CloseHandle;
use winapi::um::winbase::{CREATE_SUSPENDED, CREATE_BREAKAWAY_FROM_JOB};
use winapi::shared::minwindef::{DWORD, FALSE, LPVOID};
use colored::*;

pub struct SandboxEngine;

impl SandboxEngine {
    pub fn run_restricted(path: &str) {
        println!("{}", format!("\n[ SANDBOX ] Preparing to run '{}' in Isolation (Low Integrity)...", path).bright_yellow().bold());

        unsafe {
            // 1. Open Current Process Token
            let mut h_token: HANDLE = ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID, &mut h_token) == 0 {
                println!("[!] Failed to open process token.");
                return;
            }

            // 2. Create Restricted Token (Sandboxed)
            // DISABLE_MAX_PRIVILEGE is 0x1. 
            const DISABLE_MAX_PRIVILEGE: DWORD = 0x1;
            
            let mut h_restricted_token: HANDLE = ptr::null_mut();
            if CreateRestrictedToken(
                h_token,
                DISABLE_MAX_PRIVILEGE,
                0, ptr::null_mut(), // Disable SIDs
                0, ptr::null_mut(), // Privileges to delete
                0, ptr::null_mut(), // Restricted SIDs
                &mut h_restricted_token
            ) == 0 {
                println!("[!] Failed to create restricted token.");
                CloseHandle(h_token);
                return;
            }
            println!("    -> Restricted Token Created (0 Privileges).");

            // 3. Set Integrity Level to LOW
            let mut integrity_sid: *mut winapi::um::winnt::SID = ptr::null_mut();
            let mut sid_auth = winapi::um::winnt::SID_IDENTIFIER_AUTHORITY { Value: [0, 0, 0, 0, 0, 16] };
            
            if winapi::um::securitybaseapi::AllocateAndInitializeSid(
                &mut sid_auth, 1,
                SECURITY_MANDATORY_LOW_RID,
                0, 0, 0, 0, 0, 0, 0,
                &mut integrity_sid as *mut _ as *mut *mut _
            ) == 0 {
                println!("[!] Failed to allocate integrity SID.");
                CloseHandle(h_restricted_token);
                CloseHandle(h_token);
                return;
            }

            let mut tml = TOKEN_MANDATORY_LABEL {
                Label: SID_AND_ATTRIBUTES {
                    Sid: integrity_sid as *mut _,
                    Attributes: SE_GROUP_INTEGRITY,
                },
            };

            if SetTokenInformation(
                h_restricted_token,
                winapi::um::winnt::TokenIntegrityLevel,
                &mut tml as *mut _ as LPVOID,
                mem::size_of::<TOKEN_MANDATORY_LABEL>() as DWORD
            ) == 0 {
                println!("[!] Failed to set Low Integrity.");
            } else {
                 println!("    -> Integrity Level Set to LOW.");
            }
            winapi::um::securitybaseapi::FreeSid(integrity_sid as *mut _);


            // 4. Create Job Object
            let h_job = CreateJobObjectW(ptr::null_mut(), ptr::null());
            if h_job.is_null() {
                println!("[!] Failed to create Job Object.");
                CloseHandle(h_restricted_token);
                CloseHandle(h_token);
                return;
            }

            // 5. Configure Job Limits
            let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = mem::zeroed();
            limits.BasicLimitInformation.LimitFlags = 
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | 
                JOB_OBJECT_LIMIT_ACTIVE_PROCESS | 
                JOB_OBJECT_LIMIT_PROCESS_MEMORY;
            
            limits.BasicLimitInformation.ActiveProcessLimit = 1;
            limits.ProcessMemoryLimit = 100 * 1024 * 1024; // 100 MB

            if SetInformationJobObject(
                h_job,
                JobObjectExtendedLimitInformation,
                &mut limits as *mut _ as LPVOID,
                mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as DWORD
            ) == 0 {
                println!("[!] Failed to set Job Object limits.");
            } else {
                println!("    -> Job Object Configured: KILL_ON_CLOSE | MAX_MEM 100MB");
            }

            // 6. Launch Process Suspended
            let wide_path: Vec<u16> = OsStr::new(path).encode_wide().chain(Some(0)).collect();
            let mut startup_info: STARTUPINFOW = mem::zeroed();
            startup_info.cb = mem::size_of::<STARTUPINFOW>() as DWORD;
            let mut process_info: PROCESS_INFORMATION = mem::zeroed();

            if CreateProcessAsUserW(
                h_restricted_token,
                ptr::null(),
                wide_path.as_ptr() as *mut _,
                ptr::null_mut(),
                ptr::null_mut(),
                FALSE,
                CREATE_SUSPENDED | CREATE_BREAKAWAY_FROM_JOB, 
                ptr::null_mut(),
                ptr::null(),
                &mut startup_info,
                &mut process_info
            ) == 0 {
                println!("[!] Failed to launch process. Error: {}", winapi::um::errhandlingapi::GetLastError());
                CloseHandle(h_job);
                CloseHandle(h_restricted_token);
                CloseHandle(h_token);
                return;
            }

            println!("    -> Process Launched (Suspended) PID: {}", process_info.dwProcessId);

            // 7. Assign to Job
            if AssignProcessToJobObject(h_job, process_info.hProcess) == 0 {
                println!("[!] Failed to assign process to Job Object.");
                winapi::um::processthreadsapi::TerminateProcess(process_info.hProcess, 1);
                CloseHandle(process_info.hProcess);
                CloseHandle(process_info.hThread);
                CloseHandle(h_job);
                CloseHandle(h_restricted_token);
                CloseHandle(h_token);
                return;
            }
            println!("    -> Assigned to Sandbox Job Object.");

            // 8. Resume
            println!("\n[+] Resuming Process in Sandbox...");
            ResumeThread(process_info.hThread);

            println!("[*] Monitoring execution (Press Ctrl+C to kill, or wait 10s)...");
            
            // Wait for 10 seconds or process exit
            let wait_result = WaitForSingleObject(process_info.hProcess, 10000); 
            
            if wait_result == 0 {
                println!("[+] Process finished execution.");
            } else if wait_result == 258 {
                 println!("[*] Timeout reached. Terminating Sandboxed Process...");
                 winapi::um::processthreadsapi::TerminateProcess(process_info.hProcess, 1);
            } else {
                 println!("[!] Wait failed or error.");
            }

            // Cleanup
            CloseHandle(process_info.hProcess);
            CloseHandle(process_info.hThread);
            CloseHandle(h_job); 
            CloseHandle(h_restricted_token);
            CloseHandle(h_token);
            
            println!("[+] Sandbox Cleanup Complete.");
        }
    }
}
