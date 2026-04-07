use notify::{Watcher, RecursiveMode, EventKind, RecommendedWatcher, Config};
use std::path::{Path, PathBuf};
use std::fs::File;
use std::io::Write;
use std::sync::mpsc::channel;
use std::thread;
use std::time::Duration;
use rand::Rng;
use windows::Win32::Storage::FileSystem::{SetFileAttributesW, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_SYSTEM};
use windows::Win32::System::RestartManager::{
    RmStartSession, RmRegisterResources, RmGetList, RmEndSession, 
    RM_PROCESS_INFO
};
use windows::Win32::System::Threading::{OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
use windows::Win32::Foundation::{CloseHandle, MAX_PATH};
use windows::core::{PCWSTR, PWSTR};
use crate::active_defense::ActiveDefense;

pub struct CanarySentinel;

impl CanarySentinel {
    /// 🐤 DEPLOY: Scatters hidden canary files and starts the watchtower.
    pub fn deploy() {
        println!("\x1b[35m[CANARY] 🐤 DEPLOYING ACTIVE DECEPTION TRAPS (Phase 1)...\x1b[0m");

        let user_profile = std::env::var("USERPROFILE").unwrap_or_else(|_| "C:\\Users\\Public".to_string());
        let base_path = Path::new(&user_profile);

        // Targeted Directories (High Probability Ransomware Targets)
        let targets = vec![
            base_path.join("Documents"),
            base_path.join("Desktop"),
            base_path.join("Downloads"),
            base_path.join("Music"),
            base_path.join("Pictures"),
        ];

        // Irresistible Bait Names (Alphabetized to be hit first)
        let bait_names = vec![
            "0000_Accounting_2026.xlsx",
            "~$passwords.docx",
            "00_Backup_Codes.txt",
            "!_CRITICAL_FINANCE.pdf",
            "__Secret_Keys.kdbx"
        ];

        let mut active_traps = Vec::new();

        for dir in &targets {
            if dir.exists() {
                // Pick a random bait name
                let mut rng = rand::thread_rng();
                let bait_name = bait_names[rng.gen_range(0..bait_names.len())];
                let trap_path = dir.join(bait_name);

                if Self::plant_trap(&trap_path) {
                    active_traps.push(trap_path);
                }
            }
        }

        if active_traps.is_empty() {
            println!("\x1b[31m[CANARY] ❌ Failed to deploy any traps.\x1b[0m");
            return;
        }

        println!("\x1b[32m[CANARY] ✅ Deployed {} Hidden Traps. Tripwires Active.\x1b[0m", active_traps.len());

        // Phase 2: Start the Watchtower
        let traps_clone = active_traps.clone();
        thread::spawn(move || {
            Self::watch_traps(traps_clone);
        });
    }

    /// ELITE UPGRADE: The Tar-Pit Trap. 
    /// Creates a massive (1GB) sparse file. It takes up 0 bytes on disk, 
    /// but forces ransomware to spend minutes trying to encrypt it, 
    /// acting as a time-delay trap. 
    fn plant_trap(path: &Path) -> bool { 
        let file = match File::create(path) { 
            Ok(f) => f, 
            Err(_) => return false, 
        }; 

        // 1. Create a 1 Gigabyte File instantly using set_len 
        // To the OS and Ransomware, this is a 1GB file. 
        // To the hard drive, it takes up almost no physical space. 
        let one_gigabyte: u64 = 1024 * 1024 * 1024; 
        if file.set_len(one_gigabyte).is_err() { 
            return false; 
        } 

        // 2. Set Attributes: Hidden + System + ReadOnly (Phase 1 Requirement) 
        let path_str = path.to_string_lossy().to_string(); 
        let mut path_wide: Vec<u16> = path_str.encode_utf16().collect(); 
        path_wide.push(0); 

        unsafe { 
            // We use the Windows API to hide it from the user, but ransomware will still find it 
            let _ = SetFileAttributesW( 
                PCWSTR(path_wide.as_ptr()), 
                FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM 
            ); 
        } 

        true 
    }

    /// Phase 2: User-Mode Tripwire
    fn watch_traps(traps: Vec<PathBuf>) {
        let (tx, rx) = channel();

        // Configure watcher with a small delay to debounce events
        let config = Config::default()
            .with_poll_interval(Duration::from_millis(100));

        let mut watcher: RecommendedWatcher = Watcher::new(tx, config).expect("Failed to create watcher");

        for trap in &traps {
            // We watch the PARENT directory because watching a specific file that might be deleted/renamed is flaky
            if let Some(parent) = trap.parent() {
                let _ = watcher.watch(parent, RecursiveMode::NonRecursive);
            }
        }

        println!("[CANARY] 👁️ Watchtower running...");

        for res in rx {
            match res {
                Ok(event) => {
                    // Filter: We only care if the event touches one of our TRAPS
                    for path in &event.paths {
                        for trap in &traps {
                            if path == trap {
                                match event.kind {
                                    EventKind::Modify(_) | EventKind::Remove(_) | EventKind::Access(_) => {
                                        // 🚨 TRAP TRIGGERED!
                                        Self::trigger_failsafe(trap);
                                    },
                                    _ => {}
                                }
                            }
                        }
                    }
                },
                Err(e) => println!("[CANARY] Watch error: {:?}", e),
            }
        }
    }

    /// Phase 3: The Guillotine (Active Defense Integration)
    fn trigger_failsafe(trap_path: &Path) {
        println!("\n\x1b[41;37m[CANARY] 🚨 CRITICAL: FAILSAFE TRIGGERED on {}!\x1b[0m", trap_path.display());
        
        // 1. Identify the Attacker(s) (Who touched the file?)
        let pids = Self::get_locking_processes(trap_path);
        
        if pids.is_empty() {
            println!("[CANARY] ⚠️ Could not identify PID (File closed too fast?). System Alert Sent.");
            return;
        }

        for pid in pids {
            println!("[CANARY] 🎯 Hostile Process Identified: PID {}", pid);
            
            // Resolve the executable path for accurate firewall isolation
            let process_path = Self::get_process_path(pid).unwrap_or_else(|| "unknown_hostile.exe".to_string());
            println!("[CANARY] 📂 Process Path: {}", process_path);
            
            // 2. EXECUTE LETHAL RESPONSE
            println!("[CANARY] ⚡ ENGAGING ACTIVE DEFENSE FOR PID {}...", pid);
            
            ActiveDefense::engage_suspend(pid); // Freeze it first
            ActiveDefense::engage_network_isolation(pid, &process_path); // Cut comms
            ActiveDefense::engage_kill_switch(pid); // Terminate
        }
        
        // 3. Snapshot for recovery
        ActiveDefense::create_snapshot();
    }

    /// Uses Windows Restart Manager to find ALL processes holding a file.
    pub fn get_locking_processes(path: &Path) -> Vec<u32> {
        let mut pids = Vec::new();
        unsafe {
            let mut session_handle: u32 = 0;
            let mut session_key = [0u16; 32]; // CCH_RM_SESSION_KEY + 1
            
            // 1. Start Session
            if RmStartSession(&mut session_handle, 0, PWSTR(session_key.as_mut_ptr())).is_err() {
                return pids;
            }

            // 2. Register Resource (The File)
            let path_str = path.to_string_lossy().to_string();
            let mut path_wide: Vec<u16> = path_str.encode_utf16().collect();
            path_wide.push(0);
            let path_ptr = PCWSTR(path_wide.as_ptr());
            let resources = [path_ptr];

            if RmRegisterResources(session_handle, Some(&resources), None, None).is_err() {
                let _ = RmEndSession(session_handle);
                return pids;
            }

            // 3. Get Affected Processes
            let mut proc_info_needed: u32 = 0;
            let mut proc_count: u32 = 0;
            let mut reboot_reasons: u32 = 0;

            // First call to get count
            let _ = RmGetList(session_handle, &mut proc_info_needed, &mut proc_count, None, &mut reboot_reasons);
            
            if proc_info_needed > 0 {
                let mut processes = vec![std::mem::zeroed::<RM_PROCESS_INFO>(); proc_info_needed as usize];
                proc_count = proc_info_needed;
                
                if RmGetList(session_handle, &mut proc_info_needed, &mut proc_count, Some(processes.as_mut_ptr()), &mut reboot_reasons).is_ok() {
                    for i in 0..proc_count as usize {
                        pids.push(processes[i].Process.dwProcessId);
                    }
                }
            }

            let _ = RmEndSession(session_handle);
        }
        pids
    }

    /// Resolves the executable path of a given PID using OpenProcess and QueryFullProcessImageNameW
    pub fn get_process_path(pid: u32) -> Option<String> {
        unsafe {
            let handle = match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) {
                Ok(h) => h,
                Err(_) => return None,
            };

            let mut buffer = [0u16; MAX_PATH as usize];
            let mut size = MAX_PATH;

            let result = QueryFullProcessImageNameW(handle, windows::Win32::System::Threading::PROCESS_NAME_FORMAT(0), PWSTR(buffer.as_mut_ptr()), &mut size);
            
            let _ = CloseHandle(handle);

            if result.is_ok() {
                let path = String::from_utf16_lossy(&buffer[..size as usize]);
                Some(path)
            } else {
                None
            }
        }
    }
}
