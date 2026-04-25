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
use erdps_agent::ai_copilot::sentinel_brain::evaluate_process_behavior;

pub struct CanarySentinel;

impl CanarySentinel {
    /// 🐤 DEPLOY: Scatters hidden canary files and starts the watchtower.
    pub fn deploy() {
        println!("\x1b[35m[CANARY] 🐤 DEPLOYING ACTIVE DECEPTION TRAPS (Phase 1)...\x1b[0m");

        // Target Directory
        let base_path = Path::new("C:\\Users\\Public");

        // Irresistible Bait Names
        let bait_names = vec![
            "passwords.txt",
            "wallet.dat",
            "00_Backup_Codes.txt",
            "!_CRITICAL_FINANCE.pdf",
            "__Secret_Keys.kdbx"
        ];

        let mut active_traps = Vec::new();

        if base_path.exists() {
            for bait_name in bait_names {
                let trap_path = base_path.join(bait_name);

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

    /// Creates dummy files and sets them to hidden.
    fn plant_trap(path: &Path) -> bool { 
        let dummy_content = "This is a dummy bait file for ransomware detection.";
        if std::fs::write(path, dummy_content).is_err() {
            return false;
        }

        // Set Attributes: Hidden + System
        let path_str = path.to_string_lossy().to_string(); 
        let mut path_wide: Vec<u16> = path_str.encode_utf16().collect(); 
        path_wide.push(0); 

        unsafe { 
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

        // Configure watcher with default configuration
        let config = Config::default();

        let mut watcher: RecommendedWatcher = Watcher::new(tx, config).expect("Failed to create watcher");

        for trap in &traps {
            // We watch the PARENT directory because watching a specific file that might be deleted/renamed is flaky
            if let Some(parent) = trap.parent() {
                let _ = watcher.watch(parent, RecursiveMode::NonRecursive);
            }
        }

        println!("[CANARY] 👁️ Watchtower running... (Arming in 2 seconds)");
        let arming_time = std::time::Instant::now();

        for res in rx {
            match res {
                Ok(event) => {
                    // Grace period: Drop all filesystem events for 2 seconds to allow the agent to finish deploying honeypots
                    if arming_time.elapsed().as_secs() < 2 {
                        continue;
                    }
                    
                    // Filter: We only care if the event touches one of our TRAPS
                    for path in &event.paths {
                        for trap in &traps {
                            if path == trap {
                                match event.kind {
                                    EventKind::Modify(_) | EventKind::Remove(_) => {
                                        // 🚨 TRAP TRIGGERED!
                                        Self::trigger_failsafe(trap);
                                    },
                                    EventKind::Access(_) => {
                                        // Ignore access to prevent false positives from indexers or accidental clicks
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
            
            // 2. AI COPILOT EVALUATION (The Sentinel Genius Mind)
            let mut sys = sysinfo::System::new();
            sys.refresh_processes();
            let cmd_line = if let Some(process) = sys.process(sysinfo::Pid::from_u32(pid)) {
                process.cmd().join(" ")
            } else {
                String::from("<unknown>")
            };

            println!("[AI COPILOT] Evaluating suspicious behavior...");
            if erdps_agent::ai_copilot::sentinel_brain::evaluate_process_behavior(&process_path, &cmd_line) {
                // 3. EXECUTE LETHAL RESPONSE
                println!("[CANARY] ⚡ ENGAGING ACTIVE DEFENSE FOR PID {}...", pid);
                println!("[AI COPILOT] Verdict: BLOCK. Engaging Kill Switch.");
                
                ActiveDefense::engage_suspend(pid); // Freeze it first
                ActiveDefense::engage_network_isolation(pid, &process_path); // Cut comms
                ActiveDefense::engage_kill_switch(pid, "Canary Trap (Honeypot) Modified/Removed"); // Terminate
            } else {
                println!("[AI COPILOT] Verdict: ALLOW (Legitimate activity). Bypassing kill switch.");
            }
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
