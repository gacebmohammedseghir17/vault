use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use notify::{Watcher, RecursiveMode, EventKind, event::ModifyKind};
use crate::active_defense::ActiveDefense;
use crate::active_defense::process_freeze::ProcessFreezer;
use crate::canary_sentinel::CanarySentinel;

const RENAME_LIMIT: usize = 20;
const TIME_WINDOW: Duration = Duration::from_secs(3);

pub struct IoHunter {
    pid_events: Arc<Mutex<HashMap<u32, Vec<Instant>>>>,
}

impl IoHunter {
    pub fn new() -> Self {
        Self {
            pid_events: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn start() {
        println!("[+] Sentinel Mode: Initializing I/O Rate Limiting (True Mass-Write Detection)...");
        
        let hunter = Self::new();
        let pid_events = hunter.pid_events.clone();

        thread::spawn(move || {
            let (tx, rx) = std::sync::mpsc::channel();
            let mut watcher = match notify::recommended_watcher(tx) {
                Ok(w) => w,
                Err(e) => {
                    println!("[!] Failed to initialize notify watcher: {}", e);
                    return;
                }
            };

            // Watch C:\Users, C:\ and Temp to catch all drops
            let watch_paths = vec![
                PathBuf::from("C:\\Users"),
                PathBuf::from("C:\\"),
                std::env::temp_dir(),
            ];

            for watch_path in watch_paths {
                if let Err(e) = watcher.watch(&watch_path, RecursiveMode::Recursive) {
                    println!("\x1b[33m[!] I/O Hunter partially failed to watch {}: {}\x1b[0m", watch_path.display(), e);
                } else {
                    println!("[+] I/O Hunter actively monitoring: {}", watch_path.display());
                }
            }

            for res in rx {
                match res {
                    Ok(event) => {
                        // We are interested in file modifications and renames
                        match event.kind {
                            EventKind::Modify(ModifyKind::Name(_)) => {
                                // Explicitly handle Rename events
                                // Extract the new file extension/path (the new path is the last element)
                                if let Some(new_path) = event.paths.last() {
                                    if let Some(ext) = new_path.extension().and_then(|e| e.to_str()) {
                                        // If it's a known ransomware extension, we can trigger directly
                                        if ["darkside", "lockbit", "WCRY", "revil", "locked"].contains(&ext) {
                                            println!("\x1b[31;1m[CRITICAL] Extension Mutation Detected: .{ext}\x1b[0m");
                                            let pids = CanarySentinel::get_locking_processes(new_path);
                                            for pid in pids {
                                                ActiveDefense::engage_storyline_kill(pid, &format!("Extension Mutation (.{})", ext));
                                            }
                                        }
                                    }
                                    // Feed it into the check_mass_modification logic
                                    Self::handle_event(new_path, pid_events.clone());
                                }
                            }
                            EventKind::Modify(ModifyKind::Data(_)) => {
                                for path in event.paths {
                                    Self::handle_event(&path, pid_events.clone());
                                }
                            }
                            _ => {}
                        }
                    }
                    Err(e) => println!("watch error: {:?}", e),
                }
            }
        });
    }

    fn handle_event(path: &Path, pid_events: Arc<Mutex<HashMap<u32, Vec<Instant>>>>) {
        // 1. Resolve which PID is locking/modifying this file
        // Using our existing Restart Manager logic from CanarySentinel
        let pids = CanarySentinel::get_locking_processes(path);
        
        if pids.is_empty() {
            return; // Couldn't find the locking process
        }

        let now = Instant::now();
        let mut map = pid_events.lock().unwrap();

        for pid in pids {
            // Ignore our own PID or critical system PIDs if needed
            if pid == std::process::id() { continue; }

            let events = map.entry(pid).or_insert_with(Vec::new);
            
            // Clean up old events outside the time window
            events.retain(|&t| now.duration_since(t) < TIME_WINDOW);
            
            // Add new event
            events.push(now);

            // 2. Check if the rate exceeds our threshold (>20 files in <3 seconds)
            if events.len() > RENAME_LIMIT {
                println!("[!!!] MILITARY-GRADE ALERT: I/O Rate Limit Exceeded by PID {}!", pid);
                println!("      Detected >{} modifications in <{} seconds.", RENAME_LIMIT, TIME_WINDOW.as_secs());
                
                // 3. Instantly call NtSuspendProcess
                ProcessFreezer::freeze(pid);
                println!("[+] Process {} suspended instantly via NtSuspendProcess.", pid);
                
                // Optional: Get process path and engage network isolation
                if let Some(proc_path) = CanarySentinel::get_process_path(pid) {
                    ActiveDefense::engage_network_isolation(pid, &proc_path);
                }
                
                // Clear the events for this PID so we don't spam
                events.clear();
            }
        }
    }
}