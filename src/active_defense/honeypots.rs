use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::thread;
use notify::{Watcher, RecursiveMode, RecommendedWatcher, Config};
use console::style;
use crate::active_defense::process_freeze::ProcessFreezer;
use sysinfo::System;

pub struct Minefield;

impl Minefield {
    /// DEPLOY: Places bait files and starts the Real-Time Watcher
    pub fn deploy() {
        println!("{}", style("[*] DEPLOYING MINEFIELD (Deception Layer)...").cyan());

        // 1. Define Bait Locations (User Profile is best, but using C:\Temp for safety in demo)
        let bait_dir = "C:\\ERDPS_Honey";
        if !Path::new(bait_dir).exists() {
            let _ = fs::create_dir(bait_dir);
        }

        // 2. Create Attractive Bait Files
        let baits = [
            ("passwords.xlsx", "List of server passwords..."),
            ("financial_Q4.docx", "Confidential Budget Data..."),
            ("private_keys.pem", "-----BEGIN RSA PRIVATE KEY-----"),
        ];

        for (name, content) in baits.iter() {
            let p = Path::new(bait_dir).join(name);
            if let Ok(mut f) = File::create(&p) {
                let _ = f.write_all(content.as_bytes());
                println!("    -> Planted Bait: {:?}", p);
            }
        }

        println!("{}", style("[*] ARMING TRIPWIRES...").red().blink());

        // 3. Spawn the Watcher Thread (Non-Blocking)
        thread::spawn(move || {
            let (tx, rx) = std::sync::mpsc::channel();
            
            // Use notify 5.x+ API
            let mut watcher: RecommendedWatcher = match Watcher::new(tx, Config::default()) {
                Ok(w) => w,
                Err(e) => {
                    println!("Error creating watcher: {:?}", e);
                    return;
                }
            };

            // Watch the Honey Folder
            if watcher.watch(Path::new(bait_dir), RecursiveMode::NonRecursive).is_ok() {
                loop {
                    match rx.recv() {
                        Ok(Ok(event)) => {
                            println!("{}", style("\n[!!!] TRIPWIRE TRIGGERED! Deception file touched!").red().bold().blink());
                            println!("      Event: {:?}", event);
                            
                            handle_explosion();
                        },
                        Ok(Err(e)) => println!("watch error: {:?}", e),
                        Err(e) => println!("channel error: {:?}", e),
                    }
                }
            }
        });
    }
}

fn handle_explosion() {
    println!("{}", style("[!] ACTIVE DEFENSE PROTOCOL INITIATED").red().bold());
    
    // In a kernel driver, we'd know exactly WHO touched the file.
    // In User Mode, we must be aggressive.
    // STRATEGY: Find the process with highest I/O right now (likely the ransomware)
    
    let mut sys = System::new_all();
    sys.refresh_processes();
    
    let mut suspect_pid = 0;
    let mut max_io = 0;

    for (pid, process) in sys.processes() {
        let io = process.disk_usage().written_bytes; // Heuristic assumption
        if io > max_io {
            max_io = io;
            suspect_pid = pid.as_u32();
        }
    }

    if suspect_pid != 0 {
        println!("{}", style(format!("    -> IDENTIFIED LIKELY AGGRESSOR: PID {}", suspect_pid)).yellow());
        ProcessFreezer::freeze(suspect_pid);
        println!("{}", style("    -> HOSTILE NEUTRALIZED via Trap.").green().bold());
    }
}
