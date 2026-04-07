use std::io::{self, Write};
use std::sync::Arc;
use erdps_agent::pipeline::ForensicPipeline;
// FIX: Use crate::ml_engine instead of erdps_agent::ml_engine to match main.rs type
use crate::ml_engine::NeuralEngine;
use erdps_agent::structs::ScanReport;
use erdps_agent::intel_manager::IntelManager;
use erdps_agent::dfir_triage::DfirTriage; // Import new module
use sysinfo::System;
use colored::*;
use std::thread;
use std::sync::mpsc;
use std::time::Duration;

// Updated Signature: Reuse existing engine
pub fn run(engine: Arc<NeuralEngine>) {
    println!("\x1b[36m=== ERDPS FORENSIC SHELL ({}: MLFP ACTIVE) ===\x1b[0m", crate::MODE_LABEL);
    
    // ASYNC PIPELINE INITIALIZATION
    // Note: ForensicPipeline internally creates its own NgramEngine. 
    // Ideally we would pass 'engine' to it, but for now we optimize the shell loading experience.
    println!("Status: Initializing Multi-Layer Forensic Pipeline (Background)...");
    let (tx, rx) = mpsc::channel();
    
    thread::spawn(move || {
        // This still loads a fresh NgramEngine for the pipeline (which is lightweight compared to the main one)
        // Optimizing this would require refactoring ForensicPipeline to accept an Arc<NgramEngine>
        let pipeline = ForensicPipeline::new();
        let _ = tx.send(pipeline);
    });

    // Show spinner while loading - WITHOUT Hard Timeout
    // We wait until the channel disconnects or sends data
    let spinner = vec!['|', '/', '-', '\\'];
    let mut i = 0;
    
    // Blocking wait with visual feedback
    // recv() blocks, so we use try_recv in a loop to animate
    let mut pipeline_opt = None;
    
    loop {
        match rx.try_recv() {
            Ok(p) => {
                pipeline_opt = Some(p);
                break;
            },
            Err(mpsc::TryRecvError::Empty) => {
                print!("\r[*] Loading Engines... {}", spinner[i % 4]);
                io::stdout().flush().unwrap();
                thread::sleep(Duration::from_millis(100));
                i += 1;
            },
            Err(mpsc::TryRecvError::Disconnected) => {
                println!("\n[!] Pipeline thread disconnected unexpectedly.");
                break;
            }
        }
    }
    
    let mut pipeline = match pipeline_opt {
        Some(p) => {
            println!("\r[+] Engines Loaded.                                  ");
            p
        },
        None => {
            println!("\r[!] Engine Initialization Failed. Falling back to minimal pipeline.");
            ForensicPipeline::new()
        }
    };
    
    println!("(+) Live Intelligence Layer: \x1b[32mACTIVE\x1b[0m");
    println!("Status: Ready. Type 'scan <file>' or 'help'.");

    loop {
        print!("\n\x1b[1mERDPS > \x1b[0m");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        let input = input.trim();
        let parts: Vec<&str> = input.split_whitespace().collect();

        if parts.is_empty() { continue; }

        match parts[0] {
            "help" => {
                println!("  scan <file>    : Analyze file (Report saved to reports/)");
                println!("  timeline <min> : Generate forensic timeline from USN Journal");
                println!("  ls / dir       : List current directory");
                println!("  pwd            : Show current working directory");
                println!("  cd <path>      : Change directory");
                println!("  compile rules  : Compile Local YARA Rules");
                println!("  reload         : Reload Pipeline & Rules");
                println!("  exit           : Exit");
            },
            "ls" | "dir" => {
                 match std::fs::read_dir(".") {
                     Ok(entries) => {
                         println!("\n{:<10} {:<30}", "TYPE", "NAME");
                         println!("{:-<10} {:-<30}", "", "");
                         for entry in entries {
                             if let Ok(entry) = entry {
                                 let path = entry.path();
                                 let name = path.file_name().unwrap_or_default().to_string_lossy();
                                 let is_dir = path.is_dir();
                                 let type_str = if is_dir { "<DIR>" } else { "     " };
                                 let color_name = if is_dir { name.blue() } else { name.white() };
                                 println!("{:<10} {}", type_str, color_name);
                             }
                         }
                         println!();
                     },
                     Err(e) => println!("[!] Failed to list directory: {}", e),
                 }
            },
            "pwd" => {
                match std::env::current_dir() {
                    Ok(path) => println!("[*] Current Directory: {}", path.display()),
                    Err(e) => println!("[!] Failed to get current directory: {}", e),
                }
            },
            "cd" => {
                if parts.len() < 2 {
                    println!("[!] Usage: cd <path>");
                    continue;
                }
                let new_path = std::path::Path::new(parts[1]);
                match std::env::set_current_dir(&new_path) {
                    Ok(_) => {
                         if let Ok(cwd) = std::env::current_dir() {
                             println!("[+] Changed directory to: {}", cwd.display());
                         }
                    },
                    Err(e) => println!("[!] Failed to change directory: {}", e),
                }
            },
            "timeline" => {
                if parts.len() < 2 {
                    println!("[!] Usage: timeline <minutes> (e.g., timeline 5)");
                    continue;
                }
                if let Ok(minutes) = parts[1].parse::<u64>() {
                    println!("[*] Parsing NTFS USN Journal for last {} minutes...", minutes);
                    let events = DfirTriage::generate_timeline(minutes);
                    if events.is_empty() {
                        println!("[-] No events found or failed to read journal (Run as Admin).");
                    } else {
                        println!("\n{:<10} {:<50} {:<20}", "TIME", "FILENAME", "ACTION");
                        println!("{:-<10} {:-<50} {:-<20}", "", "", "");
                        for event in events {
                            // Truncate filename if too long
                            let fname = if event.filename.len() > 48 {
                                format!("...{}", &event.filename[event.filename.len()-45..])
                            } else {
                                event.filename.clone()
                            };
                            
                            let color = if event.reason.contains("RENAME") { "\x1b[33m" } // Yellow
                                        else if event.reason.contains("DELETE") { "\x1b[31m" } // Red
                                        else { "\x1b[32m" }; // Green
                            
                            println!("{:<10} {:<50} {}{:<20}\x1b[0m", event.timestamp, fname, color, event.reason);
                        }
                    }
                } else {
                    println!("[!] Invalid minutes.");
                }
            },
            "reload" => {
                println!("[*] Reloading Engine...");
                // Reload in background with spinner
                let (tx, rx) = mpsc::channel();
                thread::spawn(move || {
                    let pipeline = ForensicPipeline::new();
                    let _ = tx.send(pipeline);
                });
                
                let mut i = 0;
                loop {
                    match rx.try_recv() {
                        Ok(p) => {
                            pipeline = p;
                            println!("\r[+] Engine Reloaded.                 ");
                            break;
                        },
                        Err(mpsc::TryRecvError::Empty) => {
                            print!("\r[*] Reloading... {}", spinner[i % 4]);
                            io::stdout().flush().unwrap();
                            thread::sleep(Duration::from_millis(100));
                            i += 1;
                        },
                        Err(mpsc::TryRecvError::Disconnected) => {
                            println!("\r[!] Reload Failed. Keeping current engine.");
                            break;
                        }
                    }
                }
            },
            "compile" => {
                if parts.len() > 1 && parts[1] == "rules" {
                    // Run compile in background
                    println!("[*] Compiling rules in background...");
                    thread::spawn(|| {
                        IntelManager::compile_local_rules();
                    }).join().unwrap();
                } else {
                    println!("[!] Usage: compile rules");
                }
            },
            "scan" => {
                if parts.len() < 2 {
                    println!("[!] Usage: scan <file_path>");
                    continue;
                }
                let target = parts[1];
                
                // Helper: Resolve path if not found
                let path_obj = std::path::Path::new(target);
                let resolved_target = if !path_obj.exists() {
                     // Try relative to current dir? Already handled by OS.
                     // Try to guess?
                     if target == "erdps-agent.exe" {
                         "target/release/erdps-agent.exe"
                     } else {
                         target
                     }
                } else {
                    target
                };

                if !std::path::Path::new(resolved_target).exists() {
                     println!("[!] File not found: {}", resolved_target);
                     if let Ok(cwd) = std::env::current_dir() {
                         println!("    Current Directory: {}", cwd.display());
                         println!("    Tip: Use 'ls' to see files or 'cd' to change directory.");
                     }
                     continue;
                }

                println!("\n[ GOD MODE ANALYSIS STARTED ]");
                println!("Target: {}", resolved_target);

                // --- REPORTING START ---
                let mut report = ScanReport::new(resolved_target);

                match pipeline.analyze_file(resolved_target, &mut report) {
                    Ok(ctx) => {
                        println!("Size:    {} bytes", ctx.file_size);
                        println!("Imphash: {}", ctx.imphash);
                        println!("Compiler: {}", ctx.compiler);
                        
                        println!("\n---------------- LAYERS ----------------");
                        println!("1. Entropy:    {:.4} (Threshold: 7.2)", ctx.entropy);
                        println!("2. Heuristics: Found {} stack strings", ctx.stack_strings.len());
                        println!("3. Complexity: {} (Cyclomatic)", ctx.cyclomatic_complexity);
                        
                        println!("4. YARA:       {} matches", ctx.yara_matches.len());
                        for rule in &ctx.yara_matches {
                            println!("   -> Rule: {}", rule.yellow());
                        }

                        println!("5. Neural:     {:.4} (Malicious Probability)", ctx.ml_score);
                        
                        println!("\n[ CAPABILITIES DETECTED ]");
                        if ctx.capabilities.is_empty() {
                            println!("(None detected)");
                        } else {
                            for cap in &ctx.capabilities {
                                let display_text = if cap.contains("INJECTION") || cap.contains("Ransomware") {
                                    cap.red().bold()
                                } else {
                                    cap.yellow()
                                };
                                println!("[!] {}", display_text);
                            }
                        }

                        println!("\n--------------- VERDICT ----------------");
                        let color = if ctx.verdict == "MALICIOUS" { "\x1b[31m" }
                                    else if ctx.verdict == "SUSPICIOUS" { "\x1b[33m" }
                                    else { "\x1b[32m" };    
                        println!("Result: {}{}\x1b[0m", color, ctx.verdict);
                        println!("----------------------------------------");

                        // --- REPORTING END ---
                        // Finalize Report Verdicts based on Context
                        report.verdict = ctx.verdict;
                        report.risk_score = (ctx.ml_score * 100.0) as u8;
                        
                        // 4. Save Evidence (Dual Format)
                        // Save JSON
                        match report.save_json() {
                            Ok(path) => println!("[+] Evidence (JSON) Saved: {}", path.cyan()),
                            Err(e) => println!("[!] Failed to save JSON: {}", e.to_string().red()),
                        }

                        // Save HTML (New)
                        match report.save_html() {
                            Ok(path) => println!("[+] Evidence (HTML) Saved: {}", path.yellow()),
                            Err(e) => println!("[!] Failed to save HTML: {}", e.to_string().red()),
                        }
                    },
                    Err(e) => println!("[!] Analysis Failed: {}", e),
                }
            },
            "exit" => break,
            "cls" | "clear" => print!("\x1b[2J\x1b[1;1H"),
            _ => println!("[!] Unknown command."),
        }
    }
}
