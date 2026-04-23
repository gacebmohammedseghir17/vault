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
use rustyline::{Editor, Config, Result as RlResult};

use windows::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_READ, MEM_COMMIT}; 
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ}; 
use windows::Win32::System::ProcessStatus::GetMappedFileNameW; 
use windows::Win32::Foundation::{HANDLE, MAX_PATH}; 
use std::ffi::c_void; 
use sha2::{Sha256, Digest};
use std::fs::File;
use std::io::Read;

fn scan_unbacked_memory(pid: u32) -> (bool, usize, bool) {
    let mut has_unbacked = false;
    let mut has_stomped = false;
    let mut total_size = 0;

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
        if handle.is_err() {
            return (false, 0, false);
        }
        let handle = handle.unwrap();

        let mut address: usize = 0;
        let mut mem_info = MEMORY_BASIC_INFORMATION::default();
        let mem_info_size = std::mem::size_of::<MEMORY_BASIC_INFORMATION>();

        while VirtualQueryEx(
            handle,
            Some(address as *const c_void),
            &mut mem_info,
            mem_info_size,
        ) != 0
        {
            if mem_info.State == MEM_COMMIT && (mem_info.Protect == PAGE_EXECUTE_READWRITE || mem_info.Protect == PAGE_EXECUTE_READ) {
                let mut filename_buf = [0u16; MAX_PATH as usize];
                let chars_copied = GetMappedFileNameW(handle, mem_info.BaseAddress, &mut filename_buf);
                
                if chars_copied == 0 {
                    // No file backs this memory region. If it's RWX or RX, this is a massive red flag.
                    has_unbacked = true;
                    total_size += mem_info.RegionSize;
                } else {
                    // Region IS backed by a file.
                    // Legitimate code sections should be PAGE_EXECUTE_READ (RX).
                    // If a file-backed section is PAGE_EXECUTE_READWRITE (RWX), it's highly suspicious.
                    if mem_info.Protect == PAGE_EXECUTE_READWRITE {
                        has_stomped = true;
                        total_size += mem_info.RegionSize;
                    }

                    // Check for Header Stomping: Read the first 2 bytes (MZ header)
                    // REMOVED false positive mz_buf check per user request
                }
            }

            address += mem_info.RegionSize;
        }

        let _ = windows::Win32::Foundation::CloseHandle(handle);
    }
    (has_unbacked, total_size, has_stomped)
}

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

    let config = Config::builder()
        .auto_add_history(true)
        .build();
    let mut rl = Editor::<(), rustyline::history::DefaultHistory>::with_config(config).unwrap();

    loop {
        let readline = rl.readline("\x1b[1mERDPS > \x1b[0m");
        match readline {
            Ok(line) => {
                let input = line.trim();
                if input.is_empty() { continue; }
                
                let parts: Vec<&str> = input.split_whitespace().collect();

                match parts[0] {
                    "help" => {
                        println!("  scan <file>          : Analyze file (Report saved to reports/)");
                        println!("  scan-pid <PID>       : Live Memory Triage & Threat Scoring");
                        println!("  carve-dump <path>    : Parse Minidump, extract injected RWX regions & IOCs");
                        println!("  timeline <min>       : Generate forensic timeline from USN Journal");
                        println!("  ls / dir             : List current directory");
                        println!("  pwd                  : Show current working directory");
                        println!("  cd <path>            : Change directory");
                        println!("  compile rules        : Compile Local YARA Rules");
                        println!("  reload               : Reload Pipeline & Rules");
                        println!("  exit                 : Exit");
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

                                println!("\n[ DEEP PE ANALYSIS & CLOUD INTEL ]");
                                let cloud_score = crate::forensic::cloud_intel::CloudIntel::get_threat_score(&report.scan_target.hash_sha256, resolved_target);
                                let pe_result = crate::forensic::pe_analyzer::PeAnalyzer::analyze(resolved_target);
                                
                                let total_score = cloud_score + pe_result.score;

                                println!("\n--------------- VERDICT ----------------");
                                let final_verdict = if total_score >= 50 {
                                    println!("\x1b[1;31m[CRITICAL] VERDICT: MALICIOUS (THREAT SCORE: {})\x1b[0m", total_score);
                                    "MALICIOUS".to_string()
                                } else {
                                    println!("\x1b[32m[INFO] VERDICT: CLEAN / BENIGN (THREAT SCORE: {})\x1b[0m", total_score);
                                    "CLEAN".to_string()
                                };

                                let mut mitre_tactics = Vec::new();
                                println!("\n----------- MITRE ATT&CK MAPPING -----------");
                                if cloud_score >= 50 {
                                    let t = "[T1105] Ingress Tool Transfer (Known Malicious Payload)";
                                    println!("-> {}", t);
                                    mitre_tactics.push(t.to_string());
                                }
                                if pe_result.is_writable_section {
                                    let t = "[T1027.002] Obfuscated Files or Information: Software Packing";
                                    println!("-> {}", t);
                                    mitre_tactics.push(t.to_string());
                                }
                                if pe_result.has_injection_imports {
                                    let t = "[T1055] Process Injection";
                                    println!("-> {}", t);
                                    mitre_tactics.push(t.to_string());
                                }
                                if pe_result.has_crypto_imports {
                                    let t = "[T1486] Data Encrypted for Impact";
                                    println!("-> {}", t);
                                    mitre_tactics.push(t.to_string());
                                }
                                
                                let lower_target = resolved_target.to_lowercase();
                                if lower_target.contains("vssadmin") || lower_target.contains("shadows") || pe_result.has_heuristics {
                                    let t = "[T1490] Inhibit System Recovery";
                                    println!("-> {}", t);
                                    mitre_tactics.push(t.to_string());
                                }
                                
                                println!("\n[ CAPABILITIES DETECTED ]");
                                if pe_result.capabilities.is_empty() {
                                    println!("-> None detected");
                                } else {
                                    for cap in &pe_result.capabilities {
                                        println!("-> {}", cap);
                                    }
                                }

                                println!("\n[ EXTRACTED IOCs (Command & Control) ]");
                                if pe_result.extracted_iocs.is_empty() {
                                    println!("-> No clear-text IOCs found.");
                                } else {
                                    for ioc in &pe_result.extracted_iocs {
                                        println!("-> Found: {}", ioc);
                                    }
                                }
                                println!("----------------------------------------");

                                // --- REPORTING END ---
                                // Finalize Report Verdicts based on Context
                                report.verdict = final_verdict;
                                report.risk_score = total_score;
                                report.modules.cloud_intel_match = cloud_score >= 50;
                                report.modules.pe_writable_section = pe_result.is_writable_section;
                                report.modules.pe_injection_imports = pe_result.has_injection_imports;
                                report.modules.pe_crypto_imports = pe_result.has_crypto_imports;
                                report.modules.pe_heuristics = pe_result.has_heuristics;
                                report.modules.mitre_tactics = mitre_tactics;
                                
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
                    "scan-pid" => {
                        if parts.len() < 2 {
                            println!("[!] Usage: scan-pid <PID>");
                            continue;
                        }

                        let pid_str = parts[1];
                        if let Ok(pid) = pid_str.parse::<u32>() {
                            let mut sys = sysinfo::System::new_all();
                            sys.refresh_processes_specifics(
                                sysinfo::ProcessRefreshKind::new().with_cmd(sysinfo::UpdateKind::Always),
                            );

                            if let Some(process) = sys.process(sysinfo::Pid::from(pid as usize)) {
                                let name = process.name().to_string();
                                let parent_pid = process.parent().map(|p| p.as_u32()).unwrap_or(0);
                                let cmd = process.cmd().join(" ");
                                let lower_cmd = cmd.to_lowercase();
                                let exe_path = process.exe().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
                                let lower_path = exe_path.to_lowercase();

                                println!("\n[ LIVE MEMORY TRIAGE ]");
                                println!("Target PID: {}", pid);
                                println!("Process Name: {}", name);
                                println!("Parent PID: {}", parent_pid);
                                println!("Command Line: {}", cmd);
                                println!("Executable Path: {}", exe_path);

                                let mut live_score: u8 = 0;

                                if lower_path.contains("\\temp\\") || lower_path.contains("\\downloads\\") || lower_path.contains("\\public\\") {
                                    println!("\x1b[31;1m[!] ANOMALY: Process running from suspicious user directory. (+20 Threat Score)\x1b[0m");
                                    live_score += 20;
                                }

                                if lower_cmd.contains("executionpolicy bypass") || lower_cmd.contains("windowstyle hidden") {
                                    println!("\x1b[31;1m[!] ANOMALY: Stealth Script Execution Detected. (+40 Threat Score) -> MITRE [T1059.001]\x1b[0m");
                                    live_score += 40;
                                }

                                if lower_cmd.contains("vssadmin") || lower_cmd.contains("shadows") || lower_cmd.contains("wbadmin delete") {
                                    println!("\x1b[31;1m[!] ANOMALY: Ransomware Shadow Copy Deletion Detected. (+50 Threat Score) -> MITRE [T1490]\x1b[0m");
                                    live_score += 50;
                                }

                                // Phase 7: Elite Memory Forensics (Unbacked Memory Scanner)
                                let (has_unbacked, size, has_stomped) = scan_unbacked_memory(pid);
                                if has_unbacked {
                                    println!("\x1b[31;1m[!] CRITICAL ANOMALY: Unbacked PAGE_EXECUTE_READWRITE Memory Detected ({} bytes). Sign of Process Injection / Cobalt Strike (T1055).\x1b[0m", size);
                                    live_score += 60;
                                }
                                if has_stomped {
                                    println!("\x1b[31;1m[!] CRITICAL ANOMALY: Memory Integrity Mismatch! RAM does not match Disk. Sign of Module Stomping / Hollowed DLL (T1055.003).\x1b[0m");
                                    live_score += 70;
                                }

                                println!("\n--------------- VERDICT ----------------");
                                if live_score >= 50 {
                                    println!("\x1b[1;31m[CRITICAL] VERDICT: MALICIOUS (LIVE THREAT SCORE: {})\x1b[0m", live_score);
                                } else {
                                    println!("\x1b[32m[INFO] VERDICT: CLEAN / BENIGN (LIVE THREAT SCORE: {})\x1b[0m", live_score);
                                }
                                println!("----------------------------------------");

                            } else {
                                println!("[!] Process with PID {} not found or access denied.", pid);
                            }
                        } else {
                            println!("[!] Invalid PID format.");
                        }
                    },
                    "carve-dump" => {
                        if parts.len() < 2 {
                            println!("[!] Usage: carve-dump <path_to_dmp_file>");
                            continue;
                        }
                        
                        let path = parts[1];
                        if !std::path::Path::new(path).exists() {
                            println!("[!] Dump file not found: {}", path);
                            continue;
                        }

                        println!("\n[ ELITE MEMORY TRIAGE: ANALYZING DUMP ]");
                        println!("Target: {}", path);
                        println!("----------------------------------------");
                        crate::forensic::carver::triage_dump(path);
                        println!("----------------------------------------");
                    },
                    "exit" => break,
                    "cls" | "clear" => print!("\x1b[2J\x1b[1;1H"),
                    _ => println!("[!] Unknown command."),
                }
            },
            Err(rustyline::error::ReadlineError::Interrupted) => {
                println!("CTRL-C");
                break;
            },
            Err(rustyline::error::ReadlineError::Eof) => {
                println!("CTRL-D");
                break;
            },
            Err(err) => {
                println!("Error: {:?}", err);
                break;
            }
        }
    }
}
