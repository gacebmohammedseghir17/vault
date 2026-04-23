mod kernel_bridge;
mod reporter;
mod ml_engine;
// mod unpack_engine; // REMOVED
mod semantic_engine;
mod behavioral_engine;
mod active_defense; // Active Defense Module
mod disassembly_engine; // Deep Forensics Engine
// mod memory_scanner; // Phase 9: Memory Hunter
#[cfg(feature = "network-monitoring")]
mod network_sentinel; // Phase 10: Network Sentinel
mod local_cortex; // Phase 11: DeepSeek Integration
mod rootkit_hunter; // Phase 12: Rootkit Hunter
mod entropy_engine; // Phase 13: AVX2 Entropy
mod dns_hunter; // Phase 14: DNS Hunter
mod canary_sentinel; // Phase 16: Canary Sentinel
mod behavior;
mod persistence_hunter; // Phase 17: Persistence Hunter
mod hook_hunter; // Phase 18: Hook Hunter
mod io_hunter;
mod yara_forge; // Phase 19: Yara Forge
mod yara_engine; // Yara Engine (Connected to Forge)
pub mod forensic; // Phase 1: Deep PE Analysis & Simulated Cloud Threat Intel
mod forensic_shell; // Import the new shell module
mod ml_ngram; // ML N-Gram Engine
mod model_hashes;
mod supply_chain;
mod graph_engine;
mod shadow_ai;
// mod pipeline; // Multi-Layer Forensic Pipeline (Moved to Lib)
pub mod live_hunter; // New Live Hunter Module
// mod memory_scanner; // Phase 9: Memory Hunter (Moved to Lib)

use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::path::Path;

pub static SENTINEL_UI_ACTIVE: AtomicBool = AtomicBool::new(false);

use std::time::Duration;
use erdps_agent::network::etw_hunter::EtwNetworkHunter;
use erdps_agent::ghost_hunter;

// --- OPTIMIZATION: High-Performance Allocator ---
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

const VERSION: &str = "6.5";
const MODE_LABEL: &str = "MAXIMUM ENTROPY ANALYSIS";

fn main() {
    print_banner();

    // Auto-Recovery on Boot
    std::process::Command::new("cmd.exe")
        .args(["/c", "netsh advfirewall firewall delete rule name=\"ERDPS_ISOLATION\""])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok();
    
    std::process::Command::new("cmd.exe") 
        .args(["/c", "rmdir", "C:\\ERDPS_Rollback"]) 
        .stdout(std::process::Stdio::null()) 
        .stderr(std::process::Stdio::null()) 
        .spawn() 
        .ok();

    // Live Threat Intel Update
    println!("[*] Syncing Threat Intel...");
    match crate::live_hunter::fetch_active_groups() {
        Ok(groups) => {
            crate::yara_forge::generate_rules(&groups);
            println!("[+] Intel Updated: Tracking {} active groups.", groups.len());
        },
        Err(_) => println!("[!] Intel Sync Skipped (Offline).")
    }

    // 1. INITIALIZE AI ENGINE (SINGLE LOAD)
    println!("[*] INITIALIZING NEURAL ENGINE (V6 Architecture)..."); 

    shadow_ai::start_background_monitor();
    
    // 1. Load Static Brain (Existing)
    // Note: ml_ngram::NgramEngine is used by ForensicPipeline internally. 
    // To optimize, we should pass an Arc<NgramEngine> to ForensicPipeline, but ForensicPipeline creates its own.
    // However, main.rs also initializes ml_engine::NeuralEngine (which wraps LightGBM/ONNX).
    // Let's stick to the user's request: Pass the main engine to shell.
    
    // 2. Load Behavioral Brain (NEW)
    let behavioral_rels = [
        "optimized_models/behavioral_model_quantized_optimized.onnx",
        "behavioral_model_quantized.onnx",
        "behavioral_model.onnx",
    ];
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()));
    let mut base_dirs: Vec<std::path::PathBuf> = vec![std::path::PathBuf::from(".")];
    if let Some(dir) = exe_dir {
        let mut cur = dir;
        for _ in 0..5 {
            base_dirs.push(cur.clone());
            if let Some(parent) = cur.parent() {
                cur = parent.to_path_buf();
            } else {
                break;
            }
        }
    }
    let behavioral_path = behavioral_rels
        .iter()
        .flat_map(|rel| base_dirs.iter().map(move |base| base.join(rel)))
        .find(|p| p.exists())
        .unwrap_or_else(|| std::path::PathBuf::from("behavioral_model.onnx"));
    let behavioral_path = behavioral_path.to_string_lossy().to_string();
    println!("[*] Loading Behavioral AI (LSTM)...");
    let behavioral_engine = match behavioral_engine::BehavioralSentinel::new(behavioral_path.as_str()) {
        Ok(engine) => {
            println!("\x1b[32m[+] BEHAVIORAL AI LOADED: Ready for Time-Series Analysis.\x1b[0m");
            Some(engine)
        },
        Err(e) => {
            println!("\x1b[31m[!] WARNING: Could not load Behavioral AI: {}\x1b[0m", e);
            None
        }
    };
    
    // Initialize Main Neural Engine (LightGBM/ONNX)
    let mut engine_instance = ml_engine::NeuralEngine::new();
    engine_instance.init();
    let engine = Arc::new(engine_instance); 
    
    println!("[+] AI MODELS LOADED: READY."); 

    // 2. CONNECT TO KERNEL (Background Thread) 
    // We pass the engine to the bridge, but we don't block main thread if driver fails. 
    kernel_bridge::start_kernel_listener(engine.clone()); 

    // 3. MAIN MENU 
    loop { 
        std::process::Command::new("cmd").args(["/c", "cls"]).status().ok();
        
        SENTINEL_UI_ACTIVE.store(false, Ordering::SeqCst);
        std::env::set_var("SENTINEL_UI_ACTIVE", "false");
        
        print_dashboard();
        
        println!("\nSELECT OPERATION MODE:"); 
        println!("[1] START SENTINEL (Autonomous Active Defense)"); 
        println!("[2] FORENSIC TOOLKIT (Manual CLI Shell)"); 
        println!("[3] Exit"); 
        println!("[4] LIFT QUARANTINE & CLEANUP ROLLBACK"); 
        println!("[5] LOAD KERNEL DRIVER");
        println!("[6] UNLOAD KERNEL DRIVER");
        
        print!("\nChoice > "); 
        io::stdout().flush().unwrap(); 

        let mut input = String::new(); 
        io::stdin().read_line(&mut input).unwrap(); 

        match input.trim() { 
            "1" => { 
                SENTINEL_UI_ACTIVE.store(true, Ordering::SeqCst);
                std::env::set_var("SENTINEL_UI_ACTIVE", "true");
                println!("[***] SENTINEL AI: ONLINE [***]"); 
                
                // --- CANARY DEPLOYMENT ---
                // Phase 1: Deploy hidden files to trap ransomware
                canary_sentinel::CanarySentinel::deploy();
                io_hunter::IoHunter::start();
                crate::behavior::start_behavior_monitor();
                
                // --- GHOST HUNTING ---
                // Scan for hardware breakpoints (VEH evasion)
                std::thread::spawn(|| {
                    loop {
                        // Scan for hardware breakpoints
                        let _ = ghost_hunter::GhostHunter::scan_system();
                        std::thread::sleep(std::time::Duration::from_secs(5));
                    }
                });

                // --- STARGATE (API HOOK HUNTING) ---
                // Scan for Inline Hooks in ntdll.dll
                std::thread::spawn(|| {
                    loop {
                        hook_hunter::HookHunter::scan_system();
                        std::thread::sleep(std::time::Duration::from_secs(15));
                    }
                });

                // --- SURICATA (ETW NETWORK HUNTER) ---
                // Native Windows Network Tracing (No Npcap)
                EtwNetworkHunter::start_hunter();
                
                // --- OPTIMIZATION: CPU Pinning ---
                // Pin Sentinel thread to the last available core to avoid context switching
                if let Some(core_ids) = core_affinity::get_core_ids() {
                    if let Some(last_core) = core_ids.last() {
                        core_affinity::set_for_current(*last_core);
                        println!("[+] CPU Affinity: Pinned to Core {:?}", last_core.id);
                    }
                }

                #[cfg(feature = "network-monitoring")]
                network_sentinel::NetSentinel::start_monitor();
                #[cfg(not(feature = "network-monitoring"))]
                println!("[!] Network Sentinel disabled (feature: network-monitoring).");
                
                println!("\n\x1b[32;1m[ Press ENTER to safely stop Sentinel and return to Main Menu ]\x1b[0m");
                std::io::stdin().read_line(&mut String::new()).unwrap();
                println!("[*] Stopping Sentinel and returning to menu...");
                
                SENTINEL_UI_ACTIVE.store(false, Ordering::SeqCst);
                std::env::set_var("SENTINEL_UI_ACTIVE", "false");
                continue;
            },  
            "2" => { 
                // [FORENSIC SHELL]
                // Pass the EXISTING engine to avoid double loading
                // Note: forensic_shell::run expects Arc<erdps_agent::ml_engine::NeuralEngine>
                // We need to make sure the types match. Since main.rs uses `mod ml_engine`, 
                // and forensic_shell uses `erdps_agent::ml_engine`, they are technically distinct types 
                // if main.rs is compiled as a bin and erdps_agent as a lib.
                // However, forensic_shell is IN main.rs (mod forensic_shell).
                // So we can pass the local Arc.
                
                forensic_shell::run(engine.clone());
            }, 
            "3" => {
                println!("Exiting...");
                std::process::exit(0);
            }, 
            "4" => {
                println!("[*] Attempting to lift Network Quarantine & Cleanup Rollback...");
                let result = std::process::Command::new("cmd.exe")
                    .args(["/c", "netsh advfirewall firewall delete rule name=\"ERDPS_ISOLATION\""])
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .ok();
                
                std::process::Command::new("cmd.exe") 
                    .args(["/c", "rmdir", "C:\\ERDPS_Rollback"]) 
                    .stdout(std::process::Stdio::null()) 
                    .stderr(std::process::Stdio::null()) 
                    .spawn() 
                    .ok(); 

                match result {
                    Some(_) => println!("\x1b[32;1m[+] Network Restored. Rollback Mount Cleaned.\x1b[0m"),
                    None => println!("\x1b[31;1m[!] Failed to execute command.\x1b[0m"),
                }
            },
            "5" => {
                println!("[*] Attempting to load Kernel Driver...");
                let result = std::process::Command::new("cmd.exe")
                    .args(["/c", "fltmc load ERDPS_Sentinel"])
                    .status();
                
                match result {
                    Ok(status) if status.success() => println!("\x1b[32;1m[+] Kernel Driver Loaded Successfully.\x1b[0m"),
                    _ => println!("\x1b[31;1m[!] Failed to load Kernel Driver. (Are you running as Administrator?)\x1b[0m"),
                }
            },
            "6" => {
                println!("[*] Attempting to unload Kernel Driver...");
                let result = std::process::Command::new("cmd.exe")
                    .args(["/c", "fltmc unload ERDPS_Sentinel"])
                    .status();
                
                match result {
                    Ok(status) if status.success() => println!("\x1b[32;1m[+] Kernel Driver Unloaded Successfully.\x1b[0m"),
                    _ => println!("\x1b[31;1m[!] Failed to unload Kernel Driver. (Are you running as Administrator?)\x1b[0m"),
                }
            },
            _ => println!("[!] Invalid selection."), 
        } 
    } 
} 

fn print_dashboard() {
    let driver_check = std::process::Command::new("cmd.exe")
        .args(["/c", "fltmc | findstr ERDPS_Sentinel"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    let driver_status = match driver_check {
        Ok(status) if status.success() => "\x1b[32;1mLOADED (Active Defense ON)\x1b[0m",
        _ => "\x1b[31;1mOFFLINE\x1b[0m",
    };

    let network_check = std::process::Command::new("cmd.exe")
        .args(["/c", "ping -n 1 8.8.8.8"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    let network_status = match network_check {
        Ok(status) if status.success() => "\x1b[32;1mSECURE (Connected)\x1b[0m",
        _ => "\x1b[31;1mQUARANTINED (Host Isolated)\x1b[0m",
    };

    println!("\n=== [ ERDPS SYSTEM STATUS ] ===");
    println!("[+] KERNEL DRIVER:   {}", driver_status);
    println!("[+] NETWORK STATE:   {}", network_status);
    println!("===============================");
} 
fn print_banner() { 
    println!(r#" 
    ███████╗██████╗ ██████╗ ██████╗ ███████╗ 
    ██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔════╝ 
    █████╗  ██████╔╝██║  ██║██████╔╝███████╗ 
    ██╔══╝  ██╔══██╗██║  ██║██╔═══╝ ╚════██║ 
    ███████╗██║  ██║██████╔╝██║     ███████║ 
    ╚══════╝╚═╝  ╚═╝╚═════╝ ╚═╝     ╚══════╝ 
    "#); 
    println!("=== ENTERPRISE RANSOMWARE DEFENSE & PROTECTION SYSTEM ==="); 
    println!("--=[ Version {} ({}) ]\n", VERSION, MODE_LABEL); 
} 
