//! Benign Threat Simulator for Academic EDR Validation
//! This tool generates Indicators of Compromise (IoCs) to test EDR telemetry.
//! It DOES NOT contain real malware or encryption algorithms.
//! All actions are confined to %TEMP% or explicitly designated honeypot files.

use std::env;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::Command;
use std::os::windows::process::CommandExt;

const CREATE_NO_WINDOW: u32 = 0x08000000;

fn main() {
    println!("==================================================");
    println!(" ACADEMIC EDR THREAT SIMULATOR (BENIGN IoC GENERATOR)");
    println!("==================================================");

    let args: Vec<String> = env::args().collect();
    let mut mode = String::new();

    for i in 0..args.len() {
        if args[i] == "--mode" && i + 1 < args.len() {
            mode = args[i + 1].clone();
        }
    }

    if mode.is_empty() {
        println!("Usage: threat_sim.exe --mode <crypto|locker|doxware|double-extortion|raas>");
        return;
    }

    match mode.as_str() {
        "crypto" => simulate_crypto(),
        "locker" => simulate_locker(),
        "doxware" => simulate_doxware(),
        "double-extortion" => simulate_double_extortion(),
        "raas" => simulate_raas(),
        _ => println!("Unknown mode: {}", mode),
    }
}

fn get_temp_dir() -> PathBuf {
    let mut temp = env::temp_dir();
    temp.push("edr_sim_test");
    // Ensure the test directory exists
    let _ = fs::create_dir_all(&temp);
    temp
}

fn simulate_crypto() {
    println!("[*] Starting Crypto-Ransomware Simulation...");
    let temp_dir = get_temp_dir();

    // 1. Rapidly create 100 .txt files
    println!("[*] Creating 100 dummy .txt files in %TEMP%...");
    for i in 0..100 {
        let file_path = temp_dir.join(format!("sim_file_{}.txt", i));
        if let Ok(mut file) = File::create(&file_path) {
            let _ = file.write_all(b"Dummy academic test data.");
        }
    }

    // 2. Rename them to .locked
    println!("[*] Mass-renaming files to .locked...");
    for i in 0..100 {
        let old_path = temp_dir.join(format!("sim_file_{}.txt", i));
        let new_path = temp_dir.join(format!("sim_file_{}.locked", i));
        let _ = fs::rename(&old_path, &new_path);
    }

    // 3. Attempt to read Canary
    println!("[*] Attempting to access EDR Canary file...");
    let canary_path = "C:\\Users\\Public\\passwords.txt";
    match File::open(canary_path) {
        Ok(mut f) => {
            let mut buf = String::new();
            let _ = f.read_to_string(&mut buf);
            println!("[+] Successfully read Canary file.");
        }
        Err(e) => println!("[-] Failed to read Canary (Expected if EDR blocks): {}", e),
    }
    println!("[+] Crypto simulation complete.");
}

fn simulate_locker() {
    println!("[*] Starting Locker-Ransomware Simulation...");
    
    // 1. Execute vssadmin
    println!("[*] Executing vssadmin delete shadows /all /quiet...");
    let _ = Command::new("cmd")
        .args(&["/C", "vssadmin", "delete", "shadows", "/all", "/quiet"])
        .output();
    
    // 2. Drop Ransom Note
    let user_profile = env::var("USERPROFILE").unwrap_or_else(|_| "C:\\Users\\Public".to_string());
    let mut desktop = PathBuf::from(user_profile);
    desktop.push("Desktop");
    let note_path = desktop.join("README_RECOVER.txt");
    
    println!("[*] Dropping Ransom Note to: {:?}", note_path);
    if let Ok(mut file) = File::create(&note_path) {
        let _ = file.write_all(b"This is a simulated ransomware note for academic EDR testing.\nYour files have NOT been encrypted.");
    }
    println!("[+] Locker simulation complete.");
}

fn simulate_doxware() {
    println!("[*] Starting Doxware Simulation...");
    let temp_dir = get_temp_dir();

    println!("[*] Creating and exfiltrating 50 files...");
    for i in 0..50 {
        let file_path = temp_dir.join(format!("dox_file_{}.txt", i));
        if let Ok(mut file) = File::create(&file_path) {
            let _ = file.write_all(b"Confidential academic data.");
        }
        
        // Exfil: Benign HTTP GET request
        if let Ok(mut stream) = TcpStream::connect("127.0.0.1:9999") {
            let request = format!("GET /simulated_exfil?file={} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", i);
            let _ = stream.write_all(request.as_bytes());
        }
    }

    println!("[*] Mass-renaming files to .locked...");
    for i in 0..50 {
        let old_path = temp_dir.join(format!("dox_file_{}.txt", i));
        let new_path = temp_dir.join(format!("dox_file_{}.locked", i));
        let _ = fs::rename(&old_path, &new_path);
    }
    println!("[+] Doxware simulation complete.");
}

fn simulate_double_extortion() {
    println!("[*] Starting Advanced Double Extortion Simulation...");
    simulate_locker();
    simulate_doxware();
    
    println!("[*] Attempting to access EDR Canary file...");
    let canary_path = "C:\\Users\\Public\\passwords.txt";
    let _ = File::open(canary_path);
    
    println!("[+] Double Extortion simulation complete.");
}

fn simulate_raas() {
    println!("[*] Starting RaaS Loader Simulation...");
    if let Ok(exe_path) = env::current_exe() {
        println!("[*] Spawning hidden child process: {:?}", exe_path);
        
        // Use CREATE_NO_WINDOW to hide the console window, simulating a stealthy dropper
        match Command::new(&exe_path)
            .arg("--mode")
            .arg("crypto")
            .creation_flags(CREATE_NO_WINDOW)
            .spawn() {
            Ok(child) => println!("[+] Spawned hidden child PID: {}", child.id()),
            Err(e) => println!("[-] Failed to spawn child: {}", e),
        }
    }
    println!("[+] RaaS Loader simulation complete.");
}
