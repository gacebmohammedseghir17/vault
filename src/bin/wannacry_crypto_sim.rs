//! Benign Threat Simulator: WannaCry Crypto
//! Academic EDR Telemetry Validation
//! DOES NOT CONTAIN REAL MALWARE OR ENCRYPTION.

use std::env;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;

fn get_temp_dir() -> PathBuf {
    let mut temp = env::temp_dir();
    temp.push("edr_sim_wannacry");
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
    println!(" ACADEMIC SIMULATOR: WannaCry Crypto-Ransomware");
    println!("==================================================");

    let temp_dir = get_temp_dir();

    // 1. Rapidly create 100 .txt files
    println!("[*] Creating 100 dummy .txt files in %TEMP%...");
    for i in 0..100 {
        let file_path = temp_dir.join(format!("wannacry_file_{}.txt", i));
        if let Ok(mut file) = File::create(&file_path) {
            let _ = file.write_all(b"Dummy academic test data.");
        }
    }

    // 2. Rename them to .WCRY
    println!("[*] Mass-renaming files to .WCRY...");
    for i in 0..100 {
        let old_path = temp_dir.join(format!("wannacry_file_{}.txt", i));
        let new_path = temp_dir.join(format!("wannacry_file_{}.WCRY", i));
        let _ = fs::rename(&old_path, &new_path);
    }

    // 3. Attempt to read Canary
    println!("[*] Attempting to access EDR Canary file...");
    let canary_path = "C:\\Users\\Public\\passwords.txt";
    match File::open(canary_path) {
        Ok(mut f) => {
            let mut buf = String::new();
            let _ = f.read_to_string(&mut buf);
            println!("[+] Successfully read Canary file (EDR failed to block).");
        }
        Err(e) => println!("[-] Failed to read Canary (Expected if EDR blocks): {}", e),
    }
    
    println!("[+] WannaCry simulation complete.");
}