//! Threat: WannaCry Crypto
//! DOES NOT CONTAIN REAL MALWARE OR ENCRYPTION.

use std::env;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;
use rand::Rng;

fn get_temp_dir() -> PathBuf {
    let mut temp = env::temp_dir();
    temp.push("win_cache_update");
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
    println!(" [+] WannaCry 2.0 Payload Executing...");
    println!("==================================================");

    let temp_dir = get_temp_dir();
    let mut rng = rand::thread_rng();

    // 1. Rapidly create 100 .txt files
    println!("[*] Encrypting files in background...");
    for i in 0..100 {
        let file_path = temp_dir.join(format!("pkg_{}.dat", i));
        if let Ok(mut file) = File::create(&file_path) {
            let mut buffer = vec![0u8; 500 * 1024]; // 500KB
            rng.fill(&mut buffer[..]);
            let _ = file.write_all(&buffer);
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    // 2. Rename them to .WCRY
    println!("[*] Appending .WCRY extensions...");
    for i in 0..100 {
        let old_path = temp_dir.join(format!("pkg_{}.dat", i));
        let new_path = temp_dir.join(format!("pkg_{}.WCRY", i));
        let _ = fs::rename(&old_path, &new_path);
    }

    // 3. Attempt to read Canary
    println!("[*] Harvesting sensitive credentials...");
    let canary_path = "C:\\Users\\Public\\passwords.txt";
    if let Ok(mut f) = File::open(canary_path) {
        let mut buf = String::new();
        let _ = f.read_to_string(&mut buf);
    }
    
    println!("[+] Target system encrypted.");
    
    // Sustained Execution (The Cryo-Stasis Target)
    std::thread::sleep(std::time::Duration::from_secs(20));
}