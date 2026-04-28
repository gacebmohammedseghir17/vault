//! Threat: REvil RaaS Dropper
//! DOES NOT CONTAIN REAL MALWARE OR ENCRYPTION.

use std::process::Command;
use std::os::windows::process::CommandExt;
use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use rand::Rng;

const CREATE_NO_WINDOW: u32 = 0x08000000;

fn get_temp_dir() -> PathBuf {
    let mut temp = env::temp_dir();
    temp.push("win_service_cache");
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
    println!(" [+] REvil RaaS Payload Executing...");
    println!("==================================================");

    println!("[*] Injecting loader into memory...");
    println!("[*] Executing PowerShell to drop secondary payload...");

    // Spawn a hidden child instance of cmd.exe that runs powershell.exe
    match Command::new("cmd")
        .args(&[
            "/C",
            "powershell.exe",
            "-ExecutionPolicy",
            "Bypass",
            "-WindowStyle",
            "Hidden",
            "-Command",
            "Write-Host 'Payload Injected'"
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .spawn() {
        Ok(mut child) => {
            println!("[+] Secondary payload active.");
            std::thread::sleep(std::time::Duration::from_secs(5));
            let _ = child.wait();
        },
        Err(_) => println!("[-] Failed to initialize component."),
    }

    let temp_dir = get_temp_dir();
    let mut rng = rand::thread_rng();

    println!("[*] Encrypting local files...");
    for i in 0..50 {
        let file_path = temp_dir.join(format!("diag_{}.tmp", i));
        if let Ok(mut file) = File::create(&file_path) {
            let mut buffer = vec![0u8; 500 * 1024]; // 500KB
            rng.fill(&mut buffer[..]);
            let _ = file.write_all(&buffer);
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    
    println!("[*] Appending .revil extensions...");
    for i in 0..50 {
        let old_path = temp_dir.join(format!("diag_{}.tmp", i));
        let new_path = temp_dir.join(format!("diag_{}.revil", i));
        let _ = fs::rename(&old_path, &new_path);
    }

    println!("[+] Target system encrypted.");
    
    // Sustained Execution (The Cryo-Stasis Target)
    std::thread::sleep(std::time::Duration::from_secs(20));
}