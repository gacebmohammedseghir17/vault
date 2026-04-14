//! Benign Threat Simulator: REvil RaaS Dropper
//! Academic EDR Telemetry Validation
//! DOES NOT CONTAIN REAL MALWARE OR ENCRYPTION.

use std::process::Command;
use std::os::windows::process::CommandExt;

const CREATE_NO_WINDOW: u32 = 0x08000000;

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
    println!(" ACADEMIC SIMULATOR: REvil RaaS Loader/Dropper");
    println!("==================================================");

    println!("[*] Simulating stealthy dropper injection...");
    println!("[*] Spawning hidden cmd.exe -> powershell.exe...");

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
            "Write-Host 'REvil Payload Dropped'"
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .spawn() {
        Ok(child) => println!("[+] Spawned hidden dropper PID: {}", child.id()),
        Err(e) => println!("[-] Failed to spawn dropper: {}", e),
    }

    println!("[+] REvil RaaS Loader simulation complete.");
}