//! Benign Threat Simulator: DarkSide Doxware
//! Academic EDR Telemetry Validation
//! DOES NOT CONTAIN REAL MALWARE OR ENCRYPTION.

use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::net::TcpStream;
use std::path::PathBuf;

fn get_temp_dir() -> PathBuf {
    let mut temp = env::temp_dir();
    temp.push("edr_sim_darkside");
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
    println!(" ACADEMIC SIMULATOR: DarkSide Doxware (Data-Theft)");
    println!("==================================================");

    let temp_dir = get_temp_dir();

    println!("[*] Creating and exfiltrating 50 dummy files...");
    for i in 0..50 {
        let file_path = temp_dir.join(format!("darkside_file_{}.txt", i));
        if let Ok(mut file) = File::create(&file_path) {
            let _ = file.write_all(b"Confidential academic data for DarkSide simulation.");
        }
        
        // Exfil: Benign HTTP GET request
        if let Ok(mut stream) = TcpStream::connect("127.0.0.1:9999") {
            let request = format!("GET /simulated_exfil_darkside?file={} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", i);
            let _ = stream.write_all(request.as_bytes());
        }
    }

    println!("[*] Mass-renaming files to .darkside...");
    for i in 0..50 {
        let old_path = temp_dir.join(format!("darkside_file_{}.txt", i));
        let new_path = temp_dir.join(format!("darkside_file_{}.darkside", i));
        let _ = fs::rename(&old_path, &new_path);
    }
    
    println!("[+] DarkSide Doxware simulation complete.");
}