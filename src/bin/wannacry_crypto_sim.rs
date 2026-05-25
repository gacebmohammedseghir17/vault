//! Threat: WannaCry Crypto (Stress Test)
//! DOES NOT CONTAIN REAL MALWARE. FOR EDR RATE LIMITER TESTING ONLY.

use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
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
    println!(" [+] WannaCry 2.0 Payload Executing...");
    println!("==================================================");

    let test_zone = match get_test_zone() {
        Some(path) => path,
        None => {
            println!("[-] Safety Collar: Ransomware_Test_Zone not found in Music directory. Exiting safely.");
            return;
        }
    };

    println!("[*] Target zone identified: {:?}", test_zone);

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
            new_path.set_extension("WCRY");
            let _ = fs::rename(&path, &new_path);
        });
        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.join();
    }

    println!("[+] Target system encrypted.");
    
    // Sustained Execution (The Cryo-Stasis Target)
    std::thread::sleep(std::time::Duration::from_secs(20));
}