use std::fs;
use std::path::Path;
use rand::{Rng, thread_rng};
use rand::distributions::Alphanumeric;
use windows::Win32::Storage::FileSystem::{SetFileAttributesW, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_SYSTEM};
use windows::core::PCWSTR;
use lazy_static::lazy_static;
use std::sync::Mutex;

lazy_static! {
    pub static ref DEPLOYED_HONEYPOTS: Mutex<Vec<String>> = Mutex::new(Vec::new());
}

pub fn deploy_decoys() {
    println!("\x1b[35m[HONEYPOT] 🍯 DEPLOYING ZERO-FOOTPRINT DECOYS...\x1b[0m");

    let target_dirs = vec![
        "C:\\Users\\Public",
        "C:\\ProgramData",
    ];

    let decoy_names = vec![
        "~$cache_config.docx",
        "~sys_temp.pdf",
        "~$win_recovery.xlsx",
    ];

    let mut deployed = DEPLOYED_HONEYPOTS.lock().unwrap();
    let mut rng = thread_rng();

    for dir in target_dirs {
        let base_path = Path::new(dir);
        if !base_path.exists() { continue; }

        for name in &decoy_names {
            let trap_path = base_path.join(name);
            
            // Write random low-entropy text string
            let random_str: String = (0..512)
                .map(|_| rng.sample(Alphanumeric) as char)
                .collect();
            let content = format!("CONFIDENTIAL SYSTEM DATA\n{}", random_str);

            if fs::write(&trap_path, content).is_ok() {
                let path_str = trap_path.to_string_lossy().to_string();
                let mut path_wide: Vec<u16> = path_str.encode_utf16().collect();
                path_wide.push(0);

                unsafe {
                    let _ = SetFileAttributesW(
                        PCWSTR(path_wide.as_ptr()),
                        FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM
                    );
                }
                
                deployed.push(path_str.to_lowercase());
            }
        }
    }

    println!("\x1b[32m[HONEYPOT] ✅ Deployed {} Zero-Footprint Decoys.\x1b[0m", deployed.len());
}

pub fn is_honeypot(target_path: &str) -> bool {
    let lower_path = target_path.to_lowercase();
    let deployed = DEPLOYED_HONEYPOTS.lock().unwrap();
    
    for honeypot in deployed.iter() {
        // Strip the drive letter from honeypot (e.g. "c:\users\..." -> "\users\...")
        let suffix = if honeypot.len() > 2 && &honeypot[1..2] == ":" {
            &honeypot[2..]
        } else {
            honeypot
        };
        
        if lower_path.ends_with(suffix) {
            return true;
        }
    }
    false
}