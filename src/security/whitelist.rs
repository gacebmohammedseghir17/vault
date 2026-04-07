use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::io::Read;
use sha2::{Sha256, Digest};
use std::sync::{Arc, Mutex};
use lazy_static::lazy_static;

const DB_PATH: &str = "trusted_apps.json";

lazy_static! {
    static ref MEM_DB: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TrustedApp {
    pub name: String,
    pub signer: String,
    pub hash: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct DbSchema {
    apps: Vec<TrustedApp>,
}

pub fn load_db() {
    if Path::new(DB_PATH).exists() {
        if let Ok(data) = fs::read_to_string(DB_PATH) {
            if let Ok(schema) = serde_json::from_str::<DbSchema>(&data) {
                let mut db = MEM_DB.lock().unwrap();
                for app in schema.apps {
                    db.insert(app.hash);
                }
                println!("[*] Whitelist Loaded: {} trusted apps.", db.len());
                return;
            }
        }
    }
    // Create empty if not exists
    save_db(vec![]);
}

fn save_db(apps: Vec<TrustedApp>) {
    let schema = DbSchema { apps };
    if let Ok(json) = serde_json::to_string_pretty(&schema) {
        let _ = fs::write(DB_PATH, json);
    }
}

pub fn is_trusted(path: &str) -> bool {
    let hash = calculate_hash(path);
    if hash.is_empty() { return false; } // Can't trust if can't read

    // 1. Check DB
    {
        let db = MEM_DB.lock().unwrap();
        if db.contains(&hash) {
            return true;
        }
    }

    // 2. Smart Signature Check
    if check_digital_signature(path) {
        add_to_whitelist(path); // Auto-learn
        return true;
    }

    false
}

pub fn add_to_whitelist(path: &str) {
    let hash = calculate_hash(path);
    if hash.is_empty() { return; }

    let signer = get_signer(path);
    let name = Path::new(path).file_name().unwrap_or_default().to_string_lossy().to_string();

    let app = TrustedApp {
        name: name.clone(),
        signer: signer.clone(),
        hash: hash.clone(),
    };

    // Update Memory
    {
        let mut db = MEM_DB.lock().unwrap();
        if db.contains(&hash) { return; }
        db.insert(hash.clone());
    }

    // Update Disk (Inefficient but fine for v1.0)
    // Read existing, append, save
    let mut current_apps = Vec::new();
    if Path::new(DB_PATH).exists() {
        if let Ok(data) = fs::read_to_string(DB_PATH) {
            if let Ok(schema) = serde_json::from_str::<DbSchema>(&data) {
                current_apps = schema.apps;
            }
        }
    }
    current_apps.push(app);
    save_db(current_apps);

    println!("[+] Learning: Added {} to whitelist.", name);
}

fn calculate_hash(path: &str) -> String {
    if let Ok(mut file) = fs::File::open(path) {
        let mut hasher = Sha256::new();
        let mut buffer = [0; 4096];
        loop {
            let count = file.read(&mut buffer).unwrap_or(0);
            if count == 0 { break; }
            hasher.update(&buffer[..count]);
        }
        return hex::encode(hasher.finalize());
    }
    String::new()
}

fn get_signer(path: &str) -> String {
    // PowerShell wrapper to get Signer
    let ps_script = format!("(Get-AuthenticodeSignature '{}').SignerCertificate.Subject", path);
    let output = Command::new("powershell")
        .args(&["-Command", &ps_script])
        .output();
    
    if let Ok(o) = output {
        let out = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if out.is_empty() { return "Unsigned".to_string(); }
        return out;
    }
    "Unknown".to_string()
}

fn check_digital_signature(path: &str) -> bool {
    let signer = get_signer(path);
    if signer == "Unsigned" || signer == "Unknown" { return false; }

    let trusted_vendors = [
        "Microsoft Corporation",
        "Google LLC", 
        "NVIDIA Corporation",
        "Intel Corporation",
        "Mozilla Corporation",
        "Oracle Corporation"
    ];

    for vendor in trusted_vendors.iter() {
        if signer.contains(vendor) {
            return true;
        }
    }
    false
}
