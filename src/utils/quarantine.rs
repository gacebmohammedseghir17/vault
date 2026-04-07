use std::fs;
use std::path::Path;
use console::style;
use chrono::Local;

const QUARANTINE_DIR: &str = "C:\\ERDPS_Quarantine";

pub fn setup_quarantine() {
    if !Path::new(QUARANTINE_DIR).exists() {
        if let Err(e) = fs::create_dir_all(QUARANTINE_DIR) {
            eprintln!("[!] Failed to create Quarantine Vault: {}", e);
        }
    }
}

pub fn isolate_file(source_path: &str) -> bool {
    setup_quarantine();
    
    let path = Path::new(source_path);
    if let Some(filename) = path.file_name() {
        let timestamp = Local::now().format("%Y%m%d_%H%M%S");
        let new_name = format!("{}_{}.infected", filename.to_string_lossy(), timestamp);
        let dest_path = format!("{}\\{}", QUARANTINE_DIR, new_name);

        match fs::rename(source_path, &dest_path) {
            Ok(_) => {
                println!("{}", style(format!("[+] File Quarantined: {}", dest_path)).green().bold());
                true
            },
            Err(e) => {
                // Try copy-delete fallback if rename fails (cross-drive)
                if fs::copy(source_path, &dest_path).is_ok() {
                    let _ = fs::remove_file(source_path);
                    println!("{}", style(format!("[+] File Quarantined (Copy): {}", dest_path)).green().bold());
                    true
                } else {
                    eprintln!("[!] Failed to isolate file: {}", e);
                    false
                }
            }
        }
    } else {
        false
    }
}

pub fn list_quarantine() {
    println!("\n{}", style("=== QUARANTINE VAULT ===").bold().yellow());
    if let Ok(entries) = fs::read_dir(QUARANTINE_DIR) {
        let mut count = 0;
        for entry in entries.flatten() {
            if let Ok(metadata) = entry.metadata() {
                let size = metadata.len();
                println!(" - {} ({} bytes)", entry.file_name().to_string_lossy(), size);
                count += 1;
            }
        }
        if count == 0 {
            println!("   (Vault is Empty)");
        }
    } else {
        println!("   (Vault not found)");
    }
    println!();
}

pub fn clean_quarantine() {
    if let Ok(entries) = fs::read_dir(QUARANTINE_DIR) {
        for entry in entries.flatten() {
            let _ = fs::remove_file(entry.path());
        }
        println!("{}", style("[+] Quarantine Vault Purged.").green());
    }
}
