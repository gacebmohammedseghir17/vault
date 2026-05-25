use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize, Serialize)]
pub struct LedgerEntry {
    pub pid: u32,
    pub original_path: String,
    pub vault_path: String,
}

/// Triggers a surgical micro-rollback for a specific malicious PID.
/// Reads the Copy-on-Write (CoW) ledger and restores pristine files.
pub fn trigger_micro_rollback(malicious_pid: u32) {
    let ledger_path = "C:\\ERDPS_Vault\\ledger.json";
    
    if !Path::new(ledger_path).exists() {
        println!("\x1b[33m[MICRO-ROLLBACK] No ledger found at {}. Skipping restoration.\x1b[0m", ledger_path);
        return;
    }

    let data = match fs::read_to_string(ledger_path) {
        Ok(d) => d,
        Err(e) => {
            println!("\x1b[31m[MICRO-ROLLBACK] Failed to read ledger: {}\x1b[0m", e);
            return;
        }
    };

    println!("\x1b[36m[MICRO-ROLLBACK] Initiating precision restoration for PID: {}\x1b[0m", malicious_pid);
    let mut restored_count = 0;

    // We process the ledger line-by-line (JSONL format). 
    // This is safer for a ledger that a Kernel driver appends to continuously.
    for line in data.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        if let Ok(entry) = serde_json::from_str::<LedgerEntry>(line) {
            if entry.pid == malicious_pid {
                println!("[*] Restoring pristine file: {}", entry.original_path);
                
                // Perform the restoration
                if let Err(e) = fs::copy(&entry.vault_path, &entry.original_path) {
                    println!("\x1b[31m[!] Failed to restore {}: {}\x1b[0m", entry.original_path, e);
                } else {
                    // Clean up the vault to save space after successful restoration
                    let _ = fs::remove_file(&entry.vault_path);
                    restored_count += 1;
                }
            }
        }
    }

    if restored_count > 0 {
        println!("\x1b[32;1m[MICRO-ROLLBACK] SUCCESS: {} files surgically restored from CoW Vault.\x1b[0m", restored_count);
    } else {
        println!("\x1b[33m[MICRO-ROLLBACK] No files needed restoration for PID {}.\x1b[0m", malicious_pid);
    }
}
