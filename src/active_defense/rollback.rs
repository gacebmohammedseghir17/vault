use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Mutex;
use once_cell::sync::Lazy;

// Global map: PID -> Vec<Original File Paths>
pub static ROLLBACK_CACHE: Lazy<Mutex<HashMap<u32, Vec<String>>>> = Lazy::new(|| Mutex::new(HashMap::new()));

const SHADOW_DIR: &str = "C:\\.erdps_shadow";

pub fn backup_file_pre_modify(pid: u32, target_file_path: &str) {
    let path = Path::new(target_file_path);
    
    // Optimization: Only backup critical extensions
    if let Some(ext) = path.extension() {
        let ext_str = ext.to_string_lossy().to_lowercase();
        let critical_exts = ["docx", "pdf", "xlsx", "jpg", "png", "txt", "kdbx"];
        if !critical_exts.contains(&ext_str.as_str()) {
            return;
        }
    } else {
        return; // No extension
    }

    if !path.exists() {
        return; // Nothing to backup
    }

    // Generate a deterministic backup name: {pid}_{filename_hash}.bak
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    target_file_path.hash(&mut hasher);
    let hash = hasher.finish();

    let backup_name = format!("{}_{}.bak", pid, hash);
    let backup_path = Path::new(SHADOW_DIR).join(backup_name);

    // Perform the backup
    if let Ok(_) = fs::copy(target_file_path, &backup_path) {
        if let Ok(mut cache) = ROLLBACK_CACHE.lock() {
            cache.entry(pid).or_insert_with(Vec::new).push(target_file_path.to_string());
        }
    }
}

pub fn execute_rollback(pid: u32) {
    if let Ok(mut cache) = ROLLBACK_CACHE.lock() {
        if let Some(files) = cache.remove(&pid) {
            println!("\x1b[33m[ROLLBACK] 🔄 Restoring {} files for PID {}...\x1b[0m", files.len(), pid);
            
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};

            let mut restored_count = 0;
            for original_path_str in files {
                let mut hasher = DefaultHasher::new();
                original_path_str.hash(&mut hasher);
                let hash = hasher.finish();

                let backup_name = format!("{}_{}.bak", pid, hash);
                let backup_path = Path::new(SHADOW_DIR).join(backup_name);
                
                // Copy the backup back to the original location, overwriting the encrypted file
                if fs::copy(&backup_path, &original_path_str).is_ok() {
                    restored_count += 1;
                    let _ = fs::remove_file(&backup_path); // Cleanup the backup file
                }
            }
            
            if restored_count > 0 {
                println!("\x1b[32;1m[+] AUTONOMOUS ROLLBACK COMPLETE: System healed and {} original files restored for PID {}.\x1b[0m", restored_count, pid);
            }
        }
    }
}
