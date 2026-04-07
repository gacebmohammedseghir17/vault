use std::process::Command;
use std::path::Path;
use std::fs;
use colored::*;

pub struct RecoveryEngine;

impl RecoveryEngine {
    /// Lists all available Volume Shadow Copies (snapshots).
    pub fn list_snapshots() {
        println!("{}", "\n[ RECOVERY ENGINE ] Scanning for Volume Shadow Copies...".bright_cyan().bold());

        // Execute vssadmin list shadows
        let output = match Command::new("vssadmin")
            .args(&["list", "shadows"])
            .output()
        {
            Ok(o) => o,
            Err(e) => {
                println!("[!] Failed to execute vssadmin: {}", e);
                return;
            }
        };

        if !output.status.success() {
            println!("[!] Error: vssadmin failed. Ensure you are running as Administrator.");
            return;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut snapshot_count = 0;

        // Simple parsing of vssadmin output
        println!("{:<40} {:<30}", "SNAPSHOT ID", "CREATION TIME");
        println!("{:-<40} {:-<30}", "", "");

        let mut current_id = String::new();
        
        for line in stdout.lines() {
            let line = line.trim();
            if line.starts_with("Shadow Copy ID:") {
                current_id = line.replace("Shadow Copy ID:", "").trim().to_string();
            } else if line.starts_with("Creation Time:") {
                let time = line.replace("Creation Time:", "").trim().to_string();
                if !current_id.is_empty() {
                    // Extract clean ID (GUID format)
                    // Format: {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
                    println!("{:<40} {:<30}", current_id, time);
                    snapshot_count += 1;
                    current_id.clear();
                }
            }
        }

        if snapshot_count == 0 {
            println!("[!] No shadow copies found. System Restore might be disabled.");
        } else {
            println!("\n[+] Found {} recovery points.", snapshot_count);
        }
    }

    /// Recovers a specific file from a shadow copy.
    pub fn recover_file(shadow_id: &str, target_path: &str) {
        println!("{}", format!("\n[ RECOVERY ENGINE ] Attempting to recover '{}' from snapshot...", target_path).yellow());

        // 1. Get Shadow Copy Volume Path
        // We need to parse "Shadow Copy Volume Name" from vssadmin for the given ID.
        // vssadmin list shadows /Shadow={ID}
        
        // Clean up ID format (ensure braces)
        let clean_id = if !shadow_id.starts_with("{") {
            format!("{{{}}}", shadow_id)
        } else {
            shadow_id.to_string()
        };

        let output = match Command::new("vssadmin")
            .args(&["list", "shadows", &format!("/Shadow={}", clean_id)])
            .output()
        {
            Ok(o) => o,
            Err(_) => {
                println!("[!] Failed to query shadow copy info.");
                return;
            }
        };

        if !output.status.success() {
            println!("[!] Shadow copy not found or access denied.");
            return;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut shadow_volume = String::new();

        for line in stdout.lines() {
            if line.trim().starts_with("Shadow Copy Volume Name:") {
                shadow_volume = line.replace("Shadow Copy Volume Name:", "").trim().to_string();
                break;
            }
        }

        if shadow_volume.is_empty() {
            println!("[!] Could not determine Shadow Volume Path.");
            return;
        }

        // 2. Mount Shadow Volume (Symbolic Link)
        // mklink /d C:\ShadowMount \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyX\
        // Note: mklink is a shell internal command in cmd.
        
        let mount_point = r"C:\ShadowMount";
        
        // Ensure mount point doesn't exist
        let _ = fs::remove_dir(mount_point); 

        println!("    -> Mounting {} to {}...", shadow_volume, mount_point);
        
        let status = Command::new("cmd")
            .args(&["/C", "mklink", "/d", mount_point, &shadow_volume])
            .output();

        match status {
            Ok(o) if o.status.success() => {
                // 3. Copy File
                // Target path is likely "C:\Users\...\Desktop\file.txt"
                // We need to strip drive letter "C:\" and append to mount point.
                
                let relative_path = if target_path.len() > 3 {
                    &target_path[3..] // Skip "C:\"
                } else {
                    target_path
                };
                
                let source_file = Path::new(mount_point).join(relative_path);
                let dest_file = Path::new(target_path).parent().unwrap().join(format!("RECOVERED_{}", Path::new(target_path).file_name().unwrap().to_str().unwrap()));

                if source_file.exists() {
                    match fs::copy(&source_file, &dest_file) {
                        Ok(_) => println!("{}", format!("[+] SUCCESS: File recovered to {:?}", dest_file).green().bold()),
                        Err(e) => println!("[!] Recovery failed: {}", e),
                    }
                } else {
                    println!("[!] File not found in this snapshot: {:?}", source_file);
                }

                // 4. Cleanup
                let _ = fs::remove_dir(mount_point); // Removes the link
            },
            _ => println!("[!] Failed to mount shadow copy. Access denied?"),
        }
    }
}
