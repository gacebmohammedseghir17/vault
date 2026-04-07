use winreg::enums::*;
use winreg::RegKey;

pub struct PersistenceHunter;

impl PersistenceHunter {
    // 🕵️ COMMAND: persistence
    pub fn scan() {
        println!("\x1b[35m[PERSISTENCE] 👁️ SCANNING AUTO-START LOCATIONS (Registry)...\x1b[0m");

        let mut suspicious_count = 0;
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);

        // 1. Scan Run Keys (The classic spots)
        let keys = [
            (&hklm, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
            (&hklm, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
            (&hkcu, "Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
            (&hkcu, "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
        ];

        for (root, path) in keys.iter() {
            if let Ok(key) = root.open_subkey(path) {
                for (name, value) in key.enum_values().map(|x| x.unwrap()) {
                    let cmd = value.to_string();
                    
                    // 2. Heuristics: Does this look like malware?
                    if Self::analyze_command(&cmd) {
                        println!("\x1b[31m   |-> 💀 SUSPICIOUS: [{}] = {}\x1b[0m", name, cmd);
                        suspicious_count += 1;
                    }
                }
            }
        }

        if suspicious_count == 0 {
            println!("\x1b[32m[PERSISTENCE] ✅ No obvious registry malware found.\x1b[0m");
        } else {
            println!("\n\x1b[41;37m[PERSISTENCE] 🚨 FOUND {} SUSPICIOUS AUTO-START ENTRIES!\x1b[0m", suspicious_count);
        }
    }

    fn analyze_command(cmd: &str) -> bool {
        let lower = cmd.to_lowercase();
        
        // Rule 1: PowerShell with encoded commands (Fileless Malware)
        if lower.contains("powershell") && (lower.contains("-enc") || lower.contains("-encodedcommand")) {
            return true;
        }

        // Rule 2: Running from Temp folders (Droppers)
        if lower.contains("\\temp\\") || lower.contains("\\appdata\\local\\temp") {
            return true;
        }

        // Rule 3: Weird extensions
        if lower.ends_with(".vbs") || lower.ends_with(".js") || lower.ends_with(".bat") {
            return true;
        }
        
        false
    }
}
