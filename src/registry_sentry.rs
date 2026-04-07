use winreg::enums::*;
use winreg::RegKey;
use std::{thread, time};
use std::collections::HashMap;
use console::style;

pub fn start_registry_monitor() {
    thread::spawn(|| {
        println!("[*] Registry Sentry Active. Watching 'Run' Keys...");
        
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let path = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
        
        // 1. Take Initial Snapshot
        let mut known_values = get_registry_values(&hkcu, path);

        loop {
            thread::sleep(time::Duration::from_secs(3)); // Check every 3 seconds

            // 2. Take New Snapshot
            let current_values = get_registry_values(&hkcu, path);

            // 3. Compare: Did anything new appear?
            for (name, value) in &current_values {
                if !known_values.contains_key(name) {
                    println!("\n{}", style("!!! REGISTRY PERSISTENCE ATTEMPT !!!").red().bold().blink());
                    println!("    [!] Key: HKCU\\...\\Run");
                    println!("    [!] Value Name: {}", style(name).yellow());
                    println!("    [!] Command: {}", style(value).yellow());
                    
                    // IN V8.0: We would auto-delete this key.
                    // For now, we alert.
                }
            }

            // Update state
            known_values = current_values;
        }
    });
}

fn get_registry_values(root: &RegKey, path: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Ok(key) = root.open_subkey(path) {
        for i in key.enum_values().map(|x| x.unwrap()) {
            map.insert(i.0, i.1.to_string());
        }
    }
    map
}
