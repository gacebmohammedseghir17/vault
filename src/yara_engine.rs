use yara_x::{Compiler, Scanner};
use std::fs;
use std::path::Path;

pub struct YaraEngine;

impl YaraEngine {
    pub fn scan_file(file_path: &str) {
        println!("\x1b[35m[YARA] 🔍 Scanning with Global Intelligence...\x1b[0m");

        let mut compiler = Compiler::new();

        // 1. Load Core Signatures (Embedded or Local)
        if Path::new("ransomware_signatures.yar").exists() {
            let src = fs::read_to_string("ransomware_signatures.yar").unwrap_or_default();
            let _ = compiler.add_source(src.as_str());
        }

        // 2. Load Global Intelligence (YARA Forge Rules)
        let rules_dir = "yara_rules";
        let mut loaded_count = 0;
        if Path::new(rules_dir).exists() {
            if let Ok(entries) = fs::read_dir(rules_dir) {
                for entry in entries {
                    if let Ok(entry) = entry {
                        let path = entry.path();
                        if path.extension().and_then(|s| s.to_str()) == Some("yar") {
                            if let Ok(src) = fs::read_to_string(&path) {
                                // Add rule to compiler (ignore errors for broken rules)
                                if compiler.add_source(src.as_str()).is_ok() {
                                    loaded_count += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
        println!("\x1b[36m   |-- [INIT] Loaded {} external rule files.\x1b[0m", loaded_count);

        // 3. Compile & Scan
        let rules = compiler.build();
        let mut scanner = Scanner::new(&rules);

        match scanner.scan_file(file_path) {
            Ok(results) => {
                let matching_rules = results.matching_rules();
                if matching_rules.len() > 0 {
                    println!("\x1b[41;37m[YARA] 🚨 DETECTED MALWARE: {} rules matched!\x1b[0m", matching_rules.len());
                    for rule in matching_rules {
                        println!("\x1b[31m   |-- Match: {}\x1b[0m", rule.identifier());
                    }
                } else {
                    println!("\x1b[32m[YARA] ✅ No YARA signatures matched.\x1b[0m");
                }
            },
            Err(e) => println!("\x1b[31m[YARA] ❌ Scan failed: {}\x1b[0m", e),
        }
    }
}
