use winreg::RegKey;
use winreg::enums::*;
use crate::pipeline::ForensicPipeline;
use colored::*;
use std::path::Path;

pub struct PersistenceHunter;

impl PersistenceHunter {
    pub fn scan_persistence(pipeline: &mut ForensicPipeline) {
        println!("{}", "\n[ PERSISTENCE HUNTER ] Scanning Registry Autoruns...".bright_cyan().bold());
        println!("{:<10} {:<25} {:<40} {:<10}", "HIVE", "NAME", "VERDICT", "SCORE");
        println!("{:-<10} {:-<25} {:-<40} {:-<10}", "", "", "", "");

        let hives = vec![
            (HKEY_CURRENT_USER, "HKCU"),
            (HKEY_LOCAL_MACHINE, "HKLM"),
        ];

        for (hive, hive_name) in hives {
            let root = RegKey::predef(hive);
            if let Ok(key) = root.open_subkey("Software\\Microsoft\\Windows\\CurrentVersion\\Run") {
                for (name, value) in key.enum_values().filter_map(Result::ok) {
                    let cmd: String = value.to_string();
                    let path = Self::extract_path(&cmd);
                    
                    let mut verdict = "CLEAN".green();
                    let mut score = 0.0;
                    let mut details = String::new();

                    if Path::new(&path).exists() {
                        if let Ok(ctx) = pipeline.analyze(&path) {
                            score = ctx.ml_score;
                            if ctx.verdict == "MALICIOUS" {
                                verdict = "MALICIOUS".red().bold();
                                details = format!("(Score: {:.4})", score);
                                println!("[!] THREAT DETECTED IN AUTORUN: {}", name.red());
                            } else if ctx.verdict == "SUSPICIOUS" {
                                verdict = "SUSPICIOUS".yellow();
                            }
                        }
                    } else {
                        verdict = "MISSING".white(); // File not found on disk
                    }

                    println!("{:<10} {:<25} {:<40} {:.4}", 
                        hive_name, 
                        name.chars().take(24).collect::<String>(), 
                        format!("{} {}", verdict, details), 
                        score
                    );
                }
            }
        }
        println!();
    }

    fn extract_path(cmd: &str) -> String {
        let cmd = cmd.trim();
        // Handle quoted paths: "C:\Path\To\File.exe" /arg
        if cmd.starts_with('"') {
            if let Some(end) = cmd[1..].find('"') {
                return cmd[1..=end].to_string();
            }
        }
        // Handle unquoted paths: C:\Path\To\File.exe /arg
        // Simple heuristic: take everything until the first space that looks like an argument
        // For robustness, we might just take the whole string if it exists, or split by space.
        // Here we'll take the first token for simplicity, but robust parsing is hard without context.
        cmd.split_whitespace().next().unwrap_or(cmd).to_string()
    }
}
