use std::fs::{self, File};
use std::io::{Write, stdout};
use std::path::{Path, PathBuf};
use colored::*;
use walkdir::WalkDir;
use yara_x::Compiler;
use std::panic::{self, AssertUnwindSafe};

pub struct IntelManager;

impl IntelManager {
    pub fn compile_local_rules() {
        println!("{}", "\n[ INTEL MANAGER ] Harvesting Local YARA Rules (Strict Validation Mode)...".cyan().bold());

        // 1. Smart Directory Detection
        let possible_paths = vec![
            PathBuf::from("rules"),
            PathBuf::from("../../rules"),
            PathBuf::from("../rules"),
            PathBuf::from("agent/rules"),
        ];

        let mut rules_dir = PathBuf::new();
        let mut found = false;

        for p in possible_paths {
            if p.exists() && p.is_dir() {
                rules_dir = p;
                found = true;
                break;
            }
        }

        if !found {
            println!("{}", "[!] 'rules' directory not found.".red());
            return;
        }

        println!("[*] Found Rule Base: {}", rules_dir.canonicalize().unwrap_or(rules_dir.clone()).display());

        let mut valid_count = 0;
        let mut skipped_count = 0; // Duplicates or Syntax Errors
        let mut toxic_count = 0;   // Regex too large / Compilation crashes
        let mut combined_rules = String::new();

        // Global Validator for Deduplication
        let mut global_validator = Compiler::new();

        println!("    -> Scanning, Building, and Validating...");
        print!("    -> Progress: ");

        let mut processed = 0;

        // Recursive Harvesting
        for entry in WalkDir::new(&rules_dir).into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            
            if path.extension().map_or(false, |ext| ext == "yar" || ext == "yara") {
                // Don't ingest the output file itself
                if path.file_name().unwrap() == "master_threats.yara" { continue; }

                if let Ok(content) = fs::read_to_string(path) {
                    // Filter YARA-L (Google Chronicle)
                    if content.contains("rule_version = \"L\"") {
                        skipped_count += 1;
                        continue;
                    }

                    // --- STRICT ISOLATION CHECK ---
                    // 1. Create a throwaway compiler to test this specific file in isolation.
                    //    We MUST call .build() to trigger regex size limits.
                    let mut isolation_tester = Compiler::new();
                    let syntax_ok = isolation_tester.add_source(content.as_str()).is_ok();
                    
                    if syntax_ok {
                        // 2. Test Build (Catch "regexp too large" panics)
                        // Use catch_unwind because Compiler::build() might panic on resource exhaustion or internal errors
                        // and does not return a Result.
                        let build_result = panic::catch_unwind(AssertUnwindSafe(|| {
                            isolation_tester.build()
                        }));

                        if build_result.is_err() {
                            // This rule is toxic (crashes engine). Skip it.
                            toxic_count += 1;
                            // println!("\n       [!] Dropped Toxic Rule (Regex too large): {:?}", path.file_name().unwrap());
                            continue;
                        }

                        // 3. Deduplication Check (Global Context)
                        if global_validator.add_source(content.as_str()).is_ok() {
                            combined_rules.push_str(&content);
                            combined_rules.push('\n');
                            valid_count += 1;
                        } else {
                            skipped_count += 1; // Duplicate
                        }
                    } else {
                        skipped_count += 1; // Syntax Error
                    }
                }
                
                processed += 1;
                if processed % 1000 == 0 {
                    print!(".");
                    let _ = stdout().flush();
                }
            }
        }
        println!(); // Newline after dots

        // Save Master Database
        let master_path = rules_dir.join("master_threats.yara");
        match File::create(&master_path) {
            Ok(mut f) => {
                let _ = f.write_all(combined_rules.as_bytes());
                println!("\n{}", "[ INTEL COMPILATION REPORT ]".green().bold());
                println!("    -> Rules Validated: {}", valid_count);
                println!("    -> Toxic Rules:     {} (Regex too large - DROPPED)", toxic_count.to_string().red());
                println!("    -> Duplicates/Bad:  {}", skipped_count);
                println!("{}", format!("    -> Database:        {}", master_path.display()).yellow());
                println!("    -> Status:          READY. Run 'reload' to arm the engine.");
            },
            Err(e) => println!("[!] Fatal: Could not write master database: {}", e),
        }
    }
}
