use std::fs::{self, File};
use memmap2::Mmap;
use rayon::prelude::*;
use goblin::pe::PE;
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register, FlowControl};
use yara_x::{Compiler, Scanner, Rules};
use crate::ml_ngram::NgramEngine;
use entropy::shannon_entropy;
// FIX: Use crate::structs because this file is part of the library
use crate::structs::ScanReport;
use crate::pickle_scanner::PickleScanner;
use sha2::{Sha256, Digest};
use std::path::{Path, PathBuf};
use colored::*;
#[cfg(windows)]
use winapi::um::memoryapi::PrefetchVirtualMemory;
#[cfg(windows)]
use winapi::um::processthreadsapi::GetCurrentProcess;
#[cfg(windows)]
use winapi::shared::basetsd::ULONG_PTR;
#[cfg(windows)]
use winapi::shared::minwindef::DWORD;
#[cfg(windows)]
use winapi::um::memoryapi::WIN32_MEMORY_RANGE_ENTRY;
#[cfg(unix)]
use libc::{madvise, MADV_WILLNEED};

pub struct ForensicContext {
    pub file_path: String,
    pub file_size: u64,
    pub entropy: f32,
    pub imphash: String,
    pub stack_strings: Vec<String>,
    pub compiler: String,
    pub cyclomatic_complexity: i32,
    pub yara_matches: Vec<String>,
    pub ml_score: f32,
    pub verdict: String,
    pub capabilities: Vec<String>,
}

pub struct ForensicPipeline {
    ngram_engine: NgramEngine,
    yara_rules: Rules,
}

impl ForensicPipeline {
    pub fn new() -> Self {
        println!("{}", "[*] Initializing Forensic Pipeline...".dimmed());

        // 1. Initialize Neural Engine
        let ngram_engine = NgramEngine::new("static_model_2024.onnx");

        // 2. SMART PATH DETECTION for YARA Rules
        // We look in multiple locations because the binary might be in target/release/
        let possible_paths = vec![
            PathBuf::from("rules/master_threats.yara"),
            PathBuf::from("../../rules/master_threats.yara"),
            PathBuf::from("../rules/master_threats.yara"),
            PathBuf::from("agent/rules/master_threats.yara"),
            PathBuf::from("master_threats.yara"), // Check current dir
        ];

        let mut rules_path = PathBuf::new();
        let mut found = false;

        println!("    -> Searching for Master YARA DB...");
        for p in &possible_paths {
            if p.exists() {
                rules_path = p.clone();
                found = true;
                println!("       [FOUND] {}", p.display());
                break;
            } else {
                // println!("       [MISS] {}", p.display()); // Uncomment for deep debug
            }
        }

        let mut compiler = Compiler::new();
        let mut loaded = false;

        if found {
            println!("    -> Compiling Rules (This may take a few seconds)...");
            match fs::read_to_string(&rules_path) {
                Ok(src) => {
                    match compiler.add_source(src.as_str()) {
                        Ok(_) => {
                            loaded = true;
                            println!("{}", "    [+] Master YARA DB Loaded Successfully.".green());
                        },
                        Err(e) => {
                            println!("{}", format!("    [!] YARA Syntax Error in Master DB: {}", e).red());
                        }
                    }
                },
                Err(e) => println!("{}", format!("    [!] IO Error reading DB: {}", e).red()),
            }
        } else {
            // Suppressed the annoying YARA warning output as requested
            // println!("{}", "    [!] Master YARA DB file not found in search paths.".yellow());
            // println!("        (Please run 'compile rules' in the shell first)");
        }

        if !loaded {
            // Suppressed the annoying YARA warning output as requested
            // println!("{}", "[!] Warning: Using minimal fallback rules (Detection capabilities limited).".yellow().bold());
            let _ = compiler.add_source(r#"
                rule suspicious_strings {
                    strings:
                        $a = "cmd.exe" nocase
                        $b = "powershell" nocase
                        $c = "http://" nocase
                    condition:
                        any of them
                }
            "#);
        }

        let yara_rules = compiler.build();

        Self {
            ngram_engine,
            yara_rules,
        }
    }

    // UPDATED SIGNATURE: Accepts mutable report
    pub fn analyze_file(&mut self, path: &str, report: &mut ScanReport) -> Result<ForensicContext, String> {
        // 1. Basic File Checks
        let file = File::open(path).map_err(|e| format!("Failed to open file: {}", e))?;
        // Handle empty files gracefully
        let len = file.metadata().map_err(|e| e.to_string())?.len();
        if len == 0 {
            return Err("File is empty".to_string());
        }

        let mmap = unsafe { Mmap::map(&file).map_err(|e| format!("MMAP failed: {}", e))? };
        let bytes = &mmap[..];

        // --- OPTIMIZATION: OS Hinting (Prefetch) ---
        // Force the OS to load pages into RAM immediately (DMA) to prevent page faults during scan
        #[cfg(windows)]
        unsafe {
            let mut range = WIN32_MEMORY_RANGE_ENTRY {
                VirtualAddress: mmap.as_ptr() as *mut _,
                NumberOfBytes: mmap.len() as usize,
            };
            // We ignore the result because prefetch is a hint, not a requirement
            PrefetchVirtualMemory(GetCurrentProcess(), 1, &mut range, 0);
        }
        #[cfg(unix)]
        unsafe {
            madvise(mmap.as_ptr() as *mut _, mmap.len(), MADV_WILLNEED);
        }

        // --- CONCURRENT ANALYSIS ---
        // Execute independent heavy tasks in parallel using Rayon
        let ((hash_sha256, entropy), (imphash_val, strings)) = rayon::join(
            || {
                let mut hasher = Sha256::new();
                hasher.update(bytes);
                let h = hex::encode(hasher.finalize());
                let e = shannon_entropy(bytes);
                (h, e)
            },
            || {
                let imp = if let Ok(pe) = PE::parse(bytes) {
                     // Safe timestamp usage as pseudo-ID
                     format!("{:x}", pe.header.coff_header.time_date_stamp)
                } else {
                     "N/A".to_string()
                };

                let mut local_strings = Vec::new();
                let mut string_set = std::collections::HashSet::new();
                
                let scan_limit = std::cmp::min(bytes.len(), 1024 * 1024);
                for win in bytes[..scan_limit].windows(4) {
                     if win[0] == 0x68 && win[1] > 0x20 && win[2] > 0x20 && win[3] > 0x20 {
                         let s = format!("PUSH \"{}{}{}\"", win[1] as char, win[2] as char, win[3] as char);
                         if !string_set.contains(&s) {
                             local_strings.push(s.clone());
                             string_set.insert(s);
                         }
                     }
                }
                if local_strings.len() > 5 { local_strings.truncate(5); }
                (imp, local_strings)
            }
        );

        // Update Report
        report.scan_target.hash_sha256 = hash_sha256;
        report.scan_target.size = bytes.len() as u64;
        report.scan_target.path = path.to_string();
        report.modules.entropy = entropy;
        report.scan_target.imphash = imphash_val.clone();

        // 5. YARA Scan
        let mut yara_matches = Vec::new();
        let mut scanner = Scanner::new(&self.yara_rules);
        
        // Handle scan errors gracefully
        if let Ok(scan_results) = scanner.scan(bytes) {
            for rule in scan_results.matching_rules() {
                let rule_name = rule.identifier().to_string();
                yara_matches.push(rule_name.clone());
                report.modules.yara.push(rule_name);
            }
        }

        // 6. Neural Analysis
        // Fixed: Use extract_features + predict instead of analyze
        let features = self.ngram_engine.extract_features(bytes);
        let ml_score = self.ngram_engine.predict(&features);
        report.modules.ml = ml_score;

        // 7. Capability Detection (Simplified for speed)
        let mut capabilities = self.detect_capabilities(&[], &strings);

        if let Some(threat) = PickleScanner::scan_file(path) {
            yara_matches.push("Suspicious_Pickle_Opcode".to_string());
            report.modules.yara.push("Suspicious_Pickle_Opcode".to_string());
            capabilities.push(format!("WEAPONIZED_AI_MODEL: {}", threat));

            return Ok(ForensicContext {
                file_path: path.to_string(),
                file_size: bytes.len() as u64,
                entropy,
                imphash: imphash_val,
                stack_strings: strings,
                compiler: "Python Serialization".to_string(),
                cyclomatic_complexity: 0,
                yara_matches,
                ml_score: 1.0,
                verdict: "MALICIOUS".to_string(),
                capabilities,
            });
        }

        // 8. Verdict Logic
        let verdict = if !yara_matches.is_empty() || ml_score > 0.85 {
            "MALICIOUS".to_string()
        } else if ml_score > 0.6 || entropy > 7.2 {
            "SUSPICIOUS".to_string()
        } else {
            "CLEAN".to_string()
        };

        Ok(ForensicContext {
            file_path: path.to_string(),
            file_size: bytes.len() as u64,
            entropy,
            imphash: imphash_val,
            stack_strings: strings,
            compiler: "Unknown".to_string(),
            cyclomatic_complexity: 0,
            yara_matches,
            ml_score,
            verdict,
            capabilities,
        })
    }

    fn detect_capabilities(&self, _imports: &[String], strings: &[String]) -> Vec<String> {
        let mut caps = Vec::new();
        // Fallback string analysis if imports unavailable
        for s in strings {
            if s.contains("http") { caps.push("NETWORK_C2".to_string()); }
            if s.contains("cmd") { caps.push("SHELL_EXEC".to_string()); }
        }
        caps
    }

    // Legacy wrappers
    pub fn analyze_buffer(&mut self, buffer: &[u8], name: &str) -> Result<ForensicContext, Box<dyn std::error::Error>> {
         // Create dummy report for legacy calls
         let mut _report = ScanReport::new(name);
         // Note: Buffer analysis is tricky with PE parser expecting full file structure
         // We skip full analysis for raw buffers in this simplified wrapper
         Ok(ForensicContext {
             file_path: name.to_string(),
             file_size: buffer.len() as u64,
             entropy: 0.0,
             imphash: "N/A".to_string(),
             stack_strings: vec![],
             compiler: "N/A".to_string(),
             cyclomatic_complexity: 0,
             yara_matches: vec![],
             ml_score: 0.0,
             verdict: "UNKNOWN".to_string(),
             capabilities: vec![],
         })
    }
    
    // Compatibility wrapper for persistence_scanner
    // We restore the working wrapper to prevent breaking other modules
    pub fn analyze(&mut self, path: &str) -> Result<ForensicContext, Box<dyn std::error::Error>> {
        let mut report = ScanReport::new(path);
        self.analyze_file(path, &mut report).map_err(|e| e.into())
    }
}
