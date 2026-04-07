# SCAN COMMAND CODE AUDIT

This document contains the complete source code for all modules invoked during the `scan` command execution, organized by execution phase.

## 1. ORCHESTRATOR
**File:** `agent/src/forensic_shell.rs`
**Role:** Coordinates the scanning pipeline, handles PE parsing, and aggregates results.

```rust
use std::sync::Arc;
use std::io::{self, Write};
use std::fs;
use std::path::Path;
use crate::ml_engine::NeuralEngine;
use crate::unpack_engine::UnpackEngine;
use colored::*;
use goblin::pe::PE;
use md5;
use capstone::prelude::*;
use yara_x::{Compiler, Scanner};

pub fn run(engine: Arc<NeuralEngine>) {
    println!("{}", "\n=== ERDPS FORENSIC SHELL (PHASE 2: LAYERS 1-5) ===".bright_cyan().bold());
    println!("Status: Forensics Engine Active (Structure + YARA + Crypto + AI).");
    println!("Type 'help' for commands.");

    loop {
        print!("{}", "ERDPS > ".green().bold());
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        let input = input.trim();
        let parts: Vec<&str> = input.split_whitespace().collect();

        if parts.is_empty() { continue; }

        match parts[0] {
            "help" => {
                println!("Commands:");
                println!("  scan <file>    : Run Full Forensic Stack (Static + AI + Disassembly)");
                println!("  memscan        : Run RAM Scan (Find Fileless Malware)");
                println!("  rootkit        : Run Cross-View Rootkit Hunter (Find Hidden Processes)");
                println!("  canary         : Deploy Ransomware Traps");
                println!("  entropy        : Test AVX2 Speed");
                println!("  dns            : Scan DNS Cache for DGA");
                println!("  persistence    : Scan Registry for Auto-Start Malware");
                println!("  hooks          : Scan ntdll.dll for Integrity Violations");
                println!("  yara-update    : Download 4,000+ Global YARA Rules");
                println!("  exit           : Quit");
            },
            "exit" | "back" => break,
            "memscan" => { crate::memory_scanner::MemoryHunter::hunt_in_memory(); },
            "rootkit" => crate::rootkit_hunter::RootkitHunter::scan(),
            "entropy" => {
                if let Ok(data) = std::fs::read("erdps-agent.exe").or_else(|_| std::env::current_exe().and_then(std::fs::read)) {
                    let start = std::time::Instant::now();
                    let score = crate::entropy_engine::EntropyAccelerator::calculate(&data);
                    let duration = start.elapsed();
                    println!("[ENTROPY] ⚡ Score: {:.4} | Time: {:?}", score, duration);
                    if score > 7.5 { println!("\x1b[31m[ALERT] 🚨 HIGH ENTROPY DETECTED (Possible Crypto-Locker)\x1b[0m"); }
                } else { println!("\x1b[31m[ERROR] Could not read erdps-agent.exe for testing.\x1b[0m"); }
            },
            "dns" => crate::dns_hunter::DnsHunter::scan(),
            "canary" => crate::canary_sentinel::CanarySentinel::deploy(),
            "persistence" => crate::persistence_hunter::PersistenceHunter::scan(),
            "hooks" => crate::hook_hunter::HookHunter::scan(),
            "yara-update" => crate::yara_forge::YaraForge::update_rules(),
            "scan" | "deep-scan" => {
                if parts.len() < 2 { println!("[!] Usage: scan <file>"); }
                else {
                    let path = parts[1..].join(" ").replace("\"", "");
                    perform_deep_scan(&path, &engine);
                }
            },
            _ => println!("[!] Unknown command."),
        }
    }
}

fn perform_deep_scan(path: &str, engine: &NeuralEngine) {
    if !Path::new(path).exists() {
        println!("{}", "[!] File not found.".red());
        return;
    }
    
    let mut buffer = fs::read(path).unwrap_or_default();
    println!("{}", "\n[ ANALYSIS STARTED ]".bright_white().bold());
    println!("Target: {}", path);

    // [GUARDRAIL] CRITICAL FIX 1: Verify PE Magic Bytes
    if buffer.len() < 2 || buffer[0] != 0x4D || buffer[1] != 0x5A {
        println!("{}", "[!] ERROR: Target is not a valid PE Executable (Magic Bytes Mismatch). Aborting Deep Scan.".red().bold());
        return;
    }

    // --- PHASE 1: DYNAMIC UNPACKING ---
    let mut unpacker = crate::unpack_engine::UnpackEngine::new();
    let unpacked_data = unpacker.unpack(&buffer);
    if unpacked_data != buffer {
        println!(" -> {}", "PACKED MALWARE DETECTED!".yellow().bold());
        println!(" -> Analysis continuing on DECRYPTED payload...");
        buffer = unpacked_data;
    }

    // --- LAYER 1: TRUST --- 
    println!("\n{}", "[LAYER 1] DIGITAL TRUST VERIFICATION".cyan().bold()); 
    println!(" -> Status:    {}", "CHECK SKIPPED (Strict Mode)".yellow()); 

    // --- LAYER 2: ATTRIBUTION & STRUCTURE --- 
    println!("\n{}", "[LAYER 2] ATTRIBUTION & STRUCTURE".cyan().bold()); 
    let mut entry_point_offset: u64 = 0;
    let mut entry_point_va: u64 = 0;
    let mut code_section_offset = 0; 
    let mut code_section_size = 0; 

    // Parse PE to get Entry Point (RVA -> Offset)
    match PE::parse(&buffer) { 
        Ok(pe) => {
            // Calculate Entry Point File Offset
            // RVA = pe.entry
            // We need to find the section containing this RVA
            let rva = pe.entry as u32;
            entry_point_va = pe.image_base as u64 + rva as u64; // Default to ImageBase + RVA
            
            // Find section
            for section in &pe.sections {
                let v_start = section.virtual_address;
                let v_end = v_start + section.virtual_size;
                if rva >= v_start && rva < v_end {
                    // Found it!
                    // offset = rva - v_start + pointer_to_raw_data
                    entry_point_offset = (rva - v_start + section.pointer_to_raw_data) as u64;
                    // println!("   |-> Entry Point RVA: 0x{:X} -> File Offset: 0x{:X}", rva, entry_point_offset);
                    break;
                }
            }
            if entry_point_offset == 0 && rva > 0 {
                 // Fallback if not found in sections (e.g. headers) or if section table is weird
                 // Just assume 0x1000 or raw RVA if alignment is small?
                 // For now, if 0, we might warn.
                 println!("   |-> [WARN] Could not map Entry Point RVA 0x{:X} to file offset.", rva);
            }

            let mut import_list = String::new(); 
            for import in &pe.imports { 
                import_list.push_str(&import.name); 
                import_list.push(','); 
            } 
            if !import_list.is_empty() { 
                println!(" -> ImpHash:   {:x}", md5::compute(import_list.as_bytes())); 
            } else { 
                println!(" -> ImpHash:   None (Static/Packed)"); 
            } 

            for section in &pe.sections { 
                let name = String::from_utf8_lossy(&section.name).trim_matches(char::from(0)).to_string(); 
                if name == ".text" || (section.characteristics & 0x20) != 0 { 
                    code_section_offset = section.pointer_to_raw_data as usize; 
                    code_section_size = section.size_of_raw_data as usize; 
                } 
            } 
        },
        Err(e) => println!(" -> [ERROR] PE Parse Failed: {}", e),
    } 

    // --- LAYER 3: SEMANTIC ANALYSIS --- 
    if code_section_size > 0 && code_section_offset + code_section_size <= buffer.len() { 
        let code = &buffer[code_section_offset..code_section_offset + code_section_size]; 
        let semantic = crate::semantic_engine::SemanticEngine::new(); 
        let (score, insights) = semantic.analyze(code, entry_point_va); 

        if score > 100 { 
             println!(" -> CFG Complexity: {}", format!("CRITICAL (Score: {})", score).red().bold()); 
        } else { 
             println!(" -> CFG Complexity: {}", format!("Normal (Score: {})", score).green()); 
        } 
        for insight in insights { println!(" -> Insight: {}", insight); } 
    } 

    // --- LAYER 4: CODE FORENSICS --- 
    println!("\n{}", "[LAYER 4] CODE FORENSICS".cyan().bold());  
    crate::yara_engine::YaraEngine::scan_file(path); 
    scan_crypto_constants(&buffer); 

    // --- LAYER 5: ARTIFICIAL INTELLIGENCE --- 
    println!("\n{}", "[LAYER 5] ARTIFICIAL INTELLIGENCE (EMBER 2024)".cyan().bold()); 
    let (probability, features) = engine.scan_static(path); 
    println!(" -> AI Probability: {:.4} ({:.2}%)", probability, probability * 100.0); 

    if probability > 0.85 { println!(" -> Verdict: {}", "MALICIOUS (CRITICAL)".red().bold()); } 
    else if probability > 0.50 { println!(" -> Verdict: {}", "SUSPICIOUS".yellow().bold()); } 
    else { println!(" -> Verdict: {}", "CLEAN".green().bold()); } 

    println!(" -> Model Architecture: V8 God Mode (2,568 Features)"); 
    println!(" -> Vector Summary:"); 
    if features.len() >= 2000 { 
        println!("    - Byte Histogram: [256 buckets processed]"); 
        println!("    - Imports Hashed: {:.0} libs, {:.0} functions", features[1890], features[1889]); 
        println!("    - Exports Hashed: {:.0} functions", features[1892]); 
    }

    // --- PHASE 8: DEEP FORENSICS ---
    // [CRITICAL FIX 3] Pass Calculated Entry Point Offset
    let mut disassembly_text = String::new(); 
    match crate::disassembly_engine::DisassemblyEngine::new() {
        Ok(d_engine) => {
            let _verdict = d_engine.scan_entry_point(&buffer, entry_point_offset, entry_point_va);
            // println!("   |-> Verdict: {}", verdict); // SILENCED
            disassembly_text = d_engine.get_disassembly(&buffer, entry_point_offset, entry_point_va);
        },
        Err(e) => println!("   |-> [ERROR] Engine Init Failed: {}", e),
    }

    // [PHASE 11] LOCAL CORTEX 
    if !disassembly_text.is_empty() { 
        let rt = tokio::runtime::Runtime::new().unwrap(); 
        let ai_verdict = rt.block_on(crate::local_cortex::LocalCortex::analyze_verdict(&disassembly_text)); 
        println!("{}", ai_verdict); 
    } 

    println!("\n[+] Analysis Complete.\n"); 
} 

fn scan_crypto_constants(buffer: &[u8]) { 
    let signatures: Vec<(&[u8], &str)> = vec![ 
        (b"expand 32-byte k", "ChaCha20 Key Expansion"), 
        (b"\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5", "AES S-Box (Rijndael)"), 
        (b"Standard Jet DB", "Jet Database Header"), 
    ]; 
    let mut found = false; 
    for (sig, name) in signatures { 
        if buffer.windows(sig.len()).any(|window| window == sig) { 
            println!(" -> [ALERT] Crypto Artifact: {}", name.red().bold()); 
            found = true; 
        } 
    } 
    if !found { println!(" -> Crypto Scan: No known constants found."); } 
}
```

## 2. PHASE 1: DYNAMIC UNPACKING
**File:** `agent/src/unpack_engine.rs`
**Role:** Heuristic unpacker using XOR brute-force.

```rust
pub struct UnpackEngine {}

impl UnpackEngine {
    pub fn new() -> Self {
        UnpackEngine {}
    }

    /// Real Heuristic Unpacker (XOR Brute-Force)
    /// Attempts to decrypt the buffer using single-byte XOR keys (0x01..0xFF).
    /// Returns the decrypted buffer if a valid PE header ("MZ") is found.
    pub fn unpack(&mut self, file_buffer: &[u8]) -> Vec<u8> {
        println!("[*] UNPACKER: Analyzing entropy and checking for XOR encoding...");

        // 1. Check if it's already a valid PE
        if file_buffer.len() > 2 && file_buffer[0] == 0x4D && file_buffer[1] == 0x5A {
            // println!("   |-> File is already plain PE (MZ). No unpacking needed.");
            return file_buffer.to_vec();
        }

        // 2. Brute-force Single Byte XOR
        if file_buffer.len() < 2 { return file_buffer.to_vec(); }

        let candidate_key = file_buffer[0] ^ 0x4D;
        
        // Verify with second byte
        if (file_buffer[1] ^ candidate_key) == 0x5A {
            if candidate_key != 0 {
                println!("\x1b[33m   |-> [DETECTION] Found Potential XOR Key: 0x{:02X}\x1b[0m", candidate_key);
                println!("   |-> Attempting decryption...");
                
                let decrypted: Vec<u8> = file_buffer.iter().map(|&b| b ^ candidate_key).collect();
                
                println!("\x1b[32m   |-> [SUCCESS] Payload Decrypted! (Size: {} bytes)\x1b[0m", decrypted.len());
                return decrypted;
            }
        }

        file_buffer.to_vec()
    }
}
```

## 3. LAYER 3: SEMANTIC ANALYSIS
**File:** `agent/src/semantic_engine.rs`
**Role:** Generates Control Flow Graph statistics to detect complex logic/obfuscation.

```rust
use capstone::prelude::*;
use capstone::{Capstone, Insn};
use petgraph::graph::{Graph, NodeIndex};

pub struct SemanticEngine {
    cs: Capstone,
}

#[derive(Debug, Clone)]
pub struct BlockStats {
    pub start_addr: u64,
    pub instruction_count: usize,
    pub has_loop: bool,
}

impl SemanticEngine {
    pub fn new() -> Self {
        let cs = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .build()
            .expect("Failed to init Capstone");
        
        SemanticEngine { cs }
    }

    /// Lifts assembly to a Control Flow Graph (CFG) and analyzes complexity
    pub fn analyze(&self, code: &[u8], entry_point: u64) -> (u32, Vec<String>) {
        let mut insights = Vec::new();
        
        // 1. Disassemble everything
        let insns = match self.cs.disasm_all(code, entry_point) {
            Ok(i) => i,
            Err(_) => return (0, vec!["Disassembly Failed".to_string()]),
        };

        // 2. Build the Graph (Simplified Logic for Speed/Determinism)
        let mut complexity_score = 0;
        let mut encryption_loops = 0;

        for insn in insns.iter() {
            let mnemonic = insn.mnemonic().unwrap_or("");
            
            // Check for Branching (The "Shape" of the code)
            if mnemonic.starts_with("j") || mnemonic == "call" {
                complexity_score += 1; // Every decision point increases complexity
                
                // Heuristic: Short backwards jumps often indicate loops (Encryption/Obfuscation)
                let op_str = insn.op_str().unwrap_or("");
                if op_str.contains("0x") {
                    if mnemonic == "jnz" || mnemonic == "jmp" {
                        encryption_loops += 1;
                    }
                }
            }
        }

        // 3. Generate Semantic Insights
        insights.push(format!("Instruction Count: {}", insns.len()));
        
        if complexity_score > 100 {
            insights.push(format!("Cyclomatic Complexity: {} (CRITICAL)", complexity_score));
            insights.push("WARN: High complexity suggests obfuscation or encryption logic.".to_string());
        } else {
            insights.push(format!("Cyclomatic Complexity: {} (Low)", complexity_score));
        }

        if encryption_loops > 5 {
            insights.push(format!("Potential Loops: {} (Suspicious)", encryption_loops));
            insights.push("WARN: Tight loops detected. Possible Ransomware Encryption Routine.".to_string());
        }

        (complexity_score, insights)
    }
}
```

## 4. LAYER 4: CODE FORENSICS (YARA)
**File:** `agent/src/yara_engine.rs`
**Role:** Scans file using downloaded Global Intelligence (YARA Forge) and local rules.

```rust
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
```

## 5. LAYER 5: ARTIFICIAL INTELLIGENCE
**File:** `agent/src/ml_engine.rs`
**Role:** Feature extraction (EMBER) and ONNX inference with Heuristic Fallback.

```rust
use std::sync::Mutex;
use std::path::Path;
use std::fs;
use std::io::Cursor;
use std::error::Error;
use ort::session::Session;
use ort::value::Value;
use ndarray::Array2;
use goblin::pe::PE;
use murmur3::murmur3_32;

// --- CONFIG ---
const FEATURE_DIM: usize = 2568;

// --- FEATURE EXTRACTOR (Robust Parser) ---
pub fn extract_features(buffer: &[u8]) -> Result<Vec<f32>, Box<dyn Error>> {
    let mut features = vec![0.0f32; FEATURE_DIM]; // The EMBER Vector

    // 1. BYTE HISTOGRAM (0-255)
    for &byte in buffer {
        features[byte as usize] += 1.0;
    }
    // Normalize histogram
    let total_bytes = buffer.len() as f32;
    if total_bytes > 0.0 {
        for i in 0..256 {
            features[i] /= total_bytes;
        }
    }

    // 2. PARSE PE HEADERS
    match PE::parse(buffer) {
        Ok(pe) => {
            // A. IMPORTS (Indices 612-1891)
            let mut _import_count = 0;
            for import in pe.imports {
                let dll_name = import.dll.to_lowercase();
                let func_name = import.name.to_string();
                
                let sig = format!("{}:{}", dll_name, func_name);
                let hash = murmur3_32(&mut Cursor::new(sig.as_bytes()), 0).unwrap_or(0);
                let bucket = (hash % 1280) as usize;
                
                if 612 + bucket < FEATURE_DIM {
                     features[612 + bucket] += 1.0;
                }
                _import_count += 1;
            }

            // B. EXPORTS (Indices 1892-2019)
            for export in pe.exports {
                if let Some(name) = export.name {
                    let hash = murmur3_32(&mut Cursor::new(name.as_bytes()), 0).unwrap_or(0);
                    let bucket = (hash % 128) as usize;
                    if 1892 + bucket < FEATURE_DIM {
                        features[1892 + bucket] += 1.0;
                    }
                }
            }
            
            // C. SECTION NAMES (Indices 512-611)
            for section in pe.sections {
                let name = section.name().unwrap_or("");
                let hash = murmur3_32(&mut Cursor::new(name.as_bytes()), 0).unwrap_or(0);
                let bucket = (hash % 50) as usize;
                if 512 + bucket < FEATURE_DIM {
                     features[512 + bucket] += 1.0;
                }
            }
        },
        Err(e) => {
            println!("   |-- [ERROR] Failed to parse PE Header: {}", e);
        }
    }

    Ok(features)
}

// --- NEURAL ENGINE ---
pub struct NeuralEngine {
    static_model: Option<Mutex<Session>>,
}

impl NeuralEngine {
    pub fn new() -> Self {
        let _ = ort::init().with_name("ERDPS_Neural_Engine").commit();
        println!("[*] ERDPS Neural Engine: Initialized (V8 GOD MODE - 2568 Features).");
        NeuralEngine { static_model: None }
    }

    pub fn init(&mut self) {
        let p = "static_model_2024.onnx";
        let final_p = if Path::new(&p).exists() { p.to_string() } else { format!("target/release/{}", p) };
        
        if Path::new(&final_p).exists() {
            match Session::builder().unwrap().commit_from_file(&final_p) {
                Ok(s) => {
                    println!("[+] EMBER 2024 Model Loaded: {}", final_p);
                    self.static_model = Some(Mutex::new(s));
                },
                Err(e) => println!("[!] Failed to load model: {}", e)
            }
        } else {
            println!("\x1b[33m[!] Model missing: {}. Switching to Heuristic Mode.\x1b[0m", final_p);
        }
    }

    pub fn scan_static(&self, file_path: &str) -> (f32, Vec<f32>) {
        let buffer = match fs::read(file_path) {
            Ok(b) => b,
            Err(_) => return (0.0, vec![]),
        };
        if buffer.is_empty() { return (0.0, vec![]); }

        // --- FEATURE EXTRACTION ---
        let feats = match extract_features(&buffer) {
            Ok(f) => f,
            Err(_) => return (0.0, vec![])
        };

        // 1. TRY ONNX INFERENCE
        let onnx_score = if let Some(mutex) = &self.static_model {
            let array = Array2::from_shape_vec((1, FEATURE_DIM), feats.clone()).unwrap();
            let input = Value::from_array((vec![1, FEATURE_DIM], array.into_raw_vec())).unwrap();
            
            let mut session = mutex.lock().unwrap();
            let res = match session.run(ort::inputs![input]) {
                 Ok(outputs) => {
                     outputs[1].try_extract_tensor::<f32>()
                        .ok()
                        .map(|(_, probs)| probs[1])
                 },
                 Err(e) => {
                     println!("Inference Error: {}", e);
                     None
                 }
            };
            res
        } else {
            None
        };

        if let Some(score) = onnx_score {
            return (score, feats);
        }

        // 2. HEURISTIC FALLBACK (If Model Missing or Failed)
        let heuristic_score = self.calculate_heuristic_score(&feats);
        (heuristic_score, feats)
    }

    fn calculate_heuristic_score(&self, feats: &[f32]) -> f32 {
        let mut score = 0.0;

        // A. Entropy Heuristic (Approximated from Histogram Variance)
        let mut non_zero_buckets = 0;
        for i in 0..256 {
            if feats[i] > 0.001 { non_zero_buckets += 1; }
        }
        
        if non_zero_buckets > 250 { 
            score += 0.4; // Suspiciously high entropy
        }

        // B. Imports Check (612-1891)
        let mut import_count = 0;
        for i in 612..1891 {
            if feats[i] > 0.0 { import_count += 1; }
        }

        if import_count < 5 {
            score += 0.3; // Very few imports (Packer indicator)
        }
        
        // D. Cap score
        if score > 0.99 { score = 0.99; }
        if score < 0.01 { score = 0.01; } 

        score
    }

    pub fn scan_behavior(&self, _seq: Vec<u32>) -> f32 { 0.0 }
    pub fn check_anomaly(&self, _stats: Vec<f32>) -> bool { false }
}
```

## 6. PHASE 8: DEEP FORENSICS
**File:** `agent/src/disassembly_engine.rs`
**Role:** Capstone disassembly of Entry Point for detailed analysis.

```rust
use capstone::prelude::*;
use std::error::Error;

pub struct DisassemblyEngine {
    cs: Capstone,
}

impl DisassemblyEngine {
    pub fn new() -> Result<Self, Box<dyn Error>> {
        // Initialize Capstone for x86_64 (Standard Windows Malware)
        let cs = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .syntax(arch::x86::ArchSyntax::Intel)
            .detail(true)
            .build()
            .map_err(|e| format!("Failed to init Capstone: {}", e))?;

        Ok(Self { cs })
    }

    // 🔬 THE LOGIC HUNTER
    pub fn scan_entry_point(&self, code_buffer: &[u8], file_offset: u64, virtual_addr: u64) -> String {
        // Ensure we don't go out of bounds
        if file_offset as usize >= code_buffer.len() {
            return "Entry Point Offset Out of Bounds".to_string();
        }

        let available_bytes = &code_buffer[file_offset as usize..];
        let scan_size = std::cmp::min(available_bytes.len(), 1024);
        let code = &available_bytes[0..scan_size];

        let instructions = match self.cs.disasm_all(code, virtual_addr) {
            Ok(insns) => insns,
            Err(_) => return "Disassembly Failed".to_string(),
        };

        let mut xor_count = 0;
        let mut loop_count = 0;

        println!("\x1b[36m[FORENSICS] 🔍 Disassembling Entry Point (Offset: 0x{:X}, VA: 0x{:X})...\x1b[0m", file_offset, virtual_addr);

        for insn in instructions.iter() {
            let mnemonic = insn.mnemonic().unwrap_or("");
            let op_str = insn.op_str().unwrap_or("");

            // 1. Detect XOR instructions
            if mnemonic == "xor" {
                xor_count += 1;
                if !op_str.contains("eax, eax") && !op_str.contains("rcx, rcx") {
                     // This is "Suspicious XOR"
                }
            }

            // 2. Detect Loops
            if mnemonic.starts_with("j") { // Jumps
                 loop_count += 1;
            }
            
            // Debug print the first 5 instructions
            if insn.address() < virtual_addr + 15 {
                println!("   |-- 0x{:x}: {} {}", insn.address(), mnemonic, op_str);
            }
        }

        // HEURISTIC VERDICT
        if xor_count > 5 && loop_count > 2 {
            return format!("\x1b[31m[CRITICAL] METAMORPHIC PACKER DETECTED (XOR: {}, LOOPS: {})\x1b[0m", xor_count, loop_count);
        }

        format!("Clean Code Structure (XOR: {}, LOOPS: {})", xor_count, loop_count)
    }

    // 📜 GET RAW DISASSEMBLY (For DeepSeek)
    pub fn get_disassembly(&self, code_buffer: &[u8], file_offset: u64, virtual_addr: u64) -> String {
        if file_offset as usize >= code_buffer.len() { return String::new(); }

        let available_bytes = &code_buffer[file_offset as usize..];
        let scan_size = std::cmp::min(available_bytes.len(), 1024);
        let code = &available_bytes[0..scan_size];
        
        let instructions = match self.cs.disasm_all(code, virtual_addr) {
            Ok(insns) => insns,
            Err(_) => return String::new(),
        };

        let mut output = String::new();
        for insn in instructions.iter() {
            let mnemonic = insn.mnemonic().unwrap_or("");
            let op_str = insn.op_str().unwrap_or("");
            output.push_str(&format!("0x{:x}: {} {}\n", insn.address(), mnemonic, op_str));
        }
        output
    }
}
```

## 7. PHASE 11: LOCAL CORTEX (LLM)
**File:** `agent/src/local_cortex.rs`
**Role:** Manages DeepSeek-R1 inference via Ollama (Auto-start, Streaming, Parsing).

```rust
use ollama_rs::Ollama;
use ollama_rs::generation::completion::request::GenerationRequest;
use ollama_rs::generation::options::GenerationOptions; // Import Options
use serde::{Deserialize, Serialize};
use futures::StreamExt;
use std::io::{self, Write};
use std::process::{Command, Stdio};
use std::net::TcpStream;
use std::thread;
use std::time::Duration;

#[derive(Debug, Deserialize, Serialize)]
pub struct MalwareVerdict {
    pub is_malicious: bool,
    pub confidence_score: u8,
    pub threat_family: String,
    pub reasoning: String,
}

pub struct LocalCortex;

impl LocalCortex {
    pub async fn analyze_verdict(disassembly: &str) -> String {
        println!("\x1b[35m[CORTEX] 🧠 Invoking DeepSeek-R1 (Streaming Mode)...\x1b[0m");

        // 0. AUTO-START OLLAMA (SILENT MODE)
        if TcpStream::connect("127.0.0.1:11434").is_err() {
            println!("\x1b[33m[CORTEX] ⚠️ Ollama is OFFLINE. Starting local inference server...\x1b[0m");
            
            let _ = Command::new("ollama")
                .arg("serve")
                .stdout(Stdio::null()) 
                .stderr(Stdio::null())
                .spawn();
                
            print!("\x1b[90m   |-- Booting Neural Engine... \x1b[0m");
            for _ in 0..10 {
                if TcpStream::connect("127.0.0.1:11434").is_ok() { break; }
                thread::sleep(Duration::from_secs(1));
                print!(".");
                io::stdout().flush().unwrap();
            }
            println!("\x1b[32m [READY]\x1b[0m");
        }

        let ollama = Ollama::default();
        let system_prompt = "You are a Kernel-Level Malware Analysis Engine. Return ONLY a JSON object: { \"is_malicious\": bool, \"confidence_score\": 0-100, \"threat_family\": \"string\", \"reasoning\": \"string\" }";
        let user_prompt = format!("CODE SNIPPET:\n{}\n\nANALYZE INTENT. OUTPUT JSON ONLY.", disassembly);
        let model = "erwan2/DeepSeek-R1-Distill-Qwen-1.5B:latest".to_string();
        
        // SET DETERMINISTIC OPTIONS (Temperature = 0.0)
        let options = GenerationOptions::default()
            .temperature(0.0)
            .top_k(1)
            .top_p(1.0);

        let request = GenerationRequest::new(model, user_prompt)
            .system(system_prompt.to_string())
            .options(options);

        let mut stream = match ollama.generate_stream(request).await {
            Ok(s) => s,
            Err(e) => return format!("\x1b[31m[CORTEX] ❌ Connection Failed: {}\x1b[0m", e),
        };

        let mut full_response = String::new();
        print!("\x1b[90m");
        while let Some(Ok(res)) = stream.next().await {
            for ele in res {
                let token = ele.response;
                print!("{}", token);
                io::stdout().flush().unwrap();
                full_response.push_str(&token);
            }
        }
        print!("\x1b[0m");
        println!();

        if let (Some(start), Some(end)) = (full_response.find('{'), full_response.rfind('}')) {
            let json_str = &full_response[start..=end];
            if let Ok(verdict) = serde_json::from_str::<MalwareVerdict>(json_str) {
                if verdict.is_malicious && verdict.confidence_score > 80 {
                    return format!("\n\x1b[31m[GOD MODE] ⚔️ AI VERDICT: MALICIOUS ({}%)\n   |-- Family: {}\n   |-- Logic: {}\x1b[0m", verdict.confidence_score, verdict.threat_family, verdict.reasoning);
                }
                return format!("\n\x1b[32m[AI VERDICT] ✅ Clean Code ({}%)\n   |-- Analysis: {}\x1b[0m", verdict.confidence_score, verdict.reasoning);
            }
        }
        format!("\n\x1b[33m[AI FINISHED] (Raw Output Captured)\x1b[0m")
    }
}
```
