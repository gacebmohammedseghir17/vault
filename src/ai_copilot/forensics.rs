use std::fs;
use std::path::Path;
use crate::ai_copilot::client::AiCopilot;
use goblin::pe::PE;
use iced_x86::{Decoder, DecoderOptions, Formatter, IntelFormatter, Instruction};

pub fn perform_ai_forensics(file_path: &str) {
    println!("\n\x1b[36m[AI FORENSICS] 🔍 Initializing AI Copilot Analysis for: {}\x1b[0m", file_path);

    let path = Path::new(file_path);
    if !path.exists() {
        println!("\x1b[31m[!] Error: File does not exist at path: {}\x1b[0m", file_path);
        return;
    }

    let file_bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            println!("\x1b[31m[!] Error reading file: {}\x1b[0m", e);
            return;
        }
    };

    let file_name = path.file_name().unwrap_or_default().to_string_lossy();
    let file_size = file_bytes.len();
    
    // Extract PE info using existing pe_analyzer if possible, otherwise just use basic stats
    let mut extra_info = String::new();
    let analysis = crate::forensic::pe_analyzer::PeAnalyzer::analyze(file_path);
    if analysis.score > 0 || analysis.entropy > 0.0 {
        extra_info = format!(
            "File Entropy: {:.2}\nSuspicious Imports Detected: {}\nHigh Entropy: {}\nCapabilities Detected: {:?}\nExtracted IOCs: {:?}",
            analysis.entropy,
            analysis.has_injection_imports || analysis.has_crypto_imports,
            analysis.has_high_entropy,
            analysis.capabilities,
            analysis.extracted_iocs
        );
    } else {
        extra_info = "Not a valid PE file or analysis yielded no features.".to_string();
    }

    // Disassemble the first 50 instructions of the .text section
    let mut assembly_code = String::new();
    if let Ok(pe) = PE::parse(&file_bytes) {
        if let Some(text_section) = pe.sections.iter().find(|s| s.name().unwrap_or("") == ".text") {
            let start = text_section.pointer_to_raw_data as usize;
            let size = text_section.size_of_raw_data as usize;
            if start + size <= file_bytes.len() {
                let code = &file_bytes[start..start + size];
                let bitness = if pe.is_64 { 64 } else { 32 };
                let mut decoder = Decoder::with_ip(bitness, code, pe.image_base as u64 + text_section.virtual_address as u64, DecoderOptions::NONE);
                let mut formatter = IntelFormatter::new();
                let mut instruction = Instruction::default();
                let mut count = 0;
                
                assembly_code.push_str("\nDisassembly (First 50 Instructions):\n");
                while decoder.can_decode() && count < 50 {
                    decoder.decode_out(&mut instruction);
                    let mut inst_str = String::new();
                    formatter.format(&instruction, &mut inst_str);
                    assembly_code.push_str(&format!("{:016X} {}\n", instruction.ip(), inst_str));
                    count += 1;
                }
            }
        }
    }
    
    // Truncate the final assembly string to a maximum of 2000 characters
    if assembly_code.len() > 2000 {
        assembly_code.truncate(2000);
        assembly_code.push_str("\n...[TRUNCATED]...");
    }

    let prompt = format!(
        "You are an elite Malware Reverse Engineer. Analyze these assembly instructions, imports, and entropy. Is this malware? What type? Be concise. If you determine this file is malware, you MUST output a valid YARA rule to detect it inside a ```yara ... ``` code block at the end of your report.\n\
        You are an Autonomous EDR Agent. At the end of your analysis, you MUST output a JSON block formatted exactly like this:\n\
        ```json\n\
        {{\n\
          \"verdict\": \"MALICIOUS|BENIGN\",\n\
          \"confidence\": 0.0-1.0,\n\
          \"action\": \"KILL_PROCESS|LOG_ONLY\"\n\
        }}\n\
        ```\n\n\
        File Data:\n\
        Name: {}\n\
        Size: {} bytes\n\
        {}\n{}",
        file_name, file_size, extra_info, assembly_code
    );

    println!("\x1b[33m[AI FORENSICS] 📡 Sending metadata to DeepSeek AI...\x1b[0m");

    let copilot = match AiCopilot::new() {
        Ok(c) => c,
        Err(e) => {
            println!("\x1b[31m[!] Failed to initialize AI Copilot: {}\x1b[0m", e);
            return;
        }
    };

    match copilot.analyze_threat(&prompt) {
        Ok(report) => {
            println!("\n\x1b[32m=== [ 🧠 AI FORENSIC REPORT ] ===\x1b[0m");
            println!("{}", report);
            println!("\x1b[32m=================================\x1b[0m\n");

            // Extract YARA rule if present
            if let Some(yara_start) = report.find("```yara") {
                if let Some(yara_end_offset) = report[yara_start + 7..].find("```") {
                    let yara_content = &report[yara_start + 7..yara_start + 7 + yara_end_offset];
                    let yara_content = yara_content.trim();
                    
                    if !yara_content.is_empty() {
                        let rules_dir = std::path::Path::new("rules");
                        if !rules_dir.exists() {
                            let _ = std::fs::create_dir_all(rules_dir);
                        }
                        
                        let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
                        let rule_path = rules_dir.join(format!("auto_generated_{}.yar", timestamp));
                        
                        if std::fs::write(&rule_path, yara_content).is_ok() {
                            println!("\x1b[32;1m[+] AI AUTO-IMMUNITY: New YARA rule generated and saved! ({})\x1b[0m", rule_path.display());
                            
                            // SIEM Forwarder
                            crate::siem::siem_forwarder::push_alert(
                                "HIGH",
                                "AI_AUTO_IMMUNITY_YARA_GENERATED",
                                &format!("DeepSeek AI autonomously generated a YARA rule for: {}", file_name),
                                vec![rule_path.display().to_string()],
                            );
                        }
                    }
                }
            }

            // Extract Executioner JSON block
            if let Some(json_start) = report.find("```json") {
                if let Some(json_end_offset) = report[json_start + 7..].find("```") {
                    let json_content = &report[json_start + 7..json_start + 7 + json_end_offset];
                    let json_content = json_content.trim();
                    
                    if let Ok(verdict_data) = serde_json::from_str::<serde_json::Value>(json_content) {
                        let verdict = verdict_data["verdict"].as_str().unwrap_or("");
                        let confidence = verdict_data["confidence"].as_f64().unwrap_or(0.0);
                        let action = verdict_data["action"].as_str().unwrap_or("");
                        
                        if verdict == "MALICIOUS" && confidence >= 0.90 && action == "KILL_PROCESS" {
                            println!("\x1b[31;1m[!] AGENTIC AI COMMAND RECEIVED: Executing KILL_PROCESS with {} certainty.\x1b[0m", confidence);
                            
                            // Try to find the PID by process name to kill it
                            let mut sys = sysinfo::System::new();
                            sys.refresh_processes();
                            
                            for (pid, process) in sys.processes() {
                                let exe_path_str = process.exe().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
                                if process.name().to_lowercase() == file_name.to_lowercase() || 
                                   exe_path_str.to_lowercase() == file_path.to_lowercase() {
                                    crate::active_defense::ActiveDefense::engage_storyline_kill(pid.as_u32(), "Agentic AI Autonomous Kill Command");
                                    
                                    // SIEM Forwarder
                                    crate::siem::siem_forwarder::push_alert(
                                        "CRITICAL",
                                        "AI_EXECUTIONER_KILL",
                                        &format!("Agentic AI executed autonomous kill on {}. Verdict: MALICIOUS, Confidence: {}", file_name, confidence),
                                        vec![exe_path_str.clone()],
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
        Err(e) => {
            println!("\x1b[31m[!] AI Analysis failed: {}\x1b[0m", e);
        }
    }
}
