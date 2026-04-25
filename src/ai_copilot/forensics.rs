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

    let prompt = format!(
        "You are an elite Malware Reverse Engineer. Analyze these assembly instructions, imports, and entropy. Is this malware? What type? Be concise.\n\n\
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
        }
        Err(e) => {
            println!("\x1b[31m[!] AI Analysis failed: {}\x1b[0m", e);
        }
    }
}
