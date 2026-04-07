use goblin::pe::PE; 
use capstone::prelude::*; 
use std::error::Error; 

pub struct SniperEngine; 

impl SniperEngine { 
    pub fn extract_metadata(buffer: &[u8]) -> Result<String, Box<dyn Error>> { 
        // 1. ATTEMPT PE PARSE (Sniper Mode) 
        if let Ok(pe) = PE::parse(buffer) { 
            let mut report = String::new(); 

            // A. CAPABILITIES 
            report.push_str("--- [MODE: BINARY] IMPORTED CAPABILITIES ---\n"); 
            for import in pe.imports.iter() { 
                report.push_str(&format!("DLL: {} -> {}\n", import.dll, import.name)); 
            } 

            // B. STARTUP LOGIC 
            report.push_str("\n--- ENTRY POINT BEHAVIOR ---\n"); 
            let entry_addr = pe.entry as u64; 
            
            // Find Code Section 
            let mut code_bytes: &[u8] = &[]; 
            for section in pe.sections { 
                let v_start = section.virtual_address as u64; 
                let v_end = v_start + section.virtual_size as u64; 
                if entry_addr >= v_start && entry_addr < v_end { 
                    let offset = (entry_addr - v_start) as usize; 
                    let raw_start = section.pointer_to_raw_data as usize + offset; 
                    let raw_size = section.size_of_raw_data as usize; 
                    if raw_start < buffer.len() { 
                        let safe_end = std::cmp::min(raw_start + 512, raw_start + raw_size); 
                        if safe_end <= buffer.len() { code_bytes = &buffer[raw_start..safe_end]; } 
                    } 
                    break; 
                } 
            } 

            if !code_bytes.is_empty() { 
                let cs = Capstone::new().x86().mode(arch::x86::ArchMode::Mode64).build().map_err(|e| format!("{}", e))?; 
                let instructions = cs.disasm_count(code_bytes, entry_addr, 30);
                if let Ok(insns) = instructions { 
                    for i in insns.iter() { 
                        report.push_str(&format!("0x{:x}: {} {}\n", i.address(), i.mnemonic().unwrap_or(""), i.op_str().unwrap_or(""))); 
                    } 
                } 
            } 
            return Ok(report); 
        } 

        // 2. FALLBACK: TEXT/SCRIPT MODE 
        // If it's not a PE file, check if it's readable text (Scripts, HTML, Source Code) 
        // We take the first 2KB to avoid flooding the AI. 
        let scan_len = std::cmp::min(buffer.len(), 2048); 
        if let Ok(text_content) = std::str::from_utf8(&buffer[0..scan_len]) { 
            return Ok(format!("--- [MODE: SOURCE CODE/TEXT] ---\n{}", text_content)); 
        } 

        // 3. FALLBACK: UNKNOWN BINARY 
        Ok("--- [MODE: RAW DATA] Unknown Binary Format ---".to_string()) 
    } 
}