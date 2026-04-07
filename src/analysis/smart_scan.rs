use capstone::prelude::*;
use yara_x::{Compiler, Scanner};
use std::fs;
use console::style;
use super::ai_manager::AiManager;

pub struct AnalysisResult {
    pub yara_matches: Vec<String>,
    pub assembly_snippet: String,
    pub risk_score: u8,
    pub ai_verdict: String,
}

pub async fn perform_smart_scan(file_path: &str) -> AnalysisResult {
    let mut risk = 0;
    let mut matches = Vec::new();

    // --- 1. YARA SCAN (Signatures) ---
    let rules_str = r#"
        rule Suspicious_Encryption {
            strings:
                $s1 = "encrypt" nocase
                $s2 = "ransom" nocase
            condition:
                any of them
        }
    "#;
    
    let mut compiler = Compiler::new();
    if compiler.add_source(rules_str).is_ok() {
        let rules = compiler.build();
        let mut scanner = Scanner::new(&rules);
        
        if let Ok(file_content) = fs::read(file_path) {
            if let Ok(scan_res) = scanner.scan(&file_content) {
                for r in scan_res.matching_rules() {
                    matches.push(r.identifier().to_string());
                    risk += 30;
                }
            }
        }
    }

    // --- 2. DISASSEMBLY (Capstone) ---
    let mut asm_dump = String::new();
    if let Ok(bytes) = fs::read(file_path) {
        let slice = if bytes.len() > 1024 { &bytes[0..1024] } else { &bytes };
        
        let cs = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .build()
            .unwrap_or_else(|_| panic!("Capstone Init Failed"));

        // Use a block to ensure instructions are dropped before cs
        {
            if let Ok(insns) = cs.disasm_all(slice, 0x1000) {
                for i in insns.iter() {
                    let mnemonic = i.mnemonic().unwrap_or("");
                    let op = i.op_str().unwrap_or("");
                    asm_dump.push_str(&format!("{} {}\n", mnemonic, op));
                    
                    if mnemonic == "xor" { risk += 2; }
                }
            };
        }
    }

    // --- 3. REAL AI ANALYSIS (Strict Mode) ---
    println!("    [AI] Initializing DeepSeek Engine...");
    let mut ai_verdict = "OFFLINE".to_string();

    let ai = AiManager::new("deepseek-r1:1.5b");

    if ai.ensure_active().await {
        // [FIX] New Prompt: Forces a specific output format we can trust
        let prompt = format!(
            "Analyze this assembly code for ransomware behavior (Encryption loops, Ransom notes). \
             If MALICIOUS, output ONLY: ##VERDICT_MALICIOUS## \
             If BENIGN, output ONLY: ##VERDICT_BENIGN## \
             Do not provide explanations. \n\nCode:\n{}",
            asm_dump.chars().take(1000).collect::<String>()
        );

        let verdict = ai.ask(prompt).await;
        
        // [FIX] New Logic: Relaxed matching (No '##' requirement)
        // DEBUG: Prove to user this is real
        println!("    [DEBUG] AI Raw Response: {}", style(&verdict).dim());

        let v_upper = verdict.to_uppercase();
        
        if v_upper.contains("VERDICT_MALICIOUS") || v_upper.contains("MALICIOUS") {
            println!("    [AI VERDICT] {}", style("MALICIOUS").red().bold());
            risk += 50;
            ai_verdict = "MALICIOUS".to_string();
        } else if v_upper.contains("VERDICT_BENIGN") || v_upper.contains("BENIGN") {
            println!("    [AI VERDICT] {}", style("BENIGN").green().bold());
            // Trust the AI: Lower the risk significantly if it says benign
            if risk > 20 { risk -= 20; }
            ai_verdict = "BENIGN".to_string();
        } else {
            println!("    [AI VERDICT] {}", style("UNCERTAIN (Response Unclear)").yellow());
            ai_verdict = "UNCERTAIN".to_string();
        }
    } else {
        println!("    [!] AI Engine Critical Failure. Proceeding with static analysis only.");
    }

    AnalysisResult {
        yara_matches: matches,
        assembly_snippet: asm_dump.chars().take(200).collect(),
        risk_score: risk.min(100),
        ai_verdict,
    }
}
