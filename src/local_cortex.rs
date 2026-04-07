use ollama_rs::Ollama; 
use ollama_rs::generation::completion::request::GenerationRequest; 
use ollama_rs::generation::options::GenerationOptions; 
use ollama_rs::generation::parameters::FormatType; 
use serde::{Deserialize, Serialize}; 
use std::time::Instant; 

#[derive(Debug, Deserialize, Serialize, Clone)] 
pub struct SniperVerdict { 
    pub is_malicious: bool, 
    pub risk_level: String, 
    pub confidence: u8, 
    pub threat_family: String, 
    pub key_evidence: String, 
} 

pub struct LocalCortex; 

impl LocalCortex { 
    pub async fn analyze_sniper(sniper_data: &str) -> String { 
        println!("\x1b[35m[CORTEX] ⚡ Invoking Qwen2.5 (Universal Mode)...\x1b[0m"); 
        let start_time = Instant::now(); 

        let ollama = Ollama::default(); 
        let model = "qwen2.5-coder:1.5b".to_string(); 

        // UPDATED PROMPT: Handles both Binary Metadata AND Source Code 
        let system_prompt = r#"You are a Malware Analyst. 
        Analyze the provided Data (Imports, Assembly, or Source Code). 
        
        RULES: 
        - Executables: Look for Crypto/Network APIs. 
        - Scripts: Look for dangerous commands (eval, exec, subprocess, downloading). 
        - Text: Look for phishing keywords or malicious strings. 

        Output JSON ONLY: { "is_malicious": bool, "risk_level": "string", "confidence": int, "threat_family": "string", "key_evidence": "string" }"#; 

        let user_prompt = format!("DATA TO ANALYZE:\n{}\n\nVERDICT:", sniper_data); 

        let request = GenerationRequest::new(model, user_prompt) 
            .system(system_prompt.to_string()) 
            .format(FormatType::Json) 
            .options(GenerationOptions::default().temperature(0.0)); 

        match ollama.generate(request).await { 
            Ok(res) => { 
                let elapsed = start_time.elapsed(); 
                if let Ok(verdict) = serde_json::from_str::<SniperVerdict>(&res.response) { 
                    if verdict.is_malicious { 
                        return format!("\n\x1b[31m[GOD MODE] ⚔️ AI VERDICT: MALICIOUS ({}%)\n   |-- Time: {:.2?}s\n   |-- Family: {}\n   |-- Risk: {}\n   |-- Logic: {}\x1b[0m", 
                            verdict.confidence, elapsed, verdict.threat_family, verdict.risk_level, verdict.key_evidence); 
                    } else { 
                        return format!("\n\x1b[32m[AI VERDICT] ✅ Clean Code ({:.2?}s)\n   |-- Analysis: {}\x1b[0m", elapsed, verdict.key_evidence); 
                    } 
                } 
                format!("\n\x1b[33m[AI ERROR] Invalid JSON Output ({:.2?}s)\x1b[0m", elapsed) 
            }, 
            Err(_) => format!("\n\x1b[31m[API ERROR] Could not connect to Ollama.\n   |-- Please ensure 'ollama serve' is running.\x1b[0m"), 
        } 
    } 
}