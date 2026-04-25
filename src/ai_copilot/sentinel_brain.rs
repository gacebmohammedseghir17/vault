use crate::ai_copilot::client::AiCopilot;

pub fn evaluate_process_behavior(process_name: &str, details: &str) -> bool {
    println!("\x1b[35m[AI SENTINEL] 🧠 Consulting DeepSeek AI for real-time process evaluation...\x1b[0m");
    println!("\x1b[35m[AI SENTINEL] Target: {} | Details: {}\x1b[0m", process_name, details);

    let prompt = format!(
        "A process named {} did {}. Is this malware? Reply ONLY with BLOCK or ALLOW.",
        process_name, details
    );

    let copilot = match AiCopilot::new() {
        Ok(c) => c,
        Err(e) => {
            println!("\x1b[31m[!] AI Copilot initialization failed: {}. Defaulting to STRICT BLOCK.\x1b[0m", e);
            return true;
        }
    };

    match copilot.analyze_threat(&prompt) {
        Ok(response) => {
            let response_clean = response.trim().to_uppercase();
            if response_clean.contains("ALLOW") && !response_clean.contains("BLOCK") {
                println!("\x1b[32m[AI SENTINEL] ✅ AI Judgment: ALLOW (Legitimate Admin Task)\x1b[0m");
                false
            } else if response_clean.contains("BLOCK") {
                println!("\x1b[31m[AI SENTINEL] 🛑 AI Judgment: BLOCK (Malicious Behavior Detected)\x1b[0m");
                true
            } else {
                println!("\x1b[33m[AI SENTINEL] ⚠️ AI returned ambiguous response: {}. Defaulting to STRICT BLOCK.\x1b[0m", response_clean);
                true
            }
        }
        Err(e) => {
            println!("\x1b[31m[!] AI Analysis failed or timed out: {}. Defaulting to STRICT BLOCK.\x1b[0m", e);
            true
        }
    }
}
