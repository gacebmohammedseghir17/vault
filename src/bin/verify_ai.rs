use erdps_agent::analysis::smart_scan;
use std::fs;
use std::io::Write;
use console::style;

#[tokio::main]
async fn main() {
    println!("Creating dummy malicious file...");
    let dummy_path = "tests/dummy_malware.bin";
    
    // Create a file with "encrypt" string and some XOR instructions (0x31 0xC0 = xor eax, eax)
    let mut file = fs::File::create(dummy_path).unwrap();
    file.write_all(b"This is a test file with the word encrypt and ransom inside.\n").unwrap();
    // Add some x86 machine code: XOR EAX, EAX (31 C0) repeated
    let code = [0x31, 0xC0, 0x31, 0xC0, 0x31, 0xC0]; 
    file.write_all(&code).unwrap();
    
    println!("Running Smart Scan (Unified Architecture)...");
    let result = smart_scan::perform_smart_scan(dummy_path).await;
    
    println!("--- Analysis Result ---");
    println!("Risk Score: {}", result.risk_score);
    println!("YARA Matches: {:?}", result.yara_matches);
    println!("AI Verdict: {}", style(&result.ai_verdict).bold());
    println!("Assembly Snippet:\n{}", result.assembly_snippet);
    
    // Clean up
    fs::remove_file(dummy_path).unwrap();
    
    if result.ai_verdict != "OFFLINE" {
        println!("{}", style("SUCCESS: AI Integration Verified!").green().bold());
    } else {
        println!("{}", style("WARNING: AI Offline or Failed.").yellow().bold());
    }
}
