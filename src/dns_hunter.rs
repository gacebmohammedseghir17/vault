use std::process::Command;
use crate::entropy_engine::EntropyAccelerator;

pub struct DnsHunter;

impl DnsHunter {
    // 🕵️ COMMAND: dns
    pub fn scan() {
        println!("\x1b[35m[DNS] 🌍 ANALYZING RESOLVER CACHE (DGA DETECTION)...\x1b[0m");

        // 1. DUMP CACHE
        let output = Command::new("ipconfig")
            .arg("/displaydns")
            .output();

        match output {
            Ok(o) => {
                let text = String::from_utf8_lossy(&o.stdout);
                Self::analyze_cache(&text);
            },
            Err(e) => println!("\x1b[31m[DNS] ❌ Failed to query DNS cache: {}\x1b[0m", e),
        }
    }

    fn analyze_cache(raw_text: &str) {
        let mut suspicious_count = 0;
        let mut total_domains = 0;

        // 2. PARSE OUTPUT (Windows format)
        // Record Name . . . . . : google.com
        for line in raw_text.lines() {
            if line.trim().starts_with("Record Name") {
                if let Some(domain) = line.split(':').nth(1) {
                    let domain = domain.trim();
                    total_domains += 1;

                    // 3. AVX2 ENTROPY CHECK
                    // Domain names shouldn't be random. If they are, it's a DGA (Domain Generation Algorithm).
                    let score = EntropyAccelerator::calculate(domain.as_bytes());

                    // Threshold: 4.5 is usually high for a domain name (normal words are ~2.5-3.5)
                    if score > 4.2 || domain.ends_with(".ru") || domain.ends_with(".top") || domain.ends_with(".xyz") {
                        println!("\x1b[31m   |-> 💀 SUSPICIOUS: {} (Entropy: {:.2})\x1b[0m", domain, score);
                        suspicious_count += 1;
                    } else {
                        // Optional: Print safe domains in debug mode
                        // println!("   |-> OK: {} ({:.2})", domain, score);
                    }
                }
            }
        }

        if suspicious_count == 0 {
            println!("\x1b[32m[DNS] ✅ CACHE CLEAN ({} domains analyzed).\x1b[0m", total_domains);
        } else {
            println!("\n\x1b[41;37m[DNS] 🚨 DETECTED {} POTENTIAL C2 DOMAINS!\x1b[0m", suspicious_count);
        }
    }
}
