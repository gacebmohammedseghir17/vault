use std::fs;
use goblin::pe::PE;
use regex::bytes::Regex;

pub struct PeAnalyzer;

pub struct PeAnalysisResult {
    pub score: u8,
    pub is_writable_section: bool,
    pub has_injection_imports: bool,
    pub has_crypto_imports: bool,
    pub has_heuristics: bool,
    pub has_high_entropy: bool,
    pub entropy: f64,
    pub extracted_iocs: Vec<String>,
    pub capabilities: Vec<String>,
}

pub fn extract_iocs(file_data: &[u8]) -> Vec<String> {
    let ipv4_regex = Regex::new(r"(?i)\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b").unwrap();
    let url_regex = Regex::new(r"(?i)https?://[a-zA-Z0-9./\-_?=]+").unwrap();

    let mut iocs = Vec::new();

    for mat in ipv4_regex.find_iter(file_data) {
        let ioc = String::from_utf8_lossy(mat.as_bytes()).to_string();
        if ioc != "0.0.0.0" && ioc != "127.0.0.1" {
            iocs.push(ioc);
        }
    }

    for mat in url_regex.find_iter(file_data) {
        let ioc = String::from_utf8_lossy(mat.as_bytes()).to_string();
        if !ioc.to_lowercase().contains("microsoft.com") {
            iocs.push(ioc);
        }
    }

    iocs.sort();
    iocs.dedup();
    iocs
}

pub fn calculate_entropy(file_path: &str) -> f64 {
    let bytes = match fs::read(file_path) {
        Ok(b) => b,
        Err(_) => return 0.0,
    };
    
    if bytes.is_empty() {
        return 0.0;
    }

    let mut frequency = [0usize; 256];
    for &byte in &bytes {
        frequency[byte as usize] += 1;
    }

    let mut entropy = 0.0;
    let total_bytes = bytes.len() as f64;

    for &count in &frequency {
        if count > 0 {
            let p = count as f64 / total_bytes;
            entropy -= p * p.log2();
        }
    }

    entropy
}

impl PeAnalyzer {
    pub fn analyze(file_path: &str) -> PeAnalysisResult {
        let mut result = PeAnalysisResult {
            score: 0,
            is_writable_section: false,
            has_injection_imports: false,
            has_crypto_imports: false,
            has_heuristics: false,
            has_high_entropy: false,
            entropy: 0.0,
            extracted_iocs: Vec::new(),
            capabilities: Vec::new(),
        };

        let bytes = match fs::read(file_path) {
            Ok(b) => b,
            Err(_) => return result,
        };

        // Extract IOCs using the raw file buffer
        result.extracted_iocs = extract_iocs(&bytes);

        // Entropy calculation
        let entropy_score = calculate_entropy(file_path);
        result.entropy = entropy_score;
        if entropy_score > 7.5 {
            println!("\x1b[31;1m[!] HIGH ENTROPY DETECTED: {:.4} (Packed/Encrypted Payload)\x1b[0m", entropy_score);
            result.score += 25;
            result.has_high_entropy = true;
        } else {
            println!("\x1b[32;1m[+] File Entropy: {:.4} (Normal)\x1b[0m", entropy_score);
        }
        
        if let Ok(pe) = PE::parse(&bytes) {
            // 1. Section Anomaly Check
            for section in pe.sections {
                if let Ok(_name) = section.name() {
                    // Check if it's an executable section
                    if (section.characteristics & 0x20000000) != 0 {
                        // Check if it's WRITABLE
                        if (section.characteristics & 0x80000000) != 0 {
                            println!("\x1b[31;1m[!] ANOMALY: Executable section is WRITABLE (Packed/Obfuscated Code Detected!)\x1b[0m");
                            result.score += 40;
                            result.is_writable_section = true;
                        }
                    }
                }
            }

            // 2. Suspicious Imports (IAT Profiling)
            let mut has_crypto = false;
            let mut has_file_ops = false;
            let mut has_injection = false;
            let mut has_remote_thread = false;
            let mut has_network = false;

            for import in &pe.imports {
                let name = import.name.to_string();
                if name == "VirtualAllocEx" { has_injection = true; }
                if name == "CreateRemoteThread" { has_remote_thread = true; }
                if name == "CryptEncrypt" || name == "CryptAcquireContext" { has_crypto = true; }
                if name == "FindFirstFile" || name == "DeleteFile" { has_file_ops = true; }
                if name == "InternetOpenUrlA" || name == "HttpSendRequest" { has_network = true; }
                
                if name == "VirtualAllocEx" || name == "CreateRemoteThread" {
                    result.has_injection_imports = true;
                }
                if name == "CryptEncrypt" {
                    result.has_crypto_imports = true;
                }
            }

            // 3. Semantic Capability Classification (CAPA-style)
            if has_crypto && has_file_ops {
                result.capabilities.push("Ransomware Encryption Loop (T1486 + T1083)".to_string());
            }
            if has_injection && has_remote_thread {
                result.capabilities.push("Process Injection / Hollowing (T1055)".to_string());
            }
            if has_network {
                result.capabilities.push("C2 Network Communication (T1105)".to_string());
            }

            if result.has_injection_imports {
                println!("\x1b[31;1m[!] IAT ANOMALY: Injection Signature Detected (VirtualAllocEx / CreateRemoteThread)\x1b[0m");
                result.score += 30;
            }
            if result.has_crypto_imports {
                println!("\x1b[31;1m[!] IAT ANOMALY: Crypto Signature Detected (CryptEncrypt)\x1b[0m");
                result.score += 20;
            }
        }

        // 3. Hardcoded Heuristic Signatures (YARA Fallback)
        let lower_bytes: Vec<u8> = bytes.iter().map(|b| b.to_ascii_lowercase()).collect();
        let heuristic_strings = [
            "wanacrypt0r",
            "vssadmin delete shadows",
            "wbadmin delete",
            "lockbit",
            "darkside"
        ];

        for sig in heuristic_strings.iter() {
            // Very basic substring search on lowercased bytes
            if lower_bytes.windows(sig.len()).any(|window| window == sig.as_bytes()) {
                result.has_heuristics = true;
                break;
            }
        }

        if result.has_heuristics {
            println!("\x1b[33;1m[HEURISTICS] Static Signature Match Found! (+30 Threat Score)\x1b[0m");
            result.score += 30;
        }

        result
    }
}