//! PE (Portable Executable) file analyzer
//! Provides advanced analysis of Windows PE files

use super::{DisassemblyResult, AssemblyPattern, PatternType};
use std::collections::HashMap;
use tracing::{debug, info};

#[cfg(feature = "advanced-disassembly")]
use goblin::pe::PE;
#[cfg(feature = "advanced-disassembly")]
use goblin::Object;

/// PE file analyzer for Windows executables
pub struct PEAnalyzer {
    /// Cache for analysis results
    analysis_cache: HashMap<String, PEAnalysisResult>,
}

/// PE analysis result
#[derive(Debug, Clone)]
pub struct PEAnalysisResult {
    pub entropy: f64,
    pub packed: bool,
    pub suspicious_sections: Vec<SuspiciousSection>,
    pub imports: Vec<SuspiciousImport>,
    pub exports: Vec<String>,
    pub resources: Vec<ResourceInfo>,
    pub digital_signature: Option<SignatureInfo>,
}

/// Suspicious section information
#[derive(Debug, Clone)]
pub struct SuspiciousSection {
    pub name: String,
    pub virtual_address: u64,
    pub size: u64,
    pub entropy: f64,
    pub executable: bool,
    pub writable: bool,
    pub suspicious_reason: String,
}

/// Suspicious import information
#[derive(Debug, Clone)]
pub struct SuspiciousImport {
    pub dll: String,
    pub function: String,
    pub risk_level: RiskLevel,
    pub description: String,
}

/// Resource information
#[derive(Debug, Clone)]
pub struct ResourceInfo {
    pub resource_type: String,
    pub name: String,
    pub size: u64,
    pub entropy: f64,
}

/// Digital signature information
#[derive(Debug, Clone)]
pub struct SignatureInfo {
    pub valid: bool,
    pub signer: String,
    pub timestamp: Option<String>,
    pub certificate_chain: Vec<String>,
}

/// Risk level for imports
#[derive(Debug, Clone, PartialEq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl PEAnalyzer {
    /// Create new PE analyzer
    pub fn new() -> Self {
        Self {
            analysis_cache: HashMap::new(),
        }
    }

    /// Analyze PE file and update disassembly result
    #[cfg(feature = "advanced-disassembly")]
    pub fn analyze_pe(&mut self, data: &[u8], disasm: &mut DisassemblyResult) -> Result<PEAnalysisResult, Box<dyn std::error::Error>> {
        debug!("Starting PE analysis for {} bytes", data.len());

        let object = Object::parse(data)?;
        
        match object {
            Object::PE(pe) => {
                let result = self.analyze_pe_structure(&pe, data)?;
                
                // Add PE-specific patterns to disassembly result
                let mut pe_patterns = self.extract_pe_patterns(&result)?;
                disasm.patterns.append(&mut pe_patterns);
                
                info!("PE analysis completed, found {} suspicious sections", result.suspicious_sections.len());
                Ok(result)
            }
            _ => Err("Not a valid PE file".into()),
        }
    }

    /// Analyze PE file (stub implementation)
    #[cfg(not(feature = "advanced-disassembly"))]
    pub fn analyze_pe(&mut self, data: &[u8], disasm: &mut DisassemblyResult) -> Result<PEAnalysisResult, Box<dyn std::error::Error>> {
        info!("Advanced disassembly feature not enabled, returning basic PE analysis");
        
        let result = PEAnalysisResult {
            entropy: self.calculate_entropy(data),
            packed: false,
            suspicious_sections: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            resources: Vec::new(),
            digital_signature: None,
        };
        
        Ok(result)
    }

    /// Analyze PE structure in detail
    #[cfg(feature = "advanced-disassembly")]
    fn analyze_pe_structure(&self, pe: &PE, data: &[u8]) -> Result<PEAnalysisResult, Box<dyn std::error::Error>> {
        let mut result = PEAnalysisResult {
            entropy: self.calculate_entropy(data),
            packed: false,
            suspicious_sections: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            resources: Vec::new(),
            digital_signature: None,
        };

        // Analyze sections
        for section in &pe.sections {
            let section_name = String::from_utf8_lossy(&section.name).trim_end_matches('\0').to_string();
            let section_data = &data[section.pointer_to_raw_data as usize..(section.pointer_to_raw_data + section.size_of_raw_data) as usize];
            let section_entropy = self.calculate_entropy(section_data);
            
            // Check for suspicious sections
            if self.is_section_suspicious(&section_name, section_entropy, section.characteristics) {
                result.suspicious_sections.push(SuspiciousSection {
                    name: section_name.clone(),
                    virtual_address: section.virtual_address as u64,
                    size: section.size_of_raw_data as u64,
                    entropy: section_entropy,
                    executable: (section.characteristics & 0x20000000) != 0,
                    writable: (section.characteristics & 0x80000000) != 0,
                    suspicious_reason: self.get_section_suspicion_reason(&section_name, section_entropy, section.characteristics),
                });
            }
        }

        // Analyze imports
        let mut all_imports = Vec::new();
        for import in &pe.imports {
            let dll_name = import.dll.to_lowercase();
            all_imports.push(import.name.to_string());
            // Note: goblin's Import struct doesn't have a functions field
            // We'll analyze the import name directly
            if let Some(suspicious_import) = self.check_suspicious_import(&dll_name, &import.name) {
                result.imports.push(suspicious_import);
            }
        }

        // Command Mode: Correlated IAT Analysis
        if let Some(correlated) = self.check_correlated_imports(&all_imports) {
            result.imports.push(correlated);
        }

        // Check if file appears packed
        result.packed = self.detect_packing(&result.suspicious_sections, result.entropy);

        Ok(result)
    }

    /// Check if a section is suspicious
    fn is_section_suspicious(&self, name: &str, entropy: f64, characteristics: u32) -> bool {
        // High entropy sections
        if entropy > 7.5 {
            return true;
        }

        // Unusual section names
        let suspicious_names = ["upx", "aspack", "themida", "vmprotect", "obsidium", "enigma"];
        if suspicious_names.iter().any(|&s| name.to_lowercase().contains(s)) {
            return true;
        }

        // Writable and executable sections
        let writable = (characteristics & 0x80000000) != 0;
        let executable = (characteristics & 0x20000000) != 0;
        if writable && executable {
            return true;
        }

        false
    }

    /// Get reason for section suspicion
    fn get_section_suspicion_reason(&self, name: &str, entropy: f64, characteristics: u32) -> String {
        let mut reasons = Vec::new();

        if entropy > 7.5 {
            reasons.push("High entropy (possibly encrypted/packed)");
        }

        let suspicious_names = ["upx", "aspack", "themida", "vmprotect", "obsidium", "enigma"];
        if suspicious_names.iter().any(|&s| name.to_lowercase().contains(s)) {
            reasons.push("Suspicious section name (known packer)");
        }

        let writable = (characteristics & 0x80000000) != 0;
        let executable = (characteristics & 0x20000000) != 0;
        if writable && executable {
            reasons.push("Writable and executable section");
        }

        reasons.join(", ")
    }

    /// Check for suspicious imports
    fn check_correlated_imports(&self, imports: &[String]) -> Option<SuspiciousImport> {
        let mut has_crypto = false;
        let mut has_file_enum = false;
        let mut has_destructive = false;

        for imp in imports {
            let lower = imp.to_lowercase();
            if lower.contains("cryptencrypt") || lower.contains("bcryptencrypt") {
                has_crypto = true;
            }
            if lower.contains("findnextfile") || lower.contains("findfirstfile") {
                has_file_enum = true;
            }
            if lower.contains("deletevolumemountpoint") || lower.contains("vssadmin") || lower.contains("shadowcopy") {
                has_destructive = true;
            }
        }

        if has_crypto && has_file_enum && has_destructive {
            Some(SuspiciousImport {
                dll: "Multiple".to_string(),
                function: "CryptEncrypt + FindNextFile + DeleteVolumeMountPoint".to_string(),
                risk_level: RiskLevel::Critical,
                description: "Critical Ransomware Intent: Correlated API Group Detected".to_string(),
            })
        } else {
            None
        }
    }

    fn check_suspicious_import(&self, dll: &str, func: &str) -> Option<SuspiciousImport> {
        let high_risk_functions = [
            ("kernel32.dll", "VirtualAlloc", "Memory allocation for code injection"),
            ("kernel32.dll", "VirtualProtect", "Memory protection changes"),
            ("kernel32.dll", "WriteProcessMemory", "Process memory modification"),
            ("kernel32.dll", "CreateRemoteThread", "Remote thread creation"),
            ("kernel32.dll", "SetWindowsHookEx", "System hook installation"),
            ("ntdll.dll", "NtWriteVirtualMemory", "Low-level memory writing"),
            ("ntdll.dll", "NtCreateThread", "Low-level thread creation"),
            ("advapi32.dll", "CryptEncrypt", "Encryption functions"),
            ("advapi32.dll", "CryptDecrypt", "Decryption functions"),
            ("wininet.dll", "InternetOpen", "Network communication"),
            ("ws2_32.dll", "socket", "Network socket creation"),
        ];

        for (target_dll, target_func, description) in &high_risk_functions {
            if dll == *target_dll && function.to_lowercase().contains(&target_func.to_lowercase()) {
                let risk_level = match *target_dll {
                    "ntdll.dll" => RiskLevel::Critical,
                    "kernel32.dll" if target_func.contains("Virtual") || target_func.contains("Remote") => RiskLevel::High,
                    _ => RiskLevel::Medium,
                };

                return Some(SuspiciousImport {
                    dll: dll.to_string(),
                    function: function.to_string(),
                    risk_level,
                    description: description.to_string(),
                });
            }
        }

        None
    }

    /// Detect if file is packed
    fn detect_packing(&self, suspicious_sections: &[SuspiciousSection], overall_entropy: f64) -> bool {
        // High overall entropy
        if overall_entropy > 7.8 {
            return true;
        }

        // Multiple high-entropy sections
        let high_entropy_sections = suspicious_sections.iter()
            .filter(|s| s.entropy > 7.5)
            .count();
        
        if high_entropy_sections >= 2 {
            return true;
        }

        // Known packer section names
        suspicious_sections.iter().any(|s| {
            let name = s.name.to_lowercase();
            name.contains("upx") || name.contains("aspack") || name.contains("themida")
        })
    }

    /// Extract assembly patterns from PE analysis
    fn extract_pe_patterns(&self, analysis: &PEAnalysisResult) -> Result<Vec<AssemblyPattern>, Box<dyn std::error::Error>> {
        let mut patterns = Vec::new();

        // Add patterns for packed files
        if analysis.packed {
            patterns.push(AssemblyPattern {
                pattern_type: PatternType::Packer,
                confidence: 0.9,
                start_address: 0,
                end_address: 0,
                description: "File appears to be packed or encrypted".to_string(),
            });
        }

        // Add patterns for suspicious imports
        for import in &analysis.imports {
            let confidence = match import.risk_level {
                RiskLevel::Critical => 0.95,
                RiskLevel::High => 0.85,
                RiskLevel::Medium => 0.7,
                RiskLevel::Low => 0.5,
            };

            patterns.push(AssemblyPattern {
                pattern_type: PatternType::Injection,
                confidence,
                start_address: 0,
                end_address: 0,
                description: format!("Suspicious import: {}!{} - {}", import.dll, import.function, import.description),
            });
        }

        Ok(patterns)
    }

    /// Calculate entropy of data
    fn calculate_entropy(&self, data: &[u8]) -> f64 {
        let mut counts = [0u32; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }

        let len = data.len() as f64;
        let mut entropy = 0.0;

        for &count in &counts {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }

        entropy
    }
}

impl Default for PEAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pe_analyzer_creation() {
        let analyzer = PEAnalyzer::new();
        assert!(analyzer.analysis_cache.is_empty());
    }

    #[test]
    fn test_entropy_calculation() {
        let analyzer = PEAnalyzer::new();
        
        // Test with uniform data (low entropy)
        let uniform_data = vec![0x00; 1024];
        let entropy = analyzer.calculate_entropy(&uniform_data);
        assert!(entropy < 1.0);
        
        // Test with random-like data (high entropy)
        let random_data: Vec<u8> = (0..=255).cycle().take(1024).collect();
        let entropy = analyzer.calculate_entropy(&random_data);
        assert!(entropy > 7.0);
    }

    #[test]
    fn test_suspicious_import_detection() {
        let analyzer = PEAnalyzer::new();
        
        // Test high-risk function
        let result = analyzer.check_suspicious_import("kernel32.dll", "VirtualAlloc");
        assert!(result.is_some());
        assert_eq!(result.unwrap().risk_level, RiskLevel::High);
        
        // Test normal function
        let result = analyzer.check_suspicious_import("kernel32.dll", "GetCurrentProcess");
        assert!(result.is_none());
    }
}
