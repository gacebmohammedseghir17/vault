//! Advanced pattern detection for malware analysis
//! Implements sophisticated pattern matching algorithms

use super::{AssemblyPattern, PatternType};
use std::collections::{HashMap, HashSet};
use regex::Regex;
use tracing::{debug, info};

/// Pattern detector for advanced malware analysis
pub struct PatternDetector {
    /// Known malware signatures
    signatures: HashMap<String, PatternSignature>,
    /// Compiled regex patterns
    regex_cache: HashMap<String, Regex>,
    /// Behavioral pattern rules
    behavioral_rules: Vec<BehavioralRule>,
}

/// Pattern signature definition
#[derive(Debug, Clone)]
pub struct PatternSignature {
    pub name: String,
    pub pattern_type: PatternType,
    pub confidence: f32,
    pub description: String,
    pub byte_pattern: Option<Vec<u8>>,
    pub instruction_pattern: Option<Vec<String>>,
    pub behavioral_indicators: Vec<String>,
}

/// Behavioral analysis rule
#[derive(Debug, Clone)]
pub struct BehavioralRule {
    pub name: String,
    pub conditions: Vec<String>,
    pub pattern_type: PatternType,
    pub confidence: f32,
    pub description: String,
}

/// Pattern match result
#[derive(Debug, Clone)]
pub struct PatternMatch {
    pub signature_name: String,
    pub pattern: AssemblyPattern,
    pub context: Vec<String>,
}

impl PatternDetector {
    /// Create new pattern detector with default signatures
    pub fn new() -> Self {
        let mut detector = Self {
            signatures: HashMap::new(),
            regex_cache: HashMap::new(),
            behavioral_rules: Vec::new(),
        };
        
        detector.load_default_signatures();
        detector.load_behavioral_rules();
        detector
    }

    /// Load default malware signatures
    fn load_default_signatures(&mut self) {
        // Shellcode signatures
        self.add_signature(PatternSignature {
            name: "GetPC_Call".to_string(),
            pattern_type: PatternType::Shellcode,
            confidence: 0.85,
            description: "GetPC technique using CALL instruction".to_string(),
            byte_pattern: Some(vec![0xE8, 0x00, 0x00, 0x00, 0x00]),
            instruction_pattern: Some(vec!["call".to_string(), "$+5".to_string()]),
            behavioral_indicators: vec!["position_independent".to_string()],
        });

        self.add_signature(PatternSignature {
            name: "Egg_Hunter".to_string(),
            pattern_type: PatternType::Shellcode,
            confidence: 0.75,
            description: "Egg hunter shellcode pattern".to_string(),
            byte_pattern: None,
            instruction_pattern: Some(vec!["scasd".to_string(), "jnz".to_string()]),
            behavioral_indicators: vec!["memory_search".to_string()],
        });

        // Packer signatures
        self.add_signature(PatternSignature {
            name: "UPX_Packer".to_string(),
            pattern_type: PatternType::Packer,
            confidence: 0.90,
            description: "UPX packer signature".to_string(),
            byte_pattern: Some(vec![0x55, 0x50, 0x58, 0x21]), // "UPX!"
            instruction_pattern: None,
            behavioral_indicators: vec!["compressed_sections".to_string()],
        });

        self.add_signature(PatternSignature {
            name: "Themida_VM".to_string(),
            pattern_type: PatternType::Packer,
            confidence: 0.85,
            description: "Themida virtualization engine".to_string(),
            byte_pattern: None,
            instruction_pattern: Some(vec!["pushad".to_string(), "call".to_string(), "popad".to_string()]),
            behavioral_indicators: vec!["vm_protection".to_string()],
        });

        // Anti-debug signatures
        self.add_signature(PatternSignature {
            name: "IsDebuggerPresent".to_string(),
            pattern_type: PatternType::AntiDebug,
            confidence: 0.80,
            description: "IsDebuggerPresent API call".to_string(),
            byte_pattern: None,
            instruction_pattern: Some(vec!["call".to_string(), "IsDebuggerPresent".to_string()]),
            behavioral_indicators: vec!["debugger_detection".to_string()],
        });

        self.add_signature(PatternSignature {
            name: "PEB_BeingDebugged".to_string(),
            pattern_type: PatternType::AntiDebug,
            confidence: 0.85,
            description: "PEB BeingDebugged flag check".to_string(),
            byte_pattern: Some(vec![0x64, 0xA1, 0x30, 0x00, 0x00, 0x00]), // mov eax, fs:[30h]
            instruction_pattern: None,
            behavioral_indicators: vec!["peb_access".to_string()],
        });

        // Injection signatures
        self.add_signature(PatternSignature {
            name: "Process_Hollowing".to_string(),
            pattern_type: PatternType::Injection,
            confidence: 0.90,
            description: "Process hollowing technique".to_string(),
            byte_pattern: None,
            instruction_pattern: Some(vec![
                "CreateProcess".to_string(),
                "NtUnmapViewOfSection".to_string(),
                "VirtualAllocEx".to_string(),
                "WriteProcessMemory".to_string(),
                "ResumeThread".to_string()
            ]),
            behavioral_indicators: vec!["process_manipulation".to_string()],
        });

        info!("Loaded {} default signatures", self.signatures.len());
    }

    /// Load behavioral analysis rules
    fn load_behavioral_rules(&mut self) {
        self.behavioral_rules.push(BehavioralRule {
            name: "Ransomware_Behavior".to_string(),
            conditions: vec![
                "file_encryption".to_string(),
                "registry_modification".to_string(),
                "network_communication".to_string(),
                "process_creation".to_string(),
            ],
            pattern_type: PatternType::Ransomware,
            confidence: 0.95,
            description: "Typical ransomware behavioral pattern".to_string(),
        });

        self.behavioral_rules.push(BehavioralRule {
            name: "Keylogger_Behavior".to_string(),
            conditions: vec![
                "keyboard_hook".to_string(),
                "file_write".to_string(),
                "network_send".to_string(),
            ],
            pattern_type: PatternType::Keylogger,
            confidence: 0.85,
            description: "Keylogger behavioral pattern".to_string(),
        });

        self.behavioral_rules.push(BehavioralRule {
            name: "Rootkit_Behavior".to_string(),
            conditions: vec![
                "system_call_hook".to_string(),
                "file_hiding".to_string(),
                "process_hiding".to_string(),
                "registry_hiding".to_string(),
            ],
            pattern_type: PatternType::Rootkit,
            confidence: 0.90,
            description: "Rootkit stealth behavior".to_string(),
        });

        info!("Loaded {} behavioral rules", self.behavioral_rules.len());
    }

    /// Add new signature to the detector
    pub fn add_signature(&mut self, signature: PatternSignature) {
        self.signatures.insert(signature.name.clone(), signature);
    }

    /// Detect patterns in byte sequence
    pub fn detect_byte_patterns(&self, bytes: &[u8]) -> Result<Vec<PatternMatch>, Box<dyn std::error::Error>> {
        let mut matches = Vec::new();
        
        for (name, signature) in &self.signatures {
            if let Some(pattern) = &signature.byte_pattern {
                if let Some(offset) = self.find_byte_pattern(bytes, pattern) {
                    matches.push(PatternMatch {
                        signature_name: name.clone(),
                        pattern: AssemblyPattern {
                            pattern_type: signature.pattern_type.clone(),
                            confidence: signature.confidence,
                            start_address: offset as u64,
                            end_address: (offset + pattern.len()) as u64,
                            description: signature.description.clone(),
                        },
                        context: vec![format!("Byte pattern match at offset 0x{:x}", offset)],
                    });
                }
            }
        }

        debug!("Found {} byte pattern matches", matches.len());
        Ok(matches)
    }

    /// Detect patterns in instruction sequence
    pub fn detect_instruction_patterns(&self, instructions: &[String]) -> Result<Vec<PatternMatch>, Box<dyn std::error::Error>> {
        let mut matches = Vec::new();
        
        for (name, signature) in &self.signatures {
            if let Some(pattern) = &signature.instruction_pattern {
                if let Some(offset) = self.find_instruction_pattern(instructions, pattern) {
                    matches.push(PatternMatch {
                        signature_name: name.clone(),
                        pattern: AssemblyPattern {
                            pattern_type: signature.pattern_type.clone(),
                            confidence: signature.confidence,
                            start_address: offset as u64,
                            end_address: (offset + pattern.len()) as u64,
                            description: signature.description.clone(),
                        },
                        context: vec![format!("Instruction pattern match at index {}", offset)],
                    });
                }
            }
        }

        debug!("Found {} instruction pattern matches", matches.len());
        Ok(matches)
    }

    /// Analyze behavioral indicators
    pub fn analyze_behavior(&self, indicators: &[String]) -> Result<Vec<PatternMatch>, Box<dyn std::error::Error>> {
        let mut matches = Vec::new();
        let indicator_set: HashSet<_> = indicators.iter().collect();
        
        for rule in &self.behavioral_rules {
            let matched_conditions: Vec<_> = rule.conditions.iter()
                .filter(|condition| indicator_set.contains(condition))
                .collect();
            
            let match_ratio = matched_conditions.len() as f32 / rule.conditions.len() as f32;
            
            if match_ratio >= 0.6 { // At least 60% of conditions must match
                let confidence = rule.confidence * match_ratio;
                
                matches.push(PatternMatch {
                    signature_name: rule.name.clone(),
                    pattern: AssemblyPattern {
                        pattern_type: rule.pattern_type.clone(),
                        confidence,
                        start_address: 0,
                        end_address: 0,
                        description: format!("{} ({}% match)", rule.description, (match_ratio * 100.0) as u32),
                    },
                    context: matched_conditions.iter().map(|s| s.to_string()).collect(),
                });
            }
        }

        debug!("Found {} behavioral matches", matches.len());
        Ok(matches)
    }

    /// Find byte pattern in data
    fn find_byte_pattern(&self, data: &[u8], pattern: &[u8]) -> Option<usize> {
        if pattern.is_empty() || data.len() < pattern.len() {
            return None;
        }

        for i in 0..=(data.len() - pattern.len()) {
            if data[i..i + pattern.len()] == *pattern {
                return Some(i);
            }
        }
        None
    }

    /// Find instruction pattern in sequence
    fn find_instruction_pattern(&self, instructions: &[String], pattern: &[String]) -> Option<usize> {
        if pattern.is_empty() || instructions.len() < pattern.len() {
            return None;
        }

        for i in 0..=(instructions.len() - pattern.len()) {
            let mut matches = true;
            for (j, pattern_instr) in pattern.iter().enumerate() {
                if !instructions[i + j].contains(pattern_instr) {
                    matches = false;
                    break;
                }
            }
            if matches {
                return Some(i);
            }
        }
        None
    }

    /// Get signature by name
    pub fn get_signature(&self, name: &str) -> Option<&PatternSignature> {
        self.signatures.get(name)
    }

    /// Get all signatures of a specific type
    pub fn get_signatures_by_type(&self, pattern_type: &PatternType) -> Vec<&PatternSignature> {
        self.signatures.values()
            .filter(|sig| &sig.pattern_type == pattern_type)
            .collect()
    }

    /// Update signature confidence
    pub fn update_signature_confidence(&mut self, name: &str, confidence: f32) {
        if let Some(signature) = self.signatures.get_mut(name) {
            signature.confidence = confidence.clamp(0.0, 1.0);
        }
    }

    /// Remove signature
    pub fn remove_signature(&mut self, name: &str) -> Option<PatternSignature> {
        self.signatures.remove(name)
    }

    /// Clear all signatures
    pub fn clear_signatures(&mut self) {
        self.signatures.clear();
        self.regex_cache.clear();
    }

    /// Get statistics
    pub fn get_statistics(&self) -> HashMap<String, usize> {
        let mut stats = HashMap::new();
        
        for signature in self.signatures.values() {
            let type_name = format!("{:?}", signature.pattern_type);
            *stats.entry(type_name).or_insert(0) += 1;
        }
        
        stats.insert("total_signatures".to_string(), self.signatures.len());
        stats.insert("behavioral_rules".to_string(), self.behavioral_rules.len());
        
        stats
    }
}

impl Default for PatternDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_detector_creation() {
        let detector = PatternDetector::new();
        assert!(!detector.signatures.is_empty());
        assert!(!detector.behavioral_rules.is_empty());
    }

    #[test]
    fn test_byte_pattern_detection() {
        let detector = PatternDetector::new();
        let bytes = vec![0x90, 0x90, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x90];
        
        let matches = detector.detect_byte_patterns(&bytes).unwrap();
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_instruction_pattern_detection() {
        let detector = PatternDetector::new();
        // Provide instruction tokens in separate entries to match pattern finder logic
        let instructions = vec![
            "call".to_string(),
            "$+5".to_string(),
        ];
        
        let matches = detector.detect_instruction_patterns(&instructions).unwrap();
        // Should detect the GetPC_Call signature via instruction pattern
        assert!(matches.iter().any(|m| m.signature_name == "GetPC_Call"));
    }

    #[test]
    fn test_behavioral_analysis() {
        let detector = PatternDetector::new();
        let indicators = vec![
            "file_encryption".to_string(),
            "registry_modification".to_string(),
            "network_communication".to_string(),
        ];
        
        let matches = detector.analyze_behavior(&indicators).unwrap();
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_signature_management() {
        let mut detector = PatternDetector::new();
        let initial_count = detector.signatures.len();
        
        let new_signature = PatternSignature {
            name: "Test_Signature".to_string(),
            pattern_type: PatternType::Custom,
            confidence: 0.5,
            description: "Test signature".to_string(),
            byte_pattern: Some(vec![0xDE, 0xAD, 0xBE, 0xEF]),
            instruction_pattern: None,
            behavioral_indicators: vec![],
        };
        
        detector.add_signature(new_signature);
        assert_eq!(detector.signatures.len(), initial_count + 1);
        
        detector.remove_signature("Test_Signature");
        assert_eq!(detector.signatures.len(), initial_count);
    }
}
