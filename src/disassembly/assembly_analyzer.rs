//! Assembly code analyzer for advanced pattern detection
//! Provides high-level analysis of disassembled code

use super::{DisassemblyResult, Instruction, AssemblyPattern, PatternType};
use std::collections::HashMap;
use tracing::{debug, info};

/// Assembly analyzer for detecting malicious patterns
pub struct AssemblyAnalyzer {
    /// Cache for pattern analysis results
    pattern_cache: HashMap<String, Vec<AssemblyPattern>>,
    /// Configuration for analysis sensitivity
    sensitivity_threshold: f32,
}

impl AssemblyAnalyzer {
    /// Create new assembly analyzer
    pub fn new() -> Self {
        Self {
            pattern_cache: HashMap::new(),
            sensitivity_threshold: 0.7,
        }
    }

    /// Analyze disassembly result for suspicious patterns
    pub fn analyze(&mut self, disasm: &mut DisassemblyResult) -> Result<(), Box<dyn std::error::Error>> {
        debug!("Starting assembly analysis for {} instructions", disasm.instructions.len());

        let mut detected_patterns = Vec::new();

        // Detect shellcode patterns
        detected_patterns.extend(self.detect_shellcode_patterns(&disasm.instructions)?);
        
        // Detect packer patterns
        detected_patterns.extend(self.detect_packer_patterns(&disasm.instructions)?);
        
        // Detect obfuscation patterns
        detected_patterns.extend(self.detect_obfuscation_patterns(&disasm.instructions)?);
        
        // Detect anti-analysis patterns
        detected_patterns.extend(self.detect_anti_analysis_patterns(&disasm.instructions)?);
        
        // Detect injection patterns
        detected_patterns.extend(self.detect_injection_patterns(&disasm.instructions)?);

        // Update metadata
        disasm.metadata.suspicious_patterns = detected_patterns.len();
        disasm.patterns = detected_patterns;

        info!("Assembly analysis completed, found {} suspicious patterns", disasm.patterns.len());
        Ok(())
    }

    /// Detect shellcode patterns in assembly instructions
    fn detect_shellcode_patterns(&self, instructions: &[Instruction]) -> Result<Vec<AssemblyPattern>, Box<dyn std::error::Error>> {
        let mut patterns = Vec::new();
        
        // Look for common shellcode patterns
        for (i, instruction) in instructions.iter().enumerate() {
            // Pattern 1: GetPC (Get Program Counter) techniques
            if instruction.mnemonic == "call" && instruction.operands.contains("$+5") {
                patterns.push(AssemblyPattern {
                    pattern_type: PatternType::Shellcode,
                    confidence: 0.8,
                    start_address: instruction.address,
                    end_address: instruction.address + instruction.size as u64,
                    description: "GetPC shellcode pattern detected".to_string(),
                });
            }

            // Pattern 2: Stack string construction
            if instruction.mnemonic == "push" && i + 1 < instructions.len() {
                let mut consecutive_pushes = 1;
                for j in (i + 1)..instructions.len().min(i + 10) {
                    if instructions[j].mnemonic == "push" {
                        consecutive_pushes += 1;
                    } else {
                        break;
                    }
                }
                
                if consecutive_pushes >= 4 {
                    patterns.push(AssemblyPattern {
                        pattern_type: PatternType::Shellcode,
                        confidence: 0.7,
                        start_address: instruction.address,
                        end_address: instructions[i + consecutive_pushes - 1].address,
                        description: format!("Stack string construction ({} pushes)", consecutive_pushes),
                    });
                }
            }

            // Pattern 3: Egg hunter pattern
            if instruction.mnemonic == "scasd" || instruction.mnemonic == "scasb" {
                patterns.push(AssemblyPattern {
                    pattern_type: PatternType::Shellcode,
                    confidence: 0.6,
                    start_address: instruction.address,
                    end_address: instruction.address + instruction.size as u64,
                    description: "Potential egg hunter pattern".to_string(),
                });
            }
        }

        Ok(patterns)
    }

    /// Detect packer patterns
    fn detect_packer_patterns(&self, instructions: &[Instruction]) -> Result<Vec<AssemblyPattern>, Box<dyn std::error::Error>> {
        let mut patterns = Vec::new();
        
        for (i, instruction) in instructions.iter().enumerate() {
            // Pattern 1: Self-modifying code
            if instruction.mnemonic == "mov" && instruction.operands.contains("[") {
                if i + 1 < instructions.len() && instructions[i + 1].mnemonic == "jmp" {
                    patterns.push(AssemblyPattern {
                        pattern_type: PatternType::Packer,
                        confidence: 0.7,
                        start_address: instruction.address,
                        end_address: instructions[i + 1].address + instructions[i + 1].size as u64,
                        description: "Self-modifying code pattern".to_string(),
                    });
                }
            }

            // Pattern 2: Unpacking loop
            if instruction.mnemonic == "loop" || instruction.mnemonic == "loopne" {
                patterns.push(AssemblyPattern {
                    pattern_type: PatternType::Packer,
                    confidence: 0.6,
                    start_address: instruction.address,
                    end_address: instruction.address + instruction.size as u64,
                    description: "Unpacking loop detected".to_string(),
                });
            }
        }

        Ok(patterns)
    }

    /// Detect obfuscation patterns
    fn detect_obfuscation_patterns(&self, instructions: &[Instruction]) -> Result<Vec<AssemblyPattern>, Box<dyn std::error::Error>> {
        let mut patterns = Vec::new();
        
        for (i, instruction) in instructions.iter().enumerate() {
            // Pattern 1: Junk instructions
            // Only detect at the start of a NOP run to avoid overlapping duplicates
            if instruction.mnemonic == "nop"
                && (i == 0 || instructions[i - 1].mnemonic != "nop")
                && i + 1 < instructions.len()
            {
                let mut consecutive_nops = 1;
                for j in (i + 1)..instructions.len().min(i + 20) {
                    if instructions[j].mnemonic == "nop" {
                        consecutive_nops += 1;
                    } else {
                        break;
                    }
                }

                if consecutive_nops >= 5 {
                    patterns.push(AssemblyPattern {
                        pattern_type: PatternType::Obfuscation,
                        confidence: 0.5,
                        start_address: instruction.address,
                        end_address: instructions[i + consecutive_nops - 1].address,
                        description: format!("NOP sled ({} instructions)", consecutive_nops),
                    });
                }
            }

            // Pattern 2: Meaningless arithmetic
            if (instruction.mnemonic == "add" || instruction.mnemonic == "sub") && 
               instruction.operands.contains("0") {
                patterns.push(AssemblyPattern {
                    pattern_type: PatternType::Obfuscation,
                    confidence: 0.4,
                    start_address: instruction.address,
                    end_address: instruction.address + instruction.size as u64,
                    description: "Meaningless arithmetic operation".to_string(),
                });
            }
        }

        Ok(patterns)
    }

    /// Detect anti-analysis patterns
    fn detect_anti_analysis_patterns(&self, instructions: &[Instruction]) -> Result<Vec<AssemblyPattern>, Box<dyn std::error::Error>> {
        let mut patterns = Vec::new();
        
        for instruction in instructions {
            // Pattern 1: Anti-debug techniques
            if instruction.mnemonic == "int" && instruction.operands == "3" {
                patterns.push(AssemblyPattern {
                    pattern_type: PatternType::AntiDebug,
                    confidence: 0.8,
                    start_address: instruction.address,
                    end_address: instruction.address + instruction.size as u64,
                    description: "INT 3 anti-debug technique".to_string(),
                });
            }

            // Pattern 2: RDTSC timing checks
            if instruction.mnemonic == "rdtsc" {
                patterns.push(AssemblyPattern {
                    pattern_type: PatternType::AntiDebug,
                    confidence: 0.7,
                    start_address: instruction.address,
                    end_address: instruction.address + instruction.size as u64,
                    description: "RDTSC timing check".to_string(),
                });
            }

            // Pattern 3: VM detection
            if instruction.mnemonic == "cpuid" {
                patterns.push(AssemblyPattern {
                    pattern_type: PatternType::AntiVM,
                    confidence: 0.6,
                    start_address: instruction.address,
                    end_address: instruction.address + instruction.size as u64,
                    description: "CPUID VM detection".to_string(),
                });
            }
        }

        Ok(patterns)
    }

    /// Detect code injection patterns
    fn detect_injection_patterns(&self, instructions: &[Instruction]) -> Result<Vec<AssemblyPattern>, Box<dyn std::error::Error>> {
        let mut patterns = Vec::new();
        
        for instruction in instructions {
            // Pattern 1: VirtualAlloc/VirtualProtect calls
            if instruction.mnemonic == "call" && 
               (instruction.operands.contains("VirtualAlloc") || 
                instruction.operands.contains("VirtualProtect")) {
                patterns.push(AssemblyPattern {
                    pattern_type: PatternType::Injection,
                    confidence: 0.8,
                    start_address: instruction.address,
                    end_address: instruction.address + instruction.size as u64,
                    description: "Memory allocation/protection API call".to_string(),
                });
            }

            // Pattern 2: WriteProcessMemory calls
            if instruction.mnemonic == "call" && instruction.operands.contains("WriteProcessMemory") {
                patterns.push(AssemblyPattern {
                    pattern_type: PatternType::Injection,
                    confidence: 0.9,
                    start_address: instruction.address,
                    end_address: instruction.address + instruction.size as u64,
                    description: "WriteProcessMemory injection technique".to_string(),
                });
            }

            // Pattern 3: SetWindowsHookEx calls
            if instruction.mnemonic == "call" && instruction.operands.contains("SetWindowsHookEx") {
                patterns.push(AssemblyPattern {
                    pattern_type: PatternType::Hooking,
                    confidence: 0.8,
                    start_address: instruction.address,
                    end_address: instruction.address + instruction.size as u64,
                    description: "Windows hook installation".to_string(),
                });
            }
        }

        Ok(patterns)
    }

    /// Set sensitivity threshold for pattern detection
    pub fn set_sensitivity(&mut self, threshold: f32) {
        self.sensitivity_threshold = threshold.clamp(0.0, 1.0);
    }

    /// Clear pattern cache
    pub fn clear_cache(&mut self) {
        self.pattern_cache.clear();
    }
}

impl Default for AssemblyAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn test_assembly_analyzer_creation() {
        let analyzer = AssemblyAnalyzer::new();
        assert_eq!(analyzer.sensitivity_threshold, 0.7);
    }

    #[test]
    fn test_shellcode_pattern_detection() {
        let analyzer = AssemblyAnalyzer::new();
        
        let instructions = vec![
            Instruction {
                address: 0x1000,
                mnemonic: "call".to_string(),
                operands: "$+5".to_string(),
                bytes: vec![0xe8, 0x00, 0x00, 0x00, 0x00],
                size: 5,
            }
        ];

        let patterns = analyzer.detect_shellcode_patterns(&instructions).unwrap();
        assert_eq!(patterns.len(), 1);
        assert_eq!(patterns[0].pattern_type, PatternType::Shellcode);
        assert_eq!(patterns[0].confidence, 0.8);
    }

    #[test]
    fn test_nop_sled_detection() {
        let analyzer = AssemblyAnalyzer::new();
        
        let instructions: Vec<Instruction> = (0..10).map(|i| Instruction {
            address: 0x1000 + i,
            mnemonic: "nop".to_string(),
            operands: "".to_string(),
            bytes: vec![0x90],
            size: 1,
        }).collect();

        let patterns = analyzer.detect_obfuscation_patterns(&instructions).unwrap();
        assert_eq!(patterns.len(), 1);
        assert_eq!(patterns[0].pattern_type, PatternType::Obfuscation);
        assert!(patterns[0].description.contains("NOP sled"));
    }
}
