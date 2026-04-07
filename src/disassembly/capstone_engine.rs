//! Capstone disassembly engine wrapper
//! Provides safe Rust interface to Capstone disassembler

use super::{Architecture, DisassemblyConfig, DisassemblyResult, Instruction, DisassemblyMetadata};
use std::time::Instant;
#[cfg(not(feature = "advanced-disassembly"))]
use tracing::info;

#[cfg(feature = "advanced-disassembly")]
use capstone::prelude::*;
#[cfg(feature = "advanced-disassembly")]
use capstone::{Capstone, arch};

/// Capstone-based disassembly engine
pub struct CapstoneEngine {
    config: DisassemblyConfig,
    #[cfg(feature = "advanced-disassembly")]
    engines: std::collections::HashMap<Architecture, Capstone>,
}

impl CapstoneEngine {
    /// Create new Capstone engine with configuration
    #[cfg(feature = "advanced-disassembly")]
    pub fn new(config: DisassemblyConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let mut engines = std::collections::HashMap::new();
        
        // Initialize engines for supported architectures
        let x64_engine = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .syntax(arch::x86::ArchSyntax::Intel)
            .detail(true)
            .build()
            .map_err(|e| format!("Failed to create x64 engine: {:?}", e))?;
        engines.insert(Architecture::X64, x64_engine);

        let x86_engine = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode32)
            .syntax(arch::x86::ArchSyntax::Intel)
            .detail(true)
            .build()
            .map_err(|e| format!("Failed to create x86 engine: {:?}", e))?;
        engines.insert(Architecture::X86, x86_engine);

        Ok(Self { config, engines })
    }

    /// Create new Capstone engine without advanced disassembly feature
    #[cfg(not(feature = "advanced-disassembly"))]
    pub fn new(config: DisassemblyConfig) -> Result<Self, Box<dyn std::error::Error>> {
        info!("Advanced disassembly feature not enabled, creating stub engine");
        Ok(Self { config })
    }

    /// Disassemble binary data
    #[cfg(feature = "advanced-disassembly")]
    pub fn disassemble(&self, data: &[u8], base_address: u64) -> Result<DisassemblyResult, Box<dyn std::error::Error>> {
        let start_time = Instant::now();
        
        let engine = self.engines.get(&self.config.architecture)
            .ok_or("Unsupported architecture")?;

        let instructions = engine.disasm_all(data, base_address)
            .map_err(|e| format!("Failed to disassemble: {:?}", e))?;
        
        let mut result_instructions = Vec::new();
        let mut unique_mnemonics = std::collections::HashSet::new();
        
        for insn in instructions.as_ref().iter().take(self.config.max_instructions) {
            let instruction = Instruction {
                address: insn.address(),
                mnemonic: insn.mnemonic().unwrap_or("").to_string(),
                operands: insn.op_str().unwrap_or("").to_string(),
                bytes: insn.bytes().to_vec(),
                size: insn.len(),
            };
            
            unique_mnemonics.insert(instruction.mnemonic.clone());
            result_instructions.push(instruction);
        }

        let metadata = DisassemblyMetadata {
            total_instructions: result_instructions.len(),
            unique_mnemonics: unique_mnemonics.len(),
            code_entropy: self.calculate_entropy(data),
            suspicious_patterns: 0, // Will be filled by pattern detector
            architecture_detected: self.config.architecture,
        };

        Ok(DisassemblyResult {
            instructions: result_instructions,
            patterns: Vec::new(), // Will be filled by pattern detector
            metadata,
            analysis_time_ms: start_time.elapsed().as_millis() as u64,
        })
    }

    /// Disassemble binary data (stub implementation)
    #[cfg(not(feature = "advanced-disassembly"))]
    pub fn disassemble(&self, data: &[u8], base_address: u64) -> Result<DisassemblyResult, Box<dyn std::error::Error>> {
        info!("Advanced disassembly feature not enabled, returning empty result");
        let start_time = Instant::now();
        
        let metadata = DisassemblyMetadata {
            total_instructions: 0,
            unique_mnemonics: 0,
            code_entropy: self.calculate_entropy(data),
            suspicious_patterns: 0,
            architecture_detected: self.config.architecture,
        };

        Ok(DisassemblyResult {
            instructions: Vec::new(),
            patterns: Vec::new(),
            metadata,
            analysis_time_ms: start_time.elapsed().as_millis() as u64,
        })
    }

    /// Calculate entropy of binary data
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capstone_engine_creation() {
        let config = DisassemblyConfig::default();
        let engine = CapstoneEngine::new(config);
        assert!(engine.is_ok());
    }

    #[test]
    #[cfg(feature = "advanced-disassembly")]
    fn test_simple_disassembly() {
        let config = DisassemblyConfig::default();
        let engine = CapstoneEngine::new(config).unwrap();
        
        // Simple x64 NOP instruction
        let code = vec![0x90, 0x90, 0x90];
        let result = engine.disassemble(&code, 0x1000);
        
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.instructions.len(), 3);
        assert_eq!(result.instructions[0].mnemonic, "nop");
    }

    #[test]
    fn test_entropy_calculation() {
        let config = DisassemblyConfig::default();
        let engine = CapstoneEngine::new(config).unwrap();
        
        // Test with uniform data (low entropy)
        let uniform_data = vec![0x00; 1024];
        let entropy = engine.calculate_entropy(&uniform_data);
        assert!(entropy < 1.0);
        
        // Test with random-like data (high entropy)
        let random_data: Vec<u8> = (0..=255).cycle().take(1024).collect();
        let entropy = engine.calculate_entropy(&random_data);
        assert!(entropy > 7.0);
    }
}
