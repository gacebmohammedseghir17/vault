//! Advanced disassembly engine for binary analysis
//! Provides multi-architecture disassembly with pattern detection

pub mod capstone_engine;
pub mod assembly_analyzer;
pub mod pattern_detector;
pub mod pe_analyzer;

pub use capstone_engine::*;
pub use assembly_analyzer::*;
pub use pattern_detector::*;
pub use pe_analyzer::*;

use serde::{Deserialize, Serialize};
// Removed unused import

/// Supported architectures for disassembly
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Architecture {
    X86,
    X64,
    ARM,
    ARM64,
    MIPS,
}

/// Disassembly configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisassemblyConfig {
    pub architecture: Architecture,
    pub max_instructions: usize,
    pub enable_pattern_detection: bool,
    pub cache_results: bool,
    pub timeout_ms: u64,
}

impl Default for DisassemblyConfig {
    fn default() -> Self {
        Self {
            architecture: Architecture::X64,
            max_instructions: 10000,
            enable_pattern_detection: true,
            cache_results: true,
            timeout_ms: 5000,
        }
    }
}

/// Disassembly result with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisassemblyResult {
    pub instructions: Vec<Instruction>,
    pub patterns: Vec<AssemblyPattern>,
    pub metadata: DisassemblyMetadata,
    pub analysis_time_ms: u64,
}

/// Individual assembly instruction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Instruction {
    pub address: u64,
    pub mnemonic: String,
    pub operands: String,
    pub bytes: Vec<u8>,
    pub size: usize,
}

/// Detected assembly pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssemblyPattern {
    pub pattern_type: PatternType,
    pub confidence: f32,
    pub start_address: u64,
    pub end_address: u64,
    pub description: String,
}

/// Types of assembly patterns
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PatternType {
    Shellcode,
    Packer,
    Obfuscation,
    Encryption,
    AntiDebug,
    AntiVM,
    Injection,
    Hooking,
    Ransomware,
    Keylogger,
    Rootkit,
    Custom,
}

/// Disassembly metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisassemblyMetadata {
    pub total_instructions: usize,
    pub unique_mnemonics: usize,
    pub code_entropy: f64,
    pub suspicious_patterns: usize,
    pub architecture_detected: Architecture,
}
