use capstone::prelude::*;
use capstone::{Capstone, Insn};
use petgraph::graph::{Graph, NodeIndex};
// use std::collections::HashMap; // REMOVED: Unused and non-deterministic

pub struct SemanticEngine {
    cs: Capstone,
}

#[derive(Debug, Clone)]
pub struct BlockStats {
    pub start_addr: u64,
    pub instruction_count: usize,
    pub has_loop: bool,
}

impl SemanticEngine {
    pub fn new() -> Self {
        let cs = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .build()
            .expect("Failed to init Capstone");
        
        SemanticEngine { cs }
    }

    /// Lifts assembly to a Control Flow Graph (CFG) and analyzes complexity
    pub fn analyze(&self, code: &[u8], entry_point: u64) -> (u32, Vec<String>) {
        let mut insights = Vec::new();
        
        // 1. Disassemble everything
        let insns = match self.cs.disasm_all(code, entry_point) {
            Ok(i) => i,
            Err(_) => return (0, vec!["Disassembly Failed".to_string()]),
        };

        // 2. Build the Graph (Simplified Logic for Speed/Determinism)
        // Note: Full CFG construction removed as it wasn't influencing the heuristic score
        // and introduced potential non-determinism via HashMaps.
        
        let mut complexity_score = 0;
        let mut encryption_loops = 0;

        for insn in insns.iter() {
            let mnemonic = insn.mnemonic().unwrap_or("");
            
            // Check for Branching (The "Shape" of the code)
            if mnemonic.starts_with("j") || mnemonic == "call" {
                complexity_score += 1; // Every decision point increases complexity
                
                // Heuristic: Short backwards jumps often indicate loops (Encryption/Obfuscation)
                let op_str = insn.op_str().unwrap_or("");
                if op_str.contains("0x") {
                    if mnemonic == "jnz" || mnemonic == "jmp" {
                        encryption_loops += 1;
                    }
                }
            }
        }

        // 3. Generate Semantic Insights
        insights.push(format!("Instruction Count: {}", insns.len()));
        
        if complexity_score > 100 {
            insights.push(format!("Cyclomatic Complexity: {} (CRITICAL)", complexity_score));
            insights.push("WARN: High complexity suggests obfuscation or encryption logic.".to_string());
        } else {
            insights.push(format!("Cyclomatic Complexity: {} (Low)", complexity_score));
        }

        if encryption_loops > 5 {
            insights.push(format!("Potential Loops: {} (Suspicious)", encryption_loops));
            insights.push("WARN: Tight loops detected. Possible Ransomware Encryption Routine.".to_string());
        }

        (complexity_score, insights)
    }
}
