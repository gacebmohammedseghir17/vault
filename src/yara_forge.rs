use std::fs::File;
use std::io::Write;
use yara_x::Compiler;

pub fn generate_rules(groups: &[String]) {
    if let Ok(mut file) = File::create("live_threats.yara") {
        let _ = writeln!(file, "// Auto-Generated Live Intelligence Rules");
        
        for group in groups {
            // Sanitize group name for rule identifier (alphanumeric only)
            let safe_name: String = group.chars()
                .filter(|c| c.is_alphanumeric())
                .collect();
            
            if safe_name.is_empty() { continue; }

            let rule = format!(
                r#"
rule Intel_{} {{
    meta:
        description = "Detects {} group artifacts"
        author = "ERDPS Live Intel"
    strings:
        $a = "{}" nocase wide ascii
    condition:
        $a
}}
"#, safe_name, group, group);
            
            let _ = file.write_all(rule.as_bytes());
        }
    }
}

// --- OPTIMIZATION: Rule Compiler ---
// Compiles YARA rules into a binary blob for instant loading (Zero-Copy)
pub fn compile_rules_to_bin(source_path: &str, output_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("[*] Compiling YARA rules to optimized binary: {}", output_path);
    
    let mut compiler = Compiler::new();
    let source = std::fs::read_to_string(source_path)?;
    
    compiler.add_source(source.as_str())?;
    
    let rules = compiler.build();
    let serialized = rules.serialize()?;
    
    let mut file = File::create(output_path)?;
    file.write_all(&serialized)?;
    
    println!("[+] Compilation Complete. Rules binary size: {} bytes", serialized.len());
    Ok(())
}
