use std::sync::Mutex; 
use std::path::Path; 
use std::fs; 
use std::io::Cursor; 
use std::error::Error; 
use ort::session::Session; 
use ort::session::builder::GraphOptimizationLevel;
use ort::value::Value; 
use ndarray::Array2; 
use goblin::pe::PE; 
use murmur3::murmur3_32; 
use crate::model_hashes;
use crate::supply_chain;

// --- CONFIG --- 
const FEATURE_DIM: usize = 2568; 

// --- FEATURE EXTRACTOR --- 
pub fn extract_features(buffer: &[u8]) -> Result<Vec<f32>, Box<dyn Error>> { 
    let mut features = vec![0.0f32; FEATURE_DIM]; 

    // 1. BYTE HISTOGRAM (0-255) 
    for &byte in buffer { 
        features[byte as usize] += 1.0; 
    } 
    // Normalize histogram 
    let total_bytes = buffer.len() as f32; 
    if total_bytes > 0.0 { 
        for i in 0..256 { 
            features[i] /= total_bytes; 
        } 
    } 

    // 2. PARSE PE HEADERS 
    match PE::parse(buffer) { 
        Ok(pe) => { 
            // A. IMPORTS (Indices 612-1891) 
            for import in pe.imports { 
                let dll_name = import.dll.to_lowercase(); 
                let func_name = import.name.to_string(); 
                let sig = format!("{}:{}", dll_name, func_name); 
                let hash = murmur3_32(&mut Cursor::new(sig.as_bytes()), 0).unwrap_or(0); 
                let bucket = (hash % 1280) as usize; 
                if 612 + bucket < FEATURE_DIM { features[612 + bucket] = 1.0; } 
            } 

            // B. EXPORTS (Indices 1892-2019) 
            for export in pe.exports { 
                if let Some(name) = export.name { 
                    let hash = murmur3_32(&mut Cursor::new(name.as_bytes()), 0).unwrap_or(0); 
                    let bucket = (hash % 128) as usize; 
                    if 1892 + bucket < FEATURE_DIM { features[1892 + bucket] = 1.0; } 
                } 
            } 
            
            // C. SECTION NAMES (Indices 512-611) 
            for section in pe.sections { 
                if let Ok(name) = section.name() { 
                    let hash = murmur3_32(&mut Cursor::new(name.as_bytes()), 0).unwrap_or(0); 
                    let bucket = (hash % 50) as usize; 
                    if 512 + bucket < FEATURE_DIM { features[512 + bucket] = 1.0; } 
                } 
            } 
        }, 
        Err(e) => println!("   |-- [ERROR] PE Parse Failed: {}", e), 
    } 

    Ok(features) 
} 

// --- NEURAL ENGINE --- 
pub struct NeuralEngine { 
    static_model: Option<Mutex<Session>>, 
} 

impl NeuralEngine { 
    pub fn new() -> Self { 
        let _ = ort::init().with_name("ERDPS_Neural_Engine").commit(); 
        println!("[*] ERDPS Neural Engine: Initialized (2568 Features)."); 
        NeuralEngine { static_model: None } 
    } 

    pub fn init(&mut self) { 
        let rels = [
            "optimized_models/static_model_2024_quantized_optimized.onnx",
            "static_model_2024_quantized.onnx",
            "static_model_2024.onnx",
        ];

        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.to_path_buf()));

        let mut base_dirs: Vec<std::path::PathBuf> = vec![std::path::PathBuf::from(".")];
        if let Some(dir) = exe_dir.clone() {
            let mut cur = dir;
            for _ in 0..5 {
                base_dirs.push(cur.clone());
                if let Some(parent) = cur.parent() {
                    cur = parent.to_path_buf();
                } else {
                    break;
                }
            }
        }

        let mut candidates: Vec<std::path::PathBuf> = Vec::new();
        for rel in rels {
            for base in &base_dirs {
                candidates.push(base.join(rel));
            }
        }

        let found = candidates.into_iter().find(|p| p.exists());

        if let Some(model_path) = found {
            if !supply_chain::integrity_checks_disabled() {
                println!("[*] Verifying Model Integrity: {}", model_path.display());
                match supply_chain::verify_model_integrity(&model_path, model_hashes::STATIC_MODEL_SHA256_ALLOWLIST) {
                    Ok(true) => {}
                    Ok(false) => {
                        println!("\x1b[31m[!] CRITICAL: Model Hash Mismatch! Potential Supply Chain Attack.\x1b[0m");
                        if let Ok(actual) = supply_chain::calculate_sha256(&model_path) {
                            println!("\x1b[33m[DEBUG] Calculated Hash: {}\x1b[0m", actual);
                            println!("\x1b[33m[DEBUG] Allowed Hashes: {:?}\x1b[0m", model_hashes::STATIC_MODEL_SHA256_ALLOWLIST);
                        }
                        println!("\x1b[31m[!] Aborting Model Load for Safety.\x1b[0m");
                        return;
                    }
                    Err(e) => {
                        println!("\x1b[31m[!] CRITICAL: Unable to hash model file: {}\x1b[0m", e);
                        println!("\x1b[31m[!] Aborting Model Load for Safety.\x1b[0m");
                        return;
                    }
                }
            }

            match Session::builder()
                .and_then(|b| b.with_optimization_level(GraphOptimizationLevel::Disable))
                .and_then(|b| b.with_intra_threads(1))
                .and_then(|b| b.with_inter_threads(1))
                .and_then(|b| b.commit_from_file(&model_path))
            {
                Ok(s) => {
                    println!("[+] EMBER 2024 Model Loaded: {}", model_path.display());
                    self.static_model = Some(Mutex::new(s));
                }
                Err(e) => println!("[!] Failed to load model: {} ({})", model_path.display(), e),
            }
        } else {
            println!("\x1b[33m[!] Model missing. Layer 5 will rely on Heuristics.\x1b[0m");
        }
    } 

    pub fn scan_static(&self, file_path: &str) -> (f32, Vec<f32>) { 
        let buffer = match fs::read(file_path) { 
            Ok(b) => b, 
            Err(_) => return (0.0, vec![]), 
        }; 
        if buffer.is_empty() { return (0.0, vec![]); } 

        let feats = match extract_features(&buffer) { 
            Ok(f) => f, 
            Err(_) => return (0.0, vec![]) 
        }; 

        // 1. CALCULATE HEURISTIC SCORE (Baseline Truth) 
        let heuristic_score = self.calculate_heuristic_score(&feats); 

        // 2. ATTEMPT ONNX INFERENCE 
        let mut onnx_score = 0.0; 
        if let Some(mutex) = &self.static_model { 
            let array = Array2::from_shape_vec((1, FEATURE_DIM), feats.clone()).unwrap(); 
            let input = Value::from_array((vec![1, FEATURE_DIM], array.into_raw_vec())).unwrap(); 
            
            let mut session = mutex.lock().unwrap(); 
            // Fix lifetime issue: Use match or separate let binding
            let outputs_result = session.run(ort::inputs![input]);
            if let Ok(outputs) = outputs_result { 
                 if let Ok((_, probs)) = outputs[1].try_extract_tensor::<f32>() { 
                     onnx_score = probs[1]; 
                 } 
            } 
        } 

        // 3. HYBRID VERDICT (Max Pooling) 
        // If the model is confused (due to feature mismatch) but heuristics detect packing, trust heuristics. 
        let final_score = if onnx_score > heuristic_score { onnx_score } else { heuristic_score }; 
        
        // Return 0.01 floor for display consistency if totally clean 
        let display_score = if final_score < 0.01 { 0.01 } else { final_score }; 

        (display_score, feats) 
    } 

    fn calculate_heuristic_score(&self, feats: &[f32]) -> f32 { 
        let mut score = 0.0; 

        // A. High Entropy Check (Packer Indicator) 
        // Count non-zero buckets in histogram (0-255) 
        // Rust binaries and Packers both have high entropy. 
        let mut active_bytes = 0; 
        for i in 0..256 { if feats[i] > 0.001 { active_bytes += 1; } } 
        
        if active_bytes > 250 { 
            score += 0.20; // Base suspicion for high entropy 
        } 

        // B. Low Imports Check (Packer Indicator) 
        let mut import_count = 0; 
        for i in 612..1891 { if feats[i] > 0.0 { import_count += 1; } } 

        if import_count < 10 { 
            score += 0.40; // High suspicion: Very few imports often means packed/malicious 
        } else if import_count > 100 { 
            // High imports (like erdps-agent) usually reduce suspicion of being a simple packer 
            score = 0.05; 
        } 

        if score > 0.99 { 0.99 } else { score } 
    } 

    pub fn scan_behavior(&self, _seq: Vec<u32>) -> f32 { 0.0 } 
    pub fn check_anomaly(&self, _stats: Vec<f32>) -> bool { false } 
}
