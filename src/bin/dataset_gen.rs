// Run: cargo run --release --bin dataset_gen -- <malware_dir> <benign_dir>
use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use memmap2::Mmap;
use iced_x86::{Decoder, DecoderOptions, Instruction};
use twox_hash::XxHash64;
use std::hash::Hasher;
use rayon::prelude::*; // Parallel processing for speed

const FEATURE_DIM: usize = 4096; // Optimal dimension

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        println!("Usage: dataset_gen <malware_dir> <benign_dir>");
        return;
    }

    let malware_dir = &args[1];
    let benign_dir = &args[2];
    
    // Create CSV Output
    let mut csv_file = File::create("training_data.csv").expect("Failed to create CSV");
    
    // Write Header: f0,f1,...,f4095,label
    for i in 0..FEATURE_DIM { write!(csv_file, "f{},", i).unwrap(); }
    writeln!(csv_file, "label").unwrap();

    // Collect all file paths
    let mut samples = Vec::new();
    collect_samples(malware_dir, 1, &mut samples);
    collect_samples(benign_dir, 0, &mut samples);

    println!("[*] Processing {} samples using Rayon...", samples.len());

    // Process in Parallel (Map-Reduce style)
    let results: Vec<String> = samples.par_iter().map(|(path, label)| {
        if let Ok(file) = File::open(path) {
            // Safe memory map
            if let Ok(mmap) = unsafe { Mmap::map(&file) } {
                let features = extract_features(&mmap);
                
                // Convert features to CSV row string
                let mut row = String::with_capacity(FEATURE_DIM * 8);
                for val in features.iter() {
                    row.push_str(&format!("{:.4},", val));
                }
                row.push_str(&format!("{}\n", label));
                return Some(row);
            }
        }
        None
    }).filter_map(|x| x).collect();

    // Write to file (Sequential write is faster than parallel write locking)
    for row in results {
        csv_file.write_all(row.as_bytes()).unwrap();
    }
    
    println!("[+] Done! Saved {} rows to 'training_data.csv'.", samples.len());
}

fn collect_samples(dir: &str, label: u8, list: &mut Vec<(std::path::PathBuf, u8)>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            if entry.path().is_file() {
                list.push((entry.path(), label));
            }
        }
    }
}

// --- CORE LOGIC (Must match ml_ngram.rs EXACTLY) ---
fn extract_features(bytes: &[u8]) -> Vec<f32> {
    let mut vector = vec![0.0f32; FEATURE_DIM];
    
    // Skip non-executable files (basic check)
    if bytes.len() < 64 { return vector; }

    let mut decoder = Decoder::new(64, bytes, DecoderOptions::NONE);
    let mut instruction = Instruction::default();
    let mut mnemonics: Vec<u16> = Vec::with_capacity(10000);
    
    // 1. Fast Linear Sweep (Limit 10k instructions)
    let mut count = 0;
    while decoder.can_decode() && count < 10000 {
        decoder.decode_out(&mut instruction);
        // We use the raw enum variant ID (u16) instead of string for speed
        mnemonics.push(instruction.mnemonic() as u16);
        count += 1;
    }

    if mnemonics.len() < 3 { return vector; }

    // 2. N-Gram Hashing (XXH3)
    for window in mnemonics.windows(3) {
        let mut hasher = XxHash64::with_seed(0);
        hasher.write_u16(window[0]);
        hasher.write_u16(window[1]);
        hasher.write_u16(window[2]);
        let hash = hasher.finish();
        
        let index = (hash as usize) % FEATURE_DIM;
        vector[index] += 1.0;
    }

    // 3. L2 Normalization
    let magnitude: f32 = vector.iter().map(|x| x * x).sum::<f32>().sqrt();
    if magnitude > 0.0 {
        for x in vector.iter_mut() { *x /= magnitude; }
    }

    vector
}
