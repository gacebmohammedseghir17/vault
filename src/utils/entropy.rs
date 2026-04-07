//! Comprehensive entropy analysis utilities for ERDPS Ultimate Detection Enhancement
//!
//! This module provides advanced entropy calculation and analysis capabilities for:
//! - Memory forensics and code injection detection
//! - Encrypted traffic analysis and C2 detection
//! - Ransomware detection through entropy patterns
//! - Advanced malware analysis and behavioral detection

use rayon::prelude::*;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Entropy analysis results with comprehensive metrics
#[derive(Debug, Clone, PartialEq)]
pub struct EntropyAnalysis {
    pub shannon_entropy: f64,
    pub kolmogorov_complexity: f64,
    pub chi_square_score: f64,
    pub entropy_rate: f64,
    pub block_entropy_variance: f64,
    pub is_encrypted: bool,
    pub is_compressed: bool,
    pub ransomware_probability: f64,
    pub analysis_timestamp: Instant,
}

/// Configuration for entropy analysis
#[derive(Debug, Clone)]
pub struct EntropyConfig {
    pub block_size: usize,
    pub encryption_threshold: f64,
    pub compression_threshold: f64,
    pub ransomware_threshold: f64,
    pub chi_square_threshold: f64,
    pub enable_caching: bool,
    pub cache_ttl: Duration,
}

impl Default for EntropyConfig {
    fn default() -> Self {
        Self {
            block_size: 4096,
            encryption_threshold: 7.5,
            compression_threshold: 6.0,
            ransomware_threshold: 0.8,
            chi_square_threshold: 255.0,
            enable_caching: true,
            cache_ttl: Duration::from_secs(300),
        }
    }
}

/// Memory region entropy analysis
#[derive(Debug, Clone)]
pub struct MemoryEntropyAnalysis {
    pub region_start: usize,
    pub region_size: usize,
    pub entropy: f64,
    pub is_executable: bool,
    pub injection_probability: f64,
    pub shellcode_probability: f64,
}

/// File section entropy analysis
#[derive(Debug, Clone)]
pub struct FileSectionEntropy {
    pub section_name: String,
    pub offset: u64,
    pub size: u64,
    pub entropy: f64,
    pub is_suspicious: bool,
}

/// Ransomware detection metrics
#[derive(Debug, Clone)]
pub struct RansomwareMetrics {
    pub entropy_spike_detected: bool,
    pub entropy_change_rate: f64,
    pub file_extension_entropy: f64,
    pub directory_entropy_variance: f64,
    pub encryption_pattern_score: f64,
}

/// Comprehensive entropy analyzer with caching and performance optimizations
#[derive(Debug)]
pub struct EntropyAnalyzer {
    config: EntropyConfig,
    cache: Arc<RwLock<HashMap<Vec<u8>, (EntropyAnalysis, Instant)>>>,
}

impl EntropyAnalyzer {
    /// Create a new entropy analyzer with default configuration
    pub fn new() -> Self {
        Self::with_config(EntropyConfig::default())
    }

    /// Create a new entropy analyzer with custom configuration
    pub fn with_config(config: EntropyConfig) -> Self {
        Self {
            config,
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Perform comprehensive entropy analysis on data
    pub fn analyze(&self, data: &[u8]) -> EntropyAnalysis {
        if self.config.enable_caching {
            if let Some(cached) = self.get_cached_analysis(data) {
                return cached;
            }
        }

        let analysis = self.perform_analysis(data);

        if self.config.enable_caching {
            self.cache_analysis(data, &analysis);
        }

        analysis
    }

    /// Perform streaming entropy analysis for large files
    pub fn analyze_stream<R: std::io::Read>(
        &self,
        mut reader: R,
    ) -> std::io::Result<EntropyAnalysis> {
        let mut buffer = vec![0u8; self.config.block_size];
        let mut total_entropy = 0.0;
        let mut block_count = 0;
        let mut entropy_values = Vec::new();

        loop {
            let bytes_read = reader.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }

            let block_entropy = self.shannon_entropy(&buffer[..bytes_read]);
            total_entropy += block_entropy;
            entropy_values.push(block_entropy);
            block_count += 1;
        }

        let avg_entropy = if block_count > 0 {
            total_entropy / block_count as f64
        } else {
            0.0
        };
        let variance = self.calculate_variance(&entropy_values, avg_entropy);

        Ok(EntropyAnalysis {
            shannon_entropy: avg_entropy,
            kolmogorov_complexity: self.estimate_kolmogorov_complexity(&entropy_values),
            chi_square_score: 0.0, // Would need full data for accurate chi-square
            entropy_rate: self.calculate_entropy_rate(&entropy_values),
            block_entropy_variance: variance,
            is_encrypted: avg_entropy > self.config.encryption_threshold,
            is_compressed: avg_entropy > self.config.compression_threshold
                && avg_entropy < self.config.encryption_threshold,
            ransomware_probability: self.calculate_ransomware_probability(avg_entropy, variance),
            analysis_timestamp: Instant::now(),
        })
    }

    /// Analyze memory regions for injection detection
    pub fn analyze_memory_region(
        &self,
        data: &[u8],
        region_start: usize,
        is_executable: bool,
    ) -> MemoryEntropyAnalysis {
        let entropy = self.shannon_entropy(data);
        let injection_prob = self.calculate_injection_probability(data, entropy, is_executable);
        let shellcode_prob = self.calculate_shellcode_probability(data, entropy);

        MemoryEntropyAnalysis {
            region_start,
            region_size: data.len(),
            entropy,
            is_executable,
            injection_probability: injection_prob,
            shellcode_probability: shellcode_prob,
        }
    }

    /// Analyze file sections (PE, ELF, etc.)
    pub fn analyze_file_sections(
        &self,
        file_path: &Path,
    ) -> std::io::Result<Vec<FileSectionEntropy>> {
        // This would integrate with PE/ELF parsers in a real implementation
        // For now, we'll analyze the file in chunks
        let data = std::fs::read(file_path)?;
        let mut sections = Vec::new();
        let chunk_size = 4096;

        for (i, chunk) in data.chunks(chunk_size).enumerate() {
            let entropy = self.shannon_entropy(chunk);
            let is_suspicious =
                entropy > self.config.encryption_threshold || (entropy < 1.0 && chunk.len() > 100); // Very low entropy in large sections

            sections.push(FileSectionEntropy {
                section_name: format!("section_{}", i),
                offset: (i * chunk_size) as u64,
                size: chunk.len() as u64,
                entropy,
                is_suspicious,
            });
        }

        Ok(sections)
    }

    /// Detect ransomware patterns in directory
    pub fn analyze_ransomware_patterns(
        &self,
        directory_files: &[(String, Vec<u8>)],
    ) -> RansomwareMetrics {
        let entropies: Vec<f64> = directory_files
            .par_iter()
            .map(|(_, data)| self.shannon_entropy(data))
            .collect();

        let avg_entropy = entropies.iter().sum::<f64>() / entropies.len() as f64;
        let variance = self.calculate_variance(&entropies, avg_entropy);

        // Calculate entropy change rate (would need historical data in real implementation)
        let entropy_change_rate = variance; // Simplified for this example

        // Analyze file extensions
        let extension_entropy = self.analyze_extension_entropy(directory_files);

        // Detect entropy spikes
        let entropy_spike = entropies
            .iter()
            .any(|&e| e > self.config.encryption_threshold);

        // Calculate encryption pattern score
        let encryption_score = entropies
            .iter()
            .filter(|&&e| e > self.config.encryption_threshold)
            .count() as f64
            / entropies.len() as f64;

        RansomwareMetrics {
            entropy_spike_detected: entropy_spike,
            entropy_change_rate,
            file_extension_entropy: extension_entropy,
            directory_entropy_variance: variance,
            encryption_pattern_score: encryption_score,
        }
    }

    /// Calculate Shannon entropy for byte sequence
    pub fn shannon_entropy(&self, data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut frequency = [0u32; 256];
        for &byte in data {
            frequency[byte as usize] += 1;
        }

        let len = data.len() as f64;
        let mut entropy = 0.0;

        for &count in &frequency {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }

        entropy
    }

    /// Estimate Kolmogorov complexity using compression ratio
    fn estimate_kolmogorov_complexity(&self, data: &[f64]) -> f64 {
        // Simplified estimation using data patterns
        let mut complexity = 0.0;
        let mut prev = 0.0;

        for &value in data {
            complexity += (value - prev).abs();
            prev = value;
        }

        complexity / data.len() as f64
    }

    /// Perform chi-square randomness test
    fn chi_square_test(&self, data: &[u8]) -> f64 {
        let mut frequency = [0u32; 256];
        for &byte in data {
            frequency[byte as usize] += 1;
        }

        let expected = data.len() as f64 / 256.0;
        let mut chi_square = 0.0;

        for &count in &frequency {
            let diff = count as f64 - expected;
            chi_square += (diff * diff) / expected;
        }

        chi_square
    }

    /// Calculate entropy rate for time series data
    fn calculate_entropy_rate(&self, entropies: &[f64]) -> f64 {
        if entropies.len() < 2 {
            return 0.0;
        }

        let mut rate = 0.0;
        for i in 1..entropies.len() {
            rate += (entropies[i] - entropies[i - 1]).abs();
        }

        rate / (entropies.len() - 1) as f64
    }

    /// Calculate variance of entropy values
    fn calculate_variance(&self, values: &[f64], mean: f64) -> f64 {
        if values.is_empty() {
            return 0.0;
        }

        let variance =
            values.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / values.len() as f64;

        variance
    }

    /// Perform comprehensive analysis
    fn perform_analysis(&self, data: &[u8]) -> EntropyAnalysis {
        let shannon = self.shannon_entropy(data);
        let chi_square = self.chi_square_test(data);

        // Block-wise analysis
        let blocks: Vec<f64> = data
            .chunks(self.config.block_size)
            .map(|chunk| self.shannon_entropy(chunk))
            .collect();

        let block_variance = if !blocks.is_empty() {
            let mean = blocks.iter().sum::<f64>() / blocks.len() as f64;
            self.calculate_variance(&blocks, mean)
        } else {
            0.0
        };

        let kolmogorov = self.estimate_kolmogorov_complexity(&blocks);
        let entropy_rate = self.calculate_entropy_rate(&blocks);

        let is_encrypted = shannon > self.config.encryption_threshold;
        let is_compressed = shannon > self.config.compression_threshold && !is_encrypted;
        let ransomware_prob = self.calculate_ransomware_probability(shannon, block_variance);

        EntropyAnalysis {
            shannon_entropy: shannon,
            kolmogorov_complexity: kolmogorov,
            chi_square_score: chi_square,
            entropy_rate,
            block_entropy_variance: block_variance,
            is_encrypted,
            is_compressed,
            ransomware_probability: ransomware_prob,
            analysis_timestamp: Instant::now(),
        }
    }

    /// Calculate probability of code injection
    fn calculate_injection_probability(
        &self,
        data: &[u8],
        entropy: f64,
        is_executable: bool,
    ) -> f64 {
        let mut score: f64 = 0.0;

        // High entropy in executable regions is suspicious
        if is_executable && entropy > 7.0 {
            score += 0.4;
        }

        // Look for common shellcode patterns
        if self.contains_shellcode_patterns(data) {
            score += 0.3;
        }

        // Check for ROP/JOP gadgets
        if self.contains_rop_patterns(data) {
            score += 0.3;
        }

        score.min(1.0)
    }

    /// Calculate probability of shellcode
    fn calculate_shellcode_probability(&self, data: &[u8], entropy: f64) -> f64 {
        let mut score: f64 = 0.0;

        // Moderate entropy is typical for shellcode
        if entropy > 4.0 && entropy < 7.0 {
            score += 0.3;
        }

        // Look for common shellcode instructions
        if self.contains_shellcode_instructions(data) {
            score += 0.4;
        }

        // Check for NOP sleds
        if self.contains_nop_sleds(data) {
            score += 0.3;
        }

        score.min(1.0)
    }

    /// Calculate ransomware probability based on entropy patterns
    fn calculate_ransomware_probability(&self, entropy: f64, variance: f64) -> f64 {
        let mut score: f64 = 0.0;

        // High entropy suggests encryption
        if entropy > self.config.encryption_threshold {
            score += 0.5;
        }

        // High variance suggests mixed content (some encrypted, some not)
        if variance > 2.0 {
            score += 0.3;
        }

        // Very high entropy with low variance suggests uniform encryption
        if entropy > 7.8 && variance < 0.5 {
            score += 0.2;
        }

        score.min(1.0)
    }

    /// Analyze entropy of file extensions in directory
    fn analyze_extension_entropy(&self, files: &[(String, Vec<u8>)]) -> f64 {
        let extensions: Vec<String> = files
            .iter()
            .filter_map(|(name, _)| {
                Path::new(name)
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .map(|s| s.to_lowercase())
            })
            .collect();

        if extensions.is_empty() {
            return 0.0;
        }

        // Convert extensions to bytes for entropy calculation
        let ext_bytes: Vec<u8> = extensions.join("").into_bytes();
        self.shannon_entropy(&ext_bytes)
    }

    /// Check for common shellcode patterns
    fn contains_shellcode_patterns(&self, data: &[u8]) -> bool {
        // Common x86/x64 shellcode patterns
        let patterns: &[&[u8]] = &[
            &[0x90, 0x90, 0x90, 0x90], // NOP sled
            &[0x31, 0xc0],             // xor eax, eax
            &[0x50, 0x68],             // push eax; push imm32
            &[0xeb, 0xfe],             // jmp $
        ];

        patterns
            .iter()
            .any(|pattern| data.windows(pattern.len()).any(|window| window == *pattern))
    }

    /// Check for ROP/JOP patterns
    fn contains_rop_patterns(&self, data: &[u8]) -> bool {
        // Look for common ROP gadget endings
        let gadget_endings: &[&[u8]] = &[
            &[0xc3],       // ret
            &[0xff, 0xe0], // jmp eax
            &[0xff, 0xe4], // jmp esp
        ];

        gadget_endings
            .iter()
            .any(|ending| data.windows(ending.len()).any(|window| window == *ending))
    }

    /// Check for shellcode instructions
    fn contains_shellcode_instructions(&self, data: &[u8]) -> bool {
        // Common shellcode instruction patterns
        let instructions: &[&[u8]] = &[
            &[0x89, 0xe5], // mov ebp, esp
            &[0x83, 0xec], // sub esp, imm8
            &[0x68],       // push imm32
            &[0xb8],       // mov eax, imm32
        ];

        instructions.iter().any(|instr| {
            data.windows(instr.len())
                .any(|window| window.starts_with(instr))
        })
    }

    /// Check for NOP sleds
    fn contains_nop_sleds(&self, data: &[u8]) -> bool {
        let mut nop_count = 0;
        let mut max_nop_run = 0;

        for &byte in data {
            if byte == 0x90 {
                // NOP instruction
                nop_count += 1;
                max_nop_run = max_nop_run.max(nop_count);
            } else {
                nop_count = 0;
            }
        }

        max_nop_run >= 8 // 8 or more consecutive NOPs
    }

    /// Get cached analysis if available and not expired
    fn get_cached_analysis(&self, data: &[u8]) -> Option<EntropyAnalysis> {
        if let Ok(cache) = self.cache.read() {
            if let Some((analysis, timestamp)) = cache.get(data) {
                if timestamp.elapsed() < self.config.cache_ttl {
                    return Some(analysis.clone());
                }
            }
        }
        None
    }

    /// Cache analysis result
    fn cache_analysis(&self, data: &[u8], analysis: &EntropyAnalysis) {
        if let Ok(mut cache) = self.cache.write() {
            // Limit cache size to prevent memory issues
            if cache.len() > 1000 {
                cache.clear();
            }
            cache.insert(data.to_vec(), (analysis.clone(), Instant::now()));
        }
    }

    /// Clear expired cache entries
    pub fn cleanup_cache(&self) {
        if let Ok(mut cache) = self.cache.write() {
            cache.retain(|_, (_, timestamp)| timestamp.elapsed() < self.config.cache_ttl);
        }
    }
}

/// Convenience function for basic Shannon entropy calculation
pub fn shannon_entropy(data: &[u8]) -> f32 {
    EntropyAnalyzer::new().shannon_entropy(data) as f32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shannon_entropy_uniform() {
        let data: Vec<u8> = (0..=255).collect();
        let entropy = shannon_entropy(&data);
        assert!(entropy > 7.9);
    }

    #[test]
    fn test_shannon_entropy_low() {
        let data = vec![0u8; 256];
        let entropy = shannon_entropy(&data);
        assert_eq!(entropy, 0.0);
    }

    #[test]
    fn test_shannon_entropy_empty() {
        let data = vec![];
        let entropy = shannon_entropy(&data);
        assert_eq!(entropy, 0.0);
    }

    #[test]
    fn test_entropy_analyzer_basic() {
        let analyzer = EntropyAnalyzer::new();
        let data = vec![0u8; 100];
        let analysis = analyzer.analyze(&data);

        assert_eq!(analysis.shannon_entropy, 0.0);
        assert!(!analysis.is_encrypted);
        assert!(!analysis.is_compressed);
    }

    #[test]
    fn test_entropy_analyzer_high_entropy() {
        let analyzer = EntropyAnalyzer::new();
        let data: Vec<u8> = (0..=255).cycle().take(1000).collect();
        let analysis = analyzer.analyze(&data);

        assert!(analysis.shannon_entropy > 7.0);
        assert!(analysis.is_encrypted);
    }

    #[test]
    fn test_memory_region_analysis() {
        let analyzer = EntropyAnalyzer::new();
        let data = vec![0x90; 100]; // NOP sled
        let analysis = analyzer.analyze_memory_region(&data, 0x1000, true);

        assert_eq!(analysis.region_start, 0x1000);
        assert_eq!(analysis.region_size, 100);
        assert!(analysis.is_executable);
        assert!(analysis.shellcode_probability > 0.0);
    }

    #[test]
    fn test_ransomware_detection() {
        let analyzer = EntropyAnalyzer::new();
        let files = vec![
            (
                "file1.txt".to_string(),
                (0..=255u8).cycle().take(1000).collect(),
            ),
            (
                "file2.doc".to_string(),
                (0..=255u8).cycle().take(1000).collect(),
            ),
        ];

        let metrics = analyzer.analyze_ransomware_patterns(&files);
        assert!(metrics.entropy_spike_detected);
        assert!(metrics.encryption_pattern_score > 0.5);
    }

    #[test]
    fn test_shellcode_pattern_detection() {
        let analyzer = EntropyAnalyzer::new();
        let data = vec![0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x31, 0xc0]; // NOP sled (8 NOPs) + xor eax,eax

        assert!(analyzer.contains_shellcode_patterns(&data));
        assert!(analyzer.contains_nop_sleds(&data));
    }

    #[test]
    fn test_chi_square_test() {
        let analyzer = EntropyAnalyzer::new();
        let uniform_data: Vec<u8> = (0..=255).collect();
        let chi_square = analyzer.chi_square_test(&uniform_data);

        // Uniform distribution should have low chi-square value
        assert!(chi_square < 300.0);
    }

    #[test]
    fn test_entropy_caching() {
        let config = EntropyConfig {
            enable_caching: true,
            cache_ttl: Duration::from_secs(1),
            ..Default::default()
        };
        let analyzer = EntropyAnalyzer::with_config(config);
        let data = vec![1, 2, 3, 4, 5];

        let analysis1 = analyzer.analyze(&data);
        let analysis2 = analyzer.analyze(&data);

        // Should be identical due to caching
        assert_eq!(analysis1.shannon_entropy, analysis2.shannon_entropy);
    }
}
