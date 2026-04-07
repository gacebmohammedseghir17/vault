//! SIMD Operations Module
//!
//! This module provides SIMD-optimized operations for pattern matching,
//! data processing, and cryptographic operations to enhance performance.

use std::arch::x86_64::*;

use rayon::prelude::*;
use crate::performance::{PatternMatch, PerformanceError};

/// SIMD operations handler with platform-specific optimizations
pub struct SimdOperations {
    enabled: bool,
    supports_avx2: bool,
    supports_sse42: bool,
    chunk_size: usize,
}

impl SimdOperations {
    /// Create a new SIMD operations handler
    pub fn new(enabled: bool) -> Result<Self, PerformanceError> {
        let supports_avx2 = is_x86_feature_detected!("avx2");
        let supports_sse42 = is_x86_feature_detected!("sse4.2");
        
        if enabled && !supports_sse42 {
            return Err(PerformanceError::SimdNotSupported);
        }
        
        let chunk_size = if supports_avx2 { 32 } else { 16 };
        
        Ok(Self {
            enabled,
            supports_avx2,
            supports_sse42,
            chunk_size,
        })
    }
    
    /// Perform parallel pattern search using SIMD operations
    pub async fn parallel_pattern_search(
        &self,
        data: &[u8],
        patterns: &[Vec<u8>],
    ) -> Result<Vec<PatternMatch>, PerformanceError> {
        if !self.enabled {
            return self.fallback_search(data, patterns).await;
        }
        
        // Process patterns in parallel using SIMD
        let matches: Vec<PatternMatch> = patterns
            .par_iter()
            .enumerate()
            .filter_map(|(pattern_id, pattern)| {
                self.simd_pattern_search(data, pattern, pattern_id).ok()
            })
            .flatten()
            .collect();
        
        Ok(matches)
    }
    
    /// SIMD-optimized pattern search for a single pattern
    fn simd_pattern_search(
        &self,
        data: &[u8],
        pattern: &[u8],
        pattern_id: usize,
    ) -> Result<Vec<PatternMatch>, PerformanceError> {
        if pattern.is_empty() || pattern.len() > data.len() {
            return Ok(Vec::new());
        }
        
        let mut matches = Vec::new();
        
        if self.supports_avx2 && pattern.len() >= 4 {
            matches.extend(unsafe { self.avx2_pattern_search(data, pattern, pattern_id)? });
        } else if self.supports_sse42 && pattern.len() >= 2 {
            matches.extend(unsafe { self.sse42_pattern_search(data, pattern, pattern_id)? });
        } else {
            matches.extend(self.scalar_pattern_search(data, pattern, pattern_id)?);
        }
        
        Ok(matches)
    }
    
    /// AVX2-optimized pattern search
    #[target_feature(enable = "avx2")]
    unsafe fn avx2_pattern_search(
        &self,
        data: &[u8],
        pattern: &[u8],
        pattern_id: usize,
    ) -> Result<Vec<PatternMatch>, PerformanceError> {
        let mut matches = Vec::new();
        let pattern_len = pattern.len();
        
        if pattern_len == 0 || data.len() < pattern_len {
            return Ok(matches);
        }
        
        // Load first byte of pattern into AVX2 register
        let first_byte = _mm256_set1_epi8(pattern[0] as i8);
        
        let mut pos = 0;
        while pos + 32 <= data.len() {
            // Load 32 bytes of data
            let data_chunk = _mm256_loadu_si256(data.as_ptr().add(pos) as *const __m256i);
            
            // Compare with first byte of pattern
            let cmp_result = _mm256_cmpeq_epi8(data_chunk, first_byte);
            let mask = _mm256_movemask_epi8(cmp_result) as u32;
            
            // Check each potential match
            let mut bit_pos = 0;
            let mut remaining_mask = mask;
            while remaining_mask != 0 {
                let offset = remaining_mask.trailing_zeros();
                bit_pos += offset;
                
                let match_pos = pos + bit_pos as usize;
                if match_pos + pattern_len <= data.len() {
                    // Verify full pattern match
                    if data[match_pos..match_pos + pattern_len] == *pattern {
                        matches.push(PatternMatch {
                            pattern_id,
                            offset: match_pos,
                            length: pattern_len,
                            confidence: 1.0,
                        });
                    }
                }
                
                remaining_mask >>= offset + 1;
                bit_pos += 1;
            }
            
            pos += 32;
        }
        
        // Handle remaining bytes with scalar search
        matches.extend(self.scalar_pattern_search(
            &data[pos..],
            pattern,
            pattern_id,
        )?.into_iter().map(|mut m| {
            m.offset += pos;
            m
        }));
        
        Ok(matches)
    }
    
    /// SSE4.2-optimized pattern search
    #[target_feature(enable = "sse4.2")]
    unsafe fn sse42_pattern_search(
        &self,
        data: &[u8],
        pattern: &[u8],
        pattern_id: usize,
    ) -> Result<Vec<PatternMatch>, PerformanceError> {
        let mut matches = Vec::new();
        let pattern_len = pattern.len();
        
        if pattern_len == 0 || data.len() < pattern_len {
            return Ok(matches);
        }
        
        // Load first byte of pattern into SSE register
        let first_byte = _mm_set1_epi8(pattern[0] as i8);
        
        let mut pos = 0;
        while pos + 16 <= data.len() {
            // Load 16 bytes of data
            let data_chunk = _mm_loadu_si128(data.as_ptr().add(pos) as *const __m128i);
            
            // Compare with first byte of pattern
            let cmp_result = _mm_cmpeq_epi8(data_chunk, first_byte);
            let mask = _mm_movemask_epi8(cmp_result) as u16;
            
            // Check each potential match
            let mut bit_pos = 0;
            let mut remaining_mask = mask;
            while remaining_mask != 0 {
                let offset = remaining_mask.trailing_zeros();
                bit_pos += offset;
                
                let match_pos = pos + bit_pos as usize;
                if match_pos + pattern_len <= data.len() {
                    // Verify full pattern match
                    if data[match_pos..match_pos + pattern_len] == *pattern {
                        matches.push(PatternMatch {
                            pattern_id,
                            offset: match_pos,
                            length: pattern_len,
                            confidence: 1.0,
                        });
                    }
                }
                
                remaining_mask >>= offset + 1;
                bit_pos += 1;
            }
            
            pos += 16;
        }
        
        // Handle remaining bytes with scalar search
        matches.extend(self.scalar_pattern_search(
            &data[pos..],
            pattern,
            pattern_id,
        )?.into_iter().map(|mut m| {
            m.offset += pos;
            m
        }));
        
        Ok(matches)
    }
    
    /// Scalar pattern search fallback
    fn scalar_pattern_search(
        &self,
        data: &[u8],
        pattern: &[u8],
        pattern_id: usize,
    ) -> Result<Vec<PatternMatch>, PerformanceError> {
        let mut matches = Vec::new();
        let pattern_len = pattern.len();
        
        if pattern_len == 0 || data.len() < pattern_len {
            return Ok(matches);
        }
        
        // Boyer-Moore-like optimization for scalar search
        let mut pos = 0;
        while pos <= data.len() - pattern_len {
            if data[pos..pos + pattern_len] == *pattern {
                matches.push(PatternMatch {
                    pattern_id,
                    offset: pos,
                    length: pattern_len,
                    confidence: 1.0,
                });
                pos += 1; // Move by 1 to find overlapping matches
            } else {
                // Skip ahead based on last character mismatch
                let skip = self.calculate_skip_distance(
                    &data[pos..pos + pattern_len],
                    pattern,
                );
                pos += skip.max(1);
            }
        }
        
        Ok(matches)
    }
    
    /// Calculate skip distance for Boyer-Moore optimization
    fn calculate_skip_distance(&self, data_chunk: &[u8], pattern: &[u8]) -> usize {
        let last_char = data_chunk[data_chunk.len() - 1];
        
        // Find rightmost occurrence of last_char in pattern (excluding last position)
        for i in (0..pattern.len() - 1).rev() {
            if pattern[i] == last_char {
                return pattern.len() - 1 - i;
            }
        }
        
        pattern.len()
    }
    
    /// SIMD-optimized memory comparison
    pub fn simd_memory_compare(&self, data1: &[u8], data2: &[u8]) -> bool {
        if data1.len() != data2.len() {
            return false;
        }
        
        if !self.enabled {
            return data1 == data2;
        }
        
        unsafe {
            if self.supports_avx2 {
                self.avx2_memory_compare(data1, data2)
            } else if self.supports_sse42 {
                self.sse42_memory_compare(data1, data2)
            } else {
                data1 == data2
            }
        }
    }
    
    /// AVX2-optimized memory comparison
    #[target_feature(enable = "avx2")]
    unsafe fn avx2_memory_compare(&self, data1: &[u8], data2: &[u8]) -> bool {
        let len = data1.len();
        let mut pos = 0;
        
        // Process 32-byte chunks
        while pos + 32 <= len {
            let chunk1 = _mm256_loadu_si256(data1.as_ptr().add(pos) as *const __m256i);
            let chunk2 = _mm256_loadu_si256(data2.as_ptr().add(pos) as *const __m256i);
            
            let cmp_result = _mm256_cmpeq_epi8(chunk1, chunk2);
            let mask = _mm256_movemask_epi8(cmp_result);
            
            if mask != -1 {
                return false;
            }
            
            pos += 32;
        }
        
        // Handle remaining bytes
        data1[pos..] == data2[pos..]
    }
    
    /// SSE4.2-optimized memory comparison
    #[target_feature(enable = "sse4.2")]
    unsafe fn sse42_memory_compare(&self, data1: &[u8], data2: &[u8]) -> bool {
        let len = data1.len();
        let mut pos = 0;
        
        // Process 16-byte chunks
        while pos + 16 <= len {
            let chunk1 = _mm_loadu_si128(data1.as_ptr().add(pos) as *const __m128i);
            let chunk2 = _mm_loadu_si128(data2.as_ptr().add(pos) as *const __m128i);
            
            let cmp_result = _mm_cmpeq_epi8(chunk1, chunk2);
            let mask = _mm_movemask_epi8(cmp_result);
            
            if mask != 0xFFFF {
                return false;
            }
            
            pos += 16;
        }
        
        // Handle remaining bytes
        data1[pos..] == data2[pos..]
    }
    
    /// SIMD-optimized checksum calculation
    pub fn simd_checksum(&self, data: &[u8]) -> u64 {
        if !self.enabled {
            return self.scalar_checksum(data);
        }
        
        unsafe {
            if self.supports_avx2 {
                self.avx2_checksum(data)
            } else if self.supports_sse42 {
                self.sse42_checksum(data)
            } else {
                self.scalar_checksum(data)
            }
        }
    }
    
    /// AVX2-optimized checksum calculation
    #[target_feature(enable = "avx2")]
    unsafe fn avx2_checksum(&self, data: &[u8]) -> u64 {
        let mut checksum = _mm256_setzero_si256();
        let mut pos = 0;
        
        // Process 32-byte chunks
        while pos + 32 <= data.len() {
            let chunk = _mm256_loadu_si256(data.as_ptr().add(pos) as *const __m256i);
            checksum = _mm256_add_epi64(checksum, _mm256_sad_epu8(chunk, _mm256_setzero_si256()));
            pos += 32;
        }
        
        // Extract sum from AVX2 register
        let mut result = [0u64; 4];
        _mm256_storeu_si256(result.as_mut_ptr() as *mut __m256i, checksum);
        let mut sum = result[0] + result[1] + result[2] + result[3];
        
        // Handle remaining bytes
        for &byte in &data[pos..] {
            sum = sum.wrapping_add(byte as u64);
        }
        
        sum
    }
    
    /// SSE4.2-optimized checksum calculation
    #[target_feature(enable = "sse4.2")]
    unsafe fn sse42_checksum(&self, data: &[u8]) -> u64 {
        let mut checksum = _mm_setzero_si128();
        let mut pos = 0;
        
        // Process 16-byte chunks
        while pos + 16 <= data.len() {
            let chunk = _mm_loadu_si128(data.as_ptr().add(pos) as *const __m128i);
            checksum = _mm_add_epi64(checksum, _mm_sad_epu8(chunk, _mm_setzero_si128()));
            pos += 16;
        }
        
        // Extract sum from SSE register
        let mut result = [0u64; 2];
        _mm_storeu_si128(result.as_mut_ptr() as *mut __m128i, checksum);
        let mut sum = result[0] + result[1];
        
        // Handle remaining bytes
        for &byte in &data[pos..] {
            sum = sum.wrapping_add(byte as u64);
        }
        
        sum
    }
    
    /// Scalar checksum calculation
    fn scalar_checksum(&self, data: &[u8]) -> u64 {
        data.iter().map(|&b| b as u64).sum()
    }
    
    /// Fallback search without SIMD
    async fn fallback_search(
        &self,
        data: &[u8],
        patterns: &[Vec<u8>],
    ) -> Result<Vec<PatternMatch>, PerformanceError> {
        let matches: Vec<PatternMatch> = patterns
            .par_iter()
            .enumerate()
            .filter_map(|(pattern_id, pattern)| {
                self.scalar_pattern_search(data, pattern, pattern_id).ok()
            })
            .flatten()
            .collect();
        
        Ok(matches)
    }
    
    /// Get SIMD capabilities information
    pub fn get_capabilities(&self) -> SimdCapabilities {
        SimdCapabilities {
            enabled: self.enabled,
            supports_avx2: self.supports_avx2,
            supports_sse42: self.supports_sse42,
            chunk_size: self.chunk_size,
        }
    }
}

/// SIMD capabilities information
#[derive(Debug, Clone)]
pub struct SimdCapabilities {
    pub enabled: bool,
    pub supports_avx2: bool,
    pub supports_sse42: bool,
    pub chunk_size: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_simd_operations_creation() {
        let simd_ops = SimdOperations::new(true);
        assert!(simd_ops.is_ok());
        
        let simd_ops = simd_ops.unwrap();
        let capabilities = simd_ops.get_capabilities();
        assert!(capabilities.enabled);
    }
    
    #[tokio::test]
    async fn test_pattern_search() {
        let simd_ops = SimdOperations::new(false).unwrap(); // Disable SIMD for testing
        
        let data = b"This is a test string with PATTERN and another PATTERN here";
        let patterns = vec![b"PATTERN".to_vec(), b"MISSING".to_vec()];
        
        let matches = simd_ops.parallel_pattern_search(data, &patterns).await.unwrap();
        
        // Should find 2 matches for "PATTERN"
        let pattern_matches: Vec<_> = matches.iter().filter(|m| m.pattern_id == 0).collect();
        assert_eq!(pattern_matches.len(), 2);
        
        // Should find 0 matches for "MISSING"
        let missing_matches: Vec<_> = matches.iter().filter(|m| m.pattern_id == 1).collect();
        assert_eq!(missing_matches.len(), 0);
    }
    
    #[test]
    fn test_memory_compare() {
        let simd_ops = SimdOperations::new(false).unwrap();
        
        let data1 = b"Hello, World!";
        let data2 = b"Hello, World!";
        let data3 = b"Hello, Rust!";
        
        assert!(simd_ops.simd_memory_compare(data1, data2));
        assert!(!simd_ops.simd_memory_compare(data1, data3));
    }
    
    #[test]
    fn test_checksum_calculation() {
        let simd_ops = SimdOperations::new(false).unwrap();
        
        let data = b"Test data for checksum calculation";
        let checksum = simd_ops.simd_checksum(data);
        
        // Verify checksum is consistent
        let checksum2 = simd_ops.simd_checksum(data);
        assert_eq!(checksum, checksum2);
        
        // Different data should produce different checksum
        let different_data = b"Different test data";
        let different_checksum = simd_ops.simd_checksum(different_data);
        assert_ne!(checksum, different_checksum);
    }
    
    #[test]
    fn test_scalar_pattern_search() {
        let simd_ops = SimdOperations::new(false).unwrap();
        
        let data = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let pattern = b"MNOP";
        
        let matches = simd_ops.scalar_pattern_search(data, pattern, 0).unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].offset, 12); // Position of "MNOP" in alphabet
    }
}
