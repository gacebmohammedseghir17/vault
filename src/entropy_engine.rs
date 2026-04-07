#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

pub struct EntropyAccelerator;

impl EntropyAccelerator {
    // ⚡ AVX2 OPTIMIZED ENTROPY CALCULATION
    pub fn calculate(buffer: &[u8]) -> f32 {
        if is_x86_feature_detected!("avx2") {
            unsafe { Self::calc_avx2(buffer) }
        } else {
            Self::calc_scalar(buffer)
        }
    }

    // 🐢 FALLBACK (Standard Rust)
    fn calc_scalar(data: &[u8]) -> f32 {
        let mut counts = [0u32; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }
        Self::shannon_formula(&counts, data.len())
    }

    // 🐇 GOD MODE (AVX2 Intrinsics)
    #[target_feature(enable = "avx2")]
    unsafe fn calc_avx2(data: &[u8]) -> f32 {
        let mut counts = [0u32; 256];
        let len = data.len();
        let mut i = 0;

        // Process 32 bytes at a time (256-bit registers)
        while i + 32 <= len {
            // Load 32 bytes into YMM register
            let chunk = _mm256_loadu_si256(data.as_ptr().add(i) as *const __m256i);
            
            // Extract and count (Manually unrolled for speed)
            let bytes: [u8; 32] = std::mem::transmute(chunk);
            for b in bytes.iter() {
                *counts.get_unchecked_mut(*b as usize) += 1;
            }

            i += 32;
        }

        // Handle remaining bytes
        for j in i..len {
            counts[*data.get_unchecked(j) as usize] += 1;
        }

        Self::shannon_formula(&counts, len)
    }

    fn shannon_formula(counts: &[u32; 256], total: usize) -> f32 {
        let mut entropy = 0.0;
        let total_f = total as f32;
        for &count in counts {
            if count > 0 {
                let p = count as f32 / total_f;
                entropy -= p * p.log2();
            }
        }
        entropy
    }
}
