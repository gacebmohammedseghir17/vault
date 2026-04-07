//! Test utilities module
//!
//! This module provides common test utility functions that are used across
//! multiple test files in the ERDPS agent test suite.

use std::collections::HashMap;
use std::time::SystemTime;

/// Generate deterministic test process events
pub fn generate_test_process_events() -> Vec<(String, HashMap<String, String>)> {
    vec![
        (
            "CreateFile".to_string(),
            HashMap::from([
                ("filename".to_string(), "test_document_001.txt".to_string()),
                ("access".to_string(), "GENERIC_WRITE".to_string()),
                ("timestamp".to_string(), "1640995200".to_string()), // Fixed timestamp
            ]),
        ),
        (
            "WriteFile".to_string(),
            HashMap::from([
                ("bytes_written".to_string(), "2048".to_string()),
                ("pattern".to_string(), "ransomware_marker".to_string()),
            ]),
        ),
        (
            "CreateFile".to_string(),
            HashMap::from([
                (
                    "filename".to_string(),
                    "test_document_001.txt.locked".to_string(),
                ),
                ("access".to_string(), "GENERIC_WRITE".to_string()),
                ("extension_change".to_string(), "true".to_string()),
            ]),
        ),
        (
            "DeleteFile".to_string(),
            HashMap::from([
                ("filename".to_string(), "test_document_001.txt".to_string()),
                ("secure_delete".to_string(), "false".to_string()),
            ]),
        ),
        (
            "NetworkConnect".to_string(),
            HashMap::from([
                ("destination".to_string(), "192.168.1.100:8080".to_string()),
                ("protocol".to_string(), "TCP".to_string()),
            ]),
        ),
    ]
}

/// Get deterministic memory usage for testing
/// Returns consistent values based on test context for reproducible results
pub fn get_memory_usage() -> usize {
    // Use thread ID and current test context to generate deterministic values
    let thread_id = std::thread::current().id();
    let base_memory = 1024 * 1024; // 1MB base

    // Create deterministic variation based on thread ID hash
    let thread_hash = format!("{:?}", thread_id).len();
    let variation = (thread_hash * 64 * 1024) % (512 * 1024); // 0-512KB variation

    base_memory + variation
}

/// Create deterministic test data with known patterns
/// Uses fixed seed for reproducible results across test runs
pub fn create_test_malware_sample() -> Vec<u8> {
    let mut sample = Vec::with_capacity(2048);

    // Standard PE header (deterministic)
    sample.extend_from_slice(b"MZ");
    sample.extend_from_slice(&[0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00]);
    sample.extend_from_slice(&[0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0xB8, 0x00]);
    sample.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00]);
    sample.resize(64, 0x00);

    // PE signature and COFF header (deterministic)
    sample.extend_from_slice(b"PE\x00\x00");
    sample.extend_from_slice(&[0x4C, 0x01, 0x03, 0x00]); // Machine type and section count

    // Ransomware indicators (fixed patterns for deterministic detection)
    sample.extend_from_slice(b"WANNACRY_V2.0");
    sample.extend_from_slice(b"DECRYPT_INSTRUCTION_HERE");
    sample.extend_from_slice(b"BITCOIN_ADDRESS_1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
    sample.extend_from_slice(b"YOUR_FILES_ARE_ENCRYPTED_SEND_PAYMENT");

    // Deterministic high entropy section (using fixed mathematical sequence)
    let entropy_data: Vec<u8> = (0..256)
        .map(|i| ((i * 31 + 17) ^ (i * 7 + 23)) as u8)
        .collect();
    sample.extend_from_slice(&entropy_data);

    // Add suspicious API imports (deterministic)
    sample.extend_from_slice(b"\x00CreateFileA\x00");
    sample.extend_from_slice(b"\x00WriteFile\x00");
    sample.extend_from_slice(b"\x00CryptEncrypt\x00");
    sample.extend_from_slice(b"\x00DeleteFileA\x00");

    // Pad to consistent size
    sample.resize(2048, 0xCC);

    sample
}

/// Create deterministic clean test data
/// Always produces the same benign content for consistent testing
pub fn create_clean_sample() -> Vec<u8> {
    let mut clean_data = Vec::with_capacity(1024);

    // Standard text file header
    clean_data.extend_from_slice(b"# Clean Test Document\n");
    clean_data.extend_from_slice(b"Version: 1.0\n");
    clean_data.extend_from_slice(b"Generated: 2024-01-01T00:00:00Z\n\n");

    // Benign content that should never trigger detection
    let benign_content = [
        "This is a legitimate document containing normal business content.",
        "The quick brown fox jumps over the lazy dog.",
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
        "Configuration settings: timeout=30, retries=3, debug=false",
        "Data processing completed successfully at timestamp 1704067200.",
        "System status: operational, memory usage: 45%, cpu usage: 12%",
        "Log entry: User authentication successful for user@domain.com",
        "Backup completed: 1,234,567 files processed, 0 errors encountered.",
    ];

    for (i, line) in benign_content.iter().enumerate() {
        clean_data.extend_from_slice(format!("{}. {}\n", i + 1, line).as_bytes());
    }

    // Add deterministic padding
    clean_data.resize(1024, b' ');
    clean_data[1023] = b'\n';

    clean_data
}

/// Measure execution time of async operations
pub async fn measure_async_execution<F, T>(operation: F) -> (T, std::time::Duration)
where
    F: std::future::Future<Output = T>,
{
    let start = SystemTime::now();
    let result = operation.await;
    let duration = start.elapsed().unwrap_or(std::time::Duration::from_secs(0));
    (result, duration)
}

/// Run test with timeout
pub async fn run_with_timeout<F, T>(
    operation: F,
    timeout_duration: std::time::Duration,
) -> Result<T, &'static str>
where
    F: std::future::Future<Output = T>,
{
    match tokio::time::timeout(timeout_duration, operation).await {
        Ok(result) => Ok(result),
        Err(_) => Err("Test timed out"),
    }
}

/// Validate memory usage during test
pub fn check_memory_usage() -> usize {
    // Simplified memory check - in real implementation would use system APIs
    std::mem::size_of::<usize>() * 1000 // Mock value
}
