//! Simple memory forensics test to isolate compilation issues

use erdps_agent::memory::forensics_engine::{
    MemoryForensicsEngine, MemoryForensicsConfig
};

#[tokio::test]
async fn test_memory_forensics_engine_creation() {
    let config = MemoryForensicsConfig::default();
    let engine = MemoryForensicsEngine::new(config);
    
    // Just test that we can create the engine
    assert!(engine.is_ok());
}

#[tokio::test]
async fn test_memory_forensics_config_default() {
    let config = MemoryForensicsConfig::default();
    
    // Test default configuration values
    assert!(config.enable_realtime_monitoring);
    assert_eq!(config.scan_interval, 30);
    assert_eq!(config.max_regions, 1000);
    assert_eq!(config.entropy_threshold, 7.0);
    assert!(config.detect_process_injection);
    assert!(config.detect_shellcode);
    assert!(config.detect_heap_spray);
    assert!(config.detect_rop_chains);
    assert_eq!(config.min_shellcode_size, 32);
    assert_eq!(config.max_scan_time_ms, 500);
}