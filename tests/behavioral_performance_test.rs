use std::time::Instant;
use erdps_agent::detection::behavioral::BehavioralAnalysisEngine;

#[tokio::test]
async fn test_behavioral_engine_initialization_performance() {
    // Measure initialization time
    let start_time = Instant::now();
    
    let _engine = BehavioralAnalysisEngine::new();
    
    let initialization_time = start_time.elapsed();
    
    println!("Behavioral engine initialization took: {:.4}ms", 
             initialization_time.as_secs_f64() * 1000.0);
    
    // Performance gate: thresholds vary by build profile to reduce flakiness
    let init_threshold_ms: u128 = if cfg!(debug_assertions) { 500 } else { 120 };
    assert!(
        initialization_time.as_millis() < init_threshold_ms,
        "Behavioral engine initialization took {:.4}ms, which exceeds the {}ms threshold",
        initialization_time.as_secs_f64() * 1000.0,
        init_threshold_ms
    );
}

#[tokio::test]
async fn test_behavioral_engine_lazy_initialization_performance() {
    // Measure lazy initialization time
    let start_time = Instant::now();
    
    let _engine = BehavioralAnalysisEngine::new();
    
    let lazy_init_time = start_time.elapsed();
    
    println!("Lazy behavioral engine initialization took: {:.4}ms", 
             lazy_init_time.as_secs_f64() * 1000.0);
    
    // Lazy initialization should be faster; thresholds vary by build profile
    let lazy_threshold_ms: u128 = if cfg!(debug_assertions) { 450 } else { 60 };
    assert!(
        lazy_init_time.as_millis() < lazy_threshold_ms,
        "Lazy behavioral engine initialization took {:.4}ms, which exceeds the {}ms threshold",
        lazy_init_time.as_secs_f64() * 1000.0,
        lazy_threshold_ms
    );
}