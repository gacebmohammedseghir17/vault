use std::time::Instant;
use erdps_agent::detection::behavioral::BehavioralAnalysisEngine;

#[tokio::test]
async fn test_behavioral_engine_startup_performance() {
    let start = Instant::now();
    
    // Test the parameterless constructor used in performance tests
    let _engine = BehavioralAnalysisEngine::new();
    
    let duration = start.elapsed();
    println!("Behavioral engine initialization took: {:?}", duration);
    
    // Performance requirement: <100ms initialization
    assert!(
        duration.as_millis() < 100,
        "Behavioral engine initialization took {}ms, exceeding 100ms limit",
        duration.as_millis()
    );
}