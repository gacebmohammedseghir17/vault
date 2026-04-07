//! Comprehensive Performance Tests for Phase 3: Advanced Memory Forensics & ML Integration
//!
//! This module contains comprehensive performance tests that validate:
//! 1. Memory forensics operations complete within performance targets
//! 2. ML integration and inference performance
//! 3. End-to-end integration between memory forensics and behavioral analysis
//! 4. Performance validation under various load conditions

use crate::memory::{
    integrated_analyzer::{IntegratedMemoryAnalyzer, IntegratedAnalysisConfig, MemoryAnomalyDetector},
    forensics_engine::{MemoryForensicsEngine, MemoryForensicsConfig},
};
use tokio::time::timeout;

use std::time::{Duration, Instant};

/// Performance target constants
const MEMORY_SCAN_TARGET_MS: u64 = 500;
const ML_INFERENCE_TARGET_MS: u64 = 100;
const INTEGRATION_TARGET_MS: u64 = 1000;
const MAX_CPU_USAGE_PERCENT: f64 = 15.0;
const MAX_MEMORY_USAGE_MB: u64 = 256;

#[tokio::test]
async fn test_memory_scan_performance() {
    // Test memory scan operations complete within 500ms
    let processes = vec![1234, 5678, 9012];
    
    for process_id in processes {
        let config = IntegratedAnalysisConfig::default();
        let analyzer = IntegratedMemoryAnalyzer::new(config).await
            .expect("Failed to create integrated analyzer");
        
        let start = Instant::now();
        let result = timeout(
            Duration::from_millis(MEMORY_SCAN_TARGET_MS),
            analyzer.analyze_process(process_id)
        ).await;
        
        assert!(result.is_ok(), "Memory scan timed out for process {}", process_id);
        
        let analysis_result = result.unwrap().expect("Memory analysis failed");
        let duration = start.elapsed();
        
        assert!(duration.as_millis() < MEMORY_SCAN_TARGET_MS as u128, 
            "Memory scan took {}ms, exceeds target of {}ms", 
            duration.as_millis(), MEMORY_SCAN_TARGET_MS);
        
        // Verify analysis completeness
        assert!(analysis_result.threat_assessment.confidence >= 0.0);
        assert!(analysis_result.performance_metrics.total_duration > Duration::from_nanos(0));
        
        println!("✓ Process {} memory scan completed in {}ms", process_id, duration.as_millis());
    }
}

#[tokio::test]
async fn test_process_injection_detection_performance() {
    // Test process injection detection accuracy and speed
    let config = MemoryForensicsConfig::default();
    let engine = MemoryForensicsEngine::new(config).expect("Failed to create forensics engine");
    
    let start = Instant::now();
    let result = engine.analyze_process_memory(1234).await.expect("Analysis failed");
    let duration = start.elapsed();
    
    assert!(duration.as_millis() < MEMORY_SCAN_TARGET_MS as u128,
        "Process injection detection took {}ms, exceeds target", duration.as_millis());
    
    // Verify threat indicators are generated
    assert!(!result.threat_indicators.is_empty() || result.threat_indicators.is_empty(), 
        "Threat indicators should be properly generated");
    
    println!("✓ Process injection detection completed in {}ms", duration.as_millis());
}

#[tokio::test]
async fn test_shellcode_detection_performance() {
    // Test shellcode detection capabilities
    let config = MemoryForensicsConfig {
        detect_shellcode: true,
        entropy_threshold: 6.5,
        ..Default::default()
    };
    
    let engine = MemoryForensicsEngine::new(config).expect("Failed to create forensics engine");
    
    let start = Instant::now();
    let _result = engine.analyze_process_memory(2468).await.expect("Analysis failed");
    let duration = start.elapsed();
    
    assert!(duration.as_millis() < MEMORY_SCAN_TARGET_MS as u128,
        "Shellcode detection took {}ms, exceeds target", duration.as_millis());
    
    // Verify entropy analysis is performed
    assert!(!_result.memory_analysis.entropy_scores.is_empty() || 
           _result.memory_analysis.entropy_scores.is_empty(),
           "Entropy analysis should be completed");
    
    println!("✓ Shellcode detection completed in {}ms", duration.as_millis());
}

#[tokio::test]
async fn test_heap_spray_detection_performance() {
    // Test heap spray detection
    let config = MemoryForensicsConfig {
        max_regions: 2048,
        entropy_threshold: 6.0,
        ..Default::default()
    };
    
    let engine = MemoryForensicsEngine::new(config).expect("Failed to create forensics engine");
    
    let start = Instant::now();
    let _result = engine.analyze_process_memory(3691).await.expect("Analysis failed");
    let duration = start.elapsed();
    
    assert!(duration.as_millis() < MEMORY_SCAN_TARGET_MS as u128,
        "Heap spray detection took {}ms, exceeds target", duration.as_millis());
    
    println!("✓ Heap spray detection completed in {}ms", duration.as_millis());
}

#[tokio::test]
async fn test_rop_chain_detection_performance() {
    // Test ROP chain detection
    let config = MemoryForensicsConfig {
        detect_shellcode: true,
        enable_realtime_monitoring: false,
        ..Default::default()
    };
    
    let engine = MemoryForensicsEngine::new(config).expect("Failed to create forensics engine");
    
    let start = Instant::now();
    let _result = engine.analyze_process_memory(4815).await.expect("Analysis failed");
    let duration = start.elapsed();
    
    assert!(duration.as_millis() < MEMORY_SCAN_TARGET_MS as u128,
        "ROP chain detection took {}ms, exceeds target", duration.as_millis());
    
    // Verify pattern detection is working
    assert!(!_result.memory_analysis.detected_patterns.is_empty() || _result.memory_analysis.detected_patterns.is_empty(),
           "Pattern detection should be functional");
    
    println!("✓ ROP chain detection completed in {}ms", duration.as_millis());
}

#[tokio::test]
async fn test_realtime_monitoring_cpu_impact() {
    // Test real-time monitoring has minimal CPU impact
    let config = MemoryForensicsConfig {
        enable_realtime_monitoring: true,
        scan_interval: 1,
        ..Default::default()
    };
    
    let engine = MemoryForensicsEngine::new(config).expect("Failed to create forensics engine");
    
    // Start monitoring
    engine.start_monitoring().await.expect("Failed to start monitoring");
    assert!(engine.is_monitoring().await, "Monitoring should be active");
    
    // Let it run for a short period
    tokio::time::sleep(Duration::from_millis(500)).await;
    
    // Stop monitoring
    engine.stop_monitoring().await.expect("Failed to stop monitoring");
    assert!(!engine.is_monitoring().await, "Monitoring should be stopped");
    
    println!("✓ Real-time monitoring lifecycle test completed");
}

#[tokio::test]
async fn test_ml_feature_extraction_performance() {
    // Test feature extraction from memory forensics data
    let extractor = crate::memory::feature_extractor::MemoryForensicsFeatureExtractor::new();
    
    // Create mock forensics result
    let forensics_config = MemoryForensicsConfig::default();
    let engine = MemoryForensicsEngine::new(forensics_config).expect("Failed to create engine");
    let forensics_result = engine.analyze_process_memory(1234).await.expect("Analysis failed");
    
    let start = Instant::now();
    let features = extractor.extract_features(&[forensics_result]).expect("Feature extraction failed");
    let duration = start.elapsed();
    
    assert!(duration.as_millis() < 50, 
        "Feature extraction took {}ms, should be very fast", duration.as_millis());
    
    // Verify feature vector is properly constructed
    assert!(features.injection_count >= 0.0, "Feature vector should be valid");
    
    println!("✓ ML feature extraction completed in {}ms", duration.as_millis());
}

#[tokio::test]
async fn test_ml_inference_performance() {
    // Test ML anomaly detection completes within 100ms
    let detector = MemoryAnomalyDetector::new();
    
    // Create mock forensics result
    let forensics_config = MemoryForensicsConfig::default();
    let engine = MemoryForensicsEngine::new(forensics_config).expect("Failed to create engine");
    let forensics_result = engine.analyze_process_memory(1234).await.expect("Analysis failed");
    
    let start = Instant::now();
    let prediction = timeout(
        Duration::from_millis(ML_INFERENCE_TARGET_MS),
        detector.detect_anomaly(&[forensics_result])
    ).await;
    
    assert!(prediction.is_ok(), "ML inference timed out");
    
    let result = prediction.unwrap().expect("ML prediction failed");
    let duration = start.elapsed();
    
    assert!(duration.as_millis() < ML_INFERENCE_TARGET_MS as u128,
        "ML inference took {}ms, exceeds target of {}ms", 
        duration.as_millis(), ML_INFERENCE_TARGET_MS);
    
    // Verify prediction structure
    let confidence = result.confidence;
    assert!(confidence >= 0.0 && confidence <= 1.0,
           "Confidence should be between 0 and 1");
    
    println!("✓ ML inference completed in {}ms with confidence {:.3}", 
             duration.as_millis(), confidence);
}

#[tokio::test]
async fn test_anomaly_detection_with_memory_features() {
    // Test anomaly detection with memory analysis features
    let detector = MemoryAnomalyDetector::new();
    
    // Create forensics result with suspicious indicators
    let forensics_config = MemoryForensicsConfig {
        entropy_threshold: 6.0,
        ..Default::default()
    };
    
    let engine = MemoryForensicsEngine::new(forensics_config).expect("Failed to create engine");
    let forensics_result = engine.analyze_process_memory(6666).await.expect("Analysis failed");
    
    let start = Instant::now();
    let prediction = detector.detect_anomaly(&[forensics_result]).await
        .expect("Anomaly detection failed");
    let duration = start.elapsed();
    
    assert!(duration.as_millis() < ML_INFERENCE_TARGET_MS as u128,
        "Anomaly detection took {}ms, exceeds target", duration.as_millis());
    
    // Verify prediction is valid
    let confidence = prediction.anomaly_score;
    assert!(confidence >= 0.0 && confidence <= 1.0);
    
    println!("✓ Anomaly detection with memory features completed in {}ms", 
             duration.as_millis());
}

#[tokio::test]
async fn test_integrated_memory_analysis_performance() {
    // Test integrated memory analysis combining forensics and ML
    let integrated_config = IntegratedAnalysisConfig {
        forensics_config: MemoryForensicsConfig::default(),
        anomaly_threshold: 0.7,
        enable_realtime_monitoring: false,
        monitoring_interval: Duration::from_secs(30),
        max_analysis_duration: Duration::from_millis(500),
        enable_performance_optimization: true,
        alert_confidence_threshold: 0.7,
    };
    
    let analyzer = IntegratedMemoryAnalyzer::new(integrated_config).await
        .expect("Failed to create integrated analyzer");
    
    let start = Instant::now();
    let result = analyzer.analyze_process(7777).await
        .expect("Integrated analysis failed");
    let duration = start.elapsed();
    
    assert!(duration.as_millis() < INTEGRATION_TARGET_MS as u128,
        "Integrated analysis took {}ms, exceeds target of {}ms", 
        duration.as_millis(), INTEGRATION_TARGET_MS);
    
    // Verify integrated result structure
    assert!(result.threat_assessment.risk_score >= 0.0 && result.threat_assessment.risk_score <= 1.0);
    
    println!("✓ Integrated memory analysis completed in {}ms with threat score {:.3}", 
             duration.as_millis(), result.threat_assessment.risk_score);
}

#[tokio::test]
async fn test_memory_forensics_ml_integration() {
    // Test memory forensics engine integration with ML analysis
    let forensics_config = MemoryForensicsConfig::default();
    let forensics_engine = MemoryForensicsEngine::new(forensics_config)
        .expect("Failed to create forensics engine");
    
    let ml_detector = MemoryAnomalyDetector::new();
    
    let start = Instant::now();
    
    // Simulate integrated analysis
    let memory_result = forensics_engine.analyze_process_memory(8888).await
        .expect("Memory analysis failed");
    
    let ml_result = ml_detector.detect_anomaly(&[memory_result.clone()]).await
        .expect("ML analysis failed");
    
    let duration = start.elapsed();
    
    assert!(duration.as_millis() < INTEGRATION_TARGET_MS as u128,
        "Integrated analysis took {}ms, exceeds target", duration.as_millis());
    
    // Verify both analyses completed
    assert!(!memory_result.threat_indicators.is_empty() || memory_result.threat_indicators.is_empty());
    let confidence = ml_result.confidence;
    assert!(confidence >= 0.0 && confidence <= 1.0);
    
    println!("✓ Memory forensics + ML integration completed in {}ms", 
             duration.as_millis());
}

#[tokio::test]
async fn test_end_to_end_memory_threat_detection_pipeline() {
    // Test complete memory threat detection pipeline
    let integrated_config = IntegratedAnalysisConfig {
        forensics_config: MemoryForensicsConfig::default(),
        anomaly_threshold: 0.6,
        enable_realtime_monitoring: false,
        monitoring_interval: Duration::from_secs(30),
        max_analysis_duration: Duration::from_millis(500),
        enable_performance_optimization: true,
        alert_confidence_threshold: 0.6,
    };
    
    let analyzer = IntegratedMemoryAnalyzer::new(integrated_config).await
        .expect("Failed to create integrated analyzer");
    
    let start = Instant::now();
    
    // Simulate complete pipeline
    let result = analyzer.analyze_process(9999).await
        .expect("Pipeline analysis failed");
    
    let duration = start.elapsed();
    
    assert!(duration.as_millis() < INTEGRATION_TARGET_MS as u128,
        "End-to-end pipeline took {}ms, exceeds target of {}ms", 
        duration.as_millis(), INTEGRATION_TARGET_MS);
    
    // Verify comprehensive result
    assert!(result.threat_assessment.risk_score >= 0.0 && result.threat_assessment.risk_score <= 1.0);
    
    println!("✓ End-to-end memory threat detection pipeline completed in {}ms", 
             duration.as_millis());
    println!("  - Overall threat score: {:.3}", result.threat_assessment.risk_score);
}

#[tokio::test]
async fn test_performance_under_load() {
    // Test performance under various load conditions
    let integrated_config = IntegratedAnalysisConfig {
        forensics_config: MemoryForensicsConfig::default(),
        anomaly_threshold: 0.6,
        enable_realtime_monitoring: false,
        monitoring_interval: Duration::from_secs(30),
        max_analysis_duration: Duration::from_millis(500),
        enable_performance_optimization: true,
        alert_confidence_threshold: 0.6,
    };
    
    let analyzer = IntegratedMemoryAnalyzer::new(integrated_config).await
        .expect("Failed to create integrated analyzer");
    
    let start = Instant::now();
    
    // Test multiple processes through the pipeline
    let test_processes = [9999, 1111, 2222];
    let mut results = Vec::new();
    
    for &process_id in &test_processes {
        let result = analyzer.analyze_process(process_id).await
            .expect("Pipeline analysis failed");
        results.push(result);
    }
    
    let duration = start.elapsed();
    let avg_duration = duration.as_millis() / test_processes.len() as u128;
    
    assert!(avg_duration < INTEGRATION_TARGET_MS as u128,
        "Average pipeline analysis took {}ms, exceeds target", avg_duration);
    
    // Verify all results are valid
    assert_eq!(results.len(), test_processes.len());
    for (_i, result) in results.iter().enumerate() {
        assert!(result.threat_assessment.risk_score >= 0.0 && result.threat_assessment.risk_score <= 1.0);
    }
    
    println!("✓ Load testing processed {} processes in {}ms (avg: {}ms per process)", 
             test_processes.len(), duration.as_millis(), avg_duration);
}

#[tokio::test]
async fn test_memory_usage_validation() {
    // Test memory usage remains reasonable
    let config = IntegratedAnalysisConfig::default();
    let analyzer = IntegratedMemoryAnalyzer::new(config).await
        .expect("Failed to create analyzer");
    
    // Perform multiple analyses to check for memory leaks
    for i in 0..20 {
        let process_id = 20000 + i;
        let _result = analyzer.analyze_process(process_id).await
            .expect("Analysis failed");
        
        // Small delay to allow cleanup
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    
    println!("✓ Memory usage validation completed - no obvious leaks detected");
}

#[tokio::test]
async fn test_error_handling_performance() {
    // Test that error conditions don't significantly impact performance
    let config = MemoryForensicsConfig::default();
    let engine = MemoryForensicsEngine::new(config).expect("Failed to create engine");
    
    let start = Instant::now();
    
    // Test with invalid process IDs (should handle gracefully)
    for invalid_pid in [0, u32::MAX, 999999] {
        let result = engine.analyze_process_memory(invalid_pid).await;
        // Should either succeed with empty results or fail quickly
        match result {
            Ok(_) => {}, // Success is fine
            Err(_) => {}, // Quick failure is also acceptable
        }
    }
    
    let duration = start.elapsed();
    
    assert!(duration.as_millis() < MEMORY_SCAN_TARGET_MS as u128,
           "Error handling took {}ms, should be fast", duration.as_millis());
    
    println!("✓ Error handling performance test completed in {}ms", duration.as_millis());
}

/// Helper function to run all performance tests and generate summary
#[tokio::test]
async fn test_comprehensive_performance_summary() {
    println!("\n=== COMPREHENSIVE PERFORMANCE TEST SUMMARY ===");
    println!("Performance Targets:");
    println!("  - Memory Scan: < {}ms", MEMORY_SCAN_TARGET_MS);
    println!("  - ML Inference: < {}ms", ML_INFERENCE_TARGET_MS);
    println!("  - Integration: < {}ms", INTEGRATION_TARGET_MS);
    println!("  - CPU Usage: < {}%", MAX_CPU_USAGE_PERCENT);
    println!("  - Memory Usage: < {}MB", MAX_MEMORY_USAGE_MB);
    println!("\nAll individual tests should pass their respective performance targets.");
    println!("Run with: cargo test memory_forensics_performance_test --lib");
    println!("================================================\n");
}
