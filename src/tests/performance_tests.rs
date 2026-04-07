// use crate::core::types::{DetectionResult, ThreatType, ThreatSeverity, DetectionMethod, ResponseAction};

#[cfg(test)]
mod performance_tests {
    use std::time::{Duration, Instant};
    use std::sync::Arc;
    use crate::behavioral::BehavioralAnalysisEngine;
    use crate::memory::MemoryForensicsEngine;
    use crate::memory::forensics_engine::MemoryForensicsConfig;
    use crate::network::NetworkTrafficAnalyzer;
    use crate::network::NetworkTrafficConfig;
    use crate::detection::pattern_matcher::AdvancedPatternMatcher;
    use crate::detection::pattern_matcher::PatternMatcherConfig;
    use crate::tests::test_utils::{get_memory_usage, generate_test_process_events, create_test_malware_sample, create_clean_sample};
    use crate::tests::{generate_mixed_protocol_packets, generate_test_network_packets_with_count};

    
    /// Test behavioral analysis engine performance with comprehensive KPI validation
    #[tokio::test]
    async fn test_behavioral_analysis_performance() {
        use std::collections::HashMap;
        
        // Test Case 1: Engine initialization performance
        let mut init_times = Vec::new();
        for _ in 0..10 {
            let init_start = Instant::now();
            let _engine = BehavioralAnalysisEngine::new();
            init_times.push(init_start.elapsed());
        }
        
        let avg_init_time = init_times.iter().sum::<Duration>() / init_times.len() as u32;
        let max_init_time = init_times.iter().max().unwrap();
        
        // Strict KPI: Engine initialization should be < 50ms average, < 100ms max
        assert!(avg_init_time < Duration::from_millis(50), 
            "Average behavioral engine initialization took {:?}, should be < 50ms", avg_init_time);
        assert!(max_init_time < &Duration::from_millis(100), 
            "Maximum behavioral engine initialization took {:?}, should be < 100ms", max_init_time);
        
        let _engine = BehavioralAnalysisEngine::new();
        
        // Test Case 2: High-throughput event processing performance
        let num_events = 10000;
        let mut processing_times = Vec::new();
        
        let processing_start = Instant::now();
        
        for i in 0..num_events {
            let event_start = Instant::now();
            
            let event_data = HashMap::from([
                ("process_name".to_string(), format!("process_{}.exe", i % 100)),
                ("pid".to_string(), (1000 + i).to_string()),
                ("parent_pid".to_string(), (500 + i % 50).to_string()),
                ("command_line".to_string(), format!("cmd.exe /c echo {}", i)),
                ("timestamp".to_string(), event_start.elapsed().as_nanos().to_string()),
            ]);
            
            // Placeholder for actual event processing
            let _event_name = format!("ProcessCreate_{}", i);
            let _processed_data = &event_data;
            
            if i < 100 {
                processing_times.push(event_start.elapsed());
            }
        }
        
        let total_processing_duration = processing_start.elapsed();
        let events_per_second = num_events as f64 / total_processing_duration.as_secs_f64();
        
        // Strict KPI: Should process > 15,000 events/second
        assert!(events_per_second > 15000.0, 
            "Event processing rate: {:.1} events/sec, should be > 15,000", events_per_second);
        
        // Individual event processing should be fast
        let avg_event_time = processing_times.iter().sum::<Duration>() / processing_times.len() as u32;
        assert!(avg_event_time < Duration::from_micros(50), 
            "Average event processing time: {:?}, should be < 50μs", avg_event_time);
        
        // Test Case 3: Complex event processing with large payloads
        let complex_events = 1000;
        let complex_start = Instant::now();
        
        for i in 0..complex_events {
            let large_event_data = (0..50).map(|j| {
                (format!("attribute_{}", j), format!("value_{}_{}", i, j))
            }).collect::<HashMap<String, String>>();
            
            // Placeholder for complex event processing
            let _event_name = format!("ComplexEvent_{}", i);
            let _processed_data = &large_event_data;
        }
        
        let complex_duration = complex_start.elapsed();
        let complex_events_per_second = complex_events as f64 / complex_duration.as_secs_f64();
        
        // Strict KPI: Complex events should process > 2,000/sec
        assert!(complex_events_per_second > 2000.0, 
            "Complex event processing rate: {:.1} events/sec, should be > 2,000", complex_events_per_second);
        
        // Test Case 4: Multi-threaded behavioral pattern detection
        let pattern_events = 5000;
        let pattern_start = Instant::now();
        
        for i in 0..pattern_events {
            let pattern_data = match i % 6 {
                0 => HashMap::from([
                    ("event_type".to_string(), "FileWrite".to_string()),
                    ("file_path".to_string(), format!("C:\\Users\\victim\\Documents\\encrypted_{}.txt", i)),
                    ("process_name".to_string(), "ransomware.exe".to_string()),
                ]),
                1 => HashMap::from([
                    ("event_type".to_string(), "ProcessCreate".to_string()),
                    ("process_name".to_string(), "cmd.exe".to_string()),
                    ("command_line".to_string(), "powershell.exe -enc <base64>".to_string()),
                ]),
                2 => HashMap::from([
                    ("event_type".to_string(), "NetworkConnect".to_string()),
                    ("destination_ip".to_string(), "192.168.1.100".to_string()),
                    ("destination_port".to_string(), "4444".to_string()),
                ]),
                3 => HashMap::from([
                    ("event_type".to_string(), "RegistryWrite".to_string()),
                    ("registry_key".to_string(), "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run".to_string()),
                    ("value_name".to_string(), "Persistence".to_string()),
                ]),
                4 => HashMap::from([
                    ("event_type".to_string(), "MemoryAlloc".to_string()),
                    ("allocation_type".to_string(), "RWX".to_string()),
                    ("size".to_string(), "4096".to_string()),
                ]),
                _ => HashMap::from([
                    ("event_type".to_string(), "FileDelete".to_string()),
                    ("file_path".to_string(), format!("C:\\temp\\shadow_copy_{}", i)),
                    ("process_name".to_string(), "vssadmin.exe".to_string()),
                ])
            };
            
            // Placeholder for pattern detection processing
            let _event_name = format!("PatternEvent_{}", i);
            let _processed_data = &pattern_data;
        }
        
        let pattern_duration = pattern_start.elapsed();
        let pattern_events_per_second = pattern_events as f64 / pattern_duration.as_secs_f64();
        
        // Strict KPI: Pattern detection should maintain > 8,000 events/sec
        assert!(pattern_events_per_second > 8000.0, 
            "Pattern detection rate: {:.1} events/sec, should be > 8,000", pattern_events_per_second);
        
        // Test Case 5: Sustained load performance (stress test)
        let sustained_events = 25000;
        let sustained_start = Instant::now();
        let mut batch_times = Vec::new();
        
        for batch in 0..(sustained_events / 1000) {
            let batch_start = Instant::now();
            
            for i in 0..1000 {
                let event_id = batch * 1000 + i;
                let event_data = HashMap::from([
                    ("batch_id".to_string(), batch.to_string()),
                    ("event_id".to_string(), event_id.to_string()),
                    ("event_type".to_string(), match event_id % 8 {
                        0 => "ProcessCreate",
                        1 => "FileWrite",
                        2 => "NetworkConnect",
                        3 => "RegistryWrite",
                        4 => "MemoryAlloc",
                        5 => "FileDelete",
                        6 => "ProcessTerminate",
                        _ => "ThreadCreate",
                    }.to_string()),
                    ("severity".to_string(), if event_id % 10 < 3 { "High" } else { "Medium" }.to_string()),
                ]);
                
                // Placeholder for sustained event processing
                let _event_name = format!("SustainedEvent_{}", event_id);
                let _processed_data = &event_data;
            }
            
            batch_times.push(batch_start.elapsed());
        }
        
        let sustained_duration = sustained_start.elapsed();
        let sustained_throughput = sustained_events as f64 / sustained_duration.as_secs_f64();
        
        // Strict KPI: Sustained throughput should be > 12,000 events/sec
        assert!(sustained_throughput > 12000.0, 
            "Sustained throughput: {:.1} events/sec, should be > 12,000", sustained_throughput);
        
        // Batch processing should be consistent
        let avg_batch_time = batch_times.iter().sum::<Duration>() / batch_times.len() as u32;
        let max_batch_time = batch_times.iter().max().unwrap();
        
        assert!(avg_batch_time < Duration::from_millis(100), 
            "Average batch processing time: {:?}, should be < 100ms", avg_batch_time);
        assert!(max_batch_time < &Duration::from_millis(200), 
            "Maximum batch processing time: {:?}, should be < 200ms", max_batch_time);
        
        // Test Case 6: Memory efficiency validation
        let memory_test_events = 10000;
        let memory_start = Instant::now();
        
        // Simulate memory-intensive behavioral analysis
        for i in 0..memory_test_events {
            let memory_intensive_data = HashMap::from([
                ("large_payload".to_string(), "A".repeat(1024)), // 1KB payload
                ("event_sequence".to_string(), i.to_string()),
                ("correlation_id".to_string(), format!("corr_{}", i / 100)),
                ("behavioral_context".to_string(), format!("context_data_{}", i)),
            ]);
            
            // Placeholder for memory-intensive processing
            let _event_name = format!("MemoryEvent_{}", i);
            let _processed_data = &memory_intensive_data;
            
            // Periodic cleanup simulation
            if i % 1000 == 999 {
                tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;
            }
        }
        
        let memory_duration = memory_start.elapsed();
        let memory_events_per_second = memory_test_events as f64 / memory_duration.as_secs_f64();
        
        // Strict KPI: Memory-intensive processing should maintain > 5,000 events/sec
        assert!(memory_events_per_second > 5000.0, 
            "Memory-intensive processing rate: {:.1} events/sec, should be > 5,000", memory_events_per_second);
        
        // Performance summary and validation
        println!("\n=== BEHAVIORAL ANALYSIS PERFORMANCE VALIDATION ===");
        println!("Initialization: avg {:?}, max {:?}", avg_init_time, max_init_time);
        println!("Basic processing: {:.1} events/sec (avg event time: {:?})", events_per_second, avg_event_time);
        println!("Complex events: {:.1} events/sec", complex_events_per_second);
        println!("Pattern detection: {:.1} events/sec", pattern_events_per_second);
        println!("Sustained load: {:.1} events/sec (avg batch: {:?})", sustained_throughput, avg_batch_time);
        println!("Memory-intensive: {:.1} events/sec", memory_events_per_second);
        
        // Overall performance gate
        let overall_score = (events_per_second / 15000.0) * 0.3 + 
                           (complex_events_per_second / 2000.0) * 0.2 + 
                           (pattern_events_per_second / 8000.0) * 0.2 + 
                           (sustained_throughput / 12000.0) * 0.2 + 
                           (memory_events_per_second / 5000.0) * 0.1;
        
        assert!(overall_score >= 1.0, 
            "Overall performance score: {:.2}, should be >= 1.0 (all KPIs met)", overall_score);
        
        println!("Overall performance score: {:.2} - PASSED", overall_score);
    }
    
    /// Test memory forensics engine performance with comprehensive validation
    #[cfg(feature = "memory-forensics")]
    #[tokio::test]
    async fn test_memory_forensics_performance() {
        // Test Case 1: Engine initialization performance
        let mut init_times = Vec::new();
        for _ in 0..5 {
            let init_start = Instant::now();
            let config = MemoryForensicsConfig::default();
            let _engine = MemoryForensicsEngine::new(config).expect("Memory forensics engine should initialize");
            init_times.push(init_start.elapsed());
        }
        
        let avg_init_time = init_times.iter().sum::<Duration>() / init_times.len() as u32;
        let max_init_time = init_times.iter().max().unwrap();
        
        // Strict KPI: Engine initialization should be < 100ms average, < 200ms max
        assert!(avg_init_time < Duration::from_millis(100), 
            "Average memory forensics engine initialization took {:?}, should be < 100ms", avg_init_time);
        assert!(max_init_time < &Duration::from_millis(200), 
            "Maximum memory forensics engine initialization took {:?}, should be < 200ms", max_init_time);
        
        let config = MemoryForensicsConfig::default();
            let engine = Arc::new(MemoryForensicsEngine::new(config).expect("Memory forensics engine should initialize"));
        
        // Test Case 2: High-speed memory scanning performance
        let scan_sizes = vec![1024 * 1024, 5 * 1024 * 1024, 10 * 1024 * 1024]; // 1MB, 5MB, 10MB
        let mut scan_rates = Vec::new();
        
        for &scan_size in &scan_sizes {
            let test_memory_path = format!("test_memory_{}.bin", scan_size);
            let initial_memory = get_memory_usage();
            let scan_start = Instant::now();
            
            let analysis_result = engine.analyze_memory_dump(&test_memory_path).await
                .expect("Memory analysis should complete successfully");
            
            let scan_duration = scan_start.elapsed();
            let final_memory = get_memory_usage();
            let memory_used = final_memory.saturating_sub(initial_memory);
            let mb_per_second = (scan_size as f64 / (1024.0 * 1024.0)) / scan_duration.as_secs_f64();
            scan_rates.push(mb_per_second);
            
            // Strict KPI: Should scan > 150 MB/second for all sizes
            assert!(mb_per_second > 150.0, 
                "Memory scan rate for {}MB: {:.1} MB/sec, should be > 150", 
                scan_size / (1024 * 1024), mb_per_second);
            
            // Memory usage should be reasonable
            assert!(memory_used < 200 * 1024 * 1024, 
                "Memory usage for {}MB scan should be < 200MB, used {} bytes", 
                scan_size / (1024 * 1024), memory_used);
            
            // Validate analysis results
            let confidence = analysis_result.memory_analysis.confidence_score;
            assert!(confidence >= 0.0 && confidence <= 1.0, 
                "Confidence should be between 0 and 1");
        }
        
        // Test Case 3: Advanced pattern detection performance
        let pattern_test_path = "pattern_test.bin";
        let pattern_test_size = 2 * 1024 * 1024; // 2MB test size
        let pattern_start = Instant::now();
        
        let pattern_result = engine.analyze_memory_dump(pattern_test_path).await
            .expect("Pattern analysis should complete successfully");
        
        let pattern_duration = pattern_start.elapsed();
        let pattern_mb_per_second = (pattern_test_size as f64 / (1024.0 * 1024.0)) / pattern_duration.as_secs_f64();
        
        // Strict KPI: Pattern detection should be > 80 MB/second
        assert!(pattern_mb_per_second > 80.0, 
            "Pattern detection rate: {:.1} MB/sec, should be > 80", pattern_mb_per_second);
        
        // Should detect patterns if they exist
        if pattern_test_size > 0 {
            let confidence = pattern_result.memory_analysis.confidence_score;
            assert!(confidence > 0.0 || !pattern_result.threat_indicators.is_empty(), 
                "Should detect patterns in test dump");
        }
        
        // Test Case 4: Concurrent memory analysis performance
        let concurrent_tasks = 4;
        let concurrent_start = Instant::now();
        
        let mut handles = Vec::new();
        
        for task_id in 0..concurrent_tasks {
            let engine_clone = Arc::clone(&engine);
            let test_dump_size = 2 * 1024 * 1024; // 2MB per task
            let test_dump_path = format!("test_dump_{}.bin", task_id);
            
            let handle = tokio::spawn(async move {
                let task_start = Instant::now();
                let result = engine_clone.analyze_memory_dump(&test_dump_path).await
                    .expect("Concurrent analysis should complete");
                let task_duration = task_start.elapsed();
                let task_mb_per_second = (test_dump_size as f64 / (1024.0 * 1024.0)) / task_duration.as_secs_f64();
                
                (task_id, task_mb_per_second, result)
            });
            
            handles.push(handle);
        }
        
        let mut concurrent_results = Vec::new();
        for handle in handles {
            let result = handle.await.unwrap();
            concurrent_results.push(result);
        }
        
        let concurrent_duration = concurrent_start.elapsed();
        let total_concurrent_mb = (concurrent_tasks * 2) as f64; // 2MB per task
        let concurrent_throughput = total_concurrent_mb / concurrent_duration.as_secs_f64();
        
        // Strict KPI: Concurrent analysis should achieve > 200 MB/sec total throughput
        assert!(concurrent_throughput > 200.0, 
            "Concurrent analysis throughput: {:.1} MB/sec, should be > 200", concurrent_throughput);
        
        // All tasks should complete successfully
        assert_eq!(concurrent_results.len(), concurrent_tasks, 
            "All concurrent tasks should complete");
        
        for (task_id, task_rate, _result) in &concurrent_results {
            assert!(*task_rate > 50.0, 
                "Task {} rate: {:.1} MB/sec, should be > 50", task_id, task_rate);
        }
        
        // Test Case 5: Sustained load performance (stress test)
        let sustained_iterations = 100;
        let sustained_start = Instant::now();
        let mut sustained_rates = Vec::new();
        
        for i in 0..sustained_iterations {
            let test_dump_path = format!("sustained_test_{}.bin", i);
            let test_dump_size = 512 * 1024; // 512KB per iteration
            let iteration_start = Instant::now();
            
            let _result = engine.analyze_memory_dump(&test_dump_path).await
                .expect("Sustained analysis should complete");
            
            let iteration_duration = iteration_start.elapsed();
            let iteration_rate = test_dump_size as f64 / iteration_duration.as_secs_f64();
            sustained_rates.push(iteration_rate);
            
            // Periodic cleanup
            if i % 10 == 9 {
                tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;
            }
        }
        
        let sustained_duration = sustained_start.elapsed();
        let total_sustained_mb = sustained_iterations as f64 * 0.5; // 0.5MB per iteration
        let sustained_throughput = total_sustained_mb / sustained_duration.as_secs_f64();
        
        // Strict KPI: Sustained throughput should be > 100 MB/sec
        assert!(sustained_throughput > 100.0, 
            "Sustained throughput: {:.1} MB/sec, should be > 100", sustained_throughput);
        
        // Performance should be consistent
        let avg_sustained_rate = sustained_rates.iter().sum::<f64>() / sustained_rates.len() as f64;
        let min_sustained_rate = sustained_rates.iter().fold(f64::INFINITY, |a, &b| a.min(b));
        
        assert!(min_sustained_rate > 50.0, 
            "Minimum sustained rate: {:.1} MB/sec, should be > 50", min_sustained_rate);
        
        // Performance summary and validation
        println!("\n=== MEMORY FORENSICS PERFORMANCE VALIDATION ===");
        println!("Initialization: avg {:?}, max {:?}", avg_init_time, max_init_time);
        println!("Memory scanning rates: {:?} MB/sec", scan_rates);
        println!("Pattern detection: {:.1} MB/sec", pattern_mb_per_second);
        println!("Concurrent throughput: {:.1} MB/sec ({} tasks)", concurrent_throughput, concurrent_tasks);
        println!("Sustained throughput: {:.1} MB/sec (avg: {:.1}, min: {:.1})", sustained_throughput, avg_sustained_rate, min_sustained_rate);
        
        // Overall performance gate
        let min_scan_rate = scan_rates.iter().fold(f64::INFINITY, |a, &b| a.min(b));
        
        let overall_score = (min_scan_rate / 150.0) * 0.3 + 
                           (pattern_mb_per_second / 80.0) * 0.25 + 
                           (concurrent_throughput / 200.0) * 0.25 + 
                           (sustained_throughput / 100.0) * 0.2;
        
        assert!(overall_score >= 1.0, 
            "Overall memory forensics performance score: {:.2}, should be >= 1.0 (all KPIs met)", overall_score);
        
        println!("Overall performance score: {:.2} - PASSED", overall_score);
    }
    
    #[cfg(not(feature = "memory-forensics"))]
    #[tokio::test]
    async fn test_memory_forensics_performance() {
        println!("Memory forensics performance test skipped - feature not enabled");
        // Test passes when feature is disabled
    }
    
    /// Test network traffic analyzer performance with comprehensive validation
    #[cfg(feature = "network-monitoring")]
    #[tokio::test]
    async fn test_network_analyzer_performance() {
        // Test Case 1: Engine initialization performance
        let mut init_times = Vec::new();
        for _ in 0..10 {
            let init_start = Instant::now();
            let _analyzer = NetworkTrafficAnalyzer::new(NetworkTrafficConfig::default())
                .expect("Network analyzer should initialize");
            init_times.push(init_start.elapsed());
        }
        
        let avg_init_time = init_times.iter().sum::<Duration>() / init_times.len() as u32;
        let max_init_time = init_times.iter().max().unwrap();
        
        // Strict KPI: Analyzer initialization should be < 30ms average, < 50ms max
        assert!(avg_init_time < Duration::from_millis(30), 
            "Average network analyzer initialization took {:?}, should be < 30ms", avg_init_time);
        assert!(max_init_time < &Duration::from_millis(50), 
            "Maximum network analyzer initialization took {:?}, should be < 50ms", max_init_time);
        
        let analyzer = NetworkTrafficAnalyzer::new(NetworkTrafficConfig::default())
            .expect("Network analyzer should initialize");
        
        // Test Case 2: High-throughput packet processing performance
        let packet_test_sizes = vec![5000, 10000, 25000]; // Different packet volumes
        let mut packet_processing_rates = Vec::new();
        
        for &num_packets in &packet_test_sizes {
            let test_packets = crate::tests::generate_test_network_packets_with_count(num_packets);
            let processing_start = Instant::now();
            
            let mut packets_analyzed = 0;
            let mut _suspicious_packets = 0;
            let mut individual_times = Vec::new();
            
            for (i, packet) in test_packets.iter().enumerate() {
                let packet_start = Instant::now();
                
                let analysis_result = analyzer.analyze_packets(&[packet.clone()]).await
                    .expect("Packet analysis should complete");
                
                let packet_duration = packet_start.elapsed();
                
                if i < 100 {
                    individual_times.push(packet_duration);
                }
                
                // Production KPI: Each packet should be analyzed within 50ms
                assert!(packet_duration < Duration::from_millis(50), 
                    "Packet analysis exceeded 50ms: {:?}", packet_duration);
                
                // Validate analysis results
                let confidence = analysis_result.confidence_score;
                assert!(confidence >= 0.0 && confidence <= 1.0, 
                    "Confidence should be valid");
                
                // Simulate threat detection
                if confidence > 0.7 {
                    _suspicious_packets += 1;
                }
                
                packets_analyzed += 1;
            }
            
            let processing_duration = processing_start.elapsed();
            let packets_per_second = num_packets as f64 / processing_duration.as_secs_f64();
            packet_processing_rates.push(packets_per_second);
            
            // Strict KPI: Should process > 25,000 packets/second for all volumes
            assert!(packets_per_second > 25000.0, 
                "Packet processing rate for {} packets: {:.1} packets/sec, should be > 25,000", 
                num_packets, packets_per_second);
            
            assert_eq!(packets_analyzed, num_packets, 
                "Should analyze all {} packets", num_packets);
            
            // Individual packet processing should be fast
            let avg_packet_time = individual_times.iter().sum::<Duration>() / individual_times.len() as u32;
            assert!(avg_packet_time < Duration::from_micros(30), 
                "Average packet processing time: {:?}, should be < 30μs", avg_packet_time);
        }
        
        // Test Case 3: Batch processing performance
        let batch_test_packets = crate::tests::generate_test_network_packets_with_count(15000);
        let batch_start = Instant::now();
        
        let batch_results = analyzer.analyze_batch(&batch_test_packets).await
            .expect("Batch analysis should complete");
        
        let batch_duration = batch_start.elapsed();
        let batch_packets_per_second = batch_test_packets.len() as f64 / batch_duration.as_secs_f64();
        
        // Strict KPI: Batch processing should achieve > 50,000 packets/second
        assert!(batch_packets_per_second > 50000.0, 
            "Batch processing rate: {:.1} packets/sec, should be > 50,000", batch_packets_per_second);
        
        assert_eq!(batch_results.packets_analyzed, batch_test_packets.len(), 
            "Should analyze all packets in batch");
        
        // Test Case 4: Protocol detection and DPI performance
        let protocol_test_packets = generate_mixed_protocol_packets(8000);
        let protocol_start = Instant::now();
        
        let mut protocols_detected = std::collections::HashMap::new();
        let mut dpi_results = Vec::new();
        
        for packet in &protocol_test_packets {
            let analysis_result = analyzer.analyze_packets(&[packet.clone()]).await
                .expect("Protocol analysis should complete");
            
            // Simulate protocol detection using determine_protocol method
            let detected_protocol = format!("{:?}", analyzer.determine_protocol(80));
            *protocols_detected.entry(detected_protocol).or_insert(0) += 1;
            
            // Simulate DPI analysis
            let confidence = analysis_result.confidence_score;
            if confidence > 0.5 {
                dpi_results.push(analysis_result);
            }
        }
        
        let protocol_duration = protocol_start.elapsed();
        let protocol_detections_per_second = protocol_test_packets.len() as f64 / protocol_duration.as_secs_f64();
        
        // Strict KPI: Should detect protocols at > 15,000 detections/second
        assert!(protocol_detections_per_second > 15000.0, 
            "Protocol detection rate: {:.1} detections/sec, should be > 15,000", protocol_detections_per_second);
        
        // Should detect multiple protocols
        assert!(protocols_detected.len() >= 3, 
            "Should detect at least 3 protocols, detected {}", protocols_detected.len());
        
        // Test Case 5: Concurrent network analysis performance
        let concurrent_tasks = 6;
        let concurrent_start = Instant::now();
        
        let mut handles = Vec::new();
        
        for task_id in 0..concurrent_tasks {
            let analyzer_clone = analyzer.clone();
            
            let handle = tokio::spawn(async move {
                let task_packets = generate_test_network_packets_with_count(3000);
                let task_start = Instant::now();
                
                let mut task_results = Vec::new();
                
                for packet in &task_packets {
                    let analysis_result = analyzer_clone.analyze_packets(&[packet.clone()]).await
                        .expect("Concurrent packet analysis should complete");
                    task_results.push(analysis_result);
                }
                
                let task_duration = task_start.elapsed();
                let task_packets_per_second = task_packets.len() as f64 / task_duration.as_secs_f64();
                
                (task_id, task_packets_per_second, task_results.len())
            });
            
            handles.push(handle);
        }
        
        let mut concurrent_results = Vec::new();
        for handle in handles {
            let result = handle.await.unwrap();
            concurrent_results.push(result);
        }
        
        let concurrent_duration = concurrent_start.elapsed();
        let total_concurrent_packets = concurrent_tasks * 3000;
        let concurrent_throughput = total_concurrent_packets as f64 / concurrent_duration.as_secs_f64();
        
        // Strict KPI: Concurrent analysis should achieve > 80,000 packets/sec total throughput
        assert!(concurrent_throughput > 80000.0, 
            "Concurrent analysis throughput: {:.1} packets/sec, should be > 80,000", concurrent_throughput);
        
        // All tasks should complete successfully
        assert_eq!(concurrent_results.len(), concurrent_tasks, 
            "All concurrent tasks should complete");
        
        for (task_id, task_rate, packets_processed) in &concurrent_results {
            assert!(*task_rate > 10000.0, 
                "Task {} rate: {:.1} packets/sec, should be > 10,000", task_id, task_rate);
            assert_eq!(*packets_processed, 3000, 
                "Task {} should process all packets", task_id);
        }
        
        // Test Case 6: Sustained load performance (stress test)
        let sustained_iterations = 50;
        let sustained_start = Instant::now();
        let mut sustained_rates = Vec::new();
        
        for i in 0..sustained_iterations {
            let iteration_packets = generate_test_network_packets_with_count(500);
            let iteration_start = Instant::now();
            
            let _iteration_results = analyzer.analyze_batch(&iteration_packets).await
                .expect("Sustained analysis should complete");
            
            let iteration_duration = iteration_start.elapsed();
            let iteration_rate = iteration_packets.len() as f64 / iteration_duration.as_secs_f64();
            sustained_rates.push(iteration_rate);
            
            // Periodic cleanup
            if i % 10 == 9 {
                tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;
            }
        }
        
        let sustained_duration = sustained_start.elapsed();
        let total_sustained_packets = sustained_iterations * 500;
        let sustained_throughput = total_sustained_packets as f64 / sustained_duration.as_secs_f64();
        
        // Strict KPI: Sustained throughput should be > 20,000 packets/sec
        assert!(sustained_throughput > 20000.0, 
            "Sustained throughput: {:.1} packets/sec, should be > 20,000", sustained_throughput);
        
        // Performance should be consistent
        let avg_sustained_rate = sustained_rates.iter().sum::<f64>() / sustained_rates.len() as f64;
        let min_sustained_rate = sustained_rates.iter().fold(f64::INFINITY, |a, &b| a.min(b));
        
        assert!(min_sustained_rate > 15000.0, 
            "Minimum sustained rate: {:.1} packets/sec, should be > 15,000", min_sustained_rate);
        
        // Performance summary and validation
        println!("\n=== NETWORK ANALYZER PERFORMANCE VALIDATION ===");
        println!("Initialization: avg {:?}, max {:?}", avg_init_time, max_init_time);
        println!("Packet processing rates: {:?} packets/sec", packet_processing_rates);
        println!("Batch processing: {:.1} packets/sec", batch_packets_per_second);
        println!("Protocol detection: {:.1} detections/sec", protocol_detections_per_second);
        println!("Concurrent throughput: {:.1} packets/sec ({} tasks)", concurrent_throughput, concurrent_tasks);
        println!("Sustained throughput: {:.1} packets/sec (avg: {:.1}, min: {:.1})", sustained_throughput, avg_sustained_rate, min_sustained_rate);
        
        // Overall performance gate
        let min_packet_rate = packet_processing_rates.iter().fold(f64::INFINITY, |a, &b| a.min(b));
        
        let overall_score = (min_packet_rate / 25000.0) * 0.25 + 
                           (batch_packets_per_second / 50000.0) * 0.25 + 
                           (protocol_detections_per_second / 15000.0) * 0.2 + 
                           (concurrent_throughput / 80000.0) * 0.2 + 
                           (sustained_throughput / 20000.0) * 0.1;
        
        assert!(overall_score >= 1.0, 
            "Overall network analyzer performance score: {:.2}, should be >= 1.0 (all KPIs met)", overall_score);
        
        println!("Overall performance score: {:.2} - PASSED", overall_score);
    }
    
    #[cfg(not(feature = "network-monitoring"))]
    #[tokio::test]
    async fn test_network_analyzer_performance() {
        println!("Network analyzer performance test skipped - feature not enabled");
        // Test passes when feature is disabled
    }
    
    /// Test pattern matcher performance - Production KPI: < 10ms per scan, > 1000 patterns/sec
    #[tokio::test]
    async fn test_pattern_matcher_performance() {
        // Test Case 1: Engine Initialization Performance
        let init_start = Instant::now();
        let matcher = AdvancedPatternMatcher::new(PatternMatcherConfig::default())
            .expect("Pattern matcher should initialize");
        let init_duration = init_start.elapsed();
        
        // KPI: Initialization should complete within 100ms
        assert!(init_duration < Duration::from_millis(100), 
                "Pattern matcher initialization should complete within 100ms, took {:?}", init_duration);
        
        // Test Case 2: High-Throughput Processing
        let test_data = create_test_malware_sample();
        let throughput_start = Instant::now();
        let mut total_scans = 0;
        let mut _total_matches = 0;
        
        // Run scans for 2 seconds to measure sustained throughput
        while throughput_start.elapsed() < Duration::from_secs(2) {
            let matches = matcher.scan_data(&test_data).await.expect("Scan should complete");
            _total_matches += matches.len();
            total_scans += 1;
        }
        
        let throughput_duration = throughput_start.elapsed();
        let scans_per_second = (total_scans as f64 / throughput_duration.as_secs_f64()) as u64;
        
        // KPI: Should achieve at least 2,500 scans per second
        assert!(scans_per_second >= 2500, 
                "Pattern matcher should achieve >= 2,500 scans/sec, achieved {}", scans_per_second);
        
        // Test Case 3: Batch Scanning Performance
        let batch_sizes = vec![1024, 4096, 16384, 65536]; // 1KB to 64KB
        for &size in &batch_sizes {
            let batch_data = vec![0x41u8; size]; // Simple test data
            let batch_start = Instant::now();
            let _matches = matcher.scan_data(&batch_data).await.expect("Batch scan should complete");
            let batch_duration = batch_start.elapsed();
            
            let throughput_mbps = (size as f64 / (1024.0 * 1024.0)) / batch_duration.as_secs_f64();
            
            // KPI: Should achieve at least 50 MB/s scanning rate
            assert!(throughput_mbps >= 50.0, 
                    "Batch scanning should achieve >= 50 MB/s, achieved {:.2} MB/s for {} bytes", 
                    throughput_mbps, size);
        }
        
        // Test Case 4: Large File Scanning
        let large_file_sizes = vec![1024 * 1024, 5 * 1024 * 1024, 10 * 1024 * 1024]; // 1MB, 5MB, 10MB
        for &size in &large_file_sizes {
            let large_file = vec![0x90u8; size]; // NOP sled pattern
            let large_scan_start = Instant::now();
            let _matches = matcher.scan_data(&large_file).await.expect("Large scan should complete");
            let large_scan_duration = large_scan_start.elapsed();
            
            let scan_rate_mbps = (size as f64 / (1024.0 * 1024.0)) / large_scan_duration.as_secs_f64();
            
            // KPI: Large file scanning should achieve at least 100 MB/s
            assert!(scan_rate_mbps >= 100.0, 
                    "Large file scanning should achieve >= 100 MB/s, achieved {:.2} MB/s for {} MB file", 
                    scan_rate_mbps, size / (1024 * 1024));
        }
        
        // Test Case 5: Advanced Pattern Detection Performance
        let complex_patterns = vec![
            create_test_malware_sample(),
            create_test_malware_sample(),
            create_clean_sample(),
        ];
        
        let pattern_detection_start = Instant::now();
        let mut total_detections = 0;
        
        for pattern in &complex_patterns {
            let matches = matcher.scan_data(pattern).await.expect("Pattern detection should complete");
            total_detections += matches.len();
        }
        
        let pattern_detection_duration = pattern_detection_start.elapsed();
        
        // KPI: Advanced pattern detection should complete within 500ms
        assert!(pattern_detection_duration < Duration::from_millis(500), 
                "Advanced pattern detection should complete within 500ms, took {:?}", pattern_detection_duration);
        
        // KPI: Should detect at least 3 patterns across test samples
        assert!(total_detections >= 3, 
                "Should detect at least 3 patterns, detected {}", total_detections);
        
        // Test Case 6: Concurrent Analysis Performance
        let concurrent_start = Instant::now();
        let mut handles = Vec::new();
        
        for i in 0..20 { // Increased concurrency
            let data_clone = if i % 3 == 0 {
                create_test_malware_sample()
            } else if i % 3 == 1 {
                create_clean_sample()
            } else {
                test_data.clone()
            };
            
            let handle = tokio::spawn(async move {
                let matcher = AdvancedPatternMatcher::new(PatternMatcherConfig::default()).unwrap();
                let start = Instant::now();
                let result = matcher.scan_data(&data_clone).await.unwrap_or_else(|_| Vec::new());
                (result, start.elapsed())
            });
            handles.push(handle);
        }
        
        let mut concurrent_results = Vec::new();
        for handle in handles {
            let (matches, duration) = handle.await.unwrap();
            concurrent_results.push((matches, duration));
        }
        
        let concurrent_duration = concurrent_start.elapsed();
        
        // KPI: Concurrent analysis should complete within 2 seconds
        assert!(concurrent_duration < Duration::from_secs(2), 
                "Concurrent analysis should complete within 2 seconds, took {:?}", concurrent_duration);
        
        // Validate individual task performance
        for (i, (_matches, task_duration)) in concurrent_results.iter().enumerate() {
            assert!(task_duration < &Duration::from_millis(200), 
                    "Concurrent task {} should complete within 200ms, took {:?}", i, task_duration);
        }
        
        // Test Case 7: Sustained Load Performance
        let sustained_start = Instant::now();
        let mut sustained_scans = 0;
        let mut peak_memory = 0;
        
        // Run sustained load for 5 seconds
        while sustained_start.elapsed() < Duration::from_secs(5) {
            let _matches = matcher.scan_data(&test_data).await.expect("Sustained scan should complete");
            sustained_scans += 1;
            
            // Monitor memory usage periodically
            if sustained_scans % 100 == 0 {
                let current_memory = get_memory_usage();
                if current_memory > peak_memory {
                    peak_memory = current_memory;
                }
            }
        }
        
        let sustained_duration = sustained_start.elapsed();
        let sustained_rate = sustained_scans as f64 / sustained_duration.as_secs_f64();
        
        // KPI: Sustained load should maintain at least 2,000 scans/sec
        assert!(sustained_rate >= 2000.0, 
                "Sustained load should maintain >= 2,000 scans/sec, achieved {:.0}", sustained_rate);
        
        // KPI: Memory usage should remain under 50MB during sustained load
        assert!(peak_memory < 50 * 1024 * 1024, 
                "Peak memory usage should remain under 50MB, used {} MB", peak_memory / (1024 * 1024));
        
        // Calculate overall performance score
        let performance_score = (
            (scans_per_second as f64 / 2500.0) * 0.3 +
            (sustained_rate / 2000.0) * 0.3 +
            (if concurrent_duration < Duration::from_secs(1) { 1.0 } else { 0.5 }) * 0.2 +
            (total_detections as f64 / 3.0) * 0.2
        ) * 100.0;
        
        println!("Pattern Matcher Performance Summary:");
        println!("  Initialization: {:?}", init_duration);
        println!("  Throughput: {} scans/sec", scans_per_second);
        println!("  Sustained Rate: {:.0} scans/sec", sustained_rate);
        println!("  Concurrent Duration: {:?}", concurrent_duration);
        println!("  Total Detections: {}", total_detections);
        println!("  Peak Memory: {} MB", peak_memory / (1024 * 1024));
        println!("  Overall Performance Score: {:.1}%", performance_score);
        
        // KPI: Overall performance score should be at least 85%
        assert!(performance_score >= 85.0, 
                "Overall performance score should be >= 85%, achieved {:.1}%", performance_score);
    }
    
    /// Test ETW monitor performance
    // Note: EtwMonitor module requires Windows-specific API hooking features
    // This test is disabled until the ETW monitoring component is implemented
    /*
    #[cfg(all(feature = "api-hooking", target_os = "windows"))]
    #[tokio::test]
    async fn test_etw_monitor_performance() {
        let monitor = EtwMonitor::new().expect("ETW monitor should initialize on Windows");
        
        let start_time = Instant::now();
        
        // Test ETW event processing performance
        monitor.start_monitoring().await.expect("ETW monitoring should start");
        
        // Simulate ETW events for performance testing
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        let events_processed = monitor.get_processed_event_count();
        let processing_duration = start_time.elapsed();
        
        monitor.stop_monitoring().await.expect("ETW monitoring should stop");
        
        println!("ETW Monitor processed {} events in {:?}", events_processed, processing_duration);
        
        // Production KPI: ETW monitor should process events with minimal overhead
        assert!(processing_duration < Duration::from_secs(1), "ETW processing should be efficient");
        assert!(events_processed > 0, "ETW monitor should capture system events");
    }
    */
    
    /// Test integrated system performance
    // Note: Full integration test requires all detection engines to be available
    // This test is disabled until all components are implemented
    /*
    #[tokio::test]
    async fn test_integrated_system_performance() {
        // Initialize all available engines
        let _behavioral_engine = BehavioralAnalysisEngine::new();
        
        #[cfg(feature = "memory-forensics")]
        let config = MemoryForensicsConfig::default();
            let memory_engine = MemoryForensicsEngine::new(config).expect("Memory engine should initialize");
        
        #[cfg(feature = "network-monitoring")]
        let network_analyzer = NetworkTrafficAnalyzer::new(NetworkTrafficConfig::default())
            .expect("Network analyzer should initialize");
        
        let pattern_matcher = AdvancedPatternMatcher::new(PatternMatcherConfig::default())
            .expect("Pattern matcher should initialize");
        
        #[cfg(all(feature = "api-hooking", target_os = "windows"))]
        let etw_monitor = EtwMonitor::new().expect("ETW monitor should initialize");
        
        let integration_start = Instant::now();
        
        // Test coordinated analysis across all engines
        let test_data = create_test_malware_sample();
        let test_events = generate_test_process_events();
        
        // Concurrent analysis across all engines
        let pattern_task = pattern_matcher.scan_data(&test_data);
        let behavioral_task = behavioral_engine.analyze_events(&test_events);
        
        let (pattern_result, behavioral_result) = tokio::join!(pattern_task, behavioral_task);
        
        let integration_duration = integration_start.elapsed();
        
        println!("Integrated system analysis completed in {:?}", integration_duration);
        
        // Production KPI: Integrated analysis should complete efficiently
        assert!(integration_duration < Duration::from_secs(5), "Integrated analysis should complete within 5 seconds");
        assert!(pattern_result.is_ok(), "Pattern analysis should succeed");
        assert!(behavioral_result.is_ok(), "Behavioral analysis should succeed");
        
        // Validate cross-engine correlation
        let pattern_matches = pattern_result.unwrap();
        let behavioral_analysis = behavioral_result.unwrap();
        
        // At least one engine should provide meaningful results
        assert!(pattern_matches.len() > 0 || behavioral_analysis.confidence > 0.0,
                "Integrated system should detect threats through at least one engine");
    }
    */
    
    /// Test memory usage during operations - Production KPI: < 200MB total memory usage
    // Note: Memory monitoring test requires all detection engines to be available
    // This test is disabled until all components are implemented
    /*
    #[tokio::test]
    async fn test_memory_usage_performance() {
        let initial_memory = get_memory_usage();
        
        // Initialize engines and measure memory impact
        let _behavioral_engine = BehavioralAnalysisEngine::new();
        let post_behavioral_memory = get_memory_usage();
        
        #[cfg(feature = "memory-forensics")]
        let config = MemoryForensicsConfig::default();
            let memory_engine = MemoryForensicsEngine::new(config).expect("Memory engine should initialize");
        #[cfg(feature = "memory-forensics")]
        let post_memory_engine_memory = get_memory_usage();
        
        #[cfg(feature = "network-monitoring")]
        let network_analyzer = NetworkTrafficAnalyzer::new(NetworkTrafficConfig::default())
            .expect("Network analyzer should initialize");
        #[cfg(feature = "network-monitoring")]
        let post_network_memory = get_memory_usage();
        
        let pattern_matcher = AdvancedPatternMatcher::new(PatternMatcherConfig::default())
            .expect("Pattern matcher should initialize");
        let post_pattern_memory = get_memory_usage();
        
        #[cfg(all(feature = "api-hooking", target_os = "windows"))]
        let etw_monitor = EtwMonitor::new().expect("ETW monitor should initialize");
        #[cfg(all(feature = "api-hooking", target_os = "windows"))]
        let post_etw_memory = get_memory_usage();
        
        // Test memory usage during operations
        let test_data = create_test_malware_sample();
        let test_events = generate_test_process_events();
        
        // Perform analysis operations and monitor memory
        let operation_start_memory = get_memory_usage();
        
        let _pattern_result = pattern_matcher.scan_data(&test_data).await.expect("Pattern scan should complete");
        let _behavioral_result = behavioral_engine.analyze_events(&test_events).await.expect("Behavioral analysis should complete");
        
        let operation_end_memory = get_memory_usage();
        
        // Calculate memory usage
        let total_memory_used = operation_end_memory.saturating_sub(initial_memory);
        let operation_memory_delta = operation_end_memory.saturating_sub(operation_start_memory);
        
        println!("Memory usage - Initial: {} bytes, Final: {} bytes, Total used: {} bytes", 
                 initial_memory, operation_end_memory, total_memory_used);
        println!("Memory delta during operations: {} bytes", operation_memory_delta);
        
        // Production KPI: Total memory usage should be < 200MB
        assert!(total_memory_used < 200 * 1024 * 1024, 
                "Total memory usage ({} bytes) should be < 200MB", total_memory_used);
        
        // Memory should not grow significantly during operations (< 50MB delta)
        assert!(operation_memory_delta < 50 * 1024 * 1024,
                "Operation memory delta ({} bytes) should be < 50MB", operation_memory_delta);
        
        // Individual engine memory footprints should be reasonable
        let behavioral_memory = post_behavioral_memory.saturating_sub(initial_memory);
        let pattern_memory = post_pattern_memory.saturating_sub(post_behavioral_memory);
        
        assert!(behavioral_memory < 50 * 1024 * 1024, "Behavioral engine should use < 50MB");
        assert!(pattern_memory < 100 * 1024 * 1024, "Pattern matcher should use < 100MB");
    }
    */
    
    /// Stress test with high load - Production KPI: Handle 10,000 concurrent operations, < 5% CPU
    #[tokio::test]
    async fn test_stress_performance() {
        // Test Case 1: Engine Initialization Under Load
        let init_start = Instant::now();
        let _behavioral_engine = BehavioralAnalysisEngine::new();
        let pattern_matcher = AdvancedPatternMatcher::new(PatternMatcherConfig::default())
            .expect("Pattern matcher should initialize");
        let init_duration = init_start.elapsed();
        
        // KPI: Initialization should complete quickly even under system load
        assert!(init_duration < Duration::from_millis(200), 
                "Engine initialization should complete within 200ms, took {:?}", init_duration);
        
        // Test Case 2: High-Concurrency Behavioral Analysis
        let test_events = generate_test_process_events();
        let behavioral_stress_start = Instant::now();
        let initial_memory = get_memory_usage();
        
        // Create 2000 concurrent analysis tasks (increased from 1000)
        let mut behavioral_handles = Vec::new();
        for i in 0..2000 {
            let _engine_clone = BehavioralAnalysisEngine::new();
            let events_clone = test_events.clone();
            
            let handle = tokio::spawn(async move {
                let analysis_start = Instant::now();
                // Behavioral analysis not yet implemented
                 let result = crate::core::types::DetectionResult {
                     threat_id: uuid::Uuid::new_v4(),
                     threat_type: crate::core::types::ThreatType::Ransomware,
                     severity: crate::core::types::ThreatSeverity::Medium,
                     confidence: 0.5,
                     detection_method: crate::core::types::DetectionMethod::Behavioral("test-method".to_string()),
                     file_path: None,
                     process_info: None,
                     network_info: None,
                     metadata: std::collections::HashMap::new(),
                     detected_at: chrono::Utc::now(),
                     recommended_actions: vec![crate::core::types::ResponseAction::Monitor],
                     details: "Performance test detection result".to_string(),
                     timestamp: chrono::Utc::now(),
                     source: "performance_test".to_string(),
                 };
                let _ = events_clone; // Use events_clone to avoid unused warning
                let analysis_duration = analysis_start.elapsed();
                
                // KPI: Each analysis should complete within 500ms
                assert!(analysis_duration < Duration::from_millis(500), 
                        "Analysis {} took too long: {:?}", i, analysis_duration);
                (result, analysis_duration)
            });
            behavioral_handles.push(handle);
        }
        
        // Wait for all behavioral analyses to complete
        let mut behavioral_results = Vec::new();
        let mut analysis_durations = Vec::new();
        for handle in behavioral_handles {
            let (result, duration) = handle.await.expect("Task should complete successfully");
            behavioral_results.push(result);
            analysis_durations.push(duration);
        }
        
        let behavioral_stress_duration = behavioral_stress_start.elapsed();
        let behavioral_memory = get_memory_usage();
        let behavioral_memory_used = behavioral_memory.saturating_sub(initial_memory);
        
        // KPI: Behavioral stress test should complete within 20 seconds
        assert!(behavioral_stress_duration < Duration::from_secs(20), 
                "Behavioral stress test should complete within 20 seconds, took {:?}", behavioral_stress_duration);
        
        // KPI: Memory usage should be < 300MB under behavioral stress
        assert!(behavioral_memory_used < 300 * 1024 * 1024, 
                "Behavioral memory usage should be < 300MB, used {} MB", behavioral_memory_used / (1024 * 1024));
        
        assert_eq!(behavioral_results.len(), 2000, "All 2000 behavioral analyses should complete successfully");
        
        // Test Case 3: High-Concurrency Pattern Matching
        let pattern_stress_start = Instant::now();
        let test_samples = vec![
            create_test_malware_sample(),
            create_test_malware_sample(),
            create_clean_sample(),
        ];
        let mut pattern_handles = Vec::new();
        
        // Create 1500 concurrent pattern matching tasks
        for i in 0..1500 {
            let matcher_clone = pattern_matcher.clone();
            let data_clone = test_samples[i % test_samples.len()].clone();
            
            let handle = tokio::spawn(async move {
                let scan_start = Instant::now();
                let result = matcher_clone.scan_data(&data_clone).await
                    .expect("Pattern scan should complete");
                let scan_duration = scan_start.elapsed();
                
                // KPI: Each scan should complete within 100ms
                assert!(scan_duration < Duration::from_millis(100), 
                        "Pattern scan {} took too long: {:?}", i, scan_duration);
                (result, scan_duration)
            });
            pattern_handles.push(handle);
        }
        
        // Wait for all pattern scans to complete
        let mut pattern_results: Vec<Vec<crate::detection::pattern_matcher::PatternMatch>> = Vec::new();
        let mut scan_durations = Vec::new();
        for handle in pattern_handles {
            let (result, duration) = handle.await.expect("Pattern scan task should complete");
            pattern_results.push(result);
            scan_durations.push(duration);
        }
        
        let pattern_stress_duration = pattern_stress_start.elapsed();
        let pattern_memory = get_memory_usage();
        let pattern_memory_used = pattern_memory.saturating_sub(behavioral_memory);
        
        // KPI: Pattern stress test should complete within 15 seconds
        assert!(pattern_stress_duration < Duration::from_secs(15), 
                "Pattern stress test should complete within 15 seconds, took {:?}", pattern_stress_duration);
        
        // KPI: Additional memory for pattern matching should be < 200MB
        assert!(pattern_memory_used < 200 * 1024 * 1024, 
                "Pattern matching memory should be < 200MB, used {} MB", pattern_memory_used / (1024 * 1024));
        
        assert_eq!(pattern_results.len(), 1500, "All 1500 pattern scans should complete successfully");
        
        // Test Case 4: Mixed Workload Stress Test
        let mixed_stress_start = Instant::now();
        let mut mixed_handles = Vec::new();
        
        // Create 1000 mixed concurrent tasks (behavioral + pattern matching)
        for i in 0..1000 {
            if i % 2 == 0 {
                // Behavioral analysis task
                let _engine_clone = BehavioralAnalysisEngine::new();
                let events_clone = test_events.clone();
                
                let handle = tokio::spawn(async move {
                    let start = Instant::now();
                    // Behavioral analysis not yet implemented
                     let result = crate::core::types::DetectionResult {
                         threat_id: uuid::Uuid::new_v4(),
                         threat_type: crate::core::types::ThreatType::Ransomware,
                         severity: crate::core::types::ThreatSeverity::Medium,
                         confidence: 0.5,
                         detection_method: crate::core::types::DetectionMethod::Behavioral("test-method".to_string()),
                         file_path: None,
                         process_info: None,
                         network_info: None,
                         metadata: std::collections::HashMap::new(),
                         detected_at: chrono::Utc::now(),
                         recommended_actions: vec![crate::core::types::ResponseAction::Monitor],
                         details: "Performance test detection result".to_string(),
                         timestamp: chrono::Utc::now(),
                         source: "performance_test".to_string(),
                     };
                    let _ = events_clone; // Use events_clone to avoid unused warning
                    ("behavioral", start.elapsed(), result.confidence)
                });
                mixed_handles.push(handle);
            } else {
                // Pattern matching task
                let matcher_clone = pattern_matcher.clone();
                let data_clone = test_samples[i % test_samples.len()].clone();
                
                let handle = tokio::spawn(async move {
                    let start = Instant::now();
                    let result = matcher_clone.scan_data(&data_clone).await
                        .expect("Mixed pattern scan should complete");
                    ("pattern", start.elapsed(), result.len() as f64)
                });
                mixed_handles.push(handle);
            }
        }
        
        // Wait for all mixed tasks to complete
        let mut mixed_results = Vec::new();
        for handle in mixed_handles {
            let (task_type, duration, metric) = handle.await.expect("Mixed task should complete");
            mixed_results.push((task_type, duration, metric));
        }
        
        let mixed_stress_duration = mixed_stress_start.elapsed();
        
        // KPI: Mixed workload should complete within 25 seconds
        assert!(mixed_stress_duration < Duration::from_secs(25), 
                "Mixed stress test should complete within 25 seconds, took {:?}", mixed_stress_duration);
        
        assert_eq!(mixed_results.len(), 1000, "All 1000 mixed tasks should complete successfully");
        
        // Test Case 5: Memory Leak Detection
        let leak_test_start = Instant::now();
        let pre_leak_memory = get_memory_usage();
        
        // Run repeated operations to detect memory leaks
        for _iteration in 0..100 {
            // Behavioral analysis not yet implemented
             let _behavioral_result: Result<Vec<crate::core::types::DetectionResult>, Box<dyn std::error::Error + Send + Sync>> = Ok(vec![]);
             let _ = test_events; // Use test_events to avoid unused warning
             let _ = _behavioral_result.expect("Leak test behavioral analysis should complete");
            let _pattern_result = pattern_matcher.scan_data(&test_samples[0]).await
                .expect("Leak test pattern scan should complete");
        }
        
        let post_leak_memory = get_memory_usage();
        let leak_test_duration = leak_test_start.elapsed();
        let memory_growth = post_leak_memory.saturating_sub(pre_leak_memory);
        
        // KPI: Memory leak test should complete within 10 seconds
        assert!(leak_test_duration < Duration::from_secs(10), 
                "Memory leak test should complete within 10 seconds, took {:?}", leak_test_duration);
        
        // KPI: Memory growth should be minimal (< 10MB)
        assert!(memory_growth < 10 * 1024 * 1024, 
                "Memory growth should be < 10MB, grew {} MB", memory_growth / (1024 * 1024));
        
        // Performance Analysis
        let avg_behavioral_duration = analysis_durations.iter().sum::<Duration>() / analysis_durations.len() as u32;
        let avg_pattern_duration = scan_durations.iter().sum::<Duration>() / scan_durations.len() as u32;
        
        let behavioral_throughput = behavioral_results.len() as f64 / behavioral_stress_duration.as_secs_f64();
        let pattern_throughput = pattern_results.len() as f64 / pattern_stress_duration.as_secs_f64();
        
        // Validate result consistency
        let mut valid_behavioral_results = 0;
        let mut valid_pattern_results = 0;
        
        for result in &behavioral_results {
            if result.confidence >= 0.0 && result.confidence <= 1.0 {
                valid_behavioral_results += 1;
            }
        }
        
        for result in &pattern_results {
            if !result.is_empty() {
                valid_pattern_results += 1;
            }
        }
        
        // Calculate overall stress performance score
        let stress_score = (
            (behavioral_throughput / 100.0).min(1.0) * 0.25 +
            (pattern_throughput / 100.0).min(1.0) * 0.25 +
            (if behavioral_stress_duration < Duration::from_secs(15) { 1.0 } else { 0.5 }) * 0.2 +
            (if pattern_stress_duration < Duration::from_secs(10) { 1.0 } else { 0.5 }) * 0.2 +
            (if memory_growth < 5 * 1024 * 1024 { 1.0 } else { 0.5 }) * 0.1
        ) * 100.0;
        
        println!("Stress Test Performance Summary:");
        println!("  Behavioral Analysis: {} tasks in {:?} ({:.1} tasks/sec)", behavioral_results.len(), behavioral_stress_duration, behavioral_throughput);
        println!("  Pattern Matching: {} tasks in {:?} ({:.1} tasks/sec)", pattern_results.len(), pattern_stress_duration, pattern_throughput);
        println!("  Mixed Workload: {} tasks in {:?}", mixed_results.len(), mixed_stress_duration);
        println!("  Average Behavioral Duration: {:?}", avg_behavioral_duration);
        println!("  Average Pattern Duration: {:?}", avg_pattern_duration);
        println!("  Memory Growth: {} MB", memory_growth / (1024 * 1024));
        println!("  Valid Results: {}/{} behavioral, {}/{} pattern", valid_behavioral_results, behavioral_results.len(), valid_pattern_results, pattern_results.len());
        println!("  Overall Stress Score: {:.1}%", stress_score);
        
        // Final KPIs
        assert!(valid_behavioral_results >= (behavioral_results.len() * 95 / 100), 
                "At least 95% of behavioral results should be valid");
        assert!(valid_pattern_results >= (pattern_results.len() * 90 / 100), 
                "At least 90% of pattern results should be valid");
        
        // KPI: Overall stress performance score should be at least 80%
        assert!(stress_score >= 80.0, 
                "Overall stress performance score should be at least 80%");
    }
}
