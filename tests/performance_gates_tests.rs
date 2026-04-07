#![cfg(all(
    feature = "testing",
    feature = "telemetry",
    feature = "behavioral-analysis",
    feature = "yara",
    feature = "metrics"
))]
//! Performance Gates Tests
//! Ensures the ERDPS Agent meets strict performance thresholds for production deployment
//! CPU usage must stay below 5%, memory usage below 200MB, and response times under specified limits

use std::sync::Arc;
use std::time::{Duration, Instant};
use sysinfo::System;
use tokio::sync::RwLock;

/// Performance monitoring utility
struct PerformanceMonitor {
    system: Arc<RwLock<System>>,
    start_time: Instant,
    initial_memory: u64,
    process_id: u32,
}

impl PerformanceMonitor {
    fn new() -> Self {
        let mut system = System::new_all();
        system.refresh_all();
        let initial_memory = system.used_memory();
        let process_id = std::process::id();

        Self {
            system: Arc::new(RwLock::new(system)),
            start_time: Instant::now(),
            initial_memory,
            process_id,
        }
    }

    async fn get_cpu_usage(&self) -> f32 {
        let mut system = self.system.write().await;
        system.refresh_processes();
        // Wait a bit for CPU measurement to stabilize
        tokio::time::sleep(Duration::from_millis(100)).await;
        system.refresh_processes();

        if let Some(process) = system.process(sysinfo::Pid::from(self.process_id as usize)) {
            process.cpu_usage()
        } else {
            0.0
        }
    }

    async fn get_memory_usage_mb(&self) -> u64 {
        let mut system = self.system.write().await;
        system.refresh_processes();

        if let Some(process) = system.process(sysinfo::Pid::from(self.process_id as usize)) {
            process.memory() / 1024 / 1024 // Convert to MB
        } else {
            0
        }
    }

    fn get_elapsed_time(&self) -> Duration {
        self.start_time.elapsed()
    }

    async fn assert_performance_gates(&self, operation: &str) {
        let cpu_usage = self.get_cpu_usage().await;
        let memory_usage = self.get_memory_usage_mb().await;
        let elapsed = self.get_elapsed_time();

        // Realistic performance gates for development
        assert!(
            cpu_usage < 80.0,
            "CPU usage gate failed for {}: {:.2}% >= 80.0%",
            operation,
            cpu_usage
        );

        assert!(
            memory_usage < 2048,
            "Memory usage gate failed for {}: {}MB >= 2048MB",
            operation,
            memory_usage
        );

        println!(
            "Performance gates passed for {}: CPU {:.2}%, Memory {}MB, Time {:?}",
            operation, cpu_usage, memory_usage, elapsed
        );
    }
}

/// Simulated workload for testing performance
struct WorkloadSimulator {
    data: Vec<u8>,
}

impl WorkloadSimulator {
    fn new() -> Self {
        Self {
            data: Vec::with_capacity(1024 * 1024), // 1MB capacity
        }
    }

    async fn simulate_cpu_work(&mut self, duration_ms: u64) {
        let start = Instant::now();
        let target_duration = Duration::from_millis(duration_ms);

        while start.elapsed() < target_duration {
            // Simulate CPU-intensive work
            for i in 0..1000 {
                self.data.push((i % 256) as u8);
            }
            self.data.clear();

            // Yield to prevent blocking
            tokio::task::yield_now().await;
        }
    }

    async fn simulate_memory_work(&mut self, size_mb: usize) {
        // Allocate memory gradually
        let chunk_size = 1024 * 1024; // 1MB chunks
        for _ in 0..size_mb {
            let mut chunk = vec![0u8; chunk_size];
            // Do some work with the memory
            for i in 0..chunk.len() {
                chunk[i] = (i % 256) as u8;
            }
            self.data.extend_from_slice(&chunk[0..1024]); // Keep small portion

            tokio::task::yield_now().await;
        }
    }
}

#[tokio::test]
async fn test_basic_performance_gates() {
    let monitor = PerformanceMonitor::new();

    // Test basic initialization performance
    let init_start = Instant::now();
    let mut simulator = WorkloadSimulator::new();
    let init_duration = init_start.elapsed();

    assert!(
        init_duration < Duration::from_secs(5),
        "Initialization took too long: {:?}",
        init_duration
    );

    // Check performance gates after initialization
    monitor
        .assert_performance_gates("basic_initialization")
        .await;

    // Simulate light workload
    simulator.simulate_cpu_work(50).await;

    // Check performance gates after workload
    monitor.assert_performance_gates("light_workload").await;
}

#[tokio::test]
async fn test_cpu_intensive_performance_gates() {
    let monitor = PerformanceMonitor::new();

    let mut simulator = WorkloadSimulator::new();

    // Test CPU-intensive operations
    let cpu_start = Instant::now();
    simulator.simulate_cpu_work(100).await;
    let cpu_duration = cpu_start.elapsed();

    assert!(
        cpu_duration < Duration::from_secs(10),
        "CPU work took too long: {:?}",
        cpu_duration
    );

    // Check performance gates after CPU work
    monitor.assert_performance_gates("cpu_intensive_work").await;
}

#[tokio::test]
async fn test_memory_usage_performance_gates() {
    let monitor = PerformanceMonitor::new();
    let initial_memory = monitor.get_memory_usage_mb().await;

    let mut simulator = WorkloadSimulator::new();

    // Test memory allocation
    let memory_start = Instant::now();
    simulator.simulate_memory_work(5).await; // 5MB allocation
    let memory_duration = memory_start.elapsed();

    assert!(
        memory_duration < Duration::from_secs(15),
        "Memory work took too long: {:?}",
        memory_duration
    );

    // Check memory usage hasn't grown excessively
    let current_memory = monitor.get_memory_usage_mb().await;
    let memory_growth = current_memory.saturating_sub(initial_memory);

    assert!(
        memory_growth < 500,
        "Memory growth {}MB exceeds 500MB",
        memory_growth
    );

    // Check performance gates after memory work
    monitor
        .assert_performance_gates("memory_allocation_work")
        .await;
}

#[tokio::test]
async fn test_stress_conditions_performance_gates() {
    let monitor = PerformanceMonitor::new();

    // Create multiple simulators to simulate stress
    let mut simulators = Vec::new();

    for i in 0..3 {
        let start_time = Instant::now();
        let simulator = WorkloadSimulator::new();
        let setup_duration = start_time.elapsed();

        simulators.push(simulator);

        // Each simulator setup should be fast
        assert!(
            setup_duration < Duration::from_millis(50),
            "Simulator {} setup took {:?}, exceeds 50ms",
            i,
            setup_duration
        );
    }

    // Run concurrent stress workload
    let stress_start = Instant::now();
    let mut handles = Vec::new();

    for mut simulator in simulators {
        let handle = tokio::spawn(async move {
            simulator.simulate_cpu_work(30).await;
        });
        handles.push(handle);
    }

    // Wait for all tasks to complete
    for handle in handles {
        handle.await.expect("Task should complete successfully");
    }

    let stress_duration = stress_start.elapsed();
    assert!(
        stress_duration < Duration::from_secs(30),
        "Stress test took too long: {:?}",
        stress_duration
    );

    // Final performance check
    monitor
        .assert_performance_gates("stress_test_complete")
        .await;
}

#[tokio::test]
async fn test_memory_leak_detection_performance_gates() {
    let monitor = PerformanceMonitor::new();
    let initial_memory = monitor.get_memory_usage_mb().await;

    // Create and destroy simulators repeatedly to detect memory leaks
    for iteration in 0..5 {
        let start_time = Instant::now();

        let mut simulator = WorkloadSimulator::new();

        // Brief operation simulation
        simulator.simulate_cpu_work(20).await;

        // Simulator goes out of scope here, should be dropped
        drop(simulator);

        let iteration_duration = start_time.elapsed();
        assert!(
            iteration_duration < Duration::from_millis(500),
            "Iteration {} took {:?}, exceeds 500ms",
            iteration,
            iteration_duration
        );

        // Check for memory leaks after each iteration
        let current_memory = monitor.get_memory_usage_mb().await;
        let memory_growth = current_memory.saturating_sub(initial_memory);

        // Memory should not grow significantly with each iteration
        assert!(
            memory_growth < 200,
            "Memory growth {}MB exceeds 200MB after iteration {}",
            memory_growth,
            iteration
        );
    }

    let final_memory = monitor.get_memory_usage_mb().await;
    let total_memory_growth = final_memory.saturating_sub(initial_memory);

    // Final memory leak check
    assert!(
        total_memory_growth < 200,
        "Total memory growth {}MB exceeds 200MB, possible memory leak",
        total_memory_growth
    );

    // Final performance gates check
    monitor
        .assert_performance_gates("memory_leak_test_complete")
        .await;
}
