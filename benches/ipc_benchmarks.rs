//! IPC Performance Benchmarks
//!
//! This module provides comprehensive benchmarks for the ERDPS Agent IPC system,
//! measuring performance across different scenarios:
//! - File scanning with various file sizes
//! - Concurrent request handling
//! - Different command types
//! - Memory usage tracking

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use tempfile::TempDir;
use tokio::runtime::Runtime;

use erdps_agent::config::agent_config::AgentConfig;
use erdps_agent::detection::yara_engine::YaraEngine;
use erdps_agent::telemetry;

/// Benchmark configuration
struct BenchmarkConfig {
    pub temp_dir: TempDir,
    pub runtime: Runtime,
    pub config: Arc<AgentConfig>,
}

impl BenchmarkConfig {
    fn new() -> anyhow::Result<Self> {
        let runtime = Runtime::new()?;
        let temp_dir = TempDir::new()?;

        let config = Arc::new(AgentConfig {
            ipc_key: "benchmark_test_key".to_string(),
            max_concurrent_scans: 8,
            scan_timeout_secs: 30,
            memory_limit_mb: 1024,
            ..Default::default()
        });

        Ok(Self {
            temp_dir,
            runtime,
            config,
        })
    }

    /// Create test file with specified size
    fn create_test_file(&self, name: &str, size_bytes: usize) -> anyhow::Result<PathBuf> {
        let file_path = self.temp_dir.path().join(name);
        let content = vec![b'A'; size_bytes];
        fs::write(&file_path, content)?;
        Ok(file_path)
    }

    /// Create malicious test file (EICAR test string)
    fn create_malicious_file(&self, name: &str) -> anyhow::Result<PathBuf> {
        let file_path = self.temp_dir.path().join(name);
        let eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        fs::write(&file_path, eicar)?;
        Ok(file_path)
    }
}

/// Benchmark YARA engine file scanning with different file sizes
fn bench_yara_scan_sizes(c: &mut Criterion) {
    let config = BenchmarkConfig::new().expect("Failed to create benchmark config");

    // Initialize YARA engine
    let yara_engine = config
        .runtime
        .block_on(async { YaraEngine::new(Arc::clone(&config.config)) });

    let mut group = c.benchmark_group("yara_scan_sizes");

    // Test different file sizes
    let sizes = vec![
        ("1KB", 1024),
        ("10KB", 10 * 1024),
        ("100KB", 100 * 1024),
        ("1MB", 1024 * 1024),
        ("10MB", 10 * 1024 * 1024),
    ];

    for (size_name, size_bytes) in sizes {
        group.throughput(Throughput::Bytes(size_bytes as u64));

        group.bench_with_input(
            BenchmarkId::new("scan_file", size_name),
            &size_bytes,
            |b, &size| {
                let file_path = config
                    .create_test_file(&format!("test_{}.bin", size), size)
                    .expect("Failed to create test file");

                b.to_async(&config.runtime).iter(|| {
                    let engine = &yara_engine;
                    let path = file_path.clone();
                    async move {
                        let result = engine.scan_file(&path).await;
                        let _ = black_box(result);
                    }
                });
            },
        );
    }

    group.finish();
}

/// Benchmark YARA engine with malicious files
fn bench_yara_malicious_detection(c: &mut Criterion) {
    let config = BenchmarkConfig::new().expect("Failed to create benchmark config");

    // Initialize YARA engine
    let yara_engine = config
        .runtime
        .block_on(async { YaraEngine::new(Arc::clone(&config.config)) });

    let mut group = c.benchmark_group("yara_malicious_detection");

    // Create test files
    let clean_file = config
        .create_test_file("clean.txt", 1024)
        .expect("Failed to create clean file");
    let malicious_file = config
        .create_malicious_file("malicious.txt")
        .expect("Failed to create malicious file");

    group.bench_function("scan_clean_file", |b| {
        b.to_async(&config.runtime).iter(|| {
            let engine = &yara_engine;
            let path = clean_file.clone();
            async move {
                let result = engine.scan_file(&path).await;
                let _ = black_box(result);
            }
        });
    });

    group.bench_function("scan_malicious_file", |b| {
        b.to_async(&config.runtime).iter(|| {
            let engine = &yara_engine;
            let path = malicious_file.clone();
            async move {
                let result = engine.scan_file(&path).await;
                let _ = black_box(result);
            }
        });
    });

    group.finish();
}

/// Benchmark concurrent scanning
fn bench_concurrent_scanning(c: &mut Criterion) {
    let config = Arc::new(BenchmarkConfig::new().expect("Failed to create benchmark config"));

    // Initialize YARA engine
    let yara_engine = Arc::new(
        config
            .runtime
            .block_on(async { YaraEngine::new(Arc::clone(&config.config)) }),
    );

    let mut group = c.benchmark_group("concurrent_scanning");

    // Test different concurrency levels
    let concurrency_levels = vec![1, 2, 4, 8, 16];

    for concurrency in concurrency_levels {
        group.bench_with_input(
            BenchmarkId::new("concurrent_scans", concurrency),
            &concurrency,
            |b, &concurrency| {
                // Create test files for concurrent scanning
                let test_files: Vec<PathBuf> = (0..concurrency)
                    .map(|i| {
                        config
                            .create_test_file(
                                &format!("concurrent_test_{}.bin", i),
                                10 * 1024, // 10KB files
                            )
                            .expect("Failed to create test file")
                    })
                    .collect();

                b.to_async(&config.runtime).iter(|| {
                    let engine: Arc<YaraEngine> = Arc::clone(&yara_engine);
                    let files = test_files.clone();
                    async move {
                        let mut handles = Vec::new();

                        for file_path in files {
                            let engine_clone: Arc<YaraEngine> = Arc::clone(&engine);
                            let handle =
                                tokio::spawn(
                                    async move { engine_clone.scan_file(&file_path).await },
                                );
                            handles.push(handle);
                        }

                        let results = futures::future::join_all(handles).await;
                        let _ = black_box(results);
                    }
                });
            },
        );
    }

    group.finish();
}

/// Benchmark telemetry performance impact
fn bench_telemetry_overhead(c: &mut Criterion) {
    let config = BenchmarkConfig::new().expect("Failed to create benchmark config");

    let mut group = c.benchmark_group("telemetry_overhead");

    group.bench_function("telemetry_update_scan_metrics", |b| {
        b.iter(|| {
            let file_size = 1024;
            let scan_duration = Duration::from_millis(10);

            // Simulate telemetry updates
            config.runtime.block_on(async {
                telemetry::update_file_size_distribution(file_size).await;
                telemetry::increment_scan_counters(0, false).await;
                telemetry::update_scan_metrics(100.0, scan_duration.as_millis() as f64).await;
            });

            black_box(());
        });
    });

    group.bench_function("telemetry_get_metrics", |b| {
        b.to_async(&config.runtime).iter(|| async {
            let metrics = telemetry::get_telemetry().await;
            black_box(metrics);
        });
    });

    group.finish();
}

/// Benchmark cache performance
fn bench_cache_performance(c: &mut Criterion) {
    let config = BenchmarkConfig::new().expect("Failed to create benchmark config");

    // Initialize YARA engine
    let yara_engine = config
        .runtime
        .block_on(async { YaraEngine::new(Arc::clone(&config.config)) });

    let mut group = c.benchmark_group("cache_performance");

    // Create a test file
    let test_file = config
        .create_test_file("cache_test.bin", 10 * 1024)
        .expect("Failed to create test file");

    group.bench_function("first_scan_cache_miss", |b| {
        b.to_async(&config.runtime).iter(|| {
            let engine = &yara_engine;
            let path = test_file.clone();
            async move {
                // Clear cache before each iteration to ensure cache miss
                engine.clear_dedup_cache().await;
                let result = engine.scan_file(&path).await;
                let _ = black_box(result);
            }
        });
    });

    // Warm up cache
    config.runtime.block_on(async {
        let _ = yara_engine.scan_file(&test_file).await;
    });

    group.bench_function("subsequent_scan_cache_hit", |b| {
        b.to_async(&config.runtime).iter(|| {
            let engine = &yara_engine;
            let path = test_file.clone();
            async move {
                let result = engine.scan_file(&path).await;
                let _ = black_box(result);
            }
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_yara_scan_sizes,
    bench_yara_malicious_detection,
    bench_concurrent_scanning,
    bench_telemetry_overhead,
    bench_cache_performance
);
criterion_main!(benches);
