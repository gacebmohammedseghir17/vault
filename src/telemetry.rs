//! Global telemetry system for sharing metrics across components

use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

/// File size categories for distribution tracking
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FileSizeCategory {
    Tiny,   // < 1KB
    Small,  // 1KB - 100KB
    Medium, // 100KB - 10MB
    Large,  // 10MB - 100MB
    Huge,   // > 100MB
}

impl FileSizeCategory {
    pub fn from_size(size: u64) -> Self {
        match size {
            0..=1024 => FileSizeCategory::Tiny,
            1025..=102400 => FileSizeCategory::Small,
            102401..=10485760 => FileSizeCategory::Medium,
            10485761..=104857600 => FileSizeCategory::Large,
            _ => FileSizeCategory::Huge,
        }
    }
}

/// Latency histogram for tracking scan performance
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LatencyHistogram {
    pub samples: Vec<f64>,
    pub p50: f64,
    pub p90: f64,
    pub p95: f64,
    pub p99: f64,
    pub min: f64,
    pub max: f64,
    pub mean: f64,
    #[serde(skip)]
    pub last_updated: Option<std::time::Instant>,
}

impl LatencyHistogram {
    pub fn add_sample(&mut self, latency_ms: f64) {
        self.samples.push(latency_ms);
        self.last_updated = Some(std::time::Instant::now());

        // Keep only last 1000 samples to prevent memory growth
        if self.samples.len() > 1000 {
            self.samples.remove(0);
        }

        self.recalculate();
    }

    fn recalculate(&mut self) {
        if self.samples.is_empty() {
            return;
        }

        let mut sorted = self.samples.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());

        let len = sorted.len();
        self.min = sorted[0];
        self.max = sorted[len - 1];
        self.mean = sorted.iter().sum::<f64>() / len as f64;

        self.p50 = sorted[len * 50 / 100];
        self.p90 = sorted[len * 90 / 100];
        self.p95 = sorted[len * 95 / 100];
        self.p99 = sorted[len * 99 / 100];
    }
}

/// Global telemetry data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryData {
    // Basic metrics
    pub queue_depth: usize,
    pub scans_per_second: f64,
    pub median_scan_latency_ms: f64,
    pub total_scans: u64,
    pub total_matches: u64,
    pub total_errors: u64,
    pub dedup_hits: u64,
    pub dedup_misses: u64,
    #[serde(skip)]
    pub last_updated: Option<Instant>,

    // Enhanced metrics
    pub file_size_distribution: HashMap<FileSizeCategory, u64>,
    pub latency_histogram: LatencyHistogram,
    pub total_bytes_scanned: u64,
    pub average_file_size: u64,
    pub scan_throughput_mbps: f64,
    pub io_wait_time_ms: f64,
    pub actual_scan_time_ms: f64,
    pub cache_hit_rate: f64,
    pub active_scan_threads: usize,
    pub peak_memory_usage_mb: u64,
    pub rules_loaded: usize,
    pub rules_compilation_time_ms: f64,
}

impl Default for TelemetryData {
    fn default() -> Self {
        Self {
            queue_depth: 0,
            scans_per_second: 0.0,
            median_scan_latency_ms: 0.0,
            total_scans: 0,
            total_matches: 0,
            total_errors: 0,
            dedup_hits: 0,
            dedup_misses: 0,
            last_updated: None,
            file_size_distribution: HashMap::new(),
            latency_histogram: LatencyHistogram::default(),
            total_bytes_scanned: 0,
            average_file_size: 0,
            scan_throughput_mbps: 0.0,
            io_wait_time_ms: 0.0,
            actual_scan_time_ms: 0.0,
            cache_hit_rate: 0.0,
            active_scan_threads: 0,
            peak_memory_usage_mb: 0,
            rules_loaded: 0,
            rules_compilation_time_ms: 0.0,
        }
    }
}

/// Global telemetry instance
static GLOBAL_TELEMETRY: Lazy<Arc<RwLock<TelemetryData>>> =
    Lazy::new(|| Arc::new(RwLock::new(TelemetryData::default())));

/// Update telemetry data
pub async fn update_telemetry(data: TelemetryData) {
    let mut telemetry = GLOBAL_TELEMETRY.write().await;
    *telemetry = data;
}

/// Get current telemetry data
pub async fn get_telemetry() -> TelemetryData {
    GLOBAL_TELEMETRY.read().await.clone()
}

/// Update specific telemetry fields
pub async fn update_queue_depth(depth: usize) {
    let mut telemetry = GLOBAL_TELEMETRY.write().await;
    telemetry.queue_depth = depth;
    telemetry.last_updated = Some(Instant::now());
}

pub async fn update_scan_metrics(scans_per_sec: f64, median_latency_ms: f64) {
    let mut telemetry = GLOBAL_TELEMETRY.write().await;
    telemetry.scans_per_second = scans_per_sec;
    telemetry.median_scan_latency_ms = median_latency_ms;
    telemetry.last_updated = Some(Instant::now());
}

pub async fn increment_scan_counters(matches: usize, has_error: bool) {
    let mut telemetry = GLOBAL_TELEMETRY.write().await;
    telemetry.total_scans += 1;
    telemetry.total_matches += matches as u64;
    if has_error {
        telemetry.total_errors += 1;
    }
    telemetry.last_updated = Some(Instant::now());
}

pub async fn increment_dedup_counters(hits: u64, misses: u64) {
    let mut telemetry = GLOBAL_TELEMETRY.write().await;
    telemetry.dedup_hits += hits;
    telemetry.dedup_misses += misses;

    // Update cache hit rate
    let total_cache_requests = telemetry.dedup_hits + telemetry.dedup_misses;
    if total_cache_requests > 0 {
        telemetry.cache_hit_rate =
            (telemetry.dedup_hits as f64 / total_cache_requests as f64) * 100.0;
    }

    telemetry.last_updated = Some(Instant::now());
}

/// Update file size distribution
pub async fn update_file_size_distribution(file_size: u64) {
    let mut telemetry = GLOBAL_TELEMETRY.write().await;
    let category = FileSizeCategory::from_size(file_size);
    *telemetry
        .file_size_distribution
        .entry(category)
        .or_insert(0) += 1;

    // Update total bytes scanned and average file size
    telemetry.total_bytes_scanned += file_size;
    if telemetry.total_scans > 0 {
        telemetry.average_file_size = telemetry.total_bytes_scanned / telemetry.total_scans;
    }

    telemetry.last_updated = Some(Instant::now());
}

/// Add latency sample to histogram
pub async fn add_latency_sample(latency_ms: f64) {
    let mut telemetry = GLOBAL_TELEMETRY.write().await;
    telemetry.latency_histogram.add_sample(latency_ms);
    telemetry.median_scan_latency_ms = telemetry.latency_histogram.p50;
    telemetry.last_updated = Some(Instant::now());
}

/// Update scan performance metrics
pub async fn update_scan_performance(io_time_ms: f64, scan_time_ms: f64, bytes_scanned: u64) {
    let mut telemetry = GLOBAL_TELEMETRY.write().await;
    telemetry.io_wait_time_ms = io_time_ms;
    telemetry.actual_scan_time_ms = scan_time_ms;

    // Calculate throughput in MB/s
    let total_time_s = (io_time_ms + scan_time_ms) / 1000.0;
    if total_time_s > 0.0 {
        telemetry.scan_throughput_mbps = (bytes_scanned as f64 / (1024.0 * 1024.0)) / total_time_s;
    }

    telemetry.last_updated = Some(Instant::now());
}

/// Update thread and memory metrics
pub async fn update_system_metrics(active_threads: usize, memory_usage_mb: u64) {
    let mut telemetry = GLOBAL_TELEMETRY.write().await;
    telemetry.active_scan_threads = active_threads;
    if memory_usage_mb > telemetry.peak_memory_usage_mb {
        telemetry.peak_memory_usage_mb = memory_usage_mb;
    }
    telemetry.last_updated = Some(Instant::now());
}

/// Update YARA rules metrics
pub async fn update_rules_metrics(rules_count: usize, compilation_time_ms: f64) {
    let mut telemetry = GLOBAL_TELEMETRY.write().await;
    telemetry.rules_loaded = rules_count;
    telemetry.rules_compilation_time_ms = compilation_time_ms;
    telemetry.last_updated = Some(Instant::now());
}

/// Get detailed telemetry report as JSON
pub async fn get_telemetry_json() -> Result<String, serde_json::Error> {
    let telemetry = GLOBAL_TELEMETRY.read().await;
    serde_json::to_string_pretty(&*telemetry)
}

/// Reset telemetry counters (useful for benchmarking)
pub async fn reset_telemetry() {
    let mut telemetry = GLOBAL_TELEMETRY.write().await;
    *telemetry = TelemetryData::default();
}
