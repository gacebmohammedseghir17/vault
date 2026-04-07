//! Performance Metrics and MTTD Tracking
//!
//! This module provides comprehensive performance monitoring, Mean Time To Detection (MTTD)
//! tracking, and detection metrics collection for the validation framework.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Performance metrics collection and analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionMetrics {
    pub session_id: Option<Uuid>,
    pub start_time: SystemTime,
    pub total_samples_processed: u64,
    pub total_detections: u64,
    pub total_scan_time: Duration,
    pub memory_usage_samples: VecDeque<MemoryUsageSample>,
    pub cpu_usage_samples: VecDeque<CpuUsageSample>,
    pub scan_performance_samples: VecDeque<ScanPerformanceSample>,
    pub detection_latency_samples: VecDeque<DetectionLatencySample>,
    pub throughput_samples: VecDeque<ThroughputSample>,
    pub error_counts: HashMap<String, u64>,
    pub detection_confidence_distribution: HashMap<String, u64>,
    pub file_type_performance: HashMap<String, FileTypePerformance>,
}

/// Memory usage sample
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryUsageSample {
    pub timestamp: SystemTime,
    pub heap_used_bytes: u64,
    pub heap_total_bytes: u64,
    pub stack_used_bytes: u64,
    pub virtual_memory_bytes: u64,
    pub resident_set_size_bytes: u64,
}

/// CPU usage sample
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuUsageSample {
    pub timestamp: SystemTime,
    pub cpu_usage_percent: f64,
    pub user_time_percent: f64,
    pub system_time_percent: f64,
    pub idle_time_percent: f64,
    pub load_average_1min: f64,
    pub load_average_5min: f64,
    pub load_average_15min: f64,
}

/// Scan performance sample
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanPerformanceSample {
    pub timestamp: SystemTime,
    pub sample_id: String,
    pub file_size_bytes: u64,
    pub scan_duration: Duration,
    pub detection_result: DetectionResult,
    pub confidence_score: f64,
    pub rules_matched: u32,
    pub entropy_calculation_time: Duration,
    pub yara_scan_time: Duration,
    pub behavioral_analysis_time: Duration,
}

/// Detection result enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DetectionResult {
    Clean,
    Malware,
    Suspicious,
    Unknown,
    Error,
}

/// Detection latency sample
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionLatencySample {
    pub timestamp: SystemTime,
    pub sample_id: String,
    pub detection_start: Instant,
    pub first_indicator_time: Option<Instant>,
    pub final_decision_time: Instant,
    pub mttd: Duration,
    pub detection_stages: Vec<DetectionStage>,
}

/// Detection stage timing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionStage {
    pub stage_name: String,
    pub start_time: Instant,
    pub end_time: Instant,
    pub duration: Duration,
    pub stage_result: StageResult,
}

/// Stage result enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum StageResult {
    Success,
    Failed,
    Skipped,
    Timeout,
}

/// Throughput measurement sample
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThroughputSample {
    pub timestamp: SystemTime,
    pub time_window: Duration,
    pub samples_processed: u64,
    pub bytes_processed: u64,
    pub samples_per_second: f64,
    pub bytes_per_second: f64,
    pub concurrent_scans: u32,
}

/// File type specific performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileTypePerformance {
    pub file_type: String,
    pub samples_processed: u64,
    pub total_scan_time: Duration,
    pub average_scan_time: Duration,
    pub min_scan_time: Duration,
    pub max_scan_time: Duration,
    pub detection_rate: f64,
    pub false_positive_rate: f64,
    pub average_file_size: u64,
}

/// Mean Time To Detection (MTTD) tracker
#[derive(Debug, Clone)]
pub struct MTTDTracker {
    pub target_mttd: Duration,
    pub detection_samples: VecDeque<MTTDSample>,
    pub current_average: Duration,
    pub best_mttd: Duration,
    pub worst_mttd: Duration,
    pub samples_within_target: u64,
    pub total_samples: u64,
    pub percentile_95: Duration,
    pub percentile_99: Duration,
    pub rolling_window_size: usize,
}

/// MTTD sample data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MTTDSample {
    pub sample_id: String,
    pub malware_type: String,
    pub file_size_bytes: u64,
    pub detection_start: SystemTime,
    pub first_indicator: SystemTime,
    pub final_detection: SystemTime,
    pub mttd: Duration,
    pub detection_method: DetectionMethod,
    pub confidence_score: f64,
}

/// Detection method enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DetectionMethod {
    Signature,
    Behavioral,
    Entropy,
    Heuristic,
    MachineLearning,
    Hybrid,
}

/// Performance baseline configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceBaseline {
    pub baseline_id: Uuid,
    pub created_at: SystemTime,
    pub sample_count: u64,
    pub average_scan_time: Duration,
    pub memory_usage_baseline: u64,
    pub cpu_usage_baseline: f64,
    pub throughput_baseline: f64,
    pub mttd_baseline: Duration,
    pub detection_rate_baseline: f64,
    pub false_positive_rate_baseline: f64,
    pub performance_score: f64,
}

/// Performance comparison result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceComparison {
    pub baseline: PerformanceBaseline,
    pub current_metrics: DetectionMetrics,
    pub scan_time_ratio: f64,
    pub memory_usage_ratio: f64,
    pub cpu_usage_ratio: f64,
    pub throughput_ratio: f64,
    pub mttd_ratio: f64,
    pub overall_performance_change: f64,
    pub regression_detected: bool,
    pub improvement_areas: Vec<String>,
    pub regression_areas: Vec<String>,
}

impl DetectionMetrics {
    /// Create new detection metrics instance
    pub fn new() -> Self {
        Self {
            session_id: None,
            start_time: SystemTime::now(),
            total_samples_processed: 0,
            total_detections: 0,
            total_scan_time: Duration::ZERO,
            memory_usage_samples: VecDeque::with_capacity(1000),
            cpu_usage_samples: VecDeque::with_capacity(1000),
            scan_performance_samples: VecDeque::with_capacity(10000),
            detection_latency_samples: VecDeque::with_capacity(10000),
            throughput_samples: VecDeque::with_capacity(1000),
            error_counts: HashMap::new(),
            detection_confidence_distribution: HashMap::new(),
            file_type_performance: HashMap::new(),
        }
    }

    /// Record a scan performance sample
    pub fn record_scan_performance(&mut self, sample: ScanPerformanceSample) {
        self.total_samples_processed += 1;
        self.total_scan_time += sample.scan_duration;
        
        if sample.detection_result == DetectionResult::Malware {
            self.total_detections += 1;
        }

        // Update confidence distribution
        let confidence_bucket = format!("{:.1}", (sample.confidence_score * 10.0).floor() / 10.0);
        *self.detection_confidence_distribution.entry(confidence_bucket).or_insert(0) += 1;

        // Update file type performance
        let file_extension = sample.sample_id.split('.').last().unwrap_or("unknown").to_string();
        let file_perf = self.file_type_performance.entry(file_extension.clone()).or_insert(FileTypePerformance {
            file_type: file_extension,
            samples_processed: 0,
            total_scan_time: Duration::ZERO,
            average_scan_time: Duration::ZERO,
            min_scan_time: sample.scan_duration,
            max_scan_time: sample.scan_duration,
            detection_rate: 0.0,
            false_positive_rate: 0.0,
            average_file_size: 0,
        });
        
        file_perf.samples_processed += 1;
        file_perf.total_scan_time += sample.scan_duration;
        file_perf.average_scan_time = file_perf.total_scan_time / file_perf.samples_processed as u32;
        file_perf.min_scan_time = file_perf.min_scan_time.min(sample.scan_duration);
        file_perf.max_scan_time = file_perf.max_scan_time.max(sample.scan_duration);
        file_perf.average_file_size = (file_perf.average_file_size * (file_perf.samples_processed - 1) + sample.file_size_bytes) / file_perf.samples_processed;

        // Store sample with size limit
        self.scan_performance_samples.push_back(sample);
        if self.scan_performance_samples.len() > 10000 {
            self.scan_performance_samples.pop_front();
        }
    }

    /// Record memory usage sample
    pub fn record_memory_usage(&mut self, sample: MemoryUsageSample) {
        self.memory_usage_samples.push_back(sample);
        if self.memory_usage_samples.len() > 1000 {
            self.memory_usage_samples.pop_front();
        }
    }

    /// Record CPU usage sample
    pub fn record_cpu_usage(&mut self, sample: CpuUsageSample) {
        self.cpu_usage_samples.push_back(sample);
        if self.cpu_usage_samples.len() > 1000 {
            self.cpu_usage_samples.pop_front();
        }
    }

    /// Record throughput sample
    pub fn record_throughput(&mut self, sample: ThroughputSample) {
        self.throughput_samples.push_back(sample);
        if self.throughput_samples.len() > 1000 {
            self.throughput_samples.pop_front();
        }
    }

    /// Record error occurrence
    pub fn record_error(&mut self, error_type: String) {
        *self.error_counts.entry(error_type).or_insert(0) += 1;
    }

    /// Calculate current detection rate
    pub fn detection_rate(&self) -> f64 {
        if self.total_samples_processed == 0 {
            0.0
        } else {
            self.total_detections as f64 / self.total_samples_processed as f64
        }
    }

    /// Calculate average scan time
    pub fn average_scan_time(&self) -> Duration {
        if self.total_samples_processed == 0 {
            Duration::ZERO
        } else {
            self.total_scan_time / self.total_samples_processed as u32
        }
    }

    /// Calculate current throughput (samples per second)
    pub fn current_throughput(&self) -> f64 {
        let elapsed = self.start_time.elapsed().unwrap_or(Duration::from_secs(1));
        self.total_samples_processed as f64 / elapsed.as_secs_f64()
    }

    /// Get latest memory usage
    pub fn latest_memory_usage(&self) -> Option<&MemoryUsageSample> {
        self.memory_usage_samples.back()
    }

    /// Get latest CPU usage
    pub fn latest_cpu_usage(&self) -> Option<&CpuUsageSample> {
        self.cpu_usage_samples.back()
    }

    /// Generate performance summary
    pub fn generate_summary(&self) -> PerformanceSummary {
        let avg_memory = self.memory_usage_samples.iter()
            .map(|s| s.heap_used_bytes)
            .sum::<u64>() / self.memory_usage_samples.len().max(1) as u64;
        
        let avg_cpu = self.cpu_usage_samples.iter()
            .map(|s| s.cpu_usage_percent)
            .sum::<f64>() / self.cpu_usage_samples.len().max(1) as f64;

        PerformanceSummary {
            total_samples: self.total_samples_processed,
            total_detections: self.total_detections,
            detection_rate: self.detection_rate(),
            average_scan_time: self.average_scan_time(),
            current_throughput: self.current_throughput(),
            average_memory_usage: avg_memory,
            average_cpu_usage: avg_cpu,
            total_errors: self.error_counts.values().sum(),
            uptime: self.start_time.elapsed().unwrap_or(Duration::ZERO),
        }
    }

    /// Reset metrics
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

/// Performance summary structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceSummary {
    pub total_samples: u64,
    pub total_detections: u64,
    pub detection_rate: f64,
    pub average_scan_time: Duration,
    pub current_throughput: f64,
    pub average_memory_usage: u64,
    pub average_cpu_usage: f64,
    pub total_errors: u64,
    pub uptime: Duration,
}

impl MTTDTracker {
    /// Create new MTTD tracker
    pub fn new(target_mttd: Duration) -> Self {
        Self {
            target_mttd,
            detection_samples: VecDeque::with_capacity(10000),
            current_average: Duration::ZERO,
            best_mttd: Duration::MAX,
            worst_mttd: Duration::ZERO,
            samples_within_target: 0,
            total_samples: 0,
            percentile_95: Duration::ZERO,
            percentile_99: Duration::ZERO,
            rolling_window_size: 1000,
        }
    }

    /// Record MTTD sample
    pub fn record_detection(&mut self, sample: MTTDSample) {
        self.total_samples += 1;
        
        if sample.mttd <= self.target_mttd {
            self.samples_within_target += 1;
        }
        
        self.best_mttd = self.best_mttd.min(sample.mttd);
        self.worst_mttd = self.worst_mttd.max(sample.mttd);
        
        self.detection_samples.push_back(sample);
        
        // Maintain rolling window
        if self.detection_samples.len() > self.rolling_window_size {
            self.detection_samples.pop_front();
        }
        
        self.update_statistics();
    }

    /// Update internal statistics
    fn update_statistics(&mut self) {
        if self.detection_samples.is_empty() {
            return;
        }
        
        // Calculate average
        let total_time: Duration = self.detection_samples.iter()
            .map(|s| s.mttd)
            .sum();
        self.current_average = total_time / self.detection_samples.len() as u32;
        
        // Calculate percentiles
        let mut sorted_times: Vec<Duration> = self.detection_samples.iter()
            .map(|s| s.mttd)
            .collect();
        sorted_times.sort();
        
        let len = sorted_times.len();
        if len > 0 {
            let p95_index = ((len as f64) * 0.95) as usize;
            let p99_index = ((len as f64) * 0.99) as usize;
            
            self.percentile_95 = sorted_times[p95_index.min(len - 1)];
            self.percentile_99 = sorted_times[p99_index.min(len - 1)];
        }
    }

    /// Get target achievement rate
    pub fn target_achievement_rate(&self) -> f64 {
        if self.total_samples == 0 {
            0.0
        } else {
            self.samples_within_target as f64 / self.total_samples as f64
        }
    }

    /// Check if MTTD performance is acceptable
    pub fn is_performance_acceptable(&self, min_achievement_rate: f64) -> bool {
        self.target_achievement_rate() >= min_achievement_rate
    }

    /// Get MTTD statistics
    pub fn get_statistics(&self) -> MTTDStatistics {
        MTTDStatistics {
            target_mttd: self.target_mttd,
            current_average: self.current_average,
            best_mttd: self.best_mttd,
            worst_mttd: self.worst_mttd,
            percentile_95: self.percentile_95,
            percentile_99: self.percentile_99,
            target_achievement_rate: self.target_achievement_rate(),
            total_samples: self.total_samples,
            samples_within_target: self.samples_within_target,
        }
    }

    /// Generate MTTD report
    pub fn generate_report(&self) -> MTTDReport {
        let stats = self.get_statistics();
        
        let mut recommendations = Vec::new();
        
        if stats.target_achievement_rate < 0.95 {
            recommendations.push("MTTD target achievement rate is below 95%. Consider optimizing detection algorithms.".to_string());
        }
        
        if stats.current_average > self.target_mttd {
            recommendations.push(format!(
                "Average MTTD ({:.2}s) exceeds target ({:.2}s). Review detection pipeline performance.",
                stats.current_average.as_secs_f64(),
                self.target_mttd.as_secs_f64()
            ));
        }
        
        if stats.percentile_99 > self.target_mttd * 3 {
            recommendations.push("99th percentile MTTD is significantly high. Investigate worst-case scenarios.".to_string());
        }
        
        MTTDReport {
            statistics: stats,
            performance_grade: self.calculate_performance_grade(),
            recommendations,
            detection_method_breakdown: self.get_detection_method_breakdown(),
        }
    }

    /// Calculate performance grade
    fn calculate_performance_grade(&self) -> PerformanceGrade {
        let achievement_rate = self.target_achievement_rate();
        let avg_ratio = self.current_average.as_secs_f64() / self.target_mttd.as_secs_f64();
        
        match (achievement_rate, avg_ratio) {
            (rate, ratio) if rate >= 0.98 && ratio <= 0.5 => PerformanceGrade::Excellent,
            (rate, ratio) if rate >= 0.95 && ratio <= 0.8 => PerformanceGrade::Good,
            (rate, ratio) if rate >= 0.90 && ratio <= 1.2 => PerformanceGrade::Acceptable,
            (rate, ratio) if rate >= 0.80 && ratio <= 2.0 => PerformanceGrade::NeedsImprovement,
            _ => PerformanceGrade::Poor,
        }
    }

    /// Get detection method breakdown
    fn get_detection_method_breakdown(&self) -> HashMap<DetectionMethod, MTTDMethodStats> {
        let mut breakdown = HashMap::new();
        
        for sample in &self.detection_samples {
            let stats = breakdown.entry(sample.detection_method.clone()).or_insert(MTTDMethodStats {
                method: sample.detection_method.clone(),
                sample_count: 0,
                average_mttd: Duration::ZERO,
                best_mttd: Duration::MAX,
                worst_mttd: Duration::ZERO,
                total_mttd: Duration::ZERO,
            });
            
            stats.sample_count += 1;
            stats.total_mttd += sample.mttd;
            stats.average_mttd = stats.total_mttd / stats.sample_count as u32;
            stats.best_mttd = stats.best_mttd.min(sample.mttd);
            stats.worst_mttd = stats.worst_mttd.max(sample.mttd);
        }
        
        breakdown
    }
}

/// MTTD statistics structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MTTDStatistics {
    pub target_mttd: Duration,
    pub current_average: Duration,
    pub best_mttd: Duration,
    pub worst_mttd: Duration,
    pub percentile_95: Duration,
    pub percentile_99: Duration,
    pub target_achievement_rate: f64,
    pub total_samples: u64,
    pub samples_within_target: u64,
}

/// MTTD performance report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MTTDReport {
    pub statistics: MTTDStatistics,
    pub performance_grade: PerformanceGrade,
    pub recommendations: Vec<String>,
    pub detection_method_breakdown: HashMap<DetectionMethod, MTTDMethodStats>,
}

/// Performance grade enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PerformanceGrade {
    Excellent,
    Good,
    Acceptable,
    NeedsImprovement,
    Poor,
}

/// MTTD method-specific statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MTTDMethodStats {
    pub method: DetectionMethod,
    pub sample_count: u64,
    pub average_mttd: Duration,
    pub best_mttd: Duration,
    pub worst_mttd: Duration,
    pub total_mttd: Duration,
}

/// System resource monitor
pub struct ResourceMonitor {
    metrics: Arc<RwLock<DetectionMetrics>>,
    monitoring_active: Arc<RwLock<bool>>,
    sample_interval: Duration,
}

impl ResourceMonitor {
    /// Create new resource monitor
    pub fn new(metrics: Arc<RwLock<DetectionMetrics>>, sample_interval: Duration) -> Self {
        Self {
            metrics,
            monitoring_active: Arc::new(RwLock::new(false)),
            sample_interval,
        }
    }

    /// Start monitoring system resources
    pub async fn start_monitoring(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut active = self.monitoring_active.write().await;
        if *active {
            return Ok(()); // Already monitoring
        }
        *active = true;
        drop(active);

        let metrics = Arc::clone(&self.metrics);
        let monitoring_active = Arc::clone(&self.monitoring_active);
        let interval = self.sample_interval;

        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(interval);
            
            while *monitoring_active.read().await {
                interval_timer.tick().await;
                
                // Collect memory usage
                if let Ok(memory_sample) = Self::collect_memory_usage().await {
                    let mut metrics_guard = metrics.write().await;
                    metrics_guard.record_memory_usage(memory_sample);
                }
                
                // Collect CPU usage
                if let Ok(cpu_sample) = Self::collect_cpu_usage().await {
                    let mut metrics_guard = metrics.write().await;
                    metrics_guard.record_cpu_usage(cpu_sample);
                }
            }
        });

        Ok(())
    }

    /// Stop monitoring
    pub async fn stop_monitoring(&self) {
        let mut active = self.monitoring_active.write().await;
        *active = false;
    }

    /// Collect memory usage sample
    async fn collect_memory_usage() -> Result<MemoryUsageSample, Box<dyn std::error::Error + Send + Sync>> {
        // Placeholder implementation - in production, use system APIs
        Ok(MemoryUsageSample {
            timestamp: SystemTime::now(),
            heap_used_bytes: 1024 * 1024 * 64, // 64MB placeholder
            heap_total_bytes: 1024 * 1024 * 128, // 128MB placeholder
            stack_used_bytes: 1024 * 8, // 8KB placeholder
            virtual_memory_bytes: 1024 * 1024 * 256, // 256MB placeholder
            resident_set_size_bytes: 1024 * 1024 * 96, // 96MB placeholder
        })
    }

    /// Collect CPU usage sample
    async fn collect_cpu_usage() -> Result<CpuUsageSample, Box<dyn std::error::Error + Send + Sync>> {
        // Placeholder implementation - in production, use system APIs
        Ok(CpuUsageSample {
            timestamp: SystemTime::now(),
            cpu_usage_percent: 25.0, // Placeholder
            user_time_percent: 15.0,
            system_time_percent: 10.0,
            idle_time_percent: 75.0,
            load_average_1min: 1.2,
            load_average_5min: 1.1,
            load_average_15min: 1.0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detection_metrics_creation() {
        let metrics = DetectionMetrics::new();
        assert_eq!(metrics.total_samples_processed, 0);
        assert_eq!(metrics.total_detections, 0);
        assert_eq!(metrics.detection_rate(), 0.0);
    }

    #[test]
    fn test_mttd_tracker_creation() {
        let target = Duration::from_secs(5);
        let tracker = MTTDTracker::new(target);
        assert_eq!(tracker.target_mttd, target);
        assert_eq!(tracker.total_samples, 0);
        assert_eq!(tracker.target_achievement_rate(), 0.0);
    }

    #[test]
    fn test_scan_performance_recording() {
        let mut metrics = DetectionMetrics::new();
        
        let sample = ScanPerformanceSample {
            timestamp: SystemTime::now(),
            sample_id: "test.exe".to_string(),
            file_size_bytes: 1024,
            scan_duration: Duration::from_millis(100),
            detection_result: DetectionResult::Malware,
            confidence_score: 0.95,
            rules_matched: 3,
            entropy_calculation_time: Duration::from_millis(10),
            yara_scan_time: Duration::from_millis(50),
            behavioral_analysis_time: Duration::from_millis(40),
        };
        
        metrics.record_scan_performance(sample);
        
        assert_eq!(metrics.total_samples_processed, 1);
        assert_eq!(metrics.total_detections, 1);
        assert_eq!(metrics.detection_rate(), 1.0);
    }

    #[test]
    fn test_mttd_sample_recording() {
        let mut tracker = MTTDTracker::new(Duration::from_secs(5));
        
        let sample = MTTDSample {
            sample_id: "malware1.exe".to_string(),
            malware_type: "Trojan".to_string(),
            file_size_bytes: 2048,
            detection_start: SystemTime::now(),
            first_indicator: SystemTime::now(),
            final_detection: SystemTime::now(),
            mttd: Duration::from_secs(3),
            detection_method: DetectionMethod::Signature,
            confidence_score: 0.9,
        };
        
        tracker.record_detection(sample);
        
        assert_eq!(tracker.total_samples, 1);
        assert_eq!(tracker.samples_within_target, 1);
        assert_eq!(tracker.target_achievement_rate(), 1.0);
    }

    #[test]
    fn test_performance_grade_calculation() {
        let mut tracker = MTTDTracker::new(Duration::from_secs(10));
        
        // Add samples that should result in excellent performance
        for i in 0..100 {
            let sample = MTTDSample {
                sample_id: format!("sample_{}.exe", i),
                malware_type: "Test".to_string(),
                file_size_bytes: 1024,
                detection_start: SystemTime::now(),
                first_indicator: SystemTime::now(),
                final_detection: SystemTime::now(),
                mttd: Duration::from_secs(2), // Well under target
                detection_method: DetectionMethod::Signature,
                confidence_score: 0.9,
            };
            tracker.record_detection(sample);
        }
        
        let report = tracker.generate_report();
        assert_eq!(report.performance_grade, PerformanceGrade::Excellent);
    }
}
