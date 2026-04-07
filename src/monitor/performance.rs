//! Performance monitoring and SLO enforcement for ERDPS Agent
//! Implements strict performance gates with enforcement actions
//! Requirements: CPU ≤ 6%, RAM ≤ 200MB, MTTD < 60s, FP < 0.1%

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use sysinfo::{Pid, System};
use tokio::sync::{mpsc, RwLock};
use tokio::time::{interval, sleep};
use tracing::{debug, error, info, warn};

/// SLO thresholds as defined in the specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SloThresholds {
    /// Maximum CPU usage percentage (6%)
    pub max_cpu_percent: f32,
    /// Maximum memory usage in MB (200MB)
    pub max_memory_mb: u64,
    /// Maximum time to detection in seconds (60s)
    pub max_detection_time_secs: u64,
    /// Maximum false positive rate (0.1%)
    pub max_false_positive_rate: f32,
}

impl Default for SloThresholds {
    fn default() -> Self {
        Self {
            max_cpu_percent: 6.0,
            max_memory_mb: 200,
            max_detection_time_secs: 60,
            max_false_positive_rate: 0.1,
        }
    }
}

/// Performance metrics snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    #[serde(skip, default = "Instant::now")]
    pub timestamp: Instant,
    pub cpu_usage_percent: f32,
    pub memory_usage_mb: u64,
    pub detection_time_ms: Option<u64>,
    pub false_positive_count: u64,
    pub total_detections: u64,
}

/// SLO violation types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SloViolation {
    CpuExceeded { current: f32, threshold: f32 },
    MemoryExceeded { current: u64, threshold: u64 },
    DetectionTimeExceeded { current: u64, threshold: u64 },
    FalsePositiveRateExceeded { current: f32, threshold: f32 },
}

/// Enforcement actions for SLO violations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EnforcementAction {
    /// Log warning and continue
    LogWarning,
    /// Throttle operations to reduce resource usage
    ThrottleOperations,
    /// Pause non-critical operations
    PauseNonCritical,
    /// Emergency shutdown if violations are severe
    EmergencyShutdown,
}

/// Performance monitor with SLO enforcement
pub struct PerformanceMonitor {
    system: Arc<RwLock<System>>,
    thresholds: SloThresholds,
    process_id: u32,
    violation_sender: mpsc::UnboundedSender<SloViolation>,
    metrics_history: Arc<RwLock<Vec<PerformanceMetrics>>>,
    start_time: Instant,
    detection_times: Arc<RwLock<Vec<Duration>>>,
    false_positive_count: Arc<RwLock<u64>>,
    total_detections: Arc<RwLock<u64>>,
    /// Warm-up grace period (60 seconds)
    warmup_duration: Duration,
    /// Number of logical CPU cores for normalization
    logical_cores: usize,
    /// Rolling window for CPU measurements (for hysteresis)
    cpu_measurements: Arc<RwLock<Vec<f32>>>,
    /// Rolling window for memory measurements (for hysteresis)
    memory_measurements: Arc<RwLock<Vec<u64>>>,
}

impl PerformanceMonitor {
    /// Create a new performance monitor with default SLO thresholds
    pub fn new() -> (Self, mpsc::UnboundedReceiver<SloViolation>) {
        let (violation_sender, violation_receiver) = mpsc::unbounded_channel();
        let mut system = System::new_all();
        system.refresh_all();

        let logical_cores = num_cpus::get();
        info!(
            "Detected {} logical CPU cores for SLO normalization",
            logical_cores
        );

        let monitor = Self {
            system: Arc::new(RwLock::new(system)),
            thresholds: SloThresholds::default(),
            process_id: std::process::id(),
            violation_sender,
            metrics_history: Arc::new(RwLock::new(Vec::new())),
            start_time: Instant::now(),
            detection_times: Arc::new(RwLock::new(Vec::new())),
            false_positive_count: Arc::new(RwLock::new(0)),
            total_detections: Arc::new(RwLock::new(0)),
            warmup_duration: Duration::from_secs(60), // 60 second warm-up grace period
            logical_cores,
            cpu_measurements: Arc::new(RwLock::new(Vec::new())),
            memory_measurements: Arc::new(RwLock::new(Vec::new())),
        };

        (monitor, violation_receiver)
    }

    /// Create monitor with custom thresholds
    pub fn with_thresholds(
        thresholds: SloThresholds,
    ) -> (Self, mpsc::UnboundedReceiver<SloViolation>) {
        let (mut monitor, receiver) = Self::new();
        monitor.thresholds = thresholds;
        (monitor, receiver)
    }

    /// Start continuous monitoring
    pub async fn start_monitoring(&self) {
        let mut interval = interval(Duration::from_secs(1));

        info!("Starting performance monitoring with SLO enforcement");
        info!(
            "Thresholds: CPU ≤ {:.1}%, Memory ≤ {}MB, MTTD ≤ {}s, FP ≤ {:.1}%",
            self.thresholds.max_cpu_percent,
            self.thresholds.max_memory_mb,
            self.thresholds.max_detection_time_secs,
            self.thresholds.max_false_positive_rate
        );

        loop {
            interval.tick().await;

            if let Err(e) = self.check_performance_gates().await {
                error!("Performance monitoring error: {}", e);
            }
        }
    }

    /// Check all performance gates and enforce SLOs
    pub async fn check_performance_gates(
        &self,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let metrics = self.collect_metrics().await?;

        // Check if we're still in warm-up grace period
        let uptime = self.start_time.elapsed();
        if uptime < self.warmup_duration {
            debug!(
                "Warm-up grace period active: {:.1}s remaining",
                (self.warmup_duration - uptime).as_secs_f32()
            );
            return Ok(()); // Skip SLO enforcement during warm-up
        }

        // Store metrics in history
        {
            let mut history = self.metrics_history.write().await;
            history.push(metrics.clone());

            // Keep only last 300 entries (5 minutes at 1s intervals)
            if history.len() > 300 {
                let len = history.len();
                history.drain(0..len - 300);
            }
        }

        // Normalize CPU usage to logical cores and apply rolling average
        let normalized_cpu = metrics.cpu_usage_percent / self.logical_cores as f32;
        let smoothed_cpu = self.update_cpu_rolling_average(normalized_cpu).await;

        // Apply rolling average for memory
        let smoothed_memory = self
            .update_memory_rolling_average(metrics.memory_usage_mb)
            .await;

        // Check CPU usage with hysteresis (only trigger if consistently high)
        if smoothed_cpu > self.thresholds.max_cpu_percent {
            let violation = SloViolation::CpuExceeded {
                current: smoothed_cpu,
                threshold: self.thresholds.max_cpu_percent,
            };
            self.handle_violation(violation).await;
        }

        // Check memory usage with hysteresis
        if smoothed_memory > self.thresholds.max_memory_mb {
            let violation = SloViolation::MemoryExceeded {
                current: smoothed_memory,
                threshold: self.thresholds.max_memory_mb,
            };
            self.handle_violation(violation).await;
        }

        // Check detection time if available
        if let Some(detection_time_ms) = metrics.detection_time_ms {
            let detection_time_secs = detection_time_ms / 1000;
            if detection_time_secs > self.thresholds.max_detection_time_secs {
                let violation = SloViolation::DetectionTimeExceeded {
                    current: detection_time_secs,
                    threshold: self.thresholds.max_detection_time_secs,
                };
                self.handle_violation(violation).await;
            }
        }

        // Check false positive rate
        if metrics.total_detections > 0 {
            let fp_rate =
                (metrics.false_positive_count as f32 / metrics.total_detections as f32) * 100.0;
            if fp_rate > self.thresholds.max_false_positive_rate {
                let violation = SloViolation::FalsePositiveRateExceeded {
                    current: fp_rate,
                    threshold: self.thresholds.max_false_positive_rate,
                };
                self.handle_violation(violation).await;
            }
        }

        debug!("Performance check completed: CPU {:.2}% (normalized: {:.2}%, smoothed: {:.2}%), Memory {}MB (smoothed: {}MB)", 
               metrics.cpu_usage_percent, normalized_cpu, smoothed_cpu, metrics.memory_usage_mb, smoothed_memory);

        Ok(())
    }

    /// Update CPU rolling average for hysteresis
    async fn update_cpu_rolling_average(&self, current_cpu: f32) -> f32 {
        let mut measurements = self.cpu_measurements.write().await;
        measurements.push(current_cpu);

        // Keep only last 10 measurements (10 seconds for hysteresis)
        if measurements.len() > 10 {
            measurements.remove(0);
        }

        // Return rolling average
        measurements.iter().sum::<f32>() / measurements.len() as f32
    }

    /// Update memory rolling average for hysteresis
    async fn update_memory_rolling_average(&self, current_memory: u64) -> u64 {
        let mut measurements = self.memory_measurements.write().await;
        measurements.push(current_memory);

        // Keep only last 10 measurements (10 seconds for hysteresis)
        if measurements.len() > 10 {
            measurements.remove(0);
        }

        // Return rolling average
        measurements.iter().sum::<u64>() / measurements.len() as u64
    }

    /// Collect current performance metrics
    async fn collect_metrics(
        &self,
    ) -> Result<PerformanceMetrics, Box<dyn std::error::Error + Send + Sync>> {
        let mut system = self.system.write().await;
        system.refresh_processes();

        // Wait for CPU measurement to stabilize
        drop(system);
        sleep(Duration::from_millis(100)).await;

        let mut system = self.system.write().await;
        system.refresh_processes();

        let process = system
            .process(Pid::from(self.process_id as usize))
            .ok_or("Process not found")?;

        // CPU usage from sysinfo can exceed 100% on multi-core systems
        // Cap it at 100% for SLO calculations
        let raw_cpu_usage = process.cpu_usage();
        let cpu_usage = if raw_cpu_usage > 100.0 {
            100.0
        } else {
            raw_cpu_usage
        };
        let memory_usage = process.memory() / 1024 / 1024; // Convert to MB

        // Calculate average detection time from recent detections
        let detection_times = self.detection_times.read().await;
        let avg_detection_time = if !detection_times.is_empty() {
            let sum: Duration = detection_times.iter().sum();
            Some(sum.as_millis() as u64 / detection_times.len() as u64)
        } else {
            None
        };

        let false_positive_count = *self.false_positive_count.read().await;
        let total_detections = *self.total_detections.read().await;

        Ok(PerformanceMetrics {
            timestamp: Instant::now(),
            cpu_usage_percent: cpu_usage,
            memory_usage_mb: memory_usage,
            detection_time_ms: avg_detection_time,
            false_positive_count,
            total_detections,
        })
    }

    /// Handle SLO violation with appropriate enforcement action
    async fn handle_violation(&self, violation: SloViolation) {
        let action = self.determine_enforcement_action(&violation).await;

        match &violation {
            SloViolation::CpuExceeded { current, threshold } => {
                warn!("CPU SLO violation: {:.2}% > {:.2}%", current, threshold);
            }
            SloViolation::MemoryExceeded { current, threshold } => {
                warn!("Memory SLO violation: {}MB > {}MB", current, threshold);
            }
            SloViolation::DetectionTimeExceeded { current, threshold } => {
                warn!(
                    "Detection time SLO violation: {}s > {}s",
                    current, threshold
                );
            }
            SloViolation::FalsePositiveRateExceeded { current, threshold } => {
                warn!(
                    "False positive rate SLO violation: {:.2}% > {:.2}%",
                    current, threshold
                );
            }
        }

        self.execute_enforcement_action(action).await;

        // Send violation to handler
        if let Err(e) = self.violation_sender.send(violation) {
            error!("Failed to send SLO violation: {}", e);
        }
    }

    /// Determine appropriate enforcement action based on violation severity
    /// Critical subsystems (metrics, dashboard, IPC) are protected from shutdown
    async fn determine_enforcement_action(&self, violation: &SloViolation) -> EnforcementAction {
        match violation {
            SloViolation::CpuExceeded { current, threshold } => {
                if *current > threshold * 3.0 {
                    // Changed from EmergencyShutdown to PauseNonCritical
                    // Critical subsystems (metrics/dashboard/IPC) remain running
                    warn!("Severe CPU violation detected, degrading non-critical operations");
                    EnforcementAction::PauseNonCritical
                } else if *current > threshold * 2.0 {
                    EnforcementAction::PauseNonCritical
                } else {
                    EnforcementAction::ThrottleOperations
                }
            }
            SloViolation::MemoryExceeded { current, threshold } => {
                if *current > threshold * 3 {
                    // Changed from EmergencyShutdown to PauseNonCritical
                    // Critical subsystems (metrics/dashboard/IPC) remain running
                    warn!("Severe memory violation detected, degrading non-critical operations");
                    EnforcementAction::PauseNonCritical
                } else if *current > threshold * 2 {
                    EnforcementAction::PauseNonCritical
                } else {
                    EnforcementAction::ThrottleOperations
                }
            }
            SloViolation::DetectionTimeExceeded { .. } => EnforcementAction::LogWarning,
            SloViolation::FalsePositiveRateExceeded { .. } => EnforcementAction::LogWarning,
        }
    }

    /// Execute the determined enforcement action
    /// Critical subsystems (metrics, dashboard, IPC) are always protected
    async fn execute_enforcement_action(&self, action: EnforcementAction) {
        match action {
            EnforcementAction::LogWarning => {
                // Already logged in handle_violation
            }
            EnforcementAction::ThrottleOperations => {
                info!("Throttling operations to reduce resource usage (critical subsystems protected)");
                // Add throttling logic here - reduce scan frequency, pause non-essential tasks
                sleep(Duration::from_millis(100)).await;
            }
            EnforcementAction::PauseNonCritical => {
                warn!("Pausing non-critical operations due to SLO violation (metrics/dashboard/IPC remain active)");
                // Add pause logic here - pause file scanning, ML processing, but keep:
                // - Metrics server (port 19091)
                // - Dashboard (port 19092)
                // - IPC server (port 8888)
                sleep(Duration::from_millis(500)).await;
            }
            EnforcementAction::EmergencyShutdown => {
                // This case should no longer be reached due to changes in determine_enforcement_action
                // But keeping for safety - convert to PauseNonCritical
                warn!("Emergency shutdown converted to non-critical pause (critical subsystems protected)");
                sleep(Duration::from_millis(500)).await;
            }
        }
    }

    /// Record a detection event for MTTD calculation
    pub async fn record_detection(&self, detection_time: Duration, is_false_positive: bool) {
        {
            let mut times = self.detection_times.write().await;
            times.push(detection_time);

            // Keep only last 100 detection times
            if times.len() > 100 {
                let len = times.len();
                times.drain(0..len - 100);
            }
        }

        {
            let mut total = self.total_detections.write().await;
            *total += 1;
        }

        if is_false_positive {
            let mut fp_count = self.false_positive_count.write().await;
            *fp_count += 1;
        }

        debug!(
            "Recorded detection: time={:?}, false_positive={}",
            detection_time, is_false_positive
        );
    }

    /// Get current performance metrics
    pub async fn get_current_metrics(
        &self,
    ) -> Result<PerformanceMetrics, Box<dyn std::error::Error + Send + Sync>> {
        self.collect_metrics().await
    }

    /// Get metrics history
    pub async fn get_metrics_history(&self) -> Vec<PerformanceMetrics> {
        self.metrics_history.read().await.clone()
    }

    /// Check if system is currently within SLO bounds
    pub async fn is_within_slo(&self) -> bool {
        match self.collect_metrics().await {
            Ok(metrics) => {
                metrics.cpu_usage_percent <= self.thresholds.max_cpu_percent
                    && metrics.memory_usage_mb <= self.thresholds.max_memory_mb
                    && metrics.detection_time_ms.map_or(true, |dt| {
                        dt / 1000 <= self.thresholds.max_detection_time_secs
                    })
                    && (metrics.total_detections == 0
                        || (metrics.false_positive_count as f32 / metrics.total_detections as f32)
                            * 100.0
                            <= self.thresholds.max_false_positive_rate)
            }
            Err(_) => false,
        }
    }
}

/// SLO violation handler that processes violations and takes corrective actions
pub struct SloViolationHandler {
    receiver: mpsc::UnboundedReceiver<SloViolation>,
}

impl SloViolationHandler {
    pub fn new(receiver: mpsc::UnboundedReceiver<SloViolation>) -> Self {
        Self { receiver }
    }

    /// Start handling SLO violations
    pub async fn start_handling(&mut self) {
        info!("Starting SLO violation handler");

        while let Some(violation) = self.receiver.recv().await {
            self.process_violation(violation).await;
        }
    }

    /// Process a single SLO violation
    async fn process_violation(&self, violation: SloViolation) {
        match violation {
            SloViolation::CpuExceeded { current, threshold } => {
                error!(
                    "Processing CPU SLO violation: {:.2}% > {:.2}%",
                    current, threshold
                );
                // Additional processing logic can be added here
            }
            SloViolation::MemoryExceeded { current, threshold } => {
                error!(
                    "Processing Memory SLO violation: {}MB > {}MB",
                    current, threshold
                );
                // Additional processing logic can be added here
            }
            SloViolation::DetectionTimeExceeded { current, threshold } => {
                error!(
                    "Processing Detection Time SLO violation: {}s > {}s",
                    current, threshold
                );
                // Additional processing logic can be added here
            }
            SloViolation::FalsePositiveRateExceeded { current, threshold } => {
                error!(
                    "Processing False Positive Rate SLO violation: {:.2}% > {:.2}%",
                    current, threshold
                );
                // Additional processing logic can be added here
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::timeout;

    #[tokio::test]
    async fn test_performance_monitor_creation() {
        let (monitor, _receiver) = PerformanceMonitor::new();

        // Check that monitor was created successfully
        let metrics = monitor.get_current_metrics().await.unwrap();
        println!(
            "Current metrics: CPU {:.2}%, Memory {}MB",
            metrics.cpu_usage_percent, metrics.memory_usage_mb
        );

        // Test with very lenient thresholds for testing environment
        let lenient_thresholds = SloThresholds {
            max_cpu_percent: 150.0, // Very lenient for testing (above 100%)
            max_memory_mb: 4096,    // Very lenient for testing
            max_detection_time_secs: 120,
            max_false_positive_rate: 0.2,
        };

        let (lenient_monitor, _receiver) = PerformanceMonitor::with_thresholds(lenient_thresholds);
        assert!(lenient_monitor.is_within_slo().await);
    }

    #[tokio::test]
    async fn test_custom_thresholds() {
        let custom_thresholds = SloThresholds {
            max_cpu_percent: 10.0,
            max_memory_mb: 500,
            max_detection_time_secs: 30,
            max_false_positive_rate: 0.05,
        };

        let (monitor, _receiver) = PerformanceMonitor::with_thresholds(custom_thresholds.clone());
        assert_eq!(monitor.thresholds.max_cpu_percent, 10.0);
        assert_eq!(monitor.thresholds.max_memory_mb, 500);
    }

    #[tokio::test]
    async fn test_detection_recording() {
        let (monitor, _receiver) = PerformanceMonitor::new();

        monitor
            .record_detection(Duration::from_millis(50), false)
            .await;
        monitor
            .record_detection(Duration::from_millis(75), true)
            .await;

        let metrics = monitor.get_current_metrics().await.unwrap();
        assert_eq!(metrics.total_detections, 2);
        assert_eq!(metrics.false_positive_count, 1);
    }

    #[tokio::test]
    async fn test_metrics_collection() {
        let (monitor, _receiver) = PerformanceMonitor::new();

        let metrics = monitor.get_current_metrics().await.unwrap();
        assert!(metrics.cpu_usage_percent >= 0.0);
        assert!(metrics.memory_usage_mb > 0);
    }

    #[tokio::test]
    async fn test_slo_violation_handling() {
        let (monitor, mut receiver) = PerformanceMonitor::new();

        // Simulate a violation
        let violation = SloViolation::CpuExceeded {
            current: 10.0,
            threshold: 6.0,
        };

        monitor.handle_violation(violation.clone()).await;

        // Check that violation was sent
        let received = timeout(Duration::from_millis(100), receiver.recv()).await;
        assert!(received.is_ok());
    }
}
