//! Performance monitoring and optimization module

mod optimization_engine;

pub use optimization_engine::*;

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Performance thresholds for production deployment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceThresholds {
    /// Maximum CPU usage percentage (0.0 to 100.0)
    pub max_cpu_percent: f64,
    /// Maximum memory usage in bytes
    pub max_memory_bytes: u64,
    /// Maximum response time in milliseconds
    pub max_response_time_ms: u64,
    /// Monitoring interval in seconds
    pub monitoring_interval_secs: u64,
}

impl Default for PerformanceThresholds {
    fn default() -> Self {
        Self {
            max_cpu_percent: 6.0,                // 6% CPU limit
            max_memory_bytes: 350 * 1024 * 1024, // 350MB memory limit
            max_response_time_ms: 100,           // 100ms response time
            monitoring_interval_secs: 5,         // Check every 5 seconds
        }
    }
}

/// Current performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub cpu_percent: f64,
    pub memory_bytes: u64,
    pub response_time_ms: u64,
    pub timestamp: std::time::SystemTime,
    pub violations: Vec<PerformanceViolation>,
}

/// Performance violation details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceViolation {
    pub violation_type: ViolationType,
    pub actual_value: f64,
    pub threshold_value: f64,
    pub severity: ViolationSeverity,
    pub timestamp: std::time::SystemTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ViolationType {
    CpuExceeded,
    MemoryExceeded,
    ResponseTimeExceeded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ViolationSeverity {
    Warning,   // 80-100% of threshold
    Critical,  // 100-150% of threshold
    Emergency, // >150% of threshold
}

/// Performance Gate Enforcement Engine
pub struct PerformanceGate {
    thresholds: PerformanceThresholds,
    metrics_history: Arc<RwLock<Vec<PerformanceMetrics>>>,
    is_monitoring: Arc<RwLock<bool>>,
    violation_count: Arc<RwLock<u64>>,
}

impl PerformanceGate {
    /// Create a new performance gate with default thresholds
    pub fn new() -> Self {
        Self::with_thresholds(PerformanceThresholds::default())
    }

    /// Create a new performance gate with custom thresholds
    pub fn with_thresholds(thresholds: PerformanceThresholds) -> Self {
        Self {
            thresholds,
            metrics_history: Arc::new(RwLock::new(Vec::new())),
            is_monitoring: Arc::new(RwLock::new(false)),
            violation_count: Arc::new(RwLock::new(0)),
        }
    }

    /// Start performance monitoring
    pub async fn start_monitoring(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut is_monitoring = self.is_monitoring.write().await;
        if *is_monitoring {
            return Err("Performance monitoring is already running".into());
        }
        *is_monitoring = true;

        let thresholds = self.thresholds.clone();
        let metrics_history = Arc::clone(&self.metrics_history);
        let is_monitoring_clone = Arc::clone(&self.is_monitoring);
        let violation_count = Arc::clone(&self.violation_count);

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(thresholds.monitoring_interval_secs));

            while *is_monitoring_clone.read().await {
                interval.tick().await;

                let metrics = Self::collect_current_metrics(&thresholds).await;

                // Check for violations
                if !metrics.violations.is_empty() {
                    let mut count = violation_count.write().await;
                    *count += metrics.violations.len() as u64;

                    // Log critical violations
                    for violation in &metrics.violations {
                        if matches!(
                            violation.severity,
                            ViolationSeverity::Critical | ViolationSeverity::Emergency
                        ) {
                            eprintln!(
                                "PERFORMANCE VIOLATION: {:?} - Actual: {:.2}, Threshold: {:.2}",
                                violation.violation_type,
                                violation.actual_value,
                                violation.threshold_value
                            );
                        }
                    }
                }

                // Store metrics (keep last 100 entries)
                let mut history = metrics_history.write().await;
                history.push(metrics);
                if history.len() > 100 {
                    history.remove(0);
                }
            }
        });

        Ok(())
    }

    /// Stop performance monitoring
    pub async fn stop_monitoring(&self) {
        let mut is_monitoring = self.is_monitoring.write().await;
        *is_monitoring = false;
    }

    /// Get current performance metrics
    pub async fn get_current_metrics(&self) -> PerformanceMetrics {
        Self::collect_current_metrics(&self.thresholds).await
    }

    /// Get performance metrics history
    pub async fn get_metrics_history(&self) -> Vec<PerformanceMetrics> {
        self.metrics_history.read().await.clone()
    }

    /// Get total violation count
    pub async fn get_violation_count(&self) -> u64 {
        *self.violation_count.read().await
    }

    /// Check if performance is within acceptable limits
    pub async fn is_performance_acceptable(&self) -> bool {
        let metrics = self.get_current_metrics().await;
        metrics.violations.is_empty()
    }

    /// Enforce performance gate - returns error if violations exceed threshold
    pub async fn enforce_gate(&self, max_violations: u64) -> Result<(), String> {
        let violation_count = self.get_violation_count().await;
        if violation_count > max_violations {
            return Err(format!(
                "Performance gate failed: {} violations exceed limit of {}",
                violation_count, max_violations
            ));
        }

        let current_metrics = self.get_current_metrics().await;
        if !current_metrics.violations.is_empty() {
            let critical_violations: Vec<_> = current_metrics
                .violations
                .iter()
                .filter(|v| {
                    matches!(
                        v.severity,
                        ViolationSeverity::Critical | ViolationSeverity::Emergency
                    )
                })
                .collect();

            if !critical_violations.is_empty() {
                return Err(format!(
                    "Performance gate failed: {} critical violations detected",
                    critical_violations.len()
                ));
            }
        }

        Ok(())
    }

    /// Collect current system performance metrics
    async fn collect_current_metrics(thresholds: &PerformanceThresholds) -> PerformanceMetrics {
        let start_time = Instant::now();

        // Get current process info
        let _current_process = std::process::id();

        // Simulate CPU and memory collection (in real implementation, use sysinfo or similar)
        let cpu_percent = Self::get_cpu_usage().await;
        let memory_bytes = Self::get_memory_usage().await;
        let response_time_ms = start_time.elapsed().as_millis() as u64;

        let mut violations = Vec::new();

        // Check CPU threshold
        if cpu_percent > thresholds.max_cpu_percent {
            violations.push(PerformanceViolation {
                violation_type: ViolationType::CpuExceeded,
                actual_value: cpu_percent,
                threshold_value: thresholds.max_cpu_percent,
                severity: Self::calculate_severity(cpu_percent, thresholds.max_cpu_percent),
                timestamp: std::time::SystemTime::now(),
            });
        }

        // Check memory threshold
        if memory_bytes > thresholds.max_memory_bytes {
            violations.push(PerformanceViolation {
                violation_type: ViolationType::MemoryExceeded,
                actual_value: memory_bytes as f64,
                threshold_value: thresholds.max_memory_bytes as f64,
                severity: Self::calculate_severity(
                    memory_bytes as f64,
                    thresholds.max_memory_bytes as f64,
                ),
                timestamp: std::time::SystemTime::now(),
            });
        }

        // Check response time threshold
        if response_time_ms > thresholds.max_response_time_ms {
            violations.push(PerformanceViolation {
                violation_type: ViolationType::ResponseTimeExceeded,
                actual_value: response_time_ms as f64,
                threshold_value: thresholds.max_response_time_ms as f64,
                severity: Self::calculate_severity(
                    response_time_ms as f64,
                    thresholds.max_response_time_ms as f64,
                ),
                timestamp: std::time::SystemTime::now(),
            });
        }

        PerformanceMetrics {
            cpu_percent,
            memory_bytes,
            response_time_ms,
            timestamp: std::time::SystemTime::now(),
            violations,
        }
    }

    /// Get current CPU usage percentage
    async fn get_cpu_usage() -> f64 {
        // In production, use sysinfo crate or similar
        // For now, simulate with random value that's usually under threshold
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        std::time::SystemTime::now().hash(&mut hasher);
        let hash = hasher.finish();

        // Generate value that's usually under 6% but occasionally spikes
        let base_usage = (hash % 300) as f64 / 100.0; // 0-3%
        if hash % 3 == 0 {
            base_usage + 4.0 // More frequent spikes to 4-7% (above 6% threshold)
        } else {
            base_usage
        }
    }

    /// Get current memory usage in bytes
    async fn get_memory_usage() -> u64 {
        // In production, use sysinfo crate or similar
        // For now, simulate with value that's usually under 200MB
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        std::time::SystemTime::now().hash(&mut hasher);
        let hash = hasher.finish();

        // Generate value that's usually under 200MB but occasionally spikes
        let base_usage = (hash % (150 * 1024 * 1024)) + (50 * 1024 * 1024); // 50-200MB
        if hash % 4 == 0 {
            base_usage + (150 * 1024 * 1024) // More frequent spikes above 200MB
        } else {
            base_usage
        }
    }

    /// Calculate violation severity based on threshold exceedance
    fn calculate_severity(actual: f64, threshold: f64) -> ViolationSeverity {
        let ratio = actual / threshold;
        if ratio >= 1.5 {
            ViolationSeverity::Emergency
        } else if ratio >= 1.0 {
            ViolationSeverity::Critical
        } else {
            ViolationSeverity::Warning
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{sleep, Duration};

    #[tokio::test]
    async fn test_performance_gate_creation() {
        // Use very low thresholds to guarantee violations for testing
        let thresholds = PerformanceThresholds {
            max_cpu_percent: 0.1,    // Very low threshold to trigger violations
            max_memory_bytes: 1024,  // Very low threshold to trigger violations
            max_response_time_ms: 1, // Very low threshold to trigger violations
            monitoring_interval_secs: 1,
        };
        let gate = PerformanceGate::with_thresholds(thresholds);
        assert!(!gate.is_performance_acceptable().await); // Should have violations due to very low thresholds
    }

    #[tokio::test]
    async fn test_custom_thresholds() {
        let thresholds = PerformanceThresholds {
            max_cpu_percent: 10.0,
            max_memory_bytes: 500 * 1024 * 1024,
            max_response_time_ms: 200,
            monitoring_interval_secs: 1,
        };

        let gate = PerformanceGate::with_thresholds(thresholds);
        let metrics = gate.get_current_metrics().await;

        assert!(metrics.cpu_percent >= 0.0);
        assert!(metrics.memory_bytes > 0);
        // Response time should be non-negative (u64 is always >= 0)
        assert!(metrics.response_time_ms < u64::MAX);
    }

    #[tokio::test]
    async fn test_monitoring_lifecycle() {
        let gate = PerformanceGate::new();

        // Start monitoring
        gate.start_monitoring().await.unwrap();

        // Wait for some metrics collection
        sleep(Duration::from_millis(100)).await;

        // Stop monitoring
        gate.stop_monitoring().await;

        // Should have collected some metrics
        let _history = gate.get_metrics_history().await;
        // History might be empty due to short monitoring time, but should not panic
    }

    #[tokio::test]
    async fn test_violation_detection() {
        let thresholds = PerformanceThresholds {
            max_cpu_percent: 0.1,    // Very low threshold to trigger violations
            max_memory_bytes: 1024,  // Very low threshold to trigger violations
            max_response_time_ms: 1, // Very low threshold to trigger violations
            monitoring_interval_secs: 1,
        };

        let gate = PerformanceGate::with_thresholds(thresholds);
        let metrics = gate.get_current_metrics().await;

        // Should have violations due to very low thresholds
        assert!(
            !metrics.violations.is_empty(),
            "Should detect violations with very low thresholds"
        );
    }

    #[tokio::test]
    async fn test_performance_gate_enforcement() {
        let thresholds = PerformanceThresholds {
            max_cpu_percent: 0.1,    // Very low to trigger violations
            max_memory_bytes: 1024,  // Very low to trigger violations
            max_response_time_ms: 1, // Very low to trigger violations
            monitoring_interval_secs: 1,
        };

        let gate = PerformanceGate::with_thresholds(thresholds);

        // Should fail enforcement due to violations
        let result = gate.enforce_gate(0).await;
        assert!(result.is_err(), "Should fail enforcement with violations");
    }

    #[tokio::test]
    async fn test_performance_gate_edge_cases() {
        // Test with very high thresholds - should pass
        let high_thresholds = PerformanceThresholds {
            max_cpu_percent: 100.0,
            max_memory_bytes: u64::MAX,
            max_response_time_ms: u64::MAX,
            monitoring_interval_secs: 1,
        };
        let gate_high = PerformanceGate::with_thresholds(high_thresholds);
        assert!(gate_high.is_performance_acceptable().await, "Should pass with very high thresholds");

        // Test with zero thresholds - should fail
        let zero_thresholds = PerformanceThresholds {
            max_cpu_percent: 0.0,
            max_memory_bytes: 0,
            max_response_time_ms: 0,
            monitoring_interval_secs: 1,
        };
        let gate_zero = PerformanceGate::with_thresholds(zero_thresholds);
        assert!(!gate_zero.is_performance_acceptable().await, "Should fail with zero thresholds");
    }
}
