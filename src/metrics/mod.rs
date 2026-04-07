//! Metrics collection and reporting module
//!
//! This module provides comprehensive metrics collection for the ransomware detection system,
//! including performance monitoring, detection statistics, and system health tracking.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Instant;

pub mod database;
pub mod performance;
pub mod telemetry;

pub use database::*;

/// Central metrics collector for the ransomware detection system
#[derive(Debug, Clone)]
pub struct MetricsCollector {
    database: MetricsDatabase,
    start_time: Instant,
    component_metrics: Arc<RwLock<HashMap<String, ComponentMetrics>>>,
}

/// Component-specific metrics
#[derive(Debug, Clone, Default)]
pub struct ComponentMetrics {
    pub cpu_usage: f64,
    pub memory_usage: f64,
    pub disk_usage: f64,
    pub error_count: u64,
    pub warning_count: u64,
    pub last_activity: Option<DateTime<Utc>>,
    pub uptime_seconds: u64,
}

/// System-wide performance thresholds
#[derive(Debug, Clone)]
pub struct PerformanceThresholds {
    pub max_cpu_percent: f64,
    pub max_memory_mb: f64,
    pub max_disk_mb: f64,
    pub max_response_time_ms: u64,
    pub min_uptime_percent: f64,
}

impl Default for PerformanceThresholds {
    fn default() -> Self {
        Self {
            max_cpu_percent: 6.0,      // 6% CPU max
            max_memory_mb: 200.0,      // 200MB memory max
            max_disk_mb: 1000.0,       // 1GB disk max
            max_response_time_ms: 100, // 100ms response time max
            min_uptime_percent: 99.9,  // 99.9% uptime minimum
        }
    }
}

impl MetricsCollector {
    /// Create a new metrics collector with database backend
    pub fn new(database: MetricsDatabase) -> Self {
        Self {
            database,
            start_time: Instant::now(),
            component_metrics: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Record a performance metric
    pub fn record_performance(
        &self,
        component: &str,
        metric_type: &str,
        value: f64,
        unit: &str,
    ) -> anyhow::Result<()> {
        let metric = PerformanceMetric {
            id: None,
            timestamp: Utc::now(),
            metric_type: metric_type.to_string(),
            metric_value: value,
            unit: unit.to_string(),
            component: component.to_string(),
            process_id: Some(std::process::id()),
            additional_context: None,
        };

        self.database.record_performance_metric(&metric)?;

        // Update in-memory metrics
        let mut metrics = self.component_metrics.write().unwrap();
        let component_metric = metrics.entry(component.to_string()).or_default();

        match metric_type {
            "cpu_usage" => component_metric.cpu_usage = value,
            "memory_usage" => component_metric.memory_usage = value,
            "disk_usage" => component_metric.disk_usage = value,
            _ => {}
        }

        component_metric.last_activity = Some(Utc::now());

        Ok(())
    }

    /// Record a detection result
    pub fn record_detection(&self, detection: DetectionRecord) -> anyhow::Result<()> {
        self.database.record_detection(&detection)?;
        Ok(())
    }

    /// Record a validation result
    pub fn record_validation(&self, validation: ValidationRecord) -> anyhow::Result<()> {
        self.database.record_validation(&validation)?;
        Ok(())
    }

    /// Check performance gates against thresholds
    pub fn check_performance_gates(
        &self,
        thresholds: &PerformanceThresholds,
    ) -> anyhow::Result<Vec<PerformanceGateRecord>> {
        let mut gate_results = Vec::new();
        let metrics = self.component_metrics.read().unwrap();

        for (component, metric) in metrics.iter() {
            // CPU usage gate
            let cpu_gate = PerformanceGateRecord {
                id: None,
                timestamp: Utc::now(),
                gate_name: "cpu_usage_limit".to_string(),
                gate_type: "threshold".to_string(),
                threshold_value: thresholds.max_cpu_percent,
                actual_value: metric.cpu_usage,
                passed: metric.cpu_usage <= thresholds.max_cpu_percent,
                component: component.clone(),
                test_context: Some("production_monitoring".to_string()),
                severity: if metric.cpu_usage > thresholds.max_cpu_percent {
                    "critical".to_string()
                } else {
                    "info".to_string()
                },
            };

            self.database.record_performance_gate(&cpu_gate)?;
            gate_results.push(cpu_gate);

            // Memory usage gate
            let memory_gate = PerformanceGateRecord {
                id: None,
                timestamp: Utc::now(),
                gate_name: "memory_usage_limit".to_string(),
                gate_type: "threshold".to_string(),
                threshold_value: thresholds.max_memory_mb,
                actual_value: metric.memory_usage,
                passed: metric.memory_usage <= thresholds.max_memory_mb,
                component: component.clone(),
                test_context: Some("production_monitoring".to_string()),
                severity: if metric.memory_usage > thresholds.max_memory_mb {
                    "critical".to_string()
                } else {
                    "info".to_string()
                },
            };

            self.database.record_performance_gate(&memory_gate)?;
            gate_results.push(memory_gate);
        }

        Ok(gate_results)
    }

    /// Get system health summary
    pub fn get_system_health(&self) -> anyhow::Result<SystemHealthRecord> {
        let uptime = self.start_time.elapsed().as_secs();
        let metrics = self.component_metrics.read().unwrap();

        let total_errors: u64 = metrics.values().map(|m| m.error_count).sum();
        let total_warnings: u64 = metrics.values().map(|m| m.warning_count).sum();
        let avg_cpu: f64 = if !metrics.is_empty() {
            metrics.values().map(|m| m.cpu_usage).sum::<f64>() / metrics.len() as f64
        } else {
            0.0
        };
        let avg_memory: f64 = if !metrics.is_empty() {
            metrics.values().map(|m| m.memory_usage).sum::<f64>() / metrics.len() as f64
        } else {
            0.0
        };

        let health = SystemHealthRecord {
            id: None,
            timestamp: Utc::now(),
            component: "system_overall".to_string(),
            status: if total_errors == 0 {
                "healthy".to_string()
            } else {
                "degraded".to_string()
            },
            uptime_seconds: Some(uptime as i64),
            error_count: total_errors as i32,
            warning_count: total_warnings as i32,
            last_error_message: None,
            last_error_timestamp: None,
            memory_usage_mb: Some(avg_memory),
            cpu_usage_percent: Some(avg_cpu),
            disk_usage_mb: None,
        };

        self.database.record_system_health(&health)?;
        Ok(health)
    }

    /// Increment threats detected with labels
    pub fn increment_threats_detected_with_labels(&self, engine_type: &str, category: &str) {
        log::debug!(
            "Incrementing threats detected: engine={}, category={}",
            engine_type,
            category
        );
        // This would typically increment threat detection counters
    }

    /// Update behavior score
    pub fn update_behavior_score(&self, score: f64) {
        log::debug!("Updating behavior score: {}", score);
        // This would typically update behavioral analysis scores
    }

    /// Update model accuracy
    pub fn update_model_accuracy(&self, accuracy: f64) {
        log::debug!("Updating model accuracy: {}", accuracy);
        // This would typically update ML model accuracy metrics
    }

    /// Record YARA scan duration
    pub fn record_yara_scan_duration(&self, duration: f64) {
        log::debug!("Recording YARA scan duration: {:.3}s", duration);
        // This would typically record YARA scanning performance metrics
    }

    /// Increment threats detected counter
    pub fn increment_threats_detected(&self) {
        log::debug!("Incrementing threats detected counter");
        // This would typically increment the total threats detected counter
    }

    /// Increment files scanned counter
    pub fn increment_files_scanned(&self) {
        log::debug!("Incrementing files scanned counter");
        // This would typically increment the total files scanned counter
    }

    /// Increment files scanned counter with category
    pub fn inc_files_scanned(&self, category: &str) {
        log::debug!(
            "Incrementing files scanned counter for category: {}",
            category
        );
        // This would typically increment the files scanned counter for a specific category
    }

    /// Increment compile error counter for a specific file
    pub fn inc_compile_error_for(&self, filename: &str) {
        log::debug!("Incrementing compile error counter for file: {}", filename);
        // This would typically increment the compile error counter for a specific file
    }

    /// Update mean time to detection in seconds
    pub fn update_mttd_seconds(&self, mttd_seconds: f64) {
        log::debug!("Updating MTTD to {} seconds", mttd_seconds);
        // This would typically update the mean time to detection metric
    }

    /// Record a counter metric
    pub fn record_counter(&self, name: &str, value: f64) {
        log::debug!("Recording counter {}: {}", name, value);
        // This would typically record counter metrics
    }

    /// Set the number of rules loaded
    pub fn set_rules_loaded(&self, count: i64) {
        log::debug!("Setting rules loaded count: {}", count);
        // This would typically set the rules loaded counter
    }

    /// Record a histogram metric
    pub fn record_histogram(&self, name: &str, value: f64, labels: &[(&str, &str)]) {
        log::debug!(
            "Recording histogram {}: {} with labels: {:?}",
            name,
            value,
            labels
        );
        // This would typically record histogram metrics
    }

    /// Record a gauge metric
    pub fn record_gauge(&self, name: &str, value: f64) {
        log::debug!("Recording gauge {}: {}", name, value);
        // This would typically record gauge metrics
    }

    /// Increment registry modifications counter
    pub fn increment_registry_modifications(&self, operation_type: &str) {
        log::debug!("Incrementing registry modifications counter: {}", operation_type);
        // This would typically increment the registry modifications counter
    }

    /// Increment sandbox timeouts counter
    pub fn increment_sandbox_timeouts(&self) {
        log::debug!("Incrementing sandbox timeouts counter");
        // This would typically increment the sandbox timeouts counter
    }

    /// Increment sandbox completions counter
    pub fn increment_sandbox_completions(&self) {
        log::debug!("Incrementing sandbox completions counter");
        // This would typically increment the sandbox completions counter
    }

    /// Increment sandbox submissions counter
    pub fn increment_sandbox_submissions(&self) {
        log::debug!("Incrementing sandbox submissions counter");
        // This would typically increment the sandbox submissions counter
    }

    /// Update files modified per second metric
    pub fn update_files_modified_per_second(&self, rate: f64) {
        log::debug!("Updating files modified per second: {:.2}", rate);
        // This would typically update the files modified per second metric
    }

    /// Set a gauge metric
    pub fn set_gauge(&self, name: &str, value: f64) {
        log::debug!("Setting gauge {}: {}", name, value);
        // This would typically set a gauge metric
    }

    /// Increment suspicious process chains counter
    pub fn increment_suspicious_process_chains(&self, operation_type: &str) {
        log::debug!("Incrementing suspicious process chains counter: {}", operation_type);
        // This would typically increment the suspicious process chains counter
    }

    /// Update process spawn rate metric
    pub fn update_process_spawn_rate(&self, rate: f64) {
        log::debug!("Updating process spawn rate: {:.2}", rate);
        // This would typically update the process spawn rate metric
    }

    /// Increment entropy changes counter
    pub fn increment_entropy_changes(&self, operation_type: &str) {
        log::debug!("Incrementing entropy changes counter: {}", operation_type);
        // This would typically increment the entropy changes counter
    }

    /// Get metrics as formatted text
    pub fn get_metrics_text(&self) -> String {
        let metrics = self.component_metrics.read().unwrap();
        let mut text = String::new();
        
        text.push_str("=== ERDPS Agent Metrics ===\n");
        text.push_str(&format!("Uptime: {:.2} seconds\n", self.start_time.elapsed().as_secs_f64()));
        
        for (component, metric) in metrics.iter() {
            text.push_str(&format!("\n[{}]\n", component));
            text.push_str(&format!("  CPU Usage: {:.2}%\n", metric.cpu_usage));
            text.push_str(&format!("  Memory Usage: {:.2} MB\n", metric.memory_usage));
            text.push_str(&format!("  Disk Usage: {:.2} MB\n", metric.disk_usage));
            if let Some(last_activity) = &metric.last_activity {
                text.push_str(&format!("  Last Activity: {}\n", last_activity.format("%Y-%m-%d %H:%M:%S UTC")));
            }
        }
        
        text
    }

    /// Generate production readiness report
    pub fn generate_readiness_report(
        &self,
        days: i64,
    ) -> anyhow::Result<ProductionReadinessReport> {
        let detection_summary = self.database.get_detection_summary(days)?;
        let gate_summary = self.database.get_performance_gate_summary(days)?;
        let system_health = self.get_system_health()?;

        let overall_pass_rate = if !gate_summary.is_empty() {
            gate_summary
                .iter()
                .map(|(_, _, _, _, rate)| rate)
                .sum::<f64>()
                / gate_summary.len() as f64
        } else {
            100.0
        };

        Ok(ProductionReadinessReport {
            timestamp: Utc::now(),
            overall_health_status: system_health.status.clone(),
            performance_gate_pass_rate: overall_pass_rate,
            total_detections: detection_summary.iter().map(|(_, _, count, _)| count).sum(),
            average_confidence: if !detection_summary.is_empty() {
                detection_summary
                    .iter()
                    .map(|(_, _, _, conf)| conf)
                    .sum::<f64>()
                    / detection_summary.len() as f64
            } else {
                0.0
            },
            uptime_seconds: system_health.uptime_seconds.unwrap_or(0),
            error_count: system_health.error_count,
            warning_count: system_health.warning_count,
            recommendations: generate_recommendations(&gate_summary, &system_health),
        })
    }
}

/// Production readiness report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProductionReadinessReport {
    pub timestamp: DateTime<Utc>,
    pub overall_health_status: String,
    pub performance_gate_pass_rate: f64,
    pub total_detections: i64,
    pub average_confidence: f64,
    pub uptime_seconds: i64,
    pub error_count: i32,
    pub warning_count: i32,
    pub recommendations: Vec<String>,
}

/// Generate recommendations based on metrics
fn generate_recommendations(
    gate_summary: &[(String, String, i64, i64, f64)],
    system_health: &SystemHealthRecord,
) -> Vec<String> {
    let mut recommendations = Vec::new();

    // Check performance gate failures
    for (gate_name, component, _total, _passed, pass_rate) in gate_summary {
        if *pass_rate < 95.0 {
            recommendations.push(format!(
                "Performance gate '{}' in component '{}' has low pass rate ({:.1}%). Consider optimization.",
                gate_name, component, pass_rate
            ));
        }
    }

    // Check system health
    if system_health.error_count > 0 {
        recommendations.push(format!(
            "System has {} errors. Review error logs and implement fixes.",
            system_health.error_count
        ));
    }

    if system_health.warning_count > 10 {
        recommendations.push(format!(
            "System has {} warnings. Consider addressing recurring warnings.",
            system_health.warning_count
        ));
    }

    if let Some(cpu) = system_health.cpu_usage_percent {
        if cpu > 80.0 {
            recommendations
                .push("High CPU usage detected. Consider performance optimization.".to_string());
        }
    }

    if let Some(memory) = system_health.memory_usage_mb {
        if memory > 500.0 {
            recommendations.push("High memory usage detected. Check for memory leaks.".to_string());
        }
    }

    if recommendations.is_empty() {
        recommendations.push("System is operating within acceptable parameters.".to_string());
    }

    recommendations
}

/// Initialize metrics system
pub async fn init_metrics() -> anyhow::Result<()> {
    // Initialize metrics collection
    log::info!("Initializing metrics system");
    Ok(())
}

/// Get global metrics instance
pub async fn get_metrics() -> Option<MetricsCollector> {
    // Return None for now - this would typically return a global instance
    None
}

/// Start metrics server
pub async fn start_metrics_server(port: u16) -> anyhow::Result<()> {
    log::info!("Starting metrics server on port {}", port);
    // This would typically start a web server for metrics endpoint
    Ok(())
}

/// Update system metrics
pub async fn update_system_metrics() -> anyhow::Result<()> {
    log::debug!("Updating system metrics");
    // This would typically collect and update system-wide metrics
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_metrics_collector() {
        let temp_file = NamedTempFile::new().unwrap();
        let db = MetricsDatabase::new(temp_file.path()).unwrap();
        db.initialize_schema().unwrap();

        let collector = MetricsCollector::new(db);

        // Test performance recording
        collector
            .record_performance("test_component", "cpu_usage", 15.5, "percent")
            .unwrap();
        collector
            .record_performance("test_component", "memory_usage", 128.0, "mb")
            .unwrap();

        // Test performance gates
        let thresholds = PerformanceThresholds::default();
        let gates = collector.check_performance_gates(&thresholds).unwrap();

        assert_eq!(gates.len(), 2); // CPU and memory gates
        assert!(!gates[0].passed); // CPU should fail (15.5% > 6%)
        assert!(gates[1].passed); // Memory should pass (128MB < 200MB)
    }

    #[test]
    fn test_readiness_report() {
        let temp_file = NamedTempFile::new().unwrap();
        let db = MetricsDatabase::new(temp_file.path()).unwrap();
        db.initialize_schema().unwrap();

        let collector = MetricsCollector::new(db);

        // Record some metrics
        collector
            .record_performance("engine", "cpu_usage", 3.0, "percent")
            .unwrap();
        collector
            .record_performance("engine", "memory_usage", 150.0, "mb")
            .unwrap();

        let report = collector.generate_readiness_report(7).unwrap();

        assert_eq!(report.overall_health_status, "healthy");
        assert!(report.performance_gate_pass_rate >= 0.0);
        assert!(!report.recommendations.is_empty());
    }
}
