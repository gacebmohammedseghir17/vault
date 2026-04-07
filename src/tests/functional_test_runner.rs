//! Functional Test Runner
//!
//! This module provides a comprehensive test runner for executing all functional
//! validation tests and generating detailed reports on system capabilities.

use std::collections::HashMap;
use std::time::{Duration, Instant};


use uuid::Uuid;

use crate::tests::{
    functional_yara_tests::{YaraFunctionalTestSuite, YaraTestConfig},
    end_to_end_tests::{EndToEndTestSuite, E2ETestConfig},
    performance_benchmarks::{PerformanceBenchmarkSuite, BenchmarkConfig},
    network_analysis_tests_functional::{NetworkAnalysisTestSuite, NetworkTestConfig},
    integration_tests_functional::{IntegrationTestSuite, IntegrationTestConfig},
    memory_performance_tests::{MemoryPerformanceTestSuite, MemoryPerformanceConfig},
};

/// Overall functional validation configuration
#[derive(Debug, Clone)]
pub struct FunctionalValidationConfig {
    pub yara_config: YaraTestConfig,
    pub e2e_config: E2ETestConfig,
    pub benchmark_config: BenchmarkConfig,
    pub network_config: NetworkTestConfig,
    pub integration_config: IntegrationTestConfig,
    pub memory_config: MemoryPerformanceConfig,
    pub enable_detailed_logging: bool,
    pub fail_fast: bool,
    pub parallel_execution: bool,
    pub test_timeout_secs: u64,
}

impl Default for FunctionalValidationConfig {
    fn default() -> Self {
        Self {
            yara_config: YaraTestConfig::default(),
            e2e_config: E2ETestConfig::default(),
            benchmark_config: BenchmarkConfig::default(),
            network_config: NetworkTestConfig::default(),
            integration_config: IntegrationTestConfig::default(),
            memory_config: MemoryPerformanceConfig::default(),
            enable_detailed_logging: true,
            fail_fast: false,
            parallel_execution: true,
            test_timeout_secs: 1800, // 30 minutes
        }
    }
}

/// Test suite execution status
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum TestSuiteStatus {
    NotStarted,
    Running,
    Passed,
    Failed,
    Timeout,
    Skipped,
}

/// Individual test suite result
#[derive(Debug, Clone)]
pub struct TestSuiteResult {
    pub suite_name: String,
    pub status: TestSuiteStatus,
    pub execution_time: Duration,
    pub tests_passed: usize,
    pub tests_failed: usize,
    pub tests_skipped: usize,
    pub error_messages: Vec<String>,
    pub performance_metrics: HashMap<String, f64>,
    pub recommendations: Vec<String>,
}

impl TestSuiteResult {
    pub fn new(suite_name: String) -> Self {
        Self {
            suite_name,
            status: TestSuiteStatus::NotStarted,
            execution_time: Duration::default(),
            tests_passed: 0,
            tests_failed: 0,
            tests_skipped: 0,
            error_messages: Vec::new(),
            performance_metrics: HashMap::new(),
            recommendations: Vec::new(),
        }
    }
    
    pub fn total_tests(&self) -> usize {
        self.tests_passed + self.tests_failed + self.tests_skipped
    }
    
    pub fn success_rate(&self) -> f64 {
        if self.total_tests() > 0 {
            self.tests_passed as f64 / self.total_tests() as f64 * 100.0
        } else {
            0.0
        }
    }
}

/// Overall functional validation results
#[derive(Debug, Clone)]
pub struct FunctionalValidationResults {
    pub validation_id: String,

    pub start_time: Instant,
    pub total_duration: Duration,
    pub suite_results: Vec<TestSuiteResult>,
    pub overall_status: TestSuiteStatus,
    pub production_readiness_score: f64,
    pub critical_issues: Vec<String>,
    pub recommendations: Vec<String>,
    pub next_steps: Vec<String>,
}

impl FunctionalValidationResults {
    pub fn new() -> Self {
        Self {
            validation_id: Uuid::new_v4().to_string(),
            start_time: Instant::now(),
            total_duration: Duration::default(),
            suite_results: Vec::new(),
            overall_status: TestSuiteStatus::NotStarted,
            production_readiness_score: 0.0,
            critical_issues: Vec::new(),
            recommendations: Vec::new(),
            next_steps: Vec::new(),
        }
    }
    
    pub fn calculate_production_readiness_score(&mut self) {
        let mut total_score = 0.0;
        let mut weight_sum = 0.0;
        
        // Define weights for different test suites
        let weights = HashMap::from([
            ("YARA Integration", 20.0),
            ("End-to-End Workflow", 25.0),
            ("Performance Benchmarks", 20.0),
            ("Network Analysis", 15.0),
            ("Integration Tests", 10.0),
            ("Memory & Performance", 10.0),
        ]);
        
        for result in &self.suite_results {
            if let Some(&weight) = weights.get(result.suite_name.as_str()) {
                let suite_score = match result.status {
                    TestSuiteStatus::Passed => result.success_rate(),
                    TestSuiteStatus::Failed => result.success_rate() * 0.5, // Partial credit
                    _ => 0.0,
                };
                
                total_score += suite_score * weight;
                weight_sum += weight;
            }
        }
        
        self.production_readiness_score = if weight_sum > 0.0 {
            total_score / weight_sum
        } else {
            0.0
        };
    }
    
    pub fn analyze_critical_issues(&mut self) {
        self.critical_issues.clear();
        
        for result in &self.suite_results {
            match result.status {
                TestSuiteStatus::Failed => {
                    if result.success_rate() < 50.0 {
                        self.critical_issues.push(format!(
                            "CRITICAL: {} suite has <50% success rate ({:.1}%)",
                            result.suite_name, result.success_rate()
                        ));
                    }
                }
                TestSuiteStatus::Timeout => {
                    self.critical_issues.push(format!(
                        "CRITICAL: {} suite timed out - performance issues detected",
                        result.suite_name
                    ));
                }
                _ => {}
            }
            
            // Check for specific performance issues
            if let Some(&avg_scan_time) = result.performance_metrics.get("average_scan_time_ms") {
                if avg_scan_time > 1000.0 {
                    self.critical_issues.push(format!(
                        "CRITICAL: {} has slow scan times ({:.1}ms > 1000ms baseline)",
                        result.suite_name, avg_scan_time
                    ));
                }
            }
            
            if let Some(&error_rate) = result.performance_metrics.get("error_rate_percent") {
                if error_rate > 0.1 {
                    self.critical_issues.push(format!(
                        "CRITICAL: {} has high error rate ({:.3}% > 0.1% target)",
                        result.suite_name, error_rate
                    ));
                }
            }
        }
    }
    
    pub fn generate_recommendations(&mut self) {
        self.recommendations.clear();
        
        // Collect recommendations from all test suites
        for result in &self.suite_results {
            self.recommendations.extend(result.recommendations.clone());
        }
        
        // Add overall recommendations based on production readiness score
        if self.production_readiness_score < 70.0 {
            self.recommendations.push("System requires significant improvements before production deployment".to_string());
            self.recommendations.push("Focus on fixing critical test failures and performance issues".to_string());
        } else if self.production_readiness_score < 85.0 {
            self.recommendations.push("System shows good progress but needs optimization for production".to_string());
            self.recommendations.push("Address remaining performance bottlenecks and edge cases".to_string());
        } else {
            self.recommendations.push("System demonstrates production-ready characteristics".to_string());
            self.recommendations.push("Proceed with final security review and deployment preparation".to_string());
        }
        
        // Remove duplicates
        self.recommendations.sort();
        self.recommendations.dedup();
    }
    
    pub fn generate_next_steps(&mut self) {
        self.next_steps.clear();
        
        if self.production_readiness_score < 50.0 {
            self.next_steps.push("Phase 1: Critical Issue Resolution (1-2 weeks)".to_string());
            self.next_steps.push("  • Fix all failing test suites".to_string());
            self.next_steps.push("  • Address performance bottlenecks".to_string());
            self.next_steps.push("  • Implement missing core functionality".to_string());
        } else if self.production_readiness_score < 80.0 {
            self.next_steps.push("Phase 2: Performance Optimization (1 week)".to_string());
            self.next_steps.push("  • Optimize scan performance to <1s baseline".to_string());
            self.next_steps.push("  • Reduce error rates to <0.1%".to_string());
            self.next_steps.push("  • Enhance enterprise scalability".to_string());
        } else {
            self.next_steps.push("Phase 3: Production Preparation (3-5 days)".to_string());
            self.next_steps.push("  • Security hardening review".to_string());
            self.next_steps.push("  • Final integration testing".to_string());
            self.next_steps.push("  • Deployment configuration".to_string());
            self.next_steps.push("  • Monitoring and alerting setup".to_string());
        }
        
        self.next_steps.push("\nContinuous Validation:".to_string());
        self.next_steps.push("  • Run functional tests daily".to_string());
        self.next_steps.push("  • Monitor performance metrics".to_string());
        self.next_steps.push("  • Update malware signatures regularly".to_string());
    }
    
    pub fn generate_comprehensive_report(&self) -> String {
        let passed_suites = self.suite_results.iter().filter(|r| r.status == TestSuiteStatus::Passed).count();
        let failed_suites = self.suite_results.iter().filter(|r| r.status == TestSuiteStatus::Failed).count();
        let total_tests_passed: usize = self.suite_results.iter().map(|r| r.tests_passed).sum();
        let total_tests_failed: usize = self.suite_results.iter().map(|r| r.tests_failed).sum();
        let total_tests = total_tests_passed + total_tests_failed;
        
        let overall_success_rate = if total_tests > 0 {
            total_tests_passed as f64 / total_tests as f64 * 100.0
        } else {
            0.0
        };
        
        format!(
            "\n🚀 FUNCTIONAL VALIDATION COMPREHENSIVE REPORT\n\
             =============================================\n\
             \n📋 VALIDATION OVERVIEW:\n\
             • Validation ID: {}\n\
             • Total Duration: {:?}\n\
             • Test Suites: {} passed, {} failed, {} total\n\
             • Individual Tests: {} passed, {} failed, {} total\n\
             • Overall Success Rate: {:.1}%\n\
             • Production Readiness Score: {:.1}/100\n\
             \n🔍 TEST SUITE RESULTS:\n\
             {}\n\
             \n⚠️  CRITICAL ISSUES ({}):\n\
             {}\n\
             \n💡 RECOMMENDATIONS ({}):\n\
             {}\n\
             \n📋 NEXT STEPS:\n\
             {}\n\
             \n🎯 PRODUCTION READINESS ASSESSMENT:\n\
             {}\n\
             \n📊 DETAILED METRICS:\n\
             {}\n",
            self.validation_id,
            self.total_duration,
            passed_suites,
            failed_suites,
            self.suite_results.len(),
            total_tests_passed,
            total_tests_failed,
            total_tests,
            overall_success_rate,
            self.production_readiness_score,
            self.format_suite_results(),
            self.critical_issues.len(),
            if self.critical_issues.is_empty() {
                "   ✅ No critical issues detected".to_string()
            } else {
                self.critical_issues.iter()
                    .map(|issue| format!("   • {}", issue))
                    .collect::<Vec<_>>()
                    .join("\n")
            },
            self.recommendations.len(),
            self.recommendations.iter()
                .map(|rec| format!("   • {}", rec))
                .collect::<Vec<_>>()
                .join("\n"),
            self.next_steps.join("\n"),
            self.format_production_readiness_assessment(),
            self.format_detailed_metrics()
        )
    }
    
    fn format_suite_results(&self) -> String {
        self.suite_results.iter()
            .map(|result| {
                let status_icon = match result.status {
                    TestSuiteStatus::Passed => "✅",
                    TestSuiteStatus::Failed => "❌",
                    TestSuiteStatus::Timeout => "⏰",
                    TestSuiteStatus::Skipped => "⏭️",
                    _ => "❓",
                };
                
                format!(
                    "   {} {} - {:.1}% success ({}/{} tests) in {:?}",
                    status_icon,
                    result.suite_name,
                    result.success_rate(),
                    result.tests_passed,
                    result.total_tests(),
                    result.execution_time
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
    
    fn format_production_readiness_assessment(&self) -> String {
        let assessment = if self.production_readiness_score >= 90.0 {
            "🟢 EXCELLENT - Ready for production deployment"
        } else if self.production_readiness_score >= 80.0 {
            "🟡 GOOD - Minor optimizations needed before production"
        } else if self.production_readiness_score >= 65.0 {
            "🟠 FAIR - Significant improvements required"
        } else if self.production_readiness_score >= 50.0 {
            "🔴 POOR - Major issues must be resolved"
        } else {
            "🚫 CRITICAL - System not functional, extensive work required"
        };
        
        format!(
            "Score: {:.1}/100 - {}\n\
             \n🎯 MILESTONE PROGRESS:\n\
             • Compilation: ✅ Complete (100%)\n\
             • YARA Integration: {} ({:.0}%)\n\
             • Network Analysis: {} ({:.0}%)\n\
             • Performance: {} ({:.0}%)\n\
             • Integration: {} ({:.0}%)\n\
             • Memory Management: {} ({:.0}%)",
            self.production_readiness_score,
            assessment,
            self.get_milestone_status("YARA Integration"),
            self.get_milestone_score("YARA Integration"),
            self.get_milestone_status("Network Analysis"),
            self.get_milestone_score("Network Analysis"),
            self.get_milestone_status("Performance Benchmarks"),
            self.get_milestone_score("Performance Benchmarks"),
            self.get_milestone_status("Integration Tests"),
            self.get_milestone_score("Integration Tests"),
            self.get_milestone_status("Memory & Performance"),
            self.get_milestone_score("Memory & Performance")
        )
    }
    
    fn get_milestone_status(&self, suite_name: &str) -> &str {
        self.suite_results.iter()
            .find(|r| r.suite_name == suite_name)
            .map(|r| match r.status {
                TestSuiteStatus::Passed => "✅ Complete",
                TestSuiteStatus::Failed => "❌ Failed",
                TestSuiteStatus::Running => "🔄 Running",
                _ => "⏸️ Pending",
            })
            .unwrap_or("❓ Unknown")
    }
    
    fn get_milestone_score(&self, suite_name: &str) -> f64 {
        self.suite_results.iter()
            .find(|r| r.suite_name == suite_name)
            .map(|r| r.success_rate())
            .unwrap_or(0.0)
    }
    
    fn format_detailed_metrics(&self) -> String {
        let mut metrics_summary = Vec::new();
        
        for result in &self.suite_results {
            if !result.performance_metrics.is_empty() {
                let suite_metrics = result.performance_metrics.iter()
                    .map(|(key, value)| format!("     • {}: {:.2}", key, value))
                    .collect::<Vec<_>>()
                    .join("\n");
                
                metrics_summary.push(format!("   {}:\n{}", result.suite_name, suite_metrics));
            }
        }
        
        if metrics_summary.is_empty() {
            "   No detailed metrics available".to_string()
        } else {
            metrics_summary.join("\n\n")
        }
    }
}

/// Main functional test runner
pub struct FunctionalTestRunner {
    config: FunctionalValidationConfig,
}

impl FunctionalTestRunner {
    pub fn new(config: FunctionalValidationConfig) -> Self {
        Self { config }
    }
    
    /// Run all functional validation tests
    pub async fn run_comprehensive_validation(&self) -> Result<FunctionalValidationResults, Box<dyn std::error::Error>> {
        let mut results = FunctionalValidationResults::new();
        
        println!("🚀 Starting Comprehensive Functional Validation");
        println!("===============================================\n");
        println!("📋 Validation ID: {}", results.validation_id);
        println!("⏰ Start Time: {:?}\n", results.start_time);
        
        // Test Suite 1: YARA Integration
        println!("🧪 Running YARA Integration Tests...");
        let yara_result = self.run_yara_tests().await;
        results.suite_results.push(yara_result);
        
        if self.config.fail_fast && results.suite_results.last().unwrap().status == TestSuiteStatus::Failed {
            println!("❌ Fail-fast enabled: Stopping due to YARA test failure");
            return Ok(self.finalize_results(results));
        }
        
        // Test Suite 2: End-to-End Workflow
        println!("\n🔄 Running End-to-End Workflow Tests...");
        let e2e_result = self.run_e2e_tests().await;
        results.suite_results.push(e2e_result);
        
        if self.config.fail_fast && results.suite_results.last().unwrap().status == TestSuiteStatus::Failed {
            println!("❌ Fail-fast enabled: Stopping due to E2E test failure");
            return Ok(self.finalize_results(results));
        }
        
        // Test Suite 3: Performance Benchmarks
        println!("\n⚡ Running Performance Benchmark Tests...");
        let benchmark_result = self.run_benchmark_tests().await;
        results.suite_results.push(benchmark_result);
        
        // Test Suite 4: Network Analysis
        println!("\n🌐 Running Network Analysis Tests...");
        let network_result = self.run_network_tests().await;
        results.suite_results.push(network_result);
        
        // Test Suite 5: Integration Tests
        println!("\n🔗 Running Integration Tests...");
        let integration_result = self.run_integration_tests().await;
        results.suite_results.push(integration_result);
        
        // Test Suite 6: Memory & Performance
        println!("\n🧠 Running Memory & Performance Tests...");
        let memory_result = self.run_memory_tests().await;
        results.suite_results.push(memory_result);
        
        Ok(self.finalize_results(results))
    }
    
    pub async fn run_yara_tests(&self) -> TestSuiteResult {
        let mut result = TestSuiteResult::new("YARA Integration".to_string());
        let start_time = Instant::now();
        result.status = TestSuiteStatus::Running;
        
        let test_suite = YaraFunctionalTestSuite::new(self.config.yara_config.clone());
        match test_suite.run_all_tests().await {
            Ok(test_results) => {
                result.tests_passed += test_results.iter().filter(|r| r.passed).count();
                result.tests_failed += test_results.iter().filter(|r| !r.passed).count();
                
                // Store YARA-specific metrics
                let avg_scan_time: f64 = test_results.iter()
                    .map(|r| r.execution_time.as_millis() as f64)
                    .sum::<f64>() / test_results.len() as f64;
                result.performance_metrics.insert("average_scan_time_ms".to_string(), avg_scan_time);
                
                let detection_rate = test_results.iter().filter(|r| r.passed).count() as f64 / test_results.len() as f64 * 100.0;
                result.performance_metrics.insert("detection_rate_percent".to_string(), detection_rate);
                
                result.status = if result.tests_failed == 0 {
                    TestSuiteStatus::Passed
                } else {
                    TestSuiteStatus::Failed
                };
            }
            Err(e) => {
                result.status = TestSuiteStatus::Failed;
                result.error_messages.push(format!("YARA test execution failed: {}", e));
            }
        }
        
        result.execution_time = start_time.elapsed();
        result
    }
    
    pub async fn run_e2e_tests(&self) -> TestSuiteResult {
        let mut result = TestSuiteResult::new("End-to-End Workflow".to_string());
        let start_time = Instant::now();
        result.status = TestSuiteStatus::Running;
        
        let test_suite = EndToEndTestSuite::new(self.config.e2e_config.clone());
        let test_results = test_suite.run_comprehensive_tests().await;
        result.tests_passed += test_results.iter().filter(|r| r.passed).count();
        result.tests_failed += test_results.iter().filter(|r| !r.passed).count();
        
        result.status = if result.tests_failed == 0 {
            TestSuiteStatus::Passed
        } else {
            TestSuiteStatus::Failed
        };
        
        result.execution_time = start_time.elapsed();
        result
    }
    
    pub async fn run_benchmark_tests(&self) -> TestSuiteResult {
        let mut result = TestSuiteResult::new("Performance Benchmarks".to_string());
        let start_time = Instant::now();
        result.status = TestSuiteStatus::Running;
        
        let mut benchmark = PerformanceBenchmarkSuite::new(self.config.benchmark_config.clone());
         let benchmark_results = benchmark.run_all_benchmarks().await;
         result.tests_passed += benchmark_results.iter().filter(|r| r.passed).count();
         result.tests_failed += benchmark_results.iter().filter(|r| !r.passed).count();
        
        // Store performance metrics from benchmark results
        for bench_result in &benchmark_results {
            result.performance_metrics.insert("average_detection_time_ms".to_string(), bench_result.average_latency_ms);
            result.performance_metrics.insert("throughput_files_per_sec".to_string(), bench_result.throughput_ops_per_sec);
        }
        
        result.status = if result.tests_failed == 0 {
            TestSuiteStatus::Passed
        } else {
            TestSuiteStatus::Failed
        };
        
        result.execution_time = start_time.elapsed();
        result
    }
    
    pub async fn run_network_tests(&self) -> TestSuiteResult {
        let mut result = TestSuiteResult::new("Network Analysis".to_string());
        let start_time = Instant::now();
        result.status = TestSuiteStatus::Running;
        
        let test_suite = match NetworkAnalysisTestSuite::new(self.config.network_config.clone()).await {
            Ok(suite) => suite,
            Err(e) => {
                result.status = TestSuiteStatus::Failed;
                result.error_messages.push(format!("Failed to create network test suite: {}", e));
                result.execution_time = start_time.elapsed();
                return result;
            }
        };
        let network_results = test_suite.run_all_tests().await;
        result.tests_passed += network_results.iter().filter(|r| r.passed).count();
        result.tests_failed += network_results.iter().filter(|r| !r.passed).count();
        
        result.status = if result.tests_failed == 0 {
            TestSuiteStatus::Passed
        } else {
            TestSuiteStatus::Failed
        };
        
        result.execution_time = start_time.elapsed();
        result
    }
    
    pub async fn run_integration_tests(&self) -> TestSuiteResult {
        let mut result = TestSuiteResult::new("Integration Tests".to_string());
        let start_time = Instant::now();
        result.status = TestSuiteStatus::Running;
        
        let test_suite = match IntegrationTestSuite::new(self.config.integration_config.clone()).await {
            Ok(suite) => suite,
            Err(e) => {
                result.status = TestSuiteStatus::Failed;
                result.error_messages.push(format!("Failed to create integration test suite: {}", e));
                result.execution_time = start_time.elapsed();
                return result;
            }
        };
        let integration_results = test_suite.run_all_tests().await;
        result.tests_passed += integration_results.iter().filter(|r| r.passed).count();
        result.tests_failed += integration_results.iter().filter(|r| !r.passed).count();
        
        result.status = if result.tests_failed == 0 {
            TestSuiteStatus::Passed
        } else {
            TestSuiteStatus::Failed
        };
        
        result.execution_time = start_time.elapsed();
        result
    }
    
    pub async fn run_memory_tests(&self) -> TestSuiteResult {
        let mut result = TestSuiteResult::new("Memory & Performance".to_string());
        let start_time = Instant::now();
        result.status = TestSuiteStatus::Running;
        
        let mut memory_suite = MemoryPerformanceTestSuite::new(self.config.memory_config.clone());
        let memory_results = memory_suite.run_all_tests().await;
        result.tests_passed += memory_results.iter().filter(|r| r.passed).count();
        result.tests_failed += memory_results.iter().filter(|r| !r.passed).count();
        
        result.status = if result.tests_failed == 0 {
            TestSuiteStatus::Passed
        } else {
            TestSuiteStatus::Failed
        };
        
        result.execution_time = start_time.elapsed();
        result
    }
    
    pub fn finalize_results(&self, mut results: FunctionalValidationResults) -> FunctionalValidationResults {
        results.total_duration = results.start_time.elapsed();
        
        // Determine overall status
        let failed_suites = results.suite_results.iter().filter(|r| r.status == TestSuiteStatus::Failed).count();
        results.overall_status = if failed_suites == 0 {
            TestSuiteStatus::Passed
        } else {
            TestSuiteStatus::Failed
        };
        
        // Calculate production readiness score
        results.calculate_production_readiness_score();
        
        // Analyze issues and generate recommendations
        results.analyze_critical_issues();
        results.generate_recommendations();
        results.generate_next_steps();
        
        println!("\n{}", results.generate_comprehensive_report());
        
        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_functional_validation_config_default() {
        let config = FunctionalValidationConfig::default();
        
        assert!(config.enable_detailed_logging);
        assert!(!config.fail_fast);
        assert!(config.parallel_execution);
        assert_eq!(config.test_timeout_secs, 1800);
    }
    
    #[test]
    fn test_test_suite_result_creation() {
        let result = TestSuiteResult::new("Test Suite".to_string());
        
        assert_eq!(result.suite_name, "Test Suite");
        assert_eq!(result.status, TestSuiteStatus::NotStarted);
        assert_eq!(result.total_tests(), 0);
        assert_eq!(result.success_rate(), 0.0);
    }
    
    #[test]
    fn test_success_rate_calculation() {
        let mut result = TestSuiteResult::new("Test".to_string());
        result.tests_passed = 8;
        result.tests_failed = 2;
        
        assert_eq!(result.total_tests(), 10);
        assert_eq!(result.success_rate(), 80.0);
    }
    
    #[test]
    fn test_functional_validation_results() {
        let mut results = FunctionalValidationResults::new();
        
        // Add a test suite result
        let mut suite_result = TestSuiteResult::new("YARA Integration".to_string());
        suite_result.status = TestSuiteStatus::Passed;
        suite_result.tests_passed = 10;
        suite_result.tests_failed = 0;
        results.suite_results.push(suite_result);
        
        results.calculate_production_readiness_score();
        
        assert!(results.production_readiness_score > 0.0);
    }
    
    #[tokio::test]
    async fn test_functional_test_runner_creation() {
        let config = FunctionalValidationConfig::default();
        let runner = FunctionalTestRunner::new(config);
        
        // Test runner should be created successfully
        assert!(runner.config.enable_detailed_logging);
    }
}
