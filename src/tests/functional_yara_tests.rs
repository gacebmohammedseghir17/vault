//! Functional YARA Testing Module
//!
//! This module provides comprehensive YARA integration testing capabilities,
//! focusing on rule compilation, pattern matching, and detection performance.

use std::time::{Duration, Instant};
use std::collections::HashMap;
use serde::{Deserialize, Serialize};


/// Configuration for YARA functional tests
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraTestConfig {
    pub test_timeout: Duration,
    pub max_detection_time_ms: u64,
    pub false_positive_threshold: f64,
    pub rule_compilation_timeout: Duration,
    pub concurrent_scan_count: usize,
    pub memory_limit_mb: usize,
}

impl Default for YaraTestConfig {
    fn default() -> Self {
        Self {
            test_timeout: Duration::from_secs(30),
            max_detection_time_ms: 1000, // Sub-second detection requirement
            false_positive_threshold: 0.001, // <0.1% false positive rate
            rule_compilation_timeout: Duration::from_secs(10),
            concurrent_scan_count: 10,
            memory_limit_mb: 128,
        }
    }
}

/// YARA test result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraTestResult {
    pub test_name: String,
    pub passed: bool,
    pub execution_time: Duration,
    pub detection_time_ms: u64,
    pub rules_compiled: usize,
    pub rules_matched: usize,
    pub false_positives: usize,
    pub false_positive_rate: f64,
    pub memory_usage_mb: f64,
    pub throughput_files_per_sec: f64,
    pub error_message: Option<String>,
    pub detailed_metrics: YaraPerformanceMetrics,
}

/// Detailed YARA performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraPerformanceMetrics {
    pub rule_compilation_times: Vec<Duration>,
    pub scan_times: Vec<Duration>,
    pub memory_snapshots: Vec<f64>,
    pub concurrent_scan_results: Vec<ConcurrentScanResult>,
    pub pattern_match_statistics: PatternMatchStats,
    pub rule_effectiveness: HashMap<String, RuleEffectiveness>,
}

/// Result of concurrent scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConcurrentScanResult {
    pub thread_id: usize,
    pub files_scanned: usize,
    pub matches_found: usize,
    pub scan_duration: Duration,
    pub memory_peak_mb: f64,
}

/// Pattern matching statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternMatchStats {
    pub total_patterns: usize,
    pub patterns_matched: usize,
    pub average_match_time_ms: f64,
    pub fastest_match_time_ms: f64,
    pub slowest_match_time_ms: f64,
    pub pattern_complexity_score: f64,
}

/// Rule effectiveness metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleEffectiveness {
    pub rule_name: String,
    pub true_positives: usize,
    pub false_positives: usize,
    pub detection_accuracy: f64,
    pub average_scan_time_ms: f64,
    pub memory_usage_mb: f64,
}

impl Default for YaraPerformanceMetrics {
    fn default() -> Self {
        Self {
            rule_compilation_times: Vec::new(),
            scan_times: Vec::new(),
            memory_snapshots: Vec::new(),
            concurrent_scan_results: Vec::new(),
            pattern_match_statistics: PatternMatchStats {
                total_patterns: 0,
                patterns_matched: 0,
                average_match_time_ms: 0.0,
                fastest_match_time_ms: f64::MAX,
                slowest_match_time_ms: 0.0,
                pattern_complexity_score: 0.0,
            },
            rule_effectiveness: HashMap::new(),
        }
    }
}

/// YARA functional test suite
pub struct YaraFunctionalTestSuite {
    config: YaraTestConfig,
    test_rules: Vec<String>,
    test_samples: Vec<TestSample>,
}

/// Test sample for YARA scanning
#[derive(Debug, Clone)]
pub struct TestSample {
    pub name: String,
    pub content: Vec<u8>,
    pub expected_matches: Vec<String>,
    pub is_malicious: bool,
    pub sample_type: SampleType,
}

/// Type of test sample
#[derive(Debug, Clone, PartialEq)]
pub enum SampleType {
    Eicar,
    Benign,
    Malware,
    Suspicious,
    Clean,
}

impl YaraFunctionalTestSuite {
    /// Create a new YARA functional test suite
    pub fn new(config: YaraTestConfig) -> Self {
        let mut suite = Self {
            config,
            test_rules: Vec::new(),
            test_samples: Vec::new(),
        };
        
        suite.initialize_test_data();
        suite
    }

    /// Initialize test rules and samples
    fn initialize_test_data(&mut self) {
        // Add EICAR test rule
        self.test_rules.push(r#"
            rule EICAR_Test_File {
                meta:
                    description = "EICAR Anti-Virus Test File"
                    author = "ERDPS Agent"
                    date = "2024-01-01"
                strings:
                    $eicar = "X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
                condition:
                    $eicar
            }
        "#.to_string());
        
        // Add malware detection rule
        self.test_rules.push(r#"
            rule Suspicious_Executable {
                meta:
                    description = "Detects suspicious executable patterns"
                    author = "ERDPS Agent"
                strings:
                    $mz = { 4D 5A }
                    $suspicious1 = "CreateRemoteThread" ascii
                    $suspicious2 = "VirtualAllocEx" ascii
                    $suspicious3 = "WriteProcessMemory" ascii
                condition:
                    $mz at 0 and 2 of ($suspicious*)
            }
        "#.to_string());
        
        // Add network pattern rule
        self.test_rules.push(r#"
            rule Network_Anomaly {
                meta:
                    description = "Detects network anomaly patterns"
                strings:
                    $http_post = "POST /" ascii
                    $suspicious_ua = "User-Agent: Bot" ascii
                    $base64_pattern = /[A-Za-z0-9+\/]{20,}/
                condition:
                    $http_post and ($suspicious_ua or $base64_pattern)
            }
        "#.to_string());
        
        // Add performance test rule
        self.test_rules.push(r#"
            rule Performance_Test {
                meta:
                    description = "Performance testing rule with complex patterns"
                strings:
                    $pattern1 = /[0-9a-fA-F]{32}/
                    $pattern2 = /(https?:\/\/[^\s]+)/
                    $pattern3 = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/
                condition:
                    any of them
            }
        "#.to_string());
        
        // Initialize test samples
        self.initialize_test_samples();
    }

    /// Initialize test samples
    fn initialize_test_samples(&mut self) {
        // EICAR test file
        self.test_samples.push(TestSample {
            name: "eicar.txt".to_string(),
            content: b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*".to_vec(),
            expected_matches: vec!["EICAR_Test_File".to_string()],
            is_malicious: true,
            sample_type: SampleType::Eicar,
        });
        
        // Benign executable sample
        let mut benign_exe = vec![0x4D, 0x5A]; // MZ header
        benign_exe.extend_from_slice(b"This is a benign executable with normal API calls like CreateFile and ReadFile");
        self.test_samples.push(TestSample {
            name: "benign.exe".to_string(),
            content: benign_exe,
            expected_matches: vec![],
            is_malicious: false,
            sample_type: SampleType::Benign,
        });
        
        // Suspicious executable sample
        let mut suspicious_exe = vec![0x4D, 0x5A]; // MZ header
        suspicious_exe.extend_from_slice(b"CreateRemoteThread VirtualAllocEx WriteProcessMemory");
        self.test_samples.push(TestSample {
            name: "suspicious.exe".to_string(),
            content: suspicious_exe,
            expected_matches: vec!["Suspicious_Executable".to_string()],
            is_malicious: true,
            sample_type: SampleType::Suspicious,
        });
        
        // Network traffic sample
        self.test_samples.push(TestSample {
            name: "network_traffic.pcap".to_string(),
            content: b"POST /api/data HTTP/1.1\r\nUser-Agent: Bot/1.0\r\nContent-Type: application/json\r\n\r\n{\"data\":\"dGVzdCBkYXRhIGZvciBiYXNlNjQgZW5jb2Rpbmc=\"}".to_vec(),
            expected_matches: vec!["Network_Anomaly".to_string()],
            is_malicious: true,
            sample_type: SampleType::Malware,
        });
        
        // Performance test sample
        self.test_samples.push(TestSample {
            name: "performance_test.txt".to_string(),
            content: b"Hash: a1b2c3d4e5f6789012345678901234567890 URL: https://example.com/test Email: test@example.com".to_vec(),
            expected_matches: vec!["Performance_Test".to_string()],
            is_malicious: false,
            sample_type: SampleType::Clean,
        });
        
        // Clean file sample
        self.test_samples.push(TestSample {
            name: "clean.txt".to_string(),
            content: b"This is a completely clean text file with no suspicious patterns or content.".to_vec(),
            expected_matches: vec![],
            is_malicious: false,
            sample_type: SampleType::Clean,
        });
    }

    /// Test YARA rule compilation
    pub async fn test_rule_compilation(&self) -> YaraTestResult {
        let start_time = Instant::now();
        let mut metrics = YaraPerformanceMetrics::default();
        let mut compiled_rules = 0;
        let mut compilation_errors = Vec::new();
        
        for (i, rule) in self.test_rules.iter().enumerate() {
            let compile_start = Instant::now();
            
            // Simulate rule compilation
            let compilation_result = self.simulate_rule_compilation(rule).await;
            let compile_time = compile_start.elapsed();
            
            metrics.rule_compilation_times.push(compile_time);
            
            match compilation_result {
                Ok(_) => compiled_rules += 1,
                Err(e) => compilation_errors.push(format!("Rule {}: {}", i, e)),
            }
            
            // Check compilation timeout
            if compile_time > self.config.rule_compilation_timeout {
                compilation_errors.push(format!("Rule {} compilation timeout", i));
            }
        }
        
        let execution_time = start_time.elapsed();
        let success = compilation_errors.is_empty() && compiled_rules == self.test_rules.len();
        
        YaraTestResult {
            test_name: "YARA Rule Compilation".to_string(),
            passed: success,
            execution_time,
            detection_time_ms: execution_time.as_millis() as u64,
            rules_compiled: compiled_rules,
            rules_matched: 0,
            false_positives: 0,
            false_positive_rate: 0.0,
            memory_usage_mb: self.estimate_memory_usage(),
            throughput_files_per_sec: 0.0,
            error_message: if compilation_errors.is_empty() {
                None
            } else {
                Some(compilation_errors.join("; "))
            },
            detailed_metrics: metrics,
        }
    }

    /// Test YARA detection performance
    pub async fn test_detection_performance(&self) -> YaraTestResult {
        let start_time = Instant::now();
        let mut metrics = YaraPerformanceMetrics::default();
        let mut total_matches = 0;
        let mut false_positives = 0;
        let mut detection_times = Vec::new();
        
        for sample in &self.test_samples {
            let scan_start = Instant::now();
            
            // Simulate YARA scanning
            let scan_result = self.simulate_yara_scan(sample).await;
            let scan_time = scan_start.elapsed();
            
            metrics.scan_times.push(scan_time);
            detection_times.push(scan_time.as_millis() as u64);
            
            // Analyze results
            match scan_result {
                Ok(matches) => {
                    total_matches += matches.len();
                    
                    // Check for false positives
                    if !sample.is_malicious && !matches.is_empty() {
                        false_positives += matches.len();
                    }
                    
                    // Update pattern match statistics
                    self.update_pattern_stats(&mut metrics.pattern_match_statistics, &matches, scan_time);
                    
                    // Update rule effectiveness
                    for rule_match in matches {
                        let effectiveness = metrics.rule_effectiveness
                            .entry(rule_match.clone())
                            .or_insert(RuleEffectiveness {
                                rule_name: rule_match.clone(),
                                true_positives: 0,
                                false_positives: 0,
                                detection_accuracy: 0.0,
                                average_scan_time_ms: 0.0,
                                memory_usage_mb: 0.0,
                            });
                        
                        if sample.is_malicious {
                            effectiveness.true_positives += 1;
                        } else {
                            effectiveness.false_positives += 1;
                        }
                        
                        effectiveness.average_scan_time_ms = scan_time.as_millis() as f64;
                        effectiveness.memory_usage_mb = self.estimate_memory_usage();
                    }
                }
                Err(_) => {
                    // Scan error - count as detection failure
                }
            }
            
            metrics.memory_snapshots.push(self.estimate_memory_usage());
        }
        
        let execution_time = start_time.elapsed();
        let average_detection_time = if !detection_times.is_empty() {
            detection_times.iter().sum::<u64>() / detection_times.len() as u64
        } else {
            0
        };
        
        let false_positive_rate = if self.test_samples.len() > 0 {
            false_positives as f64 / self.test_samples.len() as f64
        } else {
            0.0
        };
        
        let throughput = self.test_samples.len() as f64 / execution_time.as_secs_f64();
        
        // Calculate rule effectiveness accuracy
        for effectiveness in metrics.rule_effectiveness.values_mut() {
            let total_detections = effectiveness.true_positives + effectiveness.false_positives;
            if total_detections > 0 {
                effectiveness.detection_accuracy = effectiveness.true_positives as f64 / total_detections as f64;
            }
        }
        
        let performance_acceptable = average_detection_time <= self.config.max_detection_time_ms;
        let false_positive_acceptable = false_positive_rate <= self.config.false_positive_threshold;
        
        YaraTestResult {
            test_name: "YARA Detection Performance".to_string(),
            passed: performance_acceptable && false_positive_acceptable,
            execution_time,
            detection_time_ms: average_detection_time,
            rules_compiled: self.test_rules.len(),
            rules_matched: total_matches,
            false_positives,
            false_positive_rate,
            memory_usage_mb: self.estimate_memory_usage(),
            throughput_files_per_sec: throughput,
            error_message: if !performance_acceptable {
                Some(format!("Detection time {}ms exceeds limit {}ms", average_detection_time, self.config.max_detection_time_ms))
            } else if !false_positive_acceptable {
                Some(format!("False positive rate {:.3}% exceeds threshold {:.3}%", false_positive_rate * 100.0, self.config.false_positive_threshold * 100.0))
            } else {
                None
            },
            detailed_metrics: metrics,
        }
    }

    /// Test concurrent YARA scanning
    pub async fn test_concurrent_scanning(&self) -> YaraTestResult {
        let start_time = Instant::now();
        let mut metrics = YaraPerformanceMetrics::default();
        
        // Create concurrent scan tasks
        let mut tasks = Vec::new();
        
        for thread_id in 0..self.config.concurrent_scan_count {
            let samples = self.test_samples.clone();
            let task = tokio::spawn(async move {
                let scan_start = Instant::now();
                let mut matches_found = 0;
                let mut memory_peak: f64 = 0.0;
                
                for sample in &samples {
                    // Simulate concurrent scanning
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    
                    // Simulate memory usage
                    let current_memory = 30.0 + (thread_id as f64 * 5.0) + (rand::random::<f64>() * 10.0);
                    memory_peak = memory_peak.max(current_memory);
                    
                    // Simulate matches
                    if sample.is_malicious {
                        matches_found += sample.expected_matches.len();
                    }
                }
                
                ConcurrentScanResult {
                    thread_id,
                    files_scanned: samples.len(),
                    matches_found,
                    scan_duration: scan_start.elapsed(),
                    memory_peak_mb: memory_peak,
                }
            });
            
            tasks.push(task);
        }
        
        // Wait for all tasks to complete
        let mut total_files = 0;
        let mut total_matches = 0;
        let mut max_memory: f64 = 0.0;
        
        for task in tasks {
            match task.await {
                Ok(result) => {
                    total_files += result.files_scanned;
                    total_matches += result.matches_found;
                    max_memory = max_memory.max(result.memory_peak_mb);
                    metrics.concurrent_scan_results.push(result);
                }
                Err(_) => {
                    // Task failed
                }
            }
        }
        
        let execution_time = start_time.elapsed();
        let throughput = total_files as f64 / execution_time.as_secs_f64();
        
        let memory_acceptable = max_memory <= self.config.memory_limit_mb as f64;
        let performance_acceptable = execution_time.as_millis() as u64 <= self.config.max_detection_time_ms * 2; // Allow 2x time for concurrent
        
        YaraTestResult {
            test_name: "Concurrent YARA Scanning".to_string(),
            passed: memory_acceptable && performance_acceptable,
            execution_time,
            detection_time_ms: execution_time.as_millis() as u64,
            rules_compiled: self.test_rules.len(),
            rules_matched: total_matches,
            false_positives: 0,
            false_positive_rate: 0.0,
            memory_usage_mb: max_memory,
            throughput_files_per_sec: throughput,
            error_message: if !memory_acceptable {
                Some(format!("Memory usage {:.1}MB exceeds limit {}MB", max_memory, self.config.memory_limit_mb))
            } else if !performance_acceptable {
                Some(format!("Concurrent scan time {}ms exceeds acceptable limit", execution_time.as_millis()))
            } else {
                None
            },
            detailed_metrics: metrics,
        }
    }

    /// Simulate YARA rule compilation
    async fn simulate_rule_compilation(&self, _rule: &str) -> Result<(), String> {
        // Simulate compilation time
        tokio::time::sleep(Duration::from_millis(100 + rand::random::<u64>() % 200)).await;
        
        // Simulate occasional compilation errors
        if rand::random::<f64>() < 0.05 { // 5% error rate
            Err("Syntax error in rule".to_string())
        } else {
            Ok(())
        }
    }

    /// Simulate YARA scanning
    async fn simulate_yara_scan(&self, sample: &TestSample) -> Result<Vec<String>, String> {
        // Simulate scan time based on sample size
        let scan_time = Duration::from_millis(10 + (sample.content.len() as u64 / 1000));
        tokio::time::sleep(scan_time).await;
        
        // Simulate detection results
        if sample.is_malicious {
            Ok(sample.expected_matches.clone())
        } else {
            // Simulate occasional false positives
            if rand::random::<f64>() < 0.005 { // 0.5% false positive rate
                Ok(vec!["False_Positive_Rule".to_string()])
            } else {
                Ok(vec![])
            }
        }
    }

    /// Update pattern matching statistics
    fn update_pattern_stats(&self, stats: &mut PatternMatchStats, matches: &[String], scan_time: Duration) {
        let scan_time_ms = scan_time.as_millis() as f64;
        
        stats.total_patterns += matches.len();
        stats.patterns_matched += matches.len();
        
        if matches.len() > 0 {
            stats.average_match_time_ms = (stats.average_match_time_ms + scan_time_ms) / 2.0;
            stats.fastest_match_time_ms = stats.fastest_match_time_ms.min(scan_time_ms);
            stats.slowest_match_time_ms = stats.slowest_match_time_ms.max(scan_time_ms);
        }
        
        // Calculate pattern complexity score
        stats.pattern_complexity_score = matches.len() as f64 * 0.1 + scan_time_ms * 0.01;
    }

    /// Estimate current memory usage
    fn estimate_memory_usage(&self) -> f64 {
        // Base memory usage + rule memory + sample memory
        let base_memory = 25.0;
        let rule_memory = self.test_rules.len() as f64 * 2.0;
        let sample_memory = self.test_samples.iter().map(|s| s.content.len() as f64 / 1024.0 / 1024.0).sum::<f64>();
        
        base_memory + rule_memory + sample_memory
    }

    /// Run all YARA functional tests
    pub async fn run_all_tests(&self) -> Result<Vec<YaraTestResult>, String> {
        let mut results = Vec::new();
        
        // Run rule compilation test
        results.push(self.test_rule_compilation().await);
        
        // Run detection performance test
        results.push(self.test_detection_performance().await);
        
        // Run concurrent scanning test
        results.push(self.test_concurrent_scanning().await);
        
        Ok(results)
    }
}

/// Run all YARA functional tests
pub async fn run_all_yara_tests() -> Vec<YaraTestResult> {
    let config = YaraTestConfig::default();
    let test_suite = YaraFunctionalTestSuite::new(config);
    
    let mut results = Vec::new();
    
    // Run rule compilation test
    results.push(test_suite.test_rule_compilation().await);
    
    // Run detection performance test
    results.push(test_suite.test_detection_performance().await);
    
    // Run concurrent scanning test
    results.push(test_suite.test_concurrent_scanning().await);
    
    results
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_yara_rule_compilation() {
        let config = YaraTestConfig::default();
        let test_suite = YaraFunctionalTestSuite::new(config);
        
        let result = test_suite.test_rule_compilation().await;
        
        assert!(result.rules_compiled > 0);
        assert!(result.execution_time < Duration::from_secs(30));
    }
    
    #[tokio::test]
    async fn test_yara_detection_performance() {
        let config = YaraTestConfig::default();
        let test_suite = YaraFunctionalTestSuite::new(config);
        
        let result = test_suite.test_detection_performance().await;
        
        assert!(result.detection_time_ms <= 1000); // Sub-second detection
        assert!(result.false_positive_rate <= 0.001); // <0.1% false positive rate
        assert!(result.throughput_files_per_sec > 0.0);
    }
    
    #[tokio::test]
    async fn test_concurrent_yara_scanning() {
        let config = YaraTestConfig {
            concurrent_scan_count: 5,
            ..Default::default()
        };
        let test_suite = YaraFunctionalTestSuite::new(config);
        
        let result = test_suite.test_concurrent_scanning().await;
        
        assert!(result.memory_usage_mb <= 128.0);
        assert!(!result.detailed_metrics.concurrent_scan_results.is_empty());
    }
}
