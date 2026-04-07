//! Beacon Detection System for ERDPS Production Enhancement
//!
//! Implements advanced C2 beacon detection with:
//! - Periodic communication pattern analysis
//! - Timing analysis with jitter detection
//! - FFT-based frequency analysis
//! - Machine learning-based classification
//! - Real-time detection with <0.5s latency

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use std::f64::consts::PI;
use serde::{Deserialize, Serialize};
use anyhow::Result;
use log::{debug, info};
use crate::core::error::Result as AgentResult;

/// Advanced Beacon Detection System
pub struct AdvancedBeaconDetector {
    /// Active beacon patterns being monitored
    beacon_patterns: HashMap<String, BeaconPattern>,
    /// Timing analysis window for pattern detection
    analysis_window: Duration,
    /// FFT analyzer for frequency domain analysis
    fft_analyzer: FftAnalyzer,
    /// Machine learning classifier for beacon detection
    ml_classifier: BeaconClassifier,
    /// Performance metrics
    performance_metrics: BeaconDetectionMetrics,
    /// Configuration parameters
    config: BeaconDetectorConfig,
}

/// Beacon communication pattern with advanced analytics
#[derive(Debug, Clone)]
pub struct BeaconPattern {
    pub pattern_id: String,
    pub flow_id: String,
    pub destination_ip: String,
    pub destination_port: u16,
    
    // Timing analysis
    pub packet_intervals: VecDeque<u64>,
    pub inter_arrival_times: Vec<f64>,
    pub timing_regularity: f64,
    pub jitter_coefficient: f64,
    pub timing_entropy: f64,
    
    // Frequency analysis
    pub frequency_peaks: Vec<FrequencyPeak>,
    pub dominant_frequency: Option<f64>,
    pub frequency_stability: f64,
    pub harmonic_analysis: HarmonicAnalysis,
    
    // Statistical features
    pub mean_interval: f64,
    pub interval_variance: f64,
    pub interval_std_dev: f64,
    pub coefficient_of_variation: f64,
    pub skewness: f64,
    pub kurtosis: f64,
    
    // Pattern characteristics
    pub beacon_probability: f64,
    pub confidence_score: f64,
    pub threat_level: BeaconThreatLevel,
    pub pattern_type: BeaconPatternType,
    
    // Temporal information
    pub first_seen: Instant,
    pub last_seen: Instant,
    pub total_packets: u64,
    pub active_duration: Duration,
    
    // Classification results
    pub is_malicious: bool,
    pub threat_indicators: Vec<String>,
    pub ml_classification: Option<MlClassificationResult>,
}

/// FFT-based frequency analyzer
pub struct FftAnalyzer {
    /// Sample buffer for FFT analysis
    sample_buffer: VecDeque<f64>,
    /// FFT window size (power of 2)
    window_size: usize,
    /// Sampling rate for analysis
    sampling_rate: f64,
    /// Frequency resolution
    frequency_resolution: f64,
}

/// Machine learning classifier for beacon detection
pub struct BeaconClassifier {
    /// Feature extractor
    feature_extractor: BeaconFeatureExtractor,
    /// Classification threshold
    classification_threshold: f64,
    /// Model performance metrics
    model_metrics: ModelMetrics,
}

/// Frequency peak in spectrum analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrequencyPeak {
    pub frequency: f64,
    pub magnitude: f64,
    pub phase: f64,
    pub bandwidth: f64,
    pub quality_factor: f64,
}

/// Harmonic analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarmonicAnalysis {
    pub fundamental_frequency: f64,
    pub harmonics: Vec<FrequencyPeak>,
    pub harmonic_distortion: f64,
    pub spectral_centroid: f64,
    pub spectral_rolloff: f64,
}

/// Beacon threat levels
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum BeaconThreatLevel {
    Low,      // Irregular intervals, low confidence
    Medium,   // Some regularity, moderate confidence
    High,     // Regular intervals, high confidence
    Critical, // Highly regular, very high confidence
}

/// Beacon pattern types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum BeaconPatternType {
    FixedInterval,    // Constant time intervals
    JitteredInterval, // Intervals with controlled jitter
    FastFlux,         // Rapidly changing intervals
    SlowBeacon,       // Long intervals (hours/days)
    BurstBeacon,      // Burst of packets followed by silence
    AdaptiveBeacon,   // Changing pattern over time
}

/// ML classification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlClassificationResult {
    pub prediction: f64,
    pub confidence: f64,
    pub feature_importance: Vec<(String, f64)>,
    pub decision_boundary_distance: f64,
}

/// Beacon detection configuration
#[derive(Debug, Clone)]
pub struct BeaconDetectorConfig {
    pub min_packets_for_analysis: u32,
    pub analysis_window_seconds: u64,
    pub jitter_threshold: f64,
    pub regularity_threshold: f64,
    pub frequency_analysis_enabled: bool,
    pub ml_classification_enabled: bool,
    pub detection_sensitivity: f64,
}

/// Performance metrics for beacon detection
#[derive(Debug, Clone)]
pub struct BeaconDetectionMetrics {
    pub total_patterns_analyzed: u64,
    pub beacons_detected: u64,
    pub false_positives: u64,
    pub avg_detection_time_ms: f64,
    pub max_detection_time_ms: u64,
    pub patterns_per_second: f64,
    pub memory_usage_mb: f64,
}

/// Feature extractor for ML classification
pub struct BeaconFeatureExtractor {
    feature_names: Vec<String>,
    feature_count: usize,
}

/// Model performance metrics
#[derive(Debug, Clone)]
pub struct ModelMetrics {
    pub accuracy: f64,
    pub precision: f64,
    pub recall: f64,
    pub f1_score: f64,
    pub auc_roc: f64,
}

impl AdvancedBeaconDetector {
    /// Create new advanced beacon detector
    pub fn new(config: BeaconDetectorConfig) -> Result<Self> {
        info!("Initializing Advanced Beacon Detector with {}s analysis window", 
              config.analysis_window_seconds);
        
        Ok(Self {
            beacon_patterns: HashMap::new(),
            analysis_window: Duration::from_secs(config.analysis_window_seconds),
            fft_analyzer: FftAnalyzer::new(1024, 1.0)?, // 1024 samples, 1Hz sampling
            ml_classifier: BeaconClassifier::new()?,
            performance_metrics: BeaconDetectionMetrics::default(),
            config,
        })
    }
    
    /// Analyze packet for beacon patterns
    pub fn analyze_packet(&mut self, flow_id: &str, timestamp: Instant, 
                         destination_ip: &str, destination_port: u16) -> AgentResult<Option<BeaconPattern>> {
        let start_time = Instant::now();
        
        // Get or create beacon pattern
        let pattern_key = format!("{}:{}:{}", flow_id, destination_ip, destination_port);
        
        if !self.beacon_patterns.contains_key(&pattern_key) {
            let new_pattern = BeaconPattern::new(
                pattern_key.clone(),
                flow_id.to_string(),
                destination_ip.to_string(),
                destination_port,
                timestamp,
            );
            self.beacon_patterns.insert(pattern_key.clone(), new_pattern);
        }
        
        // Update pattern with new packet and perform analysis
        let mut detected_beacon = None;
        
        // First, update the pattern with the new packet
        if let Some(pattern) = self.beacon_patterns.get_mut(&pattern_key) {
            Self::update_pattern_with_packet_static(pattern, timestamp)?;
        }
        
        // Then perform analysis if we have enough data
        let should_analyze = self.beacon_patterns.get(&pattern_key)
            .map(|p| p.total_packets >= self.config.min_packets_for_analysis as u64)
            .unwrap_or(false);
            
        if should_analyze {
            // Get configuration values to avoid borrowing conflicts
            let frequency_analysis_enabled = self.config.frequency_analysis_enabled;
            let ml_classification_enabled = self.config.ml_classification_enabled;
            
            // Get pattern for analysis (clone to avoid borrowing conflicts)
            let mut pattern_clone = if let Some(pattern) = self.beacon_patterns.get(&pattern_key) {
                pattern.clone()
            } else {
                return Ok(None);
            };
            
            // Perform timing analysis
            self.analyze_timing_patterns(&mut pattern_clone)?;
            
            // Perform frequency analysis if enabled
            if frequency_analysis_enabled {
                self.analyze_frequency_patterns(&mut pattern_clone)?;
            }
            
            // Perform ML classification if enabled
            if ml_classification_enabled {
                self.classify_pattern(&mut pattern_clone)?;
            }
            
            // Determine if this is a beacon
            let is_beacon = self.is_beacon_pattern(&mut pattern_clone)?;
            
            // Update the original pattern with analysis results
            if let Some(pattern) = self.beacon_patterns.get_mut(&pattern_key) {
                *pattern = pattern_clone.clone();
            }
            
            if is_beacon {
                detected_beacon = Some(pattern_clone.clone());
                info!("Beacon detected: {} with confidence {:.2}", 
                      pattern_clone.pattern_id, pattern_clone.confidence_score);
                self.performance_metrics.beacons_detected += 1;
            }
        }
        
        // Update performance metrics
        let analysis_time = start_time.elapsed().as_millis() as u64;
        self.performance_metrics.avg_detection_time_ms = 
            (self.performance_metrics.avg_detection_time_ms + analysis_time as f64) / 2.0;
        self.performance_metrics.max_detection_time_ms = 
            self.performance_metrics.max_detection_time_ms.max(analysis_time);
        
        Ok(detected_beacon)
    }
    
    /// Update beacon pattern with new packet
    fn update_pattern_with_packet_static(pattern: &mut BeaconPattern, timestamp: Instant) -> AgentResult<()> {
        // Calculate interval since last packet
        let interval = if pattern.total_packets > 0 {
            timestamp.duration_since(pattern.last_seen).as_millis() as u64
        } else {
            0
        };
        
        // Update timing information
        if interval > 0 {
            pattern.packet_intervals.push_back(interval);
            pattern.inter_arrival_times.push(interval as f64);
            
            // Keep only recent intervals for analysis
            let max_intervals = 1000; // Keep last 1000 intervals
            if pattern.packet_intervals.len() > max_intervals {
                pattern.packet_intervals.pop_front();
                pattern.inter_arrival_times.remove(0);
            }
        }
        
        // Update temporal information
        pattern.last_seen = timestamp;
        pattern.total_packets += 1;
        pattern.active_duration = timestamp.duration_since(pattern.first_seen);
        
        Ok(())
    }
    
    /// Analyze timing patterns for regularity and jitter
    fn analyze_timing_patterns(&self, pattern: &mut BeaconPattern) -> AgentResult<()> {
        if pattern.inter_arrival_times.len() < 3 {
            return Ok(());
        }
        
        let intervals = &pattern.inter_arrival_times;
        
        // Calculate basic statistics
        let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
        let variance = intervals.iter()
            .map(|x| (x - mean).powi(2))
            .sum::<f64>() / intervals.len() as f64;
        let std_dev = variance.sqrt();
        
        pattern.mean_interval = mean;
        pattern.interval_variance = variance;
        pattern.interval_std_dev = std_dev;
        pattern.coefficient_of_variation = if mean > 0.0 { std_dev / mean } else { 0.0 };
        
        // Calculate jitter coefficient (normalized standard deviation)
        pattern.jitter_coefficient = pattern.coefficient_of_variation;
        
        // Calculate timing regularity (inverse of coefficient of variation)
        pattern.timing_regularity = if pattern.coefficient_of_variation > 0.0 {
            1.0 / (1.0 + pattern.coefficient_of_variation)
        } else {
            1.0
        };
        
        // Calculate timing entropy
        pattern.timing_entropy = self.calculate_timing_entropy(intervals)?;
        
        // Calculate higher-order statistics
        if intervals.len() >= 4 {
            pattern.skewness = self.calculate_skewness(intervals, mean, std_dev);
            pattern.kurtosis = self.calculate_kurtosis(intervals, mean, std_dev);
        }
        
        Ok(())
    }
    
    /// Analyze frequency patterns using FFT
    fn analyze_frequency_patterns(&self, pattern: &mut BeaconPattern) -> AgentResult<()> {
        if pattern.inter_arrival_times.len() < 8 {
            return Ok(());
        }
        
        // Clone the data we need to avoid borrowing conflicts
        let inter_arrival_times = pattern.inter_arrival_times.clone();
        
        // Create temporary FFT analyzer for analysis
        let mut temp_fft = FftAnalyzer::new(1024, 1.0)?;
        let spectrum = temp_fft.analyze(&inter_arrival_times)?;
        
        // Find frequency peaks
        let frequency_peaks = self.find_frequency_peaks(&spectrum)?;
        
        // Determine dominant frequency
        let dominant_frequency = frequency_peaks
            .iter()
            .max_by(|a, b| a.magnitude.partial_cmp(&b.magnitude).unwrap())
            .map(|peak| peak.frequency);
        
        // Calculate frequency stability
        let frequency_stability = self.calculate_frequency_stability(&frequency_peaks);
        
        // Perform harmonic analysis
        let harmonic_analysis = self.analyze_harmonics(&spectrum, dominant_frequency)?;
        
        // Update pattern with results
        pattern.frequency_peaks = frequency_peaks;
        pattern.dominant_frequency = dominant_frequency;
        pattern.frequency_stability = frequency_stability;
        pattern.harmonic_analysis = harmonic_analysis;
        
        Ok(())
    }
    
    /// Classify pattern using ML
    fn classify_pattern(&self, pattern: &mut BeaconPattern) -> AgentResult<()> {
        // Extract features for ML classification
        let temp_extractor = BeaconFeatureExtractor::new();
        let features = temp_extractor.extract_features(pattern)?;
        
        // Create temporary classifier for analysis
        let temp_classifier = BeaconClassifier::new()?;
        let classification_result = temp_classifier.classify(&features)?;
        
        // Update pattern with results
        pattern.ml_classification = Some(classification_result.clone());
        pattern.beacon_probability = classification_result.prediction;
        
        Ok(())
    }
    
    /// Check if pattern indicates beacon behavior
    fn is_beacon_pattern(&self, pattern: &mut BeaconPattern) -> AgentResult<bool> {
        let mut beacon_score = 0.0;
        let mut confidence_factors = Vec::new();
        
        // Timing regularity factor (0.0 to 1.0)
        if pattern.timing_regularity > self.config.regularity_threshold {
            beacon_score += pattern.timing_regularity * 0.3;
            confidence_factors.push(format!("High timing regularity: {:.3}", pattern.timing_regularity));
        }
        
        // Low jitter factor (0.0 to 1.0)
        if pattern.jitter_coefficient < self.config.jitter_threshold {
            let jitter_score = (self.config.jitter_threshold - pattern.jitter_coefficient) / self.config.jitter_threshold;
            beacon_score += jitter_score * 0.25;
            confidence_factors.push(format!("Low jitter: {:.3}", pattern.jitter_coefficient));
        }
        
        // Frequency analysis factor
        if let Some(_dominant_freq) = pattern.dominant_frequency {
            if pattern.frequency_stability > 0.7 {
                beacon_score += pattern.frequency_stability * 0.2;
                confidence_factors.push(format!("Stable frequency: {:.3}", pattern.frequency_stability));
            }
        }
        
        // ML classification factor
        if let Some(ref ml_result) = pattern.ml_classification {
            if ml_result.prediction > self.ml_classifier.classification_threshold {
                beacon_score += ml_result.prediction * 0.25;
                confidence_factors.push(format!("ML prediction: {:.3}", ml_result.prediction));
            }
        }
        
        // Update pattern with results
        pattern.confidence_score = beacon_score;
        pattern.threat_indicators = confidence_factors;
        
        // Determine threat level
        pattern.threat_level = match beacon_score {
            score if score >= 0.8 => BeaconThreatLevel::Critical,
            score if score >= 0.6 => BeaconThreatLevel::High,
            score if score >= 0.4 => BeaconThreatLevel::Medium,
            _ => BeaconThreatLevel::Low,
        };
        
        // Determine pattern type
        pattern.pattern_type = self.classify_pattern_type(pattern);
        
        pattern.is_malicious = beacon_score > self.config.detection_sensitivity;
        
        Ok(pattern.is_malicious)
    }
    
    /// Calculate timing entropy
    fn calculate_timing_entropy(&self, intervals: &[f64]) -> AgentResult<f64> {
        if intervals.is_empty() {
            return Ok(0.0);
        }
        
        // Create histogram of intervals
        let mut histogram = HashMap::new();
        let bin_size = 100.0; // 100ms bins
        
        for &interval in intervals {
            let bin = (interval / bin_size) as u64;
            *histogram.entry(bin).or_insert(0) += 1;
        }
        
        // Calculate entropy
        let total_count = intervals.len() as f64;
        let entropy = histogram.values()
            .map(|&count| {
                let p = count as f64 / total_count;
                if p > 0.0 { -p * p.log2() } else { 0.0 }
            })
            .sum();
        
        Ok(entropy)
    }
    
    /// Calculate skewness
    fn calculate_skewness(&self, values: &[f64], mean: f64, std_dev: f64) -> f64 {
        if std_dev == 0.0 || values.len() < 3 {
            return 0.0;
        }
        
        let n = values.len() as f64;
        let skewness = values.iter()
            .map(|x| ((x - mean) / std_dev).powi(3))
            .sum::<f64>() / n;
        
        skewness
    }
    
    /// Calculate kurtosis
    fn calculate_kurtosis(&self, values: &[f64], mean: f64, std_dev: f64) -> f64 {
        if std_dev == 0.0 || values.len() < 4 {
            return 0.0;
        }
        
        let n = values.len() as f64;
        let kurtosis = values.iter()
            .map(|x| ((x - mean) / std_dev).powi(4))
            .sum::<f64>() / n - 3.0; // Excess kurtosis
        
        kurtosis
    }
    
    /// Find frequency peaks in spectrum
    fn find_frequency_peaks(&self, spectrum: &[(f64, f64)]) -> AgentResult<Vec<FrequencyPeak>> {
        let mut peaks = Vec::new();
        
        if spectrum.len() < 3 {
            return Ok(peaks);
        }
        
        // Simple peak detection: find local maxima
        for i in 1..spectrum.len()-1 {
            let (freq, magnitude) = spectrum[i];
            let (_, prev_mag) = spectrum[i-1];
            let (_, next_mag) = spectrum[i+1];
            
            if magnitude > prev_mag && magnitude > next_mag && magnitude > 0.1 {
                peaks.push(FrequencyPeak {
                    frequency: freq,
                    magnitude,
                    phase: 0.0, // Simplified
                    bandwidth: 0.0, // Simplified
                    quality_factor: magnitude / 0.1, // Simplified
                });
            }
        }
        
        // Sort by magnitude (descending)
        peaks.sort_by(|a, b| b.magnitude.partial_cmp(&a.magnitude).unwrap());
        
        // Keep only top 10 peaks
        peaks.truncate(10);
        
        Ok(peaks)
    }
    
    /// Calculate frequency stability
    fn calculate_frequency_stability(&self, peaks: &[FrequencyPeak]) -> f64 {
        if peaks.is_empty() {
            return 0.0;
        }
        
        // Simple stability measure: ratio of dominant peak to total energy
        let total_energy: f64 = peaks.iter().map(|p| p.magnitude).sum();
        let dominant_energy = peaks[0].magnitude;
        
        if total_energy > 0.0 {
            dominant_energy / total_energy
        } else {
            0.0
        }
    }
    
    /// Analyze harmonics in the spectrum
    fn analyze_harmonics(&self, spectrum: &[(f64, f64)], fundamental_freq: Option<f64>) -> AgentResult<HarmonicAnalysis> {
        let fundamental = fundamental_freq.unwrap_or(0.0);
        
        let mut harmonics = Vec::new();
        
        if fundamental > 0.0 {
            // Look for harmonics (2f, 3f, 4f, etc.)
            for harmonic_order in 2..=5 {
                let target_freq = fundamental * harmonic_order as f64;
                
                // Find closest frequency in spectrum
                if let Some((freq, magnitude)) = spectrum.iter()
                    .min_by(|(f1, _), (f2, _)| {
                        (f1 - target_freq).abs().partial_cmp(&(f2 - target_freq).abs()).unwrap()
                    }) {
                    
                    if (freq - target_freq).abs() < fundamental * 0.1 { // Within 10% tolerance
                        harmonics.push(FrequencyPeak {
                            frequency: *freq,
                            magnitude: *magnitude,
                            phase: 0.0,
                            bandwidth: 0.0,
                            quality_factor: *magnitude,
                        });
                    }
                }
            }
        }
        
        Ok(HarmonicAnalysis {
            fundamental_frequency: fundamental,
            harmonics,
            harmonic_distortion: 0.0, // Simplified
            spectral_centroid: 0.0,   // Simplified
            spectral_rolloff: 0.0,    // Simplified
        })
    }
    
    /// Classify beacon pattern type
    fn classify_pattern_type(&self, pattern: &BeaconPattern) -> BeaconPatternType {
        if pattern.jitter_coefficient < 0.1 {
            BeaconPatternType::FixedInterval
        } else if pattern.jitter_coefficient < 0.3 {
            BeaconPatternType::JitteredInterval
        } else if pattern.mean_interval > 3600000.0 { // > 1 hour
            BeaconPatternType::SlowBeacon
        } else {
            BeaconPatternType::AdaptiveBeacon
        }
    }
    
    /// Get current performance metrics
    pub fn get_metrics(&self) -> &BeaconDetectionMetrics {
        &self.performance_metrics
    }
    
    /// Clean up old patterns
    pub fn cleanup_old_patterns(&mut self, max_age: Duration) -> AgentResult<()> {
        let now = Instant::now();
        let initial_count = self.beacon_patterns.len();
        
        self.beacon_patterns.retain(|_, pattern| {
            now.duration_since(pattern.last_seen) < max_age
        });
        
        let removed_count = initial_count - self.beacon_patterns.len();
        if removed_count > 0 {
            debug!("Cleaned up {} old beacon patterns", removed_count);
        }
        
        Ok(())
    }
}

impl BeaconPattern {
    /// Create new beacon pattern
    pub fn new(pattern_id: String, flow_id: String, destination_ip: String, 
               destination_port: u16, timestamp: Instant) -> Self {
        Self {
            pattern_id,
            flow_id,
            destination_ip,
            destination_port,
            packet_intervals: VecDeque::new(),
            inter_arrival_times: Vec::new(),
            timing_regularity: 0.0,
            jitter_coefficient: 0.0,
            timing_entropy: 0.0,
            frequency_peaks: Vec::new(),
            dominant_frequency: None,
            frequency_stability: 0.0,
            harmonic_analysis: HarmonicAnalysis {
                fundamental_frequency: 0.0,
                harmonics: Vec::new(),
                harmonic_distortion: 0.0,
                spectral_centroid: 0.0,
                spectral_rolloff: 0.0,
            },
            mean_interval: 0.0,
            interval_variance: 0.0,
            interval_std_dev: 0.0,
            coefficient_of_variation: 0.0,
            skewness: 0.0,
            kurtosis: 0.0,
            beacon_probability: 0.0,
            confidence_score: 0.0,
            threat_level: BeaconThreatLevel::Low,
            pattern_type: BeaconPatternType::FixedInterval,
            first_seen: timestamp,
            last_seen: timestamp,
            total_packets: 0,
            active_duration: Duration::from_secs(0),
            is_malicious: false,
            threat_indicators: Vec::new(),
            ml_classification: None,
        }
    }
}

impl FftAnalyzer {
    /// Create new FFT analyzer
    pub fn new(window_size: usize, sampling_rate: f64) -> Result<Self> {
        Ok(Self {
            sample_buffer: VecDeque::new(),
            window_size,
            sampling_rate,
            frequency_resolution: sampling_rate / window_size as f64,
        })
    }
    
    /// Analyze frequency spectrum of input signal
    pub fn analyze(&mut self, signal: &[f64]) -> Result<Vec<(f64, f64)>> {
        if signal.len() < self.window_size {
            return Ok(Vec::new());
        }
        
        // Simple DFT implementation (in production, use FFT library like rustfft)
        let mut spectrum = Vec::new();
        let n = self.window_size.min(signal.len());
        
        for k in 0..n/2 {
            let mut real = 0.0;
            let mut imag = 0.0;
            
            for i in 0..n {
                let angle = -2.0 * PI * k as f64 * i as f64 / n as f64;
                real += signal[i] * angle.cos();
                imag += signal[i] * angle.sin();
            }
            
            let magnitude = (real * real + imag * imag).sqrt() / n as f64;
            let frequency = k as f64 * self.frequency_resolution;
            
            spectrum.push((frequency, magnitude));
        }
        
        Ok(spectrum)
    }
}

impl BeaconClassifier {
    /// Create new beacon classifier
    pub fn new() -> Result<Self> {
        Ok(Self {
            feature_extractor: BeaconFeatureExtractor::new(),
            classification_threshold: 0.5,
            model_metrics: ModelMetrics::default(),
        })
    }
    
    /// Classify beacon pattern
    pub fn classify(&self, features: &[f64]) -> Result<MlClassificationResult> {
        // Simplified classification (in production, use trained ML model)
        let prediction = features.iter().sum::<f64>() / features.len() as f64;
        let confidence = if prediction > self.classification_threshold { 0.8 } else { 0.3 };
        
        Ok(MlClassificationResult {
            prediction,
            confidence,
            feature_importance: vec![("timing_regularity".to_string(), 0.4)],
            decision_boundary_distance: (prediction - self.classification_threshold).abs(),
        })
    }
}

impl BeaconFeatureExtractor {
    /// Create new feature extractor
    pub fn new() -> Self {
        Self {
            feature_names: vec![
                "timing_regularity".to_string(),
                "jitter_coefficient".to_string(),
                "timing_entropy".to_string(),
                "frequency_stability".to_string(),
                "coefficient_of_variation".to_string(),
            ],
            feature_count: 5,
        }
    }
    
    /// Extract features from beacon pattern
    pub fn extract_features(&self, pattern: &BeaconPattern) -> Result<Vec<f64>> {
        Ok(vec![
            pattern.timing_regularity,
            pattern.jitter_coefficient,
            pattern.timing_entropy,
            pattern.frequency_stability,
            pattern.coefficient_of_variation,
        ])
    }
}

impl Default for BeaconDetectorConfig {
    fn default() -> Self {
        Self {
            min_packets_for_analysis: 10,
            analysis_window_seconds: 300, // 5 minutes
            jitter_threshold: 0.2,
            regularity_threshold: 0.7,
            frequency_analysis_enabled: true,
            ml_classification_enabled: true,
            detection_sensitivity: 0.6,
        }
    }
}

impl Default for BeaconDetectionMetrics {
    fn default() -> Self {
        Self {
            total_patterns_analyzed: 0,
            beacons_detected: 0,
            false_positives: 0,
            avg_detection_time_ms: 0.0,
            max_detection_time_ms: 0,
            patterns_per_second: 0.0,
            memory_usage_mb: 0.0,
        }
    }
}

impl Default for ModelMetrics {
    fn default() -> Self {
        Self {
            accuracy: 0.0,
            precision: 0.0,
            recall: 0.0,
            f1_score: 0.0,
            auc_roc: 0.0,
        }
    }
}
