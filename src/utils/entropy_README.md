# Enhanced Entropy Analysis System

This module provides a comprehensive entropy analysis engine designed for advanced malware detection, memory forensics, and ransomware identification as part of the ERDPS (Enhanced Ransomware Detection and Prevention System) Ultimate Detection Enhancement plan.

## Features

### Advanced Entropy Calculations
- **Shannon Entropy**: Classic information-theoretic entropy measurement
- **Kolmogorov Complexity Estimation**: Approximation using compression ratios
- **Chi-Square Randomness Test**: Statistical test for data randomness
- **Entropy Rate Calculation**: For streaming data analysis
- **Block-wise Entropy Analysis**: Sectional entropy computation

### File Entropy Analysis
- **PE Section Analysis**: Entropy analysis of executable sections (headers, code, data)
- **Entropy Spike Detection**: Identifies sudden entropy changes indicating encryption
- **Compressed vs Encrypted Differentiation**: Distinguishes between compression and encryption
- **File Type Entropy Baselines**: Establishes normal entropy ranges for different file types

### Memory Entropy Monitoring
- **Process Memory Region Analysis**: Analyzes entropy in different memory regions
- **Heap Entropy Monitoring**: Detects heap-based exploits through entropy analysis
- **Stack Entropy Analysis**: Identifies ROP/JOP attacks via stack entropy patterns
- **Executable Memory Tracking**: Monitors entropy changes in executable memory regions

### Ransomware Detection Patterns
- **Entropy Threshold Detection**: Identifies file encryption through entropy spikes
- **Entropy Change Rate Monitoring**: Tracks rapid entropy changes across files
- **File Extension Entropy Correlation**: Correlates entropy with file type changes
- **Directory-wide Entropy Analysis**: Analyzes entropy patterns across entire directories

### Performance Optimizations
- **Streaming Entropy**: Efficient analysis of large files without full memory loading
- **Cached Results**: Intelligent caching system with configurable TTL
- **Multi-threaded Analysis**: Parallel processing using Rayon for improved performance
- **Memory-efficient Processing**: Optimized algorithms for minimal memory footprint

### Integration Support
- **ML Model Export**: Serializable entropy metrics for machine learning pipelines
- **YARA Rule Integration**: Hooks for integrating with YARA rule engines
- **Real-time Monitoring**: Continuous entropy monitoring capabilities
- **Configurable Thresholds**: Customizable detection thresholds and alert systems

## Usage Examples

### Basic Entropy Analysis

```rust
use erdps_agent::utils::entropy::{EntropyAnalyzer, shannon_entropy};

// Simple Shannon entropy calculation
let data = vec![1, 2, 3, 4, 5];
let entropy = shannon_entropy(&data);
println!("Shannon entropy: {}", entropy);

// Comprehensive analysis
let analyzer = EntropyAnalyzer::new();
let analysis = analyzer.analyze(&data);
println!("Analysis: {:?}", analysis);
```

### File Analysis

```rust
use std::fs;
use erdps_agent::utils::entropy::EntropyAnalyzer;

let analyzer = EntropyAnalyzer::new();
let file_data = fs::read("suspicious_file.exe").unwrap();
let analysis = analyzer.analyze(&file_data);

if analysis.is_encrypted {
    println!("File appears to be encrypted (entropy: {})", analysis.shannon_entropy);
}

if analysis.ransomware_probability > 0.7 {
    println!("High ransomware probability detected!");
}
```

### Memory Region Analysis

```rust
use erdps_agent::utils::entropy::EntropyAnalyzer;

let analyzer = EntropyAnalyzer::new();
let memory_data = get_process_memory(); // Your memory acquisition function
let analysis = analyzer.analyze_memory_region(&memory_data, 0x401000, true);

if analysis.shellcode_probability > 0.8 {
    println!("Potential shellcode detected at 0x{:x}", analysis.region_start);
}

if analysis.injection_probability > 0.7 {
    println!("Possible code injection detected!");
}
```

### Ransomware Detection

```rust
use erdps_agent::utils::entropy::EntropyAnalyzer;
use std::fs;

let analyzer = EntropyAnalyzer::new();
let mut files = Vec::new();

// Collect files from directory
for entry in fs::read_dir("./documents").unwrap() {
    let path = entry.unwrap().path();
    if let Ok(data) = fs::read(&path) {
        files.push((path.to_string_lossy().to_string(), data));
    }
}

let metrics = analyzer.analyze_ransomware_patterns(&files);

if metrics.entropy_spike_detected {
    println!("Entropy spike detected - possible ransomware activity!");
    println!("Encryption pattern score: {}", metrics.encryption_pattern_score);
    println!("Files analyzed: {}", metrics.files_analyzed);
    println!("High entropy files: {}", metrics.high_entropy_files);
}
```

### Streaming Analysis for Large Files

```rust
use erdps_agent::utils::entropy::EntropyAnalyzer;
use std::fs::File;
use std::io::Read;

let analyzer = EntropyAnalyzer::new();
let mut file = File::open("large_file.bin").unwrap();
let mut buffer = vec![0u8; 8192]; // 8KB chunks

while let Ok(bytes_read) = file.read(&mut buffer) {
    if bytes_read == 0 { break; }
    
    let analysis = analyzer.analyze_stream(&buffer[..bytes_read]);
    
    if analysis.shannon_entropy > 7.5 {
        println!("High entropy chunk detected!");
    }
}
```

### Custom Configuration

```rust
use erdps_agent::utils::entropy::{EntropyAnalyzer, EntropyConfig};
use std::time::Duration;

let config = EntropyConfig {
    block_size: 1024,
    encryption_threshold: 7.0,
    compression_threshold: 6.0,
    enable_caching: true,
    cache_ttl: Duration::from_secs(300),
    parallel_processing: true,
};

let analyzer = EntropyAnalyzer::with_config(config);
```

## Data Structures

### EntropyAnalysis
Contains comprehensive entropy analysis results:
- `shannon_entropy`: Shannon entropy value (0.0 - 8.0)
- `kolmogorov_complexity`: Estimated Kolmogorov complexity
- `chi_square_value`: Chi-square test statistic
- `is_encrypted`: Boolean indicating likely encryption
- `is_compressed`: Boolean indicating likely compression
- `entropy_variance`: Variance in entropy across data blocks
- `ransomware_probability`: Probability of ransomware (0.0 - 1.0)

### MemoryRegionAnalysis
Specialized analysis for memory regions:
- `region_start`: Memory region start address
- `region_size`: Size of the analyzed region
- `is_executable`: Whether the region is executable
- `shellcode_probability`: Probability of containing shellcode
- `injection_probability`: Probability of code injection
- `entropy_analysis`: Standard entropy analysis results

### RansomwareMetrics
Ransomware-specific detection metrics:
- `entropy_spike_detected`: Boolean indicating entropy spikes
- `encryption_pattern_score`: Overall encryption pattern score
- `files_analyzed`: Number of files processed
- `high_entropy_files`: Count of high-entropy files
- `average_entropy`: Average entropy across all files
- `entropy_variance`: Variance in entropy across files

## Performance Considerations

1. **Caching**: Enable caching for repeated analysis of the same data
2. **Parallel Processing**: Use parallel processing for large datasets
3. **Streaming**: Use streaming analysis for files larger than available memory
4. **Block Size**: Adjust block size based on your specific use case
5. **Cache TTL**: Configure appropriate cache TTL based on your update frequency

## Integration with ERDPS

This entropy analysis system is designed to integrate seamlessly with other ERDPS components:

- **YARA Rules**: Entropy metrics can be used in YARA rule conditions
- **ML Models**: Serializable analysis results for machine learning pipelines
- **Real-time Monitoring**: Continuous entropy monitoring for live threat detection
- **Memory Forensics**: Deep memory analysis for advanced persistent threats
- **Behavioral Analysis**: Entropy patterns for behavioral malware detection

## Security Considerations

- All analysis is performed in read-only mode
- No data is modified during analysis
- Caching can be disabled for sensitive environments
- Memory usage is bounded and configurable
- Thread-safe operations for concurrent usage

## Testing

Comprehensive test suite covers:
- Basic entropy calculations
- File analysis scenarios
- Memory region analysis
- Ransomware detection patterns
- Performance optimizations
- Caching mechanisms
- Error handling

Run tests with:
```bash
cargo test entropy --features metrics
```

## Dependencies

- `rayon`: Parallel processing
- `serde`: Serialization support
- Standard library components for mathematical operations

## License

This module is part of the ERDPS project and follows the same licensing terms.