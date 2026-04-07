# Detector Specification

This document describes the ransomware detection engine implemented in `agent/src/detector.rs`. The detector analyzes file system events in real-time and applies multiple detection rules to identify potential ransomware activity.

## Overview

The detector operates as an asynchronous task that consumes file system events from the monitor and applies five distinct detection rules. When suspicious activity is detected, it generates `DetectionAlert` objects with scores from 0-100 and forwards high-score alerts to the mitigation system.

## Detection Rules

### 1. Mass Modification Detection (`mass_modification`)

**Purpose**: Detects rapid file modifications in a single directory, a common ransomware behavior.

**Algorithm**:
- Tracks unique file modifications per directory using a sliding time window
- Uses deduplication with 100ms window to prevent counting multiple events for the same file
- Maintains a HashMap of directory paths to modification timestamps

**Configuration**:
- `mass_modification_count`: Threshold for number of modifications (default: 30)
- `mass_modification_window_secs`: Time window in seconds (default: 10)

**Scoring**:
```rust
score = min(100, 100 * (unique_files / threshold))
```

**Evidence**:
- Number of unique files modified
- Directory path
- Threshold value

**Mitigation**: Process suspension and file quarantine

### 2. Extension Mutation Detection (`extension_mutation`)

**Purpose**: Detects files being renamed to suspicious extensions commonly used by ransomware.

**Algorithm**:
- Monitors file rename/creation events
- Checks against predefined list of suspicious extensions
- Calculates ratio of suspicious files to total files in directory

**Suspicious Extensions**:
- `encrypt`, `encrypted`, `locked`, `crypt`, `crypto`, `enc`, `lock`, `xxx`

**Configuration**:
- `extension_mutation_threshold`: Minimum ratio to trigger alert (default: 0.3)
- `extension_mutation_window_secs`: Time window for analysis (default: 30)

**Scoring**:
```rust
score = min(100, (suspicious_ratio * 150.0) as u8)
```

**Evidence**:
- Suspicious extension detected
- File path
- Ratio of suspicious to total files

**Mitigation**: File quarantine and process investigation

### 3. Ransom Note Detection (`ransom_note_detection`)

**Purpose**: Identifies creation of ransom notes with typical ransomware messaging.

**Algorithm**:
- Monitors creation of `.txt` and `.html` files
- Uses regex patterns to match common ransom note content
- Applies file size limits (10KB max) for performance

**Detection Patterns**:
- "your files have been encrypted"
- "contact.*decrypt"
- "bitcoin|btc|cryptocurrency"
- "ransom|payment"
- "\$[0-9]+|[0-9]+\s*(btc|bitcoin)"

**Configuration**:
- Patterns are compiled at detector initialization
- File size limit: 10,240 bytes

**Scoring**:
```rust
score = min(100, 70 + (pattern_matches * 10))
```

**Evidence**:
- File path of suspected ransom note
- Number of suspicious patterns matched
- File extension

**Mitigation**: Immediate quarantine and forensic analysis

### 4. Entropy Analysis (`entropy_analysis`)

**Purpose**: Detects file encryption by analyzing Shannon entropy of file content.

**Algorithm**:
- Samples chunks from beginning, middle, and end of modified files
- Calculates Shannon entropy for each chunk
- Compares average entropy against threshold
- Excludes known binary file types

**Configuration**:
- `entropy_threshold`: Minimum entropy to trigger alert (default: 7.5 bits/byte)
- Chunk size: 4,096 bytes
- File size limits: 0 bytes to 10MB

**Excluded Extensions**:
- Binary: `exe`, `dll`, `bin`
- Archives: `zip`, `rar`, `7z`
- Media: `jpg`, `jpeg`, `png`, `gif`, `mp4`, `avi`, `mp3`

**Scoring**:
```rust
score = min(100, (average_entropy * 10.0) as u8)
```

**Evidence**:
- Entropy value and threshold
- File path and size
- File extension

**Mitigation**: File analysis and potential quarantine

### 5. Process Behavior Detection (`process_behavior`)

**Purpose**: Identifies processes exhibiting suspicious file access patterns.

**Algorithm**:
- Tracks file write operations per process ID
- Maintains sliding window of process activity
- Counts writes within time window

**Configuration**:
- `process_behavior_write_threshold`: Minimum writes to trigger alert (default: 50)
- `process_behavior_window_secs`: Time window for analysis (default: 60)

**Scoring**:
```rust
score = min(100, (80 * write_count / threshold) as u8)
```

**Evidence**:
- Process ID and name
- Number of file writes
- Time window

**Mitigation**: Process suspension and investigation

## Alert Aggregation

The detector implements alert aggregation to combine related alerts:

- Alerts from the same directory within a time window are combined
- Scores are aggregated using weighted maximum
- Evidence from multiple rules is consolidated
- Process IDs and file paths are merged

## Mitigation Integration

When an alert score meets or exceeds `auto_quarantine_score`, the detector sends a `MitigationRequest` containing:

- Action type (suspend_or_terminate)
- Process ID(s)
- Affected file paths
- Quarantine destination

## Performance Considerations

### Asynchronous Processing
- All detection rules run asynchronously
- CPU-intensive operations (entropy calculation) use worker queues
- Bounded channels prevent memory exhaustion

### Memory Management
- Sliding windows automatically clean up old entries
- File content sampling limits memory usage
- Process behavior state is periodically cleaned

### Rate Limiting
- Event deduplication prevents duplicate processing
- File size limits prevent resource exhaustion
- Timeout mechanisms prevent blocking

## Configuration Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `alert_threshold` | 70 | Minimum score for high-priority alerts |
| `auto_quarantine_score` | 85 | Score threshold for automatic mitigation |
| `mass_modification_count` | 30 | Files modified to trigger mass modification |
| `mass_modification_window_secs` | 10 | Time window for mass modification |
| `extension_mutation_threshold` | 0.3 | Ratio threshold for extension mutation |
| `extension_mutation_window_secs` | 30 | Time window for extension analysis |
| `entropy_threshold` | 7.5 | Shannon entropy threshold (bits/byte) |
| `process_behavior_write_threshold` | 50 | File writes to trigger behavior alert |
| `process_behavior_window_secs` | 60 | Time window for process behavior |

## Testing

### Unit Tests
- Individual rule testing with controlled inputs
- Entropy calculation verification
- Sliding window behavior validation
- Pattern matching accuracy

### Integration Tests
- Staged ransomware scenario simulation
- False positive avoidance testing
- End-to-end alert generation and mitigation
- Performance under load

## Security Considerations

- No unsafe code or unwrap() calls in production paths
- Input validation for all file operations
- Resource limits prevent DoS attacks
- Deterministic behavior for reproducible results
- Secure handling of sensitive file content

## Logging and Monitoring

- All alerts logged via `logger::info!`
- Critical alerts forwarded to IPC system
- Performance metrics tracked
- Error conditions logged with context
- Debug output available for troubleshooting