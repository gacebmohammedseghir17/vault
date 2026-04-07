# Mitigation Engine Specification

## Overview

The Mitigation Engine is a production-grade component of the ERDPS (Enterprise Ransomware Detection and Prevention System) agent that performs safe mitigation actions in response to detected threats. It provides a comprehensive set of capabilities for process control, file quarantine, and policy enforcement while maintaining strict security and auditing standards.

## Architecture

### Core Components

1. **MitigationEngine**: Main orchestrator that processes mitigation requests
2. **ProcessController**: Trait-based abstraction for platform-specific process operations
3. **Audit Logger**: Structured logging system for all mitigation actions
4. **Policy Validator**: Enforces security policies and operator confirmation requirements

### Data Flow

```
Detector → MitigationRequest → Channel → MitigationEngine → Actions → MitigationResult → IPC/Audit
```

## API Reference

### Core Types

#### MitigationRequest
```rust
pub struct MitigationRequest {
    pub id: String,           // Unique request identifier
    pub action: MitigationAction,
    pub score: u32,          // Threat score (0-100)
    pub reason: String,      // Human-readable justification
    pub dry_run: bool,       // If true, log actions but don't execute
}
```

#### MitigationAction
```rust
pub enum MitigationAction {
    SuspendProcess { pid: u32 },
    ResumeProcess { pid: u32 },
    TerminateProcess { pid: u32 },
    QuarantineFiles { paths: Vec<PathBuf> },
    RestoreFiles { quarantined_paths: Vec<PathBuf> },
}
```

#### MitigationResult
```rust
pub struct MitigationResult {
    pub request_id: String,
    pub status: MitigationStatus,
    pub message: String,
    pub quarantined_paths: Option<Vec<PathBuf>>,
    pub timestamp: DateTime<Utc>,
}
```

#### MitigationStatus
```rust
pub enum MitigationStatus {
    Success,
    Denied,
    InsufficientPrivileges,
    DryRun,
    Error(String),
}
```

### Main Functions

#### start_mitigation_engine
```rust
pub fn start_mitigation_engine(
    rx: Receiver<MitigationRequest>,
    cfg: Arc<AgentConfig>
) -> JoinHandle<()>
```
Starts the mitigation engine with the specified configuration and returns a handle to the background task.

#### start_mitigation_engine_with_controller
```rust
pub fn start_mitigation_engine_with_controller(
    rx: Receiver<MitigationRequest>,
    cfg: Arc<AgentConfig>,
    controller: Arc<dyn ProcessController + Send + Sync>
) -> JoinHandle<()>
```
Starts the mitigation engine with a custom process controller (primarily for testing).

#### perform_mitigation
```rust
pub fn perform_mitigation(
    req: MitigationRequest,
    cfg: &AgentConfig
) -> MitigationResult
```
Processes a single mitigation request according to the specified configuration.

### Process Control Functions

#### suspend_process
```rust
pub fn suspend_process(pid: u32) -> anyhow::Result<()>
```
Suspends the specified process using platform-appropriate APIs.

#### resume_process
```rust
pub fn resume_process(pid: u32) -> anyhow::Result<()>
```
Resumes a previously suspended process.

#### terminate_process
```rust
pub fn terminate_process(pid: u32) -> anyhow::Result<()>
```
Terminates the specified process. Only allowed when `cfg.allow_terminate` is true.

### File Operations

#### quarantine_files
```rust
pub fn quarantine_files(
    paths: &[PathBuf],
    quarantine_path: &Path
) -> anyhow::Result<Vec<PathBuf>>
```
Moves files to quarantine using atomic operations and creates manifest files.

#### restore_files
```rust
pub fn restore_files(
    quarantined_paths: &[PathBuf]
) -> anyhow::Result<Vec<PathBuf>>
```
Restores files from quarantine to their original locations.

## Configuration

### AgentConfig Fields

- `auto_mitigate: bool` - Enable automatic mitigation without operator confirmation
- `allow_terminate: bool` - Allow process termination actions
- `mitigation_score_threshold: u32` - Minimum threat score required for mitigation
- `dry_run: bool` - Global dry-run mode
- `protected_pids: Vec<u32>` - PIDs that cannot be terminated or suspended
- `quarantine_path: PathBuf` - Base directory for quarantined files

## Platform Implementation

### Windows

Process control operations use Win32 APIs:
- `OpenProcess` with appropriate access rights
- `SuspendThread`/`ResumeThread` for suspend/resume operations
- `TerminateProcess` for process termination

All Windows-specific code is behind `#[cfg(windows)]` compilation flags.

### Linux

Process control uses standard POSIX signals:
- `kill(pid, SIGSTOP)` for process suspension
- `kill(pid, SIGCONT)` for process resumption
- `kill(pid, SIGTERM)` for process termination

### Cross-Platform

File operations use standard Rust filesystem APIs with atomic move semantics:
- `std::fs::rename` for same-volume moves
- Copy + verify + remove for cross-volume moves

## Security Features

### Policy Enforcement

1. **Score Threshold**: Requests below `mitigation_score_threshold` are denied
2. **Protected PIDs**: System-critical processes cannot be affected
3. **Privilege Checking**: Operations requiring elevated privileges are validated
4. **Operator Confirmation**: Destructive actions require explicit approval when `auto_mitigate` is false

### Audit Trail

Every mitigation action generates a structured audit record containing:
- Request ID and timestamp
- Action type and target
- Process ID and user ID
- Threat score and reason
- Result status and message
- HMAC signature for integrity

### Quarantine Structure

Quarantined files are organized as:
```
quarantine_path/
├── 20240115-143022-incident-abc123/
│   ├── suspicious_file.exe
│   ├── malware.dll
│   └── .manifest.json
└── 20240115-144501-incident-def456/
    ├── encrypted_document.docx
    └── .manifest.json
```

The manifest file contains:
```json
{
  "incident_id": "abc123",
  "timestamp": "2024-01-15T14:30:22Z",
  "files": [
    {
      "original_path": "/path/to/suspicious_file.exe",
      "quarantined_name": "suspicious_file.exe",
      "size": 1024,
      "checksum": "sha256:...",
      "metadata": {...}
    }
  ]
}
```

## Error Handling

The mitigation engine uses structured error handling:

1. **anyhow::Result** for recoverable errors
2. **MitigationStatus::Error** for operation failures
3. **MitigationStatus::InsufficientPrivileges** for permission issues
4. **MitigationStatus::Denied** for policy violations

All errors are logged with appropriate severity levels and include contextual information.

## Testing

### Unit Tests

- `quarantine_move_and_restore`: Tests file quarantine and restoration with metadata preservation
- `policy_respects_allow_terminate_flag`: Validates policy enforcement for termination actions
- `suspend_resume_stub_on_supported_platform`: Tests process control with mock controllers

### Integration Tests

- `test_mitigation_engine_quarantine_files`: End-to-end file quarantine testing
- `test_mitigation_engine_process_suspension`: Process control validation
- `test_mitigation_engine_policy_denial`: Policy enforcement verification
- `test_mitigation_engine_protected_pid`: Protected process handling

### Mock Controllers

The `MockProcessController` provides deterministic behavior for testing:
- Configurable success/failure responses
- Privilege simulation
- Action logging for verification

## Performance Considerations

1. **Async Processing**: The mitigation engine runs asynchronously to avoid blocking the detector
2. **Bounded Channels**: Channel capacity limits prevent memory exhaustion
3. **Atomic Operations**: File moves use atomic semantics when possible
4. **Lazy Logging**: Audit logs are written asynchronously

## Deployment Notes

### Privileges

The agent requires appropriate privileges for process control:
- Windows: SeDebugPrivilege for process access
- Linux: CAP_SYS_PTRACE or matching UID for target processes

### File System

Quarantine operations require:
- Write access to the quarantine directory
- Sufficient disk space for quarantined files
- Same-volume placement for atomic moves (recommended)

### Logging

Audit logs are written to `logs/mitigations.log` with automatic rotation. Ensure:
- Write permissions to the logs directory
- Adequate disk space for log retention
- Log rotation configuration matches operational requirements

## Troubleshooting

### Common Issues

1. **Permission Denied**: Check agent privileges and file system permissions
2. **Protected PID Errors**: Verify protected PID configuration
3. **Quarantine Failures**: Ensure quarantine directory exists and is writable
4. **Audit Log Issues**: Check log directory permissions and disk space

### Debug Mode

Enable debug logging with `RUST_LOG=debug` to see detailed operation traces.

### Dry Run Mode

Use dry run mode (`cfg.dry_run = true`) to test mitigation logic without executing actions.

## Future Enhancements

1. **Network Isolation**: Block network access for suspicious processes
2. **Registry Protection**: Quarantine registry modifications on Windows
3. **Container Support**: Extend process control to containerized environments
4. **Machine Learning**: Integrate ML-based policy decisions
5. **Distributed Coordination**: Coordinate mitigations across multiple agents