# ERDPS Agent - Complete Command Documentation

## Overview
ERDPS (Enhanced Real-time Detection and Protection System) Agent is a comprehensive endpoint security solution with multiple binaries for different functionalities.

## Main Agent Binary

### `erdps-agent.exe`
**Purpose**: Main ERDPS agent service
**Status**: ✅ Working
**Configuration**: Uses `config.toml`
**Default Ports**: 
- IPC Server: 127.0.0.1:7777
- Alert Server: 127.0.0.1:7778 (configurable)

**Features**:
- File system monitoring (C:\Users, C:\Program Files by default)
- YARA rule loading and scanning
- IPC server for client communication
- Mitigation engine
- Quarantine functionality
- Real-time threat detection

**Logs Output**:
```
[INFO] Agent is now running. Press Ctrl+C to stop.
[INFO] Starting IPC server on 127.0.0.1:7777
[INFO] YARA rule compilation completed: 1/2 rules compiled successfully
[INFO] File system monitor started successfully
```

## IPC Client Binaries

### `ipc_client.exe`
**Purpose**: Test utility for secure IPC communication
**Status**: ✅ Working
**Usage**: 
- `ipc_client.exe` - Get agent status
- `ipc_client.exe quarantine <file>` - Quarantine specified file

**Features**:
- HMAC-SHA256 signing
- Nonce-based replay protection
- Timestamp validation
- JSON payload handling

**Example Output**:
```json
{
  "agent_version": "0.1.0",
  "last_scan": null,
  "quarantined_files": 0,
  "status": "running",
  "threats_detected": 0,
  "uptime_seconds": 0
}
```

**Quarantine Example**:
```json
{
  "message": "Successfully quarantined 1 files",
  "quarantined_paths": [
    "./temp_quarantine_test/quarantine\\1762009473-02907c29-0854-47e8-bae8-52f8f83ae56d\\test_story.txt"
  ]
}
```

### `simple_ipc_test.exe`
**Purpose**: Simple IPC connectivity test
**Status**: ⚠️ Port mismatch (connects to 7778, agent runs on 7777)
**Issue**: Hardcoded to connect to port 7778 instead of 7777

### `test_dashboard_client.exe`
**Purpose**: Dashboard client for alert reception
**Status**: ⚠️ Port mismatch (connects to 7778, agent runs on 7777)
**Features**: IPC key parsing and alert reception testing

## Configuration and Debug Utilities

### `debug_config.exe`
**Purpose**: Configuration file validation
**Status**: ✅ Working
**Output**:
```
Config file read successfully, length: 1157 bytes
Config parsed successfully
YARA configuration found and enabled
YARA rules path: rules/
```

### `generate_baseline_config.exe`
**Purpose**: Generate default configuration file
**Status**: ✅ Working
**Output**: Creates `baseline_config.toml` with default settings
**Features**: Round-trip parsing validation

### `debug_key.exe`
**Purpose**: IPC key debugging and signature verification
**Status**: ✅ Working
**Features**:
- Base64 key decoding
- HMAC signature generation
- Signature verification testing

**Example Output**:
```
Base64 key: dGVzdF9pcGNfa2V5XzEyMzQ1Njc4OTBhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5eg==
Key buffer length: 49
Generated signature: NQHoOiUZqUFm3s16kYUnZlOpu9zIbM+T0LiZqaeF38c=
Match: true
```

### `debug_signature.exe`
**Purpose**: Signature generation testing
**Status**: ✅ Working
**Features**: HMAC-SHA256 signature generation for IPC commands

### `debug_signature_sync.exe`
**Purpose**: Signature synchronization testing
**Status**: ⚠️ Signature mismatch detected
**Issue**: Generated signatures don't match expected values from logs

### `debug_live_signature.exe`
**Purpose**: Live signature verification testing
**Status**: ⚠️ Partial success
**Features**: 
- Node.js signature compatibility: ✅ Working
- Rust signature compatibility: ❌ Mismatch

## YARA and Scanning Utilities

### `test_yara_updater.exe`
**Purpose**: YARA rule updater testing
**Status**: ✅ Working
**Features**:
- Configuration validation
- YARA updater status checking (disabled by default)
- Integration test validation

### `test_scan_file_integration.exe`
**Purpose**: File scanning integration testing
**Status**: ❌ Failed
**Issues**:
- Signature verification failed
- Failed to read response length
- IPC communication problems

**Test Cases**:
1. Valid file - no detection
2. Valid file - malware detection  
3. Non-existent file handling

## Alert System Utilities

### `test_alert_delivery.exe`
**Purpose**: Alert delivery system testing
**Status**: ⚠️ Port mismatch (connects to 7778)
**Features**: IPC alert delivery testing

### `comprehensive_alert_test.exe`
**Purpose**: Comprehensive alert system testing
**Status**: ❌ Connection refused
**Issue**: Cannot connect to IPC server

## Validation and Testing Utilities

### `run_functional_validation.exe`
**Purpose**: Functional validation testing
**Status**: ❌ Disabled in release builds
**Note**: Requires test module dependencies, use `cargo test --lib` instead

## Configuration Files

### `config.toml`
**Purpose**: Main agent configuration
**Key Settings**:
- IPC server configuration
- File system monitoring paths
- YARA rules configuration
- Logging settings
- Mitigation settings

### `baseline_config.toml`
**Purpose**: Generated baseline configuration
**Auto-generated**: Yes
**Validation**: Round-trip parsing tested

## YARA Rules

### Location: `./rules/`
**Status**: 1/2 rules compiled successfully
**Issue**: `test_rules.yar` compilation failed
**Working Rules**: 1 rule loaded successfully

## Security Features

### IPC Security
- HMAC-SHA256 message signing
- Nonce-based replay protection
- Timestamp validation
- Base64 key encoding

### File System Protection
- Real-time file monitoring
- Quarantine functionality
- Path validation
- Volume scan protection

### Detection Capabilities
- YARA rule-based detection
- Behavioral analysis
- Real-time scanning
- Threat mitigation

## Known Issues and Limitations

1. **Port Configuration Mismatch**: Several test utilities hardcoded to port 7778 while agent runs on 7777
2. **YARA Rule Compilation**: 1 out of 2 YARA rules failing to compile
3. **Signature Verification**: Inconsistencies between Rust and Node.js signature generation
4. **Test Dependencies**: Some utilities disabled in release builds
5. **IPC Communication**: Some integration tests failing due to signature/communication issues

## Recommendations

1. **Fix Port Configuration**: Update test utilities to use correct IPC port (7777)
2. **YARA Rule Debugging**: Fix compilation issues with `test_rules.yar`
3. **Signature Standardization**: Resolve signature generation inconsistencies
4. **Integration Testing**: Fix IPC communication issues in integration tests
5. **Documentation**: Add command-line help for utilities where applicable

## Test Results Summary

| Binary | Status | Functionality | Issues |
|--------|--------|---------------|---------|
| erdps-agent.exe | ✅ Working | Main agent service | YARA rule compilation |
| ipc_client.exe | ✅ Working | IPC communication | None |
| debug_config.exe | ✅ Working | Config validation | None |
| generate_baseline_config.exe | ✅ Working | Config generation | None |
| debug_key.exe | ✅ Working | Key debugging | None |
| debug_signature.exe | ✅ Working | Signature testing | None |
| test_yara_updater.exe | ✅ Working | YARA updater test | None |
| debug_signature_sync.exe | ⚠️ Partial | Signature sync | Signature mismatch |
| debug_live_signature.exe | ⚠️ Partial | Live signature test | Rust compatibility |
| simple_ipc_test.exe | ❌ Failed | Simple IPC test | Port mismatch |
| test_dashboard_client.exe | ❌ Failed | Dashboard client | Port mismatch |
| test_alert_delivery.exe | ❌ Failed | Alert delivery | Port mismatch |
| comprehensive_alert_test.exe | ❌ Failed | Alert testing | Connection issues |
| test_scan_file_integration.exe | ❌ Failed | Scan integration | IPC issues |
| run_functional_validation.exe | ❌ Disabled | Functional validation | Release build limitation |

## Usage Examples

### Basic Agent Operation
```bash
# Start the main agent
.\target\release\erdps-agent.exe

# Check agent status
.\target\release\ipc_client.exe

# Quarantine a file
.\target\release\ipc_client.exe quarantine suspicious_file.txt
```

### Configuration Management
```bash
# Validate current configuration
.\target\release\debug_config.exe

# Generate baseline configuration
.\target\release\generate_baseline_config.exe
```

### Debugging and Testing
```bash
# Test IPC key functionality
.\target\release\debug_key.exe

# Test signature generation
.\target\release\debug_signature.exe

# Test YARA updater
.\target\release\test_yara_updater.exe
```

This documentation provides a comprehensive overview of all ERDPS agent commands, their functionality, current status, and known issues.