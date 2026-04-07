# Network Monitoring Setup Guide

## Overview

The ERDPS agent includes optional network monitoring capabilities through the `network-monitoring` feature. This feature requires additional system dependencies that must be installed separately.

## Dependencies Required

The network monitoring feature depends on:
- **WinPcap** or **Npcap** (recommended) for packet capture
- **Packet.lib** - provided by the above libraries

## Installation Steps

### Option 1: Npcap (Recommended)

1. Download Npcap from: https://npcap.com/#download
2. Install Npcap with the following options:
   - ✅ Install Npcap in WinPcap API-compatible Mode
   - ✅ Install Npcap SDK (for development)
3. Ensure `Packet.lib` is available in your system library paths

### Option 2: WinPcap (Legacy)

1. Download WinPcap from: https://www.winpcap.org/install/
2. Install the WinPcap Developer's Pack
3. Add the library path to your system

## Building with Network Monitoring

Once dependencies are installed, build with network monitoring:

```bash
# Build with all default features (includes network-monitoring)
cargo build

# Or explicitly enable network monitoring
cargo build --features "network-monitoring"
```

## Building without Network Monitoring

If you don't need network monitoring capabilities:

```bash
# Build without network monitoring
cargo build --no-default-features --features "basic-detection,metrics,yara,validation-framework,advanced-logging,behavioral-analysis,automated-response,memory-forensics,api-hooking,performance-optimization"
```

## Troubleshooting

### Error: `cannot open input file 'Packet.lib'`

This error indicates that WinPcap/Npcap is not properly installed or the library path is not configured.

**Solutions:**
1. Install Npcap with SDK support
2. Verify `Packet.lib` exists in your system
3. Add the library path to your environment
4. Build without network-monitoring features if not needed

### Verifying Installation

To verify your installation:

```bash
# Check if the library is found
dir "C:\Program Files\Npcap\SDK\Lib\x64\Packet.lib"
```

## Feature Dependencies

The `network-monitoring` feature includes:
- `pcap` - Packet capture library
- `pnet` - Network protocol library
- `dns-lookup` - DNS resolution
- `trust-dns-resolver` - DNS resolver
- `network-interface` - Network interface enumeration
- `rawsock` - Raw socket access
- `x509-parser` - Certificate parsing
## Npcap Verification Script

Use `verify_npcap.ps1` to check Npcap installation, version, and service state.

Commands:
- `powershell -ExecutionPolicy Bypass -File ./verify_npcap.ps1`
- JSON output: `powershell -File ./verify_npcap.ps1 -Json`
- Require minimum version: `powershell -File ./verify_npcap.ps1 -MinVersion 1.79`
- Attempt to start service (requires admin): `powershell -File ./verify_npcap.ps1 -StartService`
- Verbose paths/registry: `powershell -File ./verify_npcap.ps1 -VerboseOutput`

Exit Codes:
- `0` — Installed and service running (or started successfully)
- `1` — Not detected
- `2` — Installed but service stopped (or need admin to start)
- `3` — Installed but version below required `-MinVersion`
- `4` — Installed but failed to start service

Notes:
- Script checks multiple file paths across `System32`, `SysWOW64`, and `Program Files` locations.
- Registry keys probed: `HKLM\SOFTWARE\Npcap` and `HKLM\SOFTWARE\WOW6432Node\Npcap` for `Version`.
- Include this verification in pre-flight checks before enabling enhanced packet capture.