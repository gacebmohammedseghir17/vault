# YARA Configuration Guide

This guide explains how administrators can configure YARA scanning settings in the ERDPS Agent.

## Overview

The ERDPS Agent includes integrated YARA scanning capabilities that can be fully controlled through configuration files. Administrators can enable/disable YARA scanning, customize scan paths, set scan intervals, and specify rules directories without requiring code changes.

## Configuration Structure

YARA settings are configured in the `[yara]` section of the agent configuration:

```toml
[yara]
enabled = true
rules_dir = "C:\\YARA\\rules"
scan_paths = ["C:\\Users", "C:\\Temp"]
interval_seconds = 1800
```

## Configuration Parameters

### `enabled` (boolean)
- **Description**: Controls whether YARA scanning is active
- **Default**: `true`
- **Values**: `true` (enable scanning) or `false` (disable scanning)
- **Example**: `enabled = false`

### `rules_dir` (string)
- **Description**: Path to the directory containing YARA rule files
- **Default**: `"C:\\YARA\\rules"` (Windows) or `"/opt/yara/rules"` (Linux)
- **Format**: Absolute or relative path
- **Example**: `rules_dir = "./custom_rules"`

### `scan_paths` (array of strings)
- **Description**: List of directories to scan for malware
- **Default**: Common user directories (Downloads, Desktop, Documents, Temp)
- **Format**: Array of directory paths
- **Example**: 
  ```toml
  scan_paths = [
      "C:\\Users",
      "C:\\Program Files",
      "D:\\Data"
  ]
  ```

### `interval_seconds` (integer)
- **Description**: Time interval between scans in seconds
- **Default**: `1800` (30 minutes)
- **Range**: Minimum 60 seconds (1 minute)
- **Example**: `interval_seconds = 3600` (1 hour)

## Configuration Examples

### Example 1: Disable YARA Scanning
```toml
[yara]
enabled = false
rules_dir = "C:\\YARA\\rules"
scan_paths = []
interval_seconds = 1800
```

### Example 2: High-Frequency Scanning
```toml
[yara]
enabled = true
rules_dir = "./production_rules"
scan_paths = [
    "C:\\Users",
    "C:\\Program Files",
    "C:\\Windows\\Temp"
]
interval_seconds = 300  # 5 minutes
```

### Example 3: Custom Enterprise Configuration
```toml
[yara]
enabled = true
rules_dir = "D:\\Security\\YARA\\Enterprise_Rules"
scan_paths = [
    "C:\\Users",
    "D:\\Shared_Data",
    "E:\\Projects",
    "F:\\Backup"
]
interval_seconds = 7200  # 2 hours
```

## Configuration Management

### Loading Configuration
The agent automatically loads configuration from `config/agent.conf` on startup. The configuration file is encrypted for security.

### Backward Compatibility
The agent includes automatic migration for legacy YARA configuration fields:
- `yara_enabled` → `yara.enabled`
- `yara_rules_directory` → `yara.rules_dir`
- `yara_scan_directories` → `yara.scan_paths`
- `yara_scan_interval_minutes` → `yara.interval_seconds` (converted from minutes)

### Configuration Validation
- Invalid paths are logged but don't prevent startup
- Minimum interval is enforced (60 seconds)
- Missing rules directory is handled gracefully
- Empty scan paths disable directory scanning

## Operational Behavior

### When YARA is Enabled (`enabled = true`)
- Agent starts periodic YARA scanning on startup
- Scans run at the configured interval using async timers
- All configured scan paths are processed
- Results are logged and reported through the IPC system

### When YARA is Disabled (`enabled = false`)
- No YARA scanning processes are started
- No periodic scanning occurs
- YARA-related resources are not initialized
- Agent continues normal operation without YARA functionality

### Dynamic Configuration Updates
- Configuration changes require agent restart
- The agent detects interval changes and updates timers accordingly
- Scan path changes take effect on the next scan cycle

## Best Practices

### Security Considerations
1. **Rules Directory**: Ensure YARA rules directory is protected from unauthorized modification
2. **Scan Paths**: Limit scan paths to necessary directories to reduce performance impact
3. **Intervals**: Balance security needs with system performance

### Performance Optimization
1. **Scan Frequency**: Longer intervals reduce CPU usage but may delay detection
2. **Path Selection**: Avoid scanning large, frequently-changing directories
3. **Rule Optimization**: Use efficient YARA rules to minimize scan time

### Monitoring
1. **Logs**: Monitor agent logs for YARA scanning status and errors
2. **Performance**: Track scan duration and system impact
3. **Detection**: Review YARA detection alerts and adjust rules as needed

## Troubleshooting

### Common Issues

**YARA Not Starting**
- Check `enabled = true` in configuration
- Verify rules directory exists and contains valid YARA files
- Review agent logs for initialization errors

**No Detections**
- Verify scan paths contain files to scan
- Check YARA rules are properly formatted
- Ensure scan interval allows sufficient time for completion

**Performance Issues**
- Increase scan interval to reduce frequency
- Limit scan paths to essential directories
- Optimize YARA rules for better performance

### Log Messages
- `YARA scanning enabled` - Confirms YARA is active
- `YARA scanning disabled` - Confirms YARA is inactive
- `Migrated legacy yara_* setting` - Shows configuration migration
- `YARA scan completed` - Indicates successful scan cycle

## Integration with Agent Features

YARA scanning integrates seamlessly with other agent features:
- **Detection System**: YARA results feed into the main detection pipeline
- **IPC Communication**: YARA alerts are sent to connected clients
- **Mitigation System**: YARA detections can trigger automated responses
- **Logging**: All YARA activity is logged through the standard logging system

---

*For additional support or advanced configuration options, consult the main agent documentation or contact your system administrator.*