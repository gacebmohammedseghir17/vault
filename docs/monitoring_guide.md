# File System Monitoring Guide

This document provides comprehensive guidance for deploying and configuring the file system monitoring component of the ERDPS ransomware detection agent.

## Overview

The monitoring system (`agent/src/monitor.rs`) provides real-time file system event detection across multiple platforms using the `notify` crate. It generates structured events for file operations and forwards them to the detection engine for analysis.

## Architecture

### Cross-Platform Implementation

The monitor uses platform-specific APIs for optimal performance:

- **Windows**: `ReadDirectoryChangesW` API via notify crate
- **Linux**: `inotify` API via notify crate
- **Fallback**: Polling-based watcher for unsupported platforms

### Event Processing Pipeline

```
File System → Platform API → notify Crate → Event Processing → Deduplication → Channel → Detector
```

## Deployment Configuration

### Basic Setup

```rust
use erdps_agent::monitor::start_monitor;
use erdps_agent::config::AgentConfig;
use std::sync::Arc;
use tokio::sync::mpsc;

// Configure monitoring paths
let monitor_paths = vec![
    PathBuf::from("C:\\Users"),      // Windows user directories
    PathBuf::from("C:\\Documents"),   // Document folders
    PathBuf::from("/home"),           // Linux home directories
];

// Create event channel
let (event_tx, event_rx) = mpsc::channel(1000);

// Load configuration
let config = Arc::new(AgentConfig::load_from_file("config/agent.conf")?);

// Start monitoring
let monitor_handle = start_monitor(monitor_paths, event_tx, config);
```

### Recommended Monitoring Paths

#### Windows
- `C:\Users\{username}\Documents`
- `C:\Users\{username}\Desktop`
- `C:\Users\{username}\Pictures`
- `C:\Users\{username}\Downloads`
- Network drives and mapped folders
- Shared directories

#### Linux
- `/home/{username}`
- `/var/www`
- `/opt/data`
- `/srv`
- Mounted network filesystems

#### Exclusions
- System directories (`C:\Windows`, `/sys`, `/proc`)
- Temporary directories with high churn
- Log directories
- Cache directories
- Virtual machine disk files

## Permissions and Security

### Required Permissions

#### Windows
- **Read Access**: Required for all monitored directories
- **Traverse Folder**: Needed to access subdirectories
- **List Folder Contents**: Required for directory enumeration
- **Read Attributes**: Needed for file metadata

#### Linux
- **Read Permission**: Required on monitored directories
- **Execute Permission**: Needed for directory traversal
- **inotify Limits**: May need to increase system limits

### Service Account Configuration

#### Windows Service
```xml
<service>
    <id>erdps-agent</id>
    <name>ERDPS Ransomware Detection Agent</name>
    <description>Real-time ransomware detection and mitigation</description>
    <executable>erdps-agent.exe</executable>
    <logmode>rotate</logmode>
    <serviceaccount>
        <domain>DOMAIN</domain>
        <user>erdps-service</user>
        <password>SecurePassword123!</password>
        <allowservicelogon>true</allowservicelogon>
    </serviceaccount>
</service>
```

#### Linux Systemd
```ini
[Unit]
Description=ERDPS Ransomware Detection Agent
After=network.target

[Service]
Type=simple
User=erdps-agent
Group=erdps-agent
ExecStart=/usr/local/bin/erdps-agent
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### Security Considerations

1. **Principle of Least Privilege**: Grant only necessary permissions
2. **Network Access**: Monitor network-mounted filesystems carefully
3. **Sensitive Data**: Avoid monitoring directories with credentials
4. **Log Security**: Protect monitoring logs from tampering
5. **Resource Limits**: Configure appropriate system limits

## Performance Optimization

### Event Rate Management

#### Deduplication
- **Window**: 200ms deduplication window (configurable)
- **Key**: Path + event type combination
- **Memory**: Automatic cleanup of old entries

#### Channel Configuration
```rust
// Bounded channel prevents memory exhaustion
let (event_tx, event_rx) = mpsc::channel(1000); // Adjust based on load

// Monitor backpressure
if event_tx.try_send(event).is_err() {
    log::warn!("Event channel full, applying backpressure");
    // Implement backpressure strategy
}
```

### Resource Limits

#### Memory Usage
- **Event Buffer**: ~1KB per event × channel size
- **Deduplication Cache**: ~100 bytes per unique path
- **Watcher Overhead**: ~10MB per 1000 watched directories

#### CPU Usage
- **Event Processing**: ~0.1ms per event
- **Metadata Extraction**: ~0.5ms per file
- **Process Information**: ~2ms per process lookup (Windows)

#### I/O Impact
- **Metadata Reads**: 1 read per monitored file event
- **Process Queries**: Minimal impact with caching
- **Log Writes**: Configurable verbosity levels

## Platform-Specific Considerations

### Windows

#### ReadDirectoryChangesW Limitations
- **Buffer Size**: 64KB default, configurable
- **Nested Directories**: Automatic recursive monitoring
- **Network Drives**: Supported but may have delays
- **Symbolic Links**: Followed automatically

#### Process Information
```rust
// Windows-specific process info extraction
if let Some(pid) = get_file_process_id(&path) {
    if let Some(process_name) = get_process_name(pid) {
        event.pid = Some(pid);
        event.process_name = Some(process_name);
    }
}
```

#### Registry Configuration
```registry
[HKEY_LOCAL_MACHINE\SOFTWARE\ERDPS\Agent]
"MonitorPaths"=REG_MULTI_SZ:C:\Users\Documents\0C:\Users\Desktop
"EventBufferSize"=REG_DWORD:1000
"DeduplicationWindow"=REG_DWORD:200
```

### Linux

#### inotify Limitations
- **Watch Limits**: `/proc/sys/fs/inotify/max_user_watches`
- **Event Queue**: `/proc/sys/fs/inotify/max_queued_events`
- **Instance Limit**: `/proc/sys/fs/inotify/max_user_instances`

#### System Tuning
```bash
# Increase inotify limits
echo 524288 > /proc/sys/fs/inotify/max_user_watches
echo 16384 > /proc/sys/fs/inotify/max_queued_events
echo 128 > /proc/sys/fs/inotify/max_user_instances

# Make permanent
echo "fs.inotify.max_user_watches=524288" >> /etc/sysctl.conf
echo "fs.inotify.max_queued_events=16384" >> /etc/sysctl.conf
echo "fs.inotify.max_user_instances=128" >> /etc/sysctl.conf
```

#### Process Information
```rust
// Linux process info from /proc filesystem
if let Some(pid) = event.pid {
    let proc_path = format!("/proc/{}/comm", pid);
    if let Ok(name) = std::fs::read_to_string(proc_path) {
        event.process_name = Some(name.trim().to_string());
    }
}
```

## Monitoring and Diagnostics

### Health Checks

```rust
// Monitor health indicators
struct MonitorHealth {
    events_processed: u64,
    events_dropped: u64,
    last_event_time: Instant,
    watcher_errors: u64,
    channel_utilization: f32,
}

// Periodic health reporting
tokio::spawn(async move {
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    loop {
        interval.tick().await;
        report_health_metrics(&health).await;
    }
});
```

### Logging Configuration

```toml
# log4rs.yaml
appenders:
  file:
    kind: file
    path: "logs/monitor.log"
    encoder:
      pattern: "{d} [{l}] {t} - {m}{n}"

root:
  level: info
  appenders:
    - file

loggers:
  erdps_agent::monitor:
    level: debug
    appenders:
      - file
    additive: false
```

### Metrics Collection

- **Event Rate**: Events per second by type
- **Processing Latency**: Time from event to detection
- **Error Rate**: Failed event processing percentage
- **Resource Usage**: Memory and CPU consumption
- **Channel Backpressure**: Queue depth and blocking time

## Troubleshooting

### Common Issues

#### High CPU Usage
- **Cause**: Too many monitored paths or high file activity
- **Solution**: Reduce monitoring scope, increase deduplication window
- **Monitoring**: Check event rate and processing time

#### Memory Growth
- **Cause**: Event channel overflow or deduplication cache growth
- **Solution**: Tune channel size, implement cache limits
- **Monitoring**: Track memory usage and channel depth

#### Missing Events
- **Cause**: System limits exceeded or permissions issues
- **Solution**: Increase system limits, verify permissions
- **Monitoring**: Check for dropped events and error logs

#### Network Drive Issues
- **Cause**: Network latency or disconnections
- **Solution**: Implement retry logic, reduce monitoring frequency
- **Monitoring**: Track network-specific error rates

### Debug Mode

```rust
// Enable debug logging
std::env::set_var("RUST_LOG", "erdps_agent::monitor=debug");
env_logger::init();

// Debug event processing
log::debug!("Processing event: {:?}", event);
log::debug!("Deduplication cache size: {}", cache.len());
log::debug!("Channel utilization: {:.2}%", utilization);
```

## Best Practices

### Deployment
1. **Start Small**: Begin with critical directories only
2. **Monitor Performance**: Track resource usage during rollout
3. **Test Thoroughly**: Validate in staging environment
4. **Gradual Expansion**: Add monitoring paths incrementally
5. **Document Configuration**: Maintain deployment documentation

### Maintenance
1. **Regular Updates**: Keep notify crate and dependencies current
2. **Log Rotation**: Implement log rotation to prevent disk filling
3. **Performance Review**: Regularly review metrics and adjust
4. **Security Audits**: Periodic permission and access reviews
5. **Backup Configuration**: Maintain configuration backups

### Scaling
1. **Horizontal Scaling**: Deploy multiple agents for large environments
2. **Load Balancing**: Distribute monitoring across multiple instances
3. **Centralized Logging**: Aggregate logs for analysis
4. **Monitoring Monitoring**: Monitor the monitoring system itself
5. **Capacity Planning**: Plan for growth in file system activity

## Integration Examples

### Docker Deployment
```dockerfile
FROM rust:1.70 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bullseye-slim
RUN apt-get update && apt-get install -y ca-certificates
COPY --from=builder /app/target/release/erdps-agent /usr/local/bin/
COPY config/ /etc/erdps/
VOLUME ["/data"]
CMD ["erdps-agent", "--config", "/etc/erdps/agent.conf"]
```

### Kubernetes Deployment
```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: erdps-agent
spec:
  selector:
    matchLabels:
      app: erdps-agent
  template:
    metadata:
      labels:
        app: erdps-agent
    spec:
      containers:
      - name: erdps-agent
        image: erdps/agent:latest
        volumeMounts:
        - name: host-data
          mountPath: /data
          readOnly: true
        securityContext:
          privileged: false
          readOnlyRootFilesystem: true
      volumes:
      - name: host-data
        hostPath:
          path: /home
```

This guide provides the foundation for successful deployment and operation of the ERDPS file system monitoring component. Regular review and updates ensure optimal performance and security in production environments.