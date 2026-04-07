# Privileged CI Lane Documentation

## Overview

The privileged CI lane is a specialized testing environment designed to validate Windows service functionality that requires elevated privileges. This lane focuses on testing service lifecycle operations, Windows Service Control Manager (SCM) integration, and event log parsing capabilities that cannot be tested in standard CI environments.

### Purpose and Scope

- **Service Lifecycle Testing**: Install, start, stop, and delete Windows services
- **SCM Integration**: Validate Service Control Manager interactions
- **Event Log Validation**: Test event log parsing and monitoring
- **Privilege-dependent Features**: Test functionality requiring administrator access
- **Security Validation**: Ensure proper privilege handling and isolation

## Prerequisites

### System Requirements

- **Windows Server 2019** or later (recommended for CI runners)
- **Administrator privileges** on the test machine
- **Windows Service Control Manager** access
- **Event Log** read/write permissions
- **PowerShell 5.1** or later

### CI Runner Configuration

- Self-hosted GitHub Actions runner with administrator privileges
- Dedicated test environment (isolated from production)
- Proper network isolation and security controls
- Sufficient disk space for service binaries and logs

## Test Scenarios

### Service Lifecycle Tests

1. **Service Installation**
   - Install ERDPS agent as Windows service
   - Verify service registration in SCM
   - Validate service configuration parameters

2. **Service Start/Stop Operations**
   - Start service and verify running state
   - Stop service gracefully
   - Test service restart scenarios
   - Validate service dependencies

3. **Service Deletion**
   - Clean service removal from SCM
   - Verify complete cleanup of service artifacts
   - Test removal with running service (error handling)

### Event Log Integration Tests

1. **Event Log Parsing**
   - Test `get_service_logs` functionality
   - Validate log entry filtering and parsing
   - Test event correlation and analysis

2. **Log Monitoring**
   - Real-time log monitoring capabilities
   - Event-driven service responses
   - Log rotation and archival testing

## CI Workflow Design

### Nightly Schedule

```yaml
name: Privileged CI Lane

on:
  schedule:
    # Run nightly at 2 AM UTC
    - cron: '0 2 * * *'
  workflow_dispatch: # Allow manual triggering

jobs:
  privileged-tests:
    runs-on: [self-hosted, windows, privileged]
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        
      - name: Setup Rust
        uses: dtolnay/rust-toolchain@stable
        
      - name: Run privileged tests
        run: |
          # Set RUSTFLAGS for warnings as errors
          $env:RUSTFLAGS = "-D warnings"
          
          # Run service integration tests
          cargo test --test service_integration_tests --features testing,yara,service
          
          # Run SCM validation tests
          cargo test --test scm_validation_tests --features testing,service
          
          # Run event log tests
          cargo test --test event_log_tests --features testing,event_logs
```

### Privileged Runner Requirements

- **Self-hosted runner** with administrator privileges
- **Isolated environment** for security
- **Dedicated test machine** (not shared with other workloads)
- **Proper cleanup** between test runs
- **Security monitoring** and audit logging

## SCM Validation

### Service Control Manager Integration

```rust
// Example test for SCM integration
#[cfg(feature = "service")]
#[test]
fn test_service_scm_integration() {
    let service_name = "erdps-agent-test";
    let service_path = get_test_service_binary_path();
    
    // Install service
    let install_result = install_windows_service(service_name, &service_path);
    assert!(install_result.is_ok(), "Failed to install service");
    
    // Verify service exists in SCM
    let service_exists = check_service_exists(service_name);
    assert!(service_exists, "Service not found in SCM");
    
    // Start service
    let start_result = start_windows_service(service_name);
    assert!(start_result.is_ok(), "Failed to start service");
    
    // Verify service is running
    let service_status = get_service_status(service_name);
    assert_eq!(service_status, ServiceStatus::Running);
    
    // Stop and remove service
    stop_windows_service(service_name).expect("Failed to stop service");
    remove_windows_service(service_name).expect("Failed to remove service");
}
```

### Service Configuration Validation

- **Service parameters**: Validate startup type, dependencies, recovery options
- **Security context**: Test service account and privilege settings
- **Resource limits**: Verify memory and CPU constraints
- **Network access**: Test service network permissions

## Event Log Integration

### Using get_service_logs Functionality

```rust
// Example event log validation test
#[cfg(feature = "event_logs")]
#[test]
fn test_event_log_parsing() {
    let service_name = "erdps-agent-test";
    
    // Start service to generate events
    start_test_service(service_name);
    
    // Wait for service startup events
    std::thread::sleep(Duration::from_secs(5));
    
    // Get service logs
    let logs = get_service_logs(service_name, LogLevel::Info)
        .expect("Failed to retrieve service logs");
    
    // Validate startup events
    assert!(!logs.is_empty(), "No service logs found");
    
    let startup_events: Vec<_> = logs.iter()
        .filter(|log| log.message.contains("Service started"))
        .collect();
    
    assert!(!startup_events.is_empty(), "Service startup event not found");
    
    // Cleanup
    stop_and_remove_test_service(service_name);
}
```

### Event Log Categories

- **Service Lifecycle Events**: Start, stop, install, remove
- **Error Events**: Service failures, configuration errors
- **Security Events**: Privilege escalation, access violations
- **Performance Events**: Resource usage, performance metrics

## Security Considerations

### Privilege Escalation

- **Principle of Least Privilege**: Only request necessary permissions
- **Temporary Elevation**: Drop privileges after privileged operations
- **Audit Logging**: Log all privileged operations
- **Access Control**: Restrict access to privileged CI runners

### Test Isolation

- **Dedicated Test Environment**: Isolated from production systems
- **Clean State**: Reset environment between test runs
- **Resource Cleanup**: Ensure complete cleanup of test artifacts
- **Network Isolation**: Restrict network access during tests

### Security Best Practices

```yaml
# Security-focused CI configuration
env:
  # Restrict PowerShell execution policy
  POWERSHELL_EXECUTION_POLICY: "RemoteSigned"
  
  # Enable audit logging
  ENABLE_AUDIT_LOGGING: "true"
  
  # Set security context
  SERVICE_ACCOUNT: "NT AUTHORITY\LocalService"

steps:
  - name: Security pre-check
    run: |
      # Verify runner isolation
      Test-NetConnection -ComputerName "production-server" -Port 443 -InformationLevel Quiet
      if ($?) { throw "Runner not properly isolated" }
      
      # Check for existing test artifacts
      $testServices = Get-Service -Name "*erdps*test*" -ErrorAction SilentlyContinue
      if ($testServices) { throw "Previous test artifacts found" }
```

## Setup Instructions

### 1. Prepare Test Environment

```powershell
# Create dedicated test user (optional)
New-LocalUser -Name "erdps-ci-test" -Password (ConvertTo-SecureString "SecurePassword123!" -AsPlainText -Force)
Add-LocalGroupMember -Group "Administrators" -Member "erdps-ci-test"

# Create test directory
New-Item -Path "C:\erdps-ci-test" -ItemType Directory -Force

# Set permissions
$acl = Get-Acl "C:\erdps-ci-test"
$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("erdps-ci-test", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$acl.SetAccessRule($accessRule)
Set-Acl "C:\erdps-ci-test" $acl
```

### 2. Configure GitHub Actions Runner

```bash
# Download and configure self-hosted runner
./config.cmd --url https://github.com/your-org/erdps --token YOUR_TOKEN --labels windows,privileged

# Install as Windows service with administrator privileges
.\svc.cmd install
.\svc.cmd start
```

### 3. Validate Setup

```powershell
# Test service creation capabilities
$testServiceName = "erdps-setup-test"
New-Service -Name $testServiceName -BinaryPathName "C:\Windows\System32\svchost.exe" -StartupType Manual

# Verify service exists
$service = Get-Service -Name $testServiceName -ErrorAction SilentlyContinue
if (-not $service) {
    throw "Failed to create test service - insufficient privileges"
}

# Cleanup
Remove-Service -Name $testServiceName -Force
Write-Host "Setup validation successful"
```

## Troubleshooting

### Common Issues and Solutions

#### 1. Insufficient Privileges

**Problem**: Tests fail with "Access Denied" errors

**Solution**:
```powershell
# Verify runner is running as administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    throw "Runner must run with administrator privileges"
}

# Check service control permissions
$scmAccess = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services"
if (-not $scmAccess) {
    throw "No access to Service Control Manager"
}
```

#### 2. Service Installation Failures

**Problem**: Service fails to install or start

**Solution**:
```powershell
# Check service binary exists and is accessible
$binaryPath = "C:\path\to\erdps-agent.exe"
if (-not (Test-Path $binaryPath)) {
    throw "Service binary not found: $binaryPath"
}

# Verify binary permissions
$acl = Get-Acl $binaryPath
$hasExecutePermission = $acl.Access | Where-Object {
    $_.IdentityReference -eq "NT AUTHORITY\SYSTEM" -and
    $_.FileSystemRights -match "Execute"
}

if (-not $hasExecutePermission) {
    throw "Service binary lacks execute permissions for SYSTEM account"
}
```

#### 3. Event Log Access Issues

**Problem**: Cannot read service event logs

**Solution**:
```powershell
# Check event log permissions
$logName = "Application"
$eventLog = Get-WinEvent -ListLog $logName -ErrorAction SilentlyContinue
if (-not $eventLog) {
    throw "Cannot access $logName event log"
}

# Verify log reading permissions
try {
    Get-WinEvent -LogName $logName -MaxEvents 1 | Out-Null
    Write-Host "Event log access verified"
} catch {
    throw "Insufficient permissions to read event logs: $_"
}
```

#### 4. Test Environment Cleanup

**Problem**: Previous test artifacts interfere with new tests

**Solution**:
```powershell
# Comprehensive cleanup script
function Clear-TestEnvironment {
    # Stop and remove test services
    Get-Service -Name "*erdps*test*" -ErrorAction SilentlyContinue | ForEach-Object {
        Stop-Service $_.Name -Force -ErrorAction SilentlyContinue
        Remove-Service $_.Name -Force -ErrorAction SilentlyContinue
    }
    
    # Clean test directories
    Remove-Item "C:\erdps-ci-test\*" -Recurse -Force -ErrorAction SilentlyContinue
    
    # Clear event logs (optional)
    Clear-EventLog -LogName Application -ErrorAction SilentlyContinue
    
    Write-Host "Test environment cleaned"
}

# Run cleanup before each test
Clear-TestEnvironment
```

## Example Workflows

### Complete GitHub Actions Workflow

```yaml
name: Privileged CI Lane - Full Suite

on:
  schedule:
    - cron: '0 2 * * *'  # Nightly at 2 AM UTC
  workflow_dispatch:
    inputs:
      test_suite:
        description: 'Test suite to run'
        required: false
        default: 'all'
        type: choice
        options:
          - all
          - service_lifecycle
          - event_logs
          - scm_integration

jobs:
  privileged-tests:
    runs-on: [self-hosted, windows, privileged]
    timeout-minutes: 60
    
    env:
      RUSTFLAGS: "-D warnings"
      RUST_BACKTRACE: "1"
      TEST_SERVICE_NAME: "erdps-agent-ci-test"
      
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
        
      - name: Setup Rust toolchain
        uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt, clippy
          
      - name: Verify privileged environment
        run: |
          # Check administrator privileges
          if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
              throw "Tests require administrator privileges"
          }
          
          # Verify SCM access
          try {
              Get-Service | Select-Object -First 1 | Out-Null
              Write-Host "✓ Service Control Manager access verified"
          } catch {
              throw "Cannot access Service Control Manager: $_"
          }
          
          # Check event log access
          try {
              Get-WinEvent -ListLog Application | Out-Null
              Write-Host "✓ Event log access verified"
          } catch {
              throw "Cannot access event logs: $_"
          }
          
      - name: Clean test environment
        run: |
          # Remove any existing test services
          Get-Service -Name "*erdps*test*" -ErrorAction SilentlyContinue | ForEach-Object {
              Write-Host "Cleaning up service: $($_.Name)"
              Stop-Service $_.Name -Force -ErrorAction SilentlyContinue
              sc.exe delete $_.Name
          }
          
          # Clean test directories
          if (Test-Path "C:\erdps-ci-test") {
              Remove-Item "C:\erdps-ci-test" -Recurse -Force
          }
          New-Item -Path "C:\erdps-ci-test" -ItemType Directory -Force
          
      - name: Build project
        run: |
          cargo build --release --features yara,service,event_logs
          
      - name: Run service lifecycle tests
        if: ${{ github.event.inputs.test_suite == 'all' || github.event.inputs.test_suite == 'service_lifecycle' }}
        run: |
          cargo test --test service_lifecycle_tests --features testing,yara,service --release -- --nocapture
          
      - name: Run SCM integration tests
        if: ${{ github.event.inputs.test_suite == 'all' || github.event.inputs.test_suite == 'scm_integration' }}
        run: |
          cargo test --test scm_integration_tests --features testing,service --release -- --nocapture
          
      - name: Run event log tests
        if: ${{ github.event.inputs.test_suite == 'all' || github.event.inputs.test_suite == 'event_logs' }}
        run: |
          cargo test --test event_log_tests --features testing,event_logs --release -- --nocapture
          
      - name: Generate test report
        if: always()
        run: |
          # Collect test artifacts
          $reportPath = "C:\erdps-ci-test\test-report.txt"
          
          "Privileged CI Test Report" | Out-File $reportPath
          "Generated: $(Get-Date)" | Out-File $reportPath -Append
          "" | Out-File $reportPath -Append
          
          # Service status
          "=== Service Status ===" | Out-File $reportPath -Append
          Get-Service -Name "*erdps*" -ErrorAction SilentlyContinue | Out-File $reportPath -Append
          
          # Event log summary
          "=== Recent Event Log Entries ===" | Out-File $reportPath -Append
          Get-WinEvent -LogName Application -MaxEvents 10 -ErrorAction SilentlyContinue | 
              Where-Object { $_.ProviderName -like "*erdps*" } | 
              Out-File $reportPath -Append
              
      - name: Upload test artifacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: privileged-test-results
          path: |
            C:\erdps-ci-test\test-report.txt
            target\debug\deps\*.exe
            
      - name: Final cleanup
        if: always()
        run: |
          # Ensure complete cleanup
          Get-Service -Name "*erdps*test*" -ErrorAction SilentlyContinue | ForEach-Object {
              Stop-Service $_.Name -Force -ErrorAction SilentlyContinue
              sc.exe delete $_.Name
          }
          
          # Clean test directories
          Remove-Item "C:\erdps-ci-test" -Recurse -Force -ErrorAction SilentlyContinue
          
          Write-Host "Cleanup completed"
```

### Azure DevOps Pipeline Example

```yaml
trigger: none

schedules:
- cron: "0 2 * * *"
  displayName: Nightly privileged tests
  branches:
    include:
    - main
  always: true

pool:
  name: 'Privileged-Windows-Pool'
  demands:
  - agent.os -equals Windows_NT
  - privileged -equals true

variables:
  RUSTFLAGS: '-D warnings'
  RUST_BACKTRACE: '1'

stages:
- stage: PrivilegedTests
  displayName: 'Privileged CI Tests'
  jobs:
  - job: ServiceTests
    displayName: 'Service Integration Tests'
    timeoutInMinutes: 60
    
    steps:
    - checkout: self
      displayName: 'Checkout source'
      
    - task: PowerShell@2
      displayName: 'Verify privileged environment'
      inputs:
        targetType: 'inline'
        script: |
          if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
              throw "Agent must run with administrator privileges"
          }
          Write-Host "✓ Administrator privileges verified"
          
    - task: PowerShell@2
      displayName: 'Setup Rust'
      inputs:
        targetType: 'inline'
        script: |
          rustup update stable
          rustup default stable
          rustc --version
          cargo --version
          
    - task: PowerShell@2
      displayName: 'Run privileged tests'
      inputs:
        targetType: 'inline'
        script: |
          # Build with all features
          cargo build --release --features yara,service,event_logs
          
          # Run test suites
          cargo test --test service_lifecycle_tests --features testing,yara,service --release
          cargo test --test scm_integration_tests --features testing,service --release
          cargo test --test event_log_tests --features testing,event_logs --release
          
    - task: PublishTestResults@2
      displayName: 'Publish test results'
      condition: always()
      inputs:
        testResultsFormat: 'JUnit'
        testResultsFiles: 'target/test-results.xml'
        failTaskOnFailedTests: true
```

## Maintenance and Updates

### Regular Maintenance Tasks

1. **Runner Health Checks**
   - Verify administrator privileges
   - Check disk space and system resources
   - Update Windows and security patches
   - Validate network isolation

2. **Test Environment Refresh**
   - Clean accumulated test artifacts
   - Reset service configurations
   - Update test data and scenarios
   - Verify security configurations

3. **Documentation Updates**
   - Update test scenarios for new features
   - Refresh troubleshooting guides
   - Document new security requirements
   - Update example workflows

### Monitoring and Alerting

```yaml
# Example monitoring configuration
monitoring:
  alerts:
    - name: "Privileged CI Failure"
      condition: "test_failure_rate > 10%"
      notification: "team-security@company.com"
      
    - name: "Security Violation"
      condition: "unauthorized_privilege_escalation"
      notification: "security-team@company.com"
      severity: "critical"
      
  metrics:
    - test_execution_time
    - service_installation_success_rate
    - event_log_parsing_accuracy
    - cleanup_completion_rate
```

This documentation provides a comprehensive guide for implementing and maintaining privileged CI testing for the ERDPS agent, ensuring robust validation of Windows service functionality while maintaining security best practices.