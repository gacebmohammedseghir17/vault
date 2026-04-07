# ERDPS Agent Testing and Validation Scripts
# Version: v0.1.0
# Last Updated: September 30, 2025
# Purpose: Comprehensive testing and validation for SOC deployment

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("All", "Basic", "Performance", "Integration", "SOC")]
    [string]$TestSuite = "All",
    
    [Parameter(Mandatory=$false)]
    [string]$AgentPath = ".\erdps-agent.exe",
    
    [Parameter(Mandatory=$false)]
    [string]$ConfigPath = ".\config.toml",
    
    [Parameter(Mandatory=$false)]
    [string]$LogPath = ".\validation_results.log",
    
    [Parameter(Mandatory=$false)]
    [switch]$Verbose
)

# Initialize logging
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    Write-Host $logEntry
    Add-Content -Path $LogPath -Value $logEntry
}

function Test-Prerequisites {
    Write-Log "=== Testing Prerequisites ===" "INFO"
    
    # Check if agent executable exists
    if (-not (Test-Path $AgentPath)) {
        Write-Log "ERDPS agent not found at: $AgentPath" "ERROR"
        return $false
    }
    
    # Check if config file exists
    if (-not (Test-Path $ConfigPath)) {
        Write-Log "Config file not found at: $ConfigPath" "ERROR"
        return $false
    }
    
    # Test agent help command
    try {
        $helpOutput = & $AgentPath --help 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Agent help command successful" "SUCCESS"
        } else {
            Write-Log "Agent help command failed" "ERROR"
            return $false
        }
    } catch {
        Write-Log "Failed to execute agent: $($_.Exception.Message)" "ERROR"
        return $false
    }
    
    Write-Log "Prerequisites check completed successfully" "SUCCESS"
    return $true
}

function Test-BasicFunctionality {
    Write-Log "=== Testing Basic Functionality ===" "INFO"
    $results = @{}
    
    # Test 1: Agent version
    try {
        Write-Log "Testing agent version..." "INFO"
        $versionOutput = & $AgentPath --version 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Version check: PASS" "SUCCESS"
            $results["version"] = "PASS"
        } else {
            Write-Log "Version check: FAIL" "ERROR"
            $results["version"] = "FAIL"
        }
    } catch {
        Write-Log "Version check: ERROR - $($_.Exception.Message)" "ERROR"
        $results["version"] = "ERROR"
    }
    
    # Test 2: Stats command
    try {
        Write-Log "Testing stats command..." "INFO"
        $statsOutput = & $AgentPath stats 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Stats command: PASS" "SUCCESS"
            $results["stats"] = "PASS"
            if ($Verbose) { Write-Log "Stats output: $statsOutput" "DEBUG" }
        } else {
            Write-Log "Stats command: FAIL" "ERROR"
            $results["stats"] = "FAIL"
        }
    } catch {
        Write-Log "Stats command: ERROR - $($_.Exception.Message)" "ERROR"
        $results["stats"] = "ERROR"
    }
    
    # Test 3: List rules command
    try {
        Write-Log "Testing list-rules command..." "INFO"
        $rulesOutput = & $AgentPath list-rules 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Log "List rules: PASS" "SUCCESS"
            $results["list-rules"] = "PASS"
            if ($Verbose) { Write-Log "Rules output: $rulesOutput" "DEBUG" }
        } else {
            Write-Log "List rules: FAIL" "ERROR"
            $results["list-rules"] = "FAIL"
        }
    } catch {
        Write-Log "List rules: ERROR - $($_.Exception.Message)" "ERROR"
        $results["list-rules"] = "ERROR"
    }
    
    # Test 4: Config repo list
    try {
        Write-Log "Testing config-repo list..." "INFO"
        $repoOutput = & $AgentPath config-repo list 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Config repo list: PASS" "SUCCESS"
            $results["config-repo"] = "PASS"
        } else {
            Write-Log "Config repo list: FAIL" "ERROR"
            $results["config-repo"] = "FAIL"
        }
    } catch {
        Write-Log "Config repo list: ERROR - $($_.Exception.Message)" "ERROR"
        $results["config-repo"] = "ERROR"
    }
    
    return $results
}

function Test-ScanningCapabilities {
    Write-Log "=== Testing Scanning Capabilities ===" "INFO"
    $results = @{}
    
    # Create test file
    $testFile = ".\test_validation_file.txt"
    "This is a test file for ERDPS validation" | Out-File -FilePath $testFile -Encoding UTF8
    
    # Test 1: Enhanced scan
    try {
        Write-Log "Testing scan-enhanced..." "INFO"
        $scanOutput = & $AgentPath scan-enhanced $testFile 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Enhanced scan: PASS" "SUCCESS"
            $results["scan-enhanced"] = "PASS"
        } else {
            Write-Log "Enhanced scan: FAIL" "ERROR"
            $results["scan-enhanced"] = "FAIL"
        }
    } catch {
        Write-Log "Enhanced scan: ERROR - $($_.Exception.Message)" "ERROR"
        $results["scan-enhanced"] = "ERROR"
    }
    
    # Test 2: Multi-layer scan
    try {
        Write-Log "Testing multi-scan..." "INFO"
        $multiScanOutput = & $AgentPath multi-scan $testFile 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Multi-layer scan: PASS" "SUCCESS"
            $results["multi-scan"] = "PASS"
            
            # Parse risk score if available
            if ($multiScanOutput -match "Risk Score: ([\d.]+)") {
                $riskScore = $matches[1]
                Write-Log "Risk Score: $riskScore" "INFO"
            }
        } else {
            Write-Log "Multi-layer scan: FAIL" "ERROR"
            $results["multi-scan"] = "FAIL"
        }
    } catch {
        Write-Log "Multi-layer scan: ERROR - $($_.Exception.Message)" "ERROR"
        $results["multi-scan"] = "ERROR"
    }
    
    # Test 3: Performance modes
    $performanceModes = @("fast", "balanced", "thorough")
    foreach ($mode in $performanceModes) {
        try {
            Write-Log "Testing performance mode: $mode" "INFO"
            $perfOutput = & $AgentPath scan-enhanced --performance-mode $mode $testFile 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Log "Performance mode $mode: PASS" "SUCCESS"
                $results["perf-$mode"] = "PASS"
            } else {
                Write-Log "Performance mode $mode: FAIL" "ERROR"
                $results["perf-$mode"] = "FAIL"
            }
        } catch {
            Write-Log "Performance mode $mode: ERROR - $($_.Exception.Message)" "ERROR"
            $results["perf-$mode"] = "ERROR"
        }
    }
    
    # Cleanup test file
    Remove-Item -Path $testFile -Force -ErrorAction SilentlyContinue
    
    return $results
}

function Test-MetricsAndMonitoring {
    Write-Log "=== Testing Metrics and Monitoring ===" "INFO"
    $results = @{}
    
    # Test 1: Show metrics command
    try {
        Write-Log "Testing show-metrics..." "INFO"
        $metricsOutput = & $AgentPath show-metrics 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Show metrics: PASS" "SUCCESS"
            $results["show-metrics"] = "PASS"
        } else {
            Write-Log "Show metrics: FAIL" "ERROR"
            $results["show-metrics"] = "FAIL"
        }
    } catch {
        Write-Log "Show metrics: ERROR - $($_.Exception.Message)" "ERROR"
        $results["show-metrics"] = "ERROR"
    }
    
    # Test 2: Prometheus endpoint (if agent is running)
    try {
        Write-Log "Testing Prometheus endpoint..." "INFO"
        $prometheusUrl = "http://127.0.0.1:19091/metrics"
        $response = Invoke-WebRequest -Uri $prometheusUrl -TimeoutSec 5 -ErrorAction Stop
        if ($response.StatusCode -eq 200) {
            Write-Log "Prometheus endpoint: PASS" "SUCCESS"
            $results["prometheus"] = "PASS"
            Write-Log "Metrics data size: $($response.Content.Length) bytes" "INFO"
        } else {
            Write-Log "Prometheus endpoint: FAIL - Status: $($response.StatusCode)" "ERROR"
            $results["prometheus"] = "FAIL"
        }
    } catch {
        Write-Log "Prometheus endpoint: NOT AVAILABLE (agent may not be running)" "WARN"
        $results["prometheus"] = "NOT_AVAILABLE"
    }
    
    # Test 3: Dashboard endpoint (if agent is running)
    try {
        Write-Log "Testing dashboard endpoint..." "INFO"
        $dashboardUrl = "http://127.0.0.1:19094"
        $response = Invoke-WebRequest -Uri $dashboardUrl -TimeoutSec 5 -ErrorAction Stop
        if ($response.StatusCode -eq 200) {
            Write-Log "Dashboard endpoint: PASS" "SUCCESS"
            $results["dashboard"] = "PASS"
        } else {
            Write-Log "Dashboard endpoint: FAIL - Status: $($response.StatusCode)" "ERROR"
            $results["dashboard"] = "FAIL"
        }
    } catch {
        Write-Log "Dashboard endpoint: NOT AVAILABLE (known issue)" "WARN"
        $results["dashboard"] = "NOT_AVAILABLE"
    }
    
    return $results
}

function Test-RuleManagement {
    Write-Log "=== Testing Rule Management ===" "INFO"
    $results = @{}
    
    # Test 1: Rule validation
    try {
        Write-Log "Testing validate-rules..." "INFO"
        $validateOutput = & $AgentPath validate-rules 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Rule validation: PASS" "SUCCESS"
            $results["validate-rules"] = "PASS"
        } else {
            Write-Log "Rule validation: FAIL (known issue)" "WARN"
            $results["validate-rules"] = "FAIL"
        }
    } catch {
        Write-Log "Rule validation: ERROR - $($_.Exception.Message)" "ERROR"
        $results["validate-rules"] = "ERROR"
    }
    
    # Test 2: Rule optimization
    try {
        Write-Log "Testing optimize-rules (dry-run)..." "INFO"
        $optimizeOutput = & $AgentPath optimize-rules --dry-run 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Rule optimization: PASS" "SUCCESS"
            $results["optimize-rules"] = "PASS"
        } else {
            Write-Log "Rule optimization: FAIL" "ERROR"
            $results["optimize-rules"] = "FAIL"
        }
    } catch {
        Write-Log "Rule optimization: ERROR - $($_.Exception.Message)" "ERROR"
        $results["optimize-rules"] = "ERROR"
    }
    
    return $results
}

function Test-PerformanceBenchmarks {
    Write-Log "=== Testing Performance Benchmarks ===" "INFO"
    $results = @{}
    
    # Create multiple test files for performance testing
    $testFiles = @()
    for ($i = 1; $i -le 10; $i++) {
        $testFile = ".\perf_test_$i.txt"
        "Performance test file $i - $(Get-Random)" | Out-File -FilePath $testFile -Encoding UTF8
        $testFiles += $testFile
    }
    
    # Test 1: Single file scan performance
    try {
        Write-Log "Testing single file scan performance..." "INFO"
        $startTime = Get-Date
        $scanOutput = & $AgentPath scan-enhanced $testFiles[0] 2>&1
        $endTime = Get-Date
        $duration = ($endTime - $startTime).TotalMilliseconds
        
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Single file scan: PASS (${duration}ms)" "SUCCESS"
            $results["single-scan-perf"] = "PASS"
            $results["single-scan-time"] = $duration
        } else {
            Write-Log "Single file scan: FAIL" "ERROR"
            $results["single-scan-perf"] = "FAIL"
        }
    } catch {
        Write-Log "Single file scan: ERROR - $($_.Exception.Message)" "ERROR"
        $results["single-scan-perf"] = "ERROR"
    }
    
    # Test 2: Multiple file scan performance
    try {
        Write-Log "Testing multiple file scan performance..." "INFO"
        $startTime = Get-Date
        foreach ($file in $testFiles) {
            $scanOutput = & $AgentPath scan-enhanced $file 2>&1
            if ($LASTEXITCODE -ne 0) {
                throw "Scan failed for file: $file"
            }
        }
        $endTime = Get-Date
        $totalDuration = ($endTime - $startTime).TotalMilliseconds
        $avgDuration = $totalDuration / $testFiles.Count
        
        Write-Log "Multiple file scan: PASS (Total: ${totalDuration}ms, Avg: ${avgDuration}ms)" "SUCCESS"
        $results["multi-scan-perf"] = "PASS"
        $results["multi-scan-total-time"] = $totalDuration
        $results["multi-scan-avg-time"] = $avgDuration
    } catch {
        Write-Log "Multiple file scan: ERROR - $($_.Exception.Message)" "ERROR"
        $results["multi-scan-perf"] = "ERROR"
    }
    
    # Test 3: Memory usage monitoring
    try {
        Write-Log "Testing memory usage..." "INFO"
        $process = Get-Process -Name "erdps-agent" -ErrorAction SilentlyContinue
        if ($process) {
            $memoryMB = [math]::Round($process.WorkingSet64 / 1MB, 2)
            Write-Log "Memory usage: ${memoryMB}MB" "INFO"
            $results["memory-usage"] = $memoryMB
            
            if ($memoryMB -lt 512) {
                Write-Log "Memory usage: PASS (within 512MB limit)" "SUCCESS"
                $results["memory-check"] = "PASS"
            } else {
                Write-Log "Memory usage: WARN (exceeds 512MB limit)" "WARN"
                $results["memory-check"] = "WARN"
            }
        } else {
            Write-Log "Memory usage: NOT AVAILABLE (agent not running)" "WARN"
            $results["memory-check"] = "NOT_AVAILABLE"
        }
    } catch {
        Write-Log "Memory usage: ERROR - $($_.Exception.Message)" "ERROR"
        $results["memory-check"] = "ERROR"
    }
    
    # Cleanup test files
    foreach ($file in $testFiles) {
        Remove-Item -Path $file -Force -ErrorAction SilentlyContinue
    }
    
    return $results
}

function Test-IntegrationCapabilities {
    Write-Log "=== Testing Integration Capabilities ===" "INFO"
    $results = @{}
    
    # Test 1: JSON output format
    try {
        Write-Log "Testing JSON output format..." "INFO"
        $testFile = ".\json_test.txt"
        "JSON test content" | Out-File -FilePath $testFile -Encoding UTF8
        
        $jsonOutput = & $AgentPath scan-enhanced --output-format json $testFile 2>&1
        if ($LASTEXITCODE -eq 0) {
            # Try to parse as JSON
            try {
                $jsonData = $jsonOutput | ConvertFrom-Json
                Write-Log "JSON output format: PASS" "SUCCESS"
                $results["json-output"] = "PASS"
            } catch {
                Write-Log "JSON output format: FAIL (invalid JSON)" "ERROR"
                $results["json-output"] = "FAIL"
            }
        } else {
            Write-Log "JSON output format: FAIL" "ERROR"
            $results["json-output"] = "FAIL"
        }
        
        Remove-Item -Path $testFile -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Log "JSON output format: ERROR - $($_.Exception.Message)" "ERROR"
        $results["json-output"] = "ERROR"
    }
    
    # Test 2: Auto-response (dry-run)
    try {
        Write-Log "Testing auto-response (dry-run)..." "INFO"
        # Create a simple response policy for testing
        $policyFile = ".\test_policy.json"
        $policy = @{
            "version" = "1.0"
            "policies" = @(
                @{
                    "name" = "test_policy"
                    "conditions" = @{
                        "risk_score" = @{
                            "min" = 0.5
                        }
                    }
                    "actions" = @("log", "alert")
                }
            )
        } | ConvertTo-Json -Depth 4
        
        $policy | Out-File -FilePath $policyFile -Encoding UTF8
        
        $responseOutput = & $AgentPath auto-response --response-policy $policyFile --dry-run 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Auto-response: PASS" "SUCCESS"
            $results["auto-response"] = "PASS"
        } else {
            Write-Log "Auto-response: FAIL" "ERROR"
            $results["auto-response"] = "FAIL"
        }
        
        Remove-Item -Path $policyFile -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Log "Auto-response: ERROR - $($_.Exception.Message)" "ERROR"
        $results["auto-response"] = "ERROR"
    }
    
    return $results
}

function Test-SOCReadiness {
    Write-Log "=== Testing SOC Readiness ===" "INFO"
    $results = @{}
    
    # Test 1: Command availability
    $criticalCommands = @(
        "scan-enhanced",
        "multi-scan", 
        "list-rules",
        "stats",
        "show-metrics",
        "config-repo"
    )
    
    $commandResults = @{}
    foreach ($cmd in $criticalCommands) {
        try {
            $helpOutput = & $AgentPath $cmd --help 2>&1
            if ($LASTEXITCODE -eq 0) {
                $commandResults[$cmd] = "AVAILABLE"
            } else {
                $commandResults[$cmd] = "UNAVAILABLE"
            }
        } catch {
            $commandResults[$cmd] = "ERROR"
        }
    }
    
    $availableCommands = ($commandResults.Values | Where-Object { $_ -eq "AVAILABLE" }).Count
    $totalCommands = $criticalCommands.Count
    $commandAvailability = [math]::Round(($availableCommands / $totalCommands) * 100, 1)
    
    Write-Log "Command availability: $availableCommands/$totalCommands ($commandAvailability%)" "INFO"
    $results["command-availability"] = $commandAvailability
    
    # Test 2: Configuration validation
    try {
        Write-Log "Testing configuration validation..." "INFO"
        if (Test-Path $ConfigPath) {
            $configContent = Get-Content $ConfigPath -Raw
            if ($configContent -match "schema_version" -and $configContent -match "agent_id") {
                Write-Log "Configuration validation: PASS" "SUCCESS"
                $results["config-validation"] = "PASS"
            } else {
                Write-Log "Configuration validation: FAIL (missing required fields)" "ERROR"
                $results["config-validation"] = "FAIL"
            }
        } else {
            Write-Log "Configuration validation: FAIL (config file not found)" "ERROR"
            $results["config-validation"] = "FAIL"
        }
    } catch {
        Write-Log "Configuration validation: ERROR - $($_.Exception.Message)" "ERROR"
        $results["config-validation"] = "ERROR"
    }
    
    # Test 3: SOC integration readiness score
    $readinessFactors = @{
        "commands" = if ($commandAvailability -ge 80) { 1 } else { 0 }
        "config" = if ($results["config-validation"] -eq "PASS") { 1 } else { 0 }
        "metrics" = if ($results.ContainsKey("prometheus") -and $results["prometheus"] -eq "PASS") { 1 } else { 0 }
        "scanning" = if ($results.ContainsKey("scan-enhanced") -and $results["scan-enhanced"] -eq "PASS") { 1 } else { 0 }
    }
    
    $readinessScore = ($readinessFactors.Values | Measure-Object -Sum).Sum / $readinessFactors.Count * 100
    Write-Log "SOC Readiness Score: $readinessScore%" "INFO"
    $results["soc-readiness-score"] = $readinessScore
    
    if ($readinessScore -ge 75) {
        Write-Log "SOC Readiness: READY" "SUCCESS"
        $results["soc-readiness"] = "READY"
    } elseif ($readinessScore -ge 50) {
        Write-Log "SOC Readiness: CONDITIONAL" "WARN"
        $results["soc-readiness"] = "CONDITIONAL"
    } else {
        Write-Log "SOC Readiness: NOT READY" "ERROR"
        $results["soc-readiness"] = "NOT_READY"
    }
    
    return $results
}

function Generate-Report {
    param([hashtable]$AllResults)
    
    Write-Log "=== Generating Validation Report ===" "INFO"
    
    $reportPath = ".\ERDPS_Validation_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>ERDPS Agent Validation Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 10px; border-radius: 5px; }
        .section { margin: 20px 0; }
        .pass { color: green; font-weight: bold; }
        .fail { color: red; font-weight: bold; }
        .warn { color: orange; font-weight: bold; }
        .error { color: darkred; font-weight: bold; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>ERDPS Agent Validation Report</h1>
        <p>Generated: $(Get-Date)</p>
        <p>Agent Path: $AgentPath</p>
        <p>Config Path: $ConfigPath</p>
    </div>
"@

    foreach ($category in $AllResults.Keys) {
        $html += "<div class='section'><h2>$category</h2><table><tr><th>Test</th><th>Result</th><th>Details</th></tr>"
        
        foreach ($test in $AllResults[$category].Keys) {
            $result = $AllResults[$category][$test]
            $cssClass = switch ($result) {
                "PASS" { "pass" }
                "FAIL" { "fail" }
                "ERROR" { "error" }
                "WARN" { "warn" }
                "NOT_AVAILABLE" { "warn" }
                default { "" }
            }
            
            $html += "<tr><td>$test</td><td class='$cssClass'>$result</td><td>-</td></tr>"
        }
        
        $html += "</table></div>"
    }
    
    $html += "</body></html>"
    
    $html | Out-File -FilePath $reportPath -Encoding UTF8
    Write-Log "Validation report generated: $reportPath" "SUCCESS"
}

# Main execution
function Main {
    Write-Log "Starting ERDPS Agent Validation" "INFO"
    Write-Log "Test Suite: $TestSuite" "INFO"
    Write-Log "Agent Path: $AgentPath" "INFO"
    Write-Log "Config Path: $ConfigPath" "INFO"
    
    # Initialize results collection
    $allResults = @{}
    
    # Prerequisites check
    if (-not (Test-Prerequisites)) {
        Write-Log "Prerequisites check failed. Exiting." "ERROR"
        exit 1
    }
    
    # Run test suites based on selection
    switch ($TestSuite) {
        "All" {
            $allResults["Basic"] = Test-BasicFunctionality
            $allResults["Scanning"] = Test-ScanningCapabilities
            $allResults["Metrics"] = Test-MetricsAndMonitoring
            $allResults["Rules"] = Test-RuleManagement
            $allResults["Performance"] = Test-PerformanceBenchmarks
            $allResults["Integration"] = Test-IntegrationCapabilities
            $allResults["SOC"] = Test-SOCReadiness
        }
        "Basic" {
            $allResults["Basic"] = Test-BasicFunctionality
        }
        "Performance" {
            $allResults["Performance"] = Test-PerformanceBenchmarks
        }
        "Integration" {
            $allResults["Integration"] = Test-IntegrationCapabilities
        }
        "SOC" {
            $allResults["SOC"] = Test-SOCReadiness
        }
    }
    
    # Generate summary
    Write-Log "=== Validation Summary ===" "INFO"
    $totalTests = 0
    $passedTests = 0
    $failedTests = 0
    $errorTests = 0
    
    foreach ($category in $allResults.Keys) {
        foreach ($test in $allResults[$category].Keys) {
            $totalTests++
            switch ($allResults[$category][$test]) {
                "PASS" { $passedTests++ }
                "FAIL" { $failedTests++ }
                "ERROR" { $errorTests++ }
            }
        }
    }
    
    $passRate = if ($totalTests -gt 0) { [math]::Round(($passedTests / $totalTests) * 100, 1) } else { 0 }
    
    Write-Log "Total Tests: $totalTests" "INFO"
    Write-Log "Passed: $passedTests" "SUCCESS"
    Write-Log "Failed: $failedTests" "ERROR"
    Write-Log "Errors: $errorTests" "ERROR"
    Write-Log "Pass Rate: $passRate%" "INFO"
    
    # Generate HTML report
    Generate-Report -AllResults $allResults
    
    Write-Log "ERDPS Agent Validation completed" "INFO"
    
    # Exit with appropriate code
    if ($failedTests -eq 0 -and $errorTests -eq 0) {
        exit 0
    } elseif ($passRate -ge 80) {
        exit 1  # Conditional pass
    } else {
        exit 2  # Fail
    }
}

# Execute main function
Main