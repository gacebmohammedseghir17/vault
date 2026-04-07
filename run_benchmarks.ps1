#!/usr/bin/env pwsh
# IPC Benchmarks Runner Script
# This script runs comprehensive IPC benchmarks and generates performance reports

param(
    [string]$Filter = "",
    [switch]$Html,
    [switch]$Baseline,
    [string]$BaselineName = "main",
    [switch]$Compare,
    [string]$CompareTo = "main",
    [switch]$Quick,
    [switch]$Verbose
)

# Colors for output
$Red = "`e[31m"
$Green = "`e[32m"
$Yellow = "`e[33m"
$Blue = "`e[34m"
$Reset = "`e[0m"

function Write-ColorOutput {
    param([string]$Message, [string]$Color = $Reset)
    Write-Host "$Color$Message$Reset"
}

function Test-CargoCommand {
    try {
        cargo --version | Out-Null
        return $true
    } catch {
        return $false
    }
}

function Test-YaraFeature {
    $cargoToml = Get-Content "Cargo.toml" -Raw
    return $cargoToml -match 'yara.*=.*".*"'
}

# Main execution
Write-ColorOutput "🚀 ERDPS Agent IPC Benchmarks Runner" $Blue
Write-ColorOutput "======================================" $Blue

# Check prerequisites
if (-not (Test-CargoCommand)) {
    Write-ColorOutput "❌ Error: Cargo not found. Please install Rust toolchain." $Red
    exit 1
}

if (-not (Test-YaraFeature)) {
    Write-ColorOutput "⚠️  Warning: YARA feature not detected. Some benchmarks may fail." $Yellow
}

# Build benchmark configuration
$benchArgs = @("bench")

if ($Filter) {
    $benchArgs += "--bench", "ipc_benchmarks", "--", $Filter
} else {
    $benchArgs += "--bench", "ipc_benchmarks"
}

if ($Html) {
    $benchArgs += "--", "--output-format", "html"
}

if ($Quick) {
    $benchArgs += "--", "--quick"
}

if ($Verbose) {
    $benchArgs += "-v"
}

# Handle baseline operations
if ($Baseline) {
    Write-ColorOutput "📊 Creating baseline: $BaselineName" $Green
    $benchArgs += "--", "--save-baseline", $BaselineName
}

if ($Compare) {
    Write-ColorOutput "📈 Comparing against baseline: $CompareTo" $Green
    $benchArgs += "--", "--baseline", $CompareTo
}

# Set environment variables for benchmarks
$env:RUST_LOG = if ($Verbose) { "debug" } else { "info" }
$env:ERDPS_BENCH_MODE = "1"

Write-ColorOutput "🔧 Building benchmark dependencies..." $Yellow
try {
    cargo build --release --features production
    if ($LASTEXITCODE -ne 0) {
        Write-ColorOutput "❌ Build failed" $Red
        exit 1
    }
} catch {
    Write-ColorOutput "❌ Build error: $_" $Red
    exit 1
}

Write-ColorOutput "🏃 Running benchmarks..." $Green
Write-ColorOutput "Command: cargo $($benchArgs -join ' ')" $Blue

try {
    & cargo @benchArgs
    
    if ($LASTEXITCODE -eq 0) {
        Write-ColorOutput "✅ Benchmarks completed successfully!" $Green
        
        if ($Html) {
            $reportPath = "target/criterion/report/index.html"
            if (Test-Path $reportPath) {
                Write-ColorOutput "📊 HTML report generated: $reportPath" $Green
                Write-ColorOutput "💡 Open in browser: file:///$((Resolve-Path $reportPath).Path.Replace('\', '/'))" $Blue
            }
        }
        
        # Display summary
        Write-ColorOutput "`n📋 Benchmark Summary" $Blue
        Write-ColorOutput "==================" $Blue
        Write-ColorOutput "• File scan performance across different sizes" $Reset
        Write-ColorOutput "• Concurrent request handling capacity" $Reset
        Write-ColorOutput "• IPC command response times" $Reset
        Write-ColorOutput "• Message serialization/deserialization performance" $Reset
        Write-ColorOutput "• Network latency simulation results" $Reset
        
        if ($Baseline) {
            Write-ColorOutput "`n💾 Baseline '$BaselineName' saved for future comparisons" $Green
        }
        
        if ($Compare) {
            Write-ColorOutput "`n📊 Performance comparison against '$CompareTo' completed" $Green
        }
        
    } else {
        Write-ColorOutput "❌ Benchmarks failed with exit code: $LASTEXITCODE" $Red
        exit $LASTEXITCODE
    }
    
} catch {
    Write-ColorOutput "❌ Benchmark execution error: $_" $Red
    exit 1
}

# Cleanup
Remove-Item Env:ERDPS_BENCH_MODE -ErrorAction SilentlyContinue

Write-ColorOutput "`n🎉 Benchmark run completed!" $Green

# Usage examples
Write-ColorOutput "`n💡 Usage Examples:" $Blue
Write-ColorOutput "================" $Blue
Write-ColorOutput "• Run all benchmarks:           .\run_benchmarks.ps1" $Reset
Write-ColorOutput "• Run with HTML report:         .\run_benchmarks.ps1 -Html" $Reset
Write-ColorOutput "• Quick run (less samples):     .\run_benchmarks.ps1 -Quick" $Reset
Write-ColorOutput "• Filter specific benchmark:     .\run_benchmarks.ps1 -Filter 'file_scan'" $Reset
Write-ColorOutput "• Create baseline:               .\run_benchmarks.ps1 -Baseline -BaselineName 'v1.0'" $Reset
Write-ColorOutput "• Compare against baseline:      .\run_benchmarks.ps1 -Compare -CompareTo 'v1.0'" $Reset
Write-ColorOutput "• Verbose output:                .\run_benchmarks.ps1 -Verbose" $Reset