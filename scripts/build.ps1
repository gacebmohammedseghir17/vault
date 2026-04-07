#
# ERDPS Agent Build Script for Windows
#
# This PowerShell script automates the build process for the ERDPS Agent with YARA scanner support on Windows.
# It handles dependency detection, environment setup, and cross-compilation.
#
# Usage:
#   .\scripts\build.ps1 [BuildType] [Target] [Features]
#
# Examples:
#   .\scripts\build.ps1                                      # Default: release native yara,production
#   .\scripts\build.ps1 debug                               # Debug build
#   .\scripts\build.ps1 release x86_64-unknown-linux-gnu   # Cross-compile to Linux
#   .\scripts\build.ps1 release native "yara,production"     # Explicit features

[CmdletBinding()]
param(
    [Parameter(Position=0)]
    [ValidateSet("debug", "release")]
    [string]$BuildType = "release",
    
    [Parameter(Position=1)]
    [string]$Target = "native",
    
    [Parameter(Position=2)]
    [string]$Features = "yara,production"
)

# Configuration
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir

# Colors for output
$Colors = @{
    Red = "Red"
    Green = "Green"
    Yellow = "Yellow"
    Blue = "Blue"
    Cyan = "Cyan"
}

# Logging functions
function Write-LogInfo {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor $Colors.Blue
}

function Write-LogWarn {
    param([string]$Message)
    Write-Host "[WARN] $Message" -ForegroundColor $Colors.Yellow
}

function Write-LogError {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor $Colors.Red
}

function Write-LogSuccess {
    param([string]$Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor $Colors.Green
}

# Check if command exists
function Test-Command {
    param([string]$Command)
    $null -ne (Get-Command $Command -ErrorAction SilentlyContinue)
}

# Get Windows architecture
function Get-WindowsArchitecture {
    $arch = $env:PROCESSOR_ARCHITECTURE
    switch ($arch) {
        "AMD64" { return "x86_64" }
        "ARM64" { return "aarch64" }
        "x86" { return "i686" }
        default { return "unknown" }
    }
}

# Check Rust installation
function Test-RustInstallation {
    Write-LogInfo "Checking Rust installation..."
    
    if (-not (Test-Command "rustc")) {
        Write-LogError "Rust is not installed. Please install Rust from https://rustup.rs/"
        exit 1
    }
    
    $rustVersion = (rustc --version).Split(' ')[1]
    Write-LogInfo "Found Rust version: $rustVersion"
    
    # Check minimum Rust version (1.70.0)
    $minVersion = [Version]"1.70.0"
    $currentVersion = [Version]$rustVersion
    
    if ($currentVersion -lt $minVersion) {
        Write-LogWarn "Rust version $rustVersion is older than recommended minimum $minVersion"
    }
}

# Check and install Rust target
function Install-RustTarget {
    param([string]$TargetTriple)
    
    if ($TargetTriple -eq "native") {
        return
    }
    
    Write-LogInfo "Checking Rust target: $TargetTriple"
    
    $installedTargets = rustup target list --installed
    if ($installedTargets -notcontains $TargetTriple) {
        Write-LogInfo "Installing Rust target: $TargetTriple"
        rustup target add $TargetTriple
        if ($LASTEXITCODE -ne 0) {
            Write-LogError "Failed to install Rust target: $TargetTriple"
            exit 1
        }
    } else {
        Write-LogInfo "Rust target $TargetTriple is already installed"
    }
}

# Check YARA installation
function Test-YaraInstallation {
    Write-LogInfo "Checking YARA installation..."
    
    # Skip YARA check if not using YARA features
    if ($Features -notlike "*yara*") {
        Write-LogInfo "YARA features not enabled, skipping YARA check"
        return $true
    }
    
    # Check vcpkg installation
    if (Test-Command "vcpkg") {
        $vcpkgList = vcpkg list yara 2>$null
        if ($vcpkgList -like "*yara*") {
            Write-LogSuccess "Found YARA via vcpkg"
            
            # Set vcpkg environment variables
            $vcpkgRoot = $env:VCPKG_ROOT
            if (-not $vcpkgRoot) {
                $vcpkgRoot = (Get-Command vcpkg).Source | Split-Path -Parent
            }
            
            $arch = Get-WindowsArchitecture
            $vcpkgTriplet = "$arch-windows"
            
            $env:YARA_LIBRARY_PATH = "$vcpkgRoot\installed\$vcpkgTriplet\lib"
            $env:YARA_INCLUDE_PATH = "$vcpkgRoot\installed\$vcpkgTriplet\include"
            
            Write-LogInfo "Set YARA_LIBRARY_PATH: $env:YARA_LIBRARY_PATH"
            Write-LogInfo "Set YARA_INCLUDE_PATH: $env:YARA_INCLUDE_PATH"
            
            return $true
        }
    }
    
    # Check environment variables
    if ($env:YARA_LIBRARY_PATH -and (Test-Path $env:YARA_LIBRARY_PATH)) {
        Write-LogSuccess "Using YARA from YARA_LIBRARY_PATH: $env:YARA_LIBRARY_PATH"
        return $true
    }
    
    # Check common installation paths
    $commonPaths = @(
        "C:\Program Files\yara\lib",
        "C:\Program Files (x86)\yara\lib",
        "C:\yara\lib",
        "C:\tools\yara\lib"
    )
    
    foreach ($path in $commonPaths) {
        if (Test-Path "$path\yara.lib") {
            Write-LogSuccess "Found YARA library at: $path\yara.lib"
            $env:YARA_LIBRARY_PATH = $path
            $env:YARA_INCLUDE_PATH = $path.Replace("\lib", "\include")
            return $true
        }
    }
    
    Write-LogError "YARA library not found!"
    Write-LogInfo "Please install YARA using one of these methods:"
    Write-LogInfo "  vcpkg: vcpkg install yara"
    Write-LogInfo "  Manual: Download from https://github.com/VirusTotal/yara/releases"
    Write-LogInfo "  Or set YARA_LIBRARY_PATH environment variable"
    
    return $false
}

# Setup cross-compilation environment
function Set-CrossCompilationEnvironment {
    param([string]$TargetTriple)
    
    if ($TargetTriple -eq "native") {
        return
    }
    
    Write-LogInfo "Setting up cross-compilation for target: $TargetTriple"
    
    switch ($TargetTriple) {
        "x86_64-unknown-linux-gnu" {
            # Check for WSL or Docker for Linux cross-compilation
            if (Test-Command "wsl") {
                Write-LogInfo "WSL detected - Linux cross-compilation may be possible"
                Write-LogWarn "Cross-compilation to Linux from Windows requires additional setup"
                Write-LogInfo "Consider using WSL or Docker for Linux builds"
            } else {
                Write-LogWarn "Cross-compilation to Linux from Windows is complex"
                Write-LogInfo "Consider using WSL, Docker, or a Linux build environment"
            }
        }
        "aarch64-pc-windows-msvc" {
            Write-LogInfo "ARM64 Windows target - ensure you have the ARM64 build tools installed"
        }
        default {
            Write-LogWarn "Cross-compilation setup for target $TargetTriple is not automated"
            Write-LogInfo "You may need to set up the environment manually"
        }
    }
}

# Setup build environment
function Set-BuildEnvironment {
    Write-LogInfo "Setting up build environment..."
    
    # Set optimization flags
    $rustFlags = $env:RUSTFLAGS
    if (-not $rustFlags) {
        $rustFlags = ""
    }
    
    switch ($BuildType) {
        "release" {
            $env:RUSTFLAGS = "$rustFlags -C target-cpu=native -C lto=fat"
        }
        "debug" {
            $env:RUSTFLAGS = "$rustFlags -C debuginfo=2"
        }
    }
    
    # Enable parallel compilation
    if (-not $env:CARGO_BUILD_JOBS) {
        $numCores = (Get-CimInstance -ClassName Win32_ComputerSystem).NumberOfLogicalProcessors
        $env:CARGO_BUILD_JOBS = $numCores
    }
    
    Write-LogInfo "Using $env:CARGO_BUILD_JOBS parallel build jobs"
    Write-LogInfo "RUSTFLAGS: $env:RUSTFLAGS"
}

# Build the project
function Invoke-ProjectBuild {
    Write-LogInfo "Building ERDPS Agent..."
    Write-LogInfo "  Build type: $BuildType"
    Write-LogInfo "  Target: $Target"
    Write-LogInfo "  Features: $Features"
    
    Set-Location $ProjectRoot
    
    $cargoArgs = @("build")
    
    # Add build type
    if ($BuildType -eq "release") {
        $cargoArgs += "--release"
    }
    
    # Add target
    if ($Target -ne "native") {
        $cargoArgs += @("--target", $Target)
    }
    
    # Add features
    if ($Features) {
        $cargoArgs += @("--features", $Features)
    }
    
    # Run cargo build
    Write-LogInfo "Running: cargo $($cargoArgs -join ' ')"
    
    $startTime = Get-Date
    
    & cargo @cargoArgs
    
    if ($LASTEXITCODE -eq 0) {
        $endTime = Get-Date
        $duration = ($endTime - $startTime).TotalSeconds
        
        Write-LogSuccess "Build completed successfully in $([math]::Round($duration, 1))s"
        
        # Show binary information
        Show-BinaryInfo
    } else {
        Write-LogError "Build failed!"
        exit 1
    }
}

# Show binary information
function Show-BinaryInfo {
    $binaryName = "erdps-agent.exe"
    
    if ($Target -eq "native") {
        $binaryPath = "target\$BuildType\$binaryName"
    } else {
        $binaryPath = "target\$Target\$BuildType\$binaryName"
    }
    
    if (Test-Path $binaryPath) {
        Write-LogInfo "Binary information:"
        Write-LogInfo "  Path: $binaryPath"
        
        $fileInfo = Get-Item $binaryPath
        $sizeKB = [math]::Round($fileInfo.Length / 1KB, 1)
        $sizeMB = [math]::Round($fileInfo.Length / 1MB, 1)
        
        if ($sizeMB -gt 1) {
            Write-LogInfo "  Size: $sizeMB MB"
        } else {
            Write-LogInfo "  Size: $sizeKB KB"
        }
        
        Write-LogInfo "  Created: $($fileInfo.CreationTime)"
        Write-LogInfo "  Modified: $($fileInfo.LastWriteTime)"
        
        # Check file version if available
        try {
            $versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($binaryPath)
            if ($versionInfo.FileVersion) {
                Write-LogInfo "  Version: $($versionInfo.FileVersion)"
            }
        } catch {
            # Version info not available
        }
    } else {
        Write-LogWarn "Binary not found at expected path: $binaryPath"
    }
}

# Run tests
function Invoke-Tests {
    $runTests = $env:RUN_TESTS
    if ($runTests -eq $null) {
        $runTests = "true"
    }
    
    if ($runTests -eq "true") {
        Write-LogInfo "Running tests..."
        
        $cargoArgs = @("test")
        
        # Add target
        if ($Target -ne "native") {
            $cargoArgs += @("--target", $Target)
        }
        
        # Add features
        if ($Features) {
            $cargoArgs += @("--features", $Features)
        }
        
        & cargo @cargoArgs
        
        if ($LASTEXITCODE -eq 0) {
            Write-LogSuccess "All tests passed!"
        } else {
            Write-LogWarn "Some tests failed"
        }
    }
}

# Check prerequisites
function Test-Prerequisites {
    Write-LogInfo "Checking prerequisites..."
    
    # Check PowerShell version
    $psVersion = $PSVersionTable.PSVersion
    Write-LogInfo "PowerShell version: $psVersion"
    
    if ($psVersion.Major -lt 5) {
        Write-LogWarn "PowerShell version $psVersion is older than recommended (5.0+)"
    }
    
    # Check Windows version
    $osVersion = [System.Environment]::OSVersion.Version
    Write-LogInfo "Windows version: $osVersion"
    
    # Check Visual Studio Build Tools (for MSVC)
    $vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vsWhere) {
        $vsInstalls = & $vsWhere -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -format json | ConvertFrom-Json
        if ($vsInstalls) {
            Write-LogSuccess "Found Visual Studio Build Tools"
        }
    }
}

# Main function
function Main {
    Write-LogInfo "ERDPS Agent Build Script for Windows"
    Write-LogInfo "===================================="
    
    # Check prerequisites
    Test-Prerequisites
    Test-RustInstallation
    Install-RustTarget $Target
    
    # Setup environment
    Set-BuildEnvironment
    Set-CrossCompilationEnvironment $Target
    
    # Check YARA if needed
    if (-not (Test-YaraInstallation)) {
        if ($Features -like "*yara*") {
            Write-LogError "YARA is required for the requested features but not found"
            Write-LogInfo "Either install YARA or build without YARA features:"
            Write-LogInfo "  .\scripts\build.ps1 $BuildType $Target ''"
            exit 1
        }
    }
    
    # Build project
    Invoke-ProjectBuild
    
    # Run tests
    Invoke-Tests
    
    Write-LogSuccess "Build process completed successfully!"
    
    $binaryLocation = "target\"
    if ($Target -ne "native") {
        $binaryLocation += "$Target\"
    }
    $binaryLocation += "$BuildType\erdps-agent.exe"
    
    Write-LogInfo "Binary location: $binaryLocation"
}

# Run main function
try {
    Main
} catch {
    Write-LogError "Build script failed: $($_.Exception.Message)"
    Write-LogError "Stack trace: $($_.ScriptStackTrace)"
    exit 1
}