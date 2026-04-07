Param(
    [string]$Configuration = "release",
    [string]$Target = "x86_64-pc-windows-msvc",
    [switch]$BundlePdb,
    [switch]$Strip
)

# Build optimized release binaries for Windows
Write-Host "Building ERDPS Agent ($Configuration) for $Target..." -ForegroundColor Cyan

# Resolve important paths based on script location
$agentDir = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$targetDir = Join-Path $agentDir "target\$Target\$Configuration"
$outDir = Join-Path (Join-Path $repoRoot "release") "windows"

# Ensure Rust target toolchain is installed (non-fatal if already)
rustup target add $Target 2>$null | Out-Null

# Use Cargo to build with features suitable for production
$env:RUSTFLAGS = "--cfg tokio_unstable"

# Determine cargo flag for configuration
$releaseFlag = if ($Configuration -eq "release") { "--release" } else { "" }

# Build the library and all binaries
Push-Location $agentDir
cargo build $releaseFlag --target $Target --features production 2>&1 | Tee-Object -Variable buildOutput
Pop-Location

if ($LASTEXITCODE -ne 0) {
    Write-Error "Cargo build failed. See output above."
    exit 1
}

# Collect all compiled .exe binaries from target directory
$bins = Get-ChildItem -Path $targetDir -Filter *.exe -File -ErrorAction SilentlyContinue
if (-not $bins -or $bins.Count -eq 0) {
    Write-Warning "No .exe binaries found in $targetDir. Ensure build succeeded and path is correct."
}

# Create release output folder
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

foreach ($bin in $bins) {
    Copy-Item $bin.FullName $outDir -Force
    if ($BundlePdb) {
        $pdb = [System.IO.Path]::ChangeExtension($bin.FullName, ".pdb")
        if (Test-Path $pdb) { Copy-Item $pdb $outDir -Force }
    }
}

# Optional: strip symbols to reduce size (requires llvm tools)
if ($Strip) {
    Write-Host "Stripping binaries with llvm-strip..." -ForegroundColor Yellow
    $outBins = Get-ChildItem -Path $outDir -Filter *.exe -File -ErrorAction SilentlyContinue
    foreach ($ob in $outBins) {
        & llvm-strip "$($ob.FullName)"
    }
}

Write-Host "Release build completed. Artifacts in: $outDir" -ForegroundColor Green