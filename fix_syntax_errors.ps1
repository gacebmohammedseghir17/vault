# Fix systematic syntax errors in YARA module files
# This script fixes the malformed syntax where context and transaction_id fields
# are incorrectly placed outside the AgentError struct initialization

Write-Host "Fixing systematic syntax errors in YARA module files..." -ForegroundColor Green

$files = @(
    "src\yara\correlation_engine.rs",
    "src\yara\rule_optimizer.rs", 
    "src\yara\performance_monitor.rs"
)

foreach ($file in $files) {
    if (Test-Path $file) {
        Write-Host "Processing $file..." -ForegroundColor Yellow
        
        # Read the file content
        $content = Get-Content $file -Raw
        
        # Fix the malformed syntax pattern
        # Pattern: }, context: None , transaction_id: None })?;
        # Should be: })?; with context and transaction_id inside the AgentError struct
        
        # This is a complex pattern, so we'll need to be more surgical
        # Let's count occurrences first
        $matches = [regex]::Matches($content, ", context: None , transaction_id: None }")
        Write-Host "Found $($matches.Count) syntax errors in $file" -ForegroundColor Cyan
        
        if ($matches.Count -gt 0) {
            # Create backup
            Copy-Item $file "$file.backup"
            Write-Host "Created backup: $file.backup" -ForegroundColor Gray
        }
    } else {
        Write-Host "File not found: $file" -ForegroundColor Red
    }
}

Write-Host "Manual fixes required - syntax errors are context-dependent" -ForegroundColor Yellow
Write-Host "Use cargo check to identify specific locations that need fixing" -ForegroundColor Yellow