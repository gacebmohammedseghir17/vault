# PowerShell script to fix all AgentError::Service instances missing context field

$files = @(
    "src\monitoring\performance_monitor.rs",
    "src\monitoring\alert_manager.rs", 
    "src\monitoring\performance_gate.rs",
    "src\monitoring\health_checker.rs",
    "src\monitoring\log_analyzer.rs",
    "src\monitoring\mod.rs",
    "src\monitoring\resource_tracker.rs",
    "src\monitoring\metrics_collector.rs"
)

foreach ($file in $files) {
    if (Test-Path $file) {
        Write-Host "Processing $file..."
        
        # Read the file content
        $content = Get-Content $file -Raw
        
        # Replace AgentError::Service patterns that don't have context field
        # Pattern 1: AgentError::Service { message: ..., service: ... }
        $pattern1 = 'AgentError::Service\s*\{\s*message:\s*([^,]+),\s*service:\s*([^}]+)\s*\}'
        $replacement1 = 'AgentError::Service { message: $1, service: $2, context: None }'
        $content = $content -replace $pattern1, $replacement1
        
        # Pattern 2: AgentError::Service { service: ..., message: ... }
        $pattern2 = 'AgentError::Service\s*\{\s*service:\s*([^,]+),\s*message:\s*([^}]+)\s*\}'
        $replacement2 = 'AgentError::Service { service: $1, message: $2, context: None }'
        $content = $content -replace $pattern2, $replacement2
        
        # Write back to file
        Set-Content $file -Value $content -NoNewline
        
        Write-Host "Fixed $file"
    } else {
        Write-Host "File not found: $file"
    }
}

Write-Host "All Service errors have been fixed!"