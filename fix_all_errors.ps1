# PowerShell script to fix all AgentError issues

$files = Get-ChildItem -Path "src" -Recurse -Filter "*.rs" | ForEach-Object { $_.FullName }

foreach ($file in $files) {
    Write-Host "Processing $file..."
    
    # Read the file content
    $content = Get-Content $file -Raw
    
    # Fix old error variant names to new ones
    $content = $content -replace 'AgentError::ValidationError\(([^)]+)\)', 'AgentError::Validation { message: $1, field: None, expected: None, actual: None, context: None }'
    $content = $content -replace 'AgentError::IoError\(([^)]+)\)', 'AgentError::Io { message: $1, path: None, operation: None, context: None }'
    $content = $content -replace 'AgentError::NetworkError\(([^)]+)\)', 'AgentError::Network { message: $1, endpoint: None, retry_count: 0, context: None }'
    $content = $content -replace 'AgentError::ParseError\(([^)]+)\)', 'AgentError::Parse { message: $1, input: None, position: None, context: None }'
    $content = $content -replace 'AgentError::ConfigError\(([^)]+)\)', 'AgentError::Configuration { message: $1, field: None, context: None }'
    $content = $content -replace 'AgentError::CryptoError\(([^)]+)\)', 'AgentError::Crypto { message: $1, algorithm: None, context: None }'
    $content = $content -replace 'AgentError::ResourceError\(([^)]+)\)', 'AgentError::Resource { message: $1, resource_type: "unknown".to_string(), current_usage: None, limit: None, context: None }'
    
    # Fix RansolutionError references (should be AgentError)
    $content = $content -replace 'RansolutionError::', 'AgentError::'
    
    # Fix missing fields in Authentication errors
    $content = $content -replace '(?s)(AgentError::Authentication\s*\{\s*message:\s*[^,}]+)\s*\}', '$1, user_id: None, context: None }'
    
    # Fix missing fields in Network errors  
    $content = $content -replace '(?s)(AgentError::Network\s*\{\s*message:\s*[^,}]+)\s*\}', '$1, endpoint: None, retry_count: 0, context: None }'
    
    # Fix missing fields in Database errors
    $content = $content -replace '(?s)(AgentError::Database\s*\{\s*message:\s*[^,}]+)\s*\}', '$1, operation: None, transaction_id: None, context: None }'
    
    # Remove duplicate context fields
    $content = $content -replace '(context:\s*[^,}]+),\s*context:\s*[^,}]+', '$1'
    
    # Write back to file
    Set-Content $file -Value $content -NoNewline
    
    Write-Host "Fixed $file"
}

Write-Host "All errors have been fixed!"