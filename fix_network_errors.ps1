# Fix specific Network error patterns
$content = Get-Content "src\network\mod.rs" -Raw

# Fix the transformer_classifier line
$content = $content -replace 'let transformer_classifier = Arc::new\(TransformerClassifier::new\(50\)\.map_err\(\|e\| AgentError::Network \{ message: format!\("Failed to create TransformerClassifier: \{\}", e\),\s*endpoint: None\s*\}\)\?\);', 'let transformer_classifier = Arc::new(TransformerClassifier::new(50).map_err(|e| AgentError::Network { 
            message: format!("Failed to create TransformerClassifier: {}", e),
            endpoint: None,
            retry_count: 0,
            context: None
        })?);'

Set-Content "src\network\mod.rs" -Value $content -NoNewline
Write-Host "Fixed transformer_classifier Network error"