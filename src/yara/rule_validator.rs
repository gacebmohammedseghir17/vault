use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use tokio::fs;
use tracing::{debug, error, info};
use yara_x::{Compiler, Rules};

/// Rule validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub rule_path: PathBuf,
    pub is_valid: bool,
    pub error_message: Option<String>,
    pub rule_count: usize,
    pub file_size: u64,
    pub validation_time: Duration,
    pub quality_score: f64, // 0.0 to 10.0
    pub metadata: RuleMetadata,
}

/// Rule metadata extracted from YARA rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMetadata {
    pub author: Option<String>,
    pub description: Option<String>,
    pub reference: Vec<String>,
    pub date: Option<String>,
    pub version: Option<String>,
    pub malware_family: Vec<String>,
    pub threat_type: Vec<String>,
    pub confidence: Option<String>,
    pub tags: Vec<String>,
}

/// Rule quality assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityAssessment {
    pub total_rules: usize,
    pub valid_rules: usize,
    pub invalid_rules: usize,
    pub average_quality_score: f64,
    pub high_quality_rules: usize, // Score >= 8.0
    pub medium_quality_rules: usize, // Score 5.0-7.9
    pub low_quality_rules: usize, // Score < 5.0
    pub validation_errors: Vec<String>,
    pub recommendations: Vec<String>,
}

/// Directory validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryValidationResult {
    pub valid_rules: Vec<ValidationResult>,
    pub invalid_rules: Vec<InvalidRuleInfo>,
    pub total_rules: usize,
}

/// Invalid rule information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvalidRuleInfo {
    pub file_path: PathBuf,
    pub error: String,
}

/// Performance benchmark results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceBenchmark {
    pub total_rules: usize,
    pub test_files_count: usize,
    pub total_duration: Duration,
    pub avg_scan_time: Duration,
    pub max_scan_time: Duration,
    pub min_scan_time: Duration,
    pub avg_memory_usage: usize, // bytes
    pub total_matches: usize,
    pub throughput_files_per_sec: f64,
}

/// YARA rule validator
pub struct RuleValidator {
    rules_path: PathBuf,
    cache_path: PathBuf,
    validation_cache: HashMap<PathBuf, ValidationResult>,
}

impl RuleValidator {
    /// Create a new rule validator
    pub fn new<P: AsRef<Path>>(rules_path: P) -> Self {
        let rules_path = rules_path.as_ref().to_path_buf();
        let cache_path = rules_path.join("cache");

        Self {
            rules_path,
            cache_path,
            validation_cache: HashMap::new(),
        }
    }

    /// Validate all YARA rules in the rules directory
    pub async fn validate_directory(&mut self, directory: &Path) -> Result<DirectoryValidationResult> {
        let mut results = Vec::new();
        let mut validation_errors = Vec::new();

        if directory.is_file() {
            // Single file validation
            match self.validate_rule_file(directory).await {
                Ok(result) => results.push(result),
                Err(e) => validation_errors.push(format!("Failed to validate {}: {}", directory.display(), e)),
            }
        } else if directory.is_dir() {
            // Directory validation
            self.validate_subdirectories(directory, &mut results, &mut validation_errors).await?;
        } else {
            return Err(anyhow::anyhow!("Path does not exist: {}", directory.display()));
        }

        Ok(DirectoryValidationResult {
            valid_rules: results.iter().filter(|r| r.is_valid).cloned().collect(),
            invalid_rules: results.iter().filter(|r| !r.is_valid).map(|r| InvalidRuleInfo {
                file_path: r.rule_path.clone(),
                error: r.error_message.clone().unwrap_or_else(|| "Unknown error".to_string()),
            }).collect(),
            total_rules: results.len(),
        })
    }

    pub async fn validate_all_rules(&mut self) -> Result<QualityAssessment> {
        info!("Starting comprehensive rule validation");
        let start_time = SystemTime::now();

        let mut results = Vec::new();
        let mut validation_errors = Vec::new();

        // Walk through all .yar and .yara files
        let mut entries = fs::read_dir(&self.rules_path).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if self.is_yara_file(&path) {
                match self.validate_rule_file(&path).await {
                    Ok(result) => {
                        if !result.is_valid {
                            if let Some(error) = &result.error_message {
                                validation_errors.push(format!("{}: {}", path.display(), error));
                            }
                        }
                        results.push(result);
                    }
                    Err(e) => {
                        error!("Failed to validate {}: {}", path.display(), e);
                        validation_errors.push(format!("{}: {}", path.display(), e));
                    }
                }
            }
        }

        // Also validate subdirectories
        let rules_path = self.rules_path.clone();
        self.validate_subdirectories(&rules_path, &mut results, &mut validation_errors).await?;

        let assessment = self.generate_quality_assessment(results, validation_errors);
        
        let elapsed = start_time.elapsed().unwrap_or_default();
        info!("Rule validation completed in {:?}", elapsed);
        info!("Validated {} rules, {} valid, {} invalid", 
              assessment.total_rules, assessment.valid_rules, assessment.invalid_rules);

        Ok(assessment)
    }

    /// Validate rules in subdirectories recursively
    fn validate_subdirectories<'a>(
        &'a mut self,
        dir_path: &'a Path,
        results: &'a mut Vec<ValidationResult>,
        validation_errors: &'a mut Vec<String>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            let mut entries = fs::read_dir(dir_path).await?;
            while let Some(entry) = entries.next_entry().await? {
                let path = entry.path();
                if path.is_dir() {
                    // Recursively validate subdirectories
                    self.validate_subdirectories(&path, results, validation_errors).await?;
                } else if self.is_yara_file(&path) {
                    match self.validate_rule_file(&path).await {
                        Ok(result) => {
                            if !result.is_valid {
                                if let Some(error) = &result.error_message {
                                    validation_errors.push(format!("{}: {}", path.display(), error));
                                }
                            }
                            results.push(result);
                        }
                        Err(e) => {
                            error!("Failed to validate {}: {}", path.display(), e);
                            validation_errors.push(format!("{}: {}", path.display(), e));
                        }
                    }
                }
            }
            Ok(())
        })
    }

    /// Validate a single YARA rule file
    pub async fn validate_rule_file(&mut self, rule_path: &Path) -> Result<ValidationResult> {
        let start_time = SystemTime::now();
        
        // Check cache first
        if let Some(cached_result) = self.validation_cache.get(rule_path) {
            // Check if file has been modified since last validation
            if let Ok(metadata) = fs::metadata(rule_path).await {
                if let Ok(modified) = metadata.modified() {
                    if modified <= start_time {
                        debug!("Using cached validation result for {}", rule_path.display());
                        return Ok(cached_result.clone());
                    }
                }
            }
        }

        debug!("Validating rule file: {}", rule_path.display());

        // Read the rule file
        let rule_content = fs::read_to_string(rule_path).await
            .context("Failed to read rule file")?;

        let file_size = rule_content.len() as u64;

        // Try to compile the rule
        let mut compiler = Compiler::new();
        let validation_result = match compiler.add_source(rule_content.as_str()) {
            Ok(_) => {
                let rules = compiler.build();
                let rule_count = self.count_rules_in_content(&rule_content);
                let metadata = self.extract_metadata(&rule_content);
                let quality_score = self.calculate_quality_score(&rule_content, &metadata, &rules);

                ValidationResult {
                    rule_path: rule_path.to_path_buf(),
                    is_valid: true,
                    error_message: None,
                    rule_count,
                    file_size,
                    validation_time: start_time.elapsed().unwrap_or_default(),
                    quality_score,
                    metadata,
                }
            }
            Err(e) => {
                // Emit debug with offending file path and reason
                debug!(
                    "YARA validation failed: file={}, reason={}",
                    rule_path.display(),
                    e
                );
                ValidationResult {
                    rule_path: rule_path.to_path_buf(),
                    is_valid: false,
                    error_message: Some(format!("Failed to add rules: {}", e)),
                    rule_count: 0,
                    file_size,
                    validation_time: start_time.elapsed().unwrap_or_default(),
                    quality_score: 0.0,
                    metadata: RuleMetadata::default(),
                }
            }
        };

        // Cache the result
        self.validation_cache.insert(rule_path.to_path_buf(), validation_result.clone());

        Ok(validation_result)
    }

    /// Count the number of rules in the content
    fn count_rules_in_content(&self, content: &str) -> usize {
        content.lines()
            .filter(|line| line.trim_start().starts_with("rule "))
            .count()
    }

    /// Extract metadata from rule content
    fn extract_metadata(&self, content: &str) -> RuleMetadata {
        let mut metadata = RuleMetadata::default();
        let mut in_meta_section = false;

        for line in content.lines() {
            let trimmed = line.trim();
            
            if trimmed == "meta:" {
                in_meta_section = true;
                continue;
            }
            
            if in_meta_section {
                if trimmed.starts_with("strings:") || trimmed.starts_with("condition:") {
                    in_meta_section = false;
                    continue;
                }

                // Parse metadata fields
                if let Some((key, value)) = self.parse_metadata_line(trimmed) {
                    match key.as_str() {
                        "author" => metadata.author = Some(value),
                        "description" => metadata.description = Some(value),
                        "reference" => metadata.reference.push(value),
                        "date" => metadata.date = Some(value),
                        "version" => metadata.version = Some(value),
                        "malware_family" | "family" => metadata.malware_family.push(value),
                        "threat_type" | "type" => metadata.threat_type.push(value),
                        "confidence" => metadata.confidence = Some(value),
                        _ => {}
                    }
                }
            }

            // Extract tags from rule declarations
            if trimmed.starts_with("rule ") && trimmed.contains(":") {
                if let Some(tags_part) = trimmed.split(':').next() {
                    if let Some(tags_start) = tags_part.find("tags") {
                        let tags_section = &tags_part[tags_start..];
                        // Simple tag extraction - could be improved
                        metadata.tags.extend(
                            tags_section.split_whitespace()
                                .filter(|s| !s.is_empty() && *s != "tags")
                                .map(|s| s.to_string())
                        );
                    }
                }
            }
        }

        metadata
    }

    /// Parse a metadata line (key = value)
    fn parse_metadata_line(&self, line: &str) -> Option<(String, String)> {
        if let Some(eq_pos) = line.find('=') {
            let key = line[..eq_pos].trim().to_lowercase();
            let value = line[eq_pos + 1..].trim()
                .trim_matches('"')
                .trim_matches('\'')
                .to_string();
            Some((key, value))
        } else {
            None
        }
    }

    /// Calculate quality score for a rule based on various factors
    fn calculate_quality_score(&self, content: &str, metadata: &RuleMetadata, _rules: &Rules) -> f64 {
        let mut score: f64 = 5.0; // Base score

        // Metadata completeness (0-2.5 points)
        if metadata.author.is_some() { score += 0.3; }
        if metadata.description.is_some() { score += 0.4; }
        if !metadata.reference.is_empty() { score += 0.5; }
        if metadata.date.is_some() { score += 0.2; }
        if !metadata.malware_family.is_empty() { score += 0.4; }
        if !metadata.threat_type.is_empty() { score += 0.4; }
        if metadata.confidence.is_some() { score += 0.3; }

        // Rule complexity and quality indicators (0-2.5 points)
        let string_count = content.matches("$").count();
        if string_count >= 3 { score += 0.5; }
        if string_count >= 5 { score += 0.5; }
        if string_count >= 10 { score += 0.3; }
        
        if content.contains("condition:") { score += 0.4; }
        if content.contains("and") || content.contains("or") { score += 0.3; }
        if content.contains("uint") || content.contains("int") { score += 0.3; }
        if content.contains("filesize") { score += 0.2; }
        if content.contains("entrypoint") { score += 0.3; }

        // Advanced pattern matching (0-1.5 points)
        if content.contains("pe.") { score += 0.4; }
        if content.contains("math.") { score += 0.3; }
        if content.contains("hash.") { score += 0.3; }
        if content.contains("for ") && content.contains("of") { score += 0.5; }

        // Security-focused features (0-1 point)
        if content.contains("imports") { score += 0.2; }
        if content.contains("sections") { score += 0.2; }
        if content.contains("resources") { score += 0.2; }
        if content.contains("version_info") { score += 0.2; }
        if content.contains("rich_signature") { score += 0.2; }

        // Deduct points for potential issues (0-2 points)
        if content.contains("*") && !content.contains("pe.") { score -= 0.3; } // Wildcards without context
        if content.lines().count() < 10 { score -= 0.5; } // Too simple
        if !content.contains("strings:") { score -= 0.7; } // No strings section
        if content.contains("nocase") && string_count < 3 { score -= 0.3; } // Overuse of nocase
        if content.matches("wide").count() > string_count / 2 { score -= 0.2; } // Too many wide strings

        // Performance considerations (0-0.5 points deduction)
        if content.matches("*").count() > 5 { score -= 0.3; } // Too many wildcards
        if content.contains("fullword") { score += 0.2; } // Good for performance

        // Ensure score is within bounds
        score.max(0.0).min(10.0)
    }

    /// Generate quality assessment from validation results
    fn generate_quality_assessment(
        &self,
        results: Vec<ValidationResult>,
        validation_errors: Vec<String>,
    ) -> QualityAssessment {
        let total_rules = results.len();
        let valid_rules = results.iter().filter(|r| r.is_valid).count();
        let invalid_rules = total_rules - valid_rules;

        let average_quality_score = if valid_rules > 0 {
            results.iter()
                .filter(|r| r.is_valid)
                .map(|r| r.quality_score)
                .sum::<f64>() / valid_rules as f64
        } else {
            0.0
        };

        let high_quality_rules = results.iter()
            .filter(|r| r.is_valid && r.quality_score >= 8.0)
            .count();
        
        let medium_quality_rules = results.iter()
            .filter(|r| r.is_valid && r.quality_score >= 5.0 && r.quality_score < 8.0)
            .count();
        
        let low_quality_rules = results.iter()
            .filter(|r| r.is_valid && r.quality_score < 5.0)
            .count();

        let mut recommendations = Vec::new();
        
        if invalid_rules > 0 {
            recommendations.push(format!("Fix {} invalid rules to improve overall quality", invalid_rules));
        }
        
        if low_quality_rules > total_rules / 4 {
            recommendations.push("Consider improving rule metadata and complexity for better detection".to_string());
        }
        
        if average_quality_score < 6.0 {
            recommendations.push("Overall rule quality is below average - consider rule review and enhancement".to_string());
        }

        QualityAssessment {
            total_rules,
            valid_rules,
            invalid_rules,
            average_quality_score,
            high_quality_rules,
            medium_quality_rules,
            low_quality_rules,
            validation_errors,
            recommendations,
        }
    }

    /// Check if a file is a YARA rule file
    fn is_yara_file(&self, path: &Path) -> bool {
        if let Some(extension) = path.extension() {
            let ext = extension.to_string_lossy().to_lowercase();
            ext == "yar" || ext == "yara"
        } else {
            false
        }
    }

    /// Get validation statistics
    pub fn get_validation_stats(&self) -> HashMap<String, usize> {
        let mut stats = HashMap::new();
        
        let total = self.validation_cache.len();
        let valid = self.validation_cache.values().filter(|r| r.is_valid).count();
        let invalid = total - valid;
        
        stats.insert("total".to_string(), total);
        stats.insert("valid".to_string(), valid);
        stats.insert("invalid".to_string(), invalid);
        
        stats
    }

    /// Get all validation results from cache
    pub fn get_validation_results(&self) -> Vec<ValidationResult> {
        self.validation_cache.values().cloned().collect()
    }

    /// Clear validation cache
    pub fn clear_cache(&mut self) {
        self.validation_cache.clear();
    }

    /// Benchmark rule performance against test files
    pub async fn benchmark_rules(&mut self, test_files: &[PathBuf]) -> Result<PerformanceBenchmark> {
        let start_time = SystemTime::now();
        let mut scan_times = Vec::new();
        let mut memory_usage = Vec::new();
        let mut match_counts = Vec::new();
        
        info!("Starting performance benchmark with {} test files", test_files.len());
        
        // Load all valid rules
        let mut compiler = Compiler::new();
        let mut total_rules = 0;
        
        for result in self.validation_cache.values() {
            if result.is_valid {
                if let Ok(content) = fs::read_to_string(&result.rule_path).await {
                    if let Err(e) = compiler.add_source(content.as_str()) {
                        debug!("Failed to add rule {} to benchmark: {}", result.rule_path.display(), e);
                        continue;
                    }
                    total_rules += result.rule_count;
                }
            }
        }
        
        let rules = compiler.build();
        info!("Compiled {} rules for benchmarking", total_rules);
        
        // Benchmark against test files
        for test_file in test_files {
            if let Ok(file_content) = fs::read(test_file).await {
                let scan_start = SystemTime::now();
                
                // Create a scanner for each file
                let mut scanner = yara_x::Scanner::new(&rules);
                let scan_result = match scanner.scan(&file_content) {
                    Ok(result) => result,
                    Err(_) => {
                        // Skip this file on scan error
                        continue;
                    }
                };
                let scan_duration = scan_start.elapsed().unwrap_or(Duration::from_secs(0));
                
                scan_times.push(scan_duration);
                match_counts.push(scan_result.matching_rules().count());
                
                // Estimate memory usage (simplified)
                let estimated_memory = file_content.len() + (total_rules * 1024); // Rough estimate
                memory_usage.push(estimated_memory);
                
                debug!("Scanned {} ({} bytes) in {:?} with {} matches", 
                    test_file.display(), file_content.len(), scan_duration, scan_result.matching_rules().count());
            }
        }
        
        let total_duration = start_time.elapsed().unwrap_or(Duration::from_secs(0));
        
        // Calculate statistics
        let avg_scan_time = if !scan_times.is_empty() {
            scan_times.iter().sum::<Duration>() / scan_times.len() as u32
        } else {
            Duration::from_secs(0)
        };
        
        let max_scan_time = scan_times.iter().max().copied().unwrap_or(Duration::from_secs(0));
        let min_scan_time = scan_times.iter().min().copied().unwrap_or(Duration::from_secs(0));
        
        let avg_memory = if !memory_usage.is_empty() {
            memory_usage.iter().sum::<usize>() / memory_usage.len()
        } else {
            0
        };
        
        let total_matches = match_counts.iter().sum::<usize>();
        
        Ok(PerformanceBenchmark {
            total_rules,
            test_files_count: test_files.len(),
            total_duration,
            avg_scan_time,
            max_scan_time,
            min_scan_time,
            avg_memory_usage: avg_memory,
            total_matches,
            throughput_files_per_sec: if total_duration.as_secs() > 0 {
                test_files.len() as f64 / total_duration.as_secs_f64()
            } else {
                0.0
            },
        })
    }
}

impl Default for RuleMetadata {
    fn default() -> Self {
        Self {
            author: None,
            description: None,
            reference: Vec::new(),
            date: None,
            version: None,
            malware_family: Vec::new(),
            threat_type: Vec::new(),
            confidence: None,
            tags: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_rule_validator_creation() {
        let temp_dir = TempDir::new().unwrap();
        let rules_path = temp_dir.path().join("rules");

        let validator = RuleValidator::new(&rules_path);
        assert_eq!(validator.rules_path, rules_path);
    }

    #[tokio::test]
    async fn test_metadata_extraction() {
        let temp_dir = TempDir::new().unwrap();
        let rules_path = temp_dir.path().join("rules");

        let validator = RuleValidator::new(&rules_path);
        
        let content = r#"
rule test_rule {
    meta:
        author = "Test Author"
        description = "Test rule"
        reference = "https://example.com"
        date = "2024-01-01"
        malware_family = "TestFamily"
    strings:
        $test = "test"
    condition:
        $test
}
"#;

        let metadata = validator.extract_metadata(content);
        assert_eq!(metadata.author, Some("Test Author".to_string()));
        assert_eq!(metadata.description, Some("Test rule".to_string()));
        assert!(metadata.reference.contains(&"https://example.com".to_string()));
    }
}
