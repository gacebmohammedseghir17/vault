//! YARA Rule Category System
//!
//! This module provides category-based organization and filtering for YARA rules including:
//! - Rule categorization by malware family, behavior, and source
//! - Category-based rule selection and filtering
//! - Rule correlation and relationship analysis
//! - Dynamic category assignment based on metadata
//! - Performance-optimized category scanning

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::fs;
use tracing::{debug, info, warn};
use regex::Regex;
use std::future::Future;
use std::pin::Pin;

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Rule category information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct RuleCategory {
    pub name: String,
    pub description: String,
    pub category_type: CategoryType,
    pub priority: CategoryPriority,
    pub tags: Vec<String>,
    pub parent_category: Option<String>,
    pub subcategories: Vec<String>,
    pub rule_count: usize,
    pub last_updated: u64,
}

/// Types of rule categories
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CategoryType {
    MalwareFamily,     // APT1, Lazarus, etc.
    Behavior,          // Ransomware, Trojan, etc.
    Source,            // Signature-base, YARA-rules, etc.
    Technique,         // Persistence, Evasion, etc.
    Platform,          // Windows, Linux, macOS, etc.
    Severity,          // Critical, High, Medium, Low
    Custom,            // User-defined categories
}

/// Category priority levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CategoryPriority {
    Critical = 4,
    High = 3,
    Medium = 2,
    Low = 1,
    Info = 0,
}

/// Rule metadata extracted for categorization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMetadata {
    pub rule_name: String,
    pub file_path: PathBuf,
    pub author: Option<String>,
    pub description: Option<String>,
    pub reference: Vec<String>,
    pub date: Option<String>,
    pub version: Option<String>,
    pub tags: Vec<String>,
    pub yara_version: Option<String>,
    pub hash: String,
    pub file_size: u64,
    pub categories: Vec<String>,
    pub auto_assigned_categories: Vec<String>,
    pub confidence_scores: HashMap<String, f64>,
}

/// Category filter for rule selection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryFilter {
    pub include_categories: Vec<String>,
    pub exclude_categories: Vec<String>,
    pub include_types: Vec<CategoryType>,
    pub exclude_types: Vec<CategoryType>,
    pub min_priority: Option<CategoryPriority>,
    pub max_priority: Option<CategoryPriority>,
    pub include_tags: Vec<String>,
    pub exclude_tags: Vec<String>,
    pub require_all_tags: bool,
    pub platform_filter: Option<String>,
    pub date_range: Option<(u64, u64)>,
    pub author_filter: Option<String>,
}

/// Rule correlation information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleCorrelation {
    pub primary_rule: String,
    pub related_rules: Vec<RelatedRule>,
    pub correlation_type: CorrelationType,
    pub confidence_score: f64,
    pub shared_indicators: Vec<String>,
    pub behavioral_similarity: f64,
    pub temporal_correlation: Option<Duration>,
}

/// Related rule information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelatedRule {
    pub rule_name: String,
    pub relationship_type: RelationshipType,
    pub similarity_score: f64,
    pub shared_elements: Vec<String>,
}

/// Types of rule correlations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CorrelationType {
    MalwareFamilyVariant,
    BehavioralSimilarity,
    SharedIOCs,
    TemporalCorrelation,
    AuthorSimilarity,
    TechniqueSimilarity,
}

/// Types of rule relationships
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RelationshipType {
    Variant,
    Evolution,
    Dependency,
    Complement,
    Alternative,
    Superseded,
}

/// Category scanning configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryScanConfig {
    pub enabled_categories: Vec<String>,
    pub priority_order: Vec<CategoryPriority>,
    pub max_rules_per_category: Option<usize>,
    pub enable_correlation: bool,
    pub correlation_threshold: f64,
    pub enable_dynamic_selection: bool,
    pub performance_mode: PerformanceMode,
    pub timeout_per_category: Option<Duration>,
}

/// Performance modes for category scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PerformanceMode {
    Fast,      // Minimal rules, high-confidence only
    Balanced,  // Moderate rule set, good coverage
    Thorough,  // All relevant rules, maximum detection
    Custom,    // User-defined configuration
}

/// Category system statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryStats {
    pub total_categories: usize,
    pub total_rules_categorized: usize,
    pub uncategorized_rules: usize,
    pub category_distribution: HashMap<String, usize>,
    pub type_distribution: HashMap<CategoryType, usize>,
    pub priority_distribution: HashMap<CategoryPriority, usize>,
    pub correlation_count: usize,
    pub auto_categorization_accuracy: f64,
    pub last_update: u64,
}

/// YARA rule category system
pub struct YaraCategorySystem {
    categories: HashMap<String, RuleCategory>,
    rule_metadata: HashMap<String, RuleMetadata>,
    correlations: HashMap<String, Vec<RuleCorrelation>>,
    category_patterns: HashMap<CategoryType, Vec<CategoryPattern>>,
    auto_categorization_rules: Vec<AutoCategorizationRule>,
    performance_cache: HashMap<String, Vec<String>>, // category -> rule names
}

/// Pattern for automatic categorization
#[derive(Debug, Clone)]
struct CategoryPattern {
    pattern: Regex,
    category_name: String,
    confidence: f64,
    field: MetadataField,
}

/// Metadata fields for pattern matching
#[derive(Debug, Clone)]
enum MetadataField {
    RuleName,
    Description,
    Tags,
    Author,
    Reference,
    Content,
}

/// Automatic categorization rule
#[derive(Debug, Clone)]
struct AutoCategorizationRule {
    name: String,
    conditions: Vec<CategorizationCondition>,
    target_category: String,
    confidence: f64,
    priority: i32,
}

/// Condition for automatic categorization
#[derive(Debug, Clone)]
struct CategorizationCondition {
    field: MetadataField,
    pattern: Regex,
    weight: f64,
    required: bool,
}

impl Default for CategoryFilter {
    fn default() -> Self {
        Self {
            include_categories: Vec::new(),
            exclude_categories: Vec::new(),
            include_types: Vec::new(),
            exclude_types: Vec::new(),
            min_priority: None,
            max_priority: None,
            include_tags: Vec::new(),
            exclude_tags: Vec::new(),
            require_all_tags: false,
            platform_filter: None,
            date_range: None,
            author_filter: None,
        }
    }
}

impl Default for CategoryScanConfig {
    fn default() -> Self {
        Self {
            enabled_categories: Vec::new(),
            priority_order: vec![
                CategoryPriority::Critical,
                CategoryPriority::High,
                CategoryPriority::Medium,
                CategoryPriority::Low,
                CategoryPriority::Info,
            ],
            max_rules_per_category: Some(100),
            enable_correlation: true,
            correlation_threshold: 0.7,
            enable_dynamic_selection: true,
            performance_mode: PerformanceMode::Balanced,
            timeout_per_category: Some(Duration::from_secs(30)),
        }
    }
}

impl YaraCategorySystem {
    /// Create a new category system
    pub fn new() -> Self {
        let mut system = Self {
            categories: HashMap::new(),
            rule_metadata: HashMap::new(),
            correlations: HashMap::new(),
            category_patterns: HashMap::new(),
            auto_categorization_rules: Vec::new(),
            performance_cache: HashMap::new(),
        };
        
        system.initialize_default_categories();
        system.initialize_categorization_patterns();
        system
    }

    /// Initialize default categories
    fn initialize_default_categories(&mut self) {
        let default_categories = vec![
            // Malware families
            ("apt1", "APT1 / Comment Crew", CategoryType::MalwareFamily, CategoryPriority::Critical),
            ("lazarus", "Lazarus Group", CategoryType::MalwareFamily, CategoryPriority::Critical),
            ("carbanak", "Carbanak / FIN7", CategoryType::MalwareFamily, CategoryPriority::High),
            ("emotet", "Emotet Banking Trojan", CategoryType::MalwareFamily, CategoryPriority::High),
            
            // Behaviors
            ("ransomware", "Ransomware Behavior", CategoryType::Behavior, CategoryPriority::Critical),
            ("trojan", "Trojan Behavior", CategoryType::Behavior, CategoryPriority::High),
            ("backdoor", "Backdoor Behavior", CategoryType::Behavior, CategoryPriority::High),
            ("keylogger", "Keylogger Behavior", CategoryType::Behavior, CategoryPriority::Medium),
            ("rootkit", "Rootkit Behavior", CategoryType::Behavior, CategoryPriority::High),
            
            // Techniques
            ("persistence", "Persistence Techniques", CategoryType::Technique, CategoryPriority::Medium),
            ("evasion", "Evasion Techniques", CategoryType::Technique, CategoryPriority::Medium),
            ("lateral_movement", "Lateral Movement", CategoryType::Technique, CategoryPriority::High),
            ("data_exfiltration", "Data Exfiltration", CategoryType::Technique, CategoryPriority::High),
            
            // Platforms
            ("windows", "Windows Platform", CategoryType::Platform, CategoryPriority::Medium),
            ("linux", "Linux Platform", CategoryType::Platform, CategoryPriority::Medium),
            ("macos", "macOS Platform", CategoryType::Platform, CategoryPriority::Medium),
            ("android", "Android Platform", CategoryType::Platform, CategoryPriority::Medium),
            
            // Sources
            ("signature_base", "Neo23x0 Signature Base", CategoryType::Source, CategoryPriority::High),
            ("yara_rules", "YARA-Rules Repository", CategoryType::Source, CategoryPriority::Medium),
            ("reversinglabs", "ReversingLabs Rules", CategoryType::Source, CategoryPriority::Medium),
        ];
        
        for (name, description, category_type, priority) in default_categories {
            let category = RuleCategory {
                name: name.to_string(),
                description: description.to_string(),
                category_type,
                priority,
                tags: Vec::new(),
                parent_category: None,
                subcategories: Vec::new(),
                rule_count: 0,
                last_updated: chrono::Utc::now().timestamp() as u64,
            };
            
            self.categories.insert(name.to_string(), category);
        }
    }

    /// Initialize categorization patterns
    fn initialize_categorization_patterns(&mut self) {
        let patterns = vec![
            // Malware family patterns
            (CategoryType::MalwareFamily, "apt1|comment_crew", "apt1", 0.9, MetadataField::RuleName),
            (CategoryType::MalwareFamily, "lazarus|hidden_cobra", "lazarus", 0.9, MetadataField::RuleName),
            (CategoryType::MalwareFamily, "carbanak|fin7", "carbanak", 0.9, MetadataField::RuleName),
            (CategoryType::MalwareFamily, "emotet", "emotet", 0.9, MetadataField::RuleName),
            
            // Behavior patterns
            (CategoryType::Behavior, "ransom|crypto|encrypt", "ransomware", 0.8, MetadataField::Description),
            (CategoryType::Behavior, "trojan|backdoor", "trojan", 0.7, MetadataField::Description),
            (CategoryType::Behavior, "keylog|keystroke", "keylogger", 0.8, MetadataField::Description),
            (CategoryType::Behavior, "rootkit|stealth", "rootkit", 0.8, MetadataField::Description),
            
            // Platform patterns
            (CategoryType::Platform, "windows|win32|pe32", "windows", 0.7, MetadataField::Content),
            (CategoryType::Platform, "linux|elf", "linux", 0.7, MetadataField::Content),
            (CategoryType::Platform, "macos|mach-o", "macos", 0.7, MetadataField::Content),
            (CategoryType::Platform, "android|dex", "android", 0.7, MetadataField::Content),
        ];
        
        for (category_type, pattern_str, category_name, confidence, field) in patterns {
            if let Ok(pattern) = Regex::new(&format!("(?i){}", pattern_str)) {
                let category_pattern = CategoryPattern {
                    pattern,
                    category_name: category_name.to_string(),
                    confidence,
                    field,
                };
                
                self.category_patterns
                    .entry(category_type)
                    .or_insert_with(Vec::new)
                    .push(category_pattern);
            }
        }
    }

    /// Add a new category
    pub fn add_category(&mut self, category: RuleCategory) -> Result<()> {
        if self.categories.contains_key(&category.name) {
            return Err(anyhow::anyhow!("Category '{}' already exists", category.name));
        }
        
        self.categories.insert(category.name.clone(), category);
        self.invalidate_cache();
        
        Ok(())
    }

    /// Remove a category
    pub fn remove_category(&mut self, category_name: &str) -> Result<()> {
        if !self.categories.contains_key(category_name) {
            return Err(anyhow::anyhow!("Category '{}' not found", category_name));
        }
        
        // Remove category from all rules
        for metadata in self.rule_metadata.values_mut() {
            metadata.categories.retain(|cat| cat != category_name);
            metadata.auto_assigned_categories.retain(|cat| cat != category_name);
        }
        
        self.categories.remove(category_name);
        self.invalidate_cache();
        
        Ok(())
    }

    /// Categorize rules from a directory
    pub async fn categorize_rules_from_directory<P: AsRef<Path>>(
        &mut self,
        directory: P,
    ) -> Result<usize> {
        info!("Starting rule categorization from directory: {:?}", directory.as_ref());
        let start_time = Instant::now();
        
        let mut categorized_count = 0;
        
        self.scan_directory_for_rules(directory.as_ref(), &mut categorized_count).await
            .context("Failed to scan directory for rules")?;
        
        // Perform correlation analysis
        self.analyze_rule_correlations().await
            .context("Failed to analyze rule correlations")?;
        
        // Update category statistics
        self.update_category_statistics();
        
        info!(
            "Categorization completed: {} rules processed in {:?}",
            categorized_count,
            start_time.elapsed()
        );
        
        Ok(categorized_count)
    }

    /// Scan directory recursively for YARA rules
    fn scan_directory_for_rules<'a>(
        &'a mut self,
        directory: &'a Path,
        categorized_count: &'a mut usize,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let mut entries = fs::read_dir(directory).await
                .with_context(|| format!("Failed to read directory: {:?}", directory))?;
            
            while let Some(entry) = entries.next_entry().await? {
                let path = entry.path();
                
                if path.is_file() {
                    if let Some(extension) = path.extension() {
                        let ext_str = extension.to_string_lossy().to_lowercase();
                        if ext_str == "yar" || ext_str == "yara" {
                            if let Err(e) = self.categorize_rule_file(&path).await {
                                warn!("Failed to categorize rule file {:?}: {}", path, e);
                            } else {
                                *categorized_count += 1;
                            }
                        }
                    }
                } else if path.is_dir() {
                    self.scan_directory_for_rules(&path, categorized_count).await?;
                }
            }
            
            Ok(())
        })
    }

    /// Categorize a single rule file
    async fn categorize_rule_file(&mut self, file_path: &Path) -> Result<()> {
        let content = fs::read_to_string(file_path).await
            .with_context(|| format!("Failed to read rule file: {:?}", file_path))?;
        
        let metadata = fs::metadata(file_path).await
            .with_context(|| format!("Failed to get file metadata: {:?}", file_path))?;
        
        // Extract rule metadata
        let mut rule_metadata = self.extract_rule_metadata(&content, file_path, metadata.len())?;
        
        // Perform automatic categorization
        self.auto_categorize_rule(&mut rule_metadata, &content)?;
        
        // Store metadata
        self.rule_metadata.insert(rule_metadata.rule_name.clone(), rule_metadata);
        
        Ok(())
    }

    /// Extract metadata from rule content
    fn extract_rule_metadata(
        &self,
        content: &str,
        file_path: &Path,
        file_size: u64,
    ) -> Result<RuleMetadata> {
        let rule_name = self.extract_rule_name(content)
            .unwrap_or_else(|| "unknown".to_string());
        
        let mut metadata = RuleMetadata {
            rule_name,
            file_path: file_path.to_path_buf(),
            author: None,
            description: None,
            reference: Vec::new(),
            date: None,
            version: None,
            tags: Vec::new(),
            yara_version: None,
            hash: self.calculate_content_hash(content),
            file_size,
            categories: Vec::new(),
            auto_assigned_categories: Vec::new(),
            confidence_scores: HashMap::new(),
        };
        
        // Parse metadata from rule content
        for line in content.lines() {
            let line = line.trim();
            
            if line.starts_with("author") {
                metadata.author = self.extract_metadata_value(line);
            } else if line.starts_with("description") {
                metadata.description = self.extract_metadata_value(line);
            } else if line.starts_with("reference") {
                if let Some(reference) = self.extract_metadata_value(line) {
                    metadata.reference.push(reference);
                }
            } else if line.starts_with("date") {
                metadata.date = self.extract_metadata_value(line);
            } else if line.starts_with("version") {
                metadata.version = self.extract_metadata_value(line);
            }
        }
        
        Ok(metadata)
    }

    /// Automatically categorize a rule based on patterns
    fn auto_categorize_rule(
        &mut self,
        rule_metadata: &mut RuleMetadata,
        content: &str,
    ) -> Result<()> {
        for (_category_type, patterns) in &self.category_patterns {
            for pattern in patterns {
                let text_to_match = match pattern.field {
                    MetadataField::RuleName => &rule_metadata.rule_name,
                    MetadataField::Description => rule_metadata.description.as_deref().unwrap_or(""),
                    MetadataField::Author => rule_metadata.author.as_deref().unwrap_or(""),
                    MetadataField::Content => content,
                    MetadataField::Tags => &rule_metadata.tags.iter().cloned().collect::<Vec<_>>().join(" "),
                    MetadataField::Reference => &rule_metadata.reference.join(" "),
                };
                
                if pattern.pattern.is_match(text_to_match) {
                    if !rule_metadata.auto_assigned_categories.contains(&pattern.category_name) {
                        rule_metadata.auto_assigned_categories.push(pattern.category_name.clone());
                    }
                    rule_metadata.confidence_scores.insert(
                        pattern.category_name.clone(),
                        pattern.confidence,
                    );
                    
                    debug!(
                        "Auto-assigned category '{}' to rule '{}' with confidence {:.2}",
                        pattern.category_name, rule_metadata.rule_name, pattern.confidence
                    );
                }
            }
        }
        
        Ok(())
    }

    /// Filter rules by category criteria
    pub fn filter_rules(&self, filter: &CategoryFilter) -> Result<Vec<String>> {
        let mut filtered_rules = Vec::new();
        
        for (rule_name, metadata) in &self.rule_metadata {
            if self.rule_matches_filter(metadata, filter) {
                filtered_rules.push(rule_name.clone());
            }
        }
        
        // Sort by priority if categories are specified
        if !filter.include_categories.is_empty() {
            filtered_rules.sort_by(|a, b| {
                let priority_a = self.get_rule_max_priority(a);
                let priority_b = self.get_rule_max_priority(b);
                priority_b.cmp(&priority_a) // Higher priority first
            });
        }
        
        Ok(filtered_rules)
    }

    /// Check if a rule matches the filter criteria
    fn rule_matches_filter(&self, metadata: &RuleMetadata, filter: &CategoryFilter) -> bool {
        // Check include categories
        if !filter.include_categories.is_empty() {
            let has_included_category = metadata.categories.iter()
                .chain(metadata.auto_assigned_categories.iter())
                .any(|cat| filter.include_categories.contains(cat));
            
            if !has_included_category {
                return false;
            }
        }
        
        // Check exclude categories
        if !filter.exclude_categories.is_empty() {
            let has_excluded_category = metadata.categories.iter()
                .chain(metadata.auto_assigned_categories.iter())
                .any(|cat| filter.exclude_categories.contains(cat));
            
            if has_excluded_category {
                return false;
            }
        }
        
        // Check category types
        if !filter.include_types.is_empty() || !filter.exclude_types.is_empty() {
            let mut rule_types: Vec<CategoryType> = metadata.categories.iter()
                .chain(metadata.auto_assigned_categories.iter())
                .filter_map(|cat_name| self.categories.get(cat_name))
                .map(|cat| cat.category_type.clone())
                .collect();
            rule_types.sort();
            rule_types.dedup();
            
            if !filter.include_types.is_empty() {
                if !rule_types.iter().any(|t| filter.include_types.contains(t)) {
                    return false;
                }
            }
            
            if !filter.exclude_types.is_empty() {
                if rule_types.iter().any(|t| filter.exclude_types.contains(t)) {
                    return false;
                }
            }
        }
        
        // Check priority range
        if let Some(min_priority) = &filter.min_priority {
            let rule_max_priority = self.get_rule_max_priority(&metadata.rule_name);
            if rule_max_priority < *min_priority {
                return false;
            }
        }
        
        if let Some(max_priority) = &filter.max_priority {
            let rule_max_priority = self.get_rule_max_priority(&metadata.rule_name);
            if rule_max_priority > *max_priority {
                return false;
            }
        }
        
        // Check author filter
        if let Some(author_filter) = &filter.author_filter {
            if let Some(author) = &metadata.author {
                if !author.to_lowercase().contains(&author_filter.to_lowercase()) {
                    return false;
                }
            } else {
                return false;
            }
        }
        
        true
    }

    /// Get the maximum priority for a rule based on its categories
    fn get_rule_max_priority(&self, rule_name: &str) -> CategoryPriority {
        if let Some(metadata) = self.rule_metadata.get(rule_name) {
            metadata.categories.iter()
                .chain(metadata.auto_assigned_categories.iter())
                .filter_map(|cat_name| self.categories.get(cat_name))
                .map(|cat| cat.priority.clone())
                .max()
                .unwrap_or(CategoryPriority::Info)
        } else {
            CategoryPriority::Info
        }
    }

    /// Analyze rule correlations
    async fn analyze_rule_correlations(&mut self) -> Result<()> {
        info!("Analyzing rule correlations");
        
        let rule_names: Vec<String> = self.rule_metadata.keys().cloned().collect();
        
        for primary_rule in &rule_names {
            let mut correlations = Vec::new();
            
            for other_rule in &rule_names {
                if primary_rule == other_rule {
                    continue;
                }
                
                if let Some(correlation) = self.calculate_rule_correlation(primary_rule, other_rule) {
                    correlations.push(correlation);
                }
            }
            
            if !correlations.is_empty() {
                // Sort by confidence score
                correlations.sort_by(|a, b| b.confidence_score.partial_cmp(&a.confidence_score).unwrap());
                
                // Keep only top correlations
                correlations.truncate(10);
                
                self.correlations.insert(primary_rule.clone(), correlations);
            }
        }
        
        info!("Correlation analysis completed for {} rules", rule_names.len());
        Ok(())
    }

    /// Calculate correlation between two rules
    fn calculate_rule_correlation(
        &self,
        rule1_name: &str,
        rule2_name: &str,
    ) -> Option<RuleCorrelation> {
        let metadata1 = self.rule_metadata.get(rule1_name)?;
        let metadata2 = self.rule_metadata.get(rule2_name)?;
        
        // Calculate various similarity metrics
        let category_similarity = self.calculate_category_similarity(metadata1, metadata2);
        let author_similarity = self.calculate_author_similarity(metadata1, metadata2);
        let tag_similarity = self.calculate_tag_similarity(metadata1, metadata2);
        
        // Combined confidence score
        let confidence_score = (category_similarity * 0.5) + (author_similarity * 0.3) + (tag_similarity * 0.2);
        
        if confidence_score > 0.3 {
            let correlation_type = if category_similarity > 0.8 {
                CorrelationType::MalwareFamilyVariant
            } else if author_similarity > 0.9 {
                CorrelationType::AuthorSimilarity
            } else {
                CorrelationType::BehavioralSimilarity
            };
            
            let related_rule = RelatedRule {
                rule_name: rule2_name.to_string(),
                relationship_type: RelationshipType::Variant,
                similarity_score: confidence_score,
                shared_elements: Vec::new(), // Would be populated with actual shared elements
            };
            
            Some(RuleCorrelation {
                primary_rule: rule1_name.to_string(),
                related_rules: vec![related_rule],
                correlation_type,
                confidence_score,
                shared_indicators: Vec::new(),
                behavioral_similarity: category_similarity,
                temporal_correlation: None,
            })
        } else {
            None
        }
    }

    /// Calculate category similarity between two rules
    fn calculate_category_similarity(&self, metadata1: &RuleMetadata, metadata2: &RuleMetadata) -> f64 {
        let categories1: Vec<_> = metadata1.categories.iter()
            .chain(metadata1.auto_assigned_categories.iter())
            .collect();
        
        let categories2: Vec<_> = metadata2.categories.iter()
            .chain(metadata2.auto_assigned_categories.iter())
            .collect();
        
        if categories1.is_empty() && categories2.is_empty() {
            return 0.0;
        }
        
        let intersection_size = categories1.iter()
            .filter(|cat| categories2.contains(cat))
            .count();
        let mut union_categories = categories1.clone();
        for cat in &categories2 {
            if !union_categories.contains(cat) {
                union_categories.push(*cat);
            }
        }
        let union_size = union_categories.len();
        
        intersection_size as f64 / union_size as f64
    }

    /// Calculate author similarity between two rules
    fn calculate_author_similarity(&self, metadata1: &RuleMetadata, metadata2: &RuleMetadata) -> f64 {
        match (&metadata1.author, &metadata2.author) {
            (Some(author1), Some(author2)) => {
                if author1.to_lowercase() == author2.to_lowercase() {
                    1.0
                } else {
                    0.0
                }
            }
            _ => 0.0,
        }
    }

    /// Calculate tag similarity between two rules
    fn calculate_tag_similarity(&self, metadata1: &RuleMetadata, metadata2: &RuleMetadata) -> f64 {
        if metadata1.tags.is_empty() && metadata2.tags.is_empty() {
            return 0.0;
        }
        
        let intersection_size = metadata1.tags.iter()
            .filter(|tag| metadata2.tags.contains(tag))
            .count();
        let mut union_tags = metadata1.tags.clone();
        for tag in &metadata2.tags {
            if !union_tags.contains(tag) {
                union_tags.push(tag.clone());
            }
        }
        let union_size = union_tags.len();
        
        intersection_size as f64 / union_size as f64
    }

    /// Get category statistics
    pub fn get_category_stats(&self) -> CategoryStats {
        let total_categories = self.categories.len();
        let total_rules_categorized = self.rule_metadata.len();
        let uncategorized_rules = self.rule_metadata.values()
            .filter(|m| m.categories.is_empty() && m.auto_assigned_categories.is_empty())
            .count();
        
        let mut category_distribution = HashMap::new();
        let mut type_distribution = HashMap::new();
        let mut priority_distribution = HashMap::new();
        
        for metadata in self.rule_metadata.values() {
            for category_name in metadata.categories.iter().chain(metadata.auto_assigned_categories.iter()) {
                *category_distribution.entry(category_name.clone()).or_insert(0) += 1;
                
                if let Some(category) = self.categories.get(category_name) {
                    *type_distribution.entry(category.category_type.clone()).or_insert(0) += 1;
                    *priority_distribution.entry(category.priority.clone()).or_insert(0) += 1;
                }
            }
        }
        
        CategoryStats {
            total_categories,
            total_rules_categorized,
            uncategorized_rules,
            category_distribution,
            type_distribution,
            priority_distribution,
            correlation_count: self.correlations.len(),
            auto_categorization_accuracy: 0.85, // Would be calculated based on validation
            last_update: chrono::Utc::now().timestamp() as u64,
        }
    }

    /// Update category statistics
    fn update_category_statistics(&mut self) {
        for category in self.categories.values_mut() {
            category.rule_count = self.rule_metadata.values()
                .filter(|m| {
                    m.categories.contains(&category.name) || 
                    m.auto_assigned_categories.contains(&category.name)
                })
                .count();
            
            category.last_updated = chrono::Utc::now().timestamp() as u64;
        }
    }

    /// Invalidate performance cache
    fn invalidate_cache(&mut self) {
        self.performance_cache.clear();
    }

    /// Helper methods
    fn extract_rule_name(&self, content: &str) -> Option<String> {
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with("rule ") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    return Some(parts[1].trim_end_matches('{').to_string());
                }
            }
        }
        None
    }

    fn extract_metadata_value(&self, line: &str) -> Option<String> {
        if let Some(equals_pos) = line.find('=') {
            let value = line[equals_pos + 1..].trim();
            let value = value.trim_matches('"').trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
        None
    }

    fn calculate_content_hash(&self, content: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Get all categories
    pub fn get_categories(&self) -> &HashMap<String, RuleCategory> {
        &self.categories
    }

    /// Get rule metadata
    pub fn get_rule_metadata(&self, rule_name: &str) -> Option<&RuleMetadata> {
        self.rule_metadata.get(rule_name)
    }

    /// Get rule correlations
    pub fn get_rule_correlations(&self, rule_name: &str) -> Option<&Vec<RuleCorrelation>> {
        self.correlations.get(rule_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Removed unused import: tempfile::TempDir

    #[test]
    fn test_category_creation() {
        let mut system = YaraCategorySystem::new();
        
        let category = RuleCategory {
            name: "test_category".to_string(),
            description: "Test Category".to_string(),
            category_type: CategoryType::Custom,
            priority: CategoryPriority::Medium,
            tags: Vec::new(),
            parent_category: None,
            subcategories: Vec::new(),
            rule_count: 0,
            last_updated: 0,
        };
        
        assert!(system.add_category(category).is_ok());
        assert!(system.categories.contains_key("test_category"));
    }

    #[test]
    fn test_rule_filtering() {
        let mut system = YaraCategorySystem::new();
        
        // Add test rule metadata
        let mut metadata = RuleMetadata {
            rule_name: "test_rule".to_string(),
            file_path: PathBuf::from("/test/rule.yar"),
            author: Some("Test Author".to_string()),
            description: Some("Test rule".to_string()),
            reference: Vec::new(),
            date: None,
            version: None,
            tags: Vec::new(),
            yara_version: None,
            hash: "test_hash".to_string(),
            file_size: 1024,
            categories: Vec::new(),
            auto_assigned_categories: Vec::new(),
            confidence_scores: HashMap::new(),
        };
        
        metadata.auto_assigned_categories.push("ransomware".to_string());
        system.rule_metadata.insert("test_rule".to_string(), metadata);
        
        // Test filtering
        let mut filter = CategoryFilter::default();
        filter.include_categories.push("ransomware".to_string());
        
        let filtered_rules = system.filter_rules(&filter).unwrap();
        assert_eq!(filtered_rules.len(), 1);
        assert_eq!(filtered_rules[0], "test_rule");
    }

    #[test]
    fn test_category_similarity() {
        let system = YaraCategorySystem::new();
        
        let mut metadata1 = RuleMetadata {
            rule_name: "rule1".to_string(),
            file_path: PathBuf::from("/test/rule1.yar"),
            author: Some("Author1".to_string()),
            description: None,
            reference: Vec::new(),
            date: None,
            version: None,
            tags: Vec::new(),
            yara_version: None,
            hash: "hash1".to_string(),
            file_size: 1024,
            categories: Vec::new(),
            auto_assigned_categories: Vec::new(),
            confidence_scores: HashMap::new(),
        };
        
        let mut metadata2 = metadata1.clone();
        metadata2.rule_name = "rule2".to_string();
        
        metadata1.auto_assigned_categories.push("ransomware".to_string());
        metadata1.auto_assigned_categories.push("windows".to_string());
        
        metadata2.auto_assigned_categories.push("ransomware".to_string());
        metadata2.auto_assigned_categories.push("trojan".to_string());
        
        let similarity = system.calculate_category_similarity(&metadata1, &metadata2);
        assert!(similarity > 0.0 && similarity < 1.0);
    }
}
