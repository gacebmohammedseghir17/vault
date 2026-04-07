//! Category Scanner Module
//!
//! This module provides simplified category filtering for YARA rules with
//! include/exclude logic for enhanced scanning operations.

use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use super::category_system::RuleMetadata;

/// Simple category filter for rule selection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryFilter {
    pub include_categories: Vec<String>,
    pub exclude_categories: Vec<String>,
}

impl CategoryFilter {
    /// Create a new CategoryFilter from command line arguments
    ///
    /// # Arguments
    /// * `include` - Array of category names to include
    /// * `exclude` - Array of category names to exclude
    ///
    /// # Returns
    /// A new CategoryFilter instance
    pub fn from_args(include: &[&str], exclude: &[&str]) -> Self {
        Self {
            include_categories: include.iter().map(|s| s.to_string()).collect(),
            exclude_categories: exclude.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// Check if a rule matches the filter criteria
    ///
    /// Returns true if:
    /// - metadata.category is in include_categories (or include_categories is empty, meaning include all)
    /// - AND metadata.category is NOT in exclude_categories
    ///
    /// # Arguments
    /// * `metadata` - The rule metadata to check
    ///
    /// # Returns
    /// true if the rule matches the filter criteria, false otherwise
    pub fn matches(&self, metadata: &RuleMetadata) -> bool {
        // Get all categories for this rule (both manual and auto-assigned)
        let rule_categories: Vec<&String> = metadata
            .categories
            .iter()
            .chain(metadata.auto_assigned_categories.iter())
            .collect();

        // If no categories are found, only match if include_categories is empty
        if rule_categories.is_empty() {
            return self.include_categories.is_empty() && self.exclude_categories.is_empty();
        }

        // Check exclude categories first (exclusion takes priority)
        if !self.exclude_categories.is_empty() {
            for rule_category in &rule_categories {
                if self.exclude_categories.contains(rule_category) {
                    debug!(
                        "Rule {} excluded due to category: {}",
                        metadata.rule_name, rule_category
                    );
                    return false;
                }
            }
        }

        // Check include categories
        if self.include_categories.is_empty() {
            // If no include categories specified, include all (that aren't excluded)
            debug!("Rule {} included (no include filter)", metadata.rule_name);
            return true;
        } else {
            // Check if any rule category is in the include list
            for rule_category in &rule_categories {
                if self.include_categories.contains(rule_category) {
                    debug!(
                        "Rule {} included due to category: {}",
                        metadata.rule_name, rule_category
                    );
                    return true;
                }
            }

            // No matching include category found
            debug!(
                "Rule {} excluded (no matching include category)",
                metadata.rule_name
            );
            return false;
        }
    }

    /// Create an empty filter that matches all rules
    pub fn allow_all() -> Self {
        Self {
            include_categories: Vec::new(),
            exclude_categories: Vec::new(),
        }
    }

    /// Create a filter that excludes specific categories
    pub fn exclude_only(exclude: &[&str]) -> Self {
        Self {
            include_categories: Vec::new(),
            exclude_categories: exclude.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// Create a filter that includes only specific categories
    pub fn include_only(include: &[&str]) -> Self {
        Self {
            include_categories: include.iter().map(|s| s.to_string()).collect(),
            exclude_categories: Vec::new(),
        }
    }

    /// Check if the filter is empty (matches all rules)
    pub fn is_empty(&self) -> bool {
        self.include_categories.is_empty() && self.exclude_categories.is_empty()
    }

    /// Get a summary of the filter configuration
    pub fn summary(&self) -> String {
        if self.is_empty() {
            "No category filtering (all rules)".to_string()
        } else {
            let mut parts = Vec::new();

            if !self.include_categories.is_empty() {
                parts.push(format!("Include: [{}]", self.include_categories.join(", ")));
            }

            if !self.exclude_categories.is_empty() {
                parts.push(format!("Exclude: [{}]", self.exclude_categories.join(", ")));
            }

            parts.join(", ")
        }
    }
}

impl Default for CategoryFilter {
    fn default() -> Self {
        Self::allow_all()
    }
}

/// Parse comma-separated category string into a vector
///
/// # Arguments
/// * `categories_str` - Comma-separated string of categories
///
/// # Returns
/// Vector of trimmed category names
pub fn parse_categories(categories_str: &str) -> Vec<String> {
    categories_str
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Create CategoryFilter from comma-separated strings
///
/// # Arguments
/// * `include_str` - Optional comma-separated string of categories to include
/// * `exclude_str` - Optional comma-separated string of categories to exclude
///
/// # Returns
/// A new CategoryFilter instance
pub fn create_filter_from_strings(
    include_str: Option<&str>,
    exclude_str: Option<&str>,
) -> CategoryFilter {
    let include_categories = include_str.map(parse_categories).unwrap_or_default();

    let exclude_categories = exclude_str.map(parse_categories).unwrap_or_default();

    info!(
        "Created category filter - Include: {:?}, Exclude: {:?}",
        include_categories, exclude_categories
    );

    CategoryFilter {
        include_categories,
        exclude_categories,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::path::PathBuf;

    fn create_test_metadata(name: &str, categories: Vec<&str>) -> RuleMetadata {
        RuleMetadata {
            rule_name: name.to_string(),
            file_path: PathBuf::from(format!("/test/{}.yar", name)),
            author: Some("Test Author".to_string()),
            description: Some("Test rule".to_string()),
            reference: vec![],
            date: Some("2024-01-01".to_string()),
            version: Some("1.0".to_string()),
            tags: vec![],
            yara_version: Some("4.0".to_string()),
            hash: "test_hash".to_string(),
            file_size: 1024,
            categories: categories.iter().map(|s| s.to_string()).collect(),
            auto_assigned_categories: vec![],
            confidence_scores: HashMap::new(),
        }
    }

    #[test]
    fn test_from_args() {
        let filter = CategoryFilter::from_args(&["ransomware", "apt"], &["test", "debug"]);

        assert_eq!(filter.include_categories, vec!["ransomware", "apt"]);
        assert_eq!(filter.exclude_categories, vec!["test", "debug"]);
    }

    #[test]
    fn test_matches_include_only() {
        let filter = CategoryFilter::include_only(&["ransomware", "apt"]);

        let ransomware_rule = create_test_metadata("test_ransomware", vec!["ransomware"]);
        let apt_rule = create_test_metadata("test_apt", vec!["apt"]);
        let malware_rule = create_test_metadata("test_malware", vec!["malware"]);

        assert!(filter.matches(&ransomware_rule));
        assert!(filter.matches(&apt_rule));
        assert!(!filter.matches(&malware_rule));
    }

    #[test]
    fn test_matches_exclude_only() {
        let filter = CategoryFilter::exclude_only(&["test", "debug"]);

        let ransomware_rule = create_test_metadata("test_ransomware", vec!["ransomware"]);
        let test_rule = create_test_metadata("test_rule", vec!["test"]);
        let debug_rule = create_test_metadata("debug_rule", vec!["debug"]);

        assert!(filter.matches(&ransomware_rule));
        assert!(!filter.matches(&test_rule));
        assert!(!filter.matches(&debug_rule));
    }

    #[test]
    fn test_matches_include_and_exclude() {
        let filter =
            CategoryFilter::from_args(&["ransomware", "apt", "malware"], &["test", "debug"]);

        let ransomware_rule = create_test_metadata("test_ransomware", vec!["ransomware"]);
        let test_ransomware_rule = create_test_metadata("test_rule", vec!["ransomware", "test"]);
        let other_rule = create_test_metadata("other_rule", vec!["other"]);

        assert!(filter.matches(&ransomware_rule));
        assert!(!filter.matches(&test_ransomware_rule)); // Excluded due to "test" category
        assert!(!filter.matches(&other_rule)); // Not in include list
    }

    #[test]
    fn test_matches_empty_filter() {
        let filter = CategoryFilter::allow_all();

        let ransomware_rule = create_test_metadata("test_ransomware", vec!["ransomware"]);
        let no_category_rule = create_test_metadata("no_category", vec![]);

        assert!(filter.matches(&ransomware_rule));
        assert!(filter.matches(&no_category_rule));
    }

    #[test]
    fn test_parse_categories() {
        let categories = parse_categories("ransomware, apt,malware , trojan");
        assert_eq!(categories, vec!["ransomware", "apt", "malware", "trojan"]);

        let empty_categories = parse_categories("");
        assert!(empty_categories.is_empty());

        let single_category = parse_categories("ransomware");
        assert_eq!(single_category, vec!["ransomware"]);
    }

    #[test]
    fn test_create_filter_from_strings() {
        let filter = create_filter_from_strings(Some("ransomware,apt"), Some("test,debug"));

        assert_eq!(filter.include_categories, vec!["ransomware", "apt"]);
        assert_eq!(filter.exclude_categories, vec!["test", "debug"]);

        let empty_filter = create_filter_from_strings(None, None);
        assert!(empty_filter.is_empty());
    }
}
