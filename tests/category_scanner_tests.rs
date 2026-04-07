//! Unit tests for the CategoryFilter implementation
//!
//! This module contains comprehensive tests for the category filtering functionality,
//! including various include/exclude scenarios and CLI parsing integration.

use erdps_agent::yara::CategoryFilter;
use std::collections::HashMap;
use std::path::PathBuf;
// Removed unused imports: parse_categories, create_filter_from_strings
use erdps_agent::yara::category_system::RuleMetadata;

/// Create a dummy RuleMetadata for testing
fn create_test_metadata(
    rule_name: &str,
    categories: Vec<String>,
    tags: Vec<String>,
) -> RuleMetadata {
    RuleMetadata {
        rule_name: rule_name.to_string(),
        file_path: PathBuf::from(format!("/test/rules/{}.yar", rule_name)),
        author: Some("Test Author".to_string()),
        description: Some("Test rule description".to_string()),
        reference: vec!["https://test.example.com".to_string()],
        date: Some("2023-01-01".to_string()),
        version: Some("1.0".to_string()),
        tags,
        yara_version: Some("4.0".to_string()),
        hash: "test_hash_123".to_string(),
        file_size: 1024,
        categories,
        auto_assigned_categories: Vec::new(),
        confidence_scores: HashMap::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_category_filter_no_restrictions() {
        // Test with no include/exclude categories - should match all
        let filter = CategoryFilter::from_args(&[], &[]);

        let ransomware_rule = create_test_metadata(
            "test_ransomware",
            vec!["ransomware".to_string()],
            vec!["test".to_string()],
        );
        let apt_rule = create_test_metadata(
            "test_apt",
            vec!["apt".to_string()],
            vec!["test".to_string()],
        );
        let malware_rule = create_test_metadata(
            "test_malware",
            vec!["malware".to_string()],
            vec!["test".to_string()],
        );

        assert!(
            filter.matches(&ransomware_rule),
            "Should match ransomware when no restrictions"
        );
        assert!(
            filter.matches(&apt_rule),
            "Should match apt when no restrictions"
        );
        assert!(
            filter.matches(&malware_rule),
            "Should match malware when no restrictions"
        );
    }

    #[test]
    fn test_category_filter_include_only() {
        // Test with include categories only
        let filter = CategoryFilter::from_args(&["ransomware", "apt"], &[]);

        let ransomware_rule = create_test_metadata(
            "test_ransomware",
            vec!["ransomware".to_string()],
            vec!["test".to_string()],
        );
        let apt_rule = create_test_metadata(
            "test_apt",
            vec!["apt".to_string()],
            vec!["test".to_string()],
        );
        let malware_rule = create_test_metadata(
            "test_malware",
            vec!["malware".to_string()],
            vec!["test".to_string()],
        );
        let trojan_rule = create_test_metadata(
            "test_trojan",
            vec!["trojan".to_string()],
            vec!["test".to_string()],
        );

        assert!(
            filter.matches(&ransomware_rule),
            "Should match included ransomware category"
        );
        assert!(
            filter.matches(&apt_rule),
            "Should match included apt category"
        );
        assert!(
            !filter.matches(&malware_rule),
            "Should not match non-included malware category"
        );
        assert!(
            !filter.matches(&trojan_rule),
            "Should not match non-included trojan category"
        );
    }

    #[test]
    fn test_category_filter_exclude_only() {
        // Test with exclude categories only
        let filter = CategoryFilter::from_args(&[], &["malware", "trojan"]);

        let ransomware_rule = create_test_metadata(
            "test_ransomware",
            vec!["ransomware".to_string()],
            vec!["test".to_string()],
        );
        let apt_rule = create_test_metadata(
            "test_apt",
            vec!["apt".to_string()],
            vec!["test".to_string()],
        );
        let malware_rule = create_test_metadata(
            "test_malware",
            vec!["malware".to_string()],
            vec!["test".to_string()],
        );
        let trojan_rule = create_test_metadata(
            "test_trojan",
            vec!["trojan".to_string()],
            vec!["test".to_string()],
        );

        assert!(
            filter.matches(&ransomware_rule),
            "Should match non-excluded ransomware category"
        );
        assert!(
            filter.matches(&apt_rule),
            "Should match non-excluded apt category"
        );
        assert!(
            !filter.matches(&malware_rule),
            "Should not match excluded malware category"
        );
        assert!(
            !filter.matches(&trojan_rule),
            "Should not match excluded trojan category"
        );
    }

    #[test]
    fn test_category_filter_include_and_exclude() {
        // Test with both include and exclude categories
        let filter = CategoryFilter::from_args(&["ransomware", "apt", "malware"], &["malware"]);

        let ransomware_rule = create_test_metadata(
            "test_ransomware",
            vec!["ransomware".to_string()],
            vec!["test".to_string()],
        );
        let apt_rule = create_test_metadata(
            "test_apt",
            vec!["apt".to_string()],
            vec!["test".to_string()],
        );
        let malware_rule = create_test_metadata(
            "test_malware",
            vec!["malware".to_string()],
            vec!["test".to_string()],
        );
        let trojan_rule = create_test_metadata(
            "test_trojan",
            vec!["trojan".to_string()],
            vec!["test".to_string()],
        );

        assert!(
            filter.matches(&ransomware_rule),
            "Should match included and non-excluded ransomware"
        );
        assert!(
            filter.matches(&apt_rule),
            "Should match included and non-excluded apt"
        );
        assert!(
            !filter.matches(&malware_rule),
            "Should not match excluded malware even if included"
        );
        assert!(
            !filter.matches(&trojan_rule),
            "Should not match non-included trojan"
        );
    }

    #[test]
    fn test_category_filter_case_sensitivity() {
        // Test case sensitivity in category matching
        let filter = CategoryFilter::from_args(&["Ransomware", "APT"], &[]);

        let ransomware_lower = create_test_metadata(
            "test_ransomware_lower",
            vec!["ransomware".to_string()],
            vec!["test".to_string()],
        );
        let ransomware_upper = create_test_metadata(
            "test_ransomware_upper",
            vec!["RANSOMWARE".to_string()],
            vec!["test".to_string()],
        );
        let ransomware_mixed = create_test_metadata(
            "test_ransomware_mixed",
            vec!["Ransomware".to_string()],
            vec!["test".to_string()],
        );
        let apt_lower = create_test_metadata(
            "test_apt_lower",
            vec!["apt".to_string()],
            vec!["test".to_string()],
        );
        let apt_upper = create_test_metadata(
            "test_apt_upper",
            vec!["APT".to_string()],
            vec!["test".to_string()],
        );

        // Exact case matches should work
        assert!(
            filter.matches(&ransomware_mixed),
            "Should match exact case Ransomware"
        );
        assert!(filter.matches(&apt_upper), "Should match exact case APT");

        // Different cases should not match (case-sensitive)
        assert!(
            !filter.matches(&ransomware_lower),
            "Should not match different case ransomware"
        );
        assert!(
            !filter.matches(&ransomware_upper),
            "Should not match different case RANSOMWARE"
        );
        assert!(
            !filter.matches(&apt_lower),
            "Should not match different case apt"
        );
    }

    #[test]
    fn test_category_filter_empty_category() {
        // Test behavior with empty category strings
        let filter = CategoryFilter::from_args(&["ransomware"], &[]);

        let empty_category_rule = create_test_metadata(
            "test_empty_category",
            vec!["".to_string()],
            vec!["test".to_string()],
        );
        let normal_rule = create_test_metadata(
            "test_normal",
            vec!["ransomware".to_string()],
            vec!["test".to_string()],
        );

        assert!(
            !filter.matches(&empty_category_rule),
            "Should not match empty category"
        );
        assert!(filter.matches(&normal_rule), "Should match normal category");
    }

    #[test]
    fn test_category_filter_whitespace_handling() {
        // Test that whitespace in categories is handled properly
        let filter = CategoryFilter::from_args(&["ransomware", "apt malware"], &[]);

        let ransomware_rule = create_test_metadata(
            "test_ransomware",
            vec!["ransomware".to_string()],
            vec!["test".to_string()],
        );
        let apt_malware_rule = create_test_metadata(
            "test_apt_malware",
            vec!["apt malware".to_string()],
            vec!["test".to_string()],
        );
        let apt_rule = create_test_metadata(
            "test_apt",
            vec!["apt".to_string()],
            vec!["test".to_string()],
        );

        assert!(filter.matches(&ransomware_rule), "Should match ransomware");
        assert!(
            filter.matches(&apt_malware_rule),
            "Should match category with spaces"
        );
        assert!(
            !filter.matches(&apt_rule),
            "Should not match partial category name"
        );
    }

    #[test]
    fn test_parse_categories_function() {
        // Test the parse_categories helper function from category_scanner module
        use erdps_agent::yara::category_scanner::parse_categories;

        let categories = parse_categories("ransomware,apt,malware");
        assert_eq!(categories, vec!["ransomware", "apt", "malware"]);

        let categories_with_spaces = parse_categories("ransomware, apt , malware ");
        assert_eq!(categories_with_spaces, vec!["ransomware", "apt", "malware"]);

        let empty_categories = parse_categories("");
        assert_eq!(empty_categories, Vec::<String>::new());

        let single_category = parse_categories("ransomware");
        assert_eq!(single_category, vec!["ransomware"]);
    }

    #[test]
    fn test_create_filter_from_strings() {
        // Test the create_filter_from_strings helper function from category_scanner module
        use erdps_agent::yara::category_scanner::create_filter_from_strings;

        let filter = create_filter_from_strings(Some("ransomware,apt"), Some("malware,trojan"));

        let ransomware_rule = create_test_metadata(
            "test_ransomware",
            vec!["ransomware".to_string()],
            vec!["test".to_string()],
        );
        let malware_rule = create_test_metadata(
            "test_malware",
            vec!["malware".to_string()],
            vec!["test".to_string()],
        );
        let spyware_rule = create_test_metadata(
            "test_spyware",
            vec!["spyware".to_string()],
            vec!["test".to_string()],
        );

        assert!(
            filter.matches(&ransomware_rule),
            "Should match included ransomware"
        );
        assert!(
            !filter.matches(&malware_rule),
            "Should not match excluded malware"
        );
        assert!(
            !filter.matches(&spyware_rule),
            "Should not match non-included spyware"
        );
    }

    #[test]
    fn test_create_filter_from_strings_none_values() {
        // Test create_filter_from_strings with None values
        use erdps_agent::yara::category_scanner::create_filter_from_strings;

        let filter_include_only = create_filter_from_strings(Some("ransomware"), None);

        let filter_exclude_only = create_filter_from_strings(None, Some("malware"));

        let filter_none = create_filter_from_strings(None, None);

        let ransomware_rule = create_test_metadata(
            "test_ransomware",
            vec!["ransomware".to_string()],
            vec!["test".to_string()],
        );
        let malware_rule = create_test_metadata(
            "test_malware",
            vec!["malware".to_string()],
            vec!["test".to_string()],
        );

        // Include only filter
        assert!(filter_include_only.matches(&ransomware_rule));
        assert!(!filter_include_only.matches(&malware_rule));

        // Exclude only filter
        assert!(filter_exclude_only.matches(&ransomware_rule));
        assert!(!filter_exclude_only.matches(&malware_rule));

        // No restrictions filter
        assert!(filter_none.matches(&ransomware_rule));
        assert!(filter_none.matches(&malware_rule));
    }

    #[test]
    fn test_cli_integration_simulation() {
        // Simulate CLI parsing and CategoryFilter creation
        let cli_include_categories = Some("ransomware,apt,banking".to_string());
        let cli_exclude_categories = Some("test,experimental".to_string());

        // Parse CLI arguments as would be done in the actual CLI handler
        let include_cats: Vec<&str> = cli_include_categories
            .as_ref()
            .map(|cats| cats.split(',').map(|s| s.trim()).collect())
            .unwrap_or_default();

        let exclude_cats: Vec<&str> = cli_exclude_categories
            .as_ref()
            .map(|cats| cats.split(',').map(|s| s.trim()).collect())
            .unwrap_or_default();

        let filter = CategoryFilter::from_args(&include_cats, &exclude_cats);

        // Test various rule categories
        let ransomware_rule = create_test_metadata(
            "test_ransomware",
            vec!["ransomware".to_string()],
            vec!["test".to_string()],
        );
        let apt_rule = create_test_metadata(
            "test_apt",
            vec!["apt".to_string()],
            vec!["test".to_string()],
        );
        let banking_rule = create_test_metadata(
            "test_banking",
            vec!["banking".to_string()],
            vec!["test".to_string()],
        );
        let test_rule = create_test_metadata(
            "test_rule",
            vec!["test".to_string()],
            vec!["test".to_string()],
        );
        let experimental_rule = create_test_metadata(
            "test_experimental",
            vec!["experimental".to_string()],
            vec!["test".to_string()],
        );
        let malware_rule = create_test_metadata(
            "test_malware",
            vec!["malware".to_string()],
            vec!["test".to_string()],
        );

        // Should match included categories that are not excluded
        assert!(
            filter.matches(&ransomware_rule),
            "Should match included ransomware"
        );
        assert!(filter.matches(&apt_rule), "Should match included apt");
        assert!(
            filter.matches(&banking_rule),
            "Should match included banking"
        );

        // Should not match excluded categories even if they might be included
        assert!(
            !filter.matches(&test_rule),
            "Should not match excluded test category"
        );
        assert!(
            !filter.matches(&experimental_rule),
            "Should not match excluded experimental category"
        );

        // Should not match categories that are not included
        assert!(
            !filter.matches(&malware_rule),
            "Should not match non-included malware category"
        );
    }

    #[test]
    fn test_edge_cases() {
        // Test various edge cases

        // Filter with duplicate categories
        let filter_duplicates = CategoryFilter::from_args(
            &["ransomware", "ransomware", "apt"],
            &["malware", "malware"],
        );

        let ransomware_rule = create_test_metadata(
            "test_ransomware",
            vec!["ransomware".to_string()],
            vec!["test".to_string()],
        );
        assert!(
            filter_duplicates.matches(&ransomware_rule),
            "Should handle duplicate includes"
        );

        // Filter with same category in both include and exclude (exclude should win)
        let filter_conflict = CategoryFilter::from_args(&["ransomware", "apt"], &["ransomware"]);

        let ransomware_rule2 = create_test_metadata(
            "test_ransomware2",
            vec!["ransomware".to_string()],
            vec!["test".to_string()],
        );
        let apt_rule = create_test_metadata(
            "test_apt",
            vec!["apt".to_string()],
            vec!["test".to_string()],
        );

        assert!(
            !filter_conflict.matches(&ransomware_rule2),
            "Exclude should override include"
        );
        assert!(
            filter_conflict.matches(&apt_rule),
            "Should still match non-conflicting includes"
        );
    }
}
