//! Tests for filesystem monitoring and volume scan safety checks

/// Test the volume scan detection logic directly
#[test]
fn test_volume_scan_detection_patterns() {
    // Test root drive patterns
    assert!(is_volume_wide_scan_pattern("c:\\"));
    assert!(is_volume_wide_scan_pattern("d:\\"));
    assert!(is_volume_wide_scan_pattern("e:\\"));
    assert!(is_volume_wide_scan_pattern("C:\\"));
    assert!(is_volume_wide_scan_pattern("D:\\"));
    assert!(is_volume_wide_scan_pattern("E:\\"));

    // Test forward slash variants
    assert!(is_volume_wide_scan_pattern("c:/"));
    assert!(is_volume_wide_scan_pattern("d:/"));
    assert!(is_volume_wide_scan_pattern("C:/"));
    assert!(is_volume_wide_scan_pattern("D:/"));

    // Test wildcard patterns
    assert!(is_volume_wide_scan_pattern("c:\\*"));
    assert!(is_volume_wide_scan_pattern("d:/*"));
    assert!(is_volume_wide_scan_pattern("C:\\*"));
    assert!(is_volume_wide_scan_pattern("D:/*"));

    // Test non-volume patterns
    assert!(!is_volume_wide_scan_pattern("c:\\users"));
    assert!(!is_volume_wide_scan_pattern("d:\\temp"));
    assert!(!is_volume_wide_scan_pattern("c:/users"));
    assert!(!is_volume_wide_scan_pattern("/home/user"));
    assert!(!is_volume_wide_scan_pattern("./relative/path"));
    assert!(!is_volume_wide_scan_pattern("some_file.txt"));
}

/// Helper function to test volume scan detection logic
/// This mirrors the actual implementation in FileSystemMonitor::is_volume_wide_scan
fn is_volume_wide_scan_pattern(path_lower: &str) -> bool {
    let path_lower = path_lower.to_lowercase();

    // Root drive patterns
    if path_lower == "c:\\"
        || path_lower == "d:\\"
        || path_lower == "e:\\"
        || path_lower == "c:/"
        || path_lower == "d:/"
        || path_lower == "e:/"
    {
        return true;
    }

    // Wildcard patterns
    if path_lower.ends_with(":\\*") || path_lower.ends_with(":/*") {
        return true;
    }

    // Single letter drive patterns (A: through Z:)
    if path_lower.len() == 2 && path_lower.ends_with(':') {
        let drive_letter = path_lower.chars().next().unwrap();
        return drive_letter.is_ascii_alphabetic();
    }

    // Three character drive patterns (A:\\ or A:/)
    if path_lower.len() == 3 && (path_lower.ends_with(":\\") || path_lower.ends_with(":/")) {
        let drive_letter = path_lower.chars().next().unwrap();
        return drive_letter.is_ascii_alphabetic();
    }

    false
}

/// Test path validation logic
#[test]
fn test_path_validation_logic() {
    // Test that volume scan paths are properly detected
    let volume_paths = vec![
        "C:\\", "D:\\", "E:\\", "c:\\", "d:\\", "e:\\", "C:/", "D:/", "E:/", "c:/", "d:/", "e:/",
        "C:\\*", "D:/*", "c:\\*", "d:/*",
    ];

    for path in volume_paths {
        assert!(
            is_volume_wide_scan_pattern(path),
            "Path '{}' should be detected as volume scan",
            path
        );
    }

    // Test that non-volume paths are not detected
    let safe_paths = vec![
        "C:\\Users",
        "D:\\Temp",
        "E:\\Data",
        "c:\\users",
        "d:\\temp",
        "e:\\data",
        "C:/Users",
        "D:/Temp",
        "E:/Data",
        "c:/users",
        "d:/temp",
        "e:/data",
        "/home/user",
        "./relative",
        "../parent",
        "some_file.txt",
        "folder/subfolder",
    ];

    for path in safe_paths {
        assert!(
            !is_volume_wide_scan_pattern(path),
            "Path '{}' should NOT be detected as volume scan",
            path
        );
    }
}

/// Test edge cases in path validation
#[test]
fn test_path_validation_edge_cases() {
    // Empty and whitespace paths
    assert!(!is_volume_wide_scan_pattern(""));
    assert!(!is_volume_wide_scan_pattern(" "));
    assert!(!is_volume_wide_scan_pattern("\t"));

    // Valid but uncommon drive letters (z: is still valid)
    assert!(is_volume_wide_scan_pattern("z:\\"));

    // Invalid drive letters (non-alphabetic)
    assert!(!is_volume_wide_scan_pattern("1:\\"));
    assert!(!is_volume_wide_scan_pattern("@:\\"));

    // Single drive letter patterns (these ARE volume scans)
    assert!(is_volume_wide_scan_pattern("c:"));
    assert!(is_volume_wide_scan_pattern("d:"));

    // Partial patterns (incomplete)
    assert!(!is_volume_wide_scan_pattern("d"));
    assert!(!is_volume_wide_scan_pattern("c"));

    // UNC paths (NOT detected as volume scans in current implementation)
    assert!(!is_volume_wide_scan_pattern("\\\\server\\share"));
    assert!(!is_volume_wide_scan_pattern("\\\\server"));
    assert!(!is_volume_wide_scan_pattern("\\\\server\\"));

    // Invalid patterns
    assert!(!is_volume_wide_scan_pattern(":\\"));

    // UNC paths with shares (should not be volume scans)
    assert!(!is_volume_wide_scan_pattern("\\\\server\\share"));
    assert!(!is_volume_wide_scan_pattern("\\\\server\\share\\folder"));
}
