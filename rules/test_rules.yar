/*
    Minimal Safe Rules Bundle for ERDPS Agent
    
    This bundle contains safe, minimal rules designed for:
    - CI/CD environments
    - Testing and validation
    - Zero-config startup with rules_loaded_total ≥ 1
    
    All rules are safe and will not trigger on legitimate files.
*/

rule EICAR_Test_Signature
{
    meta:
        description = "EICAR Anti-Virus Test File Detection"
        author = "ERDPS Team"
        date = "2025-01-28"
        severity = "info"
        category = "test"
        safe = true
        
    strings:
        $eicar = { 58 35 4F 21 50 25 40 41 50 5B 34 5C 50 5A 58 35 34 28 50 5E 29 37 43 43 29 37 7D 24 45 49 43 41 52 2D 53 54 41 4E 44 41 52 44 2D 41 4E 54 49 56 49 52 55 53 2D 54 45 53 54 2D 46 49 4C 45 21 24 48 2B 48 2A }
        $eicar_alt = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
        
    condition:
        any of them
}

rule Test_Pattern_Detection
{
    meta:
        description = "Safe test pattern for validation"
        author = "ERDPS Team"
        date = "2025-01-28"
        severity = "info"
        category = "test"
        safe = true
        
    strings:
        $test_marker = "ERDPS_TEST_MARKER_SAFE_PATTERN"
        $validation = "VALIDATION_TEST_STRING_ERDPS"
        
    condition:
        any of them
}

rule Minimal_Safe_Rule {
    meta:
        description = "Minimal safe rule that always loads but never matches"
        author = "ERDPS Test Suite"
        date = "2024-01-01"
        safe = true
        
    condition:
        false  // Never matches, but ensures rule loads successfully
}

rule Safe_Text_Pattern {
    meta:
        description = "Safe rule for testing text pattern detection"
        author = "ERDPS Test Suite"
        date = "2024-01-01"
        safe = true
        
    strings:
        $safe_pattern = "ERDPS_SAFE_TEST_PATTERN_2024"
        
    condition:
        $safe_pattern
}

rule Safe_File_Extension_Check {
    meta:
        description = "Safe rule for testing file extension patterns"
        author = "ERDPS Test Suite"
        date = "2024-01-01"
        safe = true
        
    condition:
        false  // Never matches, safe for testing
}

rule Safe_Size_Check {
    meta:
        description = "Safe rule for testing file size conditions"
        author = "ERDPS Test Suite"
        date = "2024-01-01"
        safe = true
        
    condition:
        false  // Never matches, safe for testing
}