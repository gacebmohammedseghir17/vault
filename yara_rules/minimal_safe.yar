/*
    Minimal Safe Rules Bundle for ERDPS Testing
    
    This file contains minimal, safe YARA rules for testing purposes.
    These rules are designed to be non-intrusive and safe for CI environments.
*/

// EICAR rule removed to avoid duplication with test_rules.yar

rule Minimal_PE_Header_Check
{
    meta:
        description = "Basic PE header validation for testing"
        author = "ERDPS Agent"
        date = "2024-01-01"
        severity = "info"
        category = "test"
        safe = true
        
    strings:
        $mz = { 4D 5A }  // MZ header
        
    condition:
        $mz at 0
}