rule ValidTestRule
{
    meta:
        author = "Test Author"
        description = "A valid test YARA rule"
        version = "1.0"
        date = "2024-01-01"
        
    strings:
        $text1 = "malicious_string" ascii
        $text2 = "suspicious_pattern" wide
        $hex1 = { 4D 5A 90 00 }
        
    condition:
        any of ($text*) or $hex1
}