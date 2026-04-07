rule InvalidTestRule
{
    meta:
        author = "Test Author"
        description = "An invalid test YARA rule with syntax errors"
        
    strings:
        $text1 = "malicious_string" ascii
        $invalid_hex = { ZZ XX YY }  // Invalid hex values
        
    condition:
        invalid_function($text1) and unknown_keyword  // Invalid syntax
}