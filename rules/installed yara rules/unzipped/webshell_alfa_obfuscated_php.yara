rule webshell_alfa_obfuscated_php
{
  meta:
    author      = "Tenbite @https://x.com/BitOfTen"
    date        = "2025/01/01"
    description = "Detect apostrophe-based PHP obfuscation with chunks up to 3 chars"

  strings:
    // Indicator it's at least some PHP code:
    $phpOpenorClose = "<?php"

    // Regex for obfuscation observed in the above referenced PHP webshell
    // Detects php code concatenated with dots: e.g., 'fu'.'nct'.'ion'
    $apostropheConcat = /'[a-zA-Z0-9_]{1,3}'\.'[a-zA-Z0-9_]{1,3}'(\.'[a-zA-Z0-9_]{1,3}')+/ nocase

  condition:
    // File must be PHP code AND contain at least one instance of 3-chunk apostrophe obfuscation with 1-3 letters
    $phpOpenorClose and $apostropheConcat
}
