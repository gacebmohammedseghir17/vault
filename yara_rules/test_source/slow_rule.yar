rule SlowTestRule
{
    meta:
        author = "Test Author"
        description = "A rule with complex patterns that might be slow"
        
    strings:
        $complex1 = /[a-zA-Z0-9]{100,1000}[!@#$%^&*()]{10,50}[0-9a-fA-F]{32}/ ascii
        $complex2 = /((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/ ascii
        $complex3 = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/ ascii
        $complex4 = /(http|https|ftp):\/\/[^\s\/$.?#].[^\s]*/ ascii
        
    condition:
        all of ($complex*) and filesize > 1KB and filesize < 10MB
}