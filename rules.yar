rule Suspicious_Capabilities {
    meta:
        description = "Detects networking and execution capabilities"
    strings:
        $http = "http" ascii wide
        $cmd = "cmd.exe" nocase
        $ps = "powershell" nocase
        $sock = "socket" ascii
    condition:
        2 of them
}

rule Ransomware_Indicators {
    strings:
        $s1 = "decrypt" nocase
        $s2 = "restore files" nocase
        $s3 = "bitcoin" nocase
        $s4 = "onion" nocase
    condition:
        any of them
}