rule Test_Ransom_Note {
    meta:
        description = "Detects test ransomware note"
        author = "ERDPS Test"
        severity = "High"
    strings:
        $s1 = "!!! YOUR FILES HAVE BEEN ENCRYPTED !!!"
        $s2 = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"
        $s3 = "ransomware@darkweb.onion"
    condition:
        any of them
}

rule Test_Encrypted_Header {
    meta:
        description = "Detects test encrypted file header"
        author = "ERDPS Test"
        severity = "Critical"
    strings:
        $h1 = "ENCRYPTED_HEADER_V1"
        $h2 = "PAYMENT_REQUIRED"
    condition:
        any of them
}
