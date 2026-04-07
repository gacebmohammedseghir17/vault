rule INFO_3AM_ransom {
    meta:
        author = "Ian Cook @cioaonk"
        description = "Detects 3AM ransomware note elements"
        date = "2025-01-06"
        version = "1.0"
        reference =  "https://www.ransomware.live/ransomnotes/3am"
        reference = "https://socradar.io/dark-web-profile-3am-ransomware/"
        hash = "09b226fa7ee401683dca5af60f395b4b" // not ideal
        
    strings:
        $name = "threeam" 
        $url = /http:\/\/((threeam)|(3am))[0-9,a-z]*.onion/
        $alt_name = "3 am"

        // Buzzwords:
        $enc = "encrypted" ascii
        $data = "data" ascii
        $payme = "payment" ascii


    condition:
        $name and $url and $alt_name and any of ($enc,$data,$payme)
}