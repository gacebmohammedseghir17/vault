rule CIPHER_WIPE_VIA_POWERSHELL
{
    meta:
        description = "Detects the usage of Windows native Cipher tool within Powershell, wiping the contents of the C Drive"
        author = "Ian Cook @cioaonk"
        date = "2025-01-02"
        reference = "https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/cipher"
        reference = "https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/"
        

    strings:
        $cmd_cipher_wipe = "cmd.exe /c cipher /W:C" nocase       
        $cipher_switch = "/W:C" nocase                          
        $cipher_full_cmd = "cipher /W:C" nocase      

    condition:
        uint32be(0) == 0x2321  and
        any of ($cmd_cipher_wipe, $cipher_switch, $cipher_full_cmd)
}
