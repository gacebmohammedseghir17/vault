rule Loader_Cruloader_Strings : malware cruloader {
    meta:
        author = "albertzsigovits"
        sha256 = "a0ac02a1e6c908b90173e86c3e321f2bab082ed45236503a21eb7d984de10611"
        reference = "https://courses.zero2auto.com"

    strings:
        $ = "kkd5YdPM24VBXmi" // RC4 key
        $ = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890./=" // ROT13 charset
        $ = "aaaaaaaaaaaaaaaap"
        $ = "cruloader" ascii wide

    condition:
        2 of them
}

rule Loader_Cruloader_Crypto : malware cruloader {
    meta:
        author = "albertzsigovits"
        sha256 = "279d481e36cb7d6195d83b7bc0222bc9c8f4ca5afa68facfe6177453bbd2a28f"
        reference = "https://courses.zero2auto.com"

    strings:
        $ = {
            8A 54 0D ??                         // mov     dl, [ebp+ecx-30h]
            C0 C2 ??                            // rol     dl, 4
            80 F2 ??                            // xor     dl, 0A2h
            88 54 0D ??                         // mov     [ebp+ecx-30h], dl
            41                                  // inc     ecx
            3B C8                               // cmp     ecx, eax
            7C ED                               // jl      short loc_401D00
        }

        $ = {
            0F B7 0C ??                         // movzx   ecx, word ptr [ecx+edx*2]
            66 8B C1                            // mov     ax, cx
            81 E1 [2] 00 00                     // and     ecx, 0FFFh
            66 C1 E8 ??                         // shr     ax, 0Ch
            0F B7 C0                            // movzx   eax, ax
            83 F8 ??                            // cmp     eax, 3
            74 09                               // jz      short loc_4019E2
        }

    condition:
        all of them
}
