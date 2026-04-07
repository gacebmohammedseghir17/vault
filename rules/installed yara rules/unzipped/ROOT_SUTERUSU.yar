rule ROOT_SUTERUSU
{
    meta:
        description = "Detects presence of various Suterusu Rootkit Source Code files"
        author = "Ian Cook @cioaonk"
        date = "2025-01-06"
        reference = "https://news.sophos.com/en-us/2024/10/31/pacific-rim-timeline/#Rootkit2%20" // Original Report
        reference = "https://github.com/mncoppola/suterusu/" // Source Code

        hash_1 = "59db07440f3b2d1615e8dc01995ece25" // common.h hash
        hash_2 = "46c0fd67e0db1217a1d4f80b34f4b70d" //sock.c hash
        hash_3 = "236ae98968dc4c8c3f70397d01e1e83e" // dlexec.c hash
    strings:
        // Function definitions from common.h
        $s_start = "hijack_start"
        $s_pause = "hijack_pause"
        $s_resume = "hijack_resume"
        $s_stop = "hijack_stop"

        // PrintStrings within sock.C
        $p_drop = "Dropping to root shell"
        $p_hide = "Hiding TCPv4 port %hu" 
        $p_reveal = "Unhiding TCPv6 port %hu"
        $p_enable = "Enabling module loading"
        $p_prohibit = "Silently prohibiting module loading"


        // Define Statements from dlexec.C
        $d_init = " #define SUTERUSU_INIT_WORK"


    condition:
        3 of ($s*) or 
        any of ($p*) or
        $d_init

}
