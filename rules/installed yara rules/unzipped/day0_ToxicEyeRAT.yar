rule RAT_ToxicEye_IL : malware rat toxiceye {
    meta:
        author = "albertzsigovits"
        sha256 = "2e53a6710f04dd84cfd3ac1874a2a61e690568405f192e7cbf8a4df12da334c4"
        reference = "https://github.com/albertzsigovits/malware-cfg/tree/main/ToxicEyeRAT"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.toxiceye"
        reference = "https://bazaar.abuse.ch/browse/signature/toxiceye/"

    strings:
        $ = {
            80 ?? 00 00 04                // stsfld   bool TelegramRAT.config::ClipperEnabled
            72 [4]                        // ldstr    a1dj5vetdbuqnmd // "1DJ5VetDBuQnmDZjRHRgEiCwYwvc6PSwu8"
            80 ?? 00 00 04                // stsfld   string TelegramRAT.config::bitcoin_address
            72 [4]                        // ldstr    a0x357c0541f19a // "0x357C0541F19a7755AFbF1CCD824EE06059404"...
            80 ?? 00 00 04                // stsfld   string TelegramRAT.config::etherium_address
            72 [4]                        // ldstr    a42pwy6xe4mptz3 // "42Pwy6Xe4mPTz3mLap7AB5Jjd9NBt1MWjiqyvEF"...
            80 ?? 00 00 04                // stsfld   string TelegramRAT.config::monero_address
            2?                            // ret
        }
        
        $ = {
            80 ?? 00 00 04                // stsfld   string[] TelegramRAT.config::EncryptionFileTypes
            20 [4]                        // ldc.i4   0x600000
            ??                            // conv.i8
            80 ?? 00 00 04                // stsfld   int64 TelegramRAT.config::GrabFileSize
            1F ??                         // ldc.i4.s 0x15
            8D [4]                        // newarr   [mscorlib]System.String
            2?                            // dup
        }
        
        $ = {
            80 ?? 00 00 04                // stsfld   bool TelegramRAT.config::MeltFileAfterStart
            72 [4]                        // ldstr    aCUsersToxiceye // "C:\\Users\\ToxicEye\\rat.exe"
            80 ?? 00 00 04                // stsfld   string TelegramRAT.config::InstallPath
            1?                            // ldc.i4.1
            80 ?? 00 00 04                // stsfld   bool TelegramRAT.config::AutorunEnabled
            72 [4]                        // ldstr    aChromeUpdate  // "Chrome Update"
            80 ?? 00 00 04                // stsfld   string TelegramRAT.config::AutorunName
            1?                            // ldc.i4.1
            80 ?? 00 00 04                // stsfld   bool TelegramRAT.config::ProcessBSODProtectionEnabled
            1?                            // ldc.i4.1
            80 ?? 00 00 04                // stsfld   bool TelegramRAT.config::HideConsoleWindow
            1?                            // ldc.i4.1
            80 ?? 00 00 04                // stsfld   bool TelegramRAT.config::PreventStartOnVirtualMachine
            1?                            // ldc.i4.0
            80 ?? 00 00 04                // stsfld   int32 TelegramRAT.config::StartDelay
            1?                            // ldc.i4.1
            80 ?? 00 00 04                // stsfld   bool TelegramRAT.config::BlockNetworkActivityWhenProcessStarted
            1F ??                         // ldc.i4.s 9
            8D [4]                        // newarr   [mscorlib]System.String
            2?                            // dup
        }

    condition:
        all of them
}

rule RAT_ToxicEye_StringsW : malware rat toxiceye {
    meta:
        author = "albertzsigovits"
        sha256 = "2e53a6710f04dd84cfd3ac1874a2a61e690568405f192e7cbf8a4df12da334c4"
        reference = "https://github.com/albertzsigovits/malware-cfg/tree/main/ToxicEyeRAT"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.toxiceye"
        reference = "https://bazaar.abuse.ch/browse/signature/toxiceye/"

    strings:
        $str01 = "ToxicEye" wide
        $str02 = "Coded by LimerBoy, attationin, Apasniy Suren" wide
        $str03 = "Do not spread among people, this was developed against mamonts only!" wide
        $str04 = "Preparing blue screen of death..." wide
        $str05 = "Warning! System will be destroyed! Run command /OverwriteBootSector_CONFIRM to continue." wide
        $str06 = "Trying overwrite boot sector..." wide
        $str07 = "Found blocked process" wide
        $str08 = "This is some text in the file." wide
        $str09 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" wide
        $str10 = "DisableTaskMgr" wide
        $str11 = "\\root\\SecurityCenter2" wide
        $str12 = "Select * from AntivirusProduct" wide
        $str13 = "Starting autostealer..." wide
        $str14 = "Stopping autostealer..." wide
        $str15 = "autosteal.lock" wide
        $str16 = ".crypted" wide
        $str17 = "STEALER:" wide

        $status01 = "[!] Failed load libraries, not connected to internet!" wide
        $status02 = "[!] Stopping command listener thread" wide
        $status03 = "[!] Retrying connect to api.telegram.org" wide
        $status04 = "[!] Retrying connect to internet..." wide
        $status05 = "[!] Shutdown signal received.." wide
        $status06 = "[+] Process checker started" wide
        $status07 = "[+] Restarting command listener thread" wide
        $status08 = "[+] Set process critical" wide
        $status09 = "[+] Set process not critical" wide
        $status10 = "[+] Hiding console window" wide
        $status11 = "[+] Copying to system..." wide
        $status12 = "[+] Uninstalling from system..." wide
        $status13 = "[+] Installing to autorun..." wide
        $status14 = "[+] Uninstalling from autorun..." wide
        $status15 = "[+] Clipper is starting..." wide
        $status16 = "[?] Already running 1 copy of the program" wide
        $status17 = "[?] Sleeping {0}" wide
        $status18 = "[~] Trying elevate previleges to administrator..." wide

        $cnc01 = "https://api.mylnikov.org/geolocation/wifi?bssid" wide
        $cnc02 = "http://ip-api.com/json/" wide
        $cnc03 = "https://api.telegram.org/" wide
        $cnc04 = "https://api.telegram.org/file/" wide

        $txt01 = "keylogs.txt" wide
        $txt02 = "MyTest.txt" wide
        $txt03 = "bookmarks.txt" wide
        $txt04 = "cookies.txt" wide
        $txt05 = "credit_cards.txt" wide
        $txt06 = "filezilla.txt" wide
        $txt07 = "history.txt" wide
        $txt08 = "passwords.txt" wide

        $zip01 = "desktop.zip" wide
        $zip02 = "steam.zip" wide
        $zip03 = "audio.zip" wide
        $zip04 = "fmedia.zip" wide

        $debug01 = "Trying to kill Defender..." wide
        $debug02 = "Uninstalling malware from device..." wide
        $debug03 = "Preparing ForkBomb..." wide
        $debug04 = "Preparing blue screen of death..." wide
        $debug05 = "Trying overwrite boot sector..." wide
        $debug06 = "Starting autostealer..." wide
        $debug07 = "Stopping autostealer..." wide
        $debug08 = "Archiving desktop files..." wide
        $debug09 = "Telegram session found by process. Please wait..." wide
        $debug10 = "Telegram session found in default path. Please wait..." wide
        $debug11 = "Uploading file..." wide
        $debug12 = "Uploading directory..." wide
        $debug13 = "Downloading CommandCam..." wide
        $debug14 = "Downloading FMedia..." wide
        $debug15 = "Please wait..." wide
        $debug16 = "Target turns off the power on the device..." wide

        $exfil01 = "[BOOKMARKS]" wide
        $exfil02 = "[COOKIES]" wide
        $exfil03 = "[CREDIT CARDS]" wide
        $exfil04 = "[FILEZILLA SERVERS]" wide
        $exfil05 = "[HISTORY]" wide
        $exfil06 = "[PASSWORDS]" wide

    condition:
        10 of ($str*)
        or 10 of ($status*)
        or all of ($cnc*)
        or 7 of ($txt*)
        or all of ($zip*)
        or 10 of ($debug*)
        or all of ($exfil*)
        or (
          1 of ($str*)
          and 1 of ($status*)
          and 1 of ($cnc*)
          and 1 of ($txt*)
          and 1 of ($zip*)
          and 1 of ($debug*)
          and 1 of ($exfil*)
        )
}

rule RAT_ToxicEye_StringsA : malware rat toxiceye {
    meta:
        author = "albertzsigovits"
        sha256 = "2e53a6710f04dd84cfd3ac1874a2a61e690568405f192e7cbf8a4df12da334c4"
        reference = "https://github.com/albertzsigovits/malware-cfg/tree/main/ToxicEyeRAT"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.toxiceye"
        reference = "https://bazaar.abuse.ch/browse/signature/toxiceye/"

    strings:
        $ = "\\Users\\attationin"
        $ = "\\ToxicEye-master-myfork"
        $ = "\\ToxicEye-master"
        $ = "TelegramChatID"
        $ = "TelegramRAT"
        $ = "TelegramToken"
        $ = "TelegramGrabber"
        $ = "TelegramCommandCheckDelay"
        $ = "AutoStealer"
        $ = "Clipper"
        $ = "Ivan Medvedev"
        $ = "AttributeSystemEnabled"
        $ = "AttributeHiddenEnabled"
        $ = "ProcessBSODProtectionEnabled"
        $ = "AutorunEnabled"
        $ = "AutoStealerEnabled"
        $ = "ClipperEnabled"
        $ = "inSandboxie"
        $ = "DiscordGrabber"
        $ = "SteamGrabber"
        $ = "TelegramGrabber"
        $ = "runAntiAnalysis"
        $ = "DetectAntivirus"
        $ = "webcamScreenshot"
        $ = "desktopScreenshot"

    condition:
        15 of them
}
