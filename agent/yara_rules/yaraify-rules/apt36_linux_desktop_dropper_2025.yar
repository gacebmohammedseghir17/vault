rule apt36_linux_desktop_dropper_2025
{
  meta:
    author = "CYFARE.NET"
    description = "APT36/Transparent Tribe Linux .desktop loader using Google Drive delivery, decode stages, WebSocket C2, and decoy openers (2025)"
    date = "2025-09-14"
    yarahub_reference_link = "https://cloudsek.com/blog/investigation-report-apt36-malware-campaign-using-desktop-entry-files-and-google-drive-payload-delivery"
    yarahub_reference_md5 = "a484f85d132609a4a6b5ed65ece7d331"
    yarahub_uuid = "4f9b6a2e-4b9e-4a16-b7a9-7c1f1a4a3a3f"
    yarahub_license = "CC0 1.0"
    yarahub_rule_matching_tlp = "TLP:WHITE"
    yarahub_rule_sharing_tlp = "TLP:WHITE"

  strings:
    $hdr = "[Desktop Entry]" ascii
    $type = "Type=Application" ascii

    $e1 = "Exec=sh -c" nocase ascii
    $e2 = "Exec=/bin/bash -c" nocase ascii
    $e3 = "Exec=bash -lc" nocase ascii

    $dl1 = "drive.google.com/uc?export=download" nocase ascii
    $dl2 = "googleusercontent.com" nocase ascii

    $dom1 = "securestore.cv" nocase ascii
    $dom2 = "seemysitelive.store" nocase ascii
    $dom3 = "modgovindia.space" nocase ascii

    $ws = ":8080/ws" ascii

    $hx1 = "xxd -r -p" ascii
    $hx2 = "base64 -d" ascii

    $net1 = "curl -sL" ascii
    $net2 = "wget -qO-" ascii

    $pr1 = "chmod +x /tmp/" nocase ascii
    $pr2 = "mv /tmp/" nocase ascii

    $decoy1 = "firefox" ascii
    $auto1 = "X-GNOME-Autostart-enabled=true" ascii

  condition:
    filesize < 200KB and
    $hdr and $type and
    1 of ($e*) and
    (1 of ($dl*) or 1 of ($dom*)) and
    (1 of ($hx*) or 1 of ($net*)) and
    1 of ($pr*) and
    1 of ($decoy1, $auto1, $ws)
}

