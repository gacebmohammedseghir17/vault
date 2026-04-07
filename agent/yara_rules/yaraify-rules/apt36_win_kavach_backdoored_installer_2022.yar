rule apt36_win_kavach_backdoored_installer_2022
{
  meta:
    author = "CYFARE.NET"
    description = "APT36 Kavach backdoored installer/tooling overlap: Pakistan/India-themed malvertising & payload artifacts (2022)"
    date = "2025-09-14"
    yarahub_reference_link = "https://www.zscaler.com/blogs/security-research/apt-36-uses-new-ttps-and-new-tools-target-indian-governmental-organizations"
    yarahub_reference_md5 = "faeb19cdc8089db5e17e8144c93b2509"
    yarahub_uuid = "c0e0f1ab-2d44-4e7a-8e54-4cbb0b7d92a9"
    yarahub_license = "CC0 1.0"
    yarahub_rule_matching_tlp = "TLP:WHITE"
    yarahub_rule_sharing_tlp = "TLP:WHITE"

  strings:
    $mz = { 4D 5A }
    $k1 = "kavach" wide ascii nocase
    $t1 = "India Standard Time" wide ascii
    $f1 = "oraclenotepad45.dll" wide ascii
    $f2 = "archiveviewer.scr" wide ascii
    $f3 = "hardwell.mp3" wide ascii
    $db = "Limepad.db" wide ascii
    $tok = "Auth_Token" wide ascii
    $ip1 = "139.59.79.86" ascii

  condition:
    $mz and $k1 and (2 of ($t1,$f*,$db,$tok,$ip1))
}

