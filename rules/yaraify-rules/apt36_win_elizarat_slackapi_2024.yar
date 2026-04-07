rule apt36_win_elizarat_slackapi_2024
{
  meta:
    author = "CYFARE.NET"
    description = "APT36 ElizaRAT Windows variant leveraging Slack API C2 with IST locale checks (2024)"
    date = "2025-09-14"
    yarahub_reference_link = "https://research.checkpoint.com/2024/the-evolution-of-transparent-tribes-new-malware/"
    yarahub_reference_md5 = "2b1101f9078646482eb1ae497d441104"
    yarahub_uuid = "b2a6d6ef-8c5e-4c9a-8a3e-0f5f6f7a9b3c"
    yarahub_license = "CC0 1.0"
    yarahub_rule_matching_tlp = "TLP:WHITE"
    yarahub_rule_sharing_tlp = "TLP:WHITE"

  strings:
    $mz = { 4D 5A }
    $p1 = "%appdata%\\SlackAPI" wide ascii nocase
    $p2 = "Userinfo.dll" wide ascii
    $tz = "India Standard Time" wide ascii
    $u1 = "https://slack.com/api/conversations.history?channel=" wide ascii nocase
    $u2 = "https://slack.com/api/chat.postMessage" wide ascii nocase
    $u3 = "https://slack.com/api/files.upload" wide ascii nocase
    $ch1 = "C06BM9XTVAS" ascii
    $ch2 = "C06BWCMSF1S" ascii
    $cls1 = "CplAppletDelegate" wide ascii
    $cls2 = "ReceiveMsgsInList" wide ascii
    $cls3 = "FormatMsgs" wide ascii

  condition:
    $mz and 5 of ($p*,$tz,$u*,$ch*,$cls*)
}

