rule njRat_violet_client
{
    meta:
        author = "R4ruk"
        date = "2025-09-07"
        description = "Matches NjRat violet-client payload."
        reference = "https://sidequest-lab.com/2025/09/07/njrat-part-2-c2-command-investigation/"
        yarahub_uuid                 = "8cbbbe0e-1d24-4f7e-98aa-9fbabdc719cc"
        yarahub_license              = "CC BY-NC 4.0"
        yarahub_rule_matching_tlp    = "TLP:WHITE"
        yarahub_rule_sharing_tlp     = "TLP:WHITE"
        yarahub_reference_md5        = "9a5289879140239767ecd6437f6ffd3b"

    strings:
        $s1="\\ngrok.exe" base64wide
        $s2="HKEY_CURRENT_USER\\SOFTWARE" base64wide
        $s3="7zip\\7z.exe" base64wide
        $s4="Xchat" base64wide
        $s5="GETWsoundPlu" base64wide
        $s6="GETWCamPlu" base64wide
        $s7="WinSc32.exe" wide

        $b8="89c43fcf-5e52-4be7-a719-a26139ce636a.exe" base64wide
        $b9="3d847c5c-4f5a-4918-9e07-a96cea49048d.exe" base64wide
        $b10="RunBotKiller" base64wide
        $b11="Blackbullet" base64wide
        $b12="<Violet>" base64wide

    condition:
        4 of ($s*)
        or
        any of ($b*)
}