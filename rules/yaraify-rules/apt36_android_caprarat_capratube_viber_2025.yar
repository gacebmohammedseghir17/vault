rule apt36_android_caprarat_capratube_viber_2025
{
  meta:
    author = "CYFARE.NET"
    description = "APT36 CapraRAT APKs (CapraTube/Viber impersonation) with characteristic package, config, and C2 artifacts (2025)"
    date = "2025-09-14"
    yarahub_reference_link = "https://cloudsek.com/blog/the-transparent-tribe-vibe-apt36-returns-with-caprarat-impersonating-viber"
    yarahub_reference_md5 = "f73f1a694d2a5c7e6d04fbc866a916bd"
    yarahub_uuid = "b6b7a9a4-0c0c-4a0a-87c0-2a7e3d5f6c8d"
    yarahub_license = "CC0 1.0"
    yarahub_rule_matching_tlp = "TLP:WHITE"
    yarahub_rule_sharing_tlp = "TLP:WHITE"

  strings:
    $apk = "AndroidManifest.xml" ascii
    $pkg1 = "package=\"com.moves.media.tubes\"" ascii
    $pkg2 = "com.viber.updates.links" ascii
    $cfg1 = "SERVERIP" ascii
    $cfg2 = "smsMoniter" ascii
    $cfg3 = "is_phical" ascii
    $cfg4 = "verion" ascii
    $cls1 = "com/media/gallery/service/TPSClient" ascii
    $cls2 = "com/Base/media/service/TCHPClient" ascii
    $cls3 = "com/videos/watchs/share/TCPClient" ascii
    $d1 = "shareboxs.net" ascii
    $d2 = "ptzbubble.shop" ascii
    $d3 = "newsbizshow.net" ascii

  condition:
    $apk and (1 of ($pkg*) or 2 of ($d*)) and 3 of ($cfg*,$cls*)
}

