import "lnk"

rule INFO_LNK_FILE_HIDDEN_POWERSHELL {
meta:
		version = "1"
		date = "1/1/25"
		modified = "1/1/25"
		status = "DEVELOPMENT"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of LNK File with hidden powershell commands"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://wezard4u.tistory.com/429351"
		hash = "2fa8f5f95577db335e649d5361c845b0"
strings:
		$str1 = "powershell"
		$str2 = "-windowstyle hidden"
condition:
		(lnk.is_lnk or uint16(0)==0x004c) and all of them
}
