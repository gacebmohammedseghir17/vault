rule SUSP_Encrypted_ZIP_SingleEntry
{
	meta:
		author = "Greg Lesnewich"
		description = "track encrypted ZIP files with only one embedded file"
		inspiration_ref = "https://github.com/100DaysofYARA/2024/blob/7df92fafb900e3f148d927ac8dd68bfeaea0c332/larsborn/Day_017.yara"
		date = "2025-01-02"
		version = "1.0"

	condition:
		uint32be(0) == 0x504b0304 and
		uint16(0x6) & 0x1 == 1 and // check password flag is set
		uint32be(filesize - 0x16) == 0x504b0506 and // check for end loacator of ZIP
		uint32be(filesize - 0xe) == 0x01000100 // check number of entries == 1

}

rule SUSP_Encrypted_ZIP_SingleEntry_VBS
{
	meta:
		author = "Greg Lesnewich"
		description = "track encrypted ZIP files with only one VBS file in its contents"
		inspiration_ref = "https://github.com/100DaysofYARA/2024/blob/7df92fafb900e3f148d927ac8dd68bfeaea0c332/larsborn/Day_017.yara"
		date = "2025-01-02"
		version = "1.0"

	condition:
		uint32be(0) == 0x504b0304 and
		uint16(0x6) & 0x1 == 1 and // check password flag is set
		uint32be(uint16(0x1a) + 0x1e - 4) == 0x2e766273 and // check that file ext is .vbs
		uint32be(filesize - 0x16) == 0x504b0506 and // check for end loacator of ZIP
		uint32be(filesize - 0xe) == 0x01000100 // check number of entries == 1

}

rule SUSP_Encrypted_ZIP_SingleEntry_MSC
{
	meta:
		author = "Greg Lesnewich"
		description = "track encrypted ZIP files with only one MSC file in its contents"
		inspiration_ref = "https://github.com/100DaysofYARA/2024/blob/7df92fafb900e3f148d927ac8dd68bfeaea0c332/larsborn/Day_017.yara"
		date = "2025-01-02"
		version = "1.0"

	condition:
		uint32be(0) == 0x504b0304 and
		uint16(0x6) & 0x1 == 1 and // check password flag is set
		uint32be(uint16(0x1a) + 0x1e - 4) == 0x2E6D7363 and // check that file ext is .msc
		uint32be(filesize - 0x16) == 0x504b0506 and // check for end loacator of ZIP
		uint32be(filesize - 0xe) == 0x01000100 // check number of entries == 1

}
