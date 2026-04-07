import "macho"

rule MAL_AMOS_Stealer_DylibHash
{
	meta:
		author = "Greg Lesnewich"
		description = "for YARA-X only - track Amos samples based on consistent dylibs + entitlements"
		date = "2024-07-16"
		version = "1.0"
		hash = "01980f717e500688cad1038cc9bd5d3da5c43164394035f7368b26454d877eb9"
		hash = "1a243b063238fd983f21860e812d134c4e0b98afc1f4bf47af4a899f7718c62a"

	condition:
		macho.dylib_hash() == "211ec93719409660eb313e86af400818" and
		macho.entitlement_hash() == "184d4d1b9756d111aac15c97141da66c"
}
