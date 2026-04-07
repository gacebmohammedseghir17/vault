rule APT_NK_CitrineSleet_Macho_Features
{
	meta:
		author = "Greg Lesnewich"
		description = "track CitrineSleet (aka AppleJeus, UNK_JuiceHead) devs based on consistent Dylib + Entitlement use"
		description = "catches UpdateAgent, SimpleTea, CrashReporter"
		date = "2025-01-06"
		version = "1.0"
        	hash = "e352d6ea4da596abfdf51f617584611fc9321d5a6d1c22aff243aecdef8e7e55" // CrashReporter
        	hash = "4f9d2087fadbf7a321a4fbd8d6770a7ace0e4366949b4cfc8cbeb1e9427c02da" // SimpleTea aka POOLRAT
        	hash = "6c121f2b2efa6592c2c22b29218157ec9e63f385e7a1d7425857d603ddef8c59" // UpdateAgent

	condition:
		macho.dylib_hash() == "14146344eb8737897c83e6304da2cdb0"  and
		macho.entitlement_hash() == "b1c0e03afc54794b270a3425443e19b8"
}
