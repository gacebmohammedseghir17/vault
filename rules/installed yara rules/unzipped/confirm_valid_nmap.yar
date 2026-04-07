import "pe"
import "hash"
rule CONFIRM_VALID_NMAP {
    meta:
        author = "Ian Cook @cioaonk"
        description = "Confirms Exe is latest NMAP Executable using various PE and hash values"
        date = "2025-01-03"
        reference = "https://nmap.org/download.html#windows"
    condition:
       pe.machine == pe.MACHINE_I386 and 
       (hash.md5(0, filesize) == "bd457e3fb19a7f127a23369e70ee84fc") and
       pe.linker_version.major == 6 and 
       pe.sections[1].name == ".rdata"
}
