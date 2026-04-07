import "elf"
import "math"

rule TH_Packed_Linux_ELF_AllPackers_2025_CYFARE
{
    meta:
        author                    = "CYFARE"
        description               = "Packed Linux ELF detector: UPX indicators + generic packing heuristics (high-entropy windows, few sections, unpacker API surface)."
        reference                 = "https://cyfare.net/"
        date                      = "2025-09-18"
        version                   = "1.0.0"
        yarahub_uuid              = "a2eb92b8-6c1f-4a4d-9b7f-8e78d0a3b9f5"
        yarahub_reference_md5     = "d41d8cd98f00b204e9800998ecf8427e"
        yarahub_license           = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp  = "TLP:WHITE"
        target_platform           = "Linux (ELF x86/x64/ARM/AArch64)"
        intent                    = "Threat Hunting (aggressive; tune thresholds to adjust FP/TP)"

    strings:
        // UPX-related tokens
        $upx_magic1 = "UPX!" ascii
        $upx_magic2 = "!UPX!" ascii
        $upx_nrv2b  = "NRV2B" ascii
        $upx_nrv2d  = "NRV2D" ascii
        $upx_nrv2e  = "NRV2E" ascii
        $upx_sec0U  = ".UPX0" ascii
        $upx_sec1U  = ".UPX1" ascii
        $upx_sec2U  = ".UPX2" ascii
        $upx_sec0L  = ".upx0" ascii
        $upx_sec1L  = ".upx1" ascii
        $upx_sec2L  = ".upx2" ascii

        // Common embedded compression magics used by packers
        $cm_xz    = { FD 37 7A 58 5A 00 }    // XZ
        $cm_gzip  = { 1F 8B 08 }             // GZIP
        $cm_zstd  = { 28 B5 2F FD }          // Zstandard
        $cm_bz2   = "BZh" ascii              // bzip2
        $cm_lz4   = { 04 22 4D 18 }          // LZ4 frame
        $cm_lzma  = { 5D 00 00 80 00 }       // LZMA header (typical)

        // Unpacker API surface
        $api_mprotect     = "mprotect" ascii nocase
        $api_mmap         = "mmap" ascii nocase
        $api_mremap       = "mremap" ascii nocase
        $api_dlopen       = "dlopen" ascii nocase
        $api_dlsym        = "dlsym" ascii nocase
        $api_memfd_create = "memfd_create" ascii nocase

    condition:
        // Guard: ELF magic, proper type, reasonable size
        uint32(0) == 0x7F454C46 and
        (elf.type == elf.ET_EXEC or elf.type == elf.ET_DYN) and
        filesize < (80 * 1024 * 1024) and
        (
            // 1) Direct UPX indicators
            ( any of ($upx_*) )

            or

            // 2) Generic compressed payload hints + few sections
            (
                (
                    any of ($cm_*) or
                    (filesize >= 8192  and math.entropy(0, 8192) >= 7.20) or
                    (filesize >= 16384 and math.entropy(filesize - 16384, 16384) >= 7.20)
                )
                and (elf.number_of_sections <= 6)
            )

            or

            // 3) Unpacker API surface + (compressed hints or high entropy) + few sections
            (
                ( 2 of ($api_*) ) and
                (
                    any of ($cm_*) or
                    (filesize >= 8192  and math.entropy(0, 8192) >= 7.20) or
                    (filesize >= 16384 and math.entropy(filesize - 16384, 16384) >= 7.20)
                )
                and (elf.number_of_sections <= 6)
            )
        )
}

