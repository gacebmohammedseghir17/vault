use minidump::{Minidump, MinidumpMemoryInfoList};
use minidump::format::{MemoryState, MemoryProtection};
use crate::forensic::pe_analyzer::extract_iocs;
use std::fs;

pub fn triage_dump(dump_path: &str) -> bool {
    let mut dump = match Minidump::read_path(dump_path) {
        Ok(d) => d,
        Err(_) => {
            println!("[!] Failed to read minidump file.");
            return false;
        }
    };

    let memory_info = match dump.get_stream::<MinidumpMemoryInfoList>() {
        Ok(m) => m,
        Err(_) => {
            println!("[!] Failed to get memory info stream from dump.");
            return false;
        }
    };

    let mut found_suspicious = false;

    for region in memory_info.iter() {
        if region.state == MemoryState::MEM_COMMIT && 
           (region.protection == MemoryProtection::PAGE_EXECUTE_READWRITE || region.protection == MemoryProtection::PAGE_EXECUTE_READ) 
        {
            if let Some(mem_list) = dump.get_memory() {
                if let Some(unified_mem) = mem_list.memory_at_address(region.raw.base_address) {
                    let bytes = unified_mem.bytes();
                    println!("\x1b[33;1m[+] Suspicious RWX/RX Region Found at 0x{:X} (Size: {} bytes)\x1b[0m", region.raw.base_address, region.raw.region_size);
                    found_suspicious = true;

                    let iocs = extract_iocs(bytes);
                    if !iocs.is_empty() {
                        println!("    -> Extracted IOCs from Memory:");
                        for ioc in iocs {
                            println!("       - {}", ioc);
                        }
                    } else {
                        println!("    -> No clear-text IOCs found in this region.");
                    }

                    // Ensure Dumps directory exists
                    let dump_dir = "C:\\ERDPS_Vault\\Dumps";
                    let _ = fs::create_dir_all(dump_dir);

                    let out_path = format!("{}\\{}_extracted_region_0x{:X}.bin", dump_dir, std::path::Path::new(dump_path).file_name().unwrap_or_default().to_string_lossy(), region.raw.base_address);
                    if fs::write(&out_path, bytes).is_ok() {
                        println!("    -> Region saved to: {}", out_path);
                    }
                }
            }
        }
    }

    if !found_suspicious {
        println!("[-] No suspicious memory regions found in dump.");
    }

    true
}