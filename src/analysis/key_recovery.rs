use winapi::ctypes::c_void;
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::memoryapi::{ReadProcessMemory, VirtualQueryEx};
use winapi::um::winnt::{PROCESS_VM_READ, PROCESS_QUERY_INFORMATION, MEM_COMMIT, PAGE_READWRITE, MEMORY_BASIC_INFORMATION};
use winapi::um::handleapi::CloseHandle;
use console::style;
use std::fs::File;
use std::io::Write;

const AES_256_KEY_SIZE: usize = 32;
const MIN_ENTROPY: f64 = 7.2; // Threshold for "Random-looking" data (Keys are ~7.8-8.0)

pub struct KeyHunter;

impl KeyHunter {
    /// EXTRACT: Scans a FROZEN process for potential AES Keys.
    pub fn extract_keys(pid: u32) {
        println!("[*] STARTING DEEP MEMORY CARVING for PID: {}...", pid);
        println!("[*] Target is presumed FROZEN. Memory state is stable.");

        let mut potential_keys: Vec<Vec<u8>> = Vec::new();

        unsafe {
            let handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, pid);
            if handle.is_null() {
                println!("{}", style("[!] Failed to attach to process. Ensure it is Frozen.").red());
                return;
            }

            let mut address = 0 as *mut c_void;
            let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();

            // Iterate over all committed Heap memory
            while VirtualQueryEx(handle, address as *const c_void, &mut mbi, std::mem::size_of::<MEMORY_BASIC_INFORMATION>()) != 0 {
                if mbi.State == MEM_COMMIT && mbi.Protect == PAGE_READWRITE {
                    let mut buffer: Vec<u8> = vec![0; mbi.RegionSize];
                    let mut bytes_read = 0;

                    if ReadProcessMemory(handle, address as *const c_void, buffer.as_mut_ptr() as *mut c_void, mbi.RegionSize, &mut bytes_read) != 0 {
                        // Scan chunk for keys
                        scan_chunk(&buffer[..bytes_read], &mut potential_keys);
                    }
                }
                address = (address as usize + mbi.RegionSize) as *mut c_void;
            }
            CloseHandle(handle);
        }

        if potential_keys.is_empty() {
            println!("{}", style("[-] No high-entropy key candidates found.").yellow());
        } else {
            println!("{}", style(format!("[+] SUCCESS: Recovered {} potential AES keys!", potential_keys.len())).green().bold());
            save_keys(pid, &potential_keys);
        }
    }
}

/// Analyzing Entropy to distinguish "Keys" from "Text"
fn scan_chunk(buffer: &[u8], keys: &mut Vec<Vec<u8>>) {
    // Sliding window of 32 bytes (AES-256 Key Size)
    // Optimization: Skip 16 bytes to be faster
    if buffer.len() < AES_256_KEY_SIZE { return; }

    for i in (0..buffer.len().saturating_sub(AES_256_KEY_SIZE)).step_by(16) {
        let window = &buffer[i..i+AES_256_KEY_SIZE];
        let entropy = calculate_shannon_entropy(window);

        // AES keys look like pure noise (High Entropy)
        if entropy > MIN_ENTROPY {
            // Filter out common false positives (like code segments or zero-pads)
            if !is_false_positive(window) {
                keys.push(window.to_vec());
            }
        }
    }
}

fn calculate_shannon_entropy(data: &[u8]) -> f64 {
    let mut frequency = [0u32; 256];
    for &byte in data {
        frequency[byte as usize] += 1;
    }

    let mut entropy = 0.0;
    let len = data.len() as f64;
    for &count in frequency.iter() {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

// Basic filter to ignore memory that is definitely not a key
fn is_false_positive(data: &[u8]) -> bool {
    // If it contains too many printable chars, it's likely a string, not a key
    let printable = data.iter().filter(|&&b| b >= 32 && b <= 126).count();
    if printable > 28 { return true; } // It's just a random string
    false
}

fn save_keys(pid: u32, keys: &[Vec<u8>]) {
    let filename = format!("dumped_keys_{}.bin", pid);
    let mut file = File::create(&filename).expect("Failed to create key dump");
    
    for (i, key) in keys.iter().enumerate() {
        writeln!(file, "Key #{}: {:02X?}", i, key).unwrap();
    }
    
    println!("{}", style(format!("[*] Keys saved to disk: {}", filename)).cyan());
    println!("{}", style("    -> Use 'Strings' or Hex Editor to inspect.").cyan());
}
