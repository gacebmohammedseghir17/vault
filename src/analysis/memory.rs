use winapi::ctypes::c_void;
use winapi::um::processthreadsapi::{OpenProcess, GetCurrentProcessId};
use winapi::um::memoryapi::{ReadProcessMemory, VirtualQueryEx};
use winapi::um::winnt::{PROCESS_VM_READ, PROCESS_QUERY_INFORMATION, MEM_COMMIT, PAGE_READWRITE, PAGE_READONLY, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, MEMORY_BASIC_INFORMATION};
use winapi::um::handleapi::CloseHandle;
use console::style;

const MAX_BUFFER_SIZE: usize = 10 * 1024 * 1024; // 10MB Limit per chunk to prevent OOM

pub fn scan_process(pid: u32) {
    // 1. Self-Exclusion: Don't scan ourselves to prevent false positive loops
    unsafe {
        if pid == GetCurrentProcessId() {
            println!("{}", style("[!] Skipping Self-Scan (ERDPS Agent).").yellow());
            return;
        }
    }

    println!("[*] Attaching to Process ID: {}...", pid);
    
    unsafe {
        let handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, pid);
        
        if handle.is_null() {
            println!("{}", style("[!] Failed to open process. Access Denied or Invalid PID.").red().bold());
            return;
        }

        let mut address = 0 as *mut c_void;
        let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
        let mut found_threats = false;
        
        println!("[*] Scanning Heap & Stack Memory...");

        while VirtualQueryEx(handle, address as *const c_void, &mut mbi, std::mem::size_of::<MEMORY_BASIC_INFORMATION>()) != 0 {
            // Check if memory is committed and readable
            if mbi.State == MEM_COMMIT && 
               (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_READONLY || mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE_READWRITE) {
                
                // 2. Context Awareness: Check protection for "Executable Configs"
                let is_executable = mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE_READWRITE;

                let mut size = mbi.RegionSize;
                // Safety Cap
                if size > MAX_BUFFER_SIZE {
                    size = MAX_BUFFER_SIZE; 
                }

                let mut buffer: Vec<u8> = vec![0; size];
                let mut bytes_read = 0;

                if ReadProcessMemory(handle, address as *const c_void, buffer.as_mut_ptr() as *mut c_void, size, &mut bytes_read) != 0 {
                    let content = &buffer[..bytes_read];
                    if analyze_chunk(content, pid, is_executable) {
                        found_threats = true;
                    }
                }
            }
            
            // Move to next region
            address = (address as usize + mbi.RegionSize) as *mut c_void;
        }

        CloseHandle(handle);
        
        if !found_threats {
             println!("[*] Memory Scan Complete. No obvious threats found in ASCII strings.");
        } else {
             println!("{}", style("[!] SCAN COMPLETE: THREATS DETECTED.").red().bold());
        }
    }
}

fn analyze_chunk(buffer: &[u8], pid: u32, is_executable: bool) -> bool {
    let mut found = false;
    
    // 3. Heuristics: Combined Indicators
    // Primary: Strong Indicators (Needs only 1 to trigger if Executable Memory, or just 1 really strong one)
    let strong_signatures = ["LockBit_3.0", "RyukReadMe", "WanaDecryptor", "DECRYPT_FILES.txt", "restore_files_"];
    
    // Secondary: Weak Indicators (Needs combination)
    let weak_signatures = ["bitcoin", "monero", "onion", "tor", "encrypt", "private_key", "public_key"];
    
    // Lossy conversion is fast enough for forensics
    let text = String::from_utf8_lossy(buffer).to_lowercase();
    
    // Check Strong
    for sig in strong_signatures.iter() {
        if text.contains(&sig.to_lowercase()) {
             println!("{}", style(format!("[!] MALWARE CONFIRMED: '{}' found in RAM (PID: {}).", sig, pid)).red().bold().blink());
             if is_executable {
                 println!("{}", style("    [+] Context: Found in EXECUTABLE Memory (High Confidence)").red());
             }
             found = true;
        }
    }

    // Check Weak (Heuristic Score)
    let mut weak_hits = 0;
    let mut hit_list = Vec::new();
    for sig in weak_signatures.iter() {
        if text.contains(&sig.to_lowercase()) {
            weak_hits += 1;
            hit_list.push(*sig);
        }
    }

    // Threshold: 2 Weak Indicators = Suspicious
    if weak_hits >= 2 {
        println!("{}", style(format!("[!] HEURISTIC ALERT: Multiple suspicious strings found in PID {}: {:?}", pid, hit_list)).yellow().bold());
        if is_executable {
             println!("{}", style("    [!] WARNING: Found in Executable Memory Region").yellow());
        }
        found = true;
    }
    
    // URL Extraction (Basic) - Kept as is, it's useful context
    let mut start_idx = 0;
    while let Some(idx) = text[start_idx..].find("http://") {
        let real_idx = start_idx + idx;
        extract_and_print_url(&text, real_idx);
        start_idx = real_idx + 1;
        found = true; // Finding C2 is always relevant
    }
    
    start_idx = 0;
    while let Some(idx) = text[start_idx..].find("https://") {
        let real_idx = start_idx + idx;
        extract_and_print_url(&text, real_idx);
        start_idx = real_idx + 1;
        found = true;
    }
    
    found
}

fn extract_and_print_url(text: &str, start: usize) {
    // Find end of URL (whitespace or null or common delimiters)
    let slice = &text[start..];
    // Simple parser: stop at whitespace, null, or quotes
    if let Some(end) = slice.find(|c: char| c.is_whitespace() || c == '\0' || c == '"' || c == '\'' || c == '<' || c == '>') {
        let url = &slice[..end];
        // Filter out common false positives or short strings
        if url.len() > 10 && !url.contains("schemas.microsoft.com") && !url.contains("w3.org") {
            println!("{}", style(format!("[!] C2 BEACON: {}", url)).yellow().bold());
        }
    }
}
