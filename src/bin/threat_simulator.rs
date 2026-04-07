use std::fs::{self, File};
use std::io::{Write, Read, Cursor};
use std::path::Path;
use std::thread;
use std::time::Duration;
use std::net::{TcpListener, TcpStream};
use rand::RngCore;

#[cfg(windows)]
use winapi::um::winuser::{
    CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, RegisterClassExW,
    SetWindowsHookExW, CallNextHookEx, SetTimer, PostQuitMessage, UpdateWindow, ShowWindow,
    MSG, WNDCLASSEXW, WH_KEYBOARD_LL, WS_EX_TOPMOST, WS_EX_LAYERED, WS_POPUP, WS_VISIBLE,
    SW_SHOW, KBDLLHOOKSTRUCT, LWA_ALPHA, SetLayeredWindowAttributes, TranslateMessage
};
#[cfg(windows)]
use winapi::um::fileapi::{CreateFileW, OPEN_EXISTING};
#[cfg(windows)]
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
#[cfg(windows)]
use winapi::um::winnt::{GENERIC_READ, FILE_SHARE_READ, FILE_SHARE_WRITE};
#[cfg(windows)]
use winapi::shared::minwindef::{LPARAM, LRESULT, WPARAM, HINSTANCE};
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
#[cfg(windows)]
use winapi::um::libloaderapi::GetModuleHandleW;

fn main() {
    println!("==================================================");
    println!("  ERDPS BENIGN THREAT EMULATOR (SAFE MODE)        ");
    println!("  All actions are heavily throttled for detection ");
    println!("==================================================");

    // Module 1
    simulate_crypto_io();
    
    // Module 3 (Do it before UI so console is visible)
    simulate_physical_drive_access();
    
    // Module 4
    simulate_exfiltration();

    // Module 2 (UI blocks thread usually)
    simulate_locker_ui();
    
    println!("\n[*] All simulations completed.");
}

// ---------------------------------------------------------
// 1. High-Entropy I/O Generator
// ---------------------------------------------------------
fn simulate_crypto_io() {
    println!("\n[*] MODULE 1: High-Entropy I/O Generator (Simulated Crypto)");
    let target_dir = "C:\\erdps_test_env";
    if !Path::new(target_dir).exists() {
        let _ = fs::create_dir_all(target_dir);
    }

    let mut rng = rand::thread_rng();
    let mut buffer = vec![0u8; 1024 * 4]; // 4KB block

    for i in 1..=3 {
        println!("    -> Waiting 2000ms before acquiring file handle...");
        thread::sleep(Duration::from_millis(2000));
        
        let file_path = format!("{}\\{}_dummy.txt", target_dir, i);
        println!("    -> Opening {}...", file_path);
        
        if let Ok(mut f) = File::create(&file_path) {
            println!("    -> Writing high-entropy data blocks (500ms delay between blocks)...");
            for _b in 1..=5 {
                rng.fill_bytes(&mut buffer); // Generate high entropy
                if f.write_all(&buffer).is_ok() {
                    print!(".");
                    let _ = std::io::stdout().flush();
                }
                thread::sleep(Duration::from_millis(500));
            }
            println!(" Done.");
        }
    }
}

// ---------------------------------------------------------
// 3. Anomalous Handle Acquisition
// ---------------------------------------------------------
#[cfg(windows)]
fn simulate_physical_drive_access() {
    println!("\n[*] MODULE 3: Anomalous Handle Acquisition (Simulated Leakware/MBR Tamper)");
    
    let drive_path: Vec<u16> = std::ffi::OsStr::new("\\\\.\\PhysicalDrive0")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    println!("    -> Attempting to acquire READ-ONLY handle to PhysicalDrive0...");
    unsafe {
        let handle = CreateFileW(
            drive_path.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null_mut(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        );

        if handle != INVALID_HANDLE_VALUE {
            println!("    -> [!] Handle acquired successfully! (EDR should flag this)");
            println!("    -> Sleeping for 5000ms while holding the physical drive handle...");
            thread::sleep(Duration::from_millis(5000));
            CloseHandle(handle);
            println!("    -> Handle released safely.");
        } else {
            println!("    -> [BLOCKED] Failed to acquire handle. (Did ERDPS block it?)");
        }
    }
}
#[cfg(not(windows))]
fn simulate_physical_drive_access() {
    println!("Not on Windows");
}

// ---------------------------------------------------------
// 4. Localhost Archiving & Telemetry
// ---------------------------------------------------------
fn simulate_exfiltration() {
    println!("\n[*] MODULE 4: Localhost Archiving & Telemetry (Simulated Exfiltration)");
    
    // Setup dummy receiver server
    thread::spawn(|| {
        if let Ok(listener) = TcpListener::bind("127.0.0.1:8080") {
            for stream in listener.incoming() {
                if let Ok(mut s) = stream {
                    let mut buf = [0; 1024];
                    let _ = s.read(&mut buf);
                    // Just drop the data
                }
            }
        }
    });

    thread::sleep(Duration::from_millis(500)); // Let server start

    println!("    -> Compressing C:\\erdps_test_env\\ dummy files...");
    let mut archive_data = Vec::new();
    {
        let mut zip = zip::ZipWriter::new(Cursor::new(&mut archive_data));
        let options = zip::write::FileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
            
        if let Ok(entries) = fs::read_dir("C:\\erdps_test_env") {
            for entry in entries.flatten() {
                if entry.path().is_file() {
                    let name = entry.file_name().into_string().unwrap();
                    let _ = zip.start_file(name, options);
                    if let Ok(content) = fs::read(entry.path()) {
                        let _ = zip.write_all(&content);
                    }
                }
            }
        }
        let _ = zip.finish();
    }
    
    println!("    -> Initiating slow network beaconing to localhost...");
    if let Ok(mut stream) = TcpStream::connect("127.0.0.1:8080") {
        let header = format!(
            "POST /exfiltrate HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\n\r\n",
            archive_data.len()
        );
        let _ = stream.write_all(header.as_bytes());
        
        println!("    -> Sending data in fragmented chunks (500ms delay between packets)...");
        for chunk in archive_data.chunks(256) { // Tiny fragments
            if stream.write_all(chunk).is_ok() {
                print!("^");
                let _ = std::io::stdout().flush();
            } else {
                println!("\n    -> [BLOCKED] Connection severed. (Did ERDPS isolate us?)");
                break;
            }
            thread::sleep(Duration::from_millis(500));
        }
        println!(" Done.");
    } else {
        println!("    -> Failed to connect to localhost. (Network Isolated?)");
    }
}

// ---------------------------------------------------------
// 2. Benign Hooking & Topmost Window
// ---------------------------------------------------------
#[cfg(windows)]
unsafe extern "system" fn keyboard_hook(code: i32, w_param: WPARAM, l_param: LPARAM) -> LRESULT {
    // We just log it benignly and pass it on.
    CallNextHookEx(std::ptr::null_mut(), code, w_param, l_param)
}

#[cfg(windows)]
unsafe extern "system" fn window_proc(hwnd: winapi::shared::windef::HWND, msg: u32, w_param: WPARAM, l_param: LPARAM) -> LRESULT {
    match msg {
        winapi::um::winuser::WM_TIMER => {
            // Auto close after 60s
            PostQuitMessage(0);
            0
        }
        winapi::um::winuser::WM_DESTROY => {
            PostQuitMessage(0);
            0
        }
        _ => DefWindowProcW(hwnd, msg, w_param, l_param)
    }
}

#[cfg(windows)]
fn simulate_locker_ui() {
    println!("\n[*] MODULE 2: Benign Hooking & Topmost Window (Simulated Locker)");
    
    unsafe {
        // 1. Install Hook
        println!("    -> Installing WH_KEYBOARD_LL global hook (Benign Pass-through)...");
        let h_inst = GetModuleHandleW(std::ptr::null());
        let hook = SetWindowsHookExW(WH_KEYBOARD_LL, Some(keyboard_hook), h_inst, 0);
        if hook.is_null() {
            println!("    -> [BLOCKED] Hook installation failed.");
        } else {
            println!("    -> Hook active.");
        }

        // 2. Create Topmost Transparent Window
        let class_name: Vec<u16> = std::ffi::OsStr::new("LockerClass\0").encode_wide().collect();
        let wnd_class = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            style: 0,
            lpfnWndProc: Some(window_proc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: h_inst,
            hIcon: std::ptr::null_mut(),
            hCursor: std::ptr::null_mut(),
            hbrBackground: std::ptr::null_mut(),
            lpszMenuName: std::ptr::null_mut(),
            lpszClassName: class_name.as_ptr(),
            hIconSm: std::ptr::null_mut(),
        };

        RegisterClassExW(&wnd_class);

        let window_name: Vec<u16> = std::ffi::OsStr::new("Simulated Ransomware Locker - SAFE MODE\0").encode_wide().collect();
        
        let hwnd = CreateWindowExW(
            WS_EX_TOPMOST | WS_EX_LAYERED,
            class_name.as_ptr(),
            window_name.as_ptr(),
            WS_POPUP | WS_VISIBLE,
            0, 0, 800, 600, // Small window, not full screen to keep system usable
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            h_inst,
            std::ptr::null_mut()
        );

        if !hwnd.is_null() {
            println!("    -> Creating Topmost Window (Alpha rendering over 10s)...");
            
            // Render slowly
            for alpha in (0..=200).step_by(20) {
                SetLayeredWindowAttributes(hwnd, 0, alpha as u8, LWA_ALPHA);
                UpdateWindow(hwnd);
                thread::sleep(Duration::from_millis(1000)); // 10 steps * 1000ms = 10s
            }

            println!("    -> UI Locked in. System will auto-close in 60s...");
            SetTimer(hwnd, 1, 60000, None);

            // Message Loop
            let mut msg: MSG = std::mem::zeroed();
            while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }
}
#[cfg(not(windows))]
fn simulate_locker_ui() {
    println!("Not on Windows");
}