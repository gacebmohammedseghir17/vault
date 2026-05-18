use std::ffi::c_void;
use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE, GENERIC_READ, GENERIC_WRITE};
use windows::Win32::Storage::FileSystem::{CreateFileW, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE};
use windows::Win32::System::IO::DeviceIoControl;
use windows::core::{PCWSTR, w};
use serde::Serialize;
use reqwest::Client;

const IOCTL_EDR_GET_EVENT: u32 = 0x80002000; // Custom IOCTL to get alerts from driver

#[derive(Serialize)]
struct ThreatEvent {
    process_id: u32,
    threat_type: String,
    severity: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("[*] Starting Next-Gen EDR Agent (Rust)...");

    // 1. In a real scenario, we would run as a Protected Process Light (PPL)
    // 2. Open a handle to the Kernel Minifilter Driver
    let driver_handle: HANDLE = unsafe {
        CreateFileW(
            w!("\\\\.\\EdrMinifilter"),
            GENERIC_READ.0 | GENERIC_WRITE.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )?
    };

    if driver_handle == INVALID_HANDLE_VALUE {
        eprintln!("[-] Failed to connect to Kernel Driver. Is it loaded?");
        return Ok(());
    }
    
    println!("[+] Successfully connected to Kernel Minifilter.");

    let http_client = Client::new();

    // 3. Polling loop to get alerts from the kernel driver
    // (A production EDR uses Completion Ports / Filter Communication Ports (FltPort) instead of simple polling)
    loop {
        let mut event_buffer = [0u8; 1024];
        let mut bytes_returned = 0;

        let success = unsafe {
            DeviceIoControl(
                driver_handle,
                IOCTL_EDR_GET_EVENT,
                None,
                0,
                Some(event_buffer.as_mut_ptr() as *mut c_void),
                event_buffer.len() as u32,
                Some(&mut bytes_returned),
                None,
            )
        };

        if success.is_ok() && bytes_returned > 0 {
            println!("[!] Alert received from Kernel!");
            
            // Send telemetry to Python backend
            let event = ThreatEvent {
                process_id: 1337, // Parse from event_buffer
                threat_type: "High Entropy Write (Ransomware)".to_string(),
                severity: "CRITICAL".to_string(),
            };

            let _ = http_client.post("http://127.0.0.1:8000/telemetry")
                .json(&event)
                .send()
                .await;
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    }
}
