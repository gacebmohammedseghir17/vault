use std::net::TcpListener;
use std::thread;
use std::process::Command;

pub fn start_network_canary() {
    thread::spawn(|| {
        // Try 3389 (RDP) or fallback to 33899
        let listener = match TcpListener::bind("0.0.0.0:3389") {
            Ok(l) => l,
            Err(_) => TcpListener::bind("0.0.0.0:33899").unwrap_or_else(|_| TcpListener::bind("0.0.0.0:0").unwrap()),
        };
        
        println!("\x1b[36m[DECEPTION] Network Canary listening for lateral movement on port {}...\x1b[0m", listener.local_addr().unwrap().port());
        
        for stream in listener.incoming() {
            if let Ok(stream) = stream {
                if let Ok(peer) = stream.peer_addr() {
                    println!("\x1b[31m[DECEPTION] Network Canary tripped by IP: {}\x1b[0m", peer.ip());
                    
                    if peer.ip().is_loopback() || peer.ip().to_string() == "127.0.0.1" {
                        let source_port = peer.port();
                        if let Some(pid) = find_pid_by_port(source_port) {
                            println!("\x1b[31;1m[DECEPTION] Local lateral movement detected! PID: {}\x1b[0m", pid);
                            crate::threat_graph::execute_guillotine(pid);
                        }
                    }
                }
            }
        }
    });
}

fn find_pid_by_port(port: u16) -> Option<u32> {
    let output = Command::new("netstat")
        .args(&["-ano"])
        .output()
        .ok()?;
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    let search_str = format!(":{} ", port);
    
    for line in stdout.lines() {
        if line.contains(&search_str) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(pid_str) = parts.last() {
                if let Ok(pid) = pid_str.parse::<u32>() {
                    return Some(pid);
                }
            }
        }
    }
    None
}

pub fn inject_fake_credentials() {
    #[cfg(target_os = "windows")]
    unsafe {
        use windows::Win32::Security::Credentials::{CredWriteW, CREDENTIALW, CRED_TYPE_GENERIC, CRED_PERSIST_LOCAL_MACHINE};
        use windows::core::PWSTR;

        let mut target_name: Vec<u16> = "CORP-DC-01\0".encode_utf16().collect();
        let mut user_name: Vec<u16> = "svc_admin_fake\0".encode_utf16().collect();
        let mut password = b"SuperSecret123!".to_vec();

        let mut cred: CREDENTIALW = std::mem::zeroed();
        cred.Type = CRED_TYPE_GENERIC; 
        cred.TargetName = PWSTR(target_name.as_mut_ptr());
        cred.UserName = PWSTR(user_name.as_mut_ptr());
        cred.CredentialBlobSize = password.len() as u32;
        cred.CredentialBlob = password.as_mut_ptr();
        cred.Persist = CRED_PERSIST_LOCAL_MACHINE;

        if CredWriteW(&cred, 0).is_ok() {
            println!("\x1b[32m[DECEPTION] Injected fake credential: CORP-DC-01\\svc_admin_fake\x1b[0m");
        } else {
            println!("\x1b[31m[DECEPTION] Failed to inject fake credential.\x1b[0m");
        }
    }
}
