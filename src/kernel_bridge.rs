use windows::Win32::Storage::InstallableFileSystems::{
    FilterConnectCommunicationPort, FilterGetMessage, FILTER_MESSAGE_HEADER
};
use std::mem::size_of;
use std::thread;
use std::time::Duration;
use std::process::Command;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::sync::atomic::Ordering;
use crate::active_defense::ActiveDefense;
use crate::ml_engine::NeuralEngine;
use crate::behavioral_engine::BehavioralSentinel;
use colored::*;
use crate::reporter;
use crate::graph_engine::TopologyEngine;
use crate::SENTINEL_UI_ACTIVE;
use once_cell::sync::Lazy;
use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS};
use winapi::um::handleapi::CloseHandle;
use winapi::shared::minwindef::FALSE;
use winapi::shared::winerror::ERROR_NO_MORE_FILES;

macro_rules! s_println {
    ($($arg:tt)*) => {
        if crate::SENTINEL_UI_ACTIVE.load(std::sync::atomic::Ordering::SeqCst) {
            println!($($arg)*);
        }
    };
}

static TOPOLOGY: Lazy<Mutex<TopologyEngine>> = Lazy::new(|| Mutex::new(TopologyEngine::new()));

#[repr(C)]
struct ErdpsAlert {
    pid: u32,
    reason: u32,
    file_path: [u16; 260],
}

#[repr(C)]
struct MessageWrapper {
    header: FILTER_MESSAGE_HEADER,
    alert: ErdpsAlert,
}

fn get_process_name(pid: u32) -> String {
    if pid == 4 { return "System".to_string(); }
    let output = Command::new("tasklist")
        .args(&["/FI", &format!("PID eq {}", pid), "/FO", "CSV", "/NH"])
        .output();
    match output {
        Ok(out) => {
            let csv = String::from_utf8_lossy(&out.stdout);
            if let Some(first_comma) = csv.find(',') {
                return csv[..first_comma].trim_matches('"').to_string();
            }
        },
        Err(_) => {}
    }
    return String::from("Unknown");
}

fn get_process_path(pid: u32) -> String {
    // Helper to get the full path of the EXE for scanning
    let output = Command::new("powershell")
        .args(&["-Command", &format!("(Get-Process -Id {}).Path", pid)])
        .output();
    match output {
        Ok(out) => String::from_utf8_lossy(&out.stdout).trim().to_string(),
        Err(_) => String::new(),
    }
}

fn get_parent_pid(pid: u32) -> Option<u32> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot.is_null() {
            return None;
        }

        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        let mut ok = Process32FirstW(snapshot, &mut entry);
        while ok != FALSE {
            if entry.th32ProcessID == pid {
                let ppid = entry.th32ParentProcessID;
                CloseHandle(snapshot);
                if ppid == 0 {
                    return None;
                }
                return Some(ppid);
            }
            ok = Process32NextW(snapshot, &mut entry);
            if ok == FALSE {
                let err = winapi::um::errhandlingapi::GetLastError();
                if err == ERROR_NO_MORE_FILES {
                    break;
                }
            }
        }

        CloseHandle(snapshot);
        None
    }
}

// Accepts the AI Engine as an argument
pub fn start_kernel_listener(ai_engine: Arc<NeuralEngine>) {
    thread::spawn(move || {
        let _strike_map: Arc<Mutex<HashMap<u32, u32>>> = Arc::new(Mutex::new(HashMap::new()));
        let mut killed_pids: HashSet<u32> = HashSet::new();

        unsafe {
            let port_name: Vec<u16> = "\\ERDPSPort".encode_utf16().chain(Some(0)).collect();
            let result = FilterConnectCommunicationPort(windows::core::PCWSTR(port_name.as_ptr()), 0, None, 0, None);

            if result.is_err() {
                s_println!("[ERROR] Driver not found. Is 'ERDPS_Sentinel.sys' loaded?");
                return;
            }
            let port_handle = result.unwrap();
            s_println!("[LINK] Connected to Kernel Driver. Listening for threats...");

            loop {
                let mut message: MessageWrapper = std::mem::zeroed();
                let result = FilterGetMessage(port_handle, &mut message.header, size_of::<MessageWrapper>() as u32, None);

                if result.is_ok() {
                    let pid = message.alert.pid;
                    if killed_pids.contains(&pid) { continue; }
                    let reason = message.alert.reason;
                    let target_file = String::from_utf16_lossy(&message.alert.file_path).trim_matches(char::from(0)).to_string();
                    let process_name = get_process_name(pid);

                    if let Some(ppid) = get_parent_pid(pid) {
                        let parent_name = get_process_name(ppid);
                        if let Ok(mut topo) = TOPOLOGY.lock() {
                            if let Some(alert) = topo.track_process_spawn(ppid, parent_name, pid, process_name.clone()) {
                                s_println!("\x1b[31m[GRAPH] {}\x1b[0m", alert);
                                // [ACTIVE DEFENSE] Graph Topology Kill
                                if alert.contains("MALICIOUS") {
                                    s_println!("\x1b[31m[ACTIVE DEFENSE] 🕸️ Graph Topology Rule Triggered: {}\x1b[0m", alert);
                                    ActiveDefense::engage_kill_switch(pid);
                                    reporter::log_alert(pid, &process_name, reason, &target_file);
                                    // We continue processing to allow logging, but the process is dead.
                                }
                            }
                        }
                    }

                    // --- THE NEW COLORED OUTPUT LOGIC ---
                    match reason {
                        1 => {
                            s_println!("\x1b[31m[CRITICAL] ☠️  PROCESS KILLED: {} (PID: {})\x1b[0m", process_name, pid);
                        }
                        2 => {
                            s_println!("\x1b[33m[WARNING] ⚠️  SUSPICIOUS FILE ACCESS: {} (PID: {})\x1b[0m", process_name, pid);
                        }
                        3 => {
                            s_println!("\x1b[41;37m[CRITICAL] ☠️  BLOCKED RANSOMWARE ATTEMPT (RENAME/DELETE) -> PID: {}\x1b[0m", pid);
                            ActiveDefense::engage_kill_switch(pid);
                            ActiveDefense::create_snapshot();
                            reporter::log_alert(pid, &process_name, reason, &target_file);
                        }
                        4 => {
                            s_println!("\x1b[41;37m[CRITICAL] ☠️  DELTA ENTROPY TRIGGERED (ENCRYPTION LOOP) -> PID: {}\x1b[0m", pid);
                            ActiveDefense::engage_kill_switch(pid);
                            reporter::log_alert(pid, &process_name, reason, &target_file);
                        }
                        5 => {
                            s_println!("\x1b[41;37m[CRITICAL] ☠️  DETECTED RAW DISK / MBR WRITE (PID: {})\x1b[0m", pid);
                            ActiveDefense::engage_kill_switch(pid);
                            reporter::log_alert(pid, &process_name, reason, &target_file);
                        }
                        6 => {
                            s_println!("\x1b[41;37m[CRITICAL] ☠️  ZERO-TRUST EXECUTION BLOCKED (PID: {})\x1b[0m", pid);
                            ActiveDefense::engage_kill_switch(pid);
                            reporter::log_alert(pid, &process_name, reason, &target_file);
                        }
                        7 => {
                            s_println!("\x1b[41;37m[CRITICAL] ☠️  VULNERABLE BYOVD DRIVER LOAD BLOCKED (PID: {})\x1b[0m", pid);
                            ActiveDefense::engage_kill_switch(pid);
                            reporter::log_alert(pid, &process_name, reason, &target_file);
                        }
                        8 => {
                            s_println!("\x1b[41;37m[CRITICAL] KERNEL BLOCKED CANARY TAMPERING -> PID: {}\x1b[0m", pid);
                            ActiveDefense::engage_kill_switch(pid);
                            reporter::log_alert(pid, &process_name, reason, &target_file);
                        }
                        _ => {
                            s_println!("\x1b[34m[KERNEL] Raw Alert Received: PID={} Reason={}\x1b[0m", pid, reason);
                        }
                    }

                    // --- V6 AI ANALYSIS ---
                    let mut kill_it = false;
                    let mut threat_label = "UNKNOWN";

                    // 1. STATIC AI SCAN (LightGBM)
                    // We check WHO is doing the action.
                    if process_name != "System" && process_name != "Unknown" {
                        // --- DIAMOND PATCH: BLOCK KNOWN RANSOMWARE TOOLS (Chaos v4) ---
                        if ActiveDefense::is_ransomware_tool(&process_name) {
                            s_println!("\x1b[31m[!!!] BLOCKED RANSOMWARE TOOL: {}\x1b[0m", process_name);
                            kill_it = true;
                            threat_label = "RANSOMWARE_TOOL_BLOCK";
                            
                            // Proactive Defense: Snapshot immediately if they try to touch shadows
                            if process_name.to_lowercase().contains("vssadmin") {
                                ActiveDefense::create_snapshot();
                            }
                        }

                        let proc_path = get_process_path(pid);
                        if !kill_it && !proc_path.is_empty() {
                            // Extract just the score for decision logic
                            let (malicious_score, _) = ai_engine.scan_static(&proc_path);
                            
                            if malicious_score > 0.95 {
                                s_println!("\x1b[31m[ACTIVE DEFENSE] 🧠 AI CONFIDENCE > 95% (Score: {:.2}). ENGAGING LETHAL FORCE.\x1b[0m", malicious_score);
                                kill_it = true;
                                threat_label = "AI_STATIC_CRITICAL";
                            } else if malicious_score > 0.7 {
                                s_println!("\x1b[33m[ACTIVE DEFENSE] 🧠 AI SUSPICIOUS (Score: {:.2}). ENGAGING CONTAINMENT.\x1b[0m", malicious_score);
                                // Non-Lethal Response: Suspend + Isolate
                                ActiveDefense::engage_suspend(pid);
                                ActiveDefense::engage_network_isolation(pid, &proc_path);
                                threat_label = "AI_STATIC_SUSPICIOUS";
                                reporter::log_alert(pid, &process_name, reason, &target_file);
                            } else if malicious_score < 0.2 {
                                // AI says it's safe (e.g., explorer.exe)
                                // We IGNORE the alert unless it's a Honeypot trigger.
                                if reason != 1 { continue; }
                            }
                        }
                    }

                    // 2. KERNEL REASON LOGIC (Backup)
                    if !kill_it {
                        if reason == 1 {
                            s_println!("[*] HONEYPOT TRIGGERED. KILLING...");
                            kill_it = true;
                            threat_label = "HONEYPOT";
                        }
                        else if reason == 3 {
                            // Rename detected. AI didn't flag it, but Kernel did.
                            // If AI score was low (safe), we trust AI and ignore.
                            // If AI score was medium (0.5), we trust Kernel and block.
                             s_println!("[!] SUSPICIOUS RENAME by {}", process_name);
                             // For now, only kill if not explorer
                             if process_name.to_lowercase() != "explorer.exe" {
                                 kill_it = true;
                                 threat_label = "TAMPERING";
                             }
                        }
                    }

                    if kill_it {
                        killed_pids.insert(pid);
                        s_println!("\x1b[31m[KILL] Neutralized Threat: {} (Label: {})\x1b[0m", process_name, threat_label);
                        ActiveDefense::engage_kill_switch(pid);
                        reporter::log_alert(pid, &process_name, reason, &target_file);
                    }
                } else {
                    // THIS PREVENTS THE CRASH
                    s_println!("\x1b[31m[!] KERNEL PORT DISCONNECTED. Exiting listener thread gracefully.\x1b[0m");
                    break; 
                }
            }
        }
    });
}
