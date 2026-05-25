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
use crate::active_defense::policy::{Signal, ActionPlan, PolicyGate, MitigationExecutor};
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

pub fn get_process_name(pid: u32) -> String {
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

pub fn get_process_path(pid: u32) -> String {
    // Helper to get the full path of the EXE for scanning
    let output = Command::new("powershell")
        .args(&["-Command", &format!("(Get-Process -Id {}).Path", pid)])
        .output();
    match output {
        Ok(out) => String::from_utf8_lossy(&out.stdout).trim().to_string(),
        Err(_) => String::new(),
    }
}

pub fn get_parent_pid(pid: u32) -> Option<u32> {
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
        let mut sanity_log_count = 0;

        loop {
            unsafe {
                let port_name: Vec<u16> = "\\ERDPS_SentinelPort".encode_utf16().chain(Some(0)).collect();
                let result = FilterConnectCommunicationPort(windows::core::PCWSTR(port_name.as_ptr()), 0, None, 0, None);

                if result.is_err() {
                    // println!("\x1b[33m[KERNEL] Driver not found. Retrying connection in 2 seconds...\x1b[0m");
                    crate::KERNEL_CONNECTED.store(false, Ordering::SeqCst);
                    thread::sleep(Duration::from_secs(2));
                    continue;
                }
                let port_handle = result.unwrap();
                println!("\x1b[32;1m[LINK] Connected to Kernel Driver. Listening for threats...\x1b[0m");
                crate::KERNEL_CONNECTED.store(true, Ordering::SeqCst);

                loop {
                    let mut message: MessageWrapper = std::mem::zeroed();
                    let result = FilterGetMessage(port_handle, &mut message.header, size_of::<MessageWrapper>() as u32, None);

                    if result.is_ok() {
                        let pid = message.alert.pid;
                        let reason = message.alert.reason;
                        let target_file = String::from_utf16_lossy(&message.alert.file_path).trim_matches(char::from(0)).to_string();

                        // KERNEL GUILLOTINE EXECUTION
                        if reason == 1 || reason == 2 || reason == 3 {
                            if reason == 3 {
                                println!("\x1b[41;37m[CRITICAL] KERNEL RATE LIMITER TRIGGERED -> MASS ENCRYPTION HALTED ON PID {}\x1b[0m", pid);
                            } else if reason == 2 {
                                println!("\x1b[41;37m[CRITICAL] KERNEL GUILLOTINE: BLOCKED EXTENSION RENAME -> TERMINATED PID {}\x1b[0m", pid);
                            } else {
                                println!("\x1b[41;37m[CRITICAL] KERNEL GUILLOTINE: BLOCKED EXTENSION WRITE -> TERMINATED PID {}\x1b[0m", pid);
                            }
                            crate::micro_rollback::trigger_micro_rollback(pid);
                            killed_pids.insert(pid);
                            continue; // Skip the rest of the loop since it's already killed by Kernel
                        }

                        // 1-TIME KERNEL SANITY LOG (Print unconditionally for the first 5 events)
                        if sanity_log_count < 5 {
                            println!("\x1b[36m[KERNEL SANITY] Received event: PID={} Reason={} File={}\x1b[0m", pid, reason, target_file);
                            sanity_log_count += 1;
                        }

                        let sentinel_active = crate::SENTINEL_UI_ACTIVE.load(Ordering::SeqCst);
                        if !sentinel_active {
                            continue;
                        }

                        if killed_pids.contains(&pid) { continue; }
                        let process_name = get_process_name(pid);

                        // ROLLBACK: Backup file before modification
                        if reason == 10 || reason == 4 {
                            if crate::SENTINEL_UI_ACTIVE.load(Ordering::SeqCst) {
                                crate::active_defense::rollback::backup_file_pre_modify(pid, &target_file);
                            }
                        }

                        // KERNEL-MODE EXTENSION MUTATION DETECTOR (For WannaCry / DarkSide)
                    if let Some(ext_idx) = target_file.rfind('.') {
                        let ext = &target_file[ext_idx + 1..];
                        if ["WCRY", "lockbit", "darkside", "revil", "locked", "encrypt"].contains(&ext) {
                            s_println!("\x1b[41;37m[CRITICAL] KERNEL INTERCEPT: Ransomware Extension Mutation Detected (.ext)\x1b[0m");
                            let sig = Signal { source: "KernelBridge", pid, reason: 3, file_path: target_file.clone(), metadata: Some(format!("Kernel-Mode Extension Mutation (.{})", ext)) };
                            let decided = PolicyGate::decide(&sig, ActionPlan::StorylineKill);
                            MitigationExecutor::execute(decided.clone(), &sig);
                            reporter::log_alert(pid, &process_name, 3, &target_file);
                            if matches!(decided, ActionPlan::Kill | ActionPlan::StorylineKill) {
                                killed_pids.insert(pid);
                            }
                            continue;
                        }
                    }

                    // ZERO-FOOTPRINT HONEYPOT CHECK
                    if crate::active_defense::honeypot::is_honeypot(&target_file) || 
                       target_file.contains("~$cache_config.docx") || 
                       target_file.contains("~sys_temp.pdf") || 
                       target_file.contains("~$win_recovery.xlsx") {
                        
                        // Honeytoken Exfiltration Trap: If the file was READ (Reason 2 or similar I/O), isolate but don't kill
                        // Assuming reason 2 is a read/access event based on the colored output logic below
                        if reason == 2 {
                            s_println!("\x1b[43;30m[CANARY] Honeytoken Read by PID {}. Network Isolated to prevent exfiltration.\x1b[0m", pid);
                            let proc_path = get_process_path(pid);
                            let sig = Signal { source: "KernelBridge", pid, reason, file_path: target_file.clone(), metadata: Some(proc_path) };
                            MitigationExecutor::execute(PolicyGate::decide(&sig, ActionPlan::Contain), &sig);
                            reporter::log_alert(pid, &process_name, 2, &target_file);
                            continue;
                        }

                        s_println!("\x1b[41;37m[CANARY] 💥 KERNEL INTERCEPT: Decoy file modified by PID {}. Instant Kill Engaged!\x1b[0m", pid);
                        let sig = Signal { source: "KernelBridge", pid, reason: 1, file_path: target_file.clone(), metadata: Some("Zero-Footprint Ransomware Honeypot Triggered".to_string()) };
                        let decided = PolicyGate::decide(&sig, ActionPlan::StorylineKill);
                        MitigationExecutor::execute(decided.clone(), &sig);
                        reporter::log_alert(pid, &process_name, 1, &target_file); // Log as critical
                        if matches!(decided, ActionPlan::Kill | ActionPlan::StorylineKill) {
                            killed_pids.insert(pid);
                        }
                        continue;
                    }

                    if let Some(ppid) = get_parent_pid(pid) {
                        let parent_name = get_process_name(ppid);
                        if let Ok(mut topo) = TOPOLOGY.lock() {
                            if let Some(alert) = topo.track_process_spawn(ppid, parent_name, pid, process_name.clone()) {
                                s_println!("\x1b[31m[GRAPH] {}\x1b[0m", alert);
                                // [ACTIVE DEFENSE] Graph Topology Kill
                                if alert.contains("MALICIOUS") {
                                    s_println!("\x1b[31m[ACTIVE DEFENSE] 🕸️ Graph Topology Rule Triggered: {}\x1b[0m", alert);
                                    let sig = Signal { source: "KernelBridge", pid, reason, file_path: target_file.clone(), metadata: Some("Graph Topology Rule Triggered".to_string()) };
                                    MitigationExecutor::execute(PolicyGate::decide(&sig, ActionPlan::StorylineKill), &sig);
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
                        4 => {
                            s_println!("\x1b[41;37m[CRITICAL] ⚠️  DELTA ENTROPY TRIGGERED (ENCRYPTION LOOP) -> PID: {} ({})\x1b[0m", pid, process_name);
                            reporter::log_alert(pid, &process_name, reason, &target_file);
                        }
                        5 => {
                            s_println!("\x1b[41;37m[CRITICAL] ☠️  DETECTED RAW DISK / MBR WRITE (PID: {})\x1b[0m", pid);
                            let sig = Signal { source: "KernelBridge", pid, reason, file_path: target_file.clone(), metadata: Some("Raw Disk/MBR Write Detected by Kernel (Alert 5)".to_string()) };
                            let decided = PolicyGate::decide(&sig, ActionPlan::StorylineKill);
                            MitigationExecutor::execute(decided.clone(), &sig);
                            if matches!(decided, ActionPlan::Kill | ActionPlan::StorylineKill) {
                                killed_pids.insert(pid);
                            }
                            reporter::log_alert(pid, &process_name, reason, &target_file);
                        }
                        6 => {
                            s_println!("\x1b[41;37m[CRITICAL] ☠️  ZERO-TRUST EXECUTION BLOCKED (PID: {})\x1b[0m", pid);
                            let sig = Signal { source: "KernelBridge", pid, reason, file_path: target_file.clone(), metadata: Some("Zero-Trust Execution Blocked by Kernel (Alert 6)".to_string()) };
                            let decided = PolicyGate::decide(&sig, ActionPlan::StorylineKill);
                            MitigationExecutor::execute(decided.clone(), &sig);
                            if matches!(decided, ActionPlan::Kill | ActionPlan::StorylineKill) {
                                killed_pids.insert(pid);
                            }
                            reporter::log_alert(pid, &process_name, reason, &target_file);
                        }
                        7 => {
                            s_println!("\x1b[41;37m[CRITICAL] ☠️  VULNERABLE BYOVD DRIVER LOAD BLOCKED (PID: {})\x1b[0m", pid);
                            let sig = Signal { source: "KernelBridge", pid, reason, file_path: target_file.clone(), metadata: Some("Vulnerable BYOVD Driver Load Blocked by Kernel (Alert 7)".to_string()) };
                            let decided = PolicyGate::decide(&sig, ActionPlan::StorylineKill);
                            MitigationExecutor::execute(decided.clone(), &sig);
                            if matches!(decided, ActionPlan::Kill | ActionPlan::StorylineKill) {
                                killed_pids.insert(pid);
                            }
                            reporter::log_alert(pid, &process_name, reason, &target_file);
                        }
                        8 => {
                            s_println!("\x1b[41;37m[CRITICAL] KERNEL BLOCKED CANARY TAMPERING -> PID: {}\x1b[0m", pid);
                            let sig = Signal { source: "KernelBridge", pid, reason, file_path: target_file.clone(), metadata: Some("Canary Tampering Blocked by Kernel (Alert 8)".to_string()) };
                            let decided = PolicyGate::decide(&sig, ActionPlan::StorylineKill);
                            MitigationExecutor::execute(decided.clone(), &sig);
                            if matches!(decided, ActionPlan::Kill | ActionPlan::StorylineKill) {
                                killed_pids.insert(pid);
                            }
                            reporter::log_alert(pid, &process_name, reason, &target_file);
                        }
                        10 => {
                            s_println!("\x1b[41;37m[CRITICAL] ⚠️  KERNEL BLOCKED HIGH-ENTROPY WRITE (ENCRYPTED PAYLOAD) -> PID: {}\x1b[0m", pid);
                            reporter::log_alert(pid, &process_name, reason, &target_file);
                        }
                        11 => {
                            s_println!("\x1b[41;37m[KERNEL] 🛑 CRITICAL: SAFE MODE REGISTRY TAMPERING DETECTED! (Conti/Snatch Behavior). Engage Kill Switch. -> PID: {}\x1b[0m", pid);
                            let sig = Signal { source: "KernelBridge", pid, reason, file_path: target_file.clone(), metadata: Some("Safe Mode Registry Tampering Blocked by Kernel (Alert 11)".to_string()) };
                            let decided = PolicyGate::decide(&sig, ActionPlan::StorylineKill);
                            MitigationExecutor::execute(decided.clone(), &sig);
                            if matches!(decided, ActionPlan::Kill | ActionPlan::StorylineKill) {
                                killed_pids.insert(pid);
                            }
                            reporter::log_alert(pid, &process_name, reason, &target_file);
                        }
                        12 => {
                            s_println!("\x1b[41;37m[KERNEL] 🛑 CRITICAL: VULNERABLE DRIVER LOAD BLOCKED! (BYOVD / BlackCat Behavior). Engage Kill Switch. -> PID: {}\x1b[0m", pid);
                            let sig = Signal { source: "KernelBridge", pid, reason, file_path: target_file.clone(), metadata: Some("BYOVD Vulnerable Driver Load Blocked by Kernel (Alert 12)".to_string()) };
                            let decided = PolicyGate::decide(&sig, ActionPlan::StorylineKill);
                            MitigationExecutor::execute(decided.clone(), &sig);
                            if matches!(decided, ActionPlan::Kill | ActionPlan::StorylineKill) {
                                killed_pids.insert(pid);
                            }
                            reporter::log_alert(pid, &process_name, reason, &target_file);
                        }
                        13 => {
                            s_println!("\x1b[33m[KERNEL] ⚠️  SUSPICIOUS: CROSS-PROCESS THREAD INJECTION DETECTED! (Log Only). -> PID: {}\x1b[0m", pid);
                            reporter::log_alert(pid, &process_name, reason, &target_file);
                        }
                        14 => {
                            s_println!("\x1b[41;37m[KERNEL] ⚠️  INTERMITTENT ENCRYPTION PATTERN BLOCKED! (LockBit 3.0 Behavior). Delegating to AI... -> PID: {}\x1b[0m", pid);
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
                                if crate::SENTINEL_UI_ACTIVE.load(Ordering::SeqCst) {
                                    ActiveDefense::create_snapshot();
                                }
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
                                let sig = Signal { source: "KernelBridge", pid, reason, file_path: target_file.clone(), metadata: Some(proc_path) };
                                MitigationExecutor::execute(PolicyGate::decide(&sig, ActionPlan::Contain), &sig);
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
                    }

                    if kill_it {
                        s_println!("\x1b[31m[KILL] Neutralized Threat: {} (Label: {})\x1b[0m", process_name, threat_label);
                        let sig = Signal { source: "KernelBridge", pid, reason, file_path: target_file.clone(), metadata: Some(threat_label.to_string()) };
                        let decided = PolicyGate::decide(&sig, ActionPlan::StorylineKill);
                        MitigationExecutor::execute(decided.clone(), &sig);
                        if matches!(decided, ActionPlan::Kill | ActionPlan::StorylineKill) {
                            killed_pids.insert(pid);
                        }
                        reporter::log_alert(pid, &process_name, reason, &target_file);
                    }
                } else if let Err(e) = result {
                    let err_code = e.code().0 & 0xFFFF;
                    println!("\x1b[31m[!] KERNEL PORT ERROR (Code: {:X}). Disconnected. Initiating Auto-Reconnect...\x1b[0m", err_code);
                    crate::KERNEL_CONNECTED.store(false, Ordering::SeqCst);
                    let _ = windows::Win32::Foundation::CloseHandle(port_handle);
                    thread::sleep(Duration::from_secs(2));
                    break; 
                }
            } // End inner loop
        } // End unsafe block
        } // End outer loop
    }); // End thread::spawn
} // End fn
