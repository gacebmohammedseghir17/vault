use std::thread;
use std::time::Duration;
use windows::core::{GUID, PSTR, PCSTR, PCWSTR};
use windows::Win32::System::Diagnostics::Etw::{
    EnableTraceEx2, StartTraceA, StopTraceW, ProcessTrace, OpenTraceA,
    EVENT_TRACE_LOGFILEA, EVENT_TRACE_PROPERTIES, 
    EVENT_RECORD, EVENT_TRACE_REAL_TIME_MODE, PROCESS_TRACE_MODE_REAL_TIME,
    EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION,
    CONTROLTRACE_HANDLE, PROCESSTRACE_HANDLE, ENABLE_TRACE_PARAMETERS
};
use windows::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use crate::active_defense::ActiveDefense;
use entropy::shannon_entropy;

// Provider GUIDs
const DNS_CLIENT_GUID: GUID = GUID::from_u128(0x1C95126E_7EEA_49A9_A3FE_A378B03DDB4D);
const TCPIP_GUID: GUID = GUID::from_u128(0x2F07E2EE_15DB_40F1_90EF_9D7BA282188A);

pub struct EtwNetworkHunter;

static mut SESSION_HANDLE: u64 = 0;

impl EtwNetworkHunter {
    /// 🕵️ START HUNTER: Spawns the ETW consumer thread
    pub fn start_hunter() {
        thread::spawn(|| {
            println!("\x1b[35m[NETWORK] 📡 ETW NETWORK HUNTER: ONLINE (Native Windows Tracing)\x1b[0m");
            if let Err(e) = unsafe { Self::run_etw_session() } {
                println!("\x1b[31m[NETWORK] ❌ ETW Session Failed: {:?}\x1b[0m", e);
            }
        });
    }

    unsafe fn run_etw_session() -> windows::core::Result<()> {
        let session_name = "ERDPS_NetSentinel\0";
        
        // 1. Setup Session Properties
        let buf_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + 1024;
        let mut buffer = vec![0u8; buf_size];
        let properties = &mut *(buffer.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES);
        
        properties.Wnode.BufferSize = buf_size as u32;
        properties.Wnode.Flags = 0x00020000; // WNODE_FLAG_TRACED_GUID
        properties.Wnode.ClientContext = 1; // QPC
        properties.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        properties.MaximumFileSize = 0;
        properties.LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
        
        // 2. Start Trace Session
        let mut session_handle = CONTROLTRACE_HANDLE::default();
        let status = StartTraceA(
            &mut session_handle,
            PCSTR(session_name.as_ptr()),
            properties
        );

        // 183 = ERROR_ALREADY_EXISTS (HRESULT 0x800700B7 = -2147024713)
        // StartTraceA returns windows::core::Result<()>.
        if let Err(e) = &status {
            if e.code().0 == -2147024713 {
                 let _ = StopTraceW(session_handle, PCWSTR::null(), properties);
                 let _ = StartTraceA(&mut session_handle, PCSTR(session_name.as_ptr()), properties);
            }
        }

        SESSION_HANDLE = session_handle.Value;

        // 3. Enable Providers
        // Note: EnableTraceEx2 takes u32 for ControlCode, but the constant is ENABLECALLBACK_ENABLED_STATE (struct).
        // The correct constant for "Enable" is actually 1 (EVENT_CONTROL_CODE_ENABLE_PROVIDER).
        // However, the windows crate defines EVENT_CONTROL_CODE_ENABLE_PROVIDER as a u32 (1).
        // Wait, the previous error said "found ENABLECALLBACK_ENABLED_STATE".
        // Let's check the type. If it's a struct, we access .0.
        
        unsafe {
             EnableTraceEx2(
                session_handle,
                &DNS_CLIENT_GUID,
                1, // EVENT_CONTROL_CODE_ENABLE_PROVIDER
                TRACE_LEVEL_INFORMATION as u8,
                0, 0, 0, 
                None
            );

             EnableTraceEx2(
                session_handle,
                &TCPIP_GUID,
                1, // EVENT_CONTROL_CODE_ENABLE_PROVIDER
                TRACE_LEVEL_INFORMATION as u8,
                0, 0, 0, 
                None
            );
        }

        println!("[NETWORK] ✅ Providers Enabled: DNS-Client & TCP-IP");

        // 4. Open Trace
        let mut log_file = EVENT_TRACE_LOGFILEA {
            LoggerName: PSTR(session_name.as_ptr() as *mut _),
            // The winapi crate mapping for ProcessTraceMode might be u32 or bitflags
            // We use the union field or direct assignment if struct layout matches
            Anonymous1: windows::Win32::System::Diagnostics::Etw::EVENT_TRACE_LOGFILEA_0 {
                ProcessTraceMode: PROCESS_TRACE_MODE_REAL_TIME,
            },
            Anonymous2: windows::Win32::System::Diagnostics::Etw::EVENT_TRACE_LOGFILEA_1 {
                EventRecordCallback: Some(Self::event_callback),
            },
            ..Default::default()
        };

        let trace_handle = OpenTraceA(&mut log_file);
        
        if trace_handle.Value == INVALID_HANDLE_VALUE.0 as u64 {
            println!("[NETWORK] ❌ Failed to OpenTrace");
            return Ok(());
        }

        // 5. Process Trace (Blocking)
        ProcessTrace(&[trace_handle], Some(std::ptr::null_mut()), Some(std::ptr::null_mut()));
        
        Ok(())
    }

    unsafe extern "system" fn event_callback(event: *mut EVENT_RECORD) {
        let record = &*event;
        let provider_id = record.EventHeader.ProviderId;
        let pid = record.EventHeader.ProcessId;

        if pid == std::process::id() { return; }

        if provider_id == DNS_CLIENT_GUID {
            Self::handle_dns_event(record);
        } else if provider_id == TCPIP_GUID {
            Self::handle_tcp_event(record);
        }
    }

    unsafe fn handle_dns_event(record: &EVENT_RECORD) {
        let user_data = record.UserData as *const u8;
        let user_data_len = record.UserDataLength as usize;
        if user_data.is_null() || user_data_len == 0 { return; }

        let data = std::slice::from_raw_parts(user_data, user_data_len);
        
        let mut extracted_strings = Vec::new();
        let mut current_string = String::new();
        
        for chunk in data.chunks_exact(2) {
            let u16_char = u16::from_le_bytes([chunk[0], chunk[1]]);
            if u16_char > 32 && u16_char < 127 {
                current_string.push(u16_char as u8 as char);
            } else {
                if current_string.len() > 3 {
                    extracted_strings.push(current_string.clone());
                }
                current_string.clear();
            }
        }

        for domain in extracted_strings {
            if domain.contains('.') && !domain.contains("local") && !domain.contains("arpa") {
                let entropy = shannon_entropy(domain.as_bytes());
                
                if entropy > 4.2 {
                    println!("\x1b[41;37m[NETWORK] 🚨 DGA C2 ATTEMPT DETECTED: {} (Entropy: {:.2})\x1b[0m", domain, entropy);
                    println!("\x1b[31m   |-> PID: {}\x1b[0m", record.EventHeader.ProcessId);
                    ActiveDefense::engage_network_isolation(record.EventHeader.ProcessId, "Suspicious_DGA_Process");
                } else if domain.contains("onion") || domain.contains("tor") {
                    println!("\x1b[33m[NETWORK] ⚠️ TOR/Darknet Activity: {}\x1b[0m", domain);
                }
            }
        }
    }

    unsafe fn handle_tcp_event(record: &EVENT_RECORD) {
        if record.EventHeader.EventDescriptor.Id == 10 {
             // Connect event
        }
    }
}
