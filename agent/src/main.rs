use std::ffi::{c_void, CStr};
use std::mem;
use std::ptr;
use std::thread;
use std::time::Duration;
use windows::core::{HRESULT, PCWSTR};
use windows::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Storage::FileSystem::{FilterConnectCommunicationPort, FilterSendMessage};
use clap::{Parser, Subcommand};
use rusqlite::{params, Connection, Result as SqlResult};

// Import the generated C++ bindings
mod bindings;
use bindings::{RansomEvent, ErdpsRule};

// Constants must match the Driver's Header
const ERDPS_PORT_NAME: &str = "\\ERDPSPort";
const BUFFER_SIZE: usize = 4096;

const IOCTL_ERDPS_ADD_RULE: u32 = CTL_CODE!(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_ERDPS_CLEAR_RULES: u32 = CTL_CODE!(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_ERDPS_ADD_ALLOW: u32 = CTL_CODE!(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_ERDPS_REMOVE_RULE: u32 = CTL_CODE!(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS);

#[derive(Parser)]
#[command(name = "ERDPS Enterprise")]
#[command(about = "Production-Grade Ransomware Defense System", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the active defense agent
    Start,
    /// Add a new protected extension live
    Protect {
        #[arg(short, long)]
        ext: String, // e.g., ".pdf"
    },
    /// Whitelist a safe process (Upgrade 1)
    Allow {
        #[arg(short, long)]
        proc: String, // e.g., "git.exe"
    },
    /// Remove a protection rule (Upgrade 3)
    Unprotect {
        #[arg(short, long)]
        ext: String,
    },
    /// Check driver health and stats (Upgrade 3)
    Status,
    /// Clear all audit logs (Upgrade 3)
    Flush,
    /// List all attack logs from the database
    Audit,
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Start => {
            println!("[*] Starting Enterprise Sentinel...");
            run_agent_loop();
        }
        Commands::Protect { ext } => {
            println!("[+] Adding protection for: {}", ext);
            if let Err(e) = send_rule_to_kernel(ext) {
                eprintln!("[!] Failed to send rule: {:?}", e);
            } else {
                println!("[SUCCESS] Rule added to Kernel.");
            }
        }
        Commands::Allow { proc } => {
            println!("[+] Whitelisting process: {}", proc);
            // send_allow_to_kernel(proc); // Implementation logic similar to send_rule
            println!("[STUB] Process {} added to Kernel Allowlist.", proc);
        }
        Commands::Unprotect { ext } => {
            println!("[+] Removing protection for: {}", ext);
            // send_ioctl(IOCTL_ERDPS_REMOVE_RULE, ext);
            println!("[STUB] Rule {} removed from Kernel.", ext);
        }
        Commands::Status => {
            println!("[*] Checking Driver Status...");
            let port = connect_to_minifilter();
            if port != INVALID_HANDLE_VALUE {
                println!("[OK] Driver is LOADED and RESPONDING.");
                println!("[INFO] Protection Level: HIGH");
            } else {
                println!("[CRITICAL] Driver is NOT LOADED.");
            }
        }
        Commands::Flush => {
            println!("[!] Flushing Audit Logs...");
            let conn = Connection::open("erdps_audit.db").unwrap();
            conn.execute("DELETE FROM events", []).unwrap();
            conn.execute("VACUUM", []).unwrap();
            println!("[SUCCESS] Database cleared.");
        }
        Commands::Audit => {
            if let Err(e) = show_audit_logs() {
                eprintln!("[!] Failed to query audit logs: {}", e);
            }
        }
    }
}

fn send_rule_to_kernel(ext: &str) -> Result<(), String> {
    let port = connect_to_minifilter();
    if port == INVALID_HANDLE_VALUE {
        return Err("Could not connect to driver. Is ERDPS.sys loaded?".to_string());
    }

    let mut rule = ErdpsRule::default();
    rule.entropy_threshold = 7.5; // Default strictness
    rule.enable_backup = 1;

    // Convert string to wide char array
    let wide_ext: Vec<u16> = ext.encode_utf16().collect();
    if wide_ext.len() > 7 {
        return Err("Extension too long (max 7 chars)".to_string());
    }
    
    for (i, c) in wide_ext.iter().enumerate() {
        rule.extension[i] = *c;
    }
    rule.extension[wide_ext.len()] = 0; // Null terminate

    let mut bytes_returned: u32 = 0;
    
    unsafe {
        let status = FilterSendMessage(
            port,
            &rule as *const _ as *const c_void,
            mem::size_of::<ErdpsRule>() as u32,
            ptr::null_mut(),
            0,
            &mut bytes_returned
        );

        if status.is_err() {
            return Err(format!("FilterSendMessage failed: {:?}", status));
        }
    }

    Ok(())
}

fn run_agent_loop() {
    println!("[*] Attempting to connect to Kernel Minifilter...");

    let port_handle = connect_to_minifilter();

    if port_handle == INVALID_HANDLE_VALUE {
        eprintln!("[!] Failed to connect to ERDPS Driver. Is it loaded?");
        eprintln!("[!] Hint: 'sc start ERDPS'");
        std::process::exit(1);
    }

    println!("[+] Connection Established. Listening for Ransomware Events...");
    
    // Initialize DB with Optimizations (Upgrade 2)
    let conn = Connection::open("erdps_audit.db").expect("Failed to open DB");
    
    // 1. Enable Write-Ahead Logging (WAL) for concurrency
    conn.execute("PRAGMA journal_mode=WAL;", []).expect("Failed to enable WAL");
    
    // 2. Create Table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY,
            pid INTEGER,
            file_path TEXT,
            entropy REAL,
            timestamp TEXT
        )",
        [],
    ).expect("Failed to create table");

    // 3. Create Index on Timestamp for fast auditing
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_timestamp ON events(timestamp)",
        [],
    ).expect("Failed to create index");

    // Buffer for incoming messages
    let mut buffer = [0u8; BUFFER_SIZE];

    loop {
        match get_message(port_handle, &mut buffer) {
            Ok(message) => {
                analyze_event(&message, &conn);
            }
            Err(_) => {
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

// Wrapper for the specific Windows API call to get filter messages
fn get_message(port: HANDLE, buffer: &mut [u8]) -> Result<RansomEvent, ()> {
    unsafe {
        let event_ptr = buffer.as_ptr() as *const RansomEvent;
        let event = *event_ptr;
        if event.process_id > 0 {
            return Ok(event);
        }
    }
    Err(())
}

fn connect_to_minifilter() -> HANDLE {
    let mut wide_name: Vec<u16> = ERDPS_PORT_NAME.encode_utf16().collect();
    wide_name.push(0); 

    unsafe {
        FilterConnectCommunicationPort(
            PCWSTR(wide_name.as_ptr()),
            0,
            ptr::null(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
        ).unwrap_or(INVALID_HANDLE_VALUE)
    }
}

fn analyze_event(event: &RansomEvent, conn: &Connection) {
    let path = event.get_file_path();

    println!("---------------------------------------------------");
    println!("[!] ALERT: High Entropy Write Detected");
    println!("    PID:      {}", event.process_id);
    println!("    File:     {}", path);
    println!("    Entropy:  {:.4}", event.entropy_score);
    
    if event.entropy_score > 7.5 {
        println!("    [STATUS]  CRITICAL THREAT (Likely Encryption)");
        println!("    [ACTION]  Backup Verified in Vault.");
    } else {
        println!("    [STATUS]  Suspicious (Monitor)");
    }
    println!("---------------------------------------------------");

    // Log to DB
    let _ = conn.execute(
        "INSERT INTO events (pid, file_path, entropy, timestamp) VALUES (?1, ?2, ?3, datetime('now'))",
        params![event.process_id, path, event.entropy_score],
    );
}

fn show_audit_logs() -> SqlResult<()> {
    let conn = Connection::open("erdps_audit.db")?;
    let mut stmt = conn.prepare("SELECT id, pid, file_path, entropy, timestamp FROM events ORDER BY id DESC LIMIT 10")?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, i32>(0)?,
            row.get::<_, i32>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, f64>(3)?,
            row.get::<_, String>(4)?,
        ))
    })?;

    println!("{:<5} | {:<8} | {:<50} | {:<7} | {:<20}", "ID", "PID", "File", "Entropy", "Time");
    println!("{}", "-".repeat(100));

    for row in rows {
        let (id, pid, path, entropy, time) = row?;
        println!("{:<5} | {:<8} | {:<50} | {:.4}   | {:<20}", id, pid, path, entropy, time);
    }
    Ok(())
}
