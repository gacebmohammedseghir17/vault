use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

static THREATS_DETECTED: Mutex<u64> = Mutex::new(0);
static QUARANTINED_FILES: Mutex<u64> = Mutex::new(0);

// Global state: server start time and last scan timestamp
static SERVER_START: OnceLock<std::time::Instant> = OnceLock::new();
static LAST_SCAN_TIME: Mutex<Option<i64>> = Mutex::new(None);

pub fn get_threats_detected() -> u64 {
    *THREATS_DETECTED.lock().unwrap()
}

pub fn increment_threats_detected(count: u64) {
    let mut guard = THREATS_DETECTED.lock().unwrap();
    *guard += count;
}

pub fn get_quarantined_files() -> u64 {
    *QUARANTINED_FILES.lock().unwrap()
}

pub fn increment_quarantined_files(count: u64) {
    let mut guard = QUARANTINED_FILES.lock().unwrap();
    *guard += count;
}

pub fn set_server_start() {
    let _ = SERVER_START.set(std::time::Instant::now());
}

pub fn get_uptime_seconds() -> u64 {
    if let Some(start) = SERVER_START.get() {
        start.elapsed().as_secs()
    } else {
        0
    }
}

pub fn get_last_scan_time() -> Option<i64> {
    *LAST_SCAN_TIME.lock().unwrap()
}

pub fn set_last_scan_time(time: i64) {
    let mut guard = LAST_SCAN_TIME.lock().unwrap();
    *guard = Some(time);
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScanJobStatus {
    pub job_id: String,
    pub total_paths: usize,
    pub scanned_paths: usize,
    pub matches_found: usize,
    pub started_at: i64,
    pub finished: bool,
}

pub static JOBS: OnceLock<Mutex<HashMap<String, ScanJobStatus>>> = OnceLock::new();
pub static JOB_TASKS: OnceLock<Mutex<HashMap<String, tokio::task::JoinHandle<()>>>> = OnceLock::new();
