// Auto-generated bindings for Kernel <-> User communication
// Corresponds to driver/include/shared_def.h

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct RansomEvent {
    pub process_id: u32,
    pub thread_id: u32,
    pub event_type: u32,
    pub entropy_score: f64,
    pub timestamp: u64,
    pub file_path: [u16; 512],
}

impl Default for RansomEvent {
    fn default() -> Self {
        Self {
            process_id: 0,
            thread_id: 0,
            event_type: 0,
            entropy_score: 0.0,
            timestamp: 0,
            file_path: [0; 512],
        }
    }
}

impl RansomEvent {
    /// Convert the fixed-size wide char array to a Rust String
    pub fn get_file_path(&self) -> String {
        use std::ffi::OsString;
        use std::os::windows::ffi::OsStringExt;

        // Find null terminator or end of array
        let len = self.file_path.iter().position(|&c| c == 0).unwrap_or(512);
        let os_str = OsString::from_wide(&self.file_path[0..len]);
        os_str.to_string_lossy().into_owned()
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ErdpsRule {
    pub extension: [u16; 8],
    pub entropy_threshold: f64,
    pub enable_backup: u8,
}

impl Default for ErdpsRule {
    fn default() -> Self {
        Self {
            extension: [0; 8],
            entropy_threshold: 0.0,
            enable_backup: 0,
        }
    }
}
