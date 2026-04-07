//! Windows drive discovery using proper Windows APIs
//!
//! This module implements drive enumeration using GetLogicalDriveStrings
//! and GetDriveType to discover fixed drives on Windows systems.

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use tracing::{debug, info};

#[cfg(windows)]
use windows::{
    core::PCWSTR,
    Win32::{
        Foundation::GetLastError,
        Storage::FileSystem::{GetDriveTypeW, GetLogicalDriveStringsW},
    },
};

/// Represents a discovered drive with its properties
#[derive(Debug, Clone)]
pub struct DriveInfo {
    pub path: String,
    pub drive_type: DriveType,
}

/// Drive types as returned by GetDriveType
#[derive(Debug, Clone, PartialEq)]
pub enum DriveType {
    Unknown,
    Fixed,
    Removable,
    Remote,
    CdRom,
    RamDisk,
}

#[cfg(windows)]
impl From<u32> for DriveType {
    fn from(value: u32) -> Self {
        match value {
            0 => DriveType::Unknown,   // DRIVE_UNKNOWN = 0
            1 => DriveType::Unknown,   // DRIVE_NO_ROOT_DIR = 1
            2 => DriveType::Removable, // DRIVE_REMOVABLE = 2
            3 => DriveType::Fixed,     // DRIVE_FIXED = 3
            4 => DriveType::Remote,    // DRIVE_REMOTE = 4
            5 => DriveType::CdRom,     // DRIVE_CDROM = 5
            6 => DriveType::RamDisk,   // DRIVE_RAMDISK = 6
            _ => DriveType::Unknown,
        }
    }
}

/// Discovers all available drives on the system using Windows APIs
#[cfg(windows)]
pub fn discover_drives() -> Vec<DriveInfo> {
    let mut drives = Vec::new();

    // Get the required buffer size first
    let buffer_size = unsafe { GetLogicalDriveStringsW(None) };

    if buffer_size == 0 {
        log::error!(
            "Failed to get logical drive strings buffer size: {:?}",
            unsafe { GetLastError() }
        );
        return Vec::new();
    }

    // Allocate buffer and get the drive strings
    let mut buffer = vec![0u16; buffer_size as usize];
    let result = unsafe { GetLogicalDriveStringsW(Some(&mut buffer)) };

    if result == 0 {
        log::error!("Failed to get logical drive strings: {:?}", unsafe {
            GetLastError()
        });
        return Vec::new();
    }

    // Parse the null-separated drive strings
    let mut start = 0;
    while start < buffer.len() {
        // Find the next null terminator
        let end = buffer[start..]
            .iter()
            .position(|&c| c == 0)
            .map(|pos| start + pos)
            .unwrap_or(buffer.len());

        if start == end {
            break; // Double null terminator indicates end
        }

        // Convert to OsString and then to String
        let drive_string = OsString::from_wide(&buffer[start..end]);
        if let Ok(drive_str) = drive_string.into_string() {
            if !drive_str.is_empty() {
                // Get drive type - use the original buffer slice for the API call
                let mut drive_path: Vec<u16> = buffer[start..end].to_vec();
                drive_path.push(0); // Null terminate
                let drive_type_raw = unsafe { GetDriveTypeW(PCWSTR(drive_path.as_ptr())) };

                let drive_type = DriveType::from(drive_type_raw);

                // Extract just the drive letter (e.g., "C:" from "C:\\")
                let _drive_letter = if drive_str.len() >= 2 {
                    drive_str[..1].to_string()
                } else {
                    drive_str.clone()
                };

                drives.push(DriveInfo {
                    path: drive_str.clone(),
                    drive_type: drive_type.clone(),
                });

                debug!("Discovered drive: {} (type: {:?})", drive_str, drive_type);
            }
        }

        start = end + 1;
    }

    debug!("Total drives discovered: {}", drives.len());
    drives
}

/// Discovers only fixed drives (hard disks) on the system
#[cfg(windows)]
pub fn discover_fixed_drives() -> Vec<String> {
    let all_drives = discover_drives();
    let fixed_drives: Vec<String> = all_drives
        .into_iter()
        .filter(|drive| drive.drive_type == DriveType::Fixed)
        .map(|drive| drive.path)
        .collect();

    info!("Fixed drives discovered: [{}]", fixed_drives.join(", "));
    fixed_drives
}

/// Fallback implementation for non-Windows platforms
#[cfg(not(windows))]
pub fn discover_fixed_drives() -> Vec<String> {
    // On non-Windows platforms, return a reasonable default
    vec!["/".to_string()]
}

/// Logs the current scanning drives in the required format
pub fn log_scanning_drives(drives: &[String]) {
    if drives.is_empty() {
        info!("Scanning: (no fixed drives found)");
    } else {
        info!("Scanning: {}", drives.join(", "));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_drive_type_conversion() {
        assert_eq!(DriveType::from(3), DriveType::Fixed);
        assert_eq!(DriveType::from(2), DriveType::Removable);
        assert_eq!(DriveType::from(999), DriveType::Unknown);
    }

    #[test]
    fn test_discover_fixed_drives() {
        let drives = discover_fixed_drives();
        // Should return at least one drive (or fallback)
        assert!(!drives.is_empty());
    }
}
