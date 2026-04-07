use std::mem;
use std::ptr;
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use winapi::um::winnt::{HANDLE, GENERIC_READ, GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE};
use winapi::um::fileapi::{CreateFileW, OPEN_EXISTING};
use winapi::um::ioapiset::DeviceIoControl;
use winapi::um::winioctl::{
    FSCTL_QUERY_USN_JOURNAL, FSCTL_READ_USN_JOURNAL
};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::shared::minwindef::{DWORD, LPVOID, WORD, USHORT};
use winapi::shared::ntdef::{LONG, ULONGLONG};
use chrono::{DateTime, Local, TimeZone};

type DWORDLONG = ULONGLONG;

// --- MANUAL STRUCT DEFINITIONS (winapi 0.3.9 compat) ---

#[repr(C)]
#[allow(non_snake_case)]
pub struct USN_JOURNAL_DATA_V0 {
    pub UsnJournalID: DWORDLONG,
    pub FirstUsn: i64,
    pub NextUsn: i64,
    pub LowestValidUsn: i64,
    pub MaxUsn: i64,
    pub MaximumSize: DWORDLONG,
    pub AllocationDelta: DWORDLONG,
}

#[repr(C)]
#[allow(non_snake_case)]
pub struct READ_USN_JOURNAL_DATA_V0 {
    pub StartUsn: i64,
    pub ReasonMask: DWORD,
    pub ReturnOnlyOnClose: DWORD,
    pub Timeout: DWORDLONG,
    pub BytesToWaitFor: DWORDLONG,
    pub UsnJournalID: DWORDLONG,
    pub MinMajorVersion: WORD,
    pub MaxMajorVersion: WORD,
}

#[repr(C)]
#[allow(non_snake_case)]
pub struct USN_RECORD_V2 {
    pub RecordLength: DWORD,
    pub MajorVersion: WORD,
    pub MinorVersion: WORD,
    pub FileReferenceNumber: DWORDLONG,
    pub ParentFileReferenceNumber: DWORDLONG,
    pub Usn: i64,
    pub TimeStamp: i64,
    pub Reason: DWORD,
    pub SourceInfo: DWORD,
    pub SecurityId: DWORD,
    pub FileAttributes: DWORD,
    pub FileNameLength: WORD,
    pub FileNameOffset: WORD,
    pub FileName: [u16; 1], // Variable length
}

// USN Reasons
pub const USN_REASON_DATA_OVERWRITE: DWORD = 0x00000001;
pub const USN_REASON_DATA_EXTEND: DWORD = 0x00000002;
pub const USN_REASON_DATA_TRUNCATION: DWORD = 0x00000004;
pub const USN_REASON_NAMED_DATA_OVERWRITE: DWORD = 0x00000010;
pub const USN_REASON_NAMED_DATA_EXTEND: DWORD = 0x00000020;
pub const USN_REASON_NAMED_DATA_TRUNCATION: DWORD = 0x00000040;
pub const USN_REASON_FILE_CREATE: DWORD = 0x00000100;
pub const USN_REASON_FILE_DELETE: DWORD = 0x00000200;
pub const USN_REASON_EA_CHANGE: DWORD = 0x00000400;
pub const USN_REASON_SECURITY_CHANGE: DWORD = 0x00000800;
pub const USN_REASON_RENAME_OLD_NAME: DWORD = 0x00001000;
pub const USN_REASON_RENAME_NEW_NAME: DWORD = 0x00002000;
pub const USN_REASON_INDEXABLE_CHANGE: DWORD = 0x00004000;
pub const USN_REASON_BASIC_INFO_CHANGE: DWORD = 0x00008000;
pub const USN_REASON_HARD_LINK_CHANGE: DWORD = 0x00010000;
pub const USN_REASON_COMPRESSION_CHANGE: DWORD = 0x00020000;
pub const USN_REASON_ENCRYPTION_CHANGE: DWORD = 0x00040000;
pub const USN_REASON_OBJECT_ID_CHANGE: DWORD = 0x00080000;
pub const USN_REASON_REPARSE_POINT_CHANGE: DWORD = 0x00100000;
pub const USN_REASON_STREAM_CHANGE: DWORD = 0x00200000;
pub const USN_REASON_TRANSACTED_CHANGE: DWORD = 0x00400000;
pub const USN_REASON_CLOSE: DWORD = 0x80000000;

pub struct DfirTriage;

#[derive(Debug)]
pub struct UsnEvent {
    pub timestamp: String,
    pub filename: String,
    pub reason: String,
}

impl DfirTriage {
    /// 🕵️ TIMELINE: Generates a forensic timeline of file activity from the NTFS USN Journal.
    /// lookback_minutes: How far back to search (e.g., 5 minutes).
    pub fn generate_timeline(lookback_minutes: u64) -> Vec<UsnEvent> {
        let mut events = Vec::new();
        
        unsafe {
            // 1. Open Volume Handle (Requires Admin)
            let vol_path: Vec<u16> = "\\\\.\\C:".encode_utf16().chain(Some(0)).collect();
            let h_vol = CreateFileW(
                vol_path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null_mut(),
                OPEN_EXISTING,
                0,
                ptr::null_mut()
            );

            if h_vol == INVALID_HANDLE_VALUE {
                println!("\x1b[31m[DFIR] ❌ Failed to open C: volume (Run as Admin?)\x1b[0m");
                return events;
            }

            // 2. Query USN Journal to get current USN
            let mut journal_data: USN_JOURNAL_DATA_V0 = mem::zeroed();
            let mut bytes_ret: DWORD = 0;

            let success = DeviceIoControl(
                h_vol,
                FSCTL_QUERY_USN_JOURNAL,
                ptr::null_mut(),
                0,
                &mut journal_data as *mut _ as LPVOID,
                mem::size_of::<USN_JOURNAL_DATA_V0>() as DWORD,
                &mut bytes_ret,
                ptr::null_mut()
            );

            if success == 0 {
                println!("\x1b[31m[DFIR] ❌ Failed to query USN Journal\x1b[0m");
                CloseHandle(h_vol);
                return events;
            }

            // 3. Prepare Read Data
            // Heuristic: Start reading from (NextUsn - 10MB) to cover recent events
            let start_usn = if journal_data.NextUsn > 10 * 1024 * 1024 {
                journal_data.NextUsn - (10 * 1024 * 1024)
            } else {
                0
            };

            let mut read_data = READ_USN_JOURNAL_DATA_V0 {
                StartUsn: start_usn, 
                ReasonMask: 0xFFFFFFFF,
                ReturnOnlyOnClose: 0,
                Timeout: 0,
                BytesToWaitFor: 0,
                UsnJournalID: journal_data.UsnJournalID,
                MinMajorVersion: 2,
                MaxMajorVersion: 2,
            };

            // 4. Read Loop
            let mut buffer = vec![0u8; 65536]; // 64KB buffer
            let cutoff_time = Local::now().timestamp() - (lookback_minutes as i64 * 60);

            loop {
                let status = DeviceIoControl(
                    h_vol,
                    FSCTL_READ_USN_JOURNAL,
                    &mut read_data as *mut _ as LPVOID,
                    mem::size_of::<READ_USN_JOURNAL_DATA_V0>() as DWORD,
                    buffer.as_mut_ptr() as LPVOID,
                    buffer.len() as DWORD,
                    &mut bytes_ret,
                    ptr::null_mut()
                );

                if status == 0 || bytes_ret < 8 { // 8 bytes is sizeof(USN) at start of buffer
                    break;
                }

                // First 8 bytes is the next USN to start from
                let next_usn = *(buffer.as_ptr() as *const i64);
                read_data.StartUsn = next_usn;

                // Iterate records in buffer
                let mut offset = 8;
                while offset < bytes_ret as usize {
                    let record = &*(buffer.as_ptr().add(offset) as *const USN_RECORD_V2);
                    
                    // Windows FileTime: 100-nanosecond intervals since Jan 1, 1601
                    let windows_tick = ((record.TimeStamp as u64) / 10000) as i64;
                    let unix_time = windows_tick - 11644473600000; // Adjust for epoch
                    
                    if unix_time >= cutoff_time {
                        // Extract Filename
                        let name_len = record.FileNameLength as usize;
                        let name_offset = record.FileNameOffset as usize;
                        let name_ptr = (record as *const _ as *const u8).add(name_offset) as *const u16;
                        let name_slice = std::slice::from_raw_parts(name_ptr, name_len / 2);
                        let filename = OsString::from_wide(name_slice).to_string_lossy().into_owned();

                        // Decode Reason
                        let mut reasons = Vec::new();
                        if record.Reason & USN_REASON_FILE_CREATE != 0 { reasons.push("CREATE"); }
                        if record.Reason & USN_REASON_FILE_DELETE != 0 { reasons.push("DELETE"); }
                        if record.Reason & USN_REASON_RENAME_NEW_NAME != 0 { reasons.push("RENAME"); }
                        if record.Reason & USN_REASON_DATA_OVERWRITE != 0 { reasons.push("WRITE"); }
                        if record.Reason & USN_REASON_DATA_EXTEND != 0 { reasons.push("EXTEND"); }

                        if !reasons.is_empty() {
                            let time_str = Local.timestamp_opt(unix_time / 1000, 0)
                                .unwrap()
                                .format("%H:%M:%S")
                                .to_string();

                            events.push(UsnEvent {
                                timestamp: time_str,
                                filename,
                                reason: reasons.join("|"),
                            });
                        }
                    }

                    if record.RecordLength == 0 { break; } // Safety
                    offset += record.RecordLength as usize;
                }
            }
            
            CloseHandle(h_vol);
        }

        events
    }
}
