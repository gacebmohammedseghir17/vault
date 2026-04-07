use winapi::um::psapi::{EnumDeviceDrivers, GetDeviceDriverBaseNameA};
use winapi::ctypes::c_void;
use console::style;
use std::ffi::CStr;

pub struct DriverGuard;

impl DriverGuard {
    /// SCAN: Checks all loaded Kernel Drivers against a Blocklist
    pub fn scan_kernel() {
        println!("{}", style("[*] SCANNING KERNEL SPACE (BYOVD Shield)...").cyan());

        let mut drivers = [0 as *mut c_void; 1024];
        let mut needed = 0;

        unsafe {
            if EnumDeviceDrivers(drivers.as_mut_ptr(), std::mem::size_of_val(&drivers) as u32, &mut needed) != 0 {
                let count = needed as usize / std::mem::size_of::<*mut c_void>();
                let mut threat_found = false;

                // KNOWN BAD DRIVERS (The "Kill List")
                let blocklist = [
                    "iqvw64.sys",   // Intel Network Adapter (Vulnerable)
                    "mhyprot2.sys", // Genshin Impact Anti-Cheat (Abused)
                    "RTCore64.sys", // MSI Afterburner (Vulnerable)
                    "gdrv.sys",     // Gigabyte Driver (Vulnerable)
                    "aswArPot.sys", // Avast (Old Vulnerable)
                ];

                for i in 0..count {
                    let mut name_buffer = [0i8; 1024];
                    if GetDeviceDriverBaseNameA(drivers[i], name_buffer.as_mut_ptr(), 1024) != 0 {
                        let name = CStr::from_ptr(name_buffer.as_ptr()).to_string_lossy().into_owned();
                        
                        // Check against blocklist
                        for &bad_driver in blocklist.iter() {
                            if name.eq_ignore_ascii_case(bad_driver) {
                                println!("{}", style(format!("[!] CRITICAL KERNEL THREAT: '{}' is loaded!", name)).red().bold().blink());
                                println!("{}", style("    -> DIAGNOSIS: 'Bring Your Own Vulnerable Driver' Attack Detected.").red());
                                println!("{}", style("    -> ADVICE: This system is compromised at Ring 0.").red());
                                threat_found = true;
                            }
                        }
                    }
                }

                if !threat_found {
                    println!("{}", style("[+] Kernel Integrity Verified. No known EDR-Killers found.").green());
                }
            } else {
                println!("{}", style("[!] Failed to enumerate drivers. Run as Admin.").yellow());
            }
        }
    }
}
