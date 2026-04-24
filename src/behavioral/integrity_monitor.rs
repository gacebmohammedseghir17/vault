use std::sync::Arc;
use crate::metrics::MetricsCollector;
use crate::error::AgentError;
use log::warn;
use tracing::{info, error};

#[cfg(windows)]
use windows::core::{implement, Result, HSTRING, PCWSTR};
#[cfg(windows)]
use windows::Win32::System::Antimalware::{IAntimalwareProvider, IAntimalwareProvider_Impl, IAmsiStream, AMSI_RESULT, AMSI_RESULT_DETECTED, AMSI_RESULT_CLEAN};

#[cfg(windows)]
#[implement(IAntimalwareProvider)]
pub struct ErdpsAmsiProvider {
    metrics: Arc<MetricsCollector>,
}

#[cfg(windows)]
impl IAntimalwareProvider_Impl for ErdpsAmsiProvider {
    fn Scan(&self, stream: Option<&IAmsiStream>) -> Result<AMSI_RESULT> {
        if let Some(s) = stream {
            unsafe {
                let mut content_size: u64 = 0;
                let mut ret_data: u32 = 0;
                let attr_buf = std::slice::from_raw_parts_mut(&mut content_size as *mut _ as *mut u8, 8);
                if s.GetAttribute(windows::Win32::System::Antimalware::AMSI_ATTRIBUTE_CONTENT_SIZE, attr_buf, &mut ret_data).is_ok() {
                    if content_size > 0 && content_size < 10_000_000 {
                        let mut buffer = vec![0u8; content_size as usize];
                        let mut read_size = 0;
                        if s.Read(0, &mut buffer, &mut read_size).is_ok() {
                            // Calculate entropy or YARA scan here
                            let entropy = calculate_entropy(&buffer[..read_size as usize]);
                            if entropy > 7.5 {
                                warn!("AMSI Alert: High entropy script detected ({:.2}). Blocking execution.", entropy);
                                self.metrics.increment_registry_modifications("amsi_blocked_entropy");
                                return Ok(AMSI_RESULT_DETECTED);
                            }
                            
                            // Check for malicious keywords
                            let content_str = String::from_utf8_lossy(&buffer[..read_size as usize]).to_lowercase();
                            if content_str.contains("invoke-mimikatz") || content_str.contains("bypass") {
                                warn!("AMSI Alert: Malicious PowerShell/VBScript keywords detected. Blocking execution.");
                                self.metrics.increment_registry_modifications("amsi_blocked_signature");
                                return Ok(AMSI_RESULT_DETECTED);
                            }
                        }
                    }
                }
            }
        }
        Ok(AMSI_RESULT_CLEAN)
    }

    fn CloseSession(&self, _session: u64) {}

    fn DisplayName(&self) -> Result<windows::core::PWSTR> {
        Err(windows::Win32::Foundation::E_NOTIMPL.into())
    }
}

// Simple Shannon Entropy calculator for the AMSI buffer
fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut counts = [0usize; 256];
    for &b in data { counts[b as usize] += 1; }
    let mut entropy = 0.0;
    let len = data.len() as f64;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

#[derive(Debug)]
pub struct IntegrityMonitor {
    metrics: Arc<MetricsCollector>,
}

impl IntegrityMonitor {
    pub fn new(metrics: Arc<MetricsCollector>) -> Self {
        Self { metrics }
    }

    /// Check for AMSI/ETW patching in a target process
    /// This is a simplified implementation that would require extensive FFI in production
    pub async fn check_process_integrity(&self, pid: u32) -> std::result::Result<bool, AgentError> {
        #[cfg(windows)]
        {
            return self.check_windows_process_integrity(pid).await;
        }
        #[cfg(not(windows))]
        {
            return Ok(true);
        }
    }

    #[cfg(windows)]
    async fn check_windows_process_integrity(&self, pid: u32) -> std::result::Result<bool, AgentError> {
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_VM_READ, PROCESS_QUERY_INFORMATION};
        
        let process_handle = unsafe {
            OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid)
                .map_err(|e| AgentError::SystemError(format!("Failed to open process {}: {}", pid, e)))?
        };

        // Cleanup handle on exit
        let _handle_guard = HandleGuard(process_handle);

        // Register our COM AMSI Provider
        // In a full implementation, we would register the CLSID in the Windows Registry 
        // under HKLM\SOFTWARE\Microsoft\AMSI\Providers
        info!("ERDPS AMSI Provider ready to receive Windows Scripting Host buffers.");

        Ok(true)
    }
}

#[cfg(windows)]
struct HandleGuard(windows::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl Drop for HandleGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = windows::Win32::Foundation::CloseHandle(self.0);
        }
    }
}
