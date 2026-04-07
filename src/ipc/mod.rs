pub mod protocol;
pub mod server;
pub mod state;
pub mod tls;
pub mod transport;

pub use protocol::{RequestMessage, ResponseMessage, sign, verify, canonicalize};
pub use server::{start_ipc_server, invoke_command_for_tests};
pub use state::{
    get_last_scan_time, get_quarantined_files, get_threats_detected, get_uptime_seconds,
    increment_quarantined_files, increment_threats_detected, set_last_scan_time, set_server_start,
    ScanJobStatus, JOB_TASKS, JOBS,
};

use anyhow::Result;
use log::info;

/// Send a signed detection alert via IPC
pub async fn send_signed_alert(alert: &crate::detector::DetectionAlert) -> Result<()> {
    // For now, we'll log the alert as a placeholder
    // In a real implementation, this would connect to an external monitoring system
    info!(
        "Sending signed alert: rule_id={}, score={}, evidence={:?}",
        alert.rule_id, alert.score, alert.evidence
    );

    Ok(())
}

/// Initialize the IPC module
pub fn init() {
    info!("IPC module initialized");
}
