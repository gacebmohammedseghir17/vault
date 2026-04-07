#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use uuid::Uuid;

use crate::config::AgentConfig;
use crate::ipc::sign;
use aes_gcm::{Aes256Gcm, Nonce};
use aes_gcm::aead::Aead;
use aes_gcm::KeyInit;
use rand::{thread_rng, RngCore};
use sha2::{Digest, Sha256};

/// Trait for process control operations to enable testing with mocks
#[async_trait::async_trait]
pub trait ProcessController: Send + Sync {
    /// Suspend a process by PID
    async fn suspend_process(&self, pid: u32) -> Result<()>;

    /// Resume a process by PID
    async fn resume_process(&self, pid: u32) -> Result<()>;

    /// Terminate a process by PID
    async fn terminate_process(&self, pid: u32) -> Result<()>;

    /// Check if the current user has sufficient privileges to control the process
    async fn has_process_privileges(&self, pid: u32) -> Result<bool>;

    /// Get the owner UID of a process
    async fn get_process_owner(&self, pid: u32) -> Result<u32>;

    /// Check if a process is currently running
    async fn is_process_running(&self, pid: u32) -> bool;
}

/// Real implementation of ProcessController using platform APIs
pub struct RealProcessController;

impl RealProcessController {
    pub fn new() -> Self {
        Self
    }
}

impl Default for RealProcessController {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl ProcessController for RealProcessController {
    async fn suspend_process(&self, pid: u32) -> Result<()> {
        #[cfg(windows)]
        {
            use std::process::Command;

            // First check if we have privileges to access the process
            if !self.has_process_privileges(pid).await? {
                anyhow::bail!("InsufficientPrivileges: Cannot access process {} - insufficient privileges on Windows. Process may be running as a higher privilege level or be a system process.", pid);
            }

            let output = Command::new("powershell")
                .args([
                    "-Command",
                    &format!("Suspend-Process -Id {pid} -ErrorAction Stop"),
                ])
                .output()
                .context("Failed to execute suspend command")?;

            if !output.status.success() {
                let error = String::from_utf8_lossy(&output.stderr);
                if error.contains("Access is denied")
                    || error.contains("UnauthorizedAccessException")
                {
                    anyhow::bail!("InsufficientPrivileges: Access denied when suspending process {pid} on Windows - {error}");
                }
                anyhow::bail!("Failed to suspend process {pid}: {error}");
            }
        }

        #[cfg(unix)]
        {
            use nix::errno::Errno;
            use nix::sys::signal::{kill, Signal};
            use nix::unistd::Pid;

            let pid = Pid::from_raw(pid as i32);
            match kill(pid, Signal::SIGSTOP) {
                Ok(()) => {}
                Err(nix::Error::Sys(Errno::EPERM)) => {
                    anyhow::bail!("InsufficientPrivileges: Permission denied when suspending process {pid} on Unix - insufficient privileges to send SIGSTOP signal");
                }
                Err(nix::Error::Sys(Errno::ESRCH)) => {
                    anyhow::bail!("Process {pid} not found or already terminated");
                }
                Err(e) => {
                    anyhow::bail!("Failed to suspend process {pid}: {e}");
                }
            }
        }

        info!("Process {pid} suspended");
        Ok(())
    }

    async fn resume_process(&self, pid: u32) -> Result<()> {
        #[cfg(windows)]
        {
            use std::process::Command;

            // First check if we have privileges to access the process
            if !self.has_process_privileges(pid).await? {
                anyhow::bail!("InsufficientPrivileges: Cannot access process {} - insufficient privileges on Windows. Process may be running as a higher privilege level or be a system process.", pid);
            }

            let output = Command::new("powershell")
                .args(["-Command", &format!("Get-Process -Id {pid} | ForEach-Object {{ $_.Threads }} | ForEach-Object {{ [System.Diagnostics.ProcessThread]$_.Resume() }}")])
                .output()
                .context("Failed to execute PowerShell resume command")?;

            if !output.status.success() {
                let error = String::from_utf8_lossy(&output.stderr);
                if error.contains("Access is denied")
                    || error.contains("UnauthorizedAccessException")
                {
                    anyhow::bail!("InsufficientPrivileges: Access denied when resuming process {pid} on Windows - {error}");
                }
                anyhow::bail!("Failed to resume process {pid}: {error}");
            }
        }

        #[cfg(unix)]
        {
            use nix::errno::Errno;
            use nix::sys::signal::{kill, Signal};
            use nix::unistd::Pid;

            let pid = Pid::from_raw(pid as i32);
            match kill(pid, Signal::SIGCONT) {
                Ok(()) => {}
                Err(nix::Error::Sys(Errno::EPERM)) => {
                    anyhow::bail!("InsufficientPrivileges: Permission denied when resuming process {pid} on Unix - insufficient privileges to send SIGCONT signal");
                }
                Err(nix::Error::Sys(Errno::ESRCH)) => {
                    anyhow::bail!("Process {pid} not found or already terminated");
                }
                Err(e) => {
                    anyhow::bail!("Failed to resume process {pid}: {e}");
                }
            }
        }

        info!("Process {pid} resumed");
        Ok(())
    }

    async fn terminate_process(&self, pid: u32) -> Result<()> {
        #[cfg(windows)]
        {
            use std::process::Command;

            // First check if we have privileges to access the process
            if !self.has_process_privileges(pid).await? {
                anyhow::bail!("InsufficientPrivileges: Cannot access process {} - insufficient privileges on Windows. Process may be running as a higher privilege level or be a system process.", pid);
            }

            let output = Command::new("taskkill")
                .args(["/F", "/PID", &pid.to_string()])
                .output()
                .context("Failed to execute taskkill command")?;

            if !output.status.success() {
                let error = String::from_utf8_lossy(&output.stderr);
                if error.contains("Access is denied")
                    || error.contains("The process could not be terminated")
                {
                    anyhow::bail!("InsufficientPrivileges: Access denied when terminating process {pid} on Windows - {error}");
                }
                anyhow::bail!("Failed to terminate process {pid}: {error}");
            }
        }

        #[cfg(unix)]
        {
            use nix::errno::Errno;
            use nix::sys::signal::{kill, Signal};
            use nix::unistd::Pid;

            let pid = Pid::from_raw(pid as i32);
            match kill(pid, Signal::SIGTERM) {
                Ok(()) => {}
                Err(nix::Error::Sys(Errno::EPERM)) => {
                    anyhow::bail!("InsufficientPrivileges: Permission denied when terminating process {pid} on Unix - insufficient privileges to send SIGTERM signal");
                }
                Err(nix::Error::Sys(Errno::ESRCH)) => {
                    anyhow::bail!("Process {pid} not found or already terminated");
                }
                Err(e) => {
                    anyhow::bail!("Failed to terminate process {pid}: {e}");
                }
            }
        }

        warn!("Process {pid} terminated");
        Ok(())
    }

    async fn has_process_privileges(&self, pid: u32) -> Result<bool> {
        #[cfg(windows)]
        {
            use std::process::Command;

            // Check if we can query the process using tasklist
            let output = Command::new("tasklist")
                .args(["/FI", &format!("PID eq {pid}")])
                .output();

            match output {
                Ok(output) => Ok(output.status.success() && !output.stdout.is_empty()),
                Err(_) => Ok(false),
            }
        }

        #[cfg(unix)]
        {
            // On Unix, check if we can send signal 0 (null signal) to test permissions
            use nix::sys::signal::{kill, Signal};
            use nix::unistd::Pid;

            let pid = Pid::from_raw(pid as i32);
            match kill(pid, None) {
                Ok(_) => Ok(true),
                Err(_) => Ok(false),
            }
        }

        #[cfg(not(any(windows, unix)))]
        {
            // Default to false for unsupported platforms
            Ok(false)
        }
    }

    async fn get_process_owner(&self, _pid: u32) -> Result<u32> {
        #[cfg(windows)]
        {
            // On Windows, this is more complex and would require additional APIs
            // For now, return a placeholder
            Ok(1000)
        }

        #[cfg(unix)]
        {
            use std::fs;
            let stat_path = format!("/proc/{}/stat", _pid);
            let stat_content =
                fs::read_to_string(stat_path).context("Failed to read process stat")?;

            // Parse the stat file to get the UID (this is a simplified approach)
            // In a real implementation, you'd want to use proper process APIs
            Ok(1000) // Placeholder
        }

        #[cfg(not(any(windows, unix)))]
        {
            Ok(1000) // Placeholder for unsupported platforms
        }
    }

    async fn is_process_running(&self, pid: u32) -> bool {
        #[cfg(windows)]
        {
            use std::process::Command;

            Command::new("tasklist")
                .args(["/FI", &format!("PID eq {pid}")])
                .output()
                .map(|output| output.status.success() && !output.stdout.is_empty())
                .unwrap_or(false)
        }

        #[cfg(unix)]
        {
            use nix::sys::signal::{self, Signal};
            use nix::unistd::Pid;

            let pid = Pid::from_raw(pid as i32);
            signal::kill(pid, None).is_ok()
        }

        #[cfg(not(any(windows, unix)))]
        {
            false
        }
    }
}

/// Mock implementation of ProcessController for testing
pub struct MockProcessController {
    pub suspended_processes: Arc<std::sync::Mutex<std::collections::HashSet<u32>>>,
    pub terminated_processes: Arc<std::sync::Mutex<std::collections::HashSet<u32>>>,
    pub should_fail: Arc<std::sync::Mutex<bool>>,
}

impl MockProcessController {
    pub fn new() -> Self {
        Self {
            suspended_processes: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
            terminated_processes: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
            should_fail: Arc::new(std::sync::Mutex::new(false)),
        }
    }
}

impl MockProcessController {
    pub fn set_should_fail(&self, should_fail: bool) {
        *self.should_fail.lock().unwrap() = should_fail;
    }

    pub fn is_suspended(&self, pid: u32) -> bool {
        self.suspended_processes.lock().unwrap().contains(&pid)
    }

    pub fn is_terminated(&self, pid: u32) -> bool {
        self.terminated_processes.lock().unwrap().contains(&pid)
    }
}

impl Default for MockProcessController {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl ProcessController for MockProcessController {
    async fn suspend_process(&self, pid: u32) -> Result<()> {
        if *self.should_fail.lock().unwrap() {
            return Err(anyhow::anyhow!("Mock failure"));
        }

        self.suspended_processes.lock().unwrap().insert(pid);
        info!("Mock: Process {pid} suspended");
        Ok(())
    }

    async fn resume_process(&self, pid: u32) -> Result<()> {
        if *self.should_fail.lock().unwrap() {
            return Err(anyhow::anyhow!("Mock failure"));
        }

        self.suspended_processes.lock().unwrap().remove(&pid);
        info!("Mock: Process {pid} resumed");
        Ok(())
    }

    async fn terminate_process(&self, pid: u32) -> Result<()> {
        if *self.should_fail.lock().unwrap() {
            return Err(anyhow::anyhow!("Mock failure"));
        }

        self.terminated_processes.lock().unwrap().insert(pid);
        warn!("Mock: Process {pid} terminated");
        Ok(())
    }

    async fn has_process_privileges(&self, _pid: u32) -> Result<bool> {
        if *self.should_fail.lock().unwrap() {
            return Ok(false);
        }
        Ok(true)
    }

    async fn get_process_owner(&self, _pid: u32) -> Result<u32> {
        if *self.should_fail.lock().unwrap() {
            return Err(anyhow::anyhow!("Mock failure"));
        }
        Ok(1000)
    }

    async fn is_process_running(&self, pid: u32) -> bool {
        if *self.should_fail.lock().unwrap() {
            return false;
        }
        // For mock, consider a process running if it's not terminated
        !self.terminated_processes.lock().unwrap().contains(&pid)
    }
}

/// Mitigation action types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MitigationAction {
    SuspendProcess,
    ResumeProcess,
    TerminateProcess,
    QuarantineFiles,
    RestoreFiles,
}

/// Mitigation request from detector
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitigationRequest {
    pub id: String,
    pub action: MitigationAction,
    pub pid: Option<u32>,
    pub files: Vec<PathBuf>,
    pub quarantined_paths: Vec<PathBuf>, // For restore operations
    pub reason: String,
    pub score: u32,
    pub dry_run: Option<bool>,      // Override global dry_run setting
    pub require_confirmation: bool, // If true, log pending action instead of executing
    pub timestamp: u64,
}

/// Mitigation result status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MitigationStatus {
    Success,
    Denied,
    InsufficientPrivileges,
    Failed,
    DryRun,
    PendingConfirmation,
}

/// Mitigation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitigationResult {
    pub request_id: String,
    pub status: MitigationStatus,
    pub message: String,
    pub quarantined_paths: Vec<PathBuf>,
    pub restored_paths: Vec<PathBuf>,
    pub timestamp: u64,
    pub audit_signature: Option<String>,
}

/// Audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub request_id: String,
    pub action: MitigationAction,
    pub target: String, // PID or file path
    pub pid: Option<u32>,
    pub uid: Option<u32>,
    pub timestamp: u64,
    pub reason: String,
    pub score: u32,
    pub status: MitigationStatus,
    pub signature: String,
}

/// Mitigation engine
pub struct MitigationEngine<T: ProcessController> {
    process_controller: T,
    _audit_log: flexi_logger::Logger,
}

impl<T: ProcessController> MitigationEngine<T> {
    pub fn new(process_controller: T) -> Result<Self> {
        let audit_log =
            flexi_logger::Logger::try_with_str("info").context("Failed to create audit logger")?;

        Ok(Self {
            process_controller,
            _audit_log: audit_log,
        })
    }
}

/// Start mitigation engine with real process controller
pub fn start_mitigation_engine(
    rx: mpsc::Receiver<MitigationRequest>,
    cfg: Arc<AgentConfig>,
) -> JoinHandle<()> {
    let engine =
        MitigationEngine::new(RealProcessController).expect("Failed to create mitigation engine");

    start_mitigation_engine_with_controller(rx, cfg, engine)
}

/// Start mitigation engine with custom process controller (for testing)
pub fn start_mitigation_engine_with_controller<T: ProcessController + 'static>(
    mut rx: mpsc::Receiver<MitigationRequest>,
    cfg: Arc<AgentConfig>,
    engine: MitigationEngine<T>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        log::info!("Mitigation engine started");

        while let Some(request) = rx.recv().await {
            log::info!(
                "Processing mitigation request {} for action {:?}",
                request.id,
                request.action
            );

            let result = perform_mitigation(request, &cfg, &engine.process_controller).await;

            match result {
                Ok(mitigation_result) => {
                    log::info!(
                        "Mitigation request {} completed with status {:?}",
                        mitigation_result.request_id,
                        mitigation_result.status
                    );

                    // Send result via IPC if available
                    // Note: In a full implementation, this would use the IPC channel
                }
                Err(e) => {
                    log::error!("Mitigation request failed: {e}");
                }
            }
        }

        log::info!("Mitigation engine stopped");
    })
}

/// Perform mitigation with policy validation
pub async fn perform_mitigation<T: ProcessController>(
    req: MitigationRequest,
    cfg: &AgentConfig,
    controller: &T,
) -> Result<MitigationResult> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("Failed to get timestamp")?
        .as_secs();

    let is_dry_run = req.dry_run.unwrap_or(cfg.dry_run);

    // Check if operator confirmation is required
    if req.require_confirmation {
        let result = MitigationResult {
            request_id: req.id.clone(),
            status: MitigationStatus::PendingConfirmation,
            message: format!(
                "Action pending operator confirmation: {} (Score: {}, Reason: {})",
                format_action_description(&req.action, req.pid.as_ref(), &req.files),
                req.score,
                req.reason
            ),
            quarantined_paths: vec![],
            restored_paths: vec![],
            timestamp,
            audit_signature: None,
        };

        log::warn!("PENDING ACTION - Operator confirmation required: {} - Request ID: {} - Score: {} - Reason: {}", 
                  format_action_description(&req.action, req.pid.as_ref(), &req.files),
                  req.id, req.score, req.reason);

        log_audit_entry(&req, &result, cfg).await?;
        return Ok(result);
    }

    // Policy validation
    let validation_result = validate_mitigation_policy(&req, cfg)?;
    if let Some(denial_reason) = validation_result {
        let result = MitigationResult {
            request_id: req.id.clone(),
            status: MitigationStatus::Denied,
            message: denial_reason,
            quarantined_paths: vec![],
            restored_paths: vec![],
            timestamp,
            audit_signature: None,
        };

        log_audit_entry(&req, &result, cfg).await?;
        return Ok(result);
    }

    // Execute mitigation action
    let result = match req.action {
        MitigationAction::SuspendProcess => {
            execute_suspend_process(&req, cfg, controller, is_dry_run).await?
        }
        MitigationAction::ResumeProcess => {
            execute_resume_process(&req, cfg, controller, is_dry_run).await?
        }
        MitigationAction::TerminateProcess => {
            execute_terminate_process(&req, cfg, controller, is_dry_run).await?
        }
        MitigationAction::QuarantineFiles => {
            execute_quarantine_files(&req, cfg, is_dry_run).await?
        }
        MitigationAction::RestoreFiles => execute_restore_files(&req, cfg, is_dry_run).await?,
    };

    // Log audit entry
    log_audit_entry(&req, &result, cfg).await?;

    Ok(result)
}

/// Validate mitigation request against policy
fn validate_mitigation_policy(
    req: &MitigationRequest,
    cfg: &AgentConfig,
) -> Result<Option<String>> {
    // Check score threshold
    if req.score < cfg.mitigation_score_threshold {
        return Ok(Some(format!(
            "Score {score} below threshold {threshold}",
            score = req.score, threshold = cfg.mitigation_score_threshold
        )));
    }

    // Check if auto-mitigation is enabled
    if !cfg.auto_mitigate {
        return Ok(Some(
            "Auto-mitigation disabled, operator confirmation required".to_string(),
        ));
    }

    // Check termination policy
    if req.action == MitigationAction::TerminateProcess && !cfg.allow_terminate {
        return Ok(Some(
            "Process termination not allowed by policy".to_string(),
        ));
    }

    // Check protected PIDs
    if let Some(pid) = req.pid {
        if crate::config::is_pid_protected(cfg, pid) {
            return Ok(Some(format!("PID {pid} is protected by configuration")));
        }
    }

    Ok(None)
}

/// Execute suspend process action
async fn execute_suspend_process<T: ProcessController>(
    req: &MitigationRequest,
    _cfg: &AgentConfig,
    controller: &T,
    is_dry_run: bool,
) -> Result<MitigationResult> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("Failed to get timestamp")?
        .as_secs();

    let pid = req.pid.context("PID required for suspend operation")?;

    if is_dry_run {
        log::info!("DRY RUN: Would suspend process {pid}");
        return Ok(MitigationResult {
            request_id: req.id.clone(),
            status: MitigationStatus::DryRun,
            message: format!("Would suspend process {pid}"),
            quarantined_paths: vec![],
            restored_paths: vec![],
            timestamp,
            audit_signature: None,
        });
    }

    match controller.suspend_process(pid).await {
        Ok(()) => {
            log::info!("Successfully suspended process {pid}");
            Ok(MitigationResult {
                request_id: req.id.clone(),
                status: MitigationStatus::Success,
                message: format!("Process {pid} suspended"),
                quarantined_paths: vec![],
                restored_paths: vec![],
                timestamp,
                audit_signature: None,
            })
        }
        Err(e) => {
            let error_msg = e.to_string();
            let status = if error_msg.contains("InsufficientPrivileges:") {
                log::warn!("Insufficient privileges to suspend process {pid}: {e}");
                MitigationStatus::InsufficientPrivileges
            } else {
                log::error!("Failed to suspend process {pid}: {e}");
                MitigationStatus::Failed
            };

            Ok(MitigationResult {
                request_id: req.id.clone(),
                status,
                message: format!("Failed to suspend process {pid}: {e}"),
                quarantined_paths: vec![],
                restored_paths: vec![],
                timestamp,
                audit_signature: None,
            })
        }
    }
}

/// Execute resume process action
async fn execute_resume_process<T: ProcessController>(
    req: &MitigationRequest,
    _cfg: &AgentConfig,
    controller: &T,
    is_dry_run: bool,
) -> Result<MitigationResult> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("Failed to get timestamp")?
        .as_secs();

    let pid = req.pid.context("PID required for resume operation")?;

    if is_dry_run {
        log::info!("DRY RUN: Would resume process {pid}");
        return Ok(MitigationResult {
            request_id: req.id.clone(),
            status: MitigationStatus::DryRun,
            message: format!("Would resume process {pid}"),
            quarantined_paths: vec![],
            restored_paths: vec![],
            timestamp,
            audit_signature: None,
        });
    }

    match controller.resume_process(pid).await {
        Ok(()) => {
            log::info!("Successfully resumed process {pid}");
            Ok(MitigationResult {
                request_id: req.id.clone(),
                status: MitigationStatus::Success,
                message: format!("Process {pid} resumed"),
                quarantined_paths: vec![],
                restored_paths: vec![],
                timestamp,
                audit_signature: None,
            })
        }
        Err(e) => {
            let error_msg = e.to_string();
            let status = if error_msg.contains("InsufficientPrivileges:") {
                log::warn!("Insufficient privileges to resume process {pid}: {e}");
                MitigationStatus::InsufficientPrivileges
            } else {
                log::error!("Failed to resume process {pid}: {e}");
                MitigationStatus::Failed
            };

            Ok(MitigationResult {
                request_id: req.id.clone(),
                status,
                message: format!("Failed to resume process {pid}: {e}"),
                quarantined_paths: vec![],
                restored_paths: vec![],
                timestamp,
                audit_signature: None,
            })
        }
    }
}

/// Execute terminate process action
async fn execute_terminate_process<T: ProcessController>(
    req: &MitigationRequest,
    _cfg: &AgentConfig,
    controller: &T,
    is_dry_run: bool,
) -> Result<MitigationResult> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("Failed to get timestamp")?
        .as_secs();

    let pid = req.pid.context("PID required for terminate operation")?;

    if is_dry_run {
        log::info!("DRY RUN: Would terminate process {pid}");
        return Ok(MitigationResult {
            request_id: req.id.clone(),
            status: MitigationStatus::DryRun,
            message: format!("Would terminate process {pid}"),
            quarantined_paths: vec![],
            restored_paths: vec![],
            timestamp,
            audit_signature: None,
        });
    }

    match controller.terminate_process(pid).await {
        Ok(()) => {
            log::info!("Successfully terminated process {pid}");
            Ok(MitigationResult {
                request_id: req.id.clone(),
                status: MitigationStatus::Success,
                message: format!("Process {pid} terminated"),
                quarantined_paths: vec![],
                restored_paths: vec![],
                timestamp,
                audit_signature: None,
            })
        }
        Err(e) => {
            let error_msg = e.to_string();
            let status = if error_msg.contains("InsufficientPrivileges:") {
                log::warn!(
                    "Insufficient privileges to terminate process {pid}: {e}"
                );
                MitigationStatus::InsufficientPrivileges
            } else {
                log::error!("Failed to terminate process {pid}: {e}");
                MitigationStatus::Failed
            };

            Ok(MitigationResult {
                request_id: req.id.clone(),
                status,
                message: format!("Failed to terminate process {pid}: {e}"),
                quarantined_paths: vec![],
                restored_paths: vec![],
                timestamp,
                audit_signature: None,
            })
        }
    }
}

/// Execute quarantine files action
async fn execute_quarantine_files(
    req: &MitigationRequest,
    cfg: &AgentConfig,
    is_dry_run: bool,
) -> Result<MitigationResult> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("Failed to get timestamp")?
        .as_secs();

    if is_dry_run {
        log::info!("DRY RUN: Would quarantine {} files", req.files.len());
        return Ok(MitigationResult {
            request_id: req.id.clone(),
            status: MitigationStatus::DryRun,
            message: format!("Would quarantine {} files", req.files.len()),
            quarantined_paths: vec![],
            restored_paths: vec![],
            timestamp,
            audit_signature: None,
        });
    }

    match quarantine_files(&req.files, cfg).await {
        Ok(quarantined_paths) => {
            log::info!("Successfully quarantined {} files", quarantined_paths.len());
            Ok(MitigationResult {
                request_id: req.id.clone(),
                status: MitigationStatus::Success,
                message: format!("Quarantined {} files", quarantined_paths.len()),
                quarantined_paths,
                restored_paths: vec![],
                timestamp,
                audit_signature: None,
            })
        }
        Err(e) => {
            log::error!("Failed to quarantine files: {e}");
            Ok(MitigationResult {
                request_id: req.id.clone(),
                status: MitigationStatus::Failed,
                message: format!("Failed to quarantine files: {e}"),
                quarantined_paths: vec![],
                restored_paths: vec![],
                timestamp,
                audit_signature: None,
            })
        }
    }
}

/// Execute restore files action
async fn execute_restore_files(
    req: &MitigationRequest,
    cfg: &AgentConfig,
    is_dry_run: bool,
) -> Result<MitigationResult> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("Failed to get timestamp")?
        .as_secs();

    if is_dry_run {
        log::info!(
            "DRY RUN: Would restore {} files",
            req.quarantined_paths.len()
        );
        return Ok(MitigationResult {
            request_id: req.id.clone(),
            status: MitigationStatus::DryRun,
            message: format!("Would restore {} files", req.quarantined_paths.len()),
            quarantined_paths: vec![],
            restored_paths: vec![],
            timestamp,
            audit_signature: None,
        });
    }

    match restore_files(&req.quarantined_paths, cfg).await {
        Ok(restored_paths) => {
            log::info!("Successfully restored {} files", restored_paths.len());
            Ok(MitigationResult {
                request_id: req.id.clone(),
                status: MitigationStatus::Success,
                message: format!("Restored {} files", restored_paths.len()),
                quarantined_paths: vec![],
                restored_paths,
                timestamp,
                audit_signature: None,
            })
        }
        Err(e) => {
            log::error!("Failed to restore files: {e}");
            Ok(MitigationResult {
                request_id: req.id.clone(),
                status: MitigationStatus::Failed,
                message: format!("Failed to restore files: {e}"),
                quarantined_paths: vec![],
                restored_paths: vec![],
                timestamp,
                audit_signature: None,
            })
        }
    }
}

/// Quarantine files with atomic moves and manifest creation
pub async fn quarantine_files(files: &[PathBuf], cfg: &AgentConfig) -> Result<Vec<PathBuf>> {
    let quarantine_base = PathBuf::from(&cfg.quarantine_path);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("Failed to get timestamp")?
        .as_secs();

    let incident_id = Uuid::new_v4().to_string();
    let quarantine_dir = quarantine_base.join(format!("{timestamp}-{incident_id}"));

    // Create quarantine directory
    tokio::fs::create_dir_all(&quarantine_dir)
        .await
        .context("Failed to create quarantine directory")?;

    let mut quarantined_paths = Vec::new();
    let mut manifest_entries = HashMap::new();

    for file_path in files {
        if !file_path.exists() {
            log::warn!("File does not exist, skipping: {file_path:?}");
            continue;
        }

        let file_name = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .context("Invalid file name")?;

        let quarantine_file = quarantine_dir.join(file_name);

        // Atomic move or copy+remove with checksum verification
        match atomic_move_file(file_path, &quarantine_file).await {
            Ok(()) => {
                log::info!("File quarantined: {file_path:?} -> {quarantine_file:?}");
                quarantined_paths.push(quarantine_file.clone());
                let key = derive_master_key(cfg);
                if let Err(e) = encrypt_file_in_place(&quarantine_file, &key).await {
                    log::error!("Failed to encrypt quarantined file {quarantine_file:?}: {e}");
                }

                // Write per-file metadata
                let meta = serde_json::json!({
                    "original_path": file_path.to_string_lossy().to_string(),
                    "quarantine_path": quarantine_file.to_string_lossy().to_string(),
                    "timestamp": timestamp,
                    "reason": "automatic_quarantine",
                    "score": 0,
                });
                let meta_path = quarantine_file.with_extension("meta.json");
                if let Err(e) = tokio::fs::write(&meta_path, serde_json::to_string_pretty(&meta).unwrap_or(String::new())).await {
                    log::warn!("Failed to write metadata for quarantined file {:?}: {}", quarantine_file, e);
                }

                // Record in manifest
                manifest_entries.insert(
                    quarantine_file.to_string_lossy().to_string(),
                    file_path.to_string_lossy().to_string(),
                );
            }
            Err(e) => {
                log::error!("Failed to quarantine file {file_path:?}: {e}");
            }
        }
    }

    // Create manifest file
    let manifest_path = quarantine_dir.join(".manifest.json");
    let manifest_content =
        serde_json::to_string_pretty(&manifest_entries).context("Failed to serialize manifest")?;

    tokio::fs::write(&manifest_path, manifest_content)
        .await
        .context("Failed to write manifest file")?;

    log::info!("Created quarantine manifest: {manifest_path:?}");

    Ok(quarantined_paths)
}

/// Restore files from quarantine using manifest
pub async fn restore_files(
    quarantined_paths: &[PathBuf],
    _cfg: &AgentConfig,
) -> Result<Vec<PathBuf>> {
    let mut restored_paths = Vec::new();

    for quarantine_file in quarantined_paths {
        if !quarantine_file.exists() {
            log::warn!("Quarantined file does not exist: {quarantine_file:?}");
            continue;
        }

        // Find manifest file
        let quarantine_dir = quarantine_file
            .parent()
            .context("Invalid quarantine file path")?;
        let manifest_path = quarantine_dir.join(".manifest.json");

        if !manifest_path.exists() {
            log::error!("Manifest file not found: {manifest_path:?}");
            continue;
        }

        // Read manifest
        let manifest_content = tokio::fs::read_to_string(&manifest_path)
            .await
            .context("Failed to read manifest file")?;

        let manifest: HashMap<String, String> =
            serde_json::from_str(&manifest_content).context("Failed to parse manifest file")?;

        // Find original path
        let quarantine_key = quarantine_file.to_string_lossy().to_string();
        if let Some(original_path_str) = manifest.get(&quarantine_key) {
            let original_path = PathBuf::from(original_path_str);

            // Ensure parent directory exists
            if let Some(parent) = original_path.parent() {
                tokio::fs::create_dir_all(parent)
                    .await
                    .context("Failed to create parent directory for restore")?;
            }

            // Atomic move back
            let temp_plain = quarantine_dir.join(".decrypted.tmp");
            let key = derive_master_key(_cfg);
            match decrypt_file_to_path(quarantine_file, &temp_plain, &key).await {
                Ok(()) => {
                    match atomic_move_file(&temp_plain, &original_path).await {
                        Ok(()) => {
                            log::info!(
                                "File restored: {quarantine_file:?} -> {original_path:?}"
                            );
                            restored_paths.push(original_path);
                        }
                        Err(e) => {
                            log::error!("Failed to restore file {quarantine_file:?}: {e}");
                        }
                    }
                    let _ = tokio::fs::remove_file(&temp_plain).await;
                }
                Err(e) => {
                    log::error!("Failed to decrypt quarantined file {quarantine_file:?}: {e}");
                }
            }
        } else {
            log::error!(
                "Original path not found in manifest for {quarantine_file:?}"
            );
        }
    }

    Ok(restored_paths)
}

/// Atomic file move with fallback to copy+remove
async fn atomic_move_file(src: &Path, dst: &Path) -> Result<()> {
    // Try atomic rename first (works if on same filesystem)
    match tokio::fs::rename(src, dst).await {
        Ok(()) => Ok(()),
        Err(_) => {
            // Fallback to copy+remove with checksum verification
            tokio::fs::copy(src, dst)
                .await
                .context("Failed to copy file")?;

            // Verify checksum
            let src_hash = calculate_file_hash(src).await?;
            let dst_hash = calculate_file_hash(dst).await?;

            if src_hash != dst_hash {
                // Remove incomplete copy
                let _ = tokio::fs::remove_file(dst).await;
                anyhow::bail!("File copy verification failed: checksum mismatch");
            }

            // Remove original after successful verification
            tokio::fs::remove_file(src)
                .await
                .context("Failed to remove original file after copy")?;

            Ok(())
        }
    }
}

fn derive_master_key(cfg: &AgentConfig) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(cfg.ipc_key.as_bytes());
    let digest = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest[..32]);
    key
}

async fn encrypt_file_in_place(path: &Path, key: &[u8; 32]) -> Result<()> {
    let data = tokio::fs::read(path).await.context("Failed to read file for encryption")?;
    let mut nonce_bytes = [0u8; 12];
    thread_rng().fill_bytes(&mut nonce_bytes);
    let cipher = Aes256Gcm::new_from_slice(key).context("Invalid key")?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, data.as_ref())
        .map_err(|_| anyhow::anyhow!("Encryption failed"))?;
    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    tokio::fs::write(path, out).await.context("Failed to write encrypted file")?;
    Ok(())
}

async fn decrypt_file_to_path(enc_path: &Path, out_path: &Path, key: &[u8; 32]) -> Result<()> {
    let data = tokio::fs::read(enc_path)
        .await
        .context("Failed to read encrypted file")?;
    if data.len() < 13 {
        anyhow::bail!("Encrypted file too small");
    }
    let nonce_bytes = &data[..12];
    let ciphertext = &data[12..];
    let cipher = Aes256Gcm::new_from_slice(key).context("Invalid key")?;
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow::anyhow!("Decryption failed"))?;
    tokio::fs::write(out_path, plaintext)
        .await
        .context("Failed to write decrypted file")?;
    Ok(())
}

/// Calculate SHA-256 hash of file
async fn calculate_file_hash(path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};

    let content = tokio::fs::read(path)
        .await
        .context("Failed to read file for hashing")?;

    let mut hasher = Sha256::new();
    hasher.update(&content);
    let hash = hasher.finalize();

    Ok(format!("{hash:x}"))
}

/// Format action description for logging
fn format_action_description(
    action: &MitigationAction,
    pid: Option<&u32>,
    files: &[PathBuf],
) -> String {
    match action {
        MitigationAction::SuspendProcess => {
            if let Some(pid) = pid {
                format!("Suspend process {pid}")
            } else {
                "Suspend process (PID unknown)".to_string()
            }
        }
        MitigationAction::ResumeProcess => {
            if let Some(pid) = pid {
                format!("Resume process {pid}")
            } else {
                "Resume process (PID unknown)".to_string()
            }
        }
        MitigationAction::TerminateProcess => {
            if let Some(pid) = pid {
                format!("Terminate process {pid}")
            } else {
                "Terminate process (PID unknown)".to_string()
            }
        }
        MitigationAction::QuarantineFiles => {
            format!("Quarantine {} files", files.len())
        }
        MitigationAction::RestoreFiles => {
            format!("Restore {} files", files.len())
        }
    }
}

/// Log audit entry with HMAC signature
async fn log_audit_entry(
    req: &MitigationRequest,
    result: &MitigationResult,
    cfg: &AgentConfig,
) -> Result<()> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("Failed to get timestamp")?
        .as_secs();

    let target = if let Some(pid) = req.pid {
        format!("PID:{pid}")
    } else if !req.files.is_empty() {
        format!("FILES:{}", req.files.len())
    } else {
        "UNKNOWN".to_string()
    };

    let audit_entry = AuditEntry {
        request_id: req.id.clone(),
        action: req.action.clone(),
        target,
        pid: req.pid,
        uid: None, // Would be populated in real implementation
        timestamp,
        reason: req.reason.clone(),
        score: req.score,
        status: result.status.clone(),
        signature: String::new(), // Will be filled below
    };

    // Create signature
    let audit_json_value = serde_json::to_value(&audit_entry)
        .context("Failed to serialize audit entry to JSON value")?;

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let nonce = format!("{}-{}", req.id, timestamp);
    let signature = sign(
        "audit",
        timestamp,
        &nonce,
        &audit_json_value,
        cfg.ipc_key.as_bytes(),
    )
    .context("Failed to sign audit entry")?;

    let _audit_json =
        serde_json::to_string(&audit_entry).context("Failed to serialize audit entry")?;

    let mut signed_entry = audit_entry;
    signed_entry.signature = signature;

    // Write to audit log
    let audit_log_path = Path::new(&cfg.audit_log_path);
    let audit_line = format!(
        "{}\n",
        serde_json::to_string(&signed_entry).context("Failed to serialize signed audit entry")?
    );

    // Ensure logs directory exists
    if let Some(parent) = audit_log_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .context("Failed to create logs directory")?;
    }

    // Append to audit log
    tokio::fs::write(&audit_log_path, audit_line)
        .await
        .context("Failed to write audit log entry")?;

    log::info!("Audit entry logged for request {}", req.id);

    Ok(())
}

/// Legacy compatibility functions
pub async fn suspend_process(pid: u32) -> Result<()> {
    let controller = RealProcessController;
    controller.suspend_process(pid).await
}

pub async fn resume_process(pid: u32) -> Result<()> {
    let controller = RealProcessController;
    controller.resume_process(pid).await
}

pub async fn terminate_process(pid: u32) -> Result<()> {
    let controller = RealProcessController;
    controller.terminate_process(pid).await
}

/// Legacy init function
pub fn init() {
    log::info!("Mitigations module initialized");
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_quarantine_move_and_restore() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let test_file = temp_dir.path().join("test.txt");
        let test_content = "test content for quarantine";

        // Create test file
        tokio::fs::write(&test_file, test_content)
            .await
            .expect("Failed to write test file");

        let quarantine_dir = temp_dir.path().join("quarantine");
        let cfg = AgentConfig {
            quarantine_path: quarantine_dir.to_string_lossy().to_string(),
            ..Default::default()
        };

        // Test quarantine
        let files = vec![test_file.clone()];
        let quarantined_paths = quarantine_files(&files, &cfg)
            .await
            .expect("Quarantine should succeed");

        // Original file should be moved
        assert!(!test_file.exists());
        assert_eq!(quarantined_paths.len(), 1);

        // Quarantined file should exist
        let quarantined_file = &quarantined_paths[0];
        assert!(quarantined_file.exists());

        // Content should be preserved
        let quarantined_content = tokio::fs::read_to_string(quarantined_file)
            .await
            .expect("Failed to read quarantined file");
        assert_eq!(quarantined_content, test_content);

        // Test restore
        let restored_paths = restore_files(&quarantined_paths, &cfg)
            .await
            .expect("Restore should succeed");

        assert_eq!(restored_paths.len(), 1);
        assert!(test_file.exists());

        // Content should be preserved after restore
        let restored_content = tokio::fs::read_to_string(&test_file)
            .await
            .expect("Failed to read restored file");
        assert_eq!(restored_content, test_content);
    }

    #[tokio::test]
    async fn test_policy_respects_allow_terminate_flag() {
        let cfg_allow = AgentConfig {
            allow_terminate: true,
            auto_mitigate: true,
            mitigation_score_threshold: 50,
            ..Default::default()
        };

        let cfg_deny = AgentConfig {
            allow_terminate: false,
            auto_mitigate: true,
            mitigation_score_threshold: 50,
            ..Default::default()
        };

        let request = MitigationRequest {
            id: "test-123".to_string(),
            action: MitigationAction::TerminateProcess,
            pid: Some(12345),
            files: vec![],
            quarantined_paths: vec![],
            reason: "Test termination".to_string(),
            score: 80,
            dry_run: None,
            require_confirmation: false,
            timestamp: 1234567890,
        };

        // Should be allowed
        let validation_allow =
            validate_mitigation_policy(&request, &cfg_allow).expect("Validation should succeed");
        assert!(validation_allow.is_none());

        // Should be denied
        let validation_deny =
            validate_mitigation_policy(&request, &cfg_deny).expect("Validation should succeed");
        assert!(validation_deny.is_some());
        assert!(validation_deny.unwrap().contains("not allowed by policy"));
    }

    #[tokio::test]
    async fn test_suspend_resume_stub_on_supported_platform() {
        let mock_controller = MockProcessController::new();
        let test_pid = 12345;

        // Test suspend
        mock_controller
            .suspend_process(test_pid)
            .await
            .expect("Mock suspend should succeed");

        {
            let suspended = mock_controller.suspended_processes.lock().unwrap();
            assert!(suspended.contains(&test_pid));
        }

        // Test resume
        mock_controller
            .resume_process(test_pid)
            .await
            .expect("Mock resume should succeed");

        {
            let suspended = mock_controller.suspended_processes.lock().unwrap();
            assert!(!suspended.contains(&test_pid));
        }
    }

    #[tokio::test]
    async fn test_mitigation_engine_processing() {
        let (tx, rx) = mpsc::channel(10);
        let cfg = Arc::new(AgentConfig {
            auto_mitigate: true,
            allow_terminate: false,
            mitigation_score_threshold: 50,
            dry_run: true, // Use dry run for testing
            ..Default::default()
        });

        let mock_controller = MockProcessController::new();
        let engine = MitigationEngine::new(mock_controller).expect("Failed to create engine");

        let handle = start_mitigation_engine_with_controller(rx, cfg, engine);

        // Send test request
        let request = MitigationRequest {
            id: "test-456".to_string(),
            action: MitigationAction::SuspendProcess,
            pid: Some(12345),
            files: vec![],
            quarantined_paths: vec![],
            reason: "Test suspension".to_string(),
            score: 80,
            dry_run: None,
            require_confirmation: false,
            timestamp: 1234567890,
        };

        tx.send(request).await.expect("Failed to send request");
        drop(tx); // Close channel to stop engine

        // Wait for engine to finish
        handle.await.expect("Engine task should complete");
    }

    #[tokio::test]
    async fn test_quarantine_fallback_copy_checksum() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let test_file = temp_dir.path().join("test_fallback.txt");
        let test_content = "test content for fallback quarantine";

        // Create test file
        tokio::fs::write(&test_file, test_content)
            .await
            .expect("Failed to write test file");

        // Create quarantine directory on a different temp location to potentially
        // trigger cross-filesystem move that would fail rename and use copy fallback
        let quarantine_temp = TempDir::new().expect("Failed to create quarantine temp dir");
        let quarantine_dir = quarantine_temp.path().join("quarantine_fallback");

        let cfg = AgentConfig {
            quarantine_path: quarantine_dir.to_string_lossy().to_string(),
            ..Default::default()
        };

        // Test quarantine - this should work even if rename fails and fallback is used
        let files = vec![test_file.clone()];
        let quarantined_paths = quarantine_files(&files, &cfg)
            .await
            .expect("Quarantine should succeed even with fallback");

        // Original file should be moved (regardless of method used)
        assert!(!test_file.exists(), "Original file should be removed");
        assert_eq!(
            quarantined_paths.len(),
            1,
            "Should have one quarantined file"
        );

        // Quarantined file should exist
        let quarantined_file = &quarantined_paths[0];
        assert!(quarantined_file.exists(), "Quarantined file should exist");

        // Content should be preserved (this verifies checksum worked)
        let quarantined_content = tokio::fs::read_to_string(quarantined_file)
            .await
            .expect("Failed to read quarantined file");
        assert_eq!(
            quarantined_content, test_content,
            "Content should be preserved"
        );

        // Verify checksum by calculating it manually
        let expected_hash = calculate_file_hash(quarantined_file)
            .await
            .expect("Failed to calculate hash");

        // Create a temporary copy to verify the hash matches
        let temp_copy = temp_dir.path().join("temp_copy.txt");
        tokio::fs::write(&temp_copy, test_content)
            .await
            .expect("Failed to write temp copy");

        let copy_hash = calculate_file_hash(&temp_copy)
            .await
            .expect("Failed to calculate copy hash");

        assert_eq!(expected_hash, copy_hash, "Checksums should match");

        // Test restore to ensure the fallback path works both ways
        let restored_paths = restore_files(&quarantined_paths, &cfg)
            .await
            .expect("Restore should succeed");

        assert_eq!(restored_paths.len(), 1, "Should restore one file");
        assert!(test_file.exists(), "Original file should be restored");

        // Content should be preserved after restore
        let restored_content = tokio::fs::read_to_string(&test_file)
            .await
            .expect("Failed to read restored file");
        assert_eq!(
            restored_content, test_content,
            "Restored content should match original"
        );
    }
}
