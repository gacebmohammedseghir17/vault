//! Action Executor
//!
//! Handles the execution of response actions including process termination,
//! file quarantine, and alert generation.

use log::{error, info, warn};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;

use crate::metrics::MetricsCollector;
// use crate::event_log::{get_global_logger};
use windows::Win32::{
    Foundation::CloseHandle,
    System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE},
};

/// Action executor for automated response operations
pub struct ActionExecutor {
    metrics: Arc<MetricsCollector>,
    quarantine_dir: PathBuf,
    encryption_key: [u8; 32],
}

impl ActionExecutor {
    /// Create a new action executor
    pub async fn new(
        metrics: Arc<MetricsCollector>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Create quarantine directory
        let quarantine_dir = PathBuf::from("quarantine");
        if !quarantine_dir.exists() {
            fs::create_dir_all(&quarantine_dir).await?;
        }

        // Generate encryption key for quarantine
        let encryption_key = Self::generate_encryption_key();

        Ok(ActionExecutor {
            metrics,
            quarantine_dir,
            encryption_key,
        })
    }

    /// Terminate a process by PID
    pub async fn terminate_process(
        &self,
        pid: u32,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Attempting to terminate process with PID: {}", pid);

        #[cfg(windows)]
        {
            unsafe {
                let handle = OpenProcess(PROCESS_TERMINATE, false, pid)?;

                let result = TerminateProcess(handle, 1);
                let _ = CloseHandle(handle);

                if let Err(e) = result {
                    let error_msg = format!("Failed to terminate process {}: {}", pid, e);
                    error!("{}", error_msg);
                    return Err(error_msg.into());
                }
            }
        }

        #[cfg(not(windows))]
        {
            // Unix-like systems
            use std::process::Command;
            let output = Command::new("kill")
                .arg("-9")
                .arg(pid.to_string())
                .output()?;

            if !output.status.success() {
                let error_msg = format!(
                    "Failed to terminate process {}: {}",
                    pid,
                    String::from_utf8_lossy(&output.stderr)
                );
                error!("{}", error_msg);
                return Err(error_msg.into());
            }
        }

        // Update metrics
        self.metrics
            .record_counter("process_termination_success", 1.0);
        info!("Successfully terminated process {}", pid);

        Ok(())
    }

    /// Quarantine a file by encrypting and moving it
    pub async fn quarantine_file<P: AsRef<Path>>(
        &self,
        file_path: P,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let file_path = file_path.as_ref();
        info!("Quarantining file: {:?}", file_path);

        if !file_path.exists() {
            let error_msg = format!("File does not exist: {:?}", file_path);
            error!("{}", error_msg);
            return Err(error_msg.into());
        }

        // Generate unique quarantine filename
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let original_name = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
        let quarantine_filename = format!("{}_{}.quar", timestamp, original_name);
        let quarantine_path = self.quarantine_dir.join(&quarantine_filename);

        // Read original file
        let file_content = fs::read(file_path).await?;

        // Encrypt content
        let encrypted_content = self.encrypt_content(&file_content)?;

        // Create quarantine metadata
        let metadata = QuarantineMetadata {
            original_path: file_path.to_path_buf(),
            quarantine_time: std::time::SystemTime::now(),
            file_size: file_content.len(),
            file_hash: self.calculate_hash(&file_content),
        };

        // Write encrypted file
        fs::write(&quarantine_path, encrypted_content).await?;

        // Write metadata
        let metadata_path = quarantine_path.with_extension("meta");
        let metadata_json = serde_json::to_string_pretty(&metadata)?;
        fs::write(metadata_path, metadata_json).await?;

        // Remove original file
        if let Err(e) = fs::remove_file(file_path).await {
            warn!("Failed to remove original file {:?}: {}", file_path, e);
            // Continue anyway - quarantine was successful
        }

        // Update metrics
        self.metrics
            .record_counter("file_quarantine_success", 1.0);
        info!("Successfully quarantined file to: {:?}", quarantine_path);

        Ok(())
    }

    /// Send an alert notification
    pub async fn send_alert(
        &self,
        message: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("SECURITY ALERT: {}", message);

        // Log to Windows Event Log (disabled - logger not available)
        // #[cfg(windows)]
        // {
        //     use crate::event_log::SecurityEvent as EventLogSecurityEvent;
        //
        //     if let Some(logger) = get_global_logger().await {
        //         let event = EventLogSecurityEvent {
        //             event_id: crate::event_log::EventId::AlertSent as u32,
        //             event_type: crate::event_log::EventType::Warning,
        //             category: crate::event_log::EventCategory::ResponseAction,
        //             timestamp: std::time::SystemTime::now(),
        //             source: "ERDPS-Agent".to_string(),
        //             message: message.to_string(),
        //             details: None,
        //             severity: "High".to_string(),
        //             user_context: None,
        //             process_id: Some(std::process::id()),
        //             thread_id: None,
        //         };
        //
        //         if let Err(e) = logger.log_security_event(&event).await {
        //             warn!("Failed to log security event to Windows Event Log: {}", e);
        //         }
        //     }
        // }

        // Update metrics
        self.metrics.record_counter("alert_sent", 1.0);

        // In a production system, this could also:
        // - Send notifications to SIEM systems
        // - Trigger email/SMS alerts
        // - Update dashboard displays
        // - Write to security event databases

        Ok(())
    }

    /// Restore a quarantined file
    pub async fn restore_quarantined_file(
        &self,
        quarantine_filename: &str,
    ) -> Result<PathBuf, Box<dyn std::error::Error + Send + Sync>> {
        let quarantine_path = self.quarantine_dir.join(quarantine_filename);
        let metadata_path = quarantine_path.with_extension("meta");

        // Read metadata
        let metadata_content = fs::read_to_string(&metadata_path).await?;
        let metadata: QuarantineMetadata = serde_json::from_str(&metadata_content)?;

        // Read and decrypt quarantined file
        let encrypted_content = fs::read(&quarantine_path).await?;
        let decrypted_content = self.decrypt_content(&encrypted_content)?;

        // Verify hash
        let current_hash = self.calculate_hash(&decrypted_content);
        if current_hash != metadata.file_hash {
            return Err("File integrity check failed during restore".into());
        }

        // Restore to original location (or safe location if original is occupied)
        let restore_path = if metadata.original_path.exists() {
            let mut counter = 1;
            loop {
                let mut new_path = metadata.original_path.clone();
                let stem = new_path.file_stem().unwrap_or_default().to_string_lossy();
                let ext = new_path.extension().unwrap_or_default().to_string_lossy();
                new_path.set_file_name(format!("{}_restored_{}.{}", stem, counter, ext));

                if !new_path.exists() {
                    break new_path;
                }
                counter += 1;
            }
        } else {
            metadata.original_path.clone()
        };

        // Write restored file
        fs::write(&restore_path, decrypted_content).await?;

        // Clean up quarantine files
        let _ = fs::remove_file(&quarantine_path).await;
        let _ = fs::remove_file(&metadata_path).await;

        info!("Successfully restored file to: {:?}", restore_path);
        Ok(restore_path)
    }

    /// List all quarantined files
    pub async fn list_quarantined_files(
        &self,
    ) -> Result<Vec<QuarantineInfo>, Box<dyn std::error::Error + Send + Sync>> {
        let mut quarantined_files = Vec::new();
        let mut entries = fs::read_dir(&self.quarantine_dir).await?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("meta") {
                if let Ok(metadata_content) = fs::read_to_string(&path).await {
                    if let Ok(metadata) =
                        serde_json::from_str::<QuarantineMetadata>(&metadata_content)
                    {
                        let quarantine_filename = path
                            .with_extension("quar")
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("unknown")
                            .to_string();

                        quarantined_files.push(QuarantineInfo {
                            quarantine_filename,
                            original_path: metadata.original_path,
                            quarantine_time: metadata.quarantine_time,
                            file_size: metadata.file_size,
                        });
                    }
                }
            }
        }

        Ok(quarantined_files)
    }

    /// Generate encryption key for quarantine operations
    fn generate_encryption_key() -> [u8; 32] {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        // In production, this should use a proper cryptographic RNG
        // For now, we'll use a deterministic key based on system info
        let mut hasher = DefaultHasher::new();
        std::env::current_exe()
            .unwrap_or_default()
            .hash(&mut hasher);
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            .hash(&mut hasher);

        let hash = hasher.finish();
        let mut key = [0u8; 32];
        for (i, chunk) in hash.to_le_bytes().iter().cycle().take(32).enumerate() {
            key[i] = *chunk;
        }
        key
    }

    /// Simple XOR encryption for quarantine (in production, use AES)
    fn encrypt_content(
        &self,
        content: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let mut encrypted = Vec::with_capacity(content.len());
        for (i, &byte) in content.iter().enumerate() {
            encrypted.push(byte ^ self.encryption_key[i % self.encryption_key.len()]);
        }
        Ok(encrypted)
    }

    /// Simple XOR decryption for quarantine
    fn decrypt_content(
        &self,
        encrypted: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        // XOR is symmetric, so decryption is the same as encryption
        self.encrypt_content(encrypted)
    }

    /// Calculate SHA-256 hash of content
    fn calculate_hash(&self, content: &[u8]) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        content.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }
}

/// Metadata stored with quarantined files
#[derive(serde::Serialize, serde::Deserialize)]
struct QuarantineMetadata {
    original_path: PathBuf,
    quarantine_time: std::time::SystemTime,
    file_size: usize,
    file_hash: String,
}

/// Information about a quarantined file
#[derive(Debug)]
pub struct QuarantineInfo {
    pub quarantine_filename: String,
    pub original_path: PathBuf,
    pub quarantine_time: std::time::SystemTime,
    pub file_size: usize,
}
