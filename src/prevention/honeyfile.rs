//! Honeyfile Deception Module
//!
//! This module implements active deception by deploying "honeyfiles" (canary files)
//! to sensitive directories. Any interaction with these files (Read/Write/Delete)
//! is considered a high-fidelity indicator of compromise (IoC) and triggers immediate
//! mitigation.
//!
//! Features:
//! - Automated deployment of realistic-looking files (valid headers)
//! - Real-time monitoring using filesystem filter
//! - Immediate alert generation
//! - Zero false-positive design principle
//! - Hidden + System attributes to avoid user confusion

use crate::core::error::{Result, EnhancedAgentError};
use notify::{Event, RecursiveMode, Watcher};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio::fs;
use rand::{Rng, thread_rng};
use log::{info, warn, error};

#[cfg(windows)]
use windows::Win32::Storage::FileSystem::{
    SetFileAttributesW, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_NOT_CONTENT_INDEXED
};
#[cfg(windows)]
use windows::core::HSTRING;

/// Configuration for honeyfiles
#[derive(Debug, Clone)]
pub struct HoneyfileConfig {
    /// Directories to place honeyfiles in
    pub target_directories: Vec<PathBuf>,
    /// Filenames to use (randomly selected)
    pub filenames: Vec<String>,
    /// File extensions to use
    pub extensions: Vec<String>,
}

impl Default for HoneyfileConfig {
    fn default() -> Self {
        Self {
            target_directories: vec![
                // In production, these would be user's Documents, Desktop, etc.
                // For this prototype, we use the current directory and a test dir
                PathBuf::from("."), 
                PathBuf::from("./test_honeyfiles"),
            ],
            filenames: vec![
                "passwords".to_string(),
                "budget_2024".to_string(),
                "salary_list".to_string(),
                "bitcoin_wallet".to_string(),
                "confidential".to_string(),
                "login_creds".to_string(),
                "master_key".to_string(),
                "aa_important".to_string(), // Alphabetical top
            ],
            extensions: vec![
                "txt".to_string(),
                "docx".to_string(),
                "xlsx".to_string(),
                "pdf".to_string(),
                "kdbx".to_string(), // Keepass
            ],
        }
    }
}

/// Manager for honeyfile deception
pub struct HoneyfileManager {
    config: HoneyfileConfig,
    active_honeyfiles: Arc<Mutex<HashSet<PathBuf>>>,
    alert_sender: mpsc::UnboundedSender<String>,
    watcher: Arc<Mutex<Option<Box<dyn Watcher + Send>>>>,
}

impl HoneyfileManager {
    pub fn new(config: HoneyfileConfig, alert_sender: mpsc::UnboundedSender<String>) -> Self {
        Self {
            config,
            active_honeyfiles: Arc::new(Mutex::new(HashSet::new())),
            alert_sender,
            watcher: Arc::new(Mutex::new(None)),
        }
    }

    /// Deploy honeyfiles to target directories
    pub async fn deploy(&self) -> Result<()> {
        let mut deployed_files = Vec::new();
        
        for dir in &self.config.target_directories {
            if !dir.exists() {
                if let Err(e) = fs::create_dir_all(dir).await {
                    warn!("Failed to create honeyfile directory {:?}: {}", dir, e);
                    continue;
                }
            }

            // Create 3 random honeyfiles per directory
            for _ in 0..3 {
                let filename = self.generate_random_filename();
                let path = dir.join(filename);
                
                if let Err(e) = self.create_honeyfile(&path).await {
                    error!("Failed to create honeyfile {:?}: {}", path, e);
                } else {
                    info!("Deployed honeyfile: {:?}", path);
                    deployed_files.push(path.canonicalize().unwrap_or(path));
                }
            }
        }
        
        // Update active honeyfiles
        let mut active = self.active_honeyfiles.lock().unwrap();
        for path in deployed_files {
            active.insert(path);
        }
        
        Ok(())
    }
    
    /// Start monitoring honeyfiles
    pub fn start_monitoring(&self) -> Result<()> {
        let active_files = self.active_honeyfiles.lock().unwrap().clone();
        let tx = self.alert_sender.clone();
        
        // We watch the parent directories of our honeyfiles
        let mut directories_to_watch = HashSet::new();
        for path in &active_files {
            if let Some(parent) = path.parent() {
                directories_to_watch.insert(parent.to_path_buf());
            }
        }

        let event_handler = move |res: notify::Result<Event>| {
            match res {
                Ok(event) => {
                    for path in event.paths {
                        // Canonicalize path to ensure matching works
                        let check_path = path.canonicalize().unwrap_or(path.clone());
                        
                        // Check if touched file is a honeyfile
                        if active_files.contains(&check_path) {
                            let msg = format!("CRITICAL: Honeyfile accessed! Path: {:?}", check_path);
                            warn!("{}", msg);
                            
                            // Send high-priority alert
                            if let Err(e) = tx.send(msg) {
                                error!("Failed to send honeyfile alert: {}", e);
                            }
                            
                            // TODO: In production, trigger immediate process suspension here
                            // This would require getting the PID from the event (if supported) 
                            // or using a kernel driver.
                        }
                    }
                },
                Err(e) => error!("Watch error: {:?}", e),
            }
        };

        let mut watcher = notify::recommended_watcher(event_handler)
            .map_err(|e| EnhancedAgentError::FileSystem(format!("Failed to create watcher: {}", e)))?;

        for dir in directories_to_watch {
             if let Err(e) = watcher.watch(&dir, RecursiveMode::NonRecursive) {
                 warn!("Failed to watch directory {:?}: {}", dir, e);
             } else {
                 info!("Honeyfile monitor watching: {:?}", dir);
             }
        }
        
        // Store watcher to keep it alive
        *self.watcher.lock().unwrap() = Some(Box::new(watcher));
        
        Ok(())
    }

    fn generate_random_filename(&self) -> String {
        let mut rng = thread_rng();
        let name = &self.config.filenames[rng.gen_range(0..self.config.filenames.len())];
        let ext = &self.config.extensions[rng.gen_range(0..self.config.extensions.len())];
        // Add random suffix to avoid collisions
        format!("{}_{:04x}.{}", name, rng.gen::<u16>(), ext)
    }

    async fn create_honeyfile(&self, path: &Path) -> Result<()> {
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        
        // Write realistic magic headers
        let mut content = Vec::new();
        match ext {
            "docx" | "xlsx" => {
                // PK Zip header
                content.extend_from_slice(&[0x50, 0x4B, 0x03, 0x04]);
            },
            "pdf" => {
                // PDF header
                content.extend_from_slice(b"%PDF-1.5\n");
            },
            _ => {}
        }
        
        // Fill remaining with random data
        {
            let mut rng = thread_rng();
            for _ in 0..1024 {
                content.push(rng.gen());
            }
        }
            
        fs::write(path, content).await
            .map_err(|e| EnhancedAgentError::PreventionEngine(e.to_string()))?;
            
        // Hide the file on Windows
        #[cfg(windows)]
        {
            let path_str = path.to_str().unwrap_or_default();
            if !path_str.is_empty() {
                unsafe {
                    let wide_path = HSTRING::from(path_str);
                    let attributes = FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED;
                    if let Err(e) = SetFileAttributesW(&wide_path, attributes) {
                        warn!("Failed to set attributes for honeyfile {:?}: {:?}", path, e);
                    }
                }
            }
        }

        Ok(())
    }
    
    /// Clean up honeyfiles
    pub async fn cleanup(&self) -> Result<()> {
        if self.watcher.lock().unwrap().is_none() {
            return Ok(());
        }

        let mut active = self.active_honeyfiles.lock().unwrap();
        for path in active.iter() {
            if let Err(e) = fs::remove_file(path).await {
                warn!("Failed to remove honeyfile {:?}: {}", path, e);
            }
        }
        active.clear();
        Ok(())
    }
}
