use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::sync::mpsc::UnboundedSender;

pub mod etw;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DriverEvent {
    ProcessCreate { pid: u32, image_path: PathBuf, command_line: String },
    ProcessTerminate { pid: u32 },
    FileCreate { pid: u32, path: PathBuf },
    FileWrite { pid: u32, path: PathBuf, size: u64 },
    FileRename { pid: u32, old_path: PathBuf, new_path: PathBuf },
    FileDelete { pid: u32, path: PathBuf },
}

pub trait DriverInterface {
    fn connect(&self) -> anyhow::Result<()>;
    fn disconnect(&self) -> anyhow::Result<()>;
    // Changed from polling to streaming/callback model
    fn start_monitoring(&self, event_sender: UnboundedSender<DriverEvent>) -> anyhow::Result<()>;
}

pub struct KernelDriverStub;

impl KernelDriverStub {
    pub fn new() -> Self { Self }
}

impl Default for KernelDriverStub {
    fn default() -> Self {
        Self::new()
    }
}

impl DriverInterface for KernelDriverStub {
    fn connect(&self) -> anyhow::Result<()> {
        Ok(())
    }
    fn disconnect(&self) -> anyhow::Result<()> {
        Ok(())
    }
    fn start_monitoring(&self, _event_sender: UnboundedSender<DriverEvent>) -> anyhow::Result<()> {
        // Stub implementation does nothing
        Ok(())
    }
}

// Re-export the Real ETW Consumer
pub use etw::EtwConsumer;
