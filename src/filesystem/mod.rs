//! File System Module
//!
//! This module provides file system monitoring and related utilities
//! for the RANSolution agent.

pub mod monitor;

pub mod optimized_scanner;

pub use monitor::{
    create_filesystem_monitor, FileEventType, FileSystemEvent, FileSystemMonitor, MonitoringStats,
};
pub use optimized_scanner::{OptimizedFileScanner, OptimizedScanStats, ScanResult};
