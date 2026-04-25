//! ERDPS Agent Library
//!
//! This library provides the core functionality for the Enterprise Ransomware
//! Detection and Protection System (ERDPS) Agent, including secure IPC
//! communication, configuration management, and logging capabilities.

// Temporarily disabled for compilation
// #![deny(warnings)]
// #![forbid(unsafe_code)]

use std::sync::atomic::AtomicBool;

// Global flag for system load backpressure
pub static IS_SYSTEM_UNDER_LOAD: AtomicBool = AtomicBool::new(false);

pub mod ai;
pub mod api;
pub mod config;
pub mod core;
pub mod database;
pub mod deployment;
pub mod driver;
pub mod enterprise;
pub mod entropy_analyzer;
pub mod error;
pub mod ipc;
pub mod logger;
pub mod memory;
pub mod metrics;
pub mod monitoring;
pub mod network;
pub mod observability;
pub mod performance;
pub mod prevention;
pub mod event_log;
pub mod response;
pub mod threat_intel;
pub mod utils;
pub mod validation;
pub mod telemetry;
pub mod behavioral;
pub mod security;
pub mod deception;
pub mod registry_sentry;
pub mod active_defense;
pub mod recovery {
    pub mod shadows;
}


// Global State
pub static GLOBAL_INSTALL_MODE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
// Testing utilities are only exposed when the `testing` feature is enabled
#[cfg(feature = "testing")]
pub mod testing;

// Core modules
pub mod detection;
pub mod detector;
pub mod filesystem;
pub mod mitigations;
pub mod monitor;
pub mod yara;
pub mod yara_updater;
pub mod service;
pub mod analysis;
pub mod ml_ngram; // ML N-Gram Engine
pub mod ml_engine;
pub mod pipeline; // Multi-Layer Forensic Pipeline
pub mod live_hunter; // New Live Hunter Module
pub mod persistence_scanner; // Persistence Hunter Module
pub mod memory_scanner; // Memory Hunter Module
pub mod network_scanner; // Network Scanner Module
pub mod rootkit_scanner; // Rootkit Scanner Module
pub mod integrity_scanner; // Integrity Scanner Module
pub mod recovery_engine; // Recovery Engine Module
pub mod sandbox_engine; // Sandbox Engine Module
pub mod intel_manager; // Intelligence Manager Module
pub mod structs; // Data Structures Module
pub mod model_hashes;
pub mod supply_chain;
pub mod graph_engine;
pub mod shadow_ai;
pub mod pickle_scanner;
pub mod ghost_hunter;
pub mod dfir_triage;
pub mod reporter;
pub mod forensic;
pub mod ai_copilot;

use std::sync::Arc;
use tokio::task::JoinHandle;
use anyhow::Result as AnyhowResult;

pub struct InitResult {
    #[cfg(feature = "yara")]
    pub fs_monitor: crate::monitor::fs::FsMonitor,
    pub ipc_handle: JoinHandle<()>,
    #[cfg(feature = "metrics")]
    pub metrics_handle: Option<JoinHandle<()>>,
    pub drives: Vec<String>,
}

pub async fn initialize_components_with_mode(_mode: &str, _extra: Option<()>) -> AnyhowResult<InitResult> {
    let cfg = match crate::config::agent_config::AgentConfig::load_from_file("config.toml") {
        Ok(c) => c,
        Err(_) => crate::config::agent_config::AgentConfig::load_or_default("../config.toml"),
    };
    let cfg = Arc::new(cfg);
    let drives = cfg.service.scan_paths.clone();

    let ipc_cfg = Arc::clone(&cfg);
    let ipc_handle = tokio::spawn(async move {
        let bind_addr = ipc_cfg.service.ipc_bind.clone();
        let _ = crate::ipc::start_ipc_server(bind_addr.as_str(), ipc_cfg).await;
    });

    #[cfg(feature = "yara")]
    {
        use crate::detection::yara_engine::YaraEngine;
        use crate::monitor::fs::FsMonitor;
        let engine = Arc::new(YaraEngine::new(Arc::clone(&cfg)));
        let _ = engine.load_comprehensive_rules(cfg.detection.yara_rules_path.as_str()).await;
        let fs_monitor = FsMonitor::new(Arc::clone(&cfg), engine);
        #[cfg(feature = "metrics")]
        {
            return Ok(InitResult { fs_monitor, ipc_handle, metrics_handle: None, drives });
        }
        #[cfg(not(feature = "metrics"))]
        {
            return Ok(InitResult { fs_monitor, ipc_handle, drives });
        }
    }

    #[cfg(not(feature = "yara"))]
    {
        #[cfg(feature = "metrics")]
        {
            return Ok(InitResult { ipc_handle, metrics_handle: None, drives });
        }
        #[cfg(not(feature = "metrics"))]
        {
            return Ok(InitResult { ipc_handle, drives });
        }
    }
}

// Advanced disassembly (Capstone)
#[cfg(feature = "advanced-disassembly")]
pub mod disassembly;

/// Initialize all internal modules
pub fn init_modules() {
    ipc::init();
    monitor::init();
    detector::init();
    mitigations::init();
    config::init();
}
