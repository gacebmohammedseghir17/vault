//! Process monitoring module for behavioral analysis
//! Provides real-time process enumeration and behavior tracking on Windows

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use sysinfo::System;
use tokio::sync::RwLock;
use tokio::time::interval;

// Windows-specific imports will be added when needed

use crate::metrics::MetricsCollector;

// Additional modules will be added as needed

/// Process information for behavioral analysis
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub parent_pid: Option<u32>,
    pub start_time: Instant,
    pub cpu_usage: f32,
    pub memory_usage: u64,
    pub file_operations: u64,
    pub network_connections: u32,
    pub child_processes: Vec<u32>,
}

/// Process spawn chain for detecting malicious behavior
#[derive(Debug, Clone)]
pub struct ProcessSpawnChain {
    pub root_pid: u32,
    pub chain: Vec<u32>,
    pub depth: usize,
    pub spawn_rate: f64, // processes per second
}

/// Windows process monitor for real-time process enumeration
pub struct ProcessMonitor {
    system: Arc<RwLock<System>>,
    processes: Arc<RwLock<HashMap<u32, ProcessInfo>>>,
    spawn_chains: Arc<RwLock<HashMap<u32, ProcessSpawnChain>>>,
    metrics: Arc<MetricsCollector>,
    monitoring: Arc<RwLock<bool>>,
}

impl ProcessMonitor {
    /// Create a new process monitor
    pub fn new(metrics: Arc<MetricsCollector>) -> Self {
        Self {
            system: Arc::new(RwLock::new(System::new_all())),
            processes: Arc::new(RwLock::new(HashMap::new())),
            spawn_chains: Arc::new(RwLock::new(HashMap::new())),
            metrics,
            monitoring: Arc::new(RwLock::new(false)),
        }
    }

    /// Start process monitoring
    pub async fn start_monitoring(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut monitoring = self.monitoring.write().await;
        if *monitoring {
            return Ok(()); // Already monitoring
        }
        *monitoring = true;
        drop(monitoring);

        let system = Arc::clone(&self.system);
        let processes = Arc::clone(&self.processes);
        let spawn_chains = Arc::clone(&self.spawn_chains);
        let metrics = Arc::clone(&self.metrics);
        let monitoring_flag = Arc::clone(&self.monitoring);

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(1));

            while *monitoring_flag.read().await {
                interval.tick().await;

                if let Err(e) =
                    Self::update_process_info(&system, &processes, &spawn_chains, &metrics).await
                {
                    log::error!("Process monitoring error: {}", e);
                }
            }
        });

        Ok(())
    }

    /// Stop process monitoring
    pub async fn stop_monitoring(&self) {
        let mut monitoring = self.monitoring.write().await;
        *monitoring = false;
    }

    /// Update process information
    async fn update_process_info(
        system: &Arc<RwLock<System>>,
        processes: &Arc<RwLock<HashMap<u32, ProcessInfo>>>,
        spawn_chains: &Arc<RwLock<HashMap<u32, ProcessSpawnChain>>>,
        metrics: &Arc<MetricsCollector>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut sys = system.write().await;
        sys.refresh_processes();

        let mut process_map = processes.write().await;
        let mut chains = spawn_chains.write().await;
        let current_time = Instant::now();

        // Track new processes and update existing ones
        for (pid, process) in sys.processes() {
            let pid_u32 = pid.as_u32();

            if let Some(existing) = process_map.get_mut(&pid_u32) {
                // Update existing process
                existing.cpu_usage = process.cpu_usage();
                existing.memory_usage = process.memory();
            } else {
                // New process detected
                let parent_pid = process.parent().map(|p| p.as_u32());

                let process_info = ProcessInfo {
                    pid: pid_u32,
                    name: process.name().to_string(),
                    parent_pid,
                    start_time: current_time,
                    cpu_usage: process.cpu_usage(),
                    memory_usage: process.memory(),
                    file_operations: 0,
                    network_connections: 0,
                    child_processes: Vec::new(),
                };

                process_map.insert(pid_u32, process_info);

                // Update spawn chains
                if let Some(parent_pid) = parent_pid {
                    Self::update_spawn_chain(&mut chains, parent_pid, pid_u32, current_time);
                }

                // Update metrics
                metrics.record_counter("suspicious_process_chains_total", 1.0);
            }
        }

        // Remove terminated processes
        let current_pids: std::collections::HashSet<u32> =
            sys.processes().keys().map(|pid| pid.as_u32()).collect();

        process_map.retain(|pid, _| current_pids.contains(pid));

        // Update process spawn rate metric
        let spawn_rate = Self::calculate_spawn_rate(&chains);
        metrics.update_process_spawn_rate(spawn_rate);

        Ok(())
    }

    /// Update process spawn chain
    fn update_spawn_chain(
        chains: &mut HashMap<u32, ProcessSpawnChain>,
        parent_pid: u32,
        child_pid: u32,
        _current_time: Instant,
    ) {
        // Check if parent exists and get necessary data
        let (root_pid, new_depth) = if let Some(parent_chain) = chains.get(&parent_pid) {
            (parent_chain.root_pid, parent_chain.depth + 1)
        } else {
            (parent_pid, 1)
        };

        // Update parent chain if it exists
        if let Some(parent_chain) = chains.get_mut(&parent_pid) {
            parent_chain.chain.push(child_pid);
            parent_chain.depth += 1;

            // Calculate spawn rate
            let elapsed = Duration::from_secs(parent_chain.chain.len() as u64).as_secs_f64();
            parent_chain.spawn_rate = parent_chain.chain.len() as f64 / elapsed.max(1.0);
        } else {
            // Start new chain for parent
            chains.insert(
                parent_pid,
                ProcessSpawnChain {
                    root_pid: parent_pid,
                    chain: vec![parent_pid, child_pid],
                    depth: 1,
                    spawn_rate: 1.0,
                },
            );
        }

        // Create new chain for child
        chains.insert(
            child_pid,
            ProcessSpawnChain {
                root_pid,
                chain: vec![child_pid],
                depth: new_depth,
                spawn_rate: 0.0,
            },
        );
    }

    /// Calculate overall process spawn rate
    fn calculate_spawn_rate(chains: &HashMap<u32, ProcessSpawnChain>) -> f64 {
        if chains.is_empty() {
            return 0.0;
        }

        chains.values().map(|chain| chain.spawn_rate).sum::<f64>() / chains.len() as f64
    }

    /// Get current process information
    pub async fn get_processes(&self) -> HashMap<u32, ProcessInfo> {
        self.processes.read().await.clone()
    }

    /// Get process spawn chains
    pub async fn get_spawn_chains(&self) -> HashMap<u32, ProcessSpawnChain> {
        self.spawn_chains.read().await.clone()
    }

    /// Get suspicious process spawn chains (high spawn rate or deep chains)
    pub async fn get_suspicious_chains(&self) -> Vec<ProcessSpawnChain> {
        let chains = self.spawn_chains.read().await;
        chains
            .values()
            .filter(|chain| chain.spawn_rate > 5.0 || chain.depth > 10)
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_process_monitor_creation() {
        let db = crate::metrics::MetricsDatabase::new(":memory:").unwrap();
        db.initialize_schema().unwrap();
        let metrics = Arc::new(MetricsCollector::new(db));
        let monitor = ProcessMonitor::new(metrics);

        assert!(!*monitor.monitoring.read().await);
    }

    #[tokio::test]
    async fn test_spawn_chain_update() {
        let mut chains = HashMap::new();
        let current_time = Instant::now();

        ProcessMonitor::update_spawn_chain(&mut chains, 100, 200, current_time);

        assert!(chains.contains_key(&100));
        assert_eq!(chains[&100].chain.len(), 2);
        assert_eq!(chains[&100].depth, 1);
    }
}
