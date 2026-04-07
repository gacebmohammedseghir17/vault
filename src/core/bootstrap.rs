use std::sync::Arc;
use tokio::sync::mpsc;
use std::path::PathBuf;
use crate::config::agent_config::AgentConfig;
use crate::{logger, ipc, mitigations, init_modules, filesystem, detector};
use crate::observability::prometheus_metrics::{PrometheusConfig, PrometheusMetricsServer};
use crate::metrics::{MetricsDatabase, MetricsCollector};
use crate::core::performance::{PerformanceTargets, PerformanceMonitor, PerformanceThreadPool, FastCache};

pub struct Bootstrap {
    config: Arc<AgentConfig>,
    metrics_collector: Arc<MetricsCollector>,
}

impl Bootstrap {
    pub async fn new() -> anyhow::Result<Self> {
        // Initialize structured logger first
        if let Err(e) = logger::init_logger() {
            eprintln!("Failed to initialize logger: {}", e);
            std::process::exit(1);
        }

        log::info!("ERDPS Agent starting...");

        let agent_config = match AgentConfig::load_from_file("config.toml") {
            Ok(cfg) => cfg,
            Err(_) => AgentConfig::load_or_default("../config.toml"),
        };
        log::info!("Configuration loaded successfully");
        log::info!("IPC bind: {}", agent_config.service.ipc_bind);
        log::info!("Metrics bind: {}", agent_config.observability.metrics_bind);

        let agent_config = Arc::new(agent_config);

        // Handle CLI commands
        if crate::core::cli::handle_cli(&agent_config).await {
             std::process::exit(0);
        }

        // Initialize Metrics System
        let metrics_db = MetricsDatabase::new(":memory:").expect("Failed to create metrics DB");
        if let Err(e) = metrics_db.initialize_schema() {
            log::warn!("Failed to init metrics schema: {}", e);
        }
        let metrics_collector = Arc::new(MetricsCollector::new(metrics_db));

        Ok(Self {
            config: agent_config,
            metrics_collector,
        })
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let agent_config = self.config.clone();
        let metrics_collector = self.metrics_collector.clone();

        let ipc_config_early = Arc::clone(&agent_config);
        tokio::spawn(async move {
            let bind_addr = ipc_config_early.service.ipc_bind.clone();
            if let Err(e) = ipc::start_ipc_server(bind_addr.as_str(), ipc_config_early).await {
                log::error!("IPC server error: {}", e);
            }
        });

        // Parse CLI args for metrics port override
        let mut metrics_port_override: Option<u16> = None;
        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            if arg == "--metrics-port" {
                if let Some(p) = args.next() {
                    if let Ok(port) = p.parse::<u16>() {
                        metrics_port_override = Some(port);
                    } else {
                        log::warn!("Invalid --metrics-port value '{}', using config default", p);
                    }
                } else {
                    log::warn!("--metrics-port provided without a value, using config default");
                }
            }
        }
        let metrics_port = metrics_port_override.unwrap_or(agent_config.observability.metrics_port);

        // Start Prometheus metrics server
        let mut prometheus_server = PrometheusMetricsServer::new(PrometheusConfig {
            enabled: true,
            // Force bind to 127.0.0.1 for test reliability
            bind_address: "127.0.0.1".to_string(),
            port: metrics_port,
            metrics_path: "/metrics".to_string(),
            auth_enabled: false,
            auth_token: None,
            collection_interval_seconds: 30,
        });
        if let Err(e) = prometheus_server.start().await {
            log::error!("Failed to start Prometheus metrics server: {}", e);
        } else {
            log::info!("Prometheus metrics server started on 127.0.0.1:{}", metrics_port);
        }

        if cfg!(windows) {
            #[cfg(target_os = "windows")]
            {
                use crate::behavioral::etw_monitor::EtwMonitor;
                use chrono::Utc;
                // Use global metrics_collector
                let etw = EtwMonitor::new(metrics_collector.clone());
                let reg_handle = prometheus_server.registry_handle();
                tokio::spawn(async move {
                    let _ = etw.start_monitoring().await;
                    let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
                    loop {
                        interval.tick().await;
                        let reg = etw.get_registry_events().await.len() as u64;
                        let inj = etw.get_process_injection_events().await.len() as u64;
                        let mut w = reg_handle.write().await;
                        w.registry_changes_total = reg;
                        w.injection_events_total = inj;
                        w.last_update = Utc::now();
                        let dropped = etw.get_injection_dropped_total().await;
                        let whitelisted = etw.get_injection_whitelisted_total().await;
                        w.etw_injection_dropped_total = dropped;
                        w.etw_injection_whitelisted_total = whitelisted;
                    }
                });
            }
        }

        // 🚀 Initialize Lightning-Fast Performance Optimization System
        log::info!("🚀 Initializing ERDPS Phase 2: Lightning-Fast Performance Optimization");
        
        // Create performance targets for <50ms response time
        let performance_targets = PerformanceTargets::default();
        log::info!("🎯 Performance targets: <{}ms response, {}+ files/min, <{}ms network analysis", 
                   performance_targets.max_response_time_ms,
                   performance_targets.min_files_per_minute,
                   performance_targets.max_network_analysis_ms);
        
        // Initialize performance monitor
        let performance_monitor = Arc::new(PerformanceMonitor::new(performance_targets));
        
        // Initialize high-performance thread pool
        let thread_pool = Arc::new(PerformanceThreadPool::new()
            .expect("Failed to create performance thread pool"));
        log::info!("🔥 High-performance thread pool initialized with {} CPU cores", 
                   thread_pool.cpu_cores());
        
        // Initialize lightning-fast cache system
        let _file_cache: Arc<FastCache<String, Vec<u8>>> = Arc::new(FastCache::new(10000));
        let _rule_cache: Arc<FastCache<String, bool>> = Arc::new(FastCache::new(50000));
        log::info!("💾 Lightning-fast cache system initialized (10K file cache, 50K rule cache)");
        
        log::info!("✅ ERDPS Performance Optimization System ready - targeting <50ms response time!");

        // Initialize all modules
        init_modules();

        #[cfg(feature = "yara")]
        self.init_yara(&agent_config, &prometheus_server).await;

        log::info!("ERDPS Agent initialized successfully");

        // Create bounded channels for event processing
        let (event_tx, event_rx) = mpsc::channel(1000);  // Event processing queue
        let (alert_tx, alert_rx) = mpsc::channel(500);   // Alert delivery queue
        let (mitigation_tx, mitigation_rx) = mpsc::channel(100);  // Mitigation action queue
        let mitigation_tx_honeyfile = mitigation_tx.clone(); // Clone for Honeyfile manager

        // Start file system monitor
        Self::start_fs_monitor(&agent_config, event_tx.clone()).await;

        // Start detection engine
        let detector_config = Arc::clone(&agent_config);
        let detector = detector::Detector::new(event_rx, alert_tx, Some(mitigation_tx), detector_config)
            .expect("Failed to create detector");
        let detector_handle = tokio::spawn(async move {
            let handle = detector::start_detector(detector);
            if let Err(e) = handle.await {
                log::error!("Detector task error: {}", e);
            }
        });

        // Initialize Honeyfile Deception System
        log::info!("🐝 Initializing Honeyfile Deception System");
        let (honey_tx, mut honey_rx) = tokio::sync::mpsc::unbounded_channel();
        let honeyfile_config = crate::prevention::honeyfile::HoneyfileConfig::default();
        
        // Use mitigation_tx_honeyfile for sending alerts
        let honeyfile_mitigation_tx = mitigation_tx_honeyfile.clone();

        let honeyfile_manager = Arc::new(crate::prevention::honeyfile::HoneyfileManager::new(
            honeyfile_config,
            honey_tx,
        ));

        // Deploy honeyfiles
        let hm = honeyfile_manager.clone();
        tokio::spawn(async move {
            log::info!("Deploying honeyfiles...");
            if let Err(e) = hm.deploy().await {
                log::error!("Failed to deploy honeyfiles: {}", e);
            } else {
                log::info!("✅ Honeyfiles deployed successfully");
                
                // Start monitoring
                log::info!("Starting honeyfile monitoring...");
                if let Err(e) = hm.start_monitoring() {
                     log::error!("Failed to start honeyfile monitoring: {}", e);
                } else {
                     log::info!("✅ Honeyfile monitor active");
                }
            }
        });

        // Start mitigation engine
        let mitigation_config = Arc::clone(&agent_config);
        let mitigation_handle = mitigations::start_mitigation_engine(mitigation_rx, mitigation_config);

        // Start alert processing task
        let alert_config = Arc::clone(&agent_config);
        let alert_handle = tokio::spawn(async move {
            let mut alert_rx = alert_rx;
            while let Some(alert) = alert_rx.recv().await {
                // Log all alerts
                log::info!(
                    "Detection Alert: rule_id={}, score={}, evidence={:?}",
                    alert.rule_id,
                    alert.score,
                    alert.evidence
                );

                // Forward critical alerts to IPC
                let normalized_score = alert.score as f64 / 100.0;
                if normalized_score >= alert_config.detection.false_positive_threshold {
                    if let Err(e) = ipc::send_signed_alert(&alert).await {
                        log::error!("Failed to send alert via IPC: {}", e);
                    }
                }
            }
        });

        let ipc_handle = tokio::spawn(async move {
            loop { tokio::time::sleep(std::time::Duration::from_secs(60)).await; }
        });

        // 📊 Start Performance Monitoring and Reporting
        let perf_monitor = Arc::clone(&performance_monitor);
        let performance_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                interval.tick().await;
                let report = perf_monitor.get_performance_report().await;
                log::info!("\n{}", report);
                
                // Check if performance targets are being met
                if !perf_monitor.check_performance().await {
                    log::warn!("⚠️  Performance targets not met - optimization needed!");
                }
            }
        });

        // 🖥️ Start System Resource Monitoring
        let sys_mon_metrics = metrics_collector.clone();
        tokio::spawn(async move {
            let monitor = crate::observability::system_monitor::SystemMonitor::new(sys_mon_metrics);
            monitor.start().await;
        });

        if agent_config.yara_updater.enabled {
            match crate::yara_updater::create_updater(agent_config.yara_updater.clone()) {
                Ok(updater) => {
                    tokio::spawn(async move {
                        let _ = updater.start_periodic_updates().await;
                    });
                    log::info!("YARA updater task started");
                }
                Err(e) => {
                    log::warn!("Failed to initialize YARA updater: {}", e);
                }
            }
        }

        if let Some(inst) = &agent_config.installer {
            if inst.signing_enabled {
                let inst_cfg = inst.clone();
                tokio::spawn(async move {
                    for ap in inst_cfg.artifact_paths.iter() {
                        let path = std::path::Path::new(ap);
                        if !path.exists() { continue; }
                        let mut args = vec!["sign", "/fd", "SHA256"]; 
                        if !inst_cfg.certificate_thumbprint.is_empty() {
                            args.extend(["/sha1", inst_cfg.certificate_thumbprint.as_str()]);
                        }
                        if !inst_cfg.timestamp_url.is_empty() {
                            args.extend(["/tr", inst_cfg.timestamp_url.as_str(), "/td", "SHA256"]);
                        }
                        args.push(ap);
                        let res = std::process::Command::new(&inst_cfg.signtool_path)
                            .args(&args)
                            .output();
                        match res {
                            Ok(out) => {
                                if out.status.success() {
                                    log::info!("Signed artifact: {}", ap);
                                } else {
                                    log::warn!("Signing failed for {}: exit {}; stderr: {}", ap, out.status, String::from_utf8_lossy(&out.stderr));
                                }
                            }
                            Err(e) => {
                                log::warn!("Failed to execute signtool for {}: {}", ap, e);
                            }
                        }
                    }
                });
                log::info!("Installer signing task started");
            }
        }

        // Handle Honeyfile Alerts
        tokio::spawn(async move {
            // Simple PID resolution using sysinfo
            let _system = sysinfo::System::new_all();
            
            while let Some(msg) = honey_rx.recv().await {
                log::warn!("🚨 HONEYFILE ALERT: {}", msg);
                
                // Trigger immediate mitigation (Suspend all suspicious activity)
                let request = crate::mitigations::MitigationRequest {
                    id: uuid::Uuid::new_v4().to_string(),
                    action: crate::mitigations::MitigationAction::SuspendProcess,
                    pid: None, 
                    files: vec![], 
                    quarantined_paths: vec![],
                    reason: format!("Honeyfile Compromise Detected: {}", msg),
                    score: 100, 
                    dry_run: Some(false), 
                    require_confirmation: false,
                    timestamp: chrono::Utc::now().timestamp() as u64,
                };
                
                if let Err(e) = honeyfile_mitigation_tx.send(request).await {
                    log::error!("Failed to send honeyfile mitigation request: {}", e);
                }
            }
        });

        log::info!("Agent is now running. Press Ctrl+C to stop.");

        // Wait for shutdown signal
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to listen for shutdown signal");
        log::info!("Shutdown signal received, stopping ERDPS Agent...");

        // Graceful shutdown
        ipc_handle.abort();
        // monitor_handle.abort();
        detector_handle.abort();
        mitigation_handle.abort();
        alert_handle.abort();
        performance_handle.abort();
        // Stop metrics server
        prometheus_server.stop().await;
        log::info!("ERDPS Agent stopped");

        Ok(())
    }

    #[cfg(feature = "yara")]
    async fn init_yara(&self, agent_config: &Arc<AgentConfig>, prometheus_server: &PrometheusMetricsServer) {
        use crate::yara::rule_loader::create_comprehensive_rule_loader;
        use crate::yara::file_scanner::YaraFileScanner;
        use crate::config::yara_config::{ensure_default_config, load_yara_config};
        use std::sync::Arc;
        use std::fs;
        let primary_rules_path = agent_config.detection.yara_rules_path.clone();
        let additional_paths = agent_config
            .yara
            .as_ref()
            .map(|y| y.additional_rules_paths.clone())
            .unwrap_or_default();
        if let Ok(loader) = create_comprehensive_rule_loader(primary_rules_path.as_str(), &additional_paths, false) {
            let _ = loader.initialize();
            let stats = loader.get_compilation_stats();
            let rules_loaded = if stats.successful_compilations > 0 { stats.successful_compilations as u64 } else { loader.rule_count() as u64 };
            prometheus_server.update_rules_loaded(rules_loaded).await;
            prometheus_server.update_broken_rules(stats.broken_files as u64).await;
            prometheus_server.update_duplicate_rules(stats.duplicate_files as u64).await;
            let _ = ensure_default_config();
            let cfg = load_yara_config();
            let scanner = YaraFileScanner::new(Arc::new(loader), Arc::new(cfg));
            let paths = agent_config.service.scan_paths.clone();
            tokio::spawn(async move {
                for p in paths {
                    let pb = std::path::PathBuf::from(p);
                    if pb.is_dir() {
                        if let Ok(res) = scanner.scan_directory(&pb, true).await {
                            for r in res {
                                if !r.matches.is_empty() {
                                    let rules = r.matches.iter().map(|m| m.rule_name.clone()).collect::<Vec<String>>();
                                    let path_str = r.file_path.display().to_string();
                                    let entry = serde_json::json!({"timestamp": chrono::Utc::now().to_rfc3339(), "path": path_str, "rules": rules});
                                    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open("C:/ProgramData/ERDPS/detections.jsonl") {
                                        let s = serde_json::to_string(&entry).unwrap_or_default();
                                        let _ = std::io::Write::write_all(&mut f, format!("{}\n", s).as_bytes());
                                    }
                                }
                            }
                        }
                    }
                }
            });
        } else {
            let mut files = 0u64;
            let mut dirs: Vec<PathBuf> = Vec::new();
            dirs.push(PathBuf::from(primary_rules_path.clone()));
            for p in &additional_paths { dirs.push(PathBuf::from(p)); }
            for root in dirs {
                if root.exists() {
                    let mut stack = vec![root];
                    while let Some(dir) = stack.pop() {
                        if let Ok(entries) = fs::read_dir(&dir) {
                            for entry in entries.flatten() {
                                let p = entry.path();
                                if p.is_dir() {
                                    if let Some(name) = p.file_name().and_then(|s| s.to_str()) {
                                        if name.starts_with('.') || name == "cache" || name == "tmp" || name == "temp" { continue; }
                                    }
                                    stack.push(p);
                                } else if let Some(ext) = p.extension() {
                                    if ext == "yar" || ext == "yara" { files += 1; }
                                }
                            }
                        }
                    }
                }
            }
            prometheus_server.update_rules_loaded(files).await;
        }
    }

    async fn start_fs_monitor(agent_config: &Arc<AgentConfig>, event_tx: mpsc::Sender<crate::detector::Event>) {
        let monitor_config = Arc::clone(agent_config);
        let event_forward_tx = event_tx.clone();
        
        tokio::spawn(async move {
            #[cfg(not(feature = "yara"))]
            let mut fs_monitor = filesystem::create_filesystem_monitor(monitor_config, ());
            #[cfg(not(feature = "yara"))]
            {
                fs_monitor.set_detector_event_sender(event_forward_tx.clone());
            }
            
            #[cfg(feature = "yara")]
            let mut fs_monitor = {
                use std::sync::Arc;
                use crate::yara::{YaraFileScanner, YaraRuleLoader};
                use crate::config::yara_config::Config;
                let primary = monitor_config.detection.yara_rules_path.clone();
                let additional_dirs: Vec<String> = monitor_config
                    .yara
                    .as_ref()
                    .map(|y| y.additional_rules_paths.clone())
                    .unwrap_or_default();
                let additional_dirs_str: Vec<&str> = additional_dirs.iter().map(|s| s.as_str()).collect();
                let rule_loader = Arc::new(YaraRuleLoader::new_with_multiple_dirs(
                    primary.as_str(),
                    additional_dirs_str,
                    false,
                ));
                if let Err(e) = rule_loader.initialize() {
                    log::warn!("YARA rule loader initialization encountered issues: {}. Continuing with available rules.", e);
                }
                let yara_config = Arc::new(Config::default());
                let scanner = Arc::new(YaraFileScanner::new(rule_loader, yara_config));
                let mut fs_monitor = filesystem::create_filesystem_monitor(monitor_config, scanner);
                fs_monitor.set_detector_event_sender(event_forward_tx.clone());
                fs_monitor
            };
            
            if let Err(e) = fs_monitor.start().await {
                log::error!("Filesystem monitor error: {}", e);
            }
            
            let sandbox_dir = PathBuf::from("../ransom_sim_sandbox");
            if sandbox_dir.exists() {
                 if let Err(e) = fs_monitor.add_watch_directory(&sandbox_dir).await {
                     log::warn!("Failed to add sandbox watch: {}", e);
                 }
            }
        });
    }
}
