use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use log::{debug, error, info, warn};
use tokio::net::TcpListener;

use crate::config::AgentConfig;
#[allow(unused_imports)]
use crate::metrics::MetricsCollector;
#[allow(unused_imports)]
use crate::response::action_executor::ActionExecutor;

use super::protocol::{
    normalized_payload, sign, verify, NonceStore, RequestMessage, ResponseMessage,
};
use super::state::{
    get_last_scan_time, get_quarantined_files, get_threats_detected, get_uptime_seconds,
    increment_quarantined_files, increment_threats_detected, set_last_scan_time, set_server_start,
    ScanJobStatus, JOB_TASKS, JOBS,
};
use super::transport::{read_frame, write_frame};

/// Maximum allowed timestamp skew in seconds (±15 seconds)
const MAX_TIMESTAMP_SKEW_SECS: i64 = 15;

/// Start the IPC server on the specified bind address
pub async fn start_ipc_server(bind_addr: &str, config: Arc<AgentConfig>) -> Result<()> {
    info!("Starting IPC server on {bind_addr}");

    // Record server start time for uptime tracking
    set_server_start();

    // Load TLS config
    let tls_acceptor = if let (Some(cert), Some(key)) = (&config.service.tls_cert_path, &config.service.tls_key_path) {
        info!("Loading TLS config from {} and {}", cert, key);
        match super::tls::load_server_config(std::path::Path::new(cert), std::path::Path::new(key)) {
            Ok(acceptor) => Some(acceptor),
            Err(e) => {
                error!("Failed to load TLS config: {}. Falling back to plaintext (INSECURE)", e);
                None
            }
        }
    } else {
        warn!("No TLS configuration provided. IPC will use plaintext (INSECURE)");
        None
    };

    // Try primary bind first; if address is in use, attempt a graceful fallback
    let listener = match TcpListener::bind(bind_addr).await {
        Ok(l) => {
            info!("IPC server listening on {bind_addr}");
            let _ = tokio::fs::create_dir_all("target").await;
            let _ = tokio::fs::write("target/ipc_bind.txt", bind_addr).await;
            l
        }
        Err(e) => {
            if e.kind() == std::io::ErrorKind::AddrInUse {
                warn!("Address {bind_addr} in use; attempting fallback port binding");

                // Parse host and base port from bind_addr (format: host:port)
                let (host, base_port) = match bind_addr.rfind(':') {
                    Some(pos) => {
                        let host = &bind_addr[..pos];
                        let port_str = &bind_addr[pos + 1..];
                        match port_str.parse::<u16>() {
                            Ok(p) => (host.to_string(), p),
                            Err(_) => {
                                return Err(anyhow::anyhow!(
                                    "Failed to parse port from bind address: {}",
                                    bind_addr
                                ));
                            }
                        }
                    }
                    None => {
                        return Err(anyhow::anyhow!(
                            "Invalid bind address format (expected host:port): {}",
                            bind_addr
                        ));
                    }
                };

                // Try up to 10 subsequent ports as a fallback
                let mut bound: Option<(tokio::net::TcpListener, String)> = None;
                for offset in 1..=10 {
                    let candidate_port = base_port.saturating_add(offset);
                    let candidate_addr = format!("{}:{}", host, candidate_port);
                    match TcpListener::bind(&candidate_addr).await {
                        Ok(l) => {
                            info!(
                                "IPC server fallback succeeded; listening on {}",
                                candidate_addr
                            );
                            bound = Some((l, candidate_addr));
                            break;
                        }
                        Err(err) => {
                            if err.kind() == std::io::ErrorKind::AddrInUse {
                                debug!("Fallback port {} also in use; trying next", candidate_port);
                                continue;
                            } else {
                                debug!(
                                    "Failed to bind fallback address {}: {}",
                                    candidate_addr, err
                                );
                                continue;
                            }
                        }
                    }
                }

                if let Some((listener, chosen_addr)) = bound {
                    // Note: we do not mutate the immutable config; we just log the chosen addr
                    info!(
                        "IPC server active on {} (fallback from {})",
                        chosen_addr, bind_addr
                    );
                    let _ = tokio::fs::create_dir_all("target").await;
                    let _ = tokio::fs::write("target/ipc_bind.txt", &chosen_addr).await;
                    listener
                } else {
                    return Err(anyhow::anyhow!(
                        "Failed to bind IPC server; all fallback ports from {}-{} unavailable",
                        base_port + 1,
                        base_port + 10
                    ));
                }
            } else {
                return Err(e).context("Failed to bind IPC server");
            }
        }
    };

    // Shared nonce store for all connections
    let nonce_store = Arc::new(Mutex::new(NonceStore::new()));
    let _ = JOBS.set(Mutex::new(HashMap::new()));
    let _ = JOB_TASKS.set(Mutex::new(HashMap::new()));

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                debug!("Accepted connection from: {addr}");

                let config_clone = Arc::clone(&config);
                let nonce_store_clone = Arc::clone(&nonce_store);
                let tls_acceptor_clone = tls_acceptor.clone();
                let peer_addr = addr.to_string();

                // Spawn a task to handle this connection
                tokio::spawn(async move {
                    if let Some(acceptor) = tls_acceptor_clone {
                        match acceptor.accept(stream).await {
                            Ok(tls_stream) => {
                                if let Err(e) = handle_connection(tls_stream, peer_addr, config_clone, nonce_store_clone).await
                                {
                                    error!("Connection handler error (TLS): {e}");
                                }
                            }
                            Err(e) => {
                                error!("TLS handshake failed: {e}");
                            }
                        }
                    } else {
                        if let Err(e) = handle_connection(stream, peer_addr, config_clone, nonce_store_clone).await
                        {
                            error!("Connection handler error: {e}");
                        }
                    }
                });
            }
            Err(e) => {
                error!("Failed to accept connection: {e}");
            }
        }
    }
}

use tokio::io::{AsyncRead, AsyncWrite};

/// Handle a single client connection
async fn handle_connection<S>(
    mut stream: S,
    peer_addr: String,
    config: Arc<AgentConfig>,
    nonce_store: Arc<Mutex<NonceStore>>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    debug!("New IPC connection from: {peer_addr}");

    // Decode the IPC key from base64
    let ipc_key = BASE64
        .decode(&config.ipc_key)
        .context("Failed to decode IPC key")?;

    loop {
        // Read incoming message
        let message_bytes = match read_frame(&mut stream).await {
            Ok(bytes) => bytes,
            Err(e) => {
                debug!("Connection closed by peer {peer_addr}: {e}");
                break;
            }
        };

        // Parse JSON request
        let request: RequestMessage = match serde_json::from_slice(&message_bytes) {
            Ok(req) => req,
            Err(e) => {
                error!("Invalid JSON from {peer_addr}: {e}");
                break;
            }
        };

        debug!("Received command '{}' from {}", request.command, peer_addr);

        // Verify message signature and constraints
        let verification_result = {
            let mut nonce_store = nonce_store.lock().unwrap();
            verify(
                &request,
                &ipc_key,
                MAX_TIMESTAMP_SKEW_SECS,
                &mut nonce_store,
            )
        };

        match verification_result {
            Ok(()) => {
                debug!("Message verification successful for {peer_addr}");

                // Handle the verified command
                let response = handle_command(&request, &ipc_key, Arc::clone(&config)).await;

                // Send response
                let response_json =
                    serde_json::to_vec(&response).context("Failed to serialize response")?;

                if let Err(e) = write_frame(&mut stream, &response_json).await {
                    error!("Failed to send response to {peer_addr}: {e}");
                    break;
                }

                debug!("Response sent to {peer_addr}");
            }
            Err(e) => {
                error!("Message verification failed from {peer_addr}: {e}");
                break; // Close connection on verification failure
            }
        }
    }

    debug!("Connection closed: {peer_addr}");
    Ok(())
}

/// Handle a verified command and generate a response
pub(crate) async fn handle_command(
    request: &RequestMessage,
    ipc_key: &[u8],
    config: Arc<AgentConfig>,
) -> ResponseMessage {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as i64;

    let (status, payload) = match request.command.as_str() {
        "getStatus" => {
            let uptime_seconds = get_uptime_seconds() as i64;
            let configured_bind_addr = config.service.ipc_bind.clone();
            let active_bind_addr = tokio::fs::read_to_string("target/ipc_bind.txt")
                .await
                .ok()
                .unwrap_or_else(|| configured_bind_addr.clone());
            let status_payload = serde_json::json!({
                "agent_version": "0.1.0",
                "status": "running",
                "uptime_seconds": uptime_seconds,
                "last_scan": get_last_scan_time(),
                "threats_detected": get_threats_detected(),
                "quarantined_files": get_quarantined_files(),
                "configured_bind_addr": configured_bind_addr,
                "active_bind_addr": active_bind_addr
            });

            // Persist system health to metrics DB
            {
                use crate::metrics::database::{MetricsDatabase, SystemHealthRecord};
                use chrono::Utc;
                let db_path = std::env::temp_dir().join("erdps_metrics.db");
                if let Ok(db) = MetricsDatabase::new(db_path) {
                    let _ = db.initialize_schema();
                    let _ = db.record_system_health(&SystemHealthRecord {
                        id: None,
                        timestamp: Utc::now(),
                        component: "agent".to_string(),
                        status: "running".to_string(),
                        uptime_seconds: Some(uptime_seconds),
                        error_count: 0,
                        warning_count: 0,
                        last_error_message: None,
                        last_error_timestamp: None,
                        memory_usage_mb: None,
                        cpu_usage_percent: None,
                        disk_usage_mb: None,
                    });
                }
            }
            ("success".to_string(), status_payload)
        }
        "get_quarantine_list" => {
            #[cfg(feature = "metrics")]
            {
                let db_path = std::env::temp_dir().join("erdps_metrics.db");
                let db = crate::metrics::database::MetricsDatabase::new(db_path).unwrap_or_else(|_| {
                    crate::metrics::database::MetricsDatabase::new("metrics.db").expect("metrics db")
                });
                let metrics = Arc::new(MetricsCollector::new(db));
                match ActionExecutor::new(metrics).await {
                    Ok(exec) => match exec.list_quarantined_files().await {
                        Ok(items) => {
                            let list: Vec<serde_json::Value> = items
                                .into_iter()
                                .map(|qi| serde_json::json!({
                                    "quarantine_filename": qi.quarantine_filename,
                                    "original_path": qi.original_path,
                                    "quarantine_time": qi.quarantine_time,
                                    "file_size": qi.file_size
                                }))
                                .collect();
                            let payload = normalized_payload(
                                "quarantine",
                                "list",
                                Some(serde_json::json!({"items": list})),
                                None,
                                None,
                            );
                            ("success".to_string(), payload)
                        }
                        Err(_e) => {
                            let err = normalized_payload(
                                "quarantine",
                                "error",
                                None,
                                Some("Failed to list quarantined files"),
                                Some("QUARANTINE_LIST_FAILED"),
                            );
                            ("error".to_string(), err)
                        }
                    },
                    Err(_e) => {
                        let err = normalized_payload(
                            "quarantine",
                            "error",
                            None,
                            Some("Failed to initialize action executor"),
                            Some("EXECUTOR_INIT_FAILED"),
                        );
                        ("error".to_string(), err)
                    }
                }
            }
            #[cfg(not(feature = "metrics"))]
            {
                let err = normalized_payload(
                    "quarantine",
                    "error",
                    None,
                    Some("Metrics feature disabled"),
                    Some("FEATURE_DISABLED"),
                );
                ("error".to_string(), err)
            }
        }
        "quarantineFiles" => {
            // Extract file paths from payload
            let files: Vec<std::path::PathBuf> = match request.payload.get("files") {
                Some(serde_json::Value::Array(arr)) => arr
                    .iter()
                    .filter_map(|v| v.as_str())
                    .map(std::path::PathBuf::from)
                    .collect(),
                _ => {
                    let error_payload = normalized_payload(
                        "quarantine",
                        "error",
                        None,
                        Some("Invalid or missing 'files' parameter"),
                        Some("INVALID_PARAMS"),
                    );
                    return ResponseMessage {
                        nonce: request.nonce.clone(),
                        timestamp: now,
                        status: "error".to_string(),
                        payload: error_payload,
                        signature: "invalid_signature".to_string(),
                    };
                }
            };

            // Perform quarantine operation
            match crate::mitigations::quarantine_files(&files, &config).await {
                Ok(quarantined_paths) => {
                    let success_payload = normalized_payload(
                        "quarantine",
                        "quarantine_success",
                        Some(serde_json::json!({
                            "quarantined_paths": quarantined_paths
                                .iter()
                                .map(|p| p.to_string_lossy())
                                .collect::<Vec<_>>()
                        })),
                        Some(&format!(
                            "Successfully quarantined {} files",
                            quarantined_paths.len()
                        )),
                        None,
                    );
                    increment_quarantined_files(quarantined_paths.len() as u64);
                    ("success".to_string(), success_payload)
                }
                Err(_e) => {
                    let error_payload = normalized_payload(
                        "quarantine",
                        "error",
                        None,
                        Some("Quarantine operation failed"),
                        Some("QUARANTINE_FAILED"),
                    );
                    ("error".to_string(), error_payload)
                }
            }
        }
        "quarantine_file" => {
            // Accept either single 'file' or array 'files'
            let files: Vec<std::path::PathBuf> = if let Some(f) = request.payload.get("file").and_then(|v| v.as_str()) {
                vec![std::path::PathBuf::from(f)]
            } else {
                match request.payload.get("files") {
                    Some(serde_json::Value::Array(arr)) => arr
                        .iter()
                        .filter_map(|v| v.as_str())
                        .map(std::path::PathBuf::from)
                        .collect(),
                    _ => {
                        let error_payload = normalized_payload(
                            "quarantine",
                            "error",
                            None,
                            Some("Invalid or missing 'file/files' parameter"),
                            Some("INVALID_PARAMS"),
                        );
                        return ResponseMessage {
                            nonce: request.nonce.clone(),
                            timestamp: now,
                            status: "error".to_string(),
                            payload: error_payload,
                            signature: "invalid_signature".to_string(),
                        };
                    }
                }
            };

            match crate::mitigations::quarantine_files(&files, &config).await {
                Ok(quarantined_paths) => {
                    let success_payload = normalized_payload(
                        "quarantine",
                        "quarantine_success",
                        Some(serde_json::json!({
                            "quarantined_paths": quarantined_paths
                                .iter()
                                .map(|p| p.to_string_lossy())
                                .collect::<Vec<_>>()
                        })),
                        Some(&format!(
                            "Successfully quarantined {} files",
                            quarantined_paths.len()
                        )),
                        None,
                    );
                    increment_quarantined_files(quarantined_paths.len() as u64);
                    ("success".to_string(), success_payload)
                }
                Err(_e) => {
                    let error_payload = normalized_payload(
                        "quarantine",
                        "error",
                        None,
                        Some("Quarantine operation failed"),
                        Some("QUARANTINE_FAILED"),
                    );
                    ("error".to_string(), error_payload)
                }
            }
        }
        "restore_quarantine" => {
            #[cfg(feature = "metrics")]
            {
                let quarantine_filename = request
                    .payload
                    .get("quarantine_filename")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if quarantine_filename.is_empty() {
                    let err = serde_json::json!({
                        "error": "Invalid or missing 'quarantine_filename' parameter",
                        "details": "Provide the quarantine .quar filename"
                    });
                    ("error".to_string(), err)
                } else {
                    let db_path = std::env::temp_dir().join("erdps_metrics.db");
                    let db = crate::metrics::database::MetricsDatabase::new(db_path)
                        .unwrap_or_else(|_| {
                            crate::metrics::database::MetricsDatabase::new("metrics.db")
                                .expect("metrics db")
                        });
                    let metrics = Arc::new(MetricsCollector::new(db));
                    match ActionExecutor::new(metrics).await {
                        Ok(exec) => match exec.restore_quarantined_file(quarantine_filename).await {
                            Ok(restored_path) => {
                                let payload = normalized_payload(
                                    "quarantine",
                                    "restore_success",
                                    Some(serde_json::json!({
                                        "restored_path": restored_path.to_string_lossy(),
                                        "quarantine_filename": quarantine_filename
                                    })),
                                    Some("File restored successfully"),
                                    None,
                                );
                                ("success".to_string(), payload)
                            }
                            Err(e) => {
                                let err = serde_json::json!({
                                    "error": "Failed to restore quarantined file",
                                    "details": e.to_string(),
                                    "quarantine_filename": quarantine_filename
                                });
                                ("error".to_string(), err)
                            }
                        },
                        Err(_e) => {
                            let err = normalized_payload(
                                "quarantine",
                                "error",
                                None,
                                Some("Failed to initialize action executor"),
                                Some("EXECUTOR_INIT_FAILED"),
                            );
                            ("error".to_string(), err)
                        }
                    }
                }
            }
            #[cfg(not(feature = "metrics"))]
            {
                let err = normalized_payload(
                    "quarantine",
                    "error",
                    None,
                    Some("Metrics feature disabled"),
                    Some("FEATURE_DISABLED"),
                );
                ("error".to_string(), err)
            }
        }
        "scan_file" => {
            // Extract target file path from payload
            let path_str = match request.payload.get("path").and_then(|v| v.as_str()) {
                Some(p) => p.to_string(),
                None => {
                    let error_payload = serde_json::json!({
                        "event_type": "error",
                        "context": "yara_scan",
                        "msg": "Missing 'path' in payload",
                    });
                    return ResponseMessage {
                        nonce: request.nonce.clone(),
                        timestamp: now,
                        status: "error".to_string(),
                        payload: error_payload,
                        signature: sign("response", now, &request.nonce, &serde_json::json!({
                            "event_type": "error",
                            "context": "yara_scan",
                            "msg": "Missing 'path' in payload",
                        }), ipc_key).unwrap_or_else(|e| {
                            error!("Failed to sign response: {e}");
                            "invalid_signature".to_string()
                        }),
                    };
                }
            };

            let path = std::path::PathBuf::from(&path_str);

            // Initialize YARA engine and ensure rules loaded
            let engine = crate::detection::yara_engine::YaraEngine::new(Arc::clone(&config));
            let rules_dir = &config.detection.yara_rules_path;
            if let Err(e) = engine.load_rules(rules_dir).await {
                warn!("Failed to load YARA rules from {}: {}", rules_dir, e);
            }

            let scan_result = match engine.read_and_scan_file(&path).await {
                Ok(matches) => {
                    if !matches.is_empty() {
                        let serialized_matches: Vec<serde_json::Value> = matches
                            .into_iter()
                            .map(|m| serde_json::json!({
                                "rule": m.rule,
                                "strings": m.strings.into_iter().map(|s| serde_json::json!({
                                    "identifier": s.identifier,
                                    "offset": s.offset,
                                    "length": s.length,
                                    "data": s.data,
                                })).collect::<Vec<_>>(),
                                "meta": m.meta,
                            }))
                            .collect();

                        #[allow(unused_mut)]
                        let mut ai_section: Option<serde_json::Value> = None;
                        #[cfg(feature = "ai-integration")]
                        {
                            use crate::yara::ember_detector::EmberMalwareDetector;
                            use std::path::PathBuf;
                            let model_path = request
                                .payload
                                .get("model_path")
                                .and_then(|v| v.as_str())
                                .map(PathBuf::from)
                                .unwrap_or_else(|| PathBuf::from("agent/models/ember_model_real.onnx"));
                            let threshold = request
                                .payload
                                .get("threshold")
                                .and_then(|v| v.as_f64())
                                .map(|f| f as f32)
                                .unwrap_or(0.5);
                            if let Ok(mut detector) = EmberMalwareDetector::new_with_model_path(model_path.clone(), threshold) {
                                let _ = detector.initialize(Some(&model_path)).await;
                                if let Ok(score) = detector.predict(&path).await {
                                    ai_section = Some(serde_json::json!({
                                        "model_path": model_path,
                                        "probability": score.probability,
                                        "confidence": score.confidence,
                                        "is_malware": score.is_malware
                                    }));
                                }
                            }
                        }

                        // Optional disassembly and AI narrative
                        #[allow(unused)]
                        let mut disassembly: Option<serde_json::Value> = None;
                        if request.payload.get("disassembly").and_then(|v| v.as_bool()).unwrap_or(false) {
                            if let Ok(report) = crate::analysis::disassembly::analyze_file(path.clone()) {
                                let _explanation = format!(
                                    "{} suspicious indicators; examples: {}",
                                    report.suspicious.len(),
                                    report.suspicious.iter().take(3).map(|f| f.kind.clone()).collect::<Vec<_>>().join(", ")
                                );
                                #[allow(unused_mut)]
                                let mut llm_analysis: Option<serde_json::Value> = None;
                                #[cfg(feature = "ai-integration")]
                                {
                                    use crate::ai::{AIConfig, AnalysisInput, AnalysisRequest, AnalysisType};
                                    use crate::ai::ollama_client::OllamaClient;
                                    let mut ai_cfg = AIConfig::default();
                                    if let Some(model_override) = request.payload.get("llm_model").and_then(|v| v.as_str()) {
                                        ai_cfg.default_model = model_override.to_string();
                                    }
                                    ai_cfg.timeout_seconds = ai_cfg.timeout_seconds.min(5);
                                    ai_cfg.max_retries = 1;
                                    if let Ok(client) = OllamaClient::new(ai_cfg.clone()) {
                                        use tokio::time::{timeout, Duration};
                                        if let Ok(true) = timeout(Duration::from_secs(2), client.is_available()).await {
                                            let req = AnalysisRequest {
                                                analysis_type: AnalysisType::MalwareClassification,
                                                input_data: AnalysisInput::DisassemblyCode {
                                                    instructions: report.instructions_sample.clone(),
                                                    architecture: report.architecture.clone(),
                                                    entry_point: 0,
                                                },
                                                model: None,
                                                context: std::collections::HashMap::new(),
                                            };
                                            if let Ok(Ok(result)) = timeout(Duration::from_secs(5), client.analyze(req)).await {
                                                let mut label = "malware".to_string();
                                                if let Some(tc) = &result.threat_classification {
                                                    let mt = tc.malware_type.iter().map(|s| s.to_lowercase()).collect::<Vec<_>>();
                                                    if mt.iter().any(|t| t.contains("ransom")) {
                                                        label = "ransomware".to_string();
                                                    } else if tc.family.to_lowercase().contains("trojan") {
                                                        label = "trojan".to_string();
                                                    } else if result.confidence < 0.4 {
                                                        label = "safe".to_string();
                                                    }
                                                } else if result.confidence < 0.4 {
                                                    label = "safe".to_string();
                                                }
                                                llm_analysis = Some(serde_json::json!({
                                                    "model_used": result.model_used,
                                                    "confidence": result.confidence,
                                                    "classification": label,
                                                    "findings": result.findings,
                                                    "threat_classification": result.threat_classification,
                                                }));
                                            }
                                        }
                                    }
                                }
                                // Compute simple risk scoring
                                let suspicious_count = report.suspicious.len() as f32;
                                let llm_conf = llm_analysis.as_ref()
                                    .and_then(|v| v.get("confidence").and_then(|c| c.as_f64()))
                                    .unwrap_or(0.0) as f32;
                                let risk_score = (0.2 + suspicious_count.min(10.0) * 0.08 + llm_conf * 0.7)
                                    .min(1.0);
                                let verdict = llm_analysis.as_ref()
                                    .and_then(|v| v.get("classification").and_then(|c| c.as_str()))
                                    .unwrap_or("unknown");
                                let explanation = format!(
                                    "{} suspicious; verdict: {} (conf {:.2}); examples: {}",
                                    report.suspicious.len(),
                                    verdict,
                                    llm_conf,
                                    report.suspicious.iter().take(3).map(|f| f.kind.clone()).collect::<Vec<_>>().join(", ")
                                );

                                disassembly = Some(serde_json::json!({
                                    "file_type": report.file_type,
                                    "architecture": report.architecture,
                                    "strings": report.strings,
                                    "suspicious": report.suspicious,
                                    "instructions_sample": report.instructions_sample,
                                    "explanation": explanation,
                                    "llm": llm_analysis,
                                    "risk_score": risk_score
                                }));
                            }
                        }

                        let success_payload = normalized_payload(
                            "yara_scan",
                            "yara_match",
                            Some(serde_json::json!({
                                "file": path.to_string_lossy(),
                                "matches": serialized_matches,
                                "ai": ai_section,
                                "disassembly": disassembly
                            })),
                            Some("YARA matches found"),
                            None,
                        );
                        // Persist detection record
                        {
                            use crate::metrics::database::{MetricsDatabase, DetectionRecord};
                            use chrono::Utc;
                            use sha2::{Digest, Sha256};
                            use std::fs;
                            let db_path = std::env::temp_dir().join("erdps_metrics.db");
                            if let Ok(db) = MetricsDatabase::new(db_path) {
                                let _ = db.initialize_schema();
                                let file_bytes = fs::read(&path).unwrap_or_default();
                                let mut hasher = Sha256::new();
                                hasher.update(&file_bytes);
                                let hash = format!("{:x}", hasher.finalize());
                                let prob = ai_section.as_ref().and_then(|v| v.get("probability")).and_then(|p| p.as_f64()).unwrap_or(1.0);
                                let threat_level = if prob >= 0.8 { "high" } else { "medium" };
                                let det = DetectionRecord {
                                    id: None,
                                    timestamp: Utc::now(),
                                    detection_id: uuid::Uuid::new_v4().to_string(),
                                    detection_type: "yara".to_string(),
                                    confidence_score: prob,
                                    threat_level: threat_level.to_string(),
                                    file_path: Some(path.to_string_lossy().to_string()),
                                    file_hash: Some(hash),
                                    file_size: Some(file_bytes.len() as i64),
                                    process_id: None,
                                    process_name: None,
                                    detection_engine: "yara+ember".to_string(),
                                    rule_name: serialized_matches.get(0).and_then(|m| m.get("rule")).and_then(|r| r.as_str()).map(|s| s.to_string()),
                                    mitigation_applied: false,
                                    false_positive: false,
                                    validated: false,
                                    validation_notes: None,
                                };
                                let _ = db.record_detection(&det);
                            }
                        }
                        increment_threats_detected(1);
                        ("success".to_string(), success_payload)
                    } else {
                        #[allow(unused_mut)]
                        let mut ai_section: Option<serde_json::Value> = None;
                        #[cfg(feature = "ai-integration")]
                        {
                            use crate::yara::ember_detector::EmberMalwareDetector;
                            use std::path::PathBuf;
                            let model_path = request
                                .payload
                                .get("model_path")
                                .and_then(|v| v.as_str())
                                .map(PathBuf::from)
                                .unwrap_or_else(|| PathBuf::from("agent/models/ember_model_real.onnx"));
                            let threshold = request
                                .payload
                                .get("threshold")
                                .and_then(|v| v.as_f64())
                                .map(|f| f as f32)
                                .unwrap_or(0.5);
                            if let Ok(mut detector) = EmberMalwareDetector::new_with_model_path(model_path.clone(), threshold) {
                                let _ = detector.initialize(Some(&model_path)).await;
                                if let Ok(score) = detector.predict(&path).await {
                                    ai_section = Some(serde_json::json!({
                                        "model_path": model_path,
                                        "probability": score.probability,
                                        "confidence": score.confidence,
                                        "is_malware": score.is_malware
                                    }));
                                }
                            }
                        }

                                #[allow(unused)]
                                let mut disassembly: Option<serde_json::Value> = None;
                                if request.payload.get("disassembly").and_then(|v| v.as_bool()).unwrap_or(false) {
                                    if let Ok(report) = crate::analysis::disassembly::analyze_file(path.clone()) {
                                        let _explanation = format!(
                                            "{} suspicious indicators; examples: {}",
                                            report.suspicious.len(),
                                            report.suspicious.iter().take(3).map(|f| f.kind.clone()).collect::<Vec<_>>().join(", ")
                                        );
                                        #[allow(unused_mut)]
                                        let mut llm_analysis: Option<serde_json::Value> = None;
                                        #[cfg(feature = "ai-integration")]
                                        {
                                            use crate::ai::{AIConfig, AnalysisInput, AnalysisRequest, AnalysisType};
                                            use crate::ai::ollama_client::OllamaClient;
                                            let mut ai_cfg = AIConfig::default();
                                            if let Some(model_override) = request.payload.get("llm_model").and_then(|v| v.as_str()) {
                                                ai_cfg.default_model = model_override.to_string();
                                            }
                                            ai_cfg.timeout_seconds = ai_cfg.timeout_seconds.min(5);
                                            ai_cfg.max_retries = 1;
                                            if let Ok(client) = OllamaClient::new(ai_cfg.clone()) {
                                                use tokio::time::{timeout, Duration};
                                                if let Ok(true) = timeout(Duration::from_secs(2), client.is_available()).await {
                                                    let req = AnalysisRequest {
                                                        analysis_type: AnalysisType::MalwareClassification,
                                                        input_data: AnalysisInput::DisassemblyCode {
                                                            instructions: report.instructions_sample.clone(),
                                                            architecture: report.architecture.clone(),
                                                            entry_point: 0,
                                                        },
                                                        model: None,
                                                        context: std::collections::HashMap::new(),
                                                    };
                                                    if let Ok(Ok(result)) = timeout(Duration::from_secs(5), client.analyze(req)).await {
                                                        // Map to simplified classification label
                                                        let mut label = "malware".to_string();
                                                        if let Some(tc) = &result.threat_classification {
                                                            let mt = tc.malware_type.iter().map(|s| s.to_lowercase()).collect::<Vec<_>>();
                                                            if mt.iter().any(|t| t.contains("ransom")) {
                                                                label = "ransomware".to_string();
                                                            } else if tc.family.to_lowercase().contains("trojan") {
                                                                label = "trojan".to_string();
                                                            } else if result.confidence < 0.4 {
                                                                label = "safe".to_string();
                                                            }
                                                        } else if result.confidence < 0.4 {
                                                            label = "safe".to_string();
                                                        }
                                                        llm_analysis = Some(serde_json::json!({
                                                            "model_used": result.model_used,
                                                            "confidence": result.confidence,
                                                            "classification": label,
                                                            "findings": result.findings,
                                                            "threat_classification": result.threat_classification,
                                                        }));
                                                    }
                                                }
                                            }
                                        }
                                let suspicious_count = report.suspicious.len() as f32;
                                let llm_conf = llm_analysis.as_ref()
                                    .and_then(|v| v.get("confidence").and_then(|c| c.as_f64()))
                                    .unwrap_or(0.0) as f32;
                                let risk_score = (0.2 + suspicious_count.min(10.0) * 0.08 + llm_conf * 0.7)
                                    .min(1.0);
                                let verdict = llm_analysis.as_ref()
                                    .and_then(|v| v.get("classification").and_then(|c| c.as_str()))
                                    .unwrap_or("unknown");
                                let explanation = format!(
                                    "{} suspicious; verdict: {} (conf {:.2}); examples: {}",
                                    report.suspicious.len(),
                                    verdict,
                                    llm_conf,
                                    report.suspicious.iter().take(3).map(|f| f.kind.clone()).collect::<Vec<_>>().join(", ")
                                );
                                disassembly = Some(serde_json::json!({
                                    "file_type": report.file_type,
                                    "architecture": report.architecture,
                                    "strings": report.strings,
                                    "suspicious": report.suspicious,
                                    "instructions_sample": report.instructions_sample,
                                    "explanation": explanation,
                                    "llm": llm_analysis,
                                    "risk_score": risk_score
                                }));
                            }
                        }

                        let complete_payload = normalized_payload(
                            "yara_scan",
                            "scan_complete",
                            Some(serde_json::json!({
                                "file": path.to_string_lossy(),
                                "matches_found": 0,
                                "ai": ai_section,
                                "disassembly": disassembly
                            })),
                            Some("Scan completed"),
                            None,
                        );
                        // Persist detection record (AI-only or clean)
                        {
                            use crate::metrics::database::{MetricsDatabase, DetectionRecord};
                            use chrono::Utc;
                            use sha2::{Digest, Sha256};
                            use std::fs;
                            let db_path = std::env::temp_dir().join("erdps_metrics.db");
                            if let Ok(db) = MetricsDatabase::new(db_path) {
                                let _ = db.initialize_schema();
                                let file_bytes = fs::read(&path).unwrap_or_default();
                                let mut hasher = Sha256::new();
                                hasher.update(&file_bytes);
                                let hash = format!("{:x}", hasher.finalize());
                                let prob = ai_section.as_ref().and_then(|v| v.get("probability")).and_then(|p| p.as_f64()).unwrap_or(0.0);
                                let threat_level = if prob >= 0.8 { "high" } else if prob >= 0.5 { "medium" } else { "low" };
                                let det = DetectionRecord {
                                    id: None,
                                    timestamp: Utc::now(),
                                    detection_id: uuid::Uuid::new_v4().to_string(),
                                    detection_type: if prob > 0.0 { "ai".to_string() } else { "none".to_string() },
                                    confidence_score: prob,
                                    threat_level: threat_level.to_string(),
                                    file_path: Some(path.to_string_lossy().to_string()),
                                    file_hash: Some(hash),
                                    file_size: Some(file_bytes.len() as i64),
                                    process_id: None,
                                    process_name: None,
                                    detection_engine: if prob > 0.0 { "ember".to_string() } else { "none".to_string() },
                                    rule_name: None,
                                    mitigation_applied: false,
                                    false_positive: false,
                                    validated: false,
                                    validation_notes: None,
                                };
                                let _ = db.record_detection(&det);
                            }
                        }
                        ("success".to_string(), complete_payload)
                    }
                }
                Err(e) => {
                    let error_payload = serde_json::json!({
                        "event_type": "error",
                        "context": "yara_scan",
                        "msg": e.to_string(),
                    });
                    ("error".to_string(), error_payload)
                }
            };
            set_last_scan_time(now);
            scan_result
        }
        "start_scan" => {
            let paths: Vec<std::path::PathBuf> = match request.payload.get("paths") {
                Some(serde_json::Value::Array(arr)) => arr
                    .iter()
                    .filter_map(|v| v.as_str())
                    .map(std::path::PathBuf::from)
                    .collect(),
                Some(serde_json::Value::String(s)) => vec![std::path::PathBuf::from(s)],
                _ => Vec::new(),
            };
            let job_id = format!("scan-{}", request.nonce);
            let total_paths = paths.len();
            let started_at = now;

            {
                let jobs = JOBS.get().unwrap();
                let mut guard = jobs.lock().unwrap();
                guard.insert(
                    job_id.clone(),
                    ScanJobStatus {
                        job_id: job_id.clone(),
                        total_paths,
                        scanned_paths: 0,
                        matches_found: 0,
                        started_at,
                        finished: false,
                    },
                );
            }

            let config_clone = Arc::clone(&config);
            let job_id_clone = job_id.clone();
            let task = tokio::spawn(async move {
                let engine = crate::detection::yara_engine::YaraEngine::new(Arc::clone(&config_clone));
                let _ = engine.load_rules(&config_clone.detection.yara_rules_path).await;
                for p in paths.iter() {
                    let res = engine.read_and_scan_file(p).await;
                    let jobs = JOBS.get().unwrap();
                    let mut guard = jobs.lock().unwrap();
                    if let Some(job) = guard.get_mut(&job_id_clone) {
                        job.scanned_paths += 1;
                        if let Ok(matches) = res {
                            if !matches.is_empty() {
                                job.matches_found += matches.len();
                                increment_threats_detected(matches.len() as u64);
                            }
                        }
                        if job.scanned_paths >= job.total_paths {
                            job.finished = true;
                        }
                    }
                }
            });
            if let Some(tasks) = JOB_TASKS.get() {
                let mut guard = tasks.lock().unwrap();
                guard.insert(job_id.clone(), task);
            }

            let payload = normalized_payload(
                "scan_job",
                "start",
                Some(serde_json::json!({
                    "job_id": job_id,
                    "total_paths": total_paths
                })),
                Some("Scan job accepted"),
                None,
            );
            ("success".to_string(), payload)
        }
        "get_job_status" => {
            let job_id = request.payload.get("job_id").and_then(|v| v.as_str()).unwrap_or("");
            let jobs = JOBS.get().unwrap();
            let guard = jobs.lock().unwrap();
            if let Some(job) = guard.get(job_id) {
                let payload = normalized_payload(
                    "scan_job",
                    "status",
                    Some(serde_json::json!({
                        "job_id": job.job_id,
                        "total_paths": job.total_paths,
                        "scanned_paths": job.scanned_paths,
                        "matches_found": job.matches_found,
                        "started_at": job.started_at,
                        "finished": job.finished
                    })),
                    None,
                    None,
                );
                ("success".to_string(), payload)
            } else {
                let err = normalized_payload(
                    "scan_job",
                    "error",
                    Some(serde_json::json!({ "job_id": job_id })),
                    Some("Job not found"),
                    Some("JOB_NOT_FOUND"),
                );
                ("error".to_string(), err)
            }
        }
        "stop_scan" => {
            let job_id = request.payload.get("job_id").and_then(|v| v.as_str()).unwrap_or("");
            let mut stopped = false;
            if let Some(tasks) = JOB_TASKS.get() {
                let mut guard = tasks.lock().unwrap();
                if let Some(handle) = guard.remove(job_id) {
                    handle.abort();
                    stopped = true;
                }
            }
            if let Some(jobs) = JOBS.get() {
                let mut guard = jobs.lock().unwrap();
                if let Some(job) = guard.get_mut(job_id) {
                    job.finished = true;
                }
            }
            let payload = normalized_payload(
                "scan_job",
                "stop",
                Some(serde_json::json!({ "job_id": job_id, "stopped": stopped })),
                None,
                None,
            );
            ("success".to_string(), payload)
        }
        _ => {
            let error_payload = normalized_payload(
                "ipc",
                "error",
                Some(serde_json::json!({ "command": request.command })),
                Some("Unknown command"),
                Some("UNKNOWN_COMMAND"),
            );
            ("error".to_string(), error_payload)
        }
    };

    // Generate response signature
    let signature = sign("response", now, &request.nonce, &payload, ipc_key).unwrap_or_else(|e| {
        error!("Failed to sign response: {e}");
        "invalid_signature".to_string()
    });

    ResponseMessage {
        nonce: request.nonce.clone(), // Echo the request nonce
        timestamp: now,
        status,
        payload,
        signature,
    }
}

pub async fn invoke_command_for_tests(
    request: &RequestMessage,
    ipc_key: &[u8],
    config: Arc<AgentConfig>,
) -> ResponseMessage {
    handle_command(request, ipc_key, config).await
}
