use crate::config::AgentConfig;
use crate::mitigations::MitigationRequest;
use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc::{Receiver, Sender};
use crate::ai::{ollama_client::OllamaClient, AIConfig, AnalysisRequest, AnalysisType, AnalysisInput, Severity};
use tokio::task::JoinHandle;

/// File system event types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EventType {
    Created,
    Modified,
    Deleted,
    Renamed,
    Opened,
}

/// Structured event object for file system activity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub event_type: EventType,
    pub path: PathBuf,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
    pub timestamp: u64,                 // Unix timestamp in milliseconds
    pub extra: HashMap<String, String>, // Additional metadata
}

impl Event {
    pub fn new(event_type: EventType, path: PathBuf) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        Self {
            event_type,
            path,
            pid: None,
            process_name: None,
            timestamp,
            extra: HashMap::new(),
        }
    }

    pub fn with_process_info(mut self, pid: Option<u32>, process_name: Option<String>) -> Self {
        self.pid = pid;
        self.process_name = process_name;
        self
    }

    pub fn with_extra(mut self, key: String, value: String) -> Self {
        self.extra.insert(key, value);
        self
    }
}

/// Detection event for ransomware detection rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionEvent {
    pub rule_id: &'static str,
    pub severity: u8,
    pub description: String,
    pub related_process: Option<u32>, // PID
    pub related_files: Vec<PathBuf>,
    pub timestamp: DateTime<Utc>,
}

impl DetectionEvent {
    pub fn new(
        rule_id: &'static str,
        severity: u8,
        description: String,
        related_process: Option<u32>,
        related_files: Vec<PathBuf>,
    ) -> Self {
        Self {
            rule_id,
            severity,
            description,
            related_process,
            related_files,
            timestamp: Utc::now(),
        }
    }
}

/// Detection alert with rule information and evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionAlert {
    pub rule_id: String,
    pub score: u8, // 0-100
    pub evidence: Vec<String>,
    pub action_recommendation: String,
    pub timestamp: u64,
    pub affected_paths: Vec<PathBuf>,
    pub related_pids: Vec<u32>,
}

impl DetectionAlert {
    pub fn new(
        rule_id: String,
        score: u8,
        evidence: Vec<String>,
        action_recommendation: String,
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        Self {
            rule_id,
            score,
            evidence,
            action_recommendation,
            timestamp,
            affected_paths: Vec::new(),
            related_pids: Vec::new(),
        }
    }

    pub fn with_paths(mut self, paths: Vec<PathBuf>) -> Self {
        self.affected_paths = paths;
        self
    }

    pub fn with_pids(mut self, pids: Vec<u32>) -> Self {
        self.related_pids = pids;
        self
    }
}

// MitigationRequest is now imported from mitigations module

/// Detector struct for processing events and generating alerts
pub struct Detector {
    rx: Receiver<Event>,
    alert_tx: Sender<DetectionAlert>,
    mitigation_tx: Option<Sender<MitigationRequest>>,
    cfg: Arc<AgentConfig>,
    // Rule state tracking
    mass_modification_state: HashMap<PathBuf, VecDeque<(PathBuf, u64)>>, // directory -> (file_path, timestamp)
    extension_mutation_state: HashMap<PathBuf, (String, u64)>, // file -> (old_ext, timestamp)
    process_behavior_state: HashMap<u32, ProcessBehavior>,     // pid -> behavior
    ransom_note_patterns: Vec<Regex>,
    ollama: Option<OllamaClient>,
    // Cache for LLM verdicts: file_hash -> (DetectionEvent, timestamp)
    verdict_cache: lru::LruCache<String, (DetectionEvent, Instant)>,
}

#[derive(Debug, Clone)]
struct ProcessBehavior {
    write_count: u32,
    first_seen: Instant,
    last_activity: Instant,
    suspicious_files: Vec<PathBuf>,
}

impl Detector {
    pub fn new(
        rx: Receiver<Event>,
        alert_tx: Sender<DetectionAlert>,
        mitigation_tx: Option<Sender<MitigationRequest>>,
        cfg: Arc<AgentConfig>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Compile ransom note patterns from configuration
        let content_patterns = vec![
            r"(?i)your files have been encrypted",
            r"(?i)all your files are encrypted",
            r"(?i)files have been locked",
            r"(?i)pay.*bitcoin",
            r"(?i)ransom.*payment",
            r"(?i)decrypt.*files",
            r"(?i)contact.*email",
            r"(?i)\$[0-9]+.*bitcoin",
            r"(?i)readme.*decrypt",
            r"(?i)how.*to.*recover",
        ];

        let ransom_note_patterns = content_patterns
            .into_iter()
            .map(Regex::new)
            .collect::<Result<Vec<_>, _>>()?;

        let ollama = {
            let cfg = cfg.ai.clone().unwrap_or_else(|| AIConfig::default());
            match OllamaClient::new(cfg) {
                Ok(client) => Some(client),
                Err(_) => None,
            }
        };
        Ok(Self {
            rx,
            alert_tx,
            mitigation_tx,
            cfg,
            mass_modification_state: HashMap::new(),
            extension_mutation_state: HashMap::new(),
            process_behavior_state: HashMap::new(),
            ransom_note_patterns,
            ollama,
            verdict_cache: lru::LruCache::new(std::num::NonZeroUsize::new(1000).unwrap()),
        })
    }
}

/// Start the detector task
pub fn start_detector(detector: Detector) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut detector = detector;
        log::info!("Detector started, processing events...");

        while let Some(event) = detector.rx.recv().await {
            if let Err(e) = detector.process_event(event).await {
                log::error!("Error processing event: {e}");
            }
        }

        log::info!("Detector stopped");
    })
}

impl Detector {
    async fn process_event(
        &mut self,
        event: Event,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut detection_events = Vec::new();

        // Apply detection rules
        if let Some(detection_event) = self.check_mass_modification(&event)? {
            detection_events.push(detection_event);
        }

        if let Some(detection_event) = self.check_extension_mutation(&event)? {
            detection_events.push(detection_event);
        }

        if let Some(detection_event) = self.check_ransom_note_detection(&event).await? {
            detection_events.push(detection_event);
        }

        if let Some(detection_event) = self.check_entropy_analysis(&event).await? {
            detection_events.push(detection_event);
        }

        if let Some(detection_event) = self.check_process_behavior(&event)? {
            detection_events.push(detection_event);
        }

        if let Some(detection_event) = self.check_ai_classification(&event).await? {
            detection_events.push(detection_event);
        }

        // Process detection events
        for detection_event in detection_events {
            self.handle_detection_event(detection_event).await?;
        }

        Ok(())
    }

    async fn check_ai_classification(
        &mut self,
        event: &Event,
    ) -> Result<Option<DetectionEvent>, Box<dyn std::error::Error + Send + Sync>> {
        if self.ollama.is_none() {
            return Ok(None);
        }
        if !matches!(event.event_type, EventType::Created | EventType::Modified) {
            return Ok(None);
        }
        let meta = match tokio::fs::metadata(&event.path).await { Ok(m) => m, Err(_) => return Ok(None) };
        let size = meta.len();
        if size == 0 || size > 8_388_608 { // 8MB cap
            return Ok(None);
        }

        // Calculate MD5 hash for caching
        let file_content = match tokio::fs::read(&event.path).await { Ok(b) => b, Err(_) => return Ok(None) };
        let digest = md5::compute(&file_content);
        let hash = format!("{:x}", digest);

        // Check cache
        if let Some((cached_event, timestamp)) = self.verdict_cache.get(&hash) {
            if timestamp.elapsed() < Duration::from_secs(3600) { // 1 hour TTL
                 log::info!("Cache hit for LLM verdict: {}", hash);
                 let mut fresh_event = cached_event.clone();
                 fresh_event.timestamp = Utc::now(); // Update timestamp to now
                 return Ok(Some(fresh_event));
            }
        }

        let filename = event.path.file_name().and_then(|s| s.to_str()).unwrap_or("").to_string();
        let file_type = event.path.extension().and_then(|s| s.to_str()).unwrap_or("").to_string();
        
        let input = AnalysisInput::BinaryData { data: file_content, filename, file_type };
        let req = AnalysisRequest {
            analysis_type: AnalysisType::MalwareClassification,
            input_data: input,
            model: None,
            context: HashMap::new(),
        };
        let client = self.ollama.as_ref().unwrap();
        if !client.is_available().await { return Ok(None); }
        let res = match client.analyze(req).await { Ok(r) => r, Err(_) => return Ok(None) };
        let mut high = false;
        for f in &res.findings {
            if matches!(f.severity, Severity::High | Severity::Critical) && f.confidence >= 0.7 {
                high = true; break;
            }
        }
        let mut ransomware_hint = false;
        if let Some(tc) = &res.threat_classification {
            if tc.malware_type.iter().any(|t| t.to_lowercase().contains("ransom")) {
                ransomware_hint = true;
            }
        }
        if high || ransomware_hint || res.confidence >= 0.8 {
            let sev = if ransomware_hint || res.confidence >= 0.85 { 95 } else { 80 };
            let desc = format!("AI classification indicates malware: confidence {:.2}, model {}", res.confidence, res.model_used);
            let det = DetectionEvent::new(
                "ai_malware_classification",
                sev as u8,
                desc,
                event.pid,
                vec![event.path.clone()],
            );
            
            // Cache the result
            self.verdict_cache.put(hash, (det.clone(), Instant::now()));

            return Ok(Some(det));
        }
        Ok(None)
    }

    async fn handle_detection_event(
        &mut self,
        mut detection_event: DetectionEvent,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Hybrid Analysis: Automatically escalate suspicious events to LLM analysis
        // If the event is suspicious but not critical (e.g. score 50-80), and it involves files, check with LLM
        if detection_event.severity >= 50 && detection_event.severity < 90 && !detection_event.related_files.is_empty() {
            // Create a temporary event for the AI check
            let temp_event = Event::new(EventType::Modified, detection_event.related_files[0].clone())
                .with_process_info(detection_event.related_process, None);
            
            if let Ok(Some(ai_event)) = self.check_ai_classification(&temp_event).await {
                // If AI confirms it's malicious, upgrade the severity and description
                if ai_event.severity > detection_event.severity {
                    detection_event.severity = ai_event.severity;
                    detection_event.description = format!("{} (Confirmed by AI: {})", detection_event.description, ai_event.description);
                    detection_event.rule_id = "hybrid_ai_escalation";
                }
            }
        }

        // Log the detection event
        log::info!(
            "Detection Event: {} (severity: {}) - {}",
            detection_event.rule_id,
            detection_event.severity,
            detection_event.description
        );

        // Convert DetectionEvent to DetectionAlert for backward compatibility with existing alert channel
        let alert = DetectionAlert::new(
            detection_event.rule_id.to_string(),
            detection_event.severity,
            vec![detection_event.description.clone()],
            format!("Detection rule '{}' triggered", detection_event.rule_id),
        )
        .with_paths(detection_event.related_files.clone())
        .with_pids(detection_event.related_process.into_iter().collect());

        // Send alert through channel
        if let Err(e) = self.alert_tx.send(alert.clone()).await {
            log::error!("Failed to send alert: {e}");
        }

        // Check if mitigation is needed
        if u32::from(detection_event.severity) >= self.cfg.auto_quarantine_score {
            if let Some(mitigation_tx) = &self.mitigation_tx {
                let mitigation_request = crate::mitigations::MitigationRequest {
                    id: format!(
                        "detection-{}-{}",
                        detection_event.rule_id,
                        detection_event.timestamp.timestamp()
                    ),
                    action: crate::mitigations::MitigationAction::QuarantineFiles,
                    pid: detection_event.related_process,
                    files: detection_event.related_files.clone(),
                    quarantined_paths: vec![],
                    reason: format!(
                        "Detection event triggered: {} (severity: {})",
                        detection_event.rule_id, detection_event.severity
                    ),
                    score: detection_event.severity as u32,
                    dry_run: None,
                    require_confirmation: false,
                    timestamp: detection_event.timestamp.timestamp() as u64,
                };

                if let Err(e) = mitigation_tx.send(mitigation_request).await {
                    log::error!("Failed to send mitigation request: {e}");
                }
            }
        }

        Ok(())
    }

    /// Mass modification detection rule
    fn check_mass_modification(
        &mut self,
        event: &Event,
    ) -> Result<Option<DetectionEvent>, Box<dyn std::error::Error + Send + Sync>> {
        if !matches!(event.event_type, EventType::Created | EventType::Modified) {
            return Ok(None);
        }

        let dir = match event.path.parent() {
            Some(parent) => parent.to_path_buf(),
            None => return Ok(None),
        };

        let now = event.timestamp;
        let window_ms = self.cfg.mass_modification_window_secs.unwrap_or(60) * 1000;
        let threshold = self.cfg.mass_modification_count.unwrap_or(10) as usize;

        // Get or create timestamp queue for this directory - now tracks unique file paths with timestamps
        let file_timestamps = self
            .mass_modification_state
            .entry(dir.clone())
            .or_default();

        // Add current file path with timestamp (only if not already present in recent window)
        let file_path = event.path.clone();
        let mut should_add = true;

        // Check if this file was already modified recently (within a smaller dedup window)
        let dedup_window = 100; // 100ms deduplication window to avoid duplicate events
        for (path, timestamp) in file_timestamps.iter() {
            if path == &file_path && now - timestamp <= dedup_window {
                should_add = false;
                break;
            }
        }

        if should_add {
            file_timestamps.push_back((file_path, now));
        }

        // Remove old entries outside the detection window
        while let Some((_, front_time)) = file_timestamps.front() {
            if now - front_time > window_ms {
                file_timestamps.pop_front();
            } else {
                break;
            }
        }

        // Debug output for testing
        if file_timestamps.len() > 10 {
            // Only log when we have significant activity
            println!(
                "[DEBUG] mass_modification: {} files in directory {} (threshold: {})",
                file_timestamps.len(),
                dir.display(),
                threshold
            );
        }

        // Check if threshold exceeded (count unique files)
        if file_timestamps.len() >= threshold {
            let severity = std::cmp::min(100, 100 * file_timestamps.len() / threshold) as u8;
            let description = format!(
                 "Mass file modification detected: {} unique files modified in {} seconds in directory {} (threshold: {})",
                 file_timestamps.len(), window_ms / 1000, dir.display(), threshold
             );

            let related_files: Vec<PathBuf> = file_timestamps
                .iter()
                .map(|(path, _)| path.clone())
                .collect();

            let detection_event = DetectionEvent::new(
                "mass_modification",
                severity,
                description,
                event.pid,
                related_files,
            );

            return Ok(Some(detection_event));
        }

        Ok(None)
    }

    /// Extension mutation detection rule
    fn check_extension_mutation(
        &mut self,
        event: &Event,
    ) -> Result<Option<DetectionEvent>, Box<dyn std::error::Error + Send + Sync>> {
        if !matches!(event.event_type, EventType::Modified | EventType::Renamed) {
            return Ok(None);
        }

        let current_ext = event
            .path
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("");

        // Check for suspicious extensions
        let suspicious_extensions = [
            "encrypt",
            "encrypted",
            "locked",
            "crypt",
            "crypto",
            "enc",
            "lock",
            "xxx",
        ];
        if !suspicious_extensions.contains(&current_ext) {
            return Ok(None);
        }

        // Track extension changes
        let now = event.timestamp;
        let window_ms = self.cfg.extension_mutation_window_secs.unwrap_or(300) * 1000;

        // Count recent suspicious extension changes
        let mut suspicious_count = 0;
        let mut old_extensions = Vec::new();

        // Clean up old entries and count recent ones
        self.extension_mutation_state
            .retain(|_path, (old_ext, timestamp)| {
                if now - *timestamp <= window_ms {
                    suspicious_count += 1;
                    old_extensions.push(old_ext.clone());
                    true
                } else {
                    false
                }
            });

        // Add current change
        self.extension_mutation_state
            .insert(event.path.clone(), (current_ext.to_string(), now));
        suspicious_count += 1;

        let threshold_ratio = self.cfg.extension_mutation_threshold.unwrap_or(0.5);
        let total_files = self.extension_mutation_state.len();
        if total_files > 0 && (suspicious_count as f64 / total_files as f64) >= threshold_ratio {
            let severity = std::cmp::min(
                100,
                (90.0 * (suspicious_count as f64 / total_files as f64) / threshold_ratio) as u8,
            );
            let description = format!(
                "Extension mutation detected: {} files changed to suspicious extensions in {} seconds. Current extension: .{}, Previous extensions: {}",
                suspicious_count, window_ms / 1000, current_ext, old_extensions.join(", ")
            );

            let related_files: Vec<PathBuf> =
                self.extension_mutation_state.keys().cloned().collect();

            let detection_event = DetectionEvent::new(
                "extension_mutation",
                severity,
                description,
                event.pid,
                related_files,
            );

            return Ok(Some(detection_event));
        }

        Ok(None)
    }

    /// Ransom note detection rule
    async fn check_ransom_note_detection(
        &self,
        event: &Event,
    ) -> Result<Option<DetectionEvent>, Box<dyn std::error::Error + Send + Sync>> {
        if !matches!(event.event_type, EventType::Created | EventType::Modified) {
            return Ok(None);
        }

        let ext = event
            .path
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("");

        // Check for text files that could be ransom notes
        if !["txt", "html", "htm", "md", "readme"].contains(&ext) {
            // Check against configured ransom note filename patterns
            let filename = event
                .path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("");

            let filename_lower = filename.to_lowercase();
            let matches_pattern = self
                .cfg
                .ransom_note_patterns
                .iter()
                .any(|pattern| filename_lower.contains(&pattern.to_lowercase()));

            if !matches_pattern {
                return Ok(None);
            }
        }

        // Try to read file content (with size limit for safety)
        let content = match tokio::fs::read_to_string(&event.path).await {
            Ok(content) if content.len() <= 10240 => content, // 10KB limit
            Ok(_) => return Ok(None),                         // File too large
            Err(_) => return Ok(None),                        // Can't read file
        };

        // Check for ransom note patterns
        let mut matches = Vec::new();
        for (i, pattern) in self.ransom_note_patterns.iter().enumerate() {
            if pattern.is_match(&content) {
                matches.push(i);
            }
        }

        if !matches.is_empty() {
            let severity = std::cmp::min(100, 70 + (matches.len() * 10) as u8);
            let description = format!(
                "Ransom note patterns detected in file: {} (matched {} suspicious patterns, extension: .{})",
                event.path.display(),
                matches.len(),
                ext
            );

            let detection_event = DetectionEvent::new(
                "ransom_note_detection",
                severity,
                description,
                event.pid,
                vec![event.path.clone()],
            );

            return Ok(Some(detection_event));
        }

        Ok(None)
    }

    /// Entropy analysis detection rule
    async fn check_entropy_analysis(
        &self,
        event: &Event,
    ) -> Result<Option<DetectionEvent>, Box<dyn std::error::Error + Send + Sync>> {
        if !matches!(event.event_type, EventType::Modified | EventType::Created) {
            return Ok(None);
        }

        let ext = event
            .path
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("");

        // Skip binary files that are expected to have high entropy
        let binary_extensions = [
            "exe", "dll", "bin", "zip", "rar", "7z", "jpg", "jpeg", "png", "gif", "mp4", "avi",
            "mp3",
        ];
        if binary_extensions.contains(&ext) {
            return Ok(None);
        }

        // Read file for entropy analysis (with size limits)
        let metadata = match tokio::fs::metadata(&event.path).await {
            Ok(meta) => meta,
            Err(_) => return Ok(None),
        };

        let file_size = metadata.len();
        if file_size == 0 || file_size > 10_485_760 {
            // Skip empty files or files > 10MB
            return Ok(None);
        }

        // Sample chunks from the file
        let chunk_size = 4096;
        let sample_positions = [
            0,                                    // Beginning
            file_size / 2,                        // Middle
            file_size.saturating_sub(chunk_size), // End
        ];

        let mut total_entropy = 0.0;
        let mut chunks_analyzed = 0;

        for &pos in &sample_positions {
            if let Ok(chunk) = self.read_file_chunk(&event.path, pos, chunk_size).await {
                if !chunk.is_empty() {
                    let entropy = self.calculate_shannon_entropy(&chunk);
                    total_entropy += entropy;
                    chunks_analyzed += 1;
                }
            }
        }

        if chunks_analyzed == 0 {
            return Ok(None);
        }

        let avg_entropy = total_entropy / chunks_analyzed as f64;
        let entropy_threshold = self.cfg.entropy_threshold;

        if avg_entropy > entropy_threshold {
            let severity = std::cmp::min(100, (avg_entropy * 10.0) as u8);
            let description = format!(
                "High entropy detected: {:.2} bits/byte (threshold: {:.2}) in file {} (size: {} bytes, extension: .{})",
                avg_entropy,
                entropy_threshold,
                event.path.display(),
                file_size,
                ext
            );

            let detection_event = DetectionEvent::new(
                "entropy_analysis",
                severity,
                description,
                event.pid,
                vec![event.path.clone()],
            );

            return Ok(Some(detection_event));
        }

        Ok(None)
    }

    /// Process behavior detection rule
    fn check_process_behavior(
        &mut self,
        event: &Event,
    ) -> Result<Option<DetectionEvent>, Box<dyn std::error::Error + Send + Sync>> {
        let pid = match event.pid {
            Some(pid) => pid,
            None => return Ok(None),
        };

        if !matches!(event.event_type, EventType::Modified | EventType::Created) {
            return Ok(None);
        }

        let now = Instant::now();
        let behavior = self
            .process_behavior_state
            .entry(pid)
            .or_insert_with(|| ProcessBehavior {
                write_count: 0,
                first_seen: now,
                last_activity: now,
                suspicious_files: Vec::new(),
            });

        behavior.write_count += 1;
        behavior.last_activity = now;
        behavior.suspicious_files.push(event.path.clone());

        let window_duration = Duration::from_secs(self.cfg.process_behavior_window_secs);
        let write_threshold = self.cfg.process_behavior_write_threshold;

        // Check if process has been active within the window and exceeded write threshold
        if now.duration_since(behavior.first_seen) <= window_duration
            && behavior.write_count >= write_threshold
        {
            let severity = std::cmp::min(100, (80 * behavior.write_count / write_threshold) as u8);
            let description = format!(
                "Suspicious process behavior detected: Process {} ({}) performed {} file writes in {} seconds (threshold: {} writes)",
                pid,
                event.process_name.as_deref().unwrap_or("unknown"),
                behavior.write_count,
                window_duration.as_secs(),
                write_threshold
            );

            let detection_event = DetectionEvent::new(
                "process_behavior",
                severity,
                description,
                Some(pid),
                behavior.suspicious_files.clone(),
            );

            return Ok(Some(detection_event));
        }

        // Clean up old process behavior entries
        self.process_behavior_state.retain(|_, behavior| {
            now.duration_since(behavior.last_activity) <= window_duration * 2
        });

        Ok(None)
    }

    /// Helper function to read a chunk from a file
    async fn read_file_chunk(
        &self,
        path: &PathBuf,
        offset: u64,
        size: u64,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        use tokio::io::{AsyncReadExt, AsyncSeekExt};

        let mut file = tokio::fs::File::open(path).await?;
        file.seek(std::io::SeekFrom::Start(offset)).await?;

        let mut buffer = vec![0u8; size as usize];
        let bytes_read = file.read(&mut buffer).await?;
        buffer.truncate(bytes_read);

        Ok(buffer)
    }

    /// Calculate Shannon entropy for a byte sequence
    fn calculate_shannon_entropy(&self, data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut counts = [0u32; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }

        let len = data.len() as f64;
        let mut entropy = 0.0;

        for &count in &counts {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }

        entropy
    }
}

pub fn init() {
    log::info!("Detector module initialized.");
}
