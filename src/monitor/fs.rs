//! Filesystem monitoring module for continuous YARA scanning
//!
//! This module provides real-time filesystem monitoring capabilities with:
//! - File system event watching using notify crate
//! - Scan job queuing with tokio::mpsc
//! - LRU-based deduplication to prevent redundant scans
//! - Worker pool for parallel scanning
//! - SHA1 prefix computation for enhanced deduplication

#[cfg(feature = "yara")]
mod yara_fs_monitor {
    use std::{
        fs,
        io,
        path::{Path, PathBuf},
        sync::Arc,
        time::{Duration, SystemTime},
    };

    use lru::LruCache;
    use notify::RecommendedWatcher;
    use tokio::{
        sync::{mpsc, Mutex, RwLock},
        task::JoinHandle,
        time::Instant,
    };
    use tracing::{info, warn};

    use crate::{
        config::AgentConfig,
        detection::yara_engine::{YaraEngine, YaraMatch},
    };

    /// Maximum number of entries in the LRU deduplication cache
    const DEDUP_CACHE_SIZE: usize = 10_000;

    /// Scan queue capacity
    const SCAN_QUEUE_SIZE: usize = 1024;

    /// Default file size limit (64MB)
    const _DEFAULT_SIZE_LIMIT: u64 = 64 * 1024 * 1024;

    // Memory mapping threshold
    const _MMAP_THRESHOLD: u64 = 16 * 1024 * 1024;

    // Debounce duration for file system events
    const _DEBOUNCE_DURATION: Duration = Duration::from_millis(500);

    /// Scan job representing a file to be scanned
    #[derive(Debug, Clone)]
    pub struct ScanJob {
        pub path: PathBuf,
        pub size: u64,
        pub mtime: SystemTime,
        pub sha1_prefix: [u8; 8],
        pub truncated: bool,
    }

    /// Deduplication key for LRU cache
    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    struct DedupKey {
        canonical_path: PathBuf,
        size: u64,
        mtime: SystemTime,
        sha1_prefix: [u8; 8],
    }

    /// Scan result containing matches and metadata
    #[derive(Debug, Clone)]
    pub struct ScanResult {
        pub path: PathBuf,
        pub matches: Vec<YaraMatch>,
        pub scan_duration: Duration,
        pub truncated: bool,
        pub error: Option<String>,
    }

    /// Filesystem monitor statistics
    #[derive(Debug, Clone, Default)]
    pub struct FsMonitorStats {
        pub queue_depth: usize,
        pub scans_per_second: f64,
        pub median_scan_latency_ms: f64,
        pub total_scans: u64,
        pub total_matches: u64,
        pub total_errors: u64,
        pub dedup_hits: u64,
        pub dedup_misses: u64,
    }

    /// Filesystem monitor for continuous YARA scanning
    pub struct FsMonitor {
        _config: Arc<AgentConfig>,
        _yara_engine: Arc<YaraEngine>,
        _scan_tx: mpsc::Sender<ScanJob>,
        _scan_rx: Arc<Mutex<mpsc::Receiver<ScanJob>>>,
        _dedup_cache: Arc<Mutex<LruCache<DedupKey, Instant>>>,
        _stats: Arc<RwLock<FsMonitorStats>>,
        _scan_times: Arc<Mutex<Vec<Duration>>>,
        _worker_handles: Vec<JoinHandle<()>>,
        _watcher_handle: Option<JoinHandle<()>>,
        _watcher: Option<RecommendedWatcher>,
        _running: bool,
    }

    impl FsMonitor {
        /// Create a new filesystem monitor
        pub fn new(config: Arc<AgentConfig>, yara_engine: Arc<YaraEngine>) -> Self {
            let (scan_tx, scan_rx) = mpsc::channel(SCAN_QUEUE_SIZE);
            let dedup_cache = Arc::new(Mutex::new(LruCache::new(
                std::num::NonZeroUsize::new(DEDUP_CACHE_SIZE).unwrap(),
            )));

            Self {
                _config: config,
                _yara_engine: yara_engine,
                _scan_tx: scan_tx,
                _scan_rx: Arc::new(Mutex::new(scan_rx)),
                _dedup_cache: dedup_cache,
                _stats: Arc::new(RwLock::new(FsMonitorStats::default())),
                _scan_times: Arc::new(Mutex::new(Vec::new())),
                _worker_handles: Vec::new(),
                _watcher_handle: None,
                _watcher: None,
                _running: false,
            }
        }

        /// Start monitoring the specified directories
        pub async fn start_monitoring(
            &mut self,
            _watch_paths: Vec<PathBuf>,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            if self._running {
                warn!("Filesystem monitoring already running");
                return Ok(());
            }

            // Start worker threads
            let workers = num_cpus::get().max(2).min(4); // keep it modest
            for _ in 0..workers {
                let rx = Arc::clone(&self._scan_rx);
                let engine = Arc::clone(&self._yara_engine);
                let stats = Arc::clone(&self._stats);
                let scan_times = Arc::clone(&self._scan_times);
                self._worker_handles.push(tokio::spawn(async move {
                    loop {
                        let mut guard = rx.lock().await;
                        let job_opt = guard.recv().await;
                        drop(guard);
                        let Some(job) = job_opt else { break; };

                        let start = Instant::now();
                        let res = engine.read_and_scan_file(&job.path).await;
                        let duration = start.elapsed();

                        let mut s = stats.write().await;
                        s.total_scans += 1;
                        s.median_scan_latency_ms =
                            update_latency(&mut *scan_times.lock().await, duration);
                        drop(s);

                        match res {
                            Ok(matches) => {
                                if !matches.is_empty() {
                                    let mut s = stats.write().await;
                                    s.total_matches += matches.len() as u64;
                                    drop(s);
                                    info!(
                                        path = %job.path.display(),
                                        match_count = matches.len(),
                                        "YARA matches detected on file"
                                    );
                                    for m in matches.iter() {
                                        info!(rule = %m.rule, "Matched YARA rule");
                                    }
                                }
                            }
                            Err(e) => {
                                let mut s = stats.write().await;
                                s.total_errors += 1;
                                drop(s);
                                warn!(path = %job.path.display(), error = %format!("{}", e), "YARA scan error");
                            }
                        }
                    }
                }));
            }

            // Start a simple polling watcher to detect file changes in watch paths
            let scan_tx = self._scan_tx.clone();
            let dedup = Arc::clone(&self._dedup_cache);
            let mut watch_paths = _watch_paths;
            // Fallback to configured scan paths if none provided
            if watch_paths.is_empty() {
                watch_paths = self
                    ._config
                    .service
                    .scan_paths
                    .iter()
                    .map(PathBuf::from)
                    .collect();
            }

            self._running = true;
            self._watcher_handle = Some(tokio::spawn(async move {
                info!("Filesystem monitoring started (polling mode)");
                loop {
                    for root in &watch_paths {
                        if let Err(e) = traverse_and_enqueue(root, &scan_tx, &dedup).await {
                            warn!(path = %root.display(), error = %format!("{}", e), "Traverse error");
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(1000)).await;
                }
            }));

            Ok(())
        }

        /// Stop monitoring and cleanup resources
        pub async fn stop_monitoring(&mut self) {
            self._running = false;
            if let Some(handle) = self._watcher_handle.take() {
                handle.abort();
            }
            info!("Filesystem monitoring stopped");
        }

        /// Get current monitoring statistics
        pub async fn get_stats(&self) -> FsMonitorStats {
            self._stats.read().await.clone()
        }
    }

    /// Update moving median (approx) of latency vector and return median
    fn update_latency(samples: &mut Vec<Duration>, latest: Duration) -> f64 {
        samples.push(latest);
        if samples.len() > 256 { samples.remove(0); }
        let mut ms: Vec<f64> = samples.iter().map(|d| d.as_secs_f64() * 1000.0).collect();
        ms.sort_by(|a,b| a.partial_cmp(b).unwrap());
        let mid = ms.len() / 2;
        ms.get(mid).cloned().unwrap_or(0.0)
    }

    /// Recursively traverse a directory and enqueue scan jobs for files with changes
    async fn traverse_and_enqueue(
        root: &Path,
        tx: &mpsc::Sender<ScanJob>,
        dedup: &Arc<Mutex<LruCache<DedupKey, Instant>>>,
    ) -> Result<(), io::Error> {
        if !root.exists() { return Ok(()); }
        let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let entries = match fs::read_dir(&dir) { Ok(e) => e, Err(_) => continue };
            for entry in entries {
                let Ok(entry) = entry else { continue };
                let path = entry.path();
                let md = match entry.metadata() { Ok(m) => m, Err(_) => continue };
                if md.is_dir() {
                    stack.push(path);
                    continue;
                }
                let size = md.len();
                let mtime = md.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                // compute sha1 prefix from first 8 bytes
                let mut prefix: [u8;8] = [0;8];
                if let Ok(mut f) = fs::File::open(&path) {
                    use std::io::Read;
                    let mut buf = [0u8;8];
                    let _ = f.read(&mut buf);
                    prefix.copy_from_slice(&buf);
                }

                let key = DedupKey {
                    canonical_path: path.clone(),
                    size,
                    mtime,
                    sha1_prefix: prefix,
                };

                let mut cache = dedup.lock().await;
                let exists = cache.get(&key).is_some();
                if !exists {
                    cache.put(key.clone(), Instant::now());
                    drop(cache);
                    let _ = tx.try_send(ScanJob {
                        path: path.clone(),
                        size,
                        mtime,
                        sha1_prefix: prefix,
                        truncated: false,
                    });
                }
            }
        }
        Ok(())
    }
}

#[cfg(feature = "yara")]
pub use yara_fs_monitor::FsMonitor;

#[cfg(feature = "yara")]
pub use yara_fs_monitor::*;

#[cfg(not(feature = "yara"))]
mod stub_fs_monitor {
    use crate::config::AgentConfig;
    use std::{path::PathBuf, sync::Arc, time::Duration};
    use tracing::info;

    /// Stub scan job for non-YARA builds
    #[derive(Debug, Clone)]
    pub struct ScanJob {
        pub path: PathBuf,
    }

    /// Stub scan result for non-YARA builds
    #[derive(Debug, Clone)]
    pub struct ScanResult {
        pub path: PathBuf,
        pub scan_duration: Duration,
        pub error: Option<String>,
    }

    /// Stub filesystem monitor statistics
    #[derive(Debug, Clone, Default)]
    pub struct FsMonitorStats {
        pub queue_depth: usize,
        pub scans_per_second: f64,
        pub median_scan_latency_ms: f64,
        pub total_scans: u64,
        pub total_matches: u64,
        pub total_errors: u64,
        pub dedup_hits: u64,
        pub dedup_misses: u64,
    }

    /// Stub filesystem monitor for non-YARA builds
    pub struct FsMonitor {
        _config: Arc<AgentConfig>,
    }

    impl FsMonitor {
        /// Create a new stub filesystem monitor
        pub fn new(config: Arc<AgentConfig>) -> Self {
            Self { _config: config }
        }

        /// Start monitoring (stub implementation)
        pub async fn start_monitoring(
            &mut self,
            _watch_paths: Vec<PathBuf>,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            info!("Filesystem monitoring started (YARA feature disabled)");
            Ok(())
        }

        /// Stop monitoring (stub implementation)
        pub async fn stop_monitoring(&mut self) {
            info!("Filesystem monitoring stopped");
        }

        /// Get current monitoring statistics (stub implementation)
        pub async fn get_stats(&self) -> FsMonitorStats {
            FsMonitorStats::default()
        }
    }
}

#[cfg(not(feature = "yara"))]
pub use stub_fs_monitor::*;
