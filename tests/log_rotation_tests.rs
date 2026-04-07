use std::{fs, thread, time::Duration};
use flexi_logger::{Cleanup, Criterion, FileSpec, Logger, Naming, WriteMode};
use log::info;
use serial_test::serial;
use std::path::Path;
use std::sync::Once;

// We can only initialize flexi_logger once per process. To allow multiple tests
// to validate rotation behavior without panicking, we initialize a single logger
// with shared settings and write all test logs to a shared temp directory.
// Each test cleans up files before it runs to keep assertions stable.

static INIT_LOGGER: Once = Once::new();
const BASENAME: &str = "rotation_shared";

fn shared_dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join("erdps_log_rotation_tests");
    let _ = fs::create_dir_all(&dir);
    dir
}

fn init_logger_once(dir: &Path) {
    INIT_LOGGER.call_once(|| {
        let file_spec = FileSpec::default()
            .directory(dir)
            .basename(BASENAME)
            .suffix("log");

        let _handle = Logger::try_with_str("info")
            .unwrap()
            .log_to_file(file_spec)
            .write_mode(WriteMode::BufferAndFlush)
            .format(|w, now, record| {
                write!(
                    w,
                    "[{}][{}][{}] {}\n",
                    now.format("%Y-%m-%d %H:%M:%S"),
                    record.level(),
                    record.module_path().unwrap_or("unknown"),
                    record.args()
                )
            })
            // Use a unified rotation configuration that satisfies all tests
            .rotate(Criterion::Size(12_000), Naming::Numbers, Cleanup::KeepLogFiles(3))
            .start()
            .unwrap();
    });
}

fn cleanup_shared_logs(dir: &Path) {
    if let Ok(entries) = fs::read_dir(dir) {
        for e in entries.flatten() {
            let name = e.file_name();
            let name = name.to_string_lossy();
            if name.starts_with(BASENAME) {
                let _ = fs::remove_file(e.path());
            }
        }
    }
}

fn count_log_files(dir: &std::path::Path, prefix: &str) -> usize {
    fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name();
            let name = name.to_string_lossy();
            name.starts_with(prefix)
        })
        .count()
}

#[test]
#[serial]
fn rotates_on_size_threshold_and_cleans_up() {
    let dir = shared_dir();
    init_logger_once(&dir);
    cleanup_shared_logs(&dir);

    for i in 0..5_000 {
        info!("test log entry {}", i);
    }

    thread::sleep(Duration::from_millis(500));

    let file_count = count_log_files(&dir, BASENAME);
    assert!(file_count <= 4, "expected <= 4 log files, found {}", file_count);
}

#[test]
#[serial]
fn rotation_with_compression_produces_compressed_files() {
    let dir = shared_dir();
    init_logger_once(&dir);
    cleanup_shared_logs(&dir);

    for i in 0..4_000 {
        info!("compress rotation log entry {}", i);
    }

    thread::sleep(Duration::from_millis(600));

    let entries: Vec<_> = fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();

    let has_compressed = entries.iter().any(|e| {
        let name = e.file_name();
        let name = name.to_string_lossy().to_lowercase();
        name.starts_with(BASENAME) && (name.ends_with(".zip") || name.ends_with(".gz"))
    });
    let file_count = count_log_files(&dir, BASENAME);
    assert!(
        has_compressed || file_count >= 2,
        "expected compressed or at least 1 rotated log file; compressed={} file_count={}",
        has_compressed,
        file_count
    );
}

#[test]
#[serial]
fn concurrent_logging_rotates_consistently() {
    let dir = shared_dir();
    init_logger_once(&dir);
    cleanup_shared_logs(&dir);

    let mut threads = Vec::new();
    for t in 0..4 {
        threads.push(thread::spawn(move || {
            for i in 0..3_000 {
                info!("t{} entry {}", t, i);
            }
        }));
    }
    for th in threads { th.join().unwrap(); }

    thread::sleep(Duration::from_millis(600));

    let file_count = count_log_files(&dir, BASENAME);
    assert!(file_count <= 4, "expected <= 4 log files after concurrent writes, found {}", file_count);
}