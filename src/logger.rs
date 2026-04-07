use anyhow::Result;
use flexi_logger::{Duplicate, FileSpec, Logger, WriteMode};
use std::path::Path;
use std::env;

/// Initialize the structured logger with console and file output
/// Format: [YYYY-MM-DD HH:MM:SS][LEVEL][MODULE] message
pub fn init_logger() -> Result<()> {
    // Create logs directory if it doesn't exist
    let logs_dir = Path::new("logs");
    if !logs_dir.exists() {
        std::fs::create_dir_all(logs_dir)?;
    }

    Logger::try_with_str("info")? // Default log level
        .log_to_file(
            FileSpec::default()
                .directory("logs")
                .basename("erdps_agent")
                .suffix("log"),
        )
        .duplicate_to_stderr(Duplicate::All) // Also log to console
        .write_mode(WriteMode::BufferAndFlush)
        .format_for_files(custom_format)
        .format_for_stderr(custom_format)
        .rotate(
            // Allow rotation speed override for tests via env var
            if env::var("ERDPS_LOG_ROTATION_TEST").ok().as_deref() == Some("1") {
                flexi_logger::Criterion::Age(flexi_logger::Age::Second)
            } else {
                flexi_logger::Criterion::Age(flexi_logger::Age::Day) // Daily rotation
            },
            flexi_logger::Naming::Timestamps,
            flexi_logger::Cleanup::KeepLogFiles(7), // Keep 7 days
        )
        .start()?;

    log::info!("Logger initialized successfully");
    Ok(())
}

/// Custom log format: [YYYY-MM-DD HH:MM:SS][LEVEL][MODULE] message
fn custom_format(
    w: &mut dyn std::io::Write,
    now: &mut flexi_logger::DeferredNow,
    record: &log::Record,
) -> Result<(), std::io::Error> {
    write!(
        w,
        "[{}][{}][{}] {}",
        now.format("%Y-%m-%d %H:%M:%S"),
        record.level(),
        record.module_path().unwrap_or("unknown"),
        record.args()
    )
}
