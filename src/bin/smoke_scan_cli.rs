use std::path::PathBuf;
use std::time::Instant;

use erdps_agent::config::yara_config::{ensure_default_config, load_yara_config};
use erdps_agent::yara::{rule_loader::YaraRuleLoader, file_scanner::YaraFileScanner};

#[derive(Debug, Clone)]
struct Options {
    mode: String,
    path: Option<PathBuf>,
    json: bool,
    limit: Option<usize>,
    quarantine: bool,
    include: Option<Vec<String>>, 
    exclude: Option<Vec<String>>, 
    scan_all: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self { mode: "quick".to_string(), path: None, json: false, limit: Some(50), quarantine: false, include: None, exclude: None, scan_all: true }
    }
}

fn print_usage() {
    use indoc::indoc;
    println!("{}", indoc! {"
        Smoke Scan CLI
        
        Usage:
        \tsmoke_scan_cli --mode <file|dir|quick> [--path <path>] [--json] [--limit <N>]
        
        Examples:
        \tsmoke_scan_cli --mode file --path C:\\Temp\\eicar.txt
        \tsmoke_scan_cli --mode dir --path C:\\Downloads
        \tsmoke_scan_cli --mode quick --limit 20
    "});
}

fn parse_args() -> Options {
    let mut opts = Options::default();
    let mut args = std::env::args().skip(1).peekable();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            "--mode" => {
                if let Some(v) = args.next() { opts.mode = v; }
            }
            "--path" => {
                if let Some(v) = args.next() { opts.path = Some(PathBuf::from(v)); }
            }
            "--json" => { opts.json = true; }
            "--quarantine" => { opts.quarantine = true; }
            "--include" => {
                if let Some(v) = args.next() { 
                    let exts = v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect::<Vec<_>>();
                    if !exts.is_empty() { opts.include = Some(exts); }
                }
            }
            "--exclude" => {
                if let Some(v) = args.next() { 
                    let exts = v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect::<Vec<_>>();
                    if !exts.is_empty() { opts.exclude = Some(exts); }
                }
            }
            "--scan-all" => { opts.scan_all = true; }
            "--limit" => {
                if let Some(v) = args.next() {
                    opts.limit = v.parse::<usize>().ok();
                }
            }
            unknown => {
                eprintln!("Unknown argument: {}", unknown);
                print_usage();
                std::process::exit(2);
            }
        }
    }

    opts
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opts = parse_args();

    // Ensure a default config file exists, then load config
    let _ = ensure_default_config();
    let mut config = load_yara_config();
    let effective_scan_all = opts.scan_all || (opts.include.is_none() && opts.exclude.is_none());
    if let Some(inc) = opts.include.clone() {
        config.yara.file_extensions = inc;
    } else if let Some(exc) = opts.exclude.clone() {
        config.yara.file_extensions = config
            .yara
            .file_extensions
            .into_iter()
            .filter(|e| !exc.iter().any(|x| x.eq_ignore_ascii_case(e)))
            .collect::<Vec<_>>();
    } else if effective_scan_all {
        config.yara.file_extensions = Vec::new();
    }

    // Initialize rule loader
    let rules_dir = PathBuf::from(&config.yara.rules_path);
    let loader = YaraRuleLoader::new(&rules_dir, false);
    loader.initialize()?;

    // Initialize scanner and verify readiness
    let scanner = YaraFileScanner::new(std::sync::Arc::new(loader), std::sync::Arc::new(config));
    if !scanner.is_ready() || scanner.rule_count() == 0 {
        eprintln!(
            "Scanner not ready or no rules loaded. Populate '{}' or run the downloader.",
            rules_dir.display()
        );
        std::process::exit(1);
    }

    // Dispatch by mode
    match opts.mode.as_str() {
        "file" => {
            let path = opts.path.clone().ok_or("--path is required for --mode file")?;
            run_file_scan(&scanner, path, opts.json).await?;
        }
        "dir" => {
            let path = opts.path.clone().ok_or("--path is required for --mode dir")?;
            run_dir_scan(&scanner, path, opts.json, opts.quarantine, opts.include.clone(), opts.exclude.clone(), effective_scan_all).await?;
        }
        _ => {
            // quick mode: scan a small set from configured directories
            let limit = opts.limit.unwrap_or(50);
            run_quick_scan(&scanner, limit, opts.json).await?;
        }
    }

    Ok(())
}

async fn run_file_scan(
    scanner: &YaraFileScanner,
    path: PathBuf,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let start = Instant::now();
    let res = scanner.scan_file(&path).await?;
    let dur_ms = start.elapsed().as_millis() as u64;

    if json {
        let out = serde_json::json!({
            "type": "file",
            "path": path.display().to_string(),
            "duration_ms": dur_ms,
            "skipped": res.skipped,
            "skip_reason": res.skip_reason,
            "error": res.error,
            "file_size": res.file_size,
            "matches": res.matches.iter().map(|m| {
                serde_json::json!({
                    "rule": m.rule_name,
                    "namespace": m.namespace,
                    "tags": m.tags,
                    "metadata": m.metadata,
                })
            }).collect::<Vec<_>>()
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!("== File Scan ==");
        println!("path: {}", path.display());
        println!("duration_ms: {}", dur_ms);
        if res.skipped { println!("skipped: {}", res.skip_reason.unwrap_or_default()); }
        if let Some(e) = &res.error { println!("error: {}", e); }
        println!("matches: {}", res.matches.len());
        for m in &res.matches { println!("- {} [{}]", m.rule_name, m.tags.join(",")); }
    }

    Ok(())
}

async fn run_dir_scan(
    scanner: &YaraFileScanner,
    dir: PathBuf,
    json: bool,
    quarantine: bool,
    include: Option<Vec<String>>,
    exclude: Option<Vec<String>>,
    scan_all: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let start = Instant::now();
    let results = scanner.scan_directory(&dir, true).await?;
    let dur_ms = start.elapsed().as_millis() as u64;

    let total_files = results.len();
    let total_matches: usize = results.iter().map(|r| r.matches.len()).sum();
    let skipped: usize = results.iter().filter(|r| r.skipped).count();

    if json {
        let out = serde_json::json!({
            "type": "dir",
            "path": dir.display().to_string(),
            "duration_ms": dur_ms,
            "files": total_files,
            "skipped": skipped,
            "total_matches": total_matches,
            "include": include,
            "exclude": exclude,
            "scan_all": scan_all,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!("== Directory Scan ==");
        println!("path: {}", dir.display());
        println!("duration_ms: {}", dur_ms);
        println!("files: {}  skipped: {}  matches: {}", total_files, skipped, total_matches);
    }

    if quarantine {
        let mut matched_files: Vec<PathBuf> = Vec::new();
        for r in &results {
            if !r.matches.is_empty() { matched_files.push(r.file_path.clone()); }
        }
        if !matched_files.is_empty() {
            let cfg = erdps_agent::config::agent_config::AgentConfig::default();
            match erdps_agent::mitigations::quarantine_files(&matched_files, &cfg).await {
                Ok(qpaths) => {
                    println!("quarantined: {}", qpaths.len());
                }
                Err(e) => {
                    println!("quarantine_error: {}", e);
                }
            }
        }
    }
    Ok(())
}

async fn run_quick_scan(
    scanner: &YaraFileScanner,
    limit: usize,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let start = Instant::now();
    let mut scanned = 0usize;
    let mut total_matches = 0usize;
    let mut skipped = 0usize;
    let mut errors = 0usize;

    // Sample from configured directories
    let config = load_yara_config();
    'outer: for d in &config.yara.scan_directories {
        let dir = PathBuf::from(d);
        if !dir.exists() { continue; }
        match std::fs::read_dir(&dir) {
            Ok(entries) => {
                for entry in entries {
                    let path = match entry {
                        Ok(e) => e.path(),
                        Err(_) => { errors += 1; continue; }
                    };
                    if path.is_file() {
                        match scanner.scan_file(&path).await {
                            Ok(res) => {
                                scanned += 1;
                                total_matches += res.matches.len();
                                if res.skipped { skipped += 1; }
                                if scanned >= limit { break 'outer; }
                            }
                            Err(_) => {
                                errors += 1;
                                // continue to next file
                            }
                        }
                    }
                }
            }
            Err(_) => {
                // unreadable directory, skip
                errors += 1;
                continue;
            }
        }
    }

    let dur_ms = start.elapsed().as_millis() as u64;

    if json {
        let out = serde_json::json!({
            "type": "quick",
            "duration_ms": dur_ms,
            "files": scanned,
            "skipped": skipped,
            "total_matches": total_matches,
            "errors": errors,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!("== Quick Scan ==");
        println!("duration_ms: {}", dur_ms);
        println!("files: {}  skipped: {}  matches: {}  errors: {}", scanned, skipped, total_matches, errors);
    }

    Ok(())
}
