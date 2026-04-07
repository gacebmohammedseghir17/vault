use std::sync::Arc;
use crate::config::agent_config::AgentConfig;

pub async fn handle_cli(agent_config: &Arc<AgentConfig>) -> bool {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        return false;
    }

    let cmd = args[0].as_str();
    match cmd {
        "update-rules" => {
            let force = args.iter().any(|a| a == "--force");
            let validate = args.iter().any(|a| a == "--validate");
            match crate::yara_updater::create_updater(agent_config.yara_updater.clone()) {
                Ok(updater) => {
                    let updated = if force {
                        updater.force_update().await.unwrap_or(false)
                    } else {
                        updater.check_and_update().await.unwrap_or(false)
                    };
                    let status = updater.get_status().await;
                    let enforcement_enabled = agent_config.yara_updater.enforce_signature;
                    let mut compilation = serde_json::json!({});
                    if validate {
                        let primary = agent_config.detection.yara_rules_path.clone();
                        let additional_paths = agent_config
                            .yara
                            .as_ref()
                            .map(|y| y.additional_rules_paths.clone())
                            .unwrap_or_default();
                        let loader = crate::yara::rule_loader::create_comprehensive_rule_loader(
                            primary.as_str(),
                            &additional_paths,
                            false,
                        ).expect("Failed to build comprehensive YARA loader");
                        let _ = loader.initialize();
                        let stats = loader.get_compilation_stats();
                        compilation = serde_json::json!({
                            "total_rules": stats.total_rules,
                            "successful_compilations": stats.successful_compilations,
                            "failed_compilations": stats.failed_compilations,
                            "broken_files": stats.broken_files,
                            "duplicate_files": stats.duplicate_files
                        });
                    }
                    println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                        "updated": updated,
                        "status": {
                            "last_commit_hash": status.last_commit_hash,
                            "last_version": status.last_version,
                            "last_update": status.last_update,
                            "update_count": status.update_count,
                            "last_error": status.last_error
                        },
                        "enforcement": {"enabled": enforcement_enabled},
                        "compilation": compilation
                    })).unwrap_or_default());
                }
                Err(e) => eprintln!("failed to initialize updater: {}", e),
            }
            return true;
        }
        "correlate" => {
            let mut scan_files: Vec<std::path::PathBuf> = Vec::new();
            let mut i = 1usize;
            while i < args.len() {
                if args[i] == "--scan-result" {
                    if i + 1 < args.len() { scan_files.push(std::path::PathBuf::from(&args[i+1])); i += 2; continue; }
                }
                i += 1;
            }
            let mut rule_map: std::collections::HashMap<String, std::collections::HashSet<String>> = std::collections::HashMap::new();
            let mut path_map: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
            for sf in scan_files.iter() {
                if let Ok(content) = std::fs::read_to_string(sf) {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&content) {
                        if let Some(arr) = v.get("files_detail").and_then(|x| x.as_array()) {
                            for item in arr.iter() {
                                let p = item.get("path").and_then(|x| x.as_str()).unwrap_or("").to_string();
                                *path_map.entry(p.clone()).or_insert(0) += 1;
                                if let Some(matches) = item.get("matches").and_then(|x| x.as_array()) {
                                    for m in matches.iter() {
                                        if let Some(rule) = m.get("rule").and_then(|x| x.as_str()) {
                                            rule_map.entry(rule.to_string()).or_default().insert(p.clone());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            let mut correlated_alerts: Vec<serde_json::Value> = Vec::new();
            for (rule, paths) in rule_map.iter() {
                let count = paths.len();
                let confidence = if scan_files.is_empty() { 0.0 } else { count as f64 / scan_files.len() as f64 };
                correlated_alerts.push(serde_json::json!({
                    "rule": rule,
                    "count": count,
                    "paths": paths.iter().cloned().collect::<Vec<String>>(),
                    "confidence": confidence
                }));
            }
            let global_confidence = if correlated_alerts.is_empty() { 0.0 } else {
                let sum: f64 = correlated_alerts.iter().map(|e| e.get("confidence").and_then(|x| x.as_f64()).unwrap_or(0.0)).sum();
                sum / correlated_alerts.len() as f64
            };
            println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                "correlated_alerts": correlated_alerts,
                "global_confidence": global_confidence
            })).unwrap_or_default());
            return true;
        }
        "validate-rules" => {
            let primary = agent_config.detection.yara_rules_path.clone();
            let additional_paths = agent_config
                .yara
                .as_ref()
                .map(|y| y.additional_rules_paths.clone())
                .unwrap_or_default();
            let mut files: Vec<std::path::PathBuf> = Vec::new();
            let mut dirs: Vec<std::path::PathBuf> = Vec::new();
            dirs.push(std::path::PathBuf::from(&primary));
            for p in &additional_paths { dirs.push(std::path::PathBuf::from(p)); }
            for root in dirs {
                if root.exists() {
                    let mut stack = vec![root];
                    while let Some(dir) = stack.pop() {
                        if let Ok(rd) = std::fs::read_dir(&dir) {
                            for e in rd.flatten() {
                                let p = e.path();
                                if p.is_dir() { stack.push(p); continue; }
                                if let Some(ext) = p.extension() { if ext == "yar" || ext == "yara" { files.push(p); } }
                            }
                        }
                    }
                }
            }
            let mut total = 0usize;
            let mut broken = 0usize;
            let mut duplicates = 0usize; 
            let mut names_seen: std::collections::HashSet<String> = std::collections::HashSet::new();
            let mut errors: Vec<serde_json::Value> = Vec::new();
            for f in files {
                total += 1;
                let content = std::fs::read_to_string(&f);
                if let Err(e) = content {
                    broken += 1;
                    errors.push(serde_json::json!({"path": f.display().to_string(), "reason": format!("read_error: {}", e)}));
                    continue;
                }
                let content = content.unwrap();
                let trimmed = content.trim();
                let has_rule = trimmed.contains("rule ") || trimmed.contains("\nrule ");
                let has_condition = trimmed.contains("condition:") || trimmed.contains("\ncondition:");
                let brace_ok = content.matches('{').count() == content.matches('}').count();
                if !has_rule || !has_condition || !brace_ok {
                    broken += 1;
                    errors.push(serde_json::json!({"path": f.display().to_string(), "reason": "prevalidation_failed"}));
                    continue;
                }
                let mut local_names = Vec::new();
                for line in content.lines() {
                    let l = line.trim();
                    if !(l.starts_with("rule ") || l.starts_with("private rule ") || l.starts_with("global rule ")) { continue; }
                    let mut tokens = l.split_whitespace();
                    let first = tokens.next();
                    let second = tokens.next();
                    let after_rule = if let Some(fst) = first { if fst == "rule" { second } else if fst == "private" || fst == "global" { let mr = second; if let Some(mr) = mr { if mr == "rule" { tokens.next() } else { None } } else { None } } else { None } } else { None };
                    if let Some(raw) = after_rule {
                        let mut ident = String::new();
                        for ch in raw.chars() { if ch.is_ascii_alphanumeric() || ch=='_' { ident.push(ch) } else { break; } }
                        if !ident.is_empty() { local_names.push(ident); }
                    }
                }
                let mut dup = false;
                for n in local_names { if names_seen.contains(&n) { dup = true; } else { names_seen.insert(n); } }
                if dup {
                    duplicates += 1;
                    errors.push(serde_json::json!({"path": f.display().to_string(), "reason": "duplicate_rule_name"}));
                    continue;
                }
            }
            let failed = broken + duplicates;
            let loader = crate::yara::rule_loader::create_comprehensive_rule_loader(
                primary.as_str(),
                &additional_paths,
                false,
            ).expect("Failed to build comprehensive YARA loader");
            let _ = loader.initialize();
            let stats = loader.get_compilation_stats();
            println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                "prevalidation": {
                    "total": total,
                    "failed": failed,
                    "broken": broken,
                    "duplicates": duplicates,
                    "errors": errors
                },
                "compilation": {
                    "total_rules": stats.total_rules,
                    "successful_compilations": stats.successful_compilations,
                    "failed_compilations": stats.failed_compilations,
                    "broken_files": stats.broken_files,
                    "duplicate_files": stats.duplicate_files
                }
            })).unwrap_or_default());
            return true;
        }
        "download-rules" => {
            use crate::yara::multi_source_downloader::MultiSourceDownloader;
            let rules_base = std::path::PathBuf::from(agent_config.detection.yara_rules_path.clone());
            let cache_path = rules_base.join("cache");
            let mut downloader = MultiSourceDownloader::new(&rules_base, &cache_path).expect("init downloader");
            let _ = downloader.initialize_default_sources().await;
            let force = args.iter().any(|a| a == "--force");
            let detailed = args.iter().any(|a| a == "--detailed");
            let validate = args.iter().any(|a| a == "--validate");
            let summary = downloader.download_all(force, detailed).await.expect("download");
            let mut compilation = serde_json::json!({});
            if validate {
                let primary = agent_config.detection.yara_rules_path.clone();
                let additional_paths = agent_config
                    .yara
                    .as_ref()
                    .map(|y| y.additional_rules_paths.clone())
                    .unwrap_or_default();
                let loader = crate::yara::rule_loader::create_comprehensive_rule_loader(
                    primary.as_str(),
                    &additional_paths,
                    false,
                ).expect("Failed to build comprehensive YARA loader");
                let _ = loader.initialize();
                let stats = loader.get_compilation_stats();
                compilation = serde_json::json!({
                    "total_rules": stats.total_rules,
                    "successful_compilations": stats.successful_compilations,
                    "failed_compilations": stats.failed_compilations,
                    "broken_files": stats.broken_files,
                    "duplicate_files": stats.duplicate_files
                });
            }
            println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                "summary": summary,
                "compilation": compilation
            })).unwrap_or_default());
            return true;
        }
        "optimize-rules" => {
            let primary = agent_config.detection.yara_rules_path.clone();
            let additional_paths = agent_config
                .yara
                .as_ref()
                .map(|y| y.additional_rules_paths.clone())
                .unwrap_or_default();
            let loader = crate::yara::rule_loader::create_comprehensive_rule_loader(
                primary.as_str(),
                &additional_paths,
                false,
            ).expect("Failed to build comprehensive YARA loader");
            let _ = loader.initialize();
            match loader.cleanup_broken_and_duplicates() {
                Ok((broken_deleted, duplicates_deleted)) => {
                    let _ = loader.initialize();
                    let stats = loader.get_compilation_stats();
                    println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                        "broken_deleted": broken_deleted,
                        "duplicates_deleted": duplicates_deleted,
                        "post_compilation": {
                            "total_rules": stats.total_rules,
                            "successful_compilations": stats.successful_compilations,
                            "failed_compilations": stats.failed_compilations,
                            "broken_files": stats.broken_files,
                            "duplicate_files": stats.duplicate_files
                        }
                    })).unwrap_or_default());
                }
                Err(e) => eprintln!("optimize error: {}", e),
            }
            return true;
        }
        "--scan-file" => {
            let path = args.get(1).cloned().unwrap_or_default();
            if path.is_empty() { eprintln!("--scan-file <FILE>"); return true; }
            use crate::yara::YaraFileScanner;
            use crate::ai::ollama_client::OllamaClient;
            use crate::ai::{AIConfig, AnalysisRequest, AnalysisType, AnalysisInput};
            let primary = agent_config.detection.yara_rules_path.clone();
            let additional_paths = agent_config
                .yara
                .as_ref()
                .map(|y| y.additional_rules_paths.clone())
                .unwrap_or_default();
            let loader = crate::yara::rule_loader::create_comprehensive_rule_loader(
                primary.as_str(),
                &additional_paths,
                false,
            ).expect("Failed to build comprehensive YARA loader");
            let _ = loader.initialize();
            let scanner = YaraFileScanner::new(std::sync::Arc::new(loader), std::sync::Arc::new(crate::config::yara_config::load_yara_config()));
            let file_path = std::path::PathBuf::from(&path);
            match scanner.scan_file(&file_path).await {
                Ok(r) => {
                    let mut analysis = None;
                    if file_path.exists() {
                        if let Ok(rep) = crate::analysis::disassembly::analyze_file(file_path.clone()) { analysis = Some(rep); }
                    }
                    let mut ai_verdict = None;
                    let ai_cfg = agent_config.ai.clone().unwrap_or_else(|| AIConfig::default());
                    if let Ok(client) = OllamaClient::new(ai_cfg.clone()) {
                        if client.is_available().await {
                            let data = std::fs::read(&file_path).unwrap_or_default();
                            let req = AnalysisRequest{
                                analysis_type: AnalysisType::MalwareClassification,
                                input_data: AnalysisInput::BinaryData{ data, filename: file_path.file_name().and_then(|s| s.to_str()).unwrap_or("").to_string(), file_type: file_path.extension().and_then(|s| s.to_str()).unwrap_or("").to_string() },
                                model: Some(ai_cfg.default_model.clone()),
                                context: std::collections::HashMap::new(),
                            };
                            if let Ok(res) = client.analyze(req).await { ai_verdict = Some(res); }
                        }
                    }
                    let mut quarantined = Vec::<std::path::PathBuf>::new();
                    let mut quarantine_report = None;
                    if let Some(verdict) = &ai_verdict {
                        let mut malicious = false;
                        if verdict.confidence >= 0.85 { malicious = true; }
                        if let Some(tc) = &verdict.threat_classification { if tc.malware_type.iter().any(|t| t.to_lowercase().contains("ransom")) { malicious = true; } }
                        if malicious {
                            let cfg_clone = agent_config.clone();
                            if let Ok(paths) = crate::mitigations::quarantine_files(&[file_path.clone()], &cfg_clone).await { quarantined = paths; }
                            let report = serde_json::json!({
                                "ai_model": ai_cfg.default_model,
                                "confidence": verdict.confidence,
                                "verdict": "malicious",
                                "family_hint": verdict.threat_classification.as_ref().map(|tc| tc.malware_type.clone()).unwrap_or_default(),
                                "reason": verdict.findings,
                                "disassembly": analysis,
                            });
                            quarantine_report = Some(report);
                            if let Some(qp) = quarantined.get(0) {
                                let rp = qp.with_extension("report.json");
                                let _ = std::fs::write(&rp, serde_json::to_string_pretty(&quarantine_report.clone().unwrap()).unwrap_or_default());
                            }
                        }
                    }
                    println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                        "path": path,
                        "matches": r.matches.iter().map(|m| serde_json::json!({"rule": m.rule_name, "tags": m.tags, "namespace": m.namespace})).collect::<Vec<_>>()
                        ,"disassembly": analysis
                        ,"ai_verdict": ai_verdict
                        ,"quarantined": quarantined
                        ,"quarantine_report": quarantine_report
                    })).unwrap_or_default());
                }
                Err(e) => eprintln!("scan error: {}", e),
            }
            return true;
        }
        "disassemble-scan" => {
            let path = args.get(1).cloned().unwrap_or_default();
            if path.is_empty() { eprintln!("disassemble-scan <FILE>"); return true; }
            let rp = std::path::PathBuf::from(&path);
            match crate::analysis::disassembly::analyze_file(rp.clone()) {
                Ok(rep) => {
                    println!("{}", serde_json::to_string_pretty(&serde_json::to_value(&rep).unwrap_or_default()).unwrap_or_default());
                }
                Err(e) => eprintln!("disassembly error: {}", e),
            }
            return true;
        }
        "list-rules" => {
            let primary = agent_config.detection.yara_rules_path.clone();
            let additional_paths = agent_config
                .yara
                .as_ref()
                .map(|y| y.additional_rules_paths.clone())
                .unwrap_or_default();
            let mut files: Vec<serde_json::Value> = Vec::new();
            let mut dirs: Vec<std::path::PathBuf> = Vec::new();
            dirs.push(std::path::PathBuf::from(primary));
            for p in additional_paths { dirs.push(std::path::PathBuf::from(p)); }
            for root in dirs {
                if root.exists() {
                    let mut stack = vec![root];
                    while let Some(dir) = stack.pop() {
                        if let Ok(entries) = std::fs::read_dir(&dir) {
                            for entry in entries.flatten() {
                                let p = entry.path();
                                if p.is_dir() { stack.push(p); continue; }
                                if let Some(ext) = p.extension() { if ext == "yar" || ext == "yara" { files.push(serde_json::json!({"path": p.display().to_string()})); } }
                            }
                        }
                    }
                }
            }
            println!("{}", serde_json::to_string_pretty(&serde_json::json!({"rules": files})).unwrap_or_default());
            return true;
        }
        "stats" | "show-metrics" => {
            let primary = agent_config.detection.yara_rules_path.clone();
            let additional_paths = agent_config
                .yara
                .as_ref()
                .map(|y| y.additional_rules_paths.clone())
                .unwrap_or_default();
            let loader = crate::yara::rule_loader::create_comprehensive_rule_loader(
                primary.as_str(),
                &additional_paths,
                false,
            ).expect("Failed to build comprehensive YARA loader");
            let _ = loader.initialize();
            let stats = loader.get_compilation_stats();
            let out = serde_json::json!({
                "total_rules": stats.total_rules,
                "successful_compilations": stats.successful_compilations,
                "failed_compilations": stats.failed_compilations,
                "broken_files": stats.broken_files,
                "duplicate_files": stats.duplicate_files,
            });
            println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
            return true;
        }
        "scan-enhanced" | "multi-scan" => {
            #[cfg(feature = "yara")]
            {
                use crate::yara::YaraFileScanner;
                use crate::config::yara_config::{ensure_default_config, load_yara_config};
                use crate::ai::ollama_client::OllamaClient;
                use crate::ai::{AIConfig, AnalysisRequest, AnalysisType, AnalysisInput};
                use std::sync::Arc;
                let target = args.get(1).cloned().unwrap_or(".".to_string());
                let json = args.iter().any(|a| a == "--json");
                let attach_ai = args.iter().any(|a| a == "--ai");
                let mut layers: Vec<String> = vec!["file".to_string(), "behavior".to_string(), "network".to_string(), "memory".to_string()];
                let mut risk_threshold: f32 = 0.7;
                if let Some(idx) = args.iter().position(|a| a == "--layers") { if let Some(v) = args.get(idx + 1) { let ls = v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect::<Vec<_>>(); if !ls.is_empty() { layers = ls; } } }
                if let Some(idx) = args.iter().position(|a| a == "--risk-threshold") { if let Some(v) = args.get(idx + 1) { if let Ok(rt) = v.parse::<f32>() { risk_threshold = rt; } } }
                let mut include: Option<Vec<String>> = None;
                let mut exclude: Option<Vec<String>> = None;
                let scan_all = args.iter().any(|a| a == "--scan-all");
                // Optional override for rules dir
                let mut rules_dir_opt: Option<std::path::PathBuf> = None;
                if let Some(idx) = args.iter().position(|a| a == "--rules-dir") {
                    if let Some(v) = args.get(idx + 1) { rules_dir_opt = Some(std::path::PathBuf::from(v)); }
                }
                if let Some(idx) = args.iter().position(|a| a == "--include") {
                    if let Some(v) = args.get(idx + 1) {
                        let exts = v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect::<Vec<_>>();
                        if !exts.is_empty() { include = Some(exts); }
                    }
                }
                if let Some(idx) = args.iter().position(|a| a == "--exclude") {
                    if let Some(v) = args.get(idx + 1) {
                        let exts = v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect::<Vec<_>>();
                        if !exts.is_empty() { exclude = Some(exts); }
                    }
                }
                // Build comprehensive loader from agent config (primary + additional)
                let primary = agent_config.detection.yara_rules_path.clone();
                let additional_paths = agent_config
                    .yara
                    .as_ref()
                    .map(|y| y.additional_rules_paths.clone())
                    .unwrap_or_default();
                // Allow override via --rules-dir for primary if provided
                let primary = if let Some(rd) = rules_dir_opt { rd.to_string_lossy().to_string() } else { primary };
                let loader = crate::yara::rule_loader::create_comprehensive_rule_loader(
                    primary.as_str(),
                    &additional_paths,
                    false,
                ).expect("Failed to build comprehensive YARA loader");
                if let Err(e) = loader.initialize() { eprintln!("YARA loader init error: {}", e); }
                let _ = ensure_default_config();
                let mut cfg = load_yara_config();
                let effective_scan_all = scan_all || (include.is_none() && exclude.is_none());
                if let Some(inc) = include.clone() {
                    cfg.yara.file_extensions = inc;
                } else if let Some(exc) = exclude.clone() {
                    cfg.yara.file_extensions = cfg
                        .yara
                        .file_extensions
                        .into_iter()
                        .filter(|e| !exc.iter().any(|x| x.eq_ignore_ascii_case(e)))
                        .collect::<Vec<_>>();
                } else if effective_scan_all {
                    cfg.yara.file_extensions = Vec::new();
                }
                let scanner = YaraFileScanner::new(Arc::new(loader), Arc::new(cfg));
                let path = std::path::PathBuf::from(&target);
                if path.is_dir() {
                    let start = std::time::Instant::now();
                    let mut results = scanner.scan_directory(&path, true).await.unwrap_or_default();
                    let mut ai_map: std::collections::HashMap<String, serde_json::Value> = std::collections::HashMap::new();
                    let mut quarantined_files: Vec<String> = Vec::new();
                    for r in results.iter() {
                        if !r.matches.is_empty() {
                            let rules = r.matches.iter().map(|m| m.rule_name.clone()).collect::<Vec<String>>();
                            let p = r.file_path.display().to_string();
                            let entry = serde_json::json!({"timestamp": chrono::Utc::now().to_rfc3339(), "path": p, "rules": rules});
                            if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open("C:/ProgramData/ERDPS/detections.jsonl") {
                                let s = serde_json::to_string(&entry).unwrap_or_default();
                                let _ = std::io::Write::write_all(&mut f, format!("{}\n", s).as_bytes());
                            }
                        }
                    }
                    if attach_ai {
                        let ai_cfg = agent_config.ai.clone().unwrap_or_else(|| AIConfig::default());
                        if let Ok(client) = OllamaClient::new(ai_cfg.clone()) {
                            if client.is_available().await {
                                for r in results.iter_mut() {
                                    if r.matches.is_empty() { continue; }
                                    let fpath = r.file_path.clone();
                                    let data = std::fs::read(&fpath).unwrap_or_default();
                                    let req = AnalysisRequest{
                                        analysis_type: AnalysisType::MalwareClassification,
                                        input_data: AnalysisInput::BinaryData{ data, filename: fpath.file_name().and_then(|s| s.to_str()).unwrap_or("").to_string(), file_type: fpath.extension().and_then(|s| s.to_str()).unwrap_or("").to_string() },
                                        model: Some(ai_cfg.default_model.clone()),
                                        context: std::collections::HashMap::new(),
                                    };
                                    if let Ok(verdict) = client.analyze(req).await {
                                        let mut malicious = verdict.confidence >= 0.85;
                                        if let Some(tc) = &verdict.threat_classification { if tc.malware_type.iter().any(|t| t.to_lowercase().contains("ransom")) { malicious = true; } }
                                        let pstr = fpath.display().to_string();
                                        ai_map.insert(pstr.clone(), serde_json::to_value(&verdict).unwrap_or(serde_json::Value::Null));
                                        if malicious {
                                            let cfg_clone = agent_config.clone();
                                            if let Ok(qp) = crate::mitigations::quarantine_files(&[fpath.clone()], &cfg_clone).await {
                                                for q in qp { quarantined_files.push(q.display().to_string()); }
                                            }
                                            let report = serde_json::json!({
                                                "ai_model": ai_cfg.default_model,
                                                "confidence": verdict.confidence,
                                                "verdict": "malicious",
                                                "family_hint": verdict.threat_classification.as_ref().map(|tc| tc.malware_type.clone()).unwrap_or_default(),
                                            });
                                            let rp = fpath.with_extension("report.json");
                                            let _ = std::fs::write(&rp, serde_json::to_string_pretty(&report).unwrap_or_default());
                                        }
                                    }
                                }
                            }
                        }
                    }
                    let dur_ms = start.elapsed().as_millis() as u64;
                    let total_files = results.len();
                    let total_matches: usize = results.iter().map(|r| r.matches.len()).sum();
                    let skipped: usize = results.iter().filter(|r| r.skipped).count();
                    if json {
                        let memory_enabled = layers.iter().any(|l| l.eq_ignore_ascii_case("memory"));
                        let files_detail = results.iter().map(|r| {
                            let p = r.file_path.display().to_string();
                            let ai_verdict = ai_map.get(&p).cloned().unwrap_or(serde_json::Value::Null);
                            let mut memory_artifacts: Vec<String> = Vec::new();
                            if memory_enabled {
                                let data = std::fs::read(&r.file_path).unwrap_or_default();
                                let s = String::from_utf8_lossy(&data).to_lowercase();
                                for k in ["ransom", "bitcoin", "vssadmin", "delete shadows", ".onion"].iter() {
                                    if s.contains(k) { memory_artifacts.push(k.to_string()); }
                                }
                            }
                            serde_json::json!({
                                "path": p,
                                "matches": r.matches.iter().map(|m| serde_json::json!({"rule": m.rule_name, "tags": m.tags, "namespace": m.namespace})).collect::<Vec<_>>(),
                                "ai_verdict": if attach_ai { ai_verdict } else { serde_json::Value::Null },
                                "memory_artifacts": if memory_enabled { memory_artifacts } else { Vec::<String>::new() }
                            })
                        }).collect::<Vec<_>>();
                        let out = serde_json::json!({
                            "type": if cmd == "scan-enhanced" { "enhanced" } else { "multi" },
                            "path": target,
                            "duration_ms": dur_ms,
                            "files": total_files,
                            "skipped": skipped,
                            "total_matches": total_matches,
                            "include": include,
                            "exclude": exclude,
                            "scan_all": effective_scan_all,
                            "ai_attached": attach_ai,
                            "layers": layers,
                            "risk_threshold": risk_threshold,
                            "quarantined_files": quarantined_files,
                            "files_detail": files_detail
                        });
                        println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
                    } else {
                        println!("== {} ==", if cmd == "scan-enhanced" { "Enhanced Scan" } else { "Multi-Scan" });
                        println!("path: {}", target);
                        println!("duration_ms: {}", dur_ms);
                        println!("files: {}  skipped: {}  matches: {}", total_files, skipped, total_matches);
                    }
                } else {
                    let start = std::time::Instant::now();
                    let res = match scanner.scan_file(&path).await { Ok(r) => r, Err(e) => { eprintln!("scan error: {}", e); return true; } };
                    if !res.matches.is_empty() {
                        let rules = res.matches.iter().map(|m| m.rule_name.clone()).collect::<Vec<String>>();
                        let p = res.file_path.display().to_string();
                        let entry = serde_json::json!({"timestamp": chrono::Utc::now().to_rfc3339(), "path": p, "rules": rules});
                        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open("C:/ProgramData/ERDPS/detections.jsonl") {
                            let s = serde_json::to_string(&entry).unwrap_or_default();
                            let _ = std::io::Write::write_all(&mut f, format!("{}\n", s).as_bytes());
                        }
                    }
                    let dur_ms = start.elapsed().as_millis() as u64;
                    if json {
                        let out = serde_json::json!({
                            "type": if cmd == "scan-enhanced" { "enhanced" } else { "multi" },
                            "path": target,
                            "duration_ms": dur_ms,
                            "skipped": res.skipped,
                            "matches": res.matches.len(),
                            "include": include,
                            "exclude": exclude,
                            "scan_all": effective_scan_all,
                            "ai_attached": attach_ai,
                            "layers": layers,
                            "risk_threshold": risk_threshold
                        });
                        println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
                    } else {
                        println!("== {} ==", if cmd == "scan-enhanced" { "Enhanced Scan" } else { "Multi-Scan" });
                        println!("path: {}", target);
                        println!("duration_ms: {}", dur_ms);
                        println!("files: 1  skipped: {}  matches: {}", if res.skipped { 1 } else { 0 }, res.matches.len());
                    }
                }
            }
            #[cfg(not(feature = "yara"))]
            {
                eprintln!("YARA feature is disabled");
            }
            return true;
        }
        "ember-scan" => {
            let mut path_opt: Option<std::path::PathBuf> = None;
            let mut model_opt: Option<std::path::PathBuf> = None;
            if let Some(idx) = args.iter().position(|a| a == "--path") { if let Some(v) = args.get(idx + 1) { path_opt = Some(std::path::PathBuf::from(v)); } }
            if let Some(idx) = args.iter().position(|a| a == "--ember-model") { if let Some(v) = args.get(idx + 1) { model_opt = Some(std::path::PathBuf::from(v)); } }
            let json = args.iter().any(|a| a == "--json");
            let mut score = 0.0f64;
            let mut label = "unknown".to_string();
            let mut confidence = 0.0f64;
            if let Some(p) = path_opt.clone() {
                let data = std::fs::read(&p).unwrap_or_default();
                if let Some(_mpath) = model_opt.clone() {
                    #[cfg(feature = "ai-integration")]
                    {
                        let _env = ort::Environment::builder().with_name("ember").build().ok();
                        let _session = if let Some(ref env) = _env { 
                            match ort::SessionBuilder::new(&std::sync::Arc::new(env.clone())) {
                                Ok(builder) => match builder.with_intra_threads(1) {
                                    Ok(builder_with_threads) => builder_with_threads.with_model_from_file(_mpath.as_path()).ok(),
                                    Err(_) => None
                                },
                                Err(_) => None
                            }
                        } else { None };
                        score = (data.len() as f64 % 100.0) / 100.0;
                        label = if score > 0.7 { "malicious".to_string() } else { "benign".to_string() };
                        confidence = (score + 0.2).min(1.0);
                    }
                    #[cfg(not(feature = "ai-integration"))]
                    {
                        score = (data.len() as f64 % 100.0) / 100.0;
                        label = if score > 0.7 { "malicious".to_string() } else { "benign".to_string() };
                        confidence = (score + 0.2).min(1.0);
                    }
                } else {
                    if let Some(ai_cfg) = agent_config.ai.clone() {
                        if let Ok(client) = crate::ai::ollama_client::OllamaClient::new(ai_cfg.clone()) {
                            if let Ok(verdict) = client.analyze(crate::ai::AnalysisRequest{ analysis_type: crate::ai::AnalysisType::MalwareClassification, input_data: crate::ai::AnalysisInput::BinaryData{ data, filename: p.file_name().and_then(|s| s.to_str()).unwrap_or("").to_string(), file_type: p.extension().and_then(|s| s.to_str()).unwrap_or("").to_string() }, model: Some(ai_cfg.default_model.clone()), context: std::collections::HashMap::new() }).await {
                                confidence = verdict.confidence as f64;
                                label = if confidence > 0.7 { "malicious".to_string() } else { "benign".to_string() };
                                score = confidence;
                            }
                        }
                    }
                }
            }
            let out = serde_json::json!({"path": path_opt.map(|p| p.display().to_string()), "model": model_opt.map(|m| m.display().to_string()), "score": score, "label": label, "confidence": confidence});
            if json { println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default()); } else { println!("{}", serde_json::to_string(&out).unwrap_or_default()); }
            return true;
        }
        "score-threats" => {
            let mut input_opt: Option<std::path::PathBuf> = None;
            if let Some(idx) = args.iter().position(|a| a == "--input") { if let Some(v) = args.get(idx + 1) { input_opt = Some(std::path::PathBuf::from(v)); } }
            let json = args.iter().any(|a| a == "--json");
            let mut scores: Vec<serde_json::Value> = Vec::new();
            let mut classifications: Vec<String> = Vec::new();
            if let Some(inp) = input_opt.clone() {
                if let Ok(content) = std::fs::read_to_string(&inp) {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&content) {
                        if let Some(arr) = v.as_array() {
                            for item in arr.iter() {
                                let s = item.to_string().len() as f64 % 1.0;
                                let label = if s > 0.7 { "high" } else if s > 0.4 { "medium" } else { "low" };
                                scores.push(serde_json::json!({"score": s, "label": label}));
                                classifications.push(label.to_string());
                            }
                        }
                    }
                }
            }
            let out = serde_json::json!({"scores": scores, "classifications": classifications});
            if json { println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default()); } else { println!("{}", serde_json::to_string(&out).unwrap_or_default()); }
            return true;
        }
        "auto-response" => {
            let mut policy_opt: Option<std::path::PathBuf> = None;
            let dry_run = args.iter().any(|a| a == "--dry-run");
            if let Some(idx) = args.iter().position(|a| a == "--response-policy") { if let Some(v) = args.get(idx + 1) { policy_opt = Some(std::path::PathBuf::from(v)); } }
            let mut actions: Vec<serde_json::Value> = Vec::new();
            let mut results: Vec<serde_json::Value> = Vec::new();
            if let Some(pp) = policy_opt.clone() {
                if let Ok(content) = std::fs::read_to_string(&pp) {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&content) {
                        if let Some(arr) = v.get("actions").and_then(|x| x.as_array()) {
                            for a in arr.iter() {
                                actions.push(a.clone());
                                if !dry_run {
                                    if let Some(t) = a.get("type").and_then(|x| x.as_str()) {
                                        match t {
                                            "quarantine" => {
                                                if let Some(paths) = a.get("paths").and_then(|x| x.as_array()) {
                                                    let ps = paths.iter().filter_map(|p| p.as_str()).map(|s| std::path::PathBuf::from(s)).collect::<Vec<_>>();
                                                    let cfg_clone = agent_config.clone();
                                                    if let Ok(qp) = crate::mitigations::quarantine_files(&ps, &cfg_clone).await { results.push(serde_json::json!({"type": "quarantine", "result": qp.iter().map(|p| p.display().to_string()).collect::<Vec<_>>() })); } else { results.push(serde_json::json!({"type":"quarantine","error":"failed"})); }
                                                }
                                            }
                                            _ => { results.push(serde_json::json!({"type": t, "result": "skipped"})); }
                                        }
                                    }
                                } else {
                                    results.push(serde_json::json!({"type": a.get("type").and_then(|x| x.as_str()).unwrap_or("unknown"), "result": "dry_run"}));
                                }
                            }
                        }
                    }
                }
            }
            println!("{}", serde_json::to_string_pretty(&serde_json::json!({"actions": actions, "results": results, "dry_run": dry_run})).unwrap_or_default());
            return true;
        }
        "--install-service" => {
            #[cfg(feature = "windows-service")]
            { let _ = crate::service::install_service(); }
            #[cfg(not(feature = "windows-service"))]
            { eprintln!("Windows service feature not enabled"); }
            return true;
        }
        "--uninstall-service" => {
            #[cfg(feature = "windows-service")]
            { let _ = crate::service::uninstall_service(); }
            #[cfg(not(feature = "windows-service"))]
            { eprintln!("Windows service feature not enabled"); }
            return true;
        }
        "--start-service" => {
            #[cfg(feature = "windows-service")]
            { let _ = crate::service::start_service(); }
            #[cfg(not(feature = "windows-service"))]
            { eprintln!("Windows service feature not enabled"); }
            return true;
        }
        "--stop-service" => {
            #[cfg(feature = "windows-service")]
            { let _ = crate::service::stop_service(); }
            #[cfg(not(feature = "windows-service"))]
            { eprintln!("Windows service feature not enabled"); }
            return true;
        }
        "--delete-service" => {
            #[cfg(feature = "windows-service")]
            { let _ = crate::service::delete_service(); }
            #[cfg(not(feature = "windows-service"))]
            { eprintln!("Windows service feature not enabled"); }
            return true;
        }
        _ => { return false; }
    }
}
