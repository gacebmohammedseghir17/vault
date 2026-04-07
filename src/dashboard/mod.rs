use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use serde_json::json;
use crate::config::agent_config::AgentConfig;

async fn handle_request(buf: &[u8], cfg: Arc<AgentConfig>) -> Vec<u8> {
    let req = String::from_utf8_lossy(buf);
    let mut path = "/".to_string();
    for line in req.lines() {
        if line.starts_with("GET ") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 { path = parts[1].to_string(); }
            break;
        }
    }
    let (status, body, ctype) = if path == "/rules" {
        let mut files = Vec::new();
        let mut dirs: Vec<PathBuf> = Vec::new();
        dirs.push(PathBuf::from(cfg.detection.yara_rules_path.clone()));
        if let Some(y) = &cfg.yara { for p in y.additional_rules_paths.iter() { dirs.push(PathBuf::from(p)); } }
        for root in dirs {
            if root.exists() {
                let mut stack = vec![root];
                while let Some(dir) = stack.pop() {
                    if let Ok(rd) = std::fs::read_dir(&dir) {
                        for e in rd.flatten() {
                            let p = e.path();
                            if p.is_dir() { stack.push(p); continue; }
                            if let Some(ext) = p.extension() { if ext == "yar" || ext == "yara" { files.push(json!({"path": p.display().to_string()})); } }
                        }
                    }
                }
            }
        }
        ("200 OK", serde_json::to_string(&json!({"rules": files})).unwrap_or_default(), "application/json")
    } else if path == "/metrics" {
        let url = format!("http://{}", cfg.observability.metrics_bind);
        ("200 OK", serde_json::to_string(&json!({"metrics_url": url})).unwrap_or_default(), "application/json")
    } else if path == "/quarantine" {
        let mut items = Vec::new();
        let base = String::from("C:/ProgramData/ERDPS/quarantine");
        let root = PathBuf::from(base);
        if root.exists() {
            let mut stack = vec![root];
            while let Some(dir) = stack.pop() {
                if let Ok(rd) = std::fs::read_dir(&dir) {
                    for e in rd.flatten() {
                        let p = e.path();
                        if p.is_dir() { stack.push(p); continue; }
                        if let Some(name) = p.file_name().and_then(|s| s.to_str()) {
                            if name.ends_with(".meta.json") || name.ends_with(".report.json") {
                                let content = std::fs::read_to_string(&p).unwrap_or_default();
                                items.push(json!({"path": p.display().to_string(), "content": content}));
                            }
                        }
                    }
                }
            }
        }
        ("200 OK", serde_json::to_string(&json!({"items": items})).unwrap_or_default(), "application/json")
    } else if path == "/detections" {
        ("200 OK", serde_json::to_string(&json!({"detections": []})).unwrap_or_default(), "application/json")
    } else {
        ("404 Not Found", String::from("{}"), "application/json")
    };
    let mut resp = Vec::new();
    let headers = format!("HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", status, ctype, body.len());
    resp.extend_from_slice(headers.as_bytes());
    resp.extend_from_slice(body.as_bytes());
    resp
}

pub async fn start_dashboard(bind: String, cfg: Arc<AgentConfig>) {
    let listener = TcpListener::bind(bind).await.expect("bind failed");
    loop {
        if let Ok((mut sock, _)) = listener.accept().await {
            let mut buf = vec![0u8; 8192];
            let mut n = 0usize;
            if let Ok(sz) = sock.read(&mut buf).await { n = sz; }
            let resp = handle_request(&buf[..n], Arc::clone(&cfg)).await;
            let _ = sock.write_all(&resp).await;
            let _ = sock.shutdown().await;
        }
    }
}
