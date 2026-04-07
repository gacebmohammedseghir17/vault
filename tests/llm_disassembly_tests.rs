use std::fs;
use std::io::Write;
use std::sync::Arc;
use serde_json::json;

use erdps_agent::config::AgentConfig;
use erdps_agent::ipc::{invoke_command_for_tests, RequestMessage, sign};

fn key() -> [u8; 32] { [42u8; 32] }

fn make_req(command: &str, payload: serde_json::Value) -> RequestMessage {
    let nonce = "nonce".to_string();
    let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    let sig = sign(command, ts, &nonce, &payload, &key()).unwrap();
    RequestMessage { nonce, timestamp: ts, command: command.to_string(), payload, signature: sig }
}

#[tokio::test]
async fn test_fake_ransom_py_disassembly_and_llm() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fake_ransom.py");
    let mut f = fs::File::create(&path).unwrap();
    writeln!(f, "# fake ransomware script").unwrap();
    writeln!(f, "import os, subprocess").unwrap();
    writeln!(f, "subprocess.call('vssadmin delete shadows /all /quiet', shell=True)").unwrap();
    writeln!(f, "print('ransom key exchange')").unwrap();
    f.flush().unwrap();

    let cfg = Arc::new(AgentConfig::default());
    let req = make_req("scan_file", json!({
        "path": path.to_string_lossy(),
        "disassembly": true,
        "llm_model": "deepseek-r1:1.5b"
    }));
    let resp = invoke_command_for_tests(&req, &key(), Arc::clone(&cfg)).await;
    assert_eq!(resp.status, "success");
    let payload = resp.payload;
    assert_eq!(payload.get("context").and_then(|v| v.as_str()), Some("yara_scan"));
    let data = payload.get("data").unwrap();
    let dis = data.get("disassembly").unwrap();
    // Should flag ransom indicators from strings
    let suspicious = dis.get("suspicious").unwrap().as_array().unwrap();
    assert!(suspicious.len() > 0);
    // LLM block is optional depending on runtime availability
    if let Some(llm) = dis.get("llm") {
        if !llm.is_null() {
            assert!(llm.get("confidence").is_some());
            assert!(llm.get("classification").is_some());
        }
    }
}

#[tokio::test]
async fn test_test_malware_exe_disassembly_and_llm() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test_malware.exe");
    // Minimal binary with MZ header and suspicious strings embedded
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00");
    bytes.extend_from_slice(b"vssadmin delete shadows /all /quiet\0ransom\0");
    fs::write(&path, &bytes).unwrap();

    let cfg = Arc::new(AgentConfig::default());
    let req = make_req("scan_file", json!({
        "path": path.to_string_lossy(),
        "disassembly": true,
        "llm_model": "deepseek-r1:1.5b"
    }));
    let resp = invoke_command_for_tests(&req, &key(), Arc::clone(&cfg)).await;
    assert_eq!(resp.status, "success");
    let payload = resp.payload;
    assert_eq!(payload.get("context").and_then(|v| v.as_str()), Some("yara_scan"));
    let data = payload.get("data").unwrap();
    let dis = data.get("disassembly").unwrap();
    let suspicious = dis.get("suspicious").unwrap().as_array().unwrap();
    assert!(suspicious.len() > 0);
    // Optional LLM
    if let Some(llm) = dis.get("llm") {
        if !llm.is_null() {
            assert!(llm.get("confidence").is_some());
            assert!(llm.get("classification").is_some());
        }
    }
}