use serde_json::json;
use std::sync::Arc;
use erdps_agent::config::AgentConfig;
use erdps_agent::ipc::{invoke_command_for_tests, RequestMessage, sign};

fn test_key() -> [u8; 32] {
    [42u8; 32]
}

fn make_request(command: &str, payload: serde_json::Value) -> RequestMessage {
    let key = test_key();
    let nonce = "test-nonce".to_string();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let signature = sign(command, timestamp, &nonce, &payload, &key).unwrap();
    RequestMessage {
        nonce,
        timestamp,
        command: command.to_string(),
        payload,
        signature,
    }
}

#[tokio::test]
async fn test_scan_file_error_normalized() {
    let config = Arc::new(AgentConfig::default());
    let req = make_request("scan_file", json!({}));
    let resp = invoke_command_for_tests(&req, &test_key(), Arc::clone(&config)).await;
    assert_eq!(resp.status, "error");
    let payload = resp.payload;
    assert_eq!(payload.get("event_type").and_then(|v| v.as_str()), Some("error"));
    assert_eq!(payload.get("context").and_then(|v| v.as_str()), Some("yara_scan"));
    assert!(payload.get("msg").is_some());
}

#[tokio::test]
async fn test_start_scan_normalized() {
    let config = Arc::new(AgentConfig::default());
    let req = make_request("start_scan", json!({"paths": ["C:/tmp/a", "C:/tmp/b"]}));
    let resp = invoke_command_for_tests(&req, &test_key(), Arc::clone(&config)).await;
    assert_eq!(resp.status, "success");
    let payload = resp.payload;
    assert_eq!(payload.get("context").and_then(|v| v.as_str()), Some("scan_job"));
    assert_eq!(payload.get("event_type").and_then(|v| v.as_str()), Some("start"));
    let data = payload.get("data").unwrap();
    assert!(data.get("job_id").is_some());
    assert_eq!(data.get("total_paths").and_then(|v| v.as_u64()), Some(2));
}

#[tokio::test]
async fn test_quarantine_file_invalid_params_normalized() {
    let config = Arc::new(AgentConfig::default());
    let req = make_request("quarantine_file", json!({}));
    let resp = invoke_command_for_tests(&req, &test_key(), Arc::clone(&config)).await;
    assert_eq!(resp.status, "error");
    let payload = resp.payload;
    assert_eq!(payload.get("context").and_then(|v| v.as_str()), Some("quarantine"));
    assert_eq!(payload.get("event_type").and_then(|v| v.as_str()), Some("error"));
}

#[tokio::test]
async fn test_unknown_command_normalized() {
    let config = Arc::new(AgentConfig::default());
    let req = make_request("nonexistent", json!({}));
    let resp = invoke_command_for_tests(&req, &test_key(), Arc::clone(&config)).await;
    assert_eq!(resp.status, "error");
    let payload = resp.payload;
    assert_eq!(payload.get("context").and_then(|v| v.as_str()), Some("ipc"));
    assert_eq!(payload.get("event_type").and_then(|v| v.as_str()), Some("error"));
}

#[tokio::test]
async fn test_get_quarantine_list_error_normalized() {
    let config = Arc::new(AgentConfig::default());
    let req = make_request("get_quarantine_list", json!({}));
    let resp = invoke_command_for_tests(&req, &test_key(), Arc::clone(&config)).await;
    assert_eq!(resp.status, "error");
    let payload = resp.payload;
    assert_eq!(payload.get("context").and_then(|v| v.as_str()), Some("quarantine"));
    assert_eq!(payload.get("event_type").and_then(|v| v.as_str()), Some("error"));
}

#[tokio::test]
async fn test_restore_quarantine_feature_disabled_normalized() {
    let config = Arc::new(AgentConfig::default());
    let req = make_request("restore_quarantine", json!({"quarantine_filename": "123.quar"}));
    let resp = invoke_command_for_tests(&req, &test_key(), Arc::clone(&config)).await;
    assert_eq!(resp.status, "error");
    let payload = resp.payload;
    assert_eq!(payload.get("context").and_then(|v| v.as_str()), Some("quarantine"));
    assert_eq!(payload.get("event_type").and_then(|v| v.as_str()), Some("error"));
}

#[tokio::test]
async fn test_get_job_status_not_found_normalized() {
    let config = Arc::new(AgentConfig::default());
    let req = make_request("get_job_status", json!({"job_id": "nope"}));
    let resp = invoke_command_for_tests(&req, &test_key(), Arc::clone(&config)).await;
    assert_eq!(resp.status, "error");
    let payload = resp.payload;
    assert_eq!(payload.get("context").and_then(|v| v.as_str()), Some("scan_job"));
    assert_eq!(payload.get("event_type").and_then(|v| v.as_str()), Some("error"));
}

#[tokio::test]
async fn test_stop_scan_stopped_false_normalized() {
    let config = Arc::new(AgentConfig::default());
    let req = make_request("stop_scan", json!({"job_id": "nope"}));
    let resp = invoke_command_for_tests(&req, &test_key(), Arc::clone(&config)).await;
    assert_eq!(resp.status, "success");
    let payload = resp.payload;
    assert_eq!(payload.get("context").and_then(|v| v.as_str()), Some("scan_job"));
    assert_eq!(payload.get("event_type").and_then(|v| v.as_str()), Some("stop"));
    let data = payload.get("data").unwrap();
    assert_eq!(data.get("stopped").and_then(|v| v.as_bool()), Some(false));
}