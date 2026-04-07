use erdps_agent::observability::prometheus_metrics::{PrometheusConfig, PrometheusMetricsServer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[tokio::test]
async fn test_prometheus_server_auth_end_to_end() {
    let mut server = PrometheusMetricsServer::new(PrometheusConfig {
        enabled: true,
        bind_address: "127.0.0.1".to_string(),
        port: 19991,
        metrics_path: "/metrics".to_string(),
        auth_enabled: true,
        auth_token: Some("secret".to_string()),
        collection_interval_seconds: 10,
    });

    server.start().await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Without bearer should get 401
    let mut stream = TcpStream::connect("127.0.0.1:19991").await.unwrap();
    let req = b"GET /metrics HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
    stream.write_all(req).await.unwrap();
    let mut buf = vec![0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(resp.contains("401"), "expected 401, got: {}", resp);

    // With bearer should get 200
    let mut stream = TcpStream::connect("127.0.0.1:19991").await.unwrap();
    let req = b"GET /metrics HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer secret\r\n\r\n";
    stream.write_all(req).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await.unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(resp.contains("200"), "expected 200, got: {}", resp);
    assert!(resp.to_ascii_lowercase().contains("content-type: text/plain"));

    // JSON endpoint without bearer → 401
    let mut stream = TcpStream::connect("127.0.0.1:19991").await.unwrap();
    let req = b"GET /metrics.json HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
    stream.write_all(req).await.unwrap();
    let mut buf = vec![0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(resp.contains("401"));

    // JSON endpoint with bearer → 200
    let mut stream = TcpStream::connect("127.0.0.1:19991").await.unwrap();
    let req = b"GET /metrics.json HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer secret\r\n\r\n";
    stream.write_all(req).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await.unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(resp.contains("200"));
    assert!(resp.to_ascii_lowercase().contains("content-type: application/json"));

    server.stop().await;
}