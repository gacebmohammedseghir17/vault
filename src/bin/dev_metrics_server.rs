use erdps_agent::logger::init_logger;
use erdps_agent::observability::prometheus_metrics::{PrometheusConfig, PrometheusMetricsServer};
use log::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Initialize logger for useful output
    let _ = init_logger();

    // Use default Prometheus configuration (127.0.0.1:19091, /metrics)
    let config = PrometheusConfig::default();
    info!(
        "Starting dev metrics server on {}:{}{}",
        config.bind_address, config.port, config.metrics_path
    );

    // Start the metrics server
    let mut server = PrometheusMetricsServer::new(config);
    server.start().await?;

    info!("Dev metrics server is running. Press Ctrl+C to stop.");

    // Keep running until Ctrl+C
    tokio::signal::ctrl_c().await?;
    info!("Shutdown signal received. Stopping dev metrics server...");
    server.stop().await;

    Ok(())
}