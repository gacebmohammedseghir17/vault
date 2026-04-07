//! Windows Service Integration
//!
//! This module provides Windows service wrapper functionality for the ERDPS Agent.

#[cfg(feature = "windows-service")]
use std::ffi::OsString;

#[cfg(feature = "windows-service")]
use std::time::Duration;
#[cfg(feature = "windows-service")]
use windows_service::{
    define_windows_service,
    service::{
        ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
        ServiceStartType, ServiceState, ServiceStatus, ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
    service_manager::{ServiceManager, ServiceManagerAccess},
    Result,
};

use anyhow::Result as AnyhowResult;
use tokio::sync::oneshot;
use tracing::{error, info};

#[allow(unused_imports)]
use crate::initialize_components_with_mode;

#[cfg(feature = "yara")]


const SERVICE_NAME: &str = "ERDPS Agent";
const SERVICE_DISPLAY_NAME: &str = "ERDPS Agent";
const SERVICE_DESCRIPTION: &str = "Enterprise Ransomware Detection and Prevention System Agent";
#[cfg(feature = "windows-service")]
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

#[cfg(feature = "windows-service")]
pub fn run_service() -> Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}

#[cfg(feature = "windows-service")]
define_windows_service!(ffi_service_main, service_main);

#[cfg(feature = "windows-service")]
fn service_main(_arguments: Vec<OsString>) {
    if let Err(e) = run_service_main() {
        error!("Service main error: {}", e);
    }
}

#[cfg(feature = "windows-service")]
fn run_service_main() -> AnyhowResult<()> {
    // Create a channel to receive shutdown signals
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let shutdown_tx = Arc::new(std::sync::Mutex::new(Some(shutdown_tx)));

    // Define the service control handler
    let shutdown_tx_clone = Arc::clone(&shutdown_tx);
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                info!("Received stop/shutdown signal");

                // Send shutdown signal to main loop
                if let Ok(mut tx) = shutdown_tx_clone.lock() {
                    if let Some(sender) = tx.take() {
                        let _ = sender.send(());
                    }
                }

                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    // Register the service control handler
    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

    // Set service status to start pending
    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::StartPending,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::from_secs(10), // Give 10 seconds for startup
        process_id: None,
    })?;

    info!("ERDPS Agent service starting...");

    // Create Tokio runtime for async operations
    let rt = tokio::runtime::Runtime::new()?;

    // Run the main service logic
    let result = rt.block_on(async { run_agent_async(shutdown_rx, status_handle).await });

    // Set service status to stopping
    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::StopPending,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::from_secs(5), // Give 5 seconds for cleanup
        process_id: None,
    })?;

    info!("ERDPS Agent service stopping...");

    // Set service status to stopped
    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    info!("ERDPS Agent service stopped");
    result
}

#[cfg(feature = "windows-service")]
async fn run_agent_async(
    mut shutdown_rx: oneshot::Receiver<()>,
    status_handle: service_control_handler::ServiceStatusHandle,
) -> AnyhowResult<()> {
    // Initialize components using unified function
    let mut init_result = match crate::initialize_components_with_mode("service", None).await {
        Ok(result) => result,
        Err(e) => {
            error!("Failed to initialize components: {}", e);
            // Set service status to stopped on initialization failure
            let _ = status_handle.set_service_status(ServiceStatus {
                service_type: SERVICE_TYPE,
                current_state: ServiceState::Stopped,
                controls_accepted: ServiceControlAccept::empty(),
                exit_code: ServiceExitCode::Win32(1),
                checkpoint: 0,
                wait_hint: Duration::default(),
                process_id: None,
            });
            return Err(e);
        }
    };

    // Start filesystem monitoring
    if let Err(e) = init_result
        .fs_monitor
        .start_monitoring(
            init_result
                .drives
                .into_iter()
                .map(std::path::PathBuf::from)
                .collect(),
        )
        .await
    {
        error!("Failed to start filesystem monitoring: {}", e);
        // Note: This is non-fatal, continue with service startup
    }

    // All listeners are now live, set service status to running
    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    info!("ERDPS Agent service started and all listeners are live");

    // Wait for shutdown signal
    tokio::select! {
        _ = &mut shutdown_rx => {
            info!("Shutdown signal received");
        }
    }

    // Cleanup - stop all services gracefully
    info!("Stopping filesystem monitoring...");
    init_result.fs_monitor.stop_monitoring().await;

    info!("Stopping IPC server...");
    // Give IPC server a moment to finish current requests before aborting
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    init_result.ipc_handle.abort();

    #[cfg(feature = "metrics")]
    if let Some(handle) = init_result.metrics_handle {
        info!("Stopping metrics server...");
        // Give metrics server a moment to finish current requests before aborting
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        handle.abort();
    }

    info!("Agent shutdown complete");
    Ok(())
}

// Service management functions
#[cfg(feature = "windows-service")]
pub fn install_service() -> AnyhowResult<()> {
    use std::env;

    let manager_access = ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE;
    let service_manager = ServiceManager::local_computer(None::<&str>, manager_access)?;

    let service_binary_path = env::current_exe()
        .map_err(|e| anyhow::anyhow!("Failed to get current executable path: {}", e))?
        .with_file_name("erdps-agent.exe");

    let service_info = windows_service::service::ServiceInfo {
        name: SERVICE_NAME.into(),
        display_name: SERVICE_DISPLAY_NAME.into(),
        service_type: SERVICE_TYPE,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: service_binary_path,
        launch_arguments: vec!["--service".into()],
        dependencies: vec![],
        account_name: Some("NT AUTHORITY\\LocalService".into()),
        account_password: None,
    };

    let service = service_manager.create_service(&service_info, ServiceAccess::CHANGE_CONFIG)?;
    service.set_description(SERVICE_DESCRIPTION)?;

    println!("Service '{}' installed successfully", SERVICE_NAME);
    Ok(())
}

#[cfg(feature = "windows-service")]
pub fn uninstall_service() -> AnyhowResult<()> {
    let manager_access = ServiceManagerAccess::CONNECT;
    let service_manager = ServiceManager::local_computer(None::<&str>, manager_access)?;

    let service_access = ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE;
    let service = service_manager.open_service(SERVICE_NAME, service_access)?;

    let service_status = service.query_status()?;
    if service_status.current_state != ServiceState::Stopped {
        service.stop()?;
        // Wait for the service to stop
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    service.delete()?;
    println!("Service '{}' uninstalled successfully", SERVICE_NAME);
    Ok(())
}

#[cfg(feature = "windows-service")]
pub fn start_service() -> AnyhowResult<()> {
    let manager_access = ServiceManagerAccess::CONNECT;
    let service_manager = ServiceManager::local_computer(None::<&str>, manager_access)?;

    let service_access = ServiceAccess::QUERY_STATUS | ServiceAccess::START;
    let service = service_manager.open_service(SERVICE_NAME, service_access)?;

    service.start(&[] as &[&str])?;
    println!("Service '{}' started successfully", SERVICE_NAME);
    Ok(())
}

#[cfg(feature = "windows-service")]
pub fn stop_service() -> AnyhowResult<()> {
    let manager_access = ServiceManagerAccess::CONNECT;
    let service_manager = ServiceManager::local_computer(None::<&str>, manager_access)?;

    let service_access = ServiceAccess::QUERY_STATUS | ServiceAccess::STOP;
    let service = service_manager.open_service(SERVICE_NAME, service_access)?;

    let service_status = service.query_status()?;
    if service_status.current_state != ServiceState::Stopped {
        service.stop()?;
        println!("Service '{}' stopped successfully", SERVICE_NAME);
    } else {
        println!("Service '{}' is already stopped", SERVICE_NAME);
    }
    Ok(())
}

#[cfg(feature = "windows-service")]
pub fn delete_service() -> AnyhowResult<()> {
    let manager_access = ServiceManagerAccess::CONNECT;
    let service_manager = ServiceManager::local_computer(None::<&str>, manager_access)?;

    let service_access = ServiceAccess::DELETE;
    let service = service_manager.open_service(SERVICE_NAME, service_access)?;

    service.delete()?;
    println!("Service '{}' deleted successfully", SERVICE_NAME);
    Ok(())
}

// Console mode for development
pub async fn run_console_mode() -> AnyhowResult<()> {
    info!("Running in console mode (development)");

    // Create a shutdown channel for graceful shutdown
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    // Run the agent with Ctrl+C handling
    tokio::select! {
        result = run_console_mode_async(shutdown_rx) => {
            result
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Ctrl+C received, shutting down...");
            let _ = shutdown_tx.send(());
            Ok(())
        }
    }
}

// Console mode async function (similar to service but without SCM status handling)
async fn run_console_mode_async(mut shutdown_rx: oneshot::Receiver<()>) -> AnyhowResult<()> {
    // Initialize components using unified function
    let mut init_result = crate::initialize_components_with_mode("console", None).await?;

    // Start filesystem monitoring
    if let Err(e) = init_result
        .fs_monitor
        .start_monitoring(
            init_result
                .drives
                .into_iter()
                .map(std::path::PathBuf::from)
                .collect(),
        )
        .await
    {
        error!("Failed to start filesystem monitoring: {}", e);
    }

    info!("ERDPS Agent console mode started and all listeners are live");

    // Wait for shutdown signal
    tokio::select! {
        _ = &mut shutdown_rx => {
            info!("Shutdown signal received");
        }
    }

    // Cleanup - stop all services gracefully
    info!("Stopping filesystem monitoring...");
    init_result.fs_monitor.stop_monitoring().await;

    info!("Stopping IPC server...");
    // Give IPC server a moment to finish current requests before aborting
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    init_result.ipc_handle.abort();

    #[cfg(feature = "metrics")]
    if let Some(handle) = init_result.metrics_handle {
        info!("Stopping metrics server...");
        // Give metrics server a moment to finish current requests before aborting
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        handle.abort();
    }

    info!("Agent shutdown complete");
    Ok(())
}
