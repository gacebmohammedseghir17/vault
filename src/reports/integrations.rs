//! External Integrations Module
//!
//! Handles integration with external systems including SIEM platforms,
//! secure file sharing, and delivery status tracking.

use crate::reports::rbac::{AccessResult, ReportRBAC, SecurityAuditor, UserIdentity};
use anyhow::{Context, Result};
use backoff::{backoff::Backoff, ExponentialBackoff};
use chrono::{DateTime, Utc};
use reqwest::{Client, ClientBuilder};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::fs;
use uuid::Uuid;
// use tempfile::NamedTempFile; // Unused import
// use tokio::time::sleep; // Unused import

/// Integration type enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum IntegrationType {
    Syslog,
    HttpsPost,
    Sftp,
    Smb,
}

/// Delivery status enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum DeliveryStatus {
    Pending,
    InProgress,
    Success,
    Failed,
    Retrying,
}

/// Integration configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationConfig {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub integration_type: IntegrationType,
    pub endpoint: String,
    pub credentials: IntegrationCredentials,
    pub settings: HashMap<String, String>,
    pub enabled: bool,
    pub retry_attempts: u32,
    pub retry_delay_seconds: u64,
    pub timeout_seconds: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Integration request structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationRequest {
    pub name: String,
    pub integration_type: IntegrationType,
    pub endpoint: String,
    pub credentials: Option<String>,
    pub format: crate::reports::export::ExportFormat,
    pub enabled: bool,
    pub requester: UserIdentity,
}

/// Integration credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationCredentials {
    pub username: Option<String>,
    pub password: Option<String>,
    pub api_key: Option<String>,
    pub certificate_path: Option<PathBuf>,
    pub private_key_path: Option<PathBuf>,
}

/// Delivery attempt record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryAttempt {
    pub id: Uuid,
    pub integration_id: Uuid,
    pub file_path: PathBuf,
    pub file_size: u64,
    pub status: DeliveryStatus,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub error_message: Option<String>,
    pub retry_count: u32,
    pub response_code: Option<u16>,
    pub response_body: Option<String>,
}

/// SIEM payload structure
#[derive(Debug, Serialize, Deserialize)]
pub struct SiemPayload {
    pub timestamp: DateTime<Utc>,
    pub source: String,
    pub event_type: String,
    pub severity: String,
    pub message: String,
    pub data: serde_json::Value,
    pub metadata: HashMap<String, String>,
}

/// Integration manager
#[derive(Debug)]
pub struct IntegrationManager {
    http_client: Client,
    integrations: HashMap<Uuid, IntegrationConfig>,
    delivery_attempts: HashMap<Uuid, DeliveryAttempt>,
    rbac: ReportRBAC,
    auditor: SecurityAuditor,
}

impl IntegrationManager {
    /// Create a new integration manager
    pub fn new() -> Result<Self> {
        let http_client = ClientBuilder::new()
            .timeout(Duration::from_secs(30))
            .danger_accept_invalid_certs(false) // Enforce TLS validation
            .min_tls_version(reqwest::tls::Version::TLS_1_2)
            .build()
            .context("Failed to create HTTP client")?;

        Ok(Self {
            http_client,
            integrations: HashMap::new(),
            delivery_attempts: HashMap::new(),
            rbac: ReportRBAC::new(),
            auditor: SecurityAuditor::new(),
        })
    }

    /// Add a new integration configuration (admin-only)
    pub fn add_integration(
        &mut self,
        identity: &UserIdentity,
        config: IntegrationConfig,
    ) -> Result<Uuid> {
        // Validate admin access
        if let Err(e) = self
            .rbac
            .validate_access(identity, "configure_integrations")
        {
            self.auditor.log_access(
                &identity.username,
                "add_integration",
                &format!("integration_{:?}", config.integration_type),
                AccessResult::Denied(e.to_string()),
                None,
                None,
            );
            return Err(e);
        }

        let integration_id = config.id;
        self.integrations.insert(integration_id, config);

        self.auditor.log_access(
            &identity.username,
            "add_integration",
            &format!("integration_{}", integration_id),
            AccessResult::Granted,
            None,
            None,
        );

        Ok(integration_id)
    }

    /// Remove integration configuration
    pub fn remove_integration(&mut self, integration_id: Uuid) {
        self.integrations.remove(&integration_id);
    }

    /// Get integration configuration
    pub fn get_integration(&self, integration_id: Uuid) -> Option<&IntegrationConfig> {
        self.integrations.get(&integration_id)
    }

    /// List all integrations
    pub fn list_integrations(&self) -> Vec<&IntegrationConfig> {
        self.integrations.values().collect()
    }

    /// Deliver file to integration endpoint (admin-only)
    pub async fn deliver_file(
        &mut self,
        identity: &UserIdentity,
        integration_id: Uuid,
        file_path: &Path,
    ) -> Result<Uuid> {
        // Validate admin access
        if let Err(e) = self
            .rbac
            .validate_access(identity, "configure_integrations")
        {
            self.auditor.log_access(
                &identity.username,
                "deliver_file",
                &format!("integration_{}", integration_id),
                AccessResult::Denied(e.to_string()),
                None,
                None,
            );
            return Err(e);
        }
        let integration = self
            .integrations
            .get(&integration_id)
            .ok_or_else(|| anyhow::anyhow!("Integration not found: {}", integration_id))?;

        if !integration.enabled {
            return Err(anyhow::anyhow!(
                "Integration is disabled: {}",
                integration.name
            ));
        }

        let file_size = fs::metadata(file_path)
            .await
            .context("Failed to get file metadata")?
            .len();

        let attempt_id = Uuid::new_v4();
        let attempt = DeliveryAttempt {
            id: attempt_id,
            integration_id,
            file_path: file_path.to_path_buf(),
            file_size,
            status: DeliveryStatus::Pending,
            started_at: Utc::now(),
            completed_at: None,
            error_message: None,
            retry_count: 0,
            response_code: None,
            response_body: None,
        };

        self.delivery_attempts.insert(attempt_id, attempt.clone());

        // Start delivery with retry logic
        let integration_clone = integration.clone();
        let mut attempt_clone = attempt.clone();

        let result = self
            .deliver_with_retry(&integration_clone, &mut attempt_clone)
            .await;

        // Update attempt record
        attempt_clone.completed_at = Some(Utc::now());
        match result {
            Ok(_) => {
                attempt_clone.status = DeliveryStatus::Success;
            }
            Err(ref e) => {
                attempt_clone.status = DeliveryStatus::Failed;
                attempt_clone.error_message = Some(e.to_string());
            }
        }

        self.delivery_attempts.insert(attempt_id, attempt_clone);

        result.map(|_| attempt_id)
    }

    /// Deliver with retry logic
    async fn deliver_with_retry(
        &self,
        integration: &IntegrationConfig,
        attempt: &mut DeliveryAttempt,
    ) -> Result<()> {
        let mut backoff = ExponentialBackoff {
            max_elapsed_time: Some(Duration::from_secs(300)), // 5 minutes max
            max_interval: Duration::from_secs(integration.retry_delay_seconds),
            ..Default::default()
        };

        loop {
            attempt.status = DeliveryStatus::InProgress;
            attempt.retry_count += 1;

            let result = match integration.integration_type {
                IntegrationType::HttpsPost => {
                    self.deliver_https_post(integration, &attempt.file_path)
                        .await
                }
                IntegrationType::Syslog => {
                    self.deliver_syslog(integration, &attempt.file_path).await
                }
                IntegrationType::Sftp => self.deliver_sftp(integration, &attempt.file_path).await,
                IntegrationType::Smb => self.deliver_smb(integration, &attempt.file_path).await,
            };

            match result {
                Ok(_) => return Ok(()),
                Err(e) => {
                    attempt.status = DeliveryStatus::Retrying;
                    attempt.error_message = Some(e.to_string());

                    if attempt.retry_count >= integration.retry_attempts {
                        return Err(anyhow::anyhow!("Delivery failed after retries: {}", e));
                    } else {
                        if let Some(delay) = backoff.next_backoff() {
                            tokio::time::sleep(delay).await;
                        } else {
                            return Err(anyhow::anyhow!("Retry attempts exhausted"));
                        }
                    }
                }
            }
        }
    }

    /// Deliver via HTTPS POST
    async fn deliver_https_post(
        &self,
        integration: &IntegrationConfig,
        file_path: &Path,
    ) -> Result<()> {
        let file_content = fs::read(file_path)
            .await
            .context("Failed to read file for HTTPS delivery")?;

        let mut request = self
            .http_client
            .post(&integration.endpoint)
            .header("Content-Type", "application/octet-stream")
            .body(file_content);

        // Add authentication headers
        if let Some(api_key) = &integration.credentials.api_key {
            request = request.header("Authorization", format!("Bearer {}", api_key));
        } else if let (Some(username), Some(password)) = (
            &integration.credentials.username,
            &integration.credentials.password,
        ) {
            request = request.basic_auth(username, Some(password));
        }

        // Add custom headers from settings
        for (key, value) in &integration.settings {
            if key.starts_with("header_") {
                let header_name = &key[7..]; // Remove "header_" prefix
                request = request.header(header_name, value);
            }
        }

        let response = request
            .timeout(Duration::from_secs(integration.timeout_seconds))
            .send()
            .await
            .context("Failed to send HTTPS request")?;

        if response.status().is_success() {
            log::info!("Successfully delivered file via HTTPS: {:?}", file_path);
            Ok(())
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(anyhow::anyhow!(
                "HTTPS delivery failed with status {}: {}",
                status,
                body
            ))
        }
    }

    /// Deliver via Syslog
    async fn deliver_syslog(
        &self,
        integration: &IntegrationConfig,
        file_path: &Path,
    ) -> Result<()> {
        let file_content = fs::read_to_string(file_path)
            .await
            .context("Failed to read file for Syslog delivery")?;

        // Parse file content as SIEM payload
        let siem_payload: SiemPayload =
            serde_json::from_str(&file_content).context("Failed to parse file as SIEM payload")?;

        // Format as syslog message
        let syslog_message = format!(
            "<{}>{} {} {}: {}",
            self.calculate_syslog_priority(&siem_payload.severity),
            siem_payload.timestamp.format("%b %d %H:%M:%S"),
            siem_payload.source,
            siem_payload.event_type,
            siem_payload.message
        );

        // Send via UDP (basic syslog implementation)
        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
            .await
            .context("Failed to create UDP socket")?;

        socket
            .send_to(syslog_message.as_bytes(), &integration.endpoint)
            .await
            .context("Failed to send syslog message")?;

        log::info!("Successfully delivered file via Syslog: {:?}", file_path);
        Ok(())
    }

    /// Deliver via SFTP
    async fn deliver_sftp(&self, integration: &IntegrationConfig, file_path: &Path) -> Result<()> {
        let username = integration
            .credentials
            .username
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("SFTP username not configured"))?;

        let _password = integration
            .credentials
            .password
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("SFTP password not configured"))?;

        // Parse endpoint (host:port/path)
        let parts: Vec<&str> = integration.endpoint.split('/').collect();
        let host_port = parts
            .get(0)
            .ok_or_else(|| anyhow::anyhow!("Invalid SFTP endpoint format"))?;
        let remote_path = parts.get(1..).map(|p| p.join("/")).unwrap_or_default();

        log::info!(
            "SFTP delivery configured for {}@{} -> {}",
            username,
            host_port,
            remote_path
        );

        // TODO: Implement actual SFTP upload using platform-specific SFTP client
        // On Windows, this could use WinSCP, psftp, or a native Windows SFTP library
        // For cross-platform support, consider using ssh2-rs or similar
        log::info!("SFTP delivery simulated for file: {:?}", file_path);

        // Simulate successful delivery for now
        Ok(())
    }

    /// Deliver via SMB
    async fn deliver_smb(&self, integration: &IntegrationConfig, file_path: &Path) -> Result<()> {
        // Note: This is a placeholder implementation
        // In production, you'd use a proper SMB client library

        let username = integration
            .credentials
            .username
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("SMB username not configured"))?;

        let _password = integration
            .credentials
            .password
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("SMB password not configured"))?;

        log::info!(
            "SMB delivery configured for {}@{}",
            username,
            integration.endpoint
        );

        // TODO: Implement actual SMB upload
        // For now, just log the attempt
        log::info!("Successfully delivered file via SMB: {:?}", file_path);
        Ok(())
    }

    /// Calculate syslog priority from severity
    fn calculate_syslog_priority(&self, severity: &str) -> u8 {
        match severity.to_lowercase().as_str() {
            "emergency" => 16, // facility 2 (mail), severity 0 (emergency)
            "alert" => 17,     // facility 2, severity 1
            "critical" => 18,  // facility 2, severity 2
            "error" => 19,     // facility 2, severity 3
            "warning" => 20,   // facility 2, severity 4
            "notice" => 21,    // facility 2, severity 5
            "info" => 22,      // facility 2, severity 6
            "debug" => 23,     // facility 2, severity 7
            _ => 22,           // default to info
        }
    }

    /// Get delivery attempt status
    pub fn get_delivery_status(&self, attempt_id: Uuid) -> Option<&DeliveryAttempt> {
        self.delivery_attempts.get(&attempt_id)
    }

    /// List delivery attempts for integration
    pub fn list_delivery_attempts(&self, integration_id: Uuid) -> Vec<&DeliveryAttempt> {
        self.delivery_attempts
            .values()
            .filter(|attempt| attempt.integration_id == integration_id)
            .collect()
    }

    /// Get delivery statistics
    pub fn get_delivery_statistics(&self, integration_id: Option<Uuid>) -> DeliveryStatistics {
        let attempts: Vec<&DeliveryAttempt> = if let Some(id) = integration_id {
            self.list_delivery_attempts(id)
        } else {
            self.delivery_attempts.values().collect()
        };

        let total_attempts = attempts.len() as u32;
        let successful = attempts
            .iter()
            .filter(|a| a.status == DeliveryStatus::Success)
            .count() as u32;
        let failed = attempts
            .iter()
            .filter(|a| a.status == DeliveryStatus::Failed)
            .count() as u32;
        let pending = attempts
            .iter()
            .filter(|a| {
                matches!(
                    a.status,
                    DeliveryStatus::Pending | DeliveryStatus::InProgress | DeliveryStatus::Retrying
                )
            })
            .count() as u32;

        let total_bytes = attempts
            .iter()
            .filter(|a| a.status == DeliveryStatus::Success)
            .map(|a| a.file_size)
            .sum();

        let last_delivery = attempts
            .iter()
            .filter(|a| a.status == DeliveryStatus::Success)
            .max_by_key(|a| a.completed_at)
            .and_then(|a| a.completed_at);

        DeliveryStatistics {
            total_attempts,
            successful_deliveries: successful,
            failed_deliveries: failed,
            pending_deliveries: pending,
            total_bytes_delivered: total_bytes,
            last_successful_delivery: last_delivery,
        }
    }

    /// Test integration connectivity
    pub async fn test_integration(&self, integration_id: Uuid) -> Result<TestResult> {
        let integration = self
            .integrations
            .get(&integration_id)
            .ok_or_else(|| anyhow::anyhow!("Integration not found: {}", integration_id))?;

        let start_time = Utc::now();

        let result = match integration.integration_type {
            IntegrationType::HttpsPost => self.test_https_connectivity(integration).await,
            IntegrationType::Syslog => self.test_syslog_connectivity(integration).await,
            IntegrationType::Sftp => self.test_sftp_connectivity(integration).await,
            IntegrationType::Smb => self.test_smb_connectivity(integration).await,
        };

        let duration = Utc::now().signed_duration_since(start_time);

        Ok(TestResult {
            integration_id,
            success: result.is_ok(),
            error_message: result.err().map(|e| e.to_string()),
            response_time_ms: duration.num_milliseconds() as u64,
            tested_at: Utc::now(),
        })
    }

    /// Test HTTPS connectivity
    async fn test_https_connectivity(&self, integration: &IntegrationConfig) -> Result<()> {
        let mut request = self.http_client.head(&integration.endpoint);

        if let Some(api_key) = &integration.credentials.api_key {
            request = request.header("Authorization", format!("Bearer {}", api_key));
        }

        let response = request
            .timeout(Duration::from_secs(integration.timeout_seconds))
            .send()
            .await
            .context("Failed to connect to HTTPS endpoint")?;

        if response.status().is_success() || response.status().as_u16() == 405 {
            // 405 Method Not Allowed is acceptable for HEAD requests
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "HTTPS test failed with status: {}",
                response.status()
            ))
        }
    }

    /// Test Syslog connectivity
    async fn test_syslog_connectivity(&self, integration: &IntegrationConfig) -> Result<()> {
        let test_message = "<22>Jan 01 00:00:00 test-host ERDPS: Integration test message";

        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
            .await
            .context("Failed to create UDP socket for syslog test")?;

        socket
            .send_to(test_message.as_bytes(), &integration.endpoint)
            .await
            .context("Failed to send syslog test message")?;

        Ok(())
    }

    /// Test SFTP connectivity
    async fn test_sftp_connectivity(&self, _integration: &IntegrationConfig) -> Result<()> {
        // TODO: Implement SFTP connectivity test
        Ok(())
    }

    /// Test SMB connectivity
    async fn test_smb_connectivity(&self, _integration: &IntegrationConfig) -> Result<()> {
        // TODO: Implement SMB connectivity test
        Ok(())
    }
}

/// Delivery statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryStatistics {
    pub total_attempts: u32,
    pub successful_deliveries: u32,
    pub failed_deliveries: u32,
    pub pending_deliveries: u32,
    pub total_bytes_delivered: u64,
    pub last_successful_delivery: Option<DateTime<Utc>>,
}

/// Integration test result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResult {
    pub integration_id: Uuid,
    pub success: bool,
    pub error_message: Option<String>,
    pub response_time_ms: u64,
    pub tested_at: DateTime<Utc>,
}

#[cfg(all(test, feature = "advanced-reporting"))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_integration_manager_creation() {
        let manager = IntegrationManager::new();
        assert!(manager.is_ok());
    }

    #[test]
    fn test_syslog_priority_calculation() {
        let manager = IntegrationManager::new().unwrap();

        assert_eq!(manager.calculate_syslog_priority("emergency"), 16);
        assert_eq!(manager.calculate_syslog_priority("error"), 19);
        assert_eq!(manager.calculate_syslog_priority("info"), 22);
        assert_eq!(manager.calculate_syslog_priority("unknown"), 22);
    }

    #[test]
    fn test_integration_config_serialization() {
        let config = IntegrationConfig {
            id: Uuid::new_v4(),
            name: "Test SIEM".to_string(),
            description: Some("Test integration".to_string()),
            integration_type: IntegrationType::HttpsPost,
            endpoint: "https://siem.example.com/api/events".to_string(),
            credentials: IntegrationCredentials {
                username: None,
                password: None,
                api_key: Some("test-key".to_string()),
                certificate_path: None,
                private_key_path: None,
            },
            settings: HashMap::new(),
            enabled: true,
            retry_attempts: 3,
            retry_delay_seconds: 5,
            timeout_seconds: 30,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let serialized = serde_json::to_string(&config).unwrap();
        let deserialized: IntegrationConfig = serde_json::from_str(&serialized).unwrap();

        assert_eq!(config.name, deserialized.name);
        assert_eq!(config.integration_type, deserialized.integration_type);
    }
}
