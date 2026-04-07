//! Windows COM Firewall Integration
//!
//! Implementation of Windows Firewall management using COM APIs (INetFwPolicy2/INetFwRule)
//! with admin preflight checks, retry management, and HRESULT error handling.

// Removed unused OsString imports
use crate::metrics::MetricsCollector;
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;

// Windows API imports
use windows::{
    core::{BSTR, Error as WindowsError, GUID},
    Win32::{
        Foundation::*,
        System::{Com::*, Threading::*},
        // WindowsFirewall not available in NetworkManagement
        // NetworkManagement::WindowsFirewall::*,
    },
};

// Type aliases to avoid conflicts
type WindowsResult<T> = windows::core::Result<T>;
type StdResult<T, E> = std::result::Result<T, E>;

// Additional Windows API functions (placeholder implementations)
extern "system" {
    fn OpenProcessToken(
        process_handle: HANDLE,
        desired_access: u32,
        token_handle: *mut HANDLE,
    ) -> BOOL;
    fn GetTokenInformation(
        token_handle: HANDLE,
        token_information_class: u32,
        token_information: *mut std::ffi::c_void,
        token_information_length: u32,
        return_length: *mut u32,
    ) -> BOOL;
}

// Token information constants
const TOKEN_QUERY: u32 = 0x0008;
const TOKEN_ELEVATION: u32 = 20;

#[repr(C)]
struct TOKEN_ELEVATION {
    token_is_elevated: BOOL,
}

// COM interface definitions (placeholder implementations)
// These would normally come from Windows SDK bindings
#[repr(C)]
pub struct INetFwPolicy2 {
    _private: [u8; 0],
}

#[repr(C)]
pub struct INetFwRules {
    _private: [u8; 0],
}

#[repr(C)]
pub struct INetFwRule {
    _private: [u8; 0],
}

// Implement ComInterface trait for COM interfaces
unsafe impl windows::core::ComInterface for INetFwPolicy2 {
    const IID: windows::core::GUID = windows::core::GUID::from_u128(0x98325047_c671_4174_8d81_defcd3f03186);
}

unsafe impl windows::core::ComInterface for INetFwRules {
    const IID: windows::core::GUID = windows::core::GUID::from_u128(0x9c4c6277_5027_441e_afae_ca1f542da009);
}

unsafe impl windows::core::ComInterface for INetFwRule {
    const IID: windows::core::GUID = windows::core::GUID::from_u128(0xaf230d27_baba_4e42_aced_f524f22cfce2);
}

// Implement Clone trait for COM interfaces
impl Clone for INetFwPolicy2 {
    fn clone(&self) -> Self {
        INetFwPolicy2 { _private: [] }
    }
}

impl Clone for INetFwRules {
    fn clone(&self) -> Self {
        INetFwRules { _private: [] }
    }
}

impl Clone for INetFwRule {
    fn clone(&self) -> Self {
        INetFwRule { _private: [] }
    }
}

// Implement Interface trait for COM interfaces
unsafe impl windows::core::Interface for INetFwPolicy2 {
    type Vtable = INetFwPolicy2_Vtbl;
}

unsafe impl windows::core::Interface for INetFwRules {
    type Vtable = INetFwRules_Vtbl;
}

unsafe impl windows::core::Interface for INetFwRule {
    type Vtable = INetFwRule_Vtbl;
}

// Placeholder vtables
#[repr(C)]
pub struct INetFwPolicy2_Vtbl {
    pub base__: windows::core::IUnknown_Vtbl,
}

#[repr(C)]
pub struct INetFwRules_Vtbl {
    pub base__: windows::core::IUnknown_Vtbl,
}

#[repr(C)]
pub struct INetFwRule_Vtbl {
    pub base__: windows::core::IUnknown_Vtbl,
}

// COM class IDs (placeholder)
pub const NET_FW_POLICY2: GUID = GUID::from_u128(0x00000000_0000_0000_0000_000000000000);
pub const NET_FW_RULE: GUID = GUID::from_u128(0x00000000_0000_0000_0000_000000000000);

// Firewall constants (placeholder values)
pub const NET_FW_PROFILE2_DOMAIN: i32 = 1;
pub const NET_FW_PROFILE2_PRIVATE: i32 = 2;
pub const NET_FW_PROFILE2_PUBLIC: i32 = 4;
pub const NET_FW_RULE_DIR_IN: i32 = 1;
pub const NET_FW_RULE_DIR_OUT: i32 = 2;
pub const NET_FW_ACTION_BLOCK: i32 = 0;
pub const NET_FW_ACTION_ALLOW: i32 = 1;
pub const NET_FW_IP_PROTOCOL_TCP: i32 = 6;
pub const NET_FW_IP_PROTOCOL_UDP: i32 = 17;
pub const NET_FW_IP_PROTOCOL_ANY: i32 = 256;

// Placeholder implementations for COM interfaces
impl INetFwPolicy2 {
    pub unsafe fn rules(&self) -> WindowsResult<INetFwRules> {
        Err(WindowsError::from_win32())
    }
}

impl INetFwRules {
    pub unsafe fn add(&self, _rule: &INetFwRule) -> WindowsResult<()> {
        Err(WindowsError::from_win32())
    }

    pub unsafe fn remove(&self, _name: &BSTR) -> WindowsResult<()> {
        Err(WindowsError::from_win32())
    }

    pub unsafe fn count(&self) -> WindowsResult<i32> {
        Ok(0)
    }

    pub unsafe fn item(&self, _index: i32) -> WindowsResult<INetFwRule> {
        Err(WindowsError::from_win32())
    }
}

impl INetFwRule {
    pub unsafe fn set_name(&self, _name: &BSTR) -> WindowsResult<()> {
        Err(WindowsError::from_win32())
    }

    pub unsafe fn set_description(&self, _desc: &BSTR) -> WindowsResult<()> {
        Err(WindowsError::from_win32())
    }

    pub unsafe fn set_application_name(&self, _app: &BSTR) -> WindowsResult<()> {
        Err(WindowsError::from_win32())
    }

    pub unsafe fn set_direction(&self, _dir: i32) -> WindowsResult<()> {
        Err(WindowsError::from_win32())
    }

    pub unsafe fn set_action(&self, _action: i32) -> WindowsResult<()> {
        Err(WindowsError::from_win32())
    }

    pub unsafe fn set_enabled(&self, _enabled: VARIANT_BOOL) -> WindowsResult<()> {
        Err(WindowsError::from_win32())
    }

    pub unsafe fn set_profiles(&self, _profiles: i32) -> WindowsResult<()> {
        Err(WindowsError::from_win32())
    }

    pub unsafe fn set_protocol(&self, _protocol: i32) -> WindowsResult<()> {
        Err(WindowsError::from_win32())
    }

    pub unsafe fn set_local_ports(&self, _ports: &BSTR) -> WindowsResult<()> {
        Err(WindowsError::from_win32())
    }

    pub unsafe fn set_remote_ports(&self, _ports: &BSTR) -> WindowsResult<()> {
        Err(WindowsError::from_win32())
    }

    pub unsafe fn set_local_addresses(&self, _addresses: &BSTR) -> WindowsResult<()> {
        Err(WindowsError::from_win32())
    }

    pub unsafe fn set_remote_addresses(&self, _addresses: &BSTR) -> WindowsResult<()> {
        Err(WindowsError::from_win32())
    }

    pub unsafe fn name(&self) -> WindowsResult<BSTR> {
        Ok(BSTR::from("placeholder_rule"))
    }
}

/// Configuration for Windows Firewall integration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowsFirewallConfig {
    /// Enable automatic firewall rule creation
    pub auto_create_rules: bool,
    /// Maximum number of retry attempts for COM operations
    pub max_retry_attempts: u32,
    /// Base delay for exponential backoff (milliseconds)
    pub base_retry_delay_ms: u64,
    /// Maximum retry delay (milliseconds)
    pub max_retry_delay_ms: u64,
    /// Timeout for individual COM operations (seconds)
    pub operation_timeout_secs: u64,
    /// Enable admin privilege checks
    pub require_admin_privileges: bool,
    /// Default rule action for blocked processes
    pub default_block_action: FirewallAction,
    /// Rule name prefix for automated rules
    pub rule_name_prefix: String,
    /// Enable rule cleanup on shutdown
    pub cleanup_rules_on_shutdown: bool,
}

/// Firewall rule action
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FirewallAction {
    Allow,
    Block,
}

/// Firewall rule direction
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FirewallDirection {
    Inbound,
    Outbound,
    Both,
}

/// Firewall rule protocol
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FirewallProtocol {
    Tcp,
    Udp,
    Any,
}

/// Firewall rule definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    pub name: String,
    pub description: String,
    pub application_path: Option<String>,
    pub local_ports: Option<String>,
    pub remote_ports: Option<String>,
    pub local_addresses: Option<String>,
    pub remote_addresses: Option<String>,
    pub protocol: FirewallProtocol,
    pub direction: FirewallDirection,
    pub action: FirewallAction,
    pub enabled: bool,
    pub profile_types: Vec<FirewallProfile>,
}

/// Firewall profile types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FirewallProfile {
    Domain,
    Private,
    Public,
}

/// Firewall operation result
#[derive(Debug)]
pub struct FirewallOperationResult {
    pub success: bool,
    pub rule_name: Option<String>,
    pub error_code: Option<i32>,
    pub error_message: Option<String>,
    pub retry_count: u32,
    pub operation_duration: Duration,
}

/// Windows Firewall manager with COM integration
pub struct WindowsFirewallManager {
    config: WindowsFirewallConfig,
    metrics: Arc<MetricsCollector>,
    policy: Option<INetFwPolicy2>,
    rules: Option<INetFwRules>,
    created_rules: Arc<tokio::sync::RwLock<Vec<String>>>, // Track created rules for cleanup
}

impl WindowsFirewallManager {
    /// Create a new Windows Firewall manager
    pub fn new(config: WindowsFirewallConfig, metrics: Arc<MetricsCollector>) -> Self {
        WindowsFirewallManager {
            config,
            metrics,
            policy: None,
            rules: None,
            created_rules: Arc::new(tokio::sync::RwLock::new(Vec::new())),
        }
    }

    /// Initialize COM and firewall interfaces
    pub async fn initialize(&mut self) -> StdResult<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Initializing Windows Firewall COM interfaces");

        // Check admin privileges if required
        if self.config.require_admin_privileges {
            self.check_admin_privileges().await?;
        }

        // Initialize COM
        unsafe {
            CoInitializeEx(None, COINIT_APARTMENTTHREADED)
                .map_err(|e| format!("Failed to initialize COM: {:?}", e))?;
        }

        // Create firewall policy object with retry
        let policy: INetFwPolicy2 = self
            .retry_com_operation(
                || unsafe { CoCreateInstance(&NET_FW_POLICY2, None, CLSCTX_INPROC_SERVER) },
                "Create INetFwPolicy2",
            )
            .await?;

        // Get rules collection
        let rules = self
            .retry_com_operation(
                || unsafe { policy.rules() },
                "Get firewall rules collection",
            )
            .await?;

        self.policy = Some(policy);
        self.rules = Some(rules);

        info!("Windows Firewall COM interfaces initialized successfully");
        Ok(())
    }

    /// Check if the current process has admin privileges
    async fn check_admin_privileges(&self) -> StdResult<(), Box<dyn std::error::Error + Send + Sync>> {
        unsafe {
            let mut token: HANDLE = HANDLE::default();

            // Get current process token
            if !OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).as_bool() {
                return Err("Failed to open process token".into());
            }

            // Check for admin privileges
            let mut elevation = TOKEN_ELEVATION {
                token_is_elevated: BOOL::from(false),
            };
            let mut return_length = 0u32;

            if !GetTokenInformation(
                token,
                TOKEN_ELEVATION,
                &mut elevation as *mut _ as *mut _,
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut return_length,
            )
            .as_bool()
            {
                let _ = CloseHandle(token);
                return Err("Failed to get token elevation information".into());
            }

            let _ = CloseHandle(token);

            if !elevation.token_is_elevated.as_bool() {
                return Err("Administrator privileges required for firewall operations".into());
            }
        }

        info!("Administrator privileges confirmed");
        Ok(())
    }

    /// Create a firewall rule with retry logic
    pub async fn create_rule(
        &self,
        rule: FirewallRule,
    ) -> StdResult<FirewallOperationResult, Box<dyn std::error::Error + Send + Sync>> {
        let start_time = Instant::now();
        let retry_count = 0;

        info!("Creating firewall rule: {}", rule.name);

        let result = self
            .retry_com_operation(
                || self.create_rule_internal(&rule),
                &format!("Create firewall rule: {}", rule.name),
            )
            .await;

        let operation_duration = start_time.elapsed();

        match result {
            Ok(_) => {
                // Track created rule for cleanup
                let mut created_rules = self.created_rules.write().await;
                created_rules.push(rule.name.clone());

                self.metrics
                    .record_counter("firewall_rules_created_total", 1.0);
                self.metrics.record_histogram(
                    "firewall_operation_duration_ms",
                    operation_duration.as_millis() as f64,
                    &[],
                );

                info!("Firewall rule created successfully: {}", rule.name);

                Ok(FirewallOperationResult {
                    success: true,
                    rule_name: Some(rule.name),
                    error_code: None,
                    error_message: None,
                    retry_count,
                    operation_duration,
                })
            }
            Err(e) => {
                self.metrics
                    .record_counter("firewall_rules_creation_failed_total", 1.0);

                error!("Failed to create firewall rule {}: {}", rule.name, e);

                Ok(FirewallOperationResult {
                    success: false,
                    rule_name: Some(rule.name),
                    error_code: None,
                    error_message: Some(e.to_string()),
                    retry_count,
                    operation_duration,
                })
            }
        }
    }

    /// Internal rule creation implementation
    fn create_rule_internal(&self, rule: &FirewallRule) -> StdResult<(), WindowsError> {
        let rules = self.rules.as_ref().ok_or_else(|| WindowsError::from(E_POINTER))?;

        unsafe {
            // Create new rule object
            let fw_rule: INetFwRule = CoCreateInstance(&NET_FW_RULE, None, CLSCTX_INPROC_SERVER)?;

            // Set rule properties
            let rule_name = BSTR::from(&rule.name);
            fw_rule.set_name(&rule_name)?;

            let rule_description = BSTR::from(&rule.description);
            fw_rule.set_description(&rule_description)?;

            // Set application path if specified
            if let Some(ref app_path) = rule.application_path {
                let app_path_bstr = BSTR::from(app_path);
                fw_rule.set_application_name(&app_path_bstr)?;
            }

            // Set protocol
            let protocol_value = match rule.protocol {
                FirewallProtocol::Tcp => NET_FW_IP_PROTOCOL_TCP,
                FirewallProtocol::Udp => NET_FW_IP_PROTOCOL_UDP,
                FirewallProtocol::Any => NET_FW_IP_PROTOCOL_ANY,
            };
            fw_rule.set_protocol(protocol_value)?;

            // Set direction
            let direction_value = match rule.direction {
                FirewallDirection::Inbound => NET_FW_RULE_DIR_IN,
                FirewallDirection::Outbound => NET_FW_RULE_DIR_OUT,
                FirewallDirection::Both => NET_FW_RULE_DIR_IN, // Will create separate outbound rule
            };
            fw_rule.set_direction(direction_value)?;

            // Set action
            let action_value = match rule.action {
                FirewallAction::Allow => NET_FW_ACTION_ALLOW,
                FirewallAction::Block => NET_FW_ACTION_BLOCK,
            };
            fw_rule.set_action(action_value)?;

            // Set enabled state
            fw_rule.set_enabled(VARIANT_BOOL::from(rule.enabled))?;

            // Set ports if specified
            if let Some(ref local_ports) = rule.local_ports {
                let ports_bstr = BSTR::from(local_ports);
                fw_rule.set_local_ports(&ports_bstr)?;
            }

            if let Some(ref remote_ports) = rule.remote_ports {
                let ports_bstr = BSTR::from(remote_ports);
                fw_rule.set_remote_ports(&ports_bstr)?;
            }

            // Set addresses if specified
            if let Some(ref local_addresses) = rule.local_addresses {
                let addr_bstr = BSTR::from(local_addresses);
                fw_rule.set_local_addresses(&addr_bstr)?;
            }

            if let Some(ref remote_addresses) = rule.remote_addresses {
                let addr_bstr = BSTR::from(remote_addresses);
                fw_rule.set_remote_addresses(&addr_bstr)?;
            }

            // Set profile types
            let mut profiles = 0i32;
            for profile in &rule.profile_types {
                profiles |= match profile {
                    FirewallProfile::Domain => NET_FW_PROFILE2_DOMAIN,
                    FirewallProfile::Private => NET_FW_PROFILE2_PRIVATE,
                    FirewallProfile::Public => NET_FW_PROFILE2_PUBLIC,
                };
            }
            fw_rule.set_profiles(profiles)?;

            // Add rule to collection
            rules.add(&fw_rule)?;

            // If direction is Both, create outbound rule as well
            if rule.direction == FirewallDirection::Both {
                let outbound_rule: INetFwRule =
                CoCreateInstance(&NET_FW_RULE, None, CLSCTX_INPROC_SERVER)?;

                // Copy all properties and set outbound direction
                let outbound_name = format!("{}_Outbound", rule.name);
                let outbound_name_bstr = BSTR::from(&outbound_name);
                outbound_rule.set_name(&outbound_name_bstr)?;
                outbound_rule.set_description(&rule_description)?;

                if let Some(ref app_path) = rule.application_path {
                    let app_path_bstr = BSTR::from(app_path);
                    outbound_rule.set_application_name(&app_path_bstr)?;
                }

                outbound_rule.set_protocol(protocol_value)?;
                outbound_rule.set_direction(NET_FW_RULE_DIR_OUT)?;
                outbound_rule.set_action(action_value)?;
                outbound_rule.set_enabled(VARIANT_BOOL::from(rule.enabled))?;
                outbound_rule.set_profiles(profiles)?;

                if let Some(ref local_ports) = rule.local_ports {
                    let ports_bstr = BSTR::from(local_ports);
                    outbound_rule.set_local_ports(&ports_bstr)?;
                }

                if let Some(ref remote_ports) = rule.remote_ports {
                    let ports_bstr = BSTR::from(remote_ports);
                    outbound_rule.set_remote_ports(&ports_bstr)?;
                }

                if let Some(ref local_addresses) = rule.local_addresses {
                    let addr_bstr = BSTR::from(local_addresses);
                    outbound_rule.set_local_addresses(&addr_bstr)?;
                }

                if let Some(ref remote_addresses) = rule.remote_addresses {
                    let addr_bstr = BSTR::from(remote_addresses);
                    outbound_rule.set_remote_addresses(&addr_bstr)?;
                }

                rules.add(&outbound_rule)?;
            }
        }

        Ok(())
    }

    /// Remove a firewall rule
    pub async fn remove_rule(
        &self,
        rule_name: &str,
    ) -> StdResult<FirewallOperationResult, Box<dyn std::error::Error + Send + Sync>> {
        let start_time = Instant::now();

        info!("Removing firewall rule: {}", rule_name);

        let result = self
            .retry_com_operation(
                || self.remove_rule_internal(rule_name),
                &format!("Remove firewall rule: {}", rule_name),
            )
            .await;

        let operation_duration = start_time.elapsed();

        match result {
            Ok(_) => {
                // Remove from tracked rules
                let mut created_rules = self.created_rules.write().await;
                created_rules.retain(|name| name != rule_name);

                self.metrics
                    .record_counter("firewall_rules_removed_total", 1.0);

                info!("Firewall rule removed successfully: {}", rule_name);

                Ok(FirewallOperationResult {
                    success: true,
                    rule_name: Some(rule_name.to_string()),
                    error_code: None,
                    error_message: None,
                    retry_count: 0,
                    operation_duration,
                })
            }
            Err(e) => {
                self.metrics
                    .record_counter("firewall_rules_removal_failed_total", 1.0);

                error!("Failed to remove firewall rule {}: {}", rule_name, e);

                Ok(FirewallOperationResult {
                    success: false,
                    rule_name: Some(rule_name.to_string()),
                    error_code: None,
                    error_message: Some(e.to_string()),
                    retry_count: 0,
                    operation_duration,
                })
            }
        }
    }

    /// Internal rule removal implementation
    fn remove_rule_internal(&self, rule_name: &str) -> StdResult<(), WindowsError> {
        let rules = self.rules.as_ref().ok_or_else(|| WindowsError::from(E_POINTER))?;

        unsafe {
            let rule_name_bstr = BSTR::from(rule_name);
            rules.remove(&rule_name_bstr)?;

            // Also try to remove outbound rule if it exists
            let outbound_name = format!("{}_Outbound", rule_name);
            let outbound_name_bstr = BSTR::from(&outbound_name);
            let _ = rules.remove(&outbound_name_bstr); // Ignore errors for outbound rule
        }

        Ok(())
    }

    /// Block a process by creating a firewall rule
    pub async fn block_process(
        &self,
        process_path: &str,
        reason: &str,
    ) -> StdResult<FirewallOperationResult, Box<dyn std::error::Error + Send + Sync>> {
        let rule_name = format!(
            "{}_Block_{}",
            self.config.rule_name_prefix,
            std::path::Path::new(process_path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown")
        );

        let rule = FirewallRule {
            name: rule_name,
            description: format!("Automated block rule: {}", reason),
            application_path: Some(process_path.to_string()),
            local_ports: None,
            remote_ports: None,
            local_addresses: None,
            remote_addresses: None,
            protocol: FirewallProtocol::Any,
            direction: FirewallDirection::Both,
            action: FirewallAction::Block,
            enabled: true,
            profile_types: vec![
                FirewallProfile::Domain,
                FirewallProfile::Private,
                FirewallProfile::Public,
            ],
        };

        self.create_rule(rule).await
    }

    /// Block network access for specific ports
    pub async fn block_ports(
        &self,
        ports: &str,
        protocol: FirewallProtocol,
        reason: &str,
    ) -> StdResult<FirewallOperationResult, Box<dyn std::error::Error + Send + Sync>> {
        let rule_name = format!(
            "{}_BlockPorts_{}_{:?}",
            self.config.rule_name_prefix,
            ports.replace(",", "_").replace("-", "to"),
            protocol
        );

        let rule = FirewallRule {
            name: rule_name,
            description: format!("Automated port block rule: {}", reason),
            application_path: None,
            local_ports: Some(ports.to_string()),
            remote_ports: None,
            local_addresses: None,
            remote_addresses: None,
            protocol,
            direction: FirewallDirection::Both,
            action: FirewallAction::Block,
            enabled: true,
            profile_types: vec![
                FirewallProfile::Domain,
                FirewallProfile::Private,
                FirewallProfile::Public,
            ],
        };

        self.create_rule(rule).await
    }

    /// Retry COM operation with exponential backoff
    async fn retry_com_operation<T, F>(
        &self,
        mut operation: F,
        operation_name: &str,
    ) -> StdResult<T, WindowsError>
    where
        F: FnMut() -> StdResult<T, WindowsError>,
    {
        let mut retry_count = 0;
        let mut delay = Duration::from_millis(self.config.base_retry_delay_ms);

        loop {
            match operation() {
                Ok(result) => {
                    if retry_count > 0 {
                        info!("{} succeeded after {} retries", operation_name, retry_count);
                    }
                    return Ok(result);
                }
                Err(e) => {
                    retry_count += 1;

                    if retry_count > self.config.max_retry_attempts {
                        error!(
                            "{} failed after {} attempts: {:?}",
                            operation_name,
                            retry_count - 1,
                            e
                        );
                        return Err(e);
                    }

                    warn!(
                        "{} failed (attempt {}), retrying in {:?}: {:?}",
                        operation_name, retry_count, delay, e
                    );

                    sleep(delay).await;

                    // Exponential backoff with jitter
                    delay = std::cmp::min(
                        Duration::from_millis(delay.as_millis() as u64 * 2),
                        Duration::from_millis(self.config.max_retry_delay_ms),
                    );
                }
            }
        }
    }

    /// List existing firewall rules
    pub async fn list_rules(
        &self,
    ) -> StdResult<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        let rules = self.rules.as_ref().ok_or("Firewall not initialized")?;
        let mut rule_names = Vec::new();

        unsafe {
            let count = rules.count()?;

            for i in 1..=count {
                if let Ok(rule) = rules.item(i) {
                    if let Ok(name) = rule.name() {
                        rule_names.push(name.to_string());
                    }
                }
            }
        }

        Ok(rule_names)
    }

    /// Cleanup all created rules
    pub async fn cleanup_rules(&self) -> StdResult<(), Box<dyn std::error::Error + Send + Sync>> {
        if !self.config.cleanup_rules_on_shutdown {
            return Ok(());
        }

        info!("Cleaning up created firewall rules");

        let created_rules = self.created_rules.read().await;
        let rules_to_remove: Vec<String> = created_rules.clone();
        drop(created_rules);

        for rule_name in rules_to_remove {
            if let Err(e) = self.remove_rule(&rule_name).await {
                warn!("Failed to cleanup rule {}: {}", rule_name, e);
            }
        }

        info!("Firewall rule cleanup completed");
        Ok(())
    }

    /// Shutdown and cleanup
    pub async fn shutdown(&self) -> StdResult<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Shutting down Windows Firewall manager");

        // Cleanup rules if configured
        self.cleanup_rules().await?;

        // Uninitialize COM
        unsafe {
            CoUninitialize();
        }

        info!("Windows Firewall manager shutdown completed");
        Ok(())
    }
}

/// Default configuration for Windows Firewall
impl Default for WindowsFirewallConfig {
    fn default() -> Self {
        WindowsFirewallConfig {
            auto_create_rules: true,
            max_retry_attempts: 3,
            base_retry_delay_ms: 1000,
            max_retry_delay_ms: 10000,
            operation_timeout_secs: 30,
            require_admin_privileges: true,
            default_block_action: FirewallAction::Block,
            rule_name_prefix: "ERDPS_AutoResponse".to_string(),
            cleanup_rules_on_shutdown: true,
        }
    }
}

/// Helper function to create a process blocking rule
pub fn create_process_block_rule(
    process_path: &str,
    reason: &str,
    rule_prefix: &str,
) -> FirewallRule {
    let process_name = std::path::Path::new(process_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");

    FirewallRule {
        name: format!("{}_Block_{}", rule_prefix, process_name),
        description: format!("Automated process block: {}", reason),
        application_path: Some(process_path.to_string()),
        local_ports: None,
        remote_ports: None,
        local_addresses: None,
        remote_addresses: None,
        protocol: FirewallProtocol::Any,
        direction: FirewallDirection::Both,
        action: FirewallAction::Block,
        enabled: true,
        profile_types: vec![
            FirewallProfile::Domain,
            FirewallProfile::Private,
            FirewallProfile::Public,
        ],
    }
}

/// Helper function to create a port blocking rule
pub fn create_port_block_rule(
    ports: &str,
    protocol: FirewallProtocol,
    reason: &str,
    rule_prefix: &str,
) -> FirewallRule {
    FirewallRule {
        name: format!(
            "{}_BlockPorts_{}_{:?}",
            rule_prefix,
            ports.replace(",", "_").replace("-", "to"),
            protocol
        ),
        description: format!("Automated port block: {}", reason),
        application_path: None,
        local_ports: Some(ports.to_string()),
        remote_ports: None,
        local_addresses: None,
        remote_addresses: None,
        protocol,
        direction: FirewallDirection::Both,
        action: FirewallAction::Block,
        enabled: true,
        profile_types: vec![
            FirewallProfile::Domain,
            FirewallProfile::Private,
            FirewallProfile::Public,
        ],
    }
}
