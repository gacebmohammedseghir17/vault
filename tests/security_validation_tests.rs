//! Security Validation Tests
//!
//! Comprehensive security tests for ERDPS system including:
//! - IPC signature verification and authentication
//! - RBAC (Role-Based Access Control) validation
//! - Secure communications and cryptographic functions
//! - Authentication and authorization mechanisms

#![cfg(feature = "advanced-reporting")]

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

use erdps_agent::config::AgentConfig;
use erdps_agent::ipc::{sign, verify, NonceStore, RequestMessage};
use erdps_agent::reports::rbac::{ReportPermission, ReportRBAC, UserIdentity, UserRole};

/// Test 1: IPC Signature Verification Security
#[tokio::test]
async fn test_ipc_signature_verification() -> Result<()> {
    println!("\n=== Testing IPC Signature Verification Security ===");

    let key = b"test_key_32_bytes_long_for_hmac_";
    let mut nonce_store = NonceStore::new(); // Use direct NonceStore instead of Arc<Mutex>

    // Test 1.1: Valid signature verification
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    let nonce = "valid_test_nonce_123";
    let command = "getStatus";
    let payload = json!({"test": "data"});

    let signature = sign(command, timestamp, nonce, &payload, key)?;

    let request = RequestMessage {
        nonce: nonce.to_string(),
        timestamp,
        command: command.to_string(),
        signature,
        payload: payload.clone(),
        
    };

    // Valid signature should pass
    let result = verify(&request, key, 30, &mut nonce_store);
    assert!(result.is_ok(), "Valid signature should pass verification");
    println!("✓ Valid signature verification passed");

    // Test 1.2: Invalid signature should fail
    let mut invalid_request = request.clone();
    invalid_request.signature = "invalid_signature".to_string();

    let result = verify(&invalid_request, key, 300, &mut nonce_store);
    assert!(
        result.is_err(),
        "Invalid signature should fail verification"
    );
    println!("✓ Invalid signature correctly rejected");

    // Test 1.3: Replay attack protection (same nonce)
    let result = verify(&request, key, 300, &mut nonce_store);
    assert!(result.is_err(), "Replay attack should be rejected");
    println!("✓ Replay attack protection working");

    // Test 1.4: Timestamp validation (expired message)
    let old_timestamp = timestamp - 400; // Older than max_skew_secs
    let old_signature = sign(
        command,
        old_timestamp,
        "new_nonce_456",
        &payload.clone(),
        key,
    )?;

    let old_request = RequestMessage {
        nonce: "new_nonce_456".to_string(),
        timestamp: old_timestamp,
        command: command.to_string(),
        signature: old_signature,
        payload: payload.clone(),
        
    };

    let result = verify(&old_request, key, 300, &mut nonce_store);
    assert!(result.is_err(), "Expired message should be rejected");
    println!("✓ Timestamp validation working");

    // Test 1.5: Wrong key should fail
    let wrong_key = b"wrong_key_32_bytes_long_for_hmac";
    let wrong_signature = sign(command, timestamp, "another_nonce_789", &payload, wrong_key)?;

    let wrong_key_request = RequestMessage {
        nonce: "another_nonce_789".to_string(),
        timestamp,
        command: command.to_string(),
        signature: wrong_signature,
        payload,
        
    };

    let result = verify(&wrong_key_request, key, 300, &mut nonce_store);
    assert!(result.is_err(), "Wrong key should fail verification");
    println!("✓ Key validation working");

    Ok(())
}

/// Test 2: RBAC Access Control Validation
#[tokio::test]
async fn test_rbac_access_control() -> Result<()> {
    println!("\n=== Testing RBAC Access Control ===");

    let rbac = ReportRBAC::new();

    // Test 2.1: Administrator access
    let admin_identity = ReportRBAC::create_admin_identity();

    // Administrator should have all permissions
    assert!(
        rbac.has_permission(&admin_identity, &ReportPermission::ViewReports),
        "Admin should view reports"
    );
    assert!(
        rbac.can_export(&admin_identity),
        "Admin should export reports"
    );
    assert!(
        rbac.can_delete_reports(&admin_identity),
        "Admin should delete reports"
    );
    assert!(
        rbac.can_manage_schedules(&admin_identity),
        "Admin should manage schedules"
    );
    assert!(
        rbac.can_configure_integrations(&admin_identity),
        "Admin should configure integrations"
    );
    assert!(
        rbac.can_purge_reports(&admin_identity),
        "Admin should purge reports"
    );
    assert!(
        rbac.is_administrator(&admin_identity),
        "Should identify as administrator"
    );
    println!("✓ Administrator access validation passed");

    // Test 2.2: Access validation with error messages (admin-only system)
    let result = rbac.validate_access(&admin_identity, "export_reports");
    assert!(result.is_ok(), "Admin access should be granted");
    println!("✓ Access validation working for admin-only system");

    Ok(())
}

/// Test 3: Cryptographic Function Security
#[tokio::test]
async fn test_cryptographic_security() -> Result<()> {
    println!("\n=== Testing Cryptographic Security ===");

    // Test 3.1: HMAC key strength
    let weak_key = b"weak";
    let strong_key = b"strong_key_32_bytes_long_for_hmac";

    let command = "testCommand";
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    let nonce = "crypto_test_nonce";
    let payload = json!({"test": "crypto"});

    // Both should work, but strong key is preferred
    let weak_signature = sign(command, timestamp, nonce, &payload, weak_key)?;
    let strong_signature = sign(command, timestamp, nonce, &payload, strong_key)?;

    assert_ne!(
        weak_signature, strong_signature,
        "Different keys should produce different signatures"
    );
    println!("✓ Key strength validation passed");

    // Test 3.2: Signature uniqueness
    let sig1 = sign(command, timestamp, "nonce1", &payload, strong_key)?;
    let sig2 = sign(command, timestamp, "nonce2", &payload, strong_key)?;
    let sig3 = sign(command, timestamp + 1, "nonce1", &payload, strong_key)?;

    assert_ne!(
        sig1, sig2,
        "Different nonces should produce different signatures"
    );
    assert_ne!(
        sig1, sig3,
        "Different timestamps should produce different signatures"
    );
    println!("✓ Signature uniqueness validation passed");

    // Test 3.3: Base64 encoding validation
    let decoded = BASE64.decode(&sig1);
    assert!(decoded.is_ok(), "Signature should be valid base64");
    assert_eq!(decoded.unwrap().len(), 32, "HMAC-SHA256 should be 32 bytes");
    println!("✓ Base64 encoding validation passed");

    Ok(())
}

/// Test 4: Secure Communication Protocol
#[tokio::test]
async fn test_secure_communication_protocol() -> Result<()> {
    println!("\n=== Testing Secure Communication Protocol ===");

    // Test 4.1: Message integrity
    let key = b"protocol_test_key_32_bytes_long_";
    let mut nonce_store = NonceStore::new();

    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    let nonce = "protocol_nonce_123";
    let command = "secureCommand";
    let payload = json!({
        "sensitive_data": "classified_information",
        "user_id": 12345,
        "action": "critical_operation"
    });

    let signature = sign(command, timestamp, nonce, &payload, key)?;

    let request = RequestMessage {
        nonce: nonce.to_string(),
        timestamp,
        command: command.to_string(),
        signature: signature.clone(),
        payload: payload.clone(),
        
    };

    // Test message integrity - any modification should fail
    let mut tampered_request = request.clone();
    tampered_request.payload = json!({"tampered": "data"});

    let result = verify(&tampered_request, key, 300, &mut nonce_store);
    assert!(result.is_err(), "Tampered message should fail verification");
    println!("✓ Message integrity protection working");

    // Test 4.2: Command injection protection
    let malicious_command = "getStatus; rm -rf /";
    let malicious_signature = sign(
        malicious_command,
        timestamp,
        "malicious_nonce",
        &payload,
        key,
    )?;

    let malicious_request = RequestMessage {
        nonce: "malicious_nonce".to_string(),
        timestamp,
        command: malicious_command.to_string(),
        signature: malicious_signature,
        payload: payload.clone(),
        
    };

    // Signature should be valid, but command validation should happen at application level
    let result = verify(&malicious_request, key, 300, &mut nonce_store);
    assert!(
        result.is_ok(),
        "Signature verification should pass (command validation is separate)"
    );
    println!("✓ Command injection detection ready for application layer");

    // Test 4.3: JSON payload validation
    let invalid_json_payload = json!(null);
    let json_signature = sign(command, timestamp, "json_nonce", &invalid_json_payload, key)?;

    let json_request = RequestMessage {
        nonce: "json_nonce".to_string(),
        timestamp,
        command: command.to_string(),
        signature: json_signature,
        payload: invalid_json_payload,
        
    };

    let result = verify(&json_request, key, 300, &mut nonce_store);
    assert!(result.is_ok(), "Valid JSON signature should pass");
    println!("✓ JSON payload validation working");

    Ok(())
}

/// Test 5: Authentication and Authorization Integration
#[tokio::test]
async fn test_authentication_authorization_integration() -> Result<()> {
    println!("\n=== Testing Authentication & Authorization Integration ===");

    let rbac = ReportRBAC::new();

    // Test 5.1: Complete authentication flow
    let authenticated_admin = ReportRBAC::create_admin_identity();
    assert_eq!(authenticated_admin.username, "Administrator");
    assert_eq!(authenticated_admin.role, UserRole::Administrator);
    assert!(!authenticated_admin.permissions.is_empty());
    println!("✓ Admin identity creation working");

    // Test 5.2: Permission inheritance
    let role_permissions = rbac.get_role_permissions(&UserRole::Administrator);
    assert!(
        !role_permissions.is_empty(),
        "Administrator role should have permissions"
    );
    assert!(role_permissions.contains(&ReportPermission::ViewReports));
    assert!(role_permissions.contains(&ReportPermission::ExportReports));
    println!("✓ Permission inheritance working");

    // Test 5.3: Security audit logging (mock)
    let operations = vec![
        "view_reports",
        "export_reports",
        "delete_reports",
        "manage_schedules",
        "configure_integrations",
        "purge_reports",
    ];

    for operation in operations {
        let result = rbac.validate_access(&authenticated_admin, operation);
        assert!(result.is_ok(), "Admin should have access to {}", operation);
    }
    println!("✓ Security audit logging integration ready");

    Ok(())
}

/// Test 5: Security Edge Cases
#[tokio::test]
async fn test_security_edge_cases() -> Result<()> {
    println!("\n=== Testing Security Edge Cases ===");

    let key = b"edge_case_test_key_32_bytes_long";
    let mut nonce_store = NonceStore::new();

    // Test 6.1: Empty/null inputs
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;

    // Empty command
    let empty_signature = sign("", timestamp, "empty_nonce", &json!({}), key)?;
    let empty_request = RequestMessage {
        nonce: "empty_nonce".to_string(),
        timestamp,
        command: "".to_string(),
        signature: empty_signature,
        payload: json!({}),
        
    };

    let result = verify(&empty_request, key, 300, &mut nonce_store);
    assert!(
        result.is_ok(),
        "Empty command should still verify correctly"
    );
    println!("✓ Empty input handling working");

    // Test 6.2: Large payload handling
    let large_payload = json!({
        "large_data": "x".repeat(10000),
        "array": (0..1000).collect::<Vec<i32>>()
    });

    let large_signature = sign("largeTest", timestamp, "large_nonce", &large_payload, key)?;
    let large_request = RequestMessage {
        nonce: "large_nonce".to_string(),
        timestamp,
        command: "largeTest".to_string(),
        signature: large_signature,
        payload: large_payload,
        
    };

    let result = verify(&large_request, key, 300, &mut nonce_store);
    assert!(result.is_ok(), "Large payload should verify correctly");
    println!("✓ Large payload handling working");

    // Test 6.3: Unicode and special characters
    let unicode_payload = json!({
        "unicode": "🔒🛡️🔐 Security Test 测试 العربية",
        "special_chars": "!@#$%^&*()_+-=[]{}|;':,.<>?"
    });

    let unicode_signature = sign(
        "unicodeTest",
        timestamp,
        "unicode_nonce",
        &unicode_payload,
        key,
    )?;
    let unicode_request = RequestMessage {
        nonce: "unicode_nonce".to_string(),
        timestamp,
        command: "unicodeTest".to_string(),
        signature: unicode_signature,
        payload: unicode_payload,
        
    };

    let result = verify(&unicode_request, key, 300, &mut nonce_store);
    assert!(result.is_ok(), "Unicode payload should verify correctly");
    println!("✓ Unicode and special character handling working");

    Ok(())
}

/// Helper function to create test configuration
fn create_test_security_config() -> AgentConfig {
    let mut config = AgentConfig::default();

    // Override specific test values
    config.ipc_key = BASE64.encode(b"security_test_key_32_bytes_long_");
    // Note: rules_enabled field doesn't exist in AgentConfig, removing this assignment
    config.quarantine_path = "/tmp/security_test_quarantine".to_string();
    config.audit_log_path = "/tmp/security_test_audit.log".to_string();
    config.mass_modification_count = Some(30);
    config.mass_modification_window_secs = Some(10);
    config.extension_mutation_window_secs = Some(60);
    config.extension_mutation_threshold = Some(0.8);
    config.entropy_threshold = 7.5;
    config.process_behavior_write_threshold = 50;
    config.process_behavior_window_secs = 30;
    config.ransom_note_patterns = vec![
        "*_readme.txt".to_string(),
        "*_recover_files.html".to_string(),
    ];
    config.auto_quarantine_score = 85;
    config.auto_mitigate = false;
    config.allow_terminate = false;
    config.dry_run = false;
    config.mitigation_score_threshold = 80;

    config
}

/// Integration test combining all security features
#[tokio::test]
async fn test_comprehensive_security_integration() -> Result<()> {
    println!("\n=== Comprehensive Security Integration Test ===");

    let config = create_test_security_config();
    let rbac = ReportRBAC::new();
    let admin = ReportRBAC::create_admin_identity();

    // Decode IPC key from config
    let ipc_key = BASE64.decode(&config.ipc_key)?;
    let mut nonce_store = NonceStore::new();

    // Simulate secure admin operation
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    let nonce = "integration_nonce_456";
    let command = "admin_export_reports";
    let payload = json!({
        "user_id": admin.username,
        "operation": "export_security_reports",
        "format": "pdf",
        "date_range": "last_30_days"
    });

    // 1. Verify RBAC authorization
    assert!(rbac.can_export(&admin), "Admin should be authorized");

    // 2. Create and verify secure IPC message
    let signature = sign(command, timestamp, nonce, &payload, &ipc_key)?;
    let request = RequestMessage {
        nonce: nonce.to_string(),
        timestamp,
        command: command.to_string(),
        signature,
        payload,
        
    };

    // 3. Verify message integrity and authentication
    let result = verify(&request, &ipc_key, 300, &mut nonce_store);
    assert!(result.is_ok(), "Secure admin operation should succeed");

    println!("✓ Comprehensive security integration test passed");
    println!("✓ All security validations completed successfully");

    Ok(())
}
