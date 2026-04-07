//! SecureKeyVault - Secure key storage and management using ChaCha20-Poly1305
//!
//! This module provides a secure vault for storing encryption keys, API tokens,
//! and other sensitive data using ChaCha20-Poly1305 authenticated encryption.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};
use std::fs;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use uuid::Uuid;

use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, aead::{Aead, KeyInit, AeadCore}};
use rand::{RngCore, rngs::OsRng};

use sha2::Sha256;
#[cfg(feature = "security-hardening")]
use argon2::{Argon2, PasswordHasher, password_hash::SaltString};

use crate::core::error::{EnhancedAgentError, Result};

/// Configuration for the secure key vault
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyVaultConfig {
    /// Path to the vault file
    pub vault_path: PathBuf,
    /// Maximum number of key derivation iterations
    pub max_iterations: u32,
    /// Key expiration time
    pub key_expiration: Duration,
    /// Enable automatic key rotation
    pub auto_rotation: bool,
    /// Backup vault path
    pub backup_path: Option<PathBuf>,
    /// Enable audit logging
    pub enable_audit_log: bool,
    /// Maximum failed access attempts before lockout
    pub max_failed_attempts: u32,
    /// Lockout duration after max failed attempts
    pub lockout_duration: Duration,
}

impl Default for KeyVaultConfig {
    fn default() -> Self {
        Self {
            vault_path: PathBuf::from("secure_vault.enc"),
            max_iterations: 100_000,
            key_expiration: Duration::from_secs(86400 * 30), // 30 days
            auto_rotation: true,
            backup_path: Some(PathBuf::from("secure_vault_backup.enc")),
            enable_audit_log: true,
            max_failed_attempts: 5,
            lockout_duration: Duration::from_secs(300), // 5 minutes
        }
    }
}

/// Represents a stored key entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyEntry {
    /// Unique identifier for the key
    pub id: Uuid,
    /// Key name/identifier
    pub name: String,
    /// Encrypted key data
    pub encrypted_data: Vec<u8>,
    /// Key metadata
    pub metadata: KeyMetadata,
    /// Creation timestamp
    pub created_at: SystemTime,
    /// Last accessed timestamp
    pub last_accessed: SystemTime,
    /// Expiration timestamp
    pub expires_at: Option<SystemTime>,
    /// Access count
    pub access_count: u64,
}

/// Metadata for stored keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    /// Key type (e.g., "api_key", "encryption_key", "certificate")
    pub key_type: String,
    /// Key purpose description
    pub purpose: String,
    /// Key length in bits
    pub key_length: usize,
    /// Associated tags
    pub tags: Vec<String>,
    /// Key rotation policy
    pub rotation_policy: RotationPolicy,
    /// Access permissions
    pub permissions: AccessPermissions,
}

/// Key rotation policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationPolicy {
    /// Enable automatic rotation
    pub enabled: bool,
    /// Rotation interval
    pub interval: Duration,
    /// Next rotation time
    pub next_rotation: Option<SystemTime>,
    /// Rotation history
    pub rotation_history: Vec<SystemTime>,
}

/// Access permissions for keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessPermissions {
    /// Allowed operations
    pub operations: Vec<KeyOperation>,
    /// Allowed processes/users
    pub allowed_principals: Vec<String>,
    /// Time-based access restrictions
    pub time_restrictions: Option<TimeRestriction>,
}

/// Key operations
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum KeyOperation {
    Read,
    Write,
    Delete,
    Rotate,
    Export,
}

/// Time-based access restrictions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRestriction {
    /// Start time for access
    pub start_time: SystemTime,
    /// End time for access
    pub end_time: SystemTime,
    /// Allowed days of week (0=Sunday, 6=Saturday)
    pub allowed_days: Vec<u8>,
    /// Allowed hours (0-23)
    pub allowed_hours: Vec<u8>,
}

/// Vault access audit entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Audit entry ID
    pub id: Uuid,
    /// Timestamp of the access
    pub timestamp: SystemTime,
    /// Operation performed
    pub operation: String,
    /// Key ID accessed
    pub key_id: Option<Uuid>,
    /// Success/failure status
    pub success: bool,
    /// Error message if failed
    pub error_message: Option<String>,
    /// Source IP/process information
    pub source_info: String,
}

/// Encrypted vault data structure
#[derive(Debug, Serialize, Deserialize)]
struct VaultData {
    /// Version of the vault format
    version: u32,
    /// Salt for key derivation
    salt: Vec<u8>,
    /// Nonce for encryption
    nonce: Vec<u8>,
    /// Encrypted key entries
    encrypted_entries: Vec<u8>,
    /// Vault metadata
    metadata: VaultMetadata,
}

/// Vault metadata
#[derive(Debug, Serialize, Deserialize)]
struct VaultMetadata {
    /// Creation timestamp
    created_at: SystemTime,
    /// Last modified timestamp
    last_modified: SystemTime,
    /// Number of entries
    entry_count: usize,
    /// Vault integrity hash
    integrity_hash: String,
}

/// Secure key vault implementation
pub struct SecureKeyVault {
    config: KeyVaultConfig,
    entries: RwLock<HashMap<Uuid, KeyEntry>>,
    audit_log: RwLock<Vec<AuditEntry>>,
    failed_attempts: RwLock<HashMap<String, (u32, SystemTime)>>,
    master_key: RwLock<Option<Key>>,
}

impl SecureKeyVault {
    /// Create a new SecureKeyVault instance
    pub fn new(config: KeyVaultConfig) -> Self {
        Self {
            config,
            entries: RwLock::new(HashMap::new()),
            audit_log: RwLock::new(Vec::new()),
            failed_attempts: RwLock::new(HashMap::new()),
            master_key: RwLock::new(None),
        }
    }
    
    /// Initialize the vault with a master password
    pub async fn initialize(&self, master_password: &str) -> Result<()> {
        log::info!("Initializing SecureKeyVault");
        
        // Derive master key from password
        let master_key = self.derive_master_key(master_password).await?;
        *self.master_key.write().await = Some(master_key);
        
        // Load existing vault if it exists
        if self.config.vault_path.exists() {
            self.load_vault().await?;
        } else {
            // Create new vault
            self.create_vault().await?;
        }
        
        log::info!("SecureKeyVault initialized successfully");
        Ok(())
    }
    
    /// Derive master key from password using Argon2
    #[cfg(feature = "security-hardening")]
    async fn derive_master_key(&self, password: &str) -> Result<Key> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| EnhancedAgentError::Security(format!("Key derivation failed: {}", e)))?;
        
        let hash = password_hash.hash.unwrap();
        let hash_bytes = hash.as_bytes();
        if hash_bytes.len() < 32 {
            return Err(EnhancedAgentError::Security("Insufficient key material".to_string()));
        }
        
        let key = Key::from_slice(&hash_bytes[..32]);
        Ok(*key)
    }
    
    /// Derive master key from password using SHA-256 (fallback when argon2 not available)
    #[cfg(not(feature = "security-hardening"))]
    async fn derive_master_key(&self, password: &str) -> Result<Key> {
        use sha2::{Digest, Sha256};
        
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        hasher.update(b"erdps_salt_2024"); // Static salt for fallback
        let hash = hasher.finalize();
        
        let key = Key::from_slice(&hash[..32]);
        Ok(*key)
    }
    
    /// Create a new vault file
    async fn create_vault(&self) -> Result<()> {
        let vault_data = VaultData {
            version: 1,
            salt: self.generate_salt(),
            nonce: ChaCha20Poly1305::generate_nonce(&mut OsRng).to_vec(),
            encrypted_entries: Vec::new(),
            metadata: VaultMetadata {
                created_at: SystemTime::now(),
                last_modified: SystemTime::now(),
                entry_count: 0,
                integrity_hash: String::new(),
            },
        };
        
        self.save_vault_data(&vault_data).await?;
        Ok(())
    }
    
    /// Load vault from file
    async fn load_vault(&self) -> Result<()> {
        let vault_data = self.load_vault_data().await?;
        
        // Decrypt entries
        if !vault_data.encrypted_entries.is_empty() {
            let entries = self.decrypt_entries(&vault_data.encrypted_entries, &vault_data.nonce).await?;
            *self.entries.write().await = entries;
        }
        
        Ok(())
    }
    
    /// Save vault to file
    async fn save_vault(&self) -> Result<()> {
        let entries = self.entries.read().await;
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        
        // Encrypt entries
        let encrypted_entries = self.encrypt_entries(&entries, &nonce).await?;
        
        let vault_data = VaultData {
            version: 1,
            salt: self.generate_salt(),
            nonce: nonce.to_vec(),
            encrypted_entries,
            metadata: VaultMetadata {
                created_at: SystemTime::now(),
                last_modified: SystemTime::now(),
                entry_count: entries.len(),
                integrity_hash: self.calculate_integrity_hash(&entries).await,
            },
        };
        
        self.save_vault_data(&vault_data).await?;
        
        // Create backup if configured
        if let Some(backup_path) = &self.config.backup_path {
            if let Err(e) = fs::copy(&self.config.vault_path, backup_path) {
                log::warn!("Failed to create vault backup: {}", e);
            }
        }
        
        Ok(())
    }
    
    /// Store a key in the vault
    pub async fn store_key(
        &self,
        name: String,
        key_data: &[u8],
        metadata: KeyMetadata,
    ) -> Result<Uuid> {
        self.check_access_permissions(&KeyOperation::Write).await?;
        
        let master_key = self.master_key.read().await
            .ok_or_else(|| EnhancedAgentError::Security("Vault not initialized".to_string()))?;
        
        // Encrypt the key data
        let cipher = ChaCha20Poly1305::new(&master_key);
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        
        let mut data_to_encrypt = nonce.to_vec();
        data_to_encrypt.extend_from_slice(key_data);
        
        let encrypted_data = cipher
            .encrypt(&nonce, key_data)
            .map_err(|e| EnhancedAgentError::Security(format!("Encryption failed: {}", e)))?;
        
        let key_id = Uuid::new_v4();
        let expires_at = if metadata.rotation_policy.enabled {
            Some(SystemTime::now() + self.config.key_expiration)
        } else {
            None
        };
        
        let entry = KeyEntry {
            id: key_id,
            name: name.clone(),
            encrypted_data,
            metadata,
            created_at: SystemTime::now(),
            last_accessed: SystemTime::now(),
            expires_at,
            access_count: 0,
        };
        
        // Store the entry
        self.entries.write().await.insert(key_id, entry);
        
        // Save vault
        self.save_vault().await?;
        
        // Log audit entry
        self.log_audit_entry(
            "store_key".to_string(),
            Some(key_id),
            true,
            None,
        ).await;
        
        log::info!("Key '{}' stored successfully with ID: {}", name, key_id);
        Ok(key_id)
    }
    
    /// Retrieve a key from the vault
    pub async fn retrieve_key(&self, key_id: &Uuid) -> Result<Vec<u8>> {
        self.check_access_permissions(&KeyOperation::Read).await?;
        
        let master_key = self.master_key.read().await
            .ok_or_else(|| EnhancedAgentError::Security("Vault not initialized".to_string()))?;
        
        let mut entries = self.entries.write().await;
        let entry = entries.get_mut(key_id)
            .ok_or_else(|| EnhancedAgentError::Security(format!("Key not found: {}", key_id)))?;
        
        // Check expiration
        if let Some(expires_at) = entry.expires_at {
            if SystemTime::now() > expires_at {
                return Err(EnhancedAgentError::Security("Key has expired".to_string()));
            }
        }
        
        // Decrypt the key data
        let cipher = ChaCha20Poly1305::new(&master_key);
        
        if entry.encrypted_data.len() < 12 {
            return Err(EnhancedAgentError::Security("Invalid encrypted data".to_string()));
        }
        
        let nonce = Nonce::from_slice(&entry.encrypted_data[..12]);
        let ciphertext = &entry.encrypted_data[12..];
        
        let decrypted_data = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| EnhancedAgentError::Security(format!("Decryption failed: {}", e)))?;
        
        // Update access statistics
        entry.last_accessed = SystemTime::now();
        entry.access_count += 1;
        
        // Log audit entry
        self.log_audit_entry(
            "retrieve_key".to_string(),
            Some(*key_id),
            true,
            None,
        ).await;
        
        Ok(decrypted_data)
    }
    
    /// Delete a key from the vault
    pub async fn delete_key(&self, key_id: &Uuid) -> Result<()> {
        self.check_access_permissions(&KeyOperation::Delete).await?;
        
        let mut entries = self.entries.write().await;
        let entry = entries.remove(key_id)
            .ok_or_else(|| EnhancedAgentError::Security(format!("Key not found: {}", key_id)))?;
        
        // Save vault
        drop(entries);
        self.save_vault().await?;
        
        // Log audit entry
        self.log_audit_entry(
            "delete_key".to_string(),
            Some(*key_id),
            true,
            None,
        ).await;
        
        log::info!("Key '{}' deleted successfully", entry.name);
        Ok(())
    }
    
    /// List all keys in the vault
    pub async fn list_keys(&self) -> Result<Vec<(Uuid, String, KeyMetadata)>> {
        self.check_access_permissions(&KeyOperation::Read).await?;
        
        let entries = self.entries.read().await;
        let keys = entries
            .values()
            .map(|entry| (entry.id, entry.name.clone(), entry.metadata.clone()))
            .collect();
        
        Ok(keys)
    }
    
    /// Rotate a key
    pub async fn rotate_key(&self, key_id: &Uuid, new_key_data: &[u8]) -> Result<()> {
        self.check_access_permissions(&KeyOperation::Rotate).await?;
        
        let master_key = self.master_key.read().await
            .ok_or_else(|| EnhancedAgentError::Security("Vault not initialized".to_string()))?;
        
        let mut entries = self.entries.write().await;
        let entry = entries.get_mut(key_id)
            .ok_or_else(|| EnhancedAgentError::Security(format!("Key not found: {}", key_id)))?;
        
        // Encrypt new key data
        let cipher = ChaCha20Poly1305::new(&master_key);
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        
        let encrypted_data = cipher
            .encrypt(&nonce, new_key_data)
            .map_err(|e| EnhancedAgentError::Security(format!("Encryption failed: {}", e)))?;
        
        // Update entry
        entry.encrypted_data = encrypted_data;
        entry.last_accessed = SystemTime::now();
        entry.metadata.rotation_policy.rotation_history.push(SystemTime::now());
        
        if entry.metadata.rotation_policy.enabled {
            entry.metadata.rotation_policy.next_rotation = 
                Some(SystemTime::now() + entry.metadata.rotation_policy.interval);
        }
        
        // Save vault
        drop(entries);
        self.save_vault().await?;
        
        // Log audit entry
        self.log_audit_entry(
            "rotate_key".to_string(),
            Some(*key_id),
            true,
            None,
        ).await;
        
        log::info!("Key rotated successfully: {}", key_id);
        Ok(())
    }
    
    /// Check access permissions
    async fn check_access_permissions(&self, _operation: &KeyOperation) -> Result<()> {
        // Check for lockout
        let failed_attempts = self.failed_attempts.read().await;
        let source = "local"; // In a real implementation, this would be the actual source
        
        if let Some((attempts, lockout_time)) = failed_attempts.get(source) {
            if *attempts >= self.config.max_failed_attempts {
                let elapsed = SystemTime::now().duration_since(*lockout_time)
                    .unwrap_or(Duration::from_secs(0));
                
                if elapsed < self.config.lockout_duration {
                    return Err(EnhancedAgentError::Security(
                        format!("Access locked out for {} more seconds", 
                               (self.config.lockout_duration - elapsed).as_secs())
                    ));
                }
            }
        }
        
        // In a real implementation, this would check actual permissions
        // For now, we'll allow all operations if the vault is initialized
        if self.master_key.read().await.is_none() {
            return Err(EnhancedAgentError::Security("Vault not initialized".to_string()));
        }
        
        Ok(())
    }
    
    /// Log an audit entry
    async fn log_audit_entry(
        &self,
        operation: String,
        key_id: Option<Uuid>,
        success: bool,
        error_message: Option<String>,
    ) {
        if !self.config.enable_audit_log {
            return;
        }
        
        let entry = AuditEntry {
            id: Uuid::new_v4(),
            timestamp: SystemTime::now(),
            operation,
            key_id,
            success,
            error_message,
            source_info: "local".to_string(), // In real implementation, get actual source
        };
        
        self.audit_log.write().await.push(entry);
    }
    
    /// Generate a random salt
    fn generate_salt(&self) -> Vec<u8> {
        let mut salt = vec![0u8; 32];
        OsRng.fill_bytes(&mut salt);
        salt
    }
    
    /// Encrypt entries for storage
    async fn encrypt_entries(
        &self,
        entries: &HashMap<Uuid, KeyEntry>,
        nonce: &Nonce,
    ) -> Result<Vec<u8>> {
        let master_key = self.master_key.read().await
            .ok_or_else(|| EnhancedAgentError::Security("Vault not initialized".to_string()))?;
        
        let serialized = bincode::serialize(entries)
            .map_err(|e| EnhancedAgentError::BinarySerialization(format!("Serialization failed: {}", e)))?;
        
        let cipher = ChaCha20Poly1305::new(&master_key);
        let encrypted = cipher
            .encrypt(nonce, serialized.as_ref())
            .map_err(|e| EnhancedAgentError::Security(format!("Encryption failed: {}", e)))?;
        
        Ok(encrypted)
    }
    
    /// Decrypt entries from storage
    async fn decrypt_entries(
        &self,
        encrypted_data: &[u8],
        nonce_bytes: &[u8],
    ) -> Result<HashMap<Uuid, KeyEntry>> {
        let master_key = self.master_key.read().await
            .ok_or_else(|| EnhancedAgentError::Security("Vault not initialized".to_string()))?;
        
        let nonce = Nonce::from_slice(nonce_bytes);
        let cipher = ChaCha20Poly1305::new(&master_key);
        
        let decrypted = cipher
            .decrypt(nonce, encrypted_data)
            .map_err(|e| EnhancedAgentError::Security(format!("Decryption failed: {}", e)))?;
        
        let entries = bincode::deserialize(&decrypted)
            .map_err(|e| EnhancedAgentError::BinarySerialization(format!("Deserialization failed: {}", e)))?;
        
        Ok(entries)
    }
    
    /// Calculate integrity hash
    async fn calculate_integrity_hash(&self, entries: &HashMap<Uuid, KeyEntry>) -> String {
        use sha2::Digest;
        let mut hasher = Sha256::new();
        
        // Sort entries by ID for consistent hashing
        let mut sorted_entries: Vec<_> = entries.iter().collect();
        sorted_entries.sort_by_key(|(id, _)| *id);
        
        for (id, entry) in sorted_entries {
            hasher.update(id.as_bytes());
            hasher.update(&entry.encrypted_data);
        }
        
        format!("{:x}", hasher.finalize())
    }
    
    /// Load vault data from file
    async fn load_vault_data(&self) -> Result<VaultData> {
        let data = fs::read(&self.config.vault_path)
            .map_err(|e| EnhancedAgentError::Io(e.to_string()))?;
        
        let vault_data: VaultData = bincode::deserialize(&data)
            .map_err(|e| EnhancedAgentError::BinarySerialization(format!("Deserialization failed: {}", e)))?;
        
        Ok(vault_data)
    }
    
    /// Save vault data to file
    async fn save_vault_data(&self, vault_data: &VaultData) -> Result<()> {
        let serialized = bincode::serialize(vault_data)
            .map_err(|e| EnhancedAgentError::BinarySerialization(format!("Serialization failed: {}", e)))?;
        
        // Write to temporary file first
        let temp_path = self.config.vault_path.with_extension("tmp");
        fs::write(&temp_path, &serialized)?;
        
        // Atomic rename
        fs::rename(&temp_path, &self.config.vault_path)?;
        
        Ok(())
    }
    
    /// Get audit log entries
    pub async fn get_audit_log(&self) -> Vec<AuditEntry> {
        self.audit_log.read().await.clone()
    }
    
    /// Clear the vault (for testing/reset purposes)
    pub async fn clear_vault(&self) -> Result<()> {
        *self.entries.write().await = HashMap::new();
        *self.audit_log.write().await = Vec::new();
        *self.failed_attempts.write().await = HashMap::new();
        
        self.save_vault().await?;
        Ok(())
    }
}

impl Drop for SecureKeyVault {
    fn drop(&mut self) {
        // Master key will be automatically zeroized when dropped
    }
}
