//! Authentication and Authorization Module
//!
//! This module provides comprehensive authentication and authorization capabilities
//! including JWT tokens, session management, multi-factor authentication, and RBAC.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use tokio::sync::{RwLock, Mutex};
use uuid::Uuid;
use tracing::{warn, info};
use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, EncodingKey, DecodingKey};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::{SaltString, rand_core::OsRng}};
use ring::rand::SystemRandom;
use crate::error::{AgentError, AgentResult, ErrorContext};

/// Authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// JWT secret key
    pub jwt_secret: String,
    /// JWT token expiration time
    pub token_expiration: Duration,
    /// Refresh token expiration time
    pub refresh_token_expiration: Duration,
    /// Enable multi-factor authentication
    pub enable_mfa: bool,
    /// Session timeout
    pub session_timeout: Duration,
    /// Maximum concurrent sessions per user
    pub max_concurrent_sessions: u32,
    /// Password policy
    pub password_policy: PasswordPolicy,
    /// Rate limiting for authentication attempts
    pub auth_rate_limit: AuthRateLimit,
    /// Enable session tracking
    pub enable_session_tracking: bool,
    /// Secure cookie settings
    pub secure_cookies: bool,
}

/// Password policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordPolicy {
    pub min_length: usize,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_numbers: bool,
    pub require_special_chars: bool,
    pub max_age: Option<Duration>,
    pub history_count: usize,
}

/// Authentication rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRateLimit {
    pub max_attempts: u32,
    pub window_duration: Duration,
    pub lockout_duration: Duration,
}

/// User credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserCredentials {
    pub username: String,
    pub password_hash: String,
    pub salt: String,
    pub created_at: SystemTime,
    pub last_password_change: SystemTime,
    pub password_history: Vec<String>,
    pub is_active: bool,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
    pub mfa_enabled: bool,
    pub mfa_secret: Option<String>,
}

/// JWT claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,        // Subject (user ID)
    pub username: String,   // Username
    pub roles: Vec<String>, // User roles
    pub permissions: Vec<String>, // User permissions
    pub exp: usize,         // Expiration time
    pub iat: usize,         // Issued at
    pub jti: String,        // JWT ID
    pub session_id: String, // Session ID
}

/// Authentication token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthToken {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub scope: Vec<String>,
}

/// Session information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub session_id: String,
    pub user_id: String,
    pub username: String,
    pub created_at: SystemTime,
    pub last_activity: SystemTime,
    pub expires_at: SystemTime,
    pub ip_address: String,
    pub user_agent: String,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
    pub is_active: bool,
}

/// Authentication result
#[derive(Debug, Clone)]
pub enum AuthResult {
    Success {
        token: AuthToken,
        session: Session,
    },
    Failed {
        reason: String,
    },
    MfaRequired {
        temp_token: String,
        methods: Vec<MfaMethod>,
    },
    AccountLocked {
        unlock_time: SystemTime,
    },
}

/// Multi-factor authentication methods
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MfaMethod {
    TOTP,
    SMS,
    Email,
    Hardware,
}

/// Role-based access control
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub name: String,
    pub description: String,
    pub permissions: Vec<String>,
    pub is_active: bool,
}

/// Permission definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permission {
    pub name: String,
    pub description: String,
    pub resource: String,
    pub action: String,
}

/// Authentication attempt tracking
#[derive(Debug, Clone)]
struct AuthAttempt {
    username: String,
    ip_address: String,
    timestamp: SystemTime,
    success: bool,
}

/// Authentication service
pub struct AuthService {
    config: AuthConfig,
    users: Arc<RwLock<HashMap<String, UserCredentials>>>,
    sessions: Arc<RwLock<HashMap<String, Session>>>,
    roles: Arc<RwLock<HashMap<String, Role>>>,
    permissions: Arc<RwLock<HashMap<String, Permission>>>,
    auth_attempts: Arc<RwLock<Vec<AuthAttempt>>>,
    locked_accounts: Arc<RwLock<HashMap<String, SystemTime>>>,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    rng: Arc<Mutex<SystemRandom>>,
}

impl AuthService {
    /// Create a new authentication service
    pub fn new(config: AuthConfig) -> AgentResult<Self> {
        let encoding_key = EncodingKey::from_secret(config.jwt_secret.as_ref());
        let decoding_key = DecodingKey::from_secret(config.jwt_secret.as_ref());

        Ok(Self {
            config,
            users: Arc::new(RwLock::new(HashMap::new())),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            roles: Arc::new(RwLock::new(HashMap::new())),
            permissions: Arc::new(RwLock::new(HashMap::new())),
            auth_attempts: Arc::new(RwLock::new(Vec::new())),
            locked_accounts: Arc::new(RwLock::new(HashMap::new())),
            encoding_key,
            decoding_key,
            rng: Arc::new(Mutex::new(SystemRandom::new())),
        })
    }

    /// Authenticate a user
    pub async fn authenticate(
        &self,
        username: &str,
        password: &str,
        ip_address: &str,
        user_agent: &str,
    ) -> AgentResult<AuthResult> {
        // Check if account is locked
        if self.is_account_locked(username).await? {
            let unlock_time = self.get_unlock_time(username).await?;
            return Ok(AuthResult::AccountLocked { unlock_time });
        }

        // Check rate limiting
        if self.is_rate_limited(username, ip_address).await? {
            warn!("Authentication rate limited for user: {}", username);
            return Ok(AuthResult::Failed {
                reason: "Too many authentication attempts".to_string(),
            });
        }

        // Get user credentials
        let users = self.users.read().await;
        let user = match users.get(username) {
            Some(user) if user.is_active => user,
            Some(_) => {
                self.record_auth_attempt(username, ip_address, false).await?;
                return Ok(AuthResult::Failed {
                    reason: "Account is disabled".to_string(),
                });
            }
            None => {
                self.record_auth_attempt(username, ip_address, false).await?;
                return Ok(AuthResult::Failed {
                    reason: "Invalid credentials".to_string(),
                });
            }
        };

        // Verify password
        let password_hash = PasswordHash::new(&user.password_hash).map_err(|e| AgentError::Crypto {
            message: format!("Failed to parse password hash: {}", e),
            algorithm: Some("argon2".to_string()),
            context: Some(ErrorContext::new("authenticate", "auth_service")),
        })?;

        let argon2 = Argon2::default();
        if argon2.verify_password(password.as_bytes(), &password_hash).is_err() {
            self.record_auth_attempt(username, ip_address, false).await?;
            return Ok(AuthResult::Failed {
                reason: "Invalid credentials".to_string(),
            });
        }

        // Check if MFA is required
        if user.mfa_enabled {
            let temp_token = self.generate_temp_token(username).await?;
            return Ok(AuthResult::MfaRequired {
                temp_token,
                methods: vec![MfaMethod::TOTP], // Simplified for now
            });
        }

        // Create session
        let session = self.create_session(user, ip_address, user_agent).await?;
        
        // Generate tokens
        let token = self.generate_tokens(&session).await?;

        self.record_auth_attempt(username, ip_address, true).await?;

        info!("User {} authenticated successfully", username);
        Ok(AuthResult::Success { token, session })
    }

    /// Verify JWT token
    pub async fn verify_token(&self, token: &str) -> AgentResult<Claims> {
        let validation = Validation::new(Algorithm::HS256);
        
        let token_data = decode::<Claims>(token, &self.decoding_key, &validation)
            .map_err(|e| AgentError::Authentication {
                message: format!("Invalid token: {}", e),
                user_id: None,
                context: Some(ErrorContext::new("verify_token", "auth_service")),
            })?;

        // Check if session is still active
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(&token_data.claims.session_id) {
            if !session.is_active || session.expires_at < SystemTime::now() {
                return Err(AgentError::Authentication {
                    message: "Session expired or inactive".to_string(),
                    user_id: Some(token_data.claims.sub.clone()),
                    context: Some(ErrorContext::new("verify_token", "auth_service")),
                });
            }
        } else {
            return Err(AgentError::Authentication {
                message: "Session not found".to_string(),
                user_id: Some(token_data.claims.sub.clone()),
                context: Some(ErrorContext::new("verify_token", "auth_service")),
            });
        }

        Ok(token_data.claims)
    }

    /// Refresh authentication token
    pub async fn refresh_token(&self, refresh_token: &str) -> AgentResult<AuthToken> {
        // Verify refresh token (simplified implementation)
        let claims = self.verify_token(refresh_token).await?;
        
        // Get session
        let sessions = self.sessions.read().await;
        let session = sessions.get(&claims.session_id)
            .ok_or_else(|| AgentError::Authentication {
                message: "Session not found".to_string(),
                user_id: Some(claims.sub.clone()),
                context: Some(ErrorContext::new("refresh_token", "auth_service")),
            })?;

        // Generate new tokens
        self.generate_tokens(session).await
    }

    /// Logout user
    pub async fn logout(&self, session_id: &str) -> AgentResult<()> {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(session_id) {
            session.is_active = false;
            info!("User {} logged out", session.username);
        }
        Ok(())
    }

    /// Create a new user
    pub async fn create_user(
        &self,
        username: &str,
        password: &str,
        roles: Vec<String>,
    ) -> AgentResult<()> {
        // Validate password policy
        self.validate_password(password)?;

        // Hash password
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt)
            .map_err(|e| AgentError::Crypto {
                message: format!("Failed to hash password: {}", e),
                algorithm: Some("argon2".to_string()),
                context: Some(ErrorContext::new("create_user", "auth_service")),
            })?
            .to_string();

        let user = UserCredentials {
            username: username.to_string(),
            password_hash,
            salt: salt.to_string(),
            created_at: SystemTime::now(),
            last_password_change: SystemTime::now(),
            password_history: Vec::new(),
            is_active: true,
            roles: roles.clone(),
            permissions: self.get_permissions_for_roles(&roles).await?,
            mfa_enabled: false,
            mfa_secret: None,
        };

        let mut users = self.users.write().await;
        users.insert(username.to_string(), user);

        info!("Created user: {}", username);
        Ok(())
    }

    /// Check if user has permission
    pub async fn has_permission(&self, username: &str, permission: &str) -> AgentResult<bool> {
        let users = self.users.read().await;
        if let Some(user) = users.get(username) {
            Ok(user.permissions.contains(&permission.to_string()))
        } else {
            Ok(false)
        }
    }

    /// Check if user has role
    pub async fn has_role(&self, username: &str, role: &str) -> AgentResult<bool> {
        let users = self.users.read().await;
        if let Some(user) = users.get(username) {
            Ok(user.roles.contains(&role.to_string()))
        } else {
            Ok(false)
        }
    }

    /// Create session
    async fn create_session(
        &self,
        user: &UserCredentials,
        ip_address: &str,
        user_agent: &str,
    ) -> AgentResult<Session> {
        let session_id = Uuid::new_v4().to_string();
        let now = SystemTime::now();
        let expires_at = now + self.config.session_timeout;

        let session = Session {
            session_id: session_id.clone(),
            user_id: user.username.clone(),
            username: user.username.clone(),
            created_at: now,
            last_activity: now,
            expires_at,
            ip_address: ip_address.to_string(),
            user_agent: user_agent.to_string(),
            roles: user.roles.clone(),
            permissions: user.permissions.clone(),
            is_active: true,
        };

        // Check concurrent session limit
        self.enforce_session_limit(&user.username).await?;

        let mut sessions = self.sessions.write().await;
        sessions.insert(session_id, session.clone());

        Ok(session)
    }

    /// Generate JWT tokens
    async fn generate_tokens(&self, session: &Session) -> AgentResult<AuthToken> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;

        let claims = Claims {
            sub: session.user_id.clone(),
            username: session.username.clone(),
            roles: session.roles.clone(),
            permissions: session.permissions.clone(),
            exp: now + self.config.token_expiration.as_secs() as usize,
            iat: now,
            jti: Uuid::new_v4().to_string(),
            session_id: session.session_id.clone(),
        };

        let access_token = encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|e| AgentError::Crypto {
                message: format!("Failed to encode JWT: {}", e),
                algorithm: Some("JWT".to_string()),
                context: Some(ErrorContext::new("generate_tokens", "auth_service")),
            })?;

        // Generate refresh token (simplified - in production, use different claims/expiration)
        let refresh_claims = Claims {
            exp: now + self.config.refresh_token_expiration.as_secs() as usize,
            ..claims
        };

        let refresh_token = encode(&Header::default(), &refresh_claims, &self.encoding_key)
            .map_err(|e| AgentError::Crypto {
                message: format!("Failed to encode refresh JWT: {}", e),
                algorithm: Some("JWT".to_string()),
                context: Some(ErrorContext::new("generate_tokens", "auth_service")),
            })?;

        Ok(AuthToken {
            access_token,
            refresh_token,
            token_type: "Bearer".to_string(),
            expires_in: self.config.token_expiration.as_secs(),
            scope: session.permissions.clone(),
        })
    }

    /// Generate temporary token for MFA
    async fn generate_temp_token(&self, username: &str) -> AgentResult<String> {
        // Simplified implementation - in production, use shorter expiration and different claims
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;

        let claims = Claims {
            sub: username.to_string(),
            username: username.to_string(),
            roles: vec!["temp".to_string()],
            permissions: vec!["mfa_verify".to_string()],
            exp: now + 300, // 5 minutes
            iat: now,
            jti: Uuid::new_v4().to_string(),
            session_id: "temp".to_string(),
        };

        encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|e| AgentError::Crypto {
                message: format!("Failed to encode temp JWT: {}", e),
                algorithm: Some("JWT".to_string()),
                context: Some(ErrorContext::new("generate_temp_token", "auth_service")),
            })
    }

    /// Validate password against policy
    fn validate_password(&self, password: &str) -> AgentResult<()> {
        let policy = &self.config.password_policy;

        if password.len() < policy.min_length {
            return Err(AgentError::Validation {
                message: format!("Password must be at least {} characters", policy.min_length),
                field: Some("password".to_string()),
                expected: Some(format!("minimum {} characters", policy.min_length)),
                actual: Some(format!("{} characters", password.len())),
                context: Some(ErrorContext::new("validate_password", "auth_service")),
            });
        }

        if policy.require_uppercase && !password.chars().any(|c| c.is_uppercase()) {
            return Err(AgentError::Validation {
                message: "Password must contain at least one uppercase letter".to_string(),
                field: Some("password".to_string()),
                expected: Some("at least one uppercase letter".to_string()),
                actual: Some("no uppercase letters".to_string()),
                context: Some(ErrorContext::new("validate_password", "auth_service")),
            });
        }

        if policy.require_lowercase && !password.chars().any(|c| c.is_lowercase()) {
            return Err(AgentError::Validation {
                message: "Password must contain at least one lowercase letter".to_string(),
                field: Some("password".to_string()),
                expected: Some("at least one lowercase letter".to_string()),
                actual: Some("no lowercase letters".to_string()),
                context: Some(ErrorContext::new("validate_password", "auth_service")),
            });
        }

        if policy.require_numbers && !password.chars().any(|c| c.is_numeric()) {
            return Err(AgentError::Validation {
                message: "Password must contain at least one number".to_string(),
                field: Some("password".to_string()),
                expected: Some("at least one number".to_string()),
                actual: Some("no numbers".to_string()),
                context: Some(ErrorContext::new("validate_password", "auth_service")),
            });
        }

        if policy.require_special_chars && !password.chars().any(|c| !c.is_alphanumeric()) {
            return Err(AgentError::Validation {
                message: "Password must contain at least one special character".to_string(),
                field: Some("password".to_string()),
                expected: Some("at least one special character".to_string()),
                actual: Some("no special characters".to_string()),
                context: Some(ErrorContext::new("validate_password", "auth_service")),
            });
        }

        Ok(())
    }

    /// Check if account is locked
    async fn is_account_locked(&self, username: &str) -> AgentResult<bool> {
        let locked_accounts = self.locked_accounts.read().await;
        if let Some(&unlock_time) = locked_accounts.get(username) {
            Ok(SystemTime::now() < unlock_time)
        } else {
            Ok(false)
        }
    }

    /// Get unlock time for locked account
    async fn get_unlock_time(&self, username: &str) -> AgentResult<SystemTime> {
        let locked_accounts = self.locked_accounts.read().await;
        locked_accounts.get(username).copied()
            .ok_or_else(|| AgentError::Authentication {
                message: "Account not locked".to_string(),
                user_id: Some(username.to_string()),
                context: Some(ErrorContext::new("get_unlock_time", "auth_service")),
            })
    }

    /// Check if authentication is rate limited
    async fn is_rate_limited(&self, username: &str, ip_address: &str) -> AgentResult<bool> {
        let auth_attempts = self.auth_attempts.read().await;
        let now = SystemTime::now();
        let window_start = now - self.config.auth_rate_limit.window_duration;

        let recent_attempts = auth_attempts.iter()
            .filter(|attempt| {
                attempt.timestamp >= window_start &&
                (attempt.username == username || attempt.ip_address == ip_address) &&
                !attempt.success
            })
            .count();

        Ok(recent_attempts >= self.config.auth_rate_limit.max_attempts as usize)
    }

    /// Record authentication attempt
    async fn record_auth_attempt(&self, username: &str, ip_address: &str, success: bool) -> AgentResult<()> {
        let attempt = AuthAttempt {
            username: username.to_string(),
            ip_address: ip_address.to_string(),
            timestamp: SystemTime::now(),
            success,
        };

        let mut auth_attempts = self.auth_attempts.write().await;
        auth_attempts.push(attempt);

        // Clean up old attempts
        let cutoff = SystemTime::now() - self.config.auth_rate_limit.window_duration * 2;
        auth_attempts.retain(|attempt| attempt.timestamp >= cutoff);

        // Lock account if too many failed attempts
        if !success {
            let recent_failures = auth_attempts.iter()
                .filter(|attempt| {
                    attempt.username == username &&
                    !attempt.success &&
                    attempt.timestamp >= SystemTime::now() - self.config.auth_rate_limit.window_duration
                })
                .count();

            if recent_failures >= self.config.auth_rate_limit.max_attempts as usize {
                let mut locked_accounts = self.locked_accounts.write().await;
                let unlock_time = SystemTime::now() + self.config.auth_rate_limit.lockout_duration;
                locked_accounts.insert(username.to_string(), unlock_time);
                warn!("Account {} locked due to too many failed attempts", username);
            }
        }

        Ok(())
    }

    /// Enforce concurrent session limit
    async fn enforce_session_limit(&self, username: &str) -> AgentResult<()> {
        let mut sessions = self.sessions.write().await;
        let user_sessions: Vec<_> = sessions.iter()
            .filter(|(_, session)| session.username == username && session.is_active)
            .map(|(id, _)| id.clone())
            .collect();

        if user_sessions.len() >= self.config.max_concurrent_sessions as usize {
            // Remove oldest session
            if let Some(oldest_session_id) = user_sessions.first() {
                if let Some(session) = sessions.get_mut(oldest_session_id) {
                    session.is_active = false;
                    info!("Deactivated oldest session for user {} due to session limit", username);
                }
            }
        }

        Ok(())
    }

    /// Get permissions for roles
    async fn get_permissions_for_roles(&self, roles: &[String]) -> AgentResult<Vec<String>> {
        let roles_map = self.roles.read().await;
        let mut permissions = Vec::new();

        for role_name in roles {
            if let Some(role) = roles_map.get(role_name) {
                permissions.extend(role.permissions.clone());
            }
        }

        permissions.sort();
        permissions.dedup();
        Ok(permissions)
    }

    /// Clean up expired sessions
    pub async fn cleanup_expired_sessions(&self) -> AgentResult<usize> {
        let mut sessions = self.sessions.write().await;
        let now = SystemTime::now();
        let initial_count = sessions.len();

        sessions.retain(|_, session| {
            session.is_active && session.expires_at > now
        });

        let cleaned_count = initial_count - sessions.len();
        if cleaned_count > 0 {
            info!("Cleaned up {} expired sessions", cleaned_count);
        }

        Ok(cleaned_count)
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            jwt_secret: "your-secret-key-change-in-production".to_string(),
            token_expiration: Duration::from_secs(3600), // 1 hour
            refresh_token_expiration: Duration::from_secs(86400 * 7), // 7 days
            enable_mfa: false,
            session_timeout: Duration::from_secs(3600 * 8), // 8 hours
            max_concurrent_sessions: 5,
            password_policy: PasswordPolicy::default(),
            auth_rate_limit: AuthRateLimit::default(),
            enable_session_tracking: true,
            secure_cookies: true,
        }
    }
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            min_length: 8,
            require_uppercase: true,
            require_lowercase: true,
            require_numbers: true,
            require_special_chars: true,
            max_age: Some(Duration::from_secs(86400 * 90)), // 90 days
            history_count: 5,
        }
    }
}

impl Default for AuthRateLimit {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            window_duration: Duration::from_secs(300), // 5 minutes
            lockout_duration: Duration::from_secs(900), // 15 minutes
        }
    }
}
