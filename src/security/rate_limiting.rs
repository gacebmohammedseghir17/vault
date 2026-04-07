//! Rate Limiting and DoS Protection Module
//!
//! This module provides comprehensive rate limiting capabilities to protect against
//! denial of service attacks and abuse.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn, info};
use crate::error::{AgentError, AgentResult};

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum requests per window
    pub max_requests: u32,
    /// Time window duration
    pub window_duration: Duration,
    /// Burst allowance (requests that can exceed the rate temporarily)
    pub burst_allowance: u32,
    /// Cleanup interval for expired entries
    pub cleanup_interval: Duration,
    /// Enable IP-based rate limiting
    pub enable_ip_limiting: bool,
    /// Enable user-based rate limiting
    pub enable_user_limiting: bool,
    /// Enable endpoint-based rate limiting
    pub enable_endpoint_limiting: bool,
    /// Whitelist of IPs that bypass rate limiting
    pub ip_whitelist: Vec<IpAddr>,
    /// Custom rate limits for specific endpoints
    pub endpoint_limits: HashMap<String, EndpointLimit>,
}

/// Endpoint-specific rate limit configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointLimit {
    pub max_requests: u32,
    pub window_duration: Duration,
    pub burst_allowance: u32,
}

/// Rate limit bucket for tracking requests
#[derive(Debug, Clone)]
pub struct RateLimitBucket {
    requests: Vec<Instant>,
    burst_tokens: u32,
    last_refill: Instant,
}

/// Rate limit result
#[derive(Debug, Clone, PartialEq)]
pub enum RateLimitResult {
    Allowed,
    Limited {
        retry_after: Duration,
        current_requests: u32,
        max_requests: u32,
    },
    Blocked {
        reason: String,
    },
}

/// Rate limit key for identifying clients
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum RateLimitKey {
    IpAddress(IpAddr),
    UserId(String),
    Endpoint(String),
    Combined(IpAddr, String), // IP + endpoint
}

/// Rate limiter implementation
pub struct RateLimiter {
    config: RateLimitConfig,
    buckets: Arc<Mutex<HashMap<RateLimitKey, RateLimitBucket>>>,
    last_cleanup: Arc<Mutex<Instant>>,
}

/// Rate limiting statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitStats {
    pub total_requests: u64,
    pub allowed_requests: u64,
    pub limited_requests: u64,
    pub blocked_requests: u64,
    pub active_buckets: usize,
    pub top_clients: Vec<ClientStats>,
}

/// Client statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientStats {
    pub key: String,
    pub requests: u32,
    pub last_request: SystemTime,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            buckets: Arc::new(Mutex::new(HashMap::new())),
            last_cleanup: Arc::new(Mutex::new(Instant::now())),
        }
    }

    /// Check if a request should be allowed
    pub fn check_rate_limit(&self, key: RateLimitKey, endpoint: Option<&str>) -> AgentResult<RateLimitResult> {
        // Check if IP is whitelisted
        if let RateLimitKey::IpAddress(ip) = &key {
            if self.config.ip_whitelist.contains(ip) {
                return Ok(RateLimitResult::Allowed);
            }
        }

        // Get the appropriate limit configuration
        let (max_requests, window_duration, burst_allowance) = if let Some(endpoint) = endpoint {
            if let Some(endpoint_limit) = self.config.endpoint_limits.get(endpoint) {
                (endpoint_limit.max_requests, endpoint_limit.window_duration, endpoint_limit.burst_allowance)
            } else {
                (self.config.max_requests, self.config.window_duration, self.config.burst_allowance)
            }
        } else {
            (self.config.max_requests, self.config.window_duration, self.config.burst_allowance)
        };

        let mut buckets = self.buckets.lock().map_err(|e| 
            AgentError::SystemError(format!("Failed to acquire rate limit lock: {}", e))
        )?;

        let now = Instant::now();
        let bucket = buckets.entry(key.clone()).or_insert_with(|| RateLimitBucket {
            requests: Vec::new(),
            burst_tokens: burst_allowance,
            last_refill: now,
        });

        // Refill burst tokens
        self.refill_burst_tokens(bucket, now, burst_allowance, window_duration);

        // Clean up old requests
        bucket.requests.retain(|&request_time| {
            now.duration_since(request_time) < window_duration
        });

        // Check if request should be allowed
        let current_requests = bucket.requests.len() as u32;
        
        if current_requests < max_requests {
            // Within normal rate limit
            bucket.requests.push(now);
            debug!("Rate limit check passed for {:?}: {}/{}", key, current_requests + 1, max_requests);
            Ok(RateLimitResult::Allowed)
        } else if bucket.burst_tokens > 0 {
            // Use burst token
            bucket.burst_tokens -= 1;
            bucket.requests.push(now);
            info!("Rate limit burst token used for {:?}: {} tokens remaining", key, bucket.burst_tokens);
            Ok(RateLimitResult::Allowed)
        } else {
            // Rate limited
            let oldest_request = bucket.requests.first().copied().unwrap_or(now);
            let retry_after = window_duration.saturating_sub(now.duration_since(oldest_request));
            
            warn!("Rate limit exceeded for {:?}: {}/{}, retry after {:?}", 
                  key, current_requests, max_requests, retry_after);
            
            Ok(RateLimitResult::Limited {
                retry_after,
                current_requests,
                max_requests,
            })
        }
    }

    /// Check rate limit for IP address
    pub fn check_ip_rate_limit(&self, ip: IpAddr, endpoint: Option<&str>) -> AgentResult<RateLimitResult> {
        if !self.config.enable_ip_limiting {
            return Ok(RateLimitResult::Allowed);
        }

        let key = if let Some(endpoint) = endpoint {
            RateLimitKey::Combined(ip, endpoint.to_string())
        } else {
            RateLimitKey::IpAddress(ip)
        };

        self.check_rate_limit(key, endpoint)
    }

    /// Check rate limit for user
    pub fn check_user_rate_limit(&self, user_id: &str, endpoint: Option<&str>) -> AgentResult<RateLimitResult> {
        if !self.config.enable_user_limiting {
            return Ok(RateLimitResult::Allowed);
        }

        let key = RateLimitKey::UserId(user_id.to_string());
        self.check_rate_limit(key, endpoint)
    }

    /// Check rate limit for endpoint
    pub fn check_endpoint_rate_limit(&self, endpoint: &str) -> AgentResult<RateLimitResult> {
        if !self.config.enable_endpoint_limiting {
            return Ok(RateLimitResult::Allowed);
        }

        let key = RateLimitKey::Endpoint(endpoint.to_string());
        self.check_rate_limit(key, Some(endpoint))
    }

    /// Perform cleanup of expired buckets
    pub fn cleanup_expired_buckets(&self) -> AgentResult<usize> {
        let mut last_cleanup = self.last_cleanup.lock().map_err(|e| 
            AgentError::SystemError(format!("Failed to acquire cleanup lock: {}", e))
        )?;

        let now = Instant::now();
        if now.duration_since(*last_cleanup) < self.config.cleanup_interval {
            return Ok(0);
        }

        let mut buckets = self.buckets.lock().map_err(|e| 
            AgentError::SystemError(format!("Failed to acquire rate limit lock: {}", e))
        )?;

        let initial_count = buckets.len();
        
        buckets.retain(|_, bucket| {
            // Keep buckets that have recent requests or burst tokens
            !bucket.requests.is_empty() || 
            bucket.burst_tokens < self.config.burst_allowance ||
            now.duration_since(bucket.last_refill) < self.config.window_duration * 2
        });

        let cleaned_count = initial_count - buckets.len();
        *last_cleanup = now;

        if cleaned_count > 0 {
            info!("Cleaned up {} expired rate limit buckets", cleaned_count);
        }

        Ok(cleaned_count)
    }

    /// Get rate limiting statistics
    pub fn get_statistics(&self) -> AgentResult<RateLimitStats> {
        let buckets = self.buckets.lock().map_err(|e| 
            AgentError::SystemError(format!("Failed to acquire rate limit lock: {}", e))
        )?;

        let now = Instant::now();
        let mut total_requests = 0u64;
        let mut client_stats = Vec::new();

        for (key, bucket) in buckets.iter() {
            let recent_requests = bucket.requests.iter()
                .filter(|&&request_time| now.duration_since(request_time) < self.config.window_duration)
                .count() as u32;

            total_requests += recent_requests as u64;

            if recent_requests > 0 {
                let last_instant = bucket.requests.last().copied().unwrap_or(now);
                let elapsed_since_last = now.duration_since(last_instant);
                let last_system_time = SystemTime::now() - elapsed_since_last;
                client_stats.push(ClientStats {
                    key: format!("{:?}", key),
                    requests: recent_requests,
                    last_request: last_system_time,
                });
            }
        }

        // Sort by request count (descending)
        client_stats.sort_by(|a, b| b.requests.cmp(&a.requests));
        client_stats.truncate(10); // Top 10 clients

        Ok(RateLimitStats {
            total_requests,
            allowed_requests: total_requests, // Simplified for now
            limited_requests: 0,              // Would need to track this separately
            blocked_requests: 0,              // Would need to track this separately
            active_buckets: buckets.len(),
            top_clients: client_stats,
        })
    }

    /// Reset rate limits for a specific key
    pub fn reset_rate_limit(&self, key: RateLimitKey) -> AgentResult<bool> {
        let mut buckets = self.buckets.lock().map_err(|e| 
            AgentError::SystemError(format!("Failed to acquire rate limit lock: {}", e))
        )?;

        let removed = buckets.remove(&key).is_some();
        if removed {
            info!("Reset rate limit for key: {:?}", key);
        }

        Ok(removed)
    }

    /// Add IP to whitelist
    pub fn add_to_whitelist(&mut self, ip: IpAddr) {
        if !self.config.ip_whitelist.contains(&ip) {
            self.config.ip_whitelist.push(ip);
            info!("Added IP {} to rate limit whitelist", ip);
        }
    }

    /// Remove IP from whitelist
    pub fn remove_from_whitelist(&mut self, ip: IpAddr) -> bool {
        if let Some(pos) = self.config.ip_whitelist.iter().position(|&x| x == ip) {
            self.config.ip_whitelist.remove(pos);
            info!("Removed IP {} from rate limit whitelist", ip);
            true
        } else {
            false
        }
    }

    /// Refill burst tokens based on time elapsed
    fn refill_burst_tokens(&self, bucket: &mut RateLimitBucket, now: Instant, max_tokens: u32, window_duration: Duration) {
        let time_since_refill = now.duration_since(bucket.last_refill);
        let refill_rate = max_tokens as f64 / window_duration.as_secs_f64();
        let tokens_to_add = (time_since_refill.as_secs_f64() * refill_rate) as u32;

        if tokens_to_add > 0 {
            bucket.burst_tokens = (bucket.burst_tokens + tokens_to_add).min(max_tokens);
            bucket.last_refill = now;
        }
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_requests: 100,
            window_duration: Duration::from_secs(60), // 1 minute
            burst_allowance: 10,
            cleanup_interval: Duration::from_secs(300), // 5 minutes
            enable_ip_limiting: true,
            enable_user_limiting: true,
            enable_endpoint_limiting: true,
            ip_whitelist: vec![
                "127.0.0.1".parse().unwrap(),
                "::1".parse().unwrap(),
            ],
            endpoint_limits: HashMap::new(),
        }
    }
}

impl Default for EndpointLimit {
    fn default() -> Self {
        Self {
            max_requests: 50,
            window_duration: Duration::from_secs(60),
            burst_allowance: 5,
        }
    }
}

/// DoS protection middleware
pub struct DosProtection {
    rate_limiter: RateLimiter,
    blocked_ips: Arc<Mutex<HashMap<IpAddr, BlockedIpInfo>>>,
}

/// Information about blocked IPs
#[derive(Debug, Clone)]
struct BlockedIpInfo {
    blocked_at: Instant,
    reason: String,
    block_duration: Duration,
}

impl DosProtection {
    /// Create new DoS protection instance
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            rate_limiter: RateLimiter::new(config),
            blocked_ips: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Check if IP is currently blocked
    pub fn is_ip_blocked(&self, ip: IpAddr) -> AgentResult<bool> {
        let blocked_ips = self.blocked_ips.lock().map_err(|e| 
            AgentError::SystemError(format!("Failed to acquire blocked IPs lock: {}", e))
        )?;

        if let Some(block_info) = blocked_ips.get(&ip) {
            let now = Instant::now();
            if now.duration_since(block_info.blocked_at) < block_info.block_duration {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Block an IP address
    pub fn block_ip(&self, ip: IpAddr, reason: String, duration: Duration) -> AgentResult<()> {
        let mut blocked_ips = self.blocked_ips.lock().map_err(|e| 
            AgentError::SystemError(format!("Failed to acquire blocked IPs lock: {}", e))
        )?;

        blocked_ips.insert(ip, BlockedIpInfo {
            blocked_at: Instant::now(),
            reason,
            block_duration: duration,
        });

        warn!("Blocked IP {} for {:?}", ip, duration);
        Ok(())
    }

    /// Unblock an IP address
    pub fn unblock_ip(&self, ip: IpAddr) -> AgentResult<bool> {
        let mut blocked_ips = self.blocked_ips.lock().map_err(|e| 
            AgentError::SystemError(format!("Failed to acquire blocked IPs lock: {}", e))
        )?;

        let was_blocked = blocked_ips.remove(&ip).is_some();
        if was_blocked {
            info!("Unblocked IP {}", ip);
        }

        Ok(was_blocked)
    }

    /// Get rate limiter reference
    pub fn rate_limiter(&self) -> &RateLimiter {
        &self.rate_limiter
    }

    /// Clean up expired blocks
    pub fn cleanup_expired_blocks(&self) -> AgentResult<usize> {
        let mut blocked_ips = self.blocked_ips.lock().map_err(|e| 
            AgentError::SystemError(format!("Failed to acquire blocked IPs lock: {}", e))
        )?;

        let now = Instant::now();
        let initial_count = blocked_ips.len();

        blocked_ips.retain(|_, block_info| {
            now.duration_since(block_info.blocked_at) < block_info.block_duration
        });

        let cleaned_count = initial_count - blocked_ips.len();
        if cleaned_count > 0 {
            info!("Cleaned up {} expired IP blocks", cleaned_count);
        }

        Ok(cleaned_count)
    }
}
