// src/auth/claims.rs
// JWT claims structure

use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Access token claims
#[derive(Debug, Serialize, Deserialize)]
pub struct AccessClaims {
    /// Subject (user ID)
    pub sub: Uuid,
    /// Expiration time (Unix timestamp)
    pub exp: i64,
    /// Issued at (Unix timestamp)
    pub iat: i64,
    /// Token type
    pub typ: String,
    /// User email
    pub email: String,
    /// User roles for authorization
    pub roles: Vec<String>,
}

impl AccessClaims {
    /// Create new access token claims
    pub fn new(user_id: Uuid, email: String, roles: Vec<String>, expires_in: Duration) -> Self {
        let now = Utc::now();

        Self {
            sub: user_id,
            exp: (now + expires_in).timestamp(),
            iat: now.timestamp(),
            typ: "access".to_string(),
            email,
            roles,
        }
    }

    /// Check if token is expired
    pub fn is_expired(&self) -> bool {
        Utc::now().timestamp() > self.exp
    }
}

/// Refresh token claims (minimal - just for re-authentication)
#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshClaims {
    /// Subject (user ID)
    pub sub: Uuid,
    /// Expiration time
    pub exp: i64,
    /// Issued at
    pub iat: i64,
    /// Token type
    pub typ: String,
    /// Token family ID (for rotation detection)
    pub family: Uuid,
}

impl RefreshClaims {
    pub fn new(user_id: Uuid, expires_in: Duration) -> Self {
        let now = Utc::now();

        Self {
            sub: user_id,
            exp: (now + expires_in).timestamp(),
            iat: now.timestamp(),
            typ: "refresh".to_string(),
            family: Uuid::new_v4(),
        }
    }
}