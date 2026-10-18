// src/handlers/auth.rs
// Authentication endpoints

use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

use crate::auth::{password, token_service::TokenPair, TokenService};
use crate::db;
use crate::error::{AppError, Result};
use crate::state::AppState;

/// Login request
#[derive(Debug, Deserialize, Validate)]
pub struct LoginRequest {
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 8))]
    pub password: String,
}

/// Registration request
#[derive(Debug, Deserialize, Validate)]
pub struct RegisterRequest {
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 8, message = "Password must be at least 8 characters"))]
    pub password: String,
    #[validate(length(min = 1, max = 100))]
    pub name: String,
}

/// Refresh token request
#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

/// Authentication response
#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub user: UserInfo,
    #[serde(flatten)]
    pub tokens: TokenPair,
}

#[derive(Debug, Serialize)]
pub struct UserInfo {
    pub id: Uuid,
    pub email: String,
    pub name: String,
}

/// User login
#[tracing::instrument(skip(state, payload), fields(user.email = %payload.email))]
pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<AuthResponse>> {
    payload.validate().map_err(|e| AppError::Validation(e.to_string()))?;

    // Find user by email
    let user = db::find_user_by_email(&state.db, &payload.email)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))?
        .ok_or(AppError::Unauthorized)?;

    // Verify password
    let password_valid = tokio::task::spawn_blocking({
        let password = payload.password.clone();
        let hash = user.password_hash.clone();
        move || password::verify_password(&password, &hash)
    })
    .await
    .map_err(|_| AppError::Internal(anyhow::anyhow!("Password verification failed")))?
    .map_err(|_| AppError::Unauthorized)?;

    if !password_valid {
        tracing::warn!("Invalid password attempt");
        return Err(AppError::Unauthorized);
    }

    // Generate tokens
    let tokens = state
        .token_service
        .generate_token_pair(user.id, user.email.clone(), user.roles.clone())?;

    tracing::info!(user.id = %user.id, "User logged in");

    Ok(Json(AuthResponse {
        user: UserInfo {
            id: user.id,
            email: user.email,
            name: user.name,
        },
        tokens,
    }))
}

/// User registration
#[tracing::instrument(skip(state, payload), fields(user.email = %payload.email))]
pub async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<AuthResponse>)> {
    payload.validate().map_err(|e| AppError::Validation(e.to_string()))?;

    // Check if user exists
    if db::user_exists(&state.db, &payload.email)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))?
    {
        return Err(AppError::Conflict("Email already registered".to_string()));
    }

    // Hash password (CPU-intensive, use spawn_blocking)
    let password_hash = tokio::task::spawn_blocking({
        let password = payload.password.clone();
        move || password::hash_password(&password)
    })
    .await
    .map_err(|_| AppError::Internal(anyhow::anyhow!("Password hashing failed")))?
    .map_err(|_| AppError::Internal(anyhow::anyhow!("Password hashing failed")))?;

    // Create user
    let user_id = db::create_user(&state.db, &payload.email, &password_hash, &payload.name)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))?;

    // Generate tokens
    let tokens = state.token_service.generate_token_pair(
        user_id,
        payload.email.clone(),
        vec!["user".to_string()],
    )?;

    tracing::info!(user.id = %user_id, "User registered");

    Ok((
        StatusCode::CREATED,
        Json(AuthResponse {
            user: UserInfo {
                id: user_id,
                email: payload.email,
                name: payload.name,
            },
            tokens,
        }),
    ))
}

/// Refresh access token
#[tracing::instrument(skip(state, payload))]
pub async fn refresh(
    State(state): State<AppState>,
    Json(payload): Json<RefreshRequest>,
) -> Result<Json<TokenPair>> {
    // Validate refresh token
    let claims = state
        .token_service
        .validate_refresh_token(&payload.refresh_token)?;

    // Check if token is revoked (should check database/cache)
    // if is_token_revoked(&claims.family).await {
    //     return Err(AppError::Unauthorized);
    // }

    // Fetch current user info
    let user = db::find_user_by_id(&state.db, claims.sub)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))?
        .ok_or(AppError::Unauthorized)?;

    // Generate new token pair
    let tokens = state
        .token_service
        .generate_token_pair(user.id, user.email, user.roles)?;

    // Optionally: Revoke old refresh token family (rotation)
    // revoke_token_family(&claims.family).await;

    tracing::info!(user.id = %claims.sub, "Tokens refreshed");

    Ok(Json(tokens))
}

/// Logout (revoke refresh token)
#[tracing::instrument(skip(state, payload))]
pub async fn logout(
    State(state): State<AppState>,
    Json(payload): Json<RefreshRequest>,
) -> Result<StatusCode> {
    // Validate and get claims
    if let Ok(claims) = state.token_service.validate_refresh_token(&payload.refresh_token) {
        // Revoke the token family
        // revoke_token_family(&claims.family).await;
        tracing::info!(user.id = %claims.sub, "User logged out");
    }

    // Always return success (don't reveal if token was valid)
    Ok(StatusCode::NO_CONTENT)
}
