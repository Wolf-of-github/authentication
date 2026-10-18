// src/routes/protected.rs
// Routes requiring authentication

use axum::{extract::State, routing::get, Json, Router};

use crate::db;
use crate::error::{AppError, Result};
use crate::middleware::auth::{AuthUser, RequireAdmin};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/me", get(get_current_user))
        .route("/api/admin/users", get(admin_list_users))
}

/// Get current user profile (requires authentication)
async fn get_current_user(user: AuthUser) -> Json<UserProfile> {
    Json(UserProfile {
        id: user.id,
        email: user.email,
        roles: user.roles,
    })
}

/// Admin-only endpoint (requires admin role)
async fn admin_list_users(
    _admin: RequireAdmin,
    user: AuthUser,  // Also get user info
    State(state): State<AppState>,
) -> Result<Json<AdminResponse>> {
    tracing::info!(admin.id = %user.id, "Admin accessed user list");

    let users = db::list_users(&state.db)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))?;

    let profiles: Vec<UserProfile> = users
        .into_iter()
        .map(|u| UserProfile {
            id: u.id,
            email: u.email,
            roles: u.roles,
        })
        .collect();

    Ok(Json(AdminResponse {
        total: profiles.len(),
        users: profiles,
    }))
}

#[derive(serde::Serialize)]
struct UserProfile {
    id: uuid::Uuid,
    email: String,
    roles: Vec<String>,
}

#[derive(serde::Serialize)]
struct AdminResponse {
    users: Vec<UserProfile>,
    total: usize,
}