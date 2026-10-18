// src/routes/protected.rs
// Routes requiring authentication

use axum::{routing::get, Json, Router};

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
) -> Json<AdminResponse> {
    tracing::info!(admin.id = %user.id, "Admin accessed user list");

    Json(AdminResponse {
        users: vec![],
        total: 0,
    })
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