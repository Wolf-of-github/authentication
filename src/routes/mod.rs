// src/routes/mod.rs

pub mod protected;

use axum::{routing::post, Router};

use crate::handlers::auth::{login, logout, refresh, register};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    let auth_routes = Router::new()
        .route("/api/auth/login", post(login))
        .route("/api/auth/register", post(register))
        .route("/api/auth/refresh", post(refresh))
        .route("/api/auth/logout", post(logout));

    auth_routes.merge(protected::router())
}
