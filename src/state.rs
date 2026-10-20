// src/state.rs
// Shared application state, available to every handler via axum's State extractor

use mongodb::Database;

use crate::auth::TokenService;

#[derive(Clone)]
pub struct AppState {
    pub token_service: TokenService,
    pub db: Database,
}
