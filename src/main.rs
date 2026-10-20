// src/main.rs

mod auth;
mod config;
mod db;
mod error;
mod handlers;
mod middleware;
mod routes;
mod state;

use mongodb::Client;
use std::env;

use auth::TokenService;
use config::AuthConfig;
use state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let mongodb_uri = env::var("MONGODB_URI").expect("MONGODB_URI must be set");
    let mongodb_db_name =
        env::var("MONGODB_DB_NAME").unwrap_or_else(|_| "authentication".to_string());

    let client = Client::with_uri_str(&mongodb_uri).await?;
    let db = client.database(&mongodb_db_name);

    db::ensure_indexes(&db).await?;

    seed_admin_from_env(&db).await?;

    let auth_config = AuthConfig::from_env();
    let token_service = TokenService::new(&auth_config);

    let state = AppState {
        token_service,
        db,
    };

    let app = routes::router().with_state(state);

    let addr = env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:3000".to_string());
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    tracing::info!(%addr, "authentication service listening");

    axum::serve(listener, app).await?;

    Ok(())
}

async fn seed_admin_from_env(db: &mongodb::Database) -> anyhow::Result<()> {
    let (email, password) = match (env::var("ADMIN_EMAIL"), env::var("ADMIN_PASSWORD")) {
        (Ok(email), Ok(password)) => (email, password),
        _ => return Ok(()),
    };

    let name = env::var("ADMIN_NAME").unwrap_or_else(|_| "Admin".to_string());

    let password_hash = tokio::task::spawn_blocking({
        let password = password.clone();
        move || auth::password::hash_password(&password)
    })
    .await??;

    db::create_admin_if_missing(db, &email, &password_hash, &name).await?;

    tracing::info!(%email, "admin user ensured");

    Ok(())
}
