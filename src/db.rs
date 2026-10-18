// src/db.rs
// SQLite queries for user accounts

use sqlx::SqlitePool;
use uuid::Uuid;

pub struct User {
    pub id: Uuid,
    pub email: String,
    pub name: String,
    pub password_hash: String,
    pub roles: Vec<String>,
}

fn parse_roles(roles: &str) -> Vec<String> {
    roles.split(',').map(|r| r.trim().to_string()).collect()
}

struct UserRow {
    id: String,
    email: String,
    name: String,
    password_hash: String,
    roles: String,
}

impl From<UserRow> for User {
    fn from(row: UserRow) -> Self {
        User {
            id: Uuid::parse_str(&row.id).expect("stored user id is not a valid UUID"),
            email: row.email,
            name: row.name,
            password_hash: row.password_hash,
            roles: parse_roles(&row.roles),
        }
    }
}

pub async fn find_user_by_email(pool: &SqlitePool, email: &str) -> sqlx::Result<Option<User>> {
    let row = sqlx::query_as!(
        UserRow,
        "SELECT id, email, name, password_hash, roles FROM users WHERE email = ?",
        email
    )
    .fetch_optional(pool)
    .await?;

    Ok(row.map(User::from))
}

pub async fn find_user_by_id(pool: &SqlitePool, id: Uuid) -> sqlx::Result<Option<User>> {
    let id_str = id.to_string();
    let row = sqlx::query_as!(
        UserRow,
        "SELECT id, email, name, password_hash, roles FROM users WHERE id = ?",
        id_str
    )
    .fetch_optional(pool)
    .await?;

    Ok(row.map(User::from))
}

pub async fn user_exists(pool: &SqlitePool, email: &str) -> sqlx::Result<bool> {
    let row = sqlx::query!("SELECT 1 as present FROM users WHERE email = ?", email)
        .fetch_optional(pool)
        .await?;

    Ok(row.is_some())
}

pub async fn create_user(
    pool: &SqlitePool,
    email: &str,
    password_hash: &str,
    name: &str,
) -> sqlx::Result<Uuid> {
    let id = Uuid::new_v4();
    let id_str = id.to_string();

    sqlx::query!(
        "INSERT INTO users (id, email, password_hash, name, roles) VALUES (?, ?, ?, ?, 'user')",
        id_str,
        email,
        password_hash,
        name
    )
    .execute(pool)
    .await?;

    Ok(id)
}

pub async fn create_admin_if_missing(
    pool: &SqlitePool,
    email: &str,
    password_hash: &str,
    name: &str,
) -> sqlx::Result<()> {
    if user_exists(pool, email).await? {
        return Ok(());
    }

    let id = Uuid::new_v4().to_string();

    sqlx::query!(
        "INSERT INTO users (id, email, password_hash, name, roles) VALUES (?, ?, ?, ?, 'admin,user')",
        id,
        email,
        password_hash,
        name
    )
    .execute(pool)
    .await?;

    Ok(())
}
