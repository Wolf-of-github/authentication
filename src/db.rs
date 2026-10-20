// src/db.rs
// MongoDB queries for user accounts

use bson::doc;
use chrono::Utc;
use futures::stream::TryStreamExt;
use mongodb::{Collection, Database};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub struct User {
    pub id: Uuid,
    pub email: String,
    pub name: String,
    pub password_hash: String,
    pub roles: Vec<String>,
}

// _id/family are stored as `bson::Uuid` rather than `uuid::Uuid`: the latter's
// serde impl writes a plain string, while the `doc! { "_id": uuid::Uuid }` query
// macro (via bson's uuid-1 feature) builds a Binary value for the same type —
// mismatched representations mean a query would never match what got inserted.
#[derive(Debug, Serialize, Deserialize)]
struct UserDoc {
    #[serde(rename = "_id")]
    id: bson::Uuid,
    email: String,
    name: String,
    password_hash: String,
    roles: Vec<String>,
    created_at: chrono::DateTime<Utc>,
}

impl From<UserDoc> for User {
    fn from(doc: UserDoc) -> Self {
        User {
            id: doc.id.into(),
            email: doc.email,
            name: doc.name,
            password_hash: doc.password_hash,
            roles: doc.roles,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct RevokedFamilyDoc {
    #[serde(rename = "_id")]
    family: bson::Uuid,
    revoked_at: chrono::DateTime<Utc>,
}

fn users_collection(db: &Database) -> Collection<UserDoc> {
    db.collection("users")
}

fn revoked_token_families_collection(db: &Database) -> Collection<RevokedFamilyDoc> {
    db.collection("revoked_token_families")
}

/// Create indexes required by the application. Safe to call on every startup.
pub async fn ensure_indexes(db: &Database) -> mongodb::error::Result<()> {
    use mongodb::options::IndexOptions;
    use mongodb::IndexModel;

    let email_index = IndexModel::builder()
        .keys(doc! { "email": 1 })
        .options(IndexOptions::builder().unique(true).build())
        .build();

    users_collection(db).create_index(email_index).await?;

    Ok(())
}

pub async fn find_user_by_email(db: &Database, email: &str) -> mongodb::error::Result<Option<User>> {
    let doc = users_collection(db)
        .find_one(doc! { "email": email })
        .await?;

    Ok(doc.map(User::from))
}

pub async fn find_user_by_id(db: &Database, id: Uuid) -> mongodb::error::Result<Option<User>> {
    let doc = users_collection(db)
        .find_one(doc! { "_id": bson::Uuid::from(id) })
        .await?;

    Ok(doc.map(User::from))
}

pub async fn user_exists(db: &Database, email: &str) -> mongodb::error::Result<bool> {
    let count = users_collection(db)
        .count_documents(doc! { "email": email })
        .await?;

    Ok(count > 0)
}

pub async fn create_user(
    db: &Database,
    email: &str,
    password_hash: &str,
    name: &str,
) -> mongodb::error::Result<Uuid> {
    let id = Uuid::new_v4();

    let doc = UserDoc {
        id: id.into(),
        email: email.to_string(),
        name: name.to_string(),
        password_hash: password_hash.to_string(),
        roles: vec!["user".to_string()],
        created_at: Utc::now(),
    };

    users_collection(db).insert_one(doc).await?;

    Ok(id)
}

pub async fn list_users(db: &Database) -> mongodb::error::Result<Vec<User>> {
    let mut cursor = users_collection(db)
        .find(doc! {})
        .sort(doc! { "created_at": 1 })
        .await?;

    let mut users = Vec::new();
    while let Some(doc) = cursor.try_next().await? {
        users.push(User::from(doc));
    }

    Ok(users)
}

pub async fn is_token_family_revoked(db: &Database, family: Uuid) -> mongodb::error::Result<bool> {
    let count = revoked_token_families_collection(db)
        .count_documents(doc! { "_id": bson::Uuid::from(family) })
        .await?;

    Ok(count > 0)
}

pub async fn revoke_token_family(db: &Database, family: Uuid) -> mongodb::error::Result<()> {
    let doc = RevokedFamilyDoc {
        family: family.into(),
        revoked_at: Utc::now(),
    };

    // Mirrors the old "INSERT ... ON CONFLICT DO NOTHING": a duplicate _id
    // means the family is already revoked, which is not an error here.
    match revoked_token_families_collection(db).insert_one(doc).await {
        Ok(_) => Ok(()),
        Err(e) if is_duplicate_key_error(&e) => Ok(()),
        Err(e) => Err(e),
    }
}

fn is_duplicate_key_error(err: &mongodb::error::Error) -> bool {
    matches!(
        *err.kind,
        mongodb::error::ErrorKind::Write(mongodb::error::WriteFailure::WriteError(
            mongodb::error::WriteError { code: 11000, .. }
        ))
    )
}

pub async fn create_admin_if_missing(
    db: &Database,
    email: &str,
    password_hash: &str,
    name: &str,
) -> mongodb::error::Result<()> {
    if user_exists(db, email).await? {
        return Ok(());
    }

    let doc = UserDoc {
        id: Uuid::new_v4().into(),
        email: email.to_string(),
        name: name.to_string(),
        password_hash: password_hash.to_string(),
        roles: vec!["admin".to_string(), "user".to_string()],
        created_at: Utc::now(),
    };

    users_collection(db).insert_one(doc).await?;

    Ok(())
}
