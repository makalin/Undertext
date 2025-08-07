use sqlx::{sqlite::SqlitePoolOptions, SqlitePool, Row};
use tracing::{info, error};
use uuid::Uuid;
use chrono::Utc;

use crate::models::{User, Session, DecryptionKey};

pub async fn init_database(database_url: &str) -> Result<SqlitePool, sqlx::Error> {
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(database_url)
        .await?;

    // Run migrations
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await?;

    info!("Database initialized successfully");
    Ok(pool)
}

pub async fn create_user(
    pool: &SqlitePool,
    email: &str,
    name: &str,
) -> Result<User, sqlx::Error> {
    let id = Uuid::new_v4();
    let now = Utc::now();

    sqlx::query!(
        r#"
        INSERT INTO users (id, email, name, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?)
        "#,
        id,
        email,
        name,
        now,
        now
    )
    .execute(pool)
    .await?;

    Ok(User {
        id,
        email: email.to_string(),
        name: name.to_string(),
        created_at: now,
        updated_at: now,
    })
}

pub async fn get_user_by_email(
    pool: &SqlitePool,
    email: &str,
) -> Result<Option<User>, sqlx::Error> {
    let row = sqlx::query!(
        r#"
        SELECT id, email, name, created_at, updated_at
        FROM users
        WHERE email = ?
        "#,
        email
    )
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| User {
        id: r.id,
        email: r.email,
        name: r.name,
        created_at: r.created_at,
        updated_at: r.updated_at,
    }))
}

pub async fn create_session(
    pool: &SqlitePool,
    user_id: Uuid,
    device_id: &str,
    access_token: &str,
    refresh_token: &str,
    expires_at: chrono::DateTime<Utc>,
) -> Result<Session, sqlx::Error> {
    let id = Uuid::new_v4();
    let now = Utc::now();

    sqlx::query!(
        r#"
        INSERT INTO sessions (id, user_id, device_id, access_token, refresh_token, expires_at, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        "#,
        id,
        user_id,
        device_id,
        access_token,
        refresh_token,
        expires_at,
        now
    )
    .execute(pool)
    .await?;

    Ok(Session {
        id,
        user_id,
        device_id: device_id.to_string(),
        access_token: access_token.to_string(),
        refresh_token: refresh_token.to_string(),
        expires_at,
        created_at: now,
    })
}

pub async fn get_session_by_token(
    pool: &SqlitePool,
    access_token: &str,
) -> Result<Option<Session>, sqlx::Error> {
    let row = sqlx::query!(
        r#"
        SELECT id, user_id, device_id, access_token, refresh_token, expires_at, created_at
        FROM sessions
        WHERE access_token = ? AND expires_at > ?
        "#,
        access_token,
        Utc::now()
    )
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| Session {
        id: r.id,
        user_id: r.user_id,
        device_id: r.device_id,
        access_token: r.access_token,
        refresh_token: r.refresh_token,
        expires_at: r.expires_at,
        created_at: r.created_at,
    }))
}

pub async fn create_decryption_key(
    pool: &SqlitePool,
    session_id: Uuid,
    stream_id: &str,
    key_data: &str,
    iv: &str,
    expires_at: chrono::DateTime<Utc>,
) -> Result<DecryptionKey, sqlx::Error> {
    let id = Uuid::new_v4();
    let now = Utc::now();

    sqlx::query!(
        r#"
        INSERT INTO decryption_keys (id, session_id, stream_id, key_data, iv, expires_at, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        "#,
        id,
        session_id,
        stream_id,
        key_data,
        iv,
        expires_at,
        now
    )
    .execute(pool)
    .await?;

    Ok(DecryptionKey {
        id,
        session_id,
        stream_id: stream_id.to_string(),
        key_data: key_data.to_string(),
        iv: iv.to_string(),
        expires_at,
        created_at: now,
    })
}

pub async fn get_decryption_key(
    pool: &SqlitePool,
    key_id: Uuid,
) -> Result<Option<DecryptionKey>, sqlx::Error> {
    let row = sqlx::query!(
        r#"
        SELECT id, session_id, stream_id, key_data, iv, expires_at, created_at
        FROM decryption_keys
        WHERE id = ? AND expires_at > ?
        "#,
        key_id,
        Utc::now()
    )
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| DecryptionKey {
        id: r.id,
        session_id: r.session_id,
        stream_id: r.stream_id,
        key_data: r.key_data,
        iv: r.iv,
        expires_at: r.expires_at,
        created_at: r.created_at,
    }))
} 