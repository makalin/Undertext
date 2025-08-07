use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub port: u16,
    pub database_url: String,
    pub oauth_client_id: String,
    pub oauth_client_secret: String,
    pub oauth_redirect_uri: String,
    pub encryption_master_key: String,
    pub jwt_secret: String,
    pub session_timeout_minutes: u64,
}

impl Config {
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Config {
            port: env::var("PORT")
                .unwrap_or_else(|_| "8080".to_string())
                .parse()?,
            database_url: env::var("DATABASE_URL")
                .unwrap_or_else(|_| "sqlite:undertext.db".to_string()),
            oauth_client_id: env::var("OAUTH_CLIENT_ID")
                .expect("OAUTH_CLIENT_ID must be set"),
            oauth_client_secret: env::var("OAUTH_CLIENT_SECRET")
                .expect("OAUTH_CLIENT_SECRET must be set"),
            oauth_redirect_uri: env::var("OAUTH_REDIRECT_URI")
                .unwrap_or_else(|_| "http://localhost:8080/callback".to_string()),
            encryption_master_key: env::var("ENCRYPTION_MASTER_KEY")
                .expect("ENCRYPTION_MASTER_KEY must be set"),
            jwt_secret: env::var("JWT_SECRET")
                .expect("JWT_SECRET must be set"),
            session_timeout_minutes: env::var("SESSION_TIMEOUT_MINUTES")
                .unwrap_or_else(|_| "60".to_string())
                .parse()?,
        })
    }
} 