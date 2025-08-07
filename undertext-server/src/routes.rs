use actix_web::{web, HttpResponse, HttpRequest};
use serde::{Deserialize, Serialize};
use tracing::{info, error, debug};
use uuid::Uuid;
use chrono::{Utc, Duration};

use crate::{
    config::Config,
    models::{KeyRequest, KeyResponse, ErrorResponse},
    database::{get_session_by_token, create_decryption_key, get_decryption_key},
    encryption::EncryptionManager,
    auth::auth_callback,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthUrlResponse {
    pub auth_url: String,
    pub code_verifier: String,
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/v1")
            .route("/auth/url", web::get().to(generate_auth_url))
            .route("/auth/callback", web::post().to(auth_callback))
            .route("/keys/request", web::post().to(request_decryption_key))
            .route("/keys/{key_id}", web::get().to(get_decryption_key_endpoint))
            .route("/health", web::get().to(health_check))
    );
}

pub async fn generate_auth_url(
    config: web::Data<Config>,
) -> Result<HttpResponse, actix_web::Error> {
    use crate::auth::AuthService;
    
    let auth_service = AuthService::new(&config);
    let (auth_url, code_verifier) = auth_service.generate_auth_url();
    
    Ok(HttpResponse::Ok().json(AuthUrlResponse {
        auth_url,
        code_verifier: code_verifier.secret().clone(),
    }))
}

pub async fn request_decryption_key(
    pool: web::Data<sqlx::SqlitePool>,
    config: web::Data<Config>,
    key_request: web::Json<KeyRequest>,
) -> Result<HttpResponse, actix_web::Error> {
    // Extract session token from Authorization header
    let auth_header = key_request.session_token.clone();
    if !auth_header.starts_with("Bearer ") {
        return Ok(HttpResponse::Unauthorized().json(ErrorResponse {
            error: "invalid_token".to_string(),
            message: "Invalid authorization header format".to_string(),
        }));
    }

    let token = &auth_header[7..]; // Remove "Bearer " prefix

    // Validate session
    let session = match get_session_by_token(&pool, token).await {
        Ok(Some(session)) => session,
        Ok(None) => {
            return Ok(HttpResponse::Unauthorized().json(ErrorResponse {
                error: "invalid_session".to_string(),
                message: "Session not found or expired".to_string(),
            }));
        }
        Err(e) => {
            error!("Database error: {}", e);
            return Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: "database_error".to_string(),
                message: "Internal server error".to_string(),
            }));
        }
    };

    // Initialize encryption manager
    let encryption_manager = match EncryptionManager::new(&config.encryption_master_key) {
        Ok(manager) => manager,
        Err(e) => {
            error!("Failed to initialize encryption manager: {}", e);
            return Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: "encryption_error".to_string(),
                message: "Failed to initialize encryption".to_string(),
            }));
        }
    };

    // Generate session key and IV
    let (session_key, iv) = match encryption_manager.generate_session_key() {
        Ok(key_iv) => key_iv,
        Err(e) => {
            error!("Failed to generate session key: {}", e);
            return Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: "key_generation_error".to_string(),
                message: "Failed to generate encryption key".to_string(),
            }));
        }
    };

    // Set expiration time (1 hour from now)
    let expires_at = Utc::now() + Duration::hours(1);

    // Store decryption key in database
    let decryption_key = match create_decryption_key(
        &pool,
        session.id,
        &key_request.stream_id,
        &encryption_manager.encode_key_for_transmission(&session_key),
        &encryption_manager.encode_key_for_transmission(&iv),
        expires_at,
    ).await {
        Ok(key) => key,
        Err(e) => {
            error!("Failed to store decryption key: {}", e);
            return Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: "database_error".to_string(),
                message: "Failed to store encryption key".to_string(),
            }));
        }
    };

    info!("Generated decryption key for stream: {} (user: {})", 
          key_request.stream_id, session.user_id);

    Ok(HttpResponse::Ok().json(KeyResponse {
        key_id: decryption_key.id,
        key_data: decryption_key.key_data,
        iv: decryption_key.iv,
        expires_at: decryption_key.expires_at,
    }))
}

pub async fn get_decryption_key_endpoint(
    pool: web::Data<sqlx::SqlitePool>,
    path: web::Path<Uuid>,
    req: HttpRequest,
) -> Result<HttpResponse, actix_web::Error> {
    let key_id = path.into_inner();

    // Extract session token from Authorization header
    let auth_header = req.headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    if !auth_header.starts_with("Bearer ") {
        return Ok(HttpResponse::Unauthorized().json(ErrorResponse {
            error: "invalid_token".to_string(),
            message: "Invalid authorization header format".to_string(),
        }));
    }

    let token = &auth_header[7..]; // Remove "Bearer " prefix

    // Validate session
    let session = match get_session_by_token(&pool, token).await {
        Ok(Some(session)) => session,
        Ok(None) => {
            return Ok(HttpResponse::Unauthorized().json(ErrorResponse {
                error: "invalid_session".to_string(),
                message: "Session not found or expired".to_string(),
            }));
        }
        Err(e) => {
            error!("Database error: {}", e);
            return Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: "database_error".to_string(),
                message: "Internal server error".to_string(),
            }));
        }
    };

    // Get decryption key
    let decryption_key = match get_decryption_key(&pool, key_id).await {
        Ok(Some(key)) => key,
        Ok(None) => {
            return Ok(HttpResponse::NotFound().json(ErrorResponse {
                error: "key_not_found".to_string(),
                message: "Decryption key not found or expired".to_string(),
            }));
        }
        Err(e) => {
            error!("Database error: {}", e);
            return Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: "database_error".to_string(),
                message: "Internal server error".to_string(),
            }));
        }
    };

    // Verify that the key belongs to the authenticated session
    if decryption_key.session_id != session.id {
        return Ok(HttpResponse::Forbidden().json(ErrorResponse {
            error: "access_denied".to_string(),
            message: "Access denied to this decryption key".to_string(),
        }));
    }

    debug!("Retrieved decryption key: {} for session: {}", key_id, session.id);

    Ok(HttpResponse::Ok().json(KeyResponse {
        key_id: decryption_key.id,
        key_data: decryption_key.key_data,
        iv: decryption_key.iv,
        expires_at: decryption_key.expires_at,
    }))
}

pub async fn health_check() -> Result<HttpResponse, actix_web::Error> {
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "healthy",
        "timestamp": Utc::now(),
        "service": "undertext-server"
    })))
} 