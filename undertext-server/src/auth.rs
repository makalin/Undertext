use actix_web::{HttpResponse, web};
use oauth2::{
    basic::BasicClient, AuthUrl, ClientId, ClientSecret, RedirectUrl, Scope, TokenUrl,
    PkceCodeChallenge, PkceCodeVerifier, CsrfToken, AuthorizationCode,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{info, error, debug};
use uuid::Uuid;
use chrono::{Utc, Duration};

use crate::{
    config::Config,
    models::{AuthRequest, AuthResponse, User, Session},
    database::{create_user, get_user_by_email, create_session},
};

#[derive(Debug, Serialize, Deserialize)]
pub struct OAuthUserInfo {
    pub id: String,
    pub email: String,
    pub name: String,
}

pub struct AuthService {
    oauth_client: BasicClient,
    http_client: Client,
}

impl AuthService {
    pub fn new(config: &Config) -> Self {
        let oauth_client = BasicClient::new(
            ClientId::new(config.oauth_client_id.clone()),
            Some(ClientSecret::new(config.oauth_client_secret.clone())),
            AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string()).unwrap(),
            Some(TokenUrl::new("https://oauth2.googleapis.com/token".to_string()).unwrap()),
        )
        .set_redirect_uri(RedirectUrl::new(config.oauth_redirect_uri.clone()).unwrap());

        let http_client = Client::new();

        AuthService {
            oauth_client,
            http_client,
        }
    }

    pub fn generate_auth_url(&self) -> (String, PkceCodeVerifier) {
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        
        let (auth_url, _csrf_token) = self.oauth_client
            .authorize_url(|| CsrfToken::new_random())
            .add_scope(Scope::new("openid".to_string()))
            .add_scope(Scope::new("email".to_string()))
            .add_scope(Scope::new("profile".to_string()))
            .set_pkce_challenge(pkce_challenge)
            .url();

        (auth_url.to_string(), pkce_verifier)
    }

    pub async fn exchange_code_for_token(
        &self,
        auth_request: &AuthRequest,
    ) -> Result<AuthResponse, Box<dyn std::error::Error>> {
        let token_result = self.oauth_client
            .exchange_code(AuthorizationCode::new(auth_request.code.clone()))
            .set_pkce_verifier(PkceCodeVerifier::new(auth_request.code_verifier.clone()))
            .request_async(oauth2::reqwest::async_http_client)
            .await?;

        let access_token = token_result.access_token().secret();
        let refresh_token = token_result.refresh_token()
            .map(|rt| rt.secret().clone())
            .unwrap_or_else(String::new);

        Ok(AuthResponse {
            access_token: access_token.clone(),
            refresh_token,
            expires_in: token_result.expires_in()
                .map(|d| d.as_secs() as i64)
                .unwrap_or(3600),
            token_type: "Bearer".to_string(),
        })
    }

    pub async fn get_user_info(
        &self,
        access_token: &str,
    ) -> Result<OAuthUserInfo, Box<dyn std::error::Error>> {
        let response = self.http_client
            .get("https://www.googleapis.com/oauth2/v2/userinfo")
            .header("Authorization", format!("Bearer {}", access_token))
            .send()
            .await?;

        if !response.status().is_success() {
            return Err("Failed to get user info from OAuth provider".into());
        }

        let user_info: OAuthUserInfo = response.json().await?;
        Ok(user_info)
    }

    pub async fn authenticate_user(
        &self,
        pool: &sqlx::SqlitePool,
        oauth_user_info: &OAuthUserInfo,
        device_id: &str,
        access_token: &str,
        refresh_token: &str,
        expires_in: i64,
    ) -> Result<Session, Box<dyn std::error::Error>> {
        // Check if user exists, create if not
        let user = match get_user_by_email(pool, &oauth_user_info.email).await? {
            Some(user) => user,
            None => {
                info!("Creating new user: {}", oauth_user_info.email);
                create_user(pool, &oauth_user_info.email, &oauth_user_info.name).await?
            }
        };

        // Create session
        let expires_at = Utc::now() + Duration::seconds(expires_in);
        let session = create_session(
            pool,
            user.id,
            device_id,
            access_token,
            refresh_token,
            expires_at,
        ).await?;

        info!("User authenticated: {} (device: {})", user.email, device_id);
        Ok(session)
    }
}

pub async fn auth_callback(
    pool: web::Data<sqlx::SqlitePool>,
    config: web::Data<Config>,
    auth_request: web::Json<AuthRequest>,
) -> Result<HttpResponse, actix_web::Error> {
    let auth_service = AuthService::new(&config);
    
    // Exchange code for token
    let auth_response = match auth_service.exchange_code_for_token(&auth_request).await {
        Ok(response) => response,
        Err(e) => {
            error!("Token exchange failed: {}", e);
            return Ok(HttpResponse::BadRequest().json(crate::models::ErrorResponse {
                error: "token_exchange_failed".to_string(),
                message: "Failed to exchange authorization code for token".to_string(),
            }));
        }
    };

    // Get user info
    let user_info = match auth_service.get_user_info(&auth_response.access_token).await {
        Ok(info) => info,
        Err(e) => {
            error!("Failed to get user info: {}", e);
            return Ok(HttpResponse::BadRequest().json(crate::models::ErrorResponse {
                error: "user_info_failed".to_string(),
                message: "Failed to retrieve user information".to_string(),
            }));
        }
    };

    // Generate device ID (in production, this should come from the client)
    let device_id = format!("device_{}", Uuid::new_v4());

    // Authenticate user and create session
    let session = match auth_service.authenticate_user(
        &pool,
        &user_info,
        &device_id,
        &auth_response.access_token,
        &auth_response.refresh_token,
        auth_response.expires_in,
    ).await {
        Ok(session) => session,
        Err(e) => {
            error!("Authentication failed: {}", e);
            return Ok(HttpResponse::InternalServerError().json(crate::models::ErrorResponse {
                error: "authentication_failed".to_string(),
                message: "Failed to authenticate user".to_string(),
            }));
        }
    };

    debug!("Authentication successful for user: {}", user_info.email);
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "session_id": session.id,
        "access_token": session.access_token,
        "expires_at": session.expires_at,
        "user": {
            "id": user_info.id,
            "email": user_info.email,
            "name": user_info.name
        }
    })))
} 