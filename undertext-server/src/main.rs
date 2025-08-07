use actix_web::{App, HttpServer, middleware::Logger};
use actix_cors::Cors;
use dotenv::dotenv;
use tracing::{info, error};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod auth;
mod encryption;
mod models;
mod routes;
mod config;
mod database;

use config::Config;
use database::init_database;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Load environment variables
    dotenv().ok();
    
    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Starting Undertext Server...");

    // Load configuration
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(e) => {
            error!("Failed to load configuration: {}", e);
            std::process::exit(1);
        }
    };

    // Initialize database
    let pool = match init_database(&config.database_url).await {
        Ok(pool) => pool,
        Err(e) => {
            error!("Failed to initialize database: {}", e);
            std::process::exit(1);
        }
    };

    info!("Server configured for port {}", config.port);

    // Start HTTP server
    HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .max_age(3600);

        App::new()
            .wrap(Logger::default())
            .wrap(cors)
            .app_data(actix_web::web::Data::new(pool.clone()))
            .app_data(actix_web::web::Data::new(config.clone()))
            .configure(routes::configure)
    })
    .bind(format!("127.0.0.1:{}", config.port))?
    .run()
    .await
} 