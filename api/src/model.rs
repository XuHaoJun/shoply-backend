use shoply_service::sea_orm::{Database, DatabaseConnection, Schema};

#[derive(Debug, Clone, Default)]
pub struct Config {
    pub database: DatabaseConfig,
    pub jwt: JwtConfig,
}

#[derive(Debug, Clone, Default)]
pub struct DatabaseConfig {
    pub url: String,
}

#[derive(Debug, Clone, Default)]
pub struct JwtConfig {
    pub secret: String,
    pub expires_in: String,
    pub maxage: i32,
}

#[derive(Debug, Clone)]
pub struct AppState {
    pub conn: DatabaseConnection,
    pub config: Config,
}
