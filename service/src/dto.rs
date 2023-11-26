use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AppConfig {
    pub host: String,
    pub port: String,
    pub database_url: String,
    pub jwt: AppJwtConfig,
    // pub cors: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AppJwtConfig {
    pub secret: String,
    // pub expires_in: String,
    // pub maxage: i32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: String,
    pub iat: usize,
    pub exp: usize,
    pub jti: String,
    pub acjti: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommonError {
    #[serde(skip_serializing)]
    pub http_status: u16,
    pub error_code: i32,
    pub result: Option<serde_json::Value>,
}
