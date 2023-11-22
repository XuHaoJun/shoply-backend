use serde::{Deserialize, Serialize};

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
