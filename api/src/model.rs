use axum::extract::FromRef;
use serde::{Deserialize, Serialize};
use shoply_service::{sea_orm::DatabaseConnection, dto::AppConfig};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct AppState {
    pub conn: DatabaseConnection,
    pub config: AppConfig,
}
