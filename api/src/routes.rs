use axum::{
    extract::{Path, State},
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use hyper::StatusCode;
use shoply_member_service::dto::{LoginForm, SendOtpForm, VerifyOtpForm};
use std::sync::Arc;
use tower_http::cors::CorsLayer;

use crate::model::AppState;

async fn send_otp_handler(
    State(app_state): State<Arc<AppState>>,
    Json(body): Json<SendOtpForm>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let x = shoply_member_service::Mutation::send_otp(&app_state.conn, body)
        .await
        .map_err(|err| {
            (
                StatusCode::from_u16(err.http_status).unwrap(),
                Json(serde_json::to_value(err).unwrap()),
            )
        })?;
    Ok(Json(x))
}

async fn verify_otp_handler(
    State(app_state): State<Arc<AppState>>,
    Json(body): Json<VerifyOtpForm>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    shoply_member_service::Query::verify_otp(&app_state.conn, body)
        .await
        .map_err(|err| {
            (
                StatusCode::from_u16(err.http_status).unwrap(),
                Json(serde_json::to_value(err).unwrap()),
            )
        })?;
    Ok(())
}

async fn login_handler(
    State(app_state): State<Arc<AppState>>,
    Json(body): Json<LoginForm>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let x = shoply_member_service::Query::login(&app_state.conn, body)
        .await
        .map_err(|err| {
            (
                StatusCode::from_u16(err.http_status).unwrap(),
                Json(serde_json::to_value(err).unwrap()),
            )
        })?;
    Ok(Json(x))
}

pub fn get_member_routes(app_state: Arc<AppState>) -> Router {
    Router::new()
        .route("/sendOtp", post(send_otp_handler))
        .route("/verifyOtp", post(verify_otp_handler))
        .route("/login", post(login_handler))
        .with_state(app_state)
}

pub fn create_routes(app_state: Arc<AppState>) -> Router {
    Router::new()
        .layer(CorsLayer::permissive())
        .nest("/member", get_member_routes(app_state))
}
