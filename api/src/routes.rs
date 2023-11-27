use axum::{
    extract::{Extension, Path, State},
    http::{header, Request},
    middleware,
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use axum_extra::extract::cookie::CookieJar;
use hyper::StatusCode;
use jsonwebtoken::{decode, DecodingKey, Validation};
use shoply_member_service::dto::{
    LoginForm, RefreshTokenForm, RegisterForm, SendOtpForm, VerifyOtpForm,
};
use shoply_service::dto::{CommonError, TokenClaims};
use std::sync::Arc;
use tower::ServiceBuilder;
use tower_http::cors::CorsLayer;

use crate::model::*;

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
    shoply_member_service::Mutation::verify_otp(&app_state.conn, body)
        .await
        .map_err(|err| {
            (
                StatusCode::from_u16(err.http_status).unwrap(),
                Json(serde_json::to_value(err).unwrap()),
            )
        })?;
    Ok(Json(true))
}

async fn login_handler(
    State(app_state): State<Arc<AppState>>,
    Json(body): Json<LoginForm>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let x = shoply_member_service::Query::login(&app_state.conn, &app_state.config.jwt, body)
        .await
        .map_err(|err| {
            (
                StatusCode::from_u16(err.http_status).unwrap(),
                Json(serde_json::to_value(err).unwrap()),
            )
        })?;
    Ok(Json(x))
}

async fn register_handler(
    State(app_state): State<Arc<AppState>>,
    Json(body): Json<RegisterForm>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let x = shoply_member_service::Mutation::register(&app_state.conn, body)
        .await
        .map_err(|err| {
            (
                StatusCode::from_u16(err.http_status).unwrap(),
                Json(serde_json::to_value(err).unwrap()),
            )
        })?;
    Ok(Json(x))
}

async fn refresh_token_handler(
    State(app_state): State<Arc<AppState>>,
    Json(body): Json<RefreshTokenForm>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let x = shoply_member_service::Query::refresh_token(&app_state.config.jwt, body).map_err(
        |err| {
            (
                StatusCode::from_u16(err.http_status).unwrap(),
                Json(serde_json::to_value(err).unwrap()),
            )
        },
    )?;
    Ok(Json(x))
}

pub fn extract_token<B>(cookie_jar: CookieJar, req: &Request<B>) -> Option<String> {
    cookie_jar
        .get("token")
        .map(|cookie| cookie.value().to_string())
        .or_else(|| {
            req.headers()
                .get(header::AUTHORIZATION)
                .and_then(|auth_header| auth_header.to_str().ok())
                .and_then(|auth_value| {
                    if auth_value.starts_with("Bearer ") {
                        Some(auth_value[7..].to_owned())
                    } else {
                        None
                    }
                })
        })
}

pub async fn try_extract_claims<B>(
    cookie_jar: CookieJar,
    State(app_state): State<Arc<AppState>>,
    mut req: Request<B>,
    next: middleware::Next<B>,
) -> Result<impl IntoResponse, (StatusCode, Json<CommonError>)> {
    let token = extract_token(cookie_jar, &req);
    if token == None {
        return Ok(next.run(req).await);
    }
    let claims = decode::<TokenClaims>(
        &token.unwrap(),
        &DecodingKey::from_secret(app_state.config.jwt.secret.as_ref()),
        &Validation::default(),
    );
    if let Ok(data) = claims {
        req.extensions_mut().insert(data.claims);
    }
    Ok(next.run(req).await)
}

pub async fn authorize<B>(
    cookie_jar: CookieJar,
    State(app_state): State<Arc<AppState>>,
    mut req: Request<B>,
    next: middleware::Next<B>,
) -> Result<impl IntoResponse, (StatusCode, Json<CommonError>)> {
    let token = extract_token(cookie_jar, &req);
    let token = token.ok_or_else(|| {
        let json_error = CommonError {
            http_status: 401,
            error_code: 100000,
            result: None,
        };
        (StatusCode::UNAUTHORIZED, Json(json_error))
    })?;

    let claims = decode::<TokenClaims>(
        &token,
        &DecodingKey::from_secret(app_state.config.jwt.secret.as_ref()),
        &Validation::default(),
    )
    .map_err(|_| {
        let json_error = CommonError {
            http_status: 401,
            error_code: 100000,
            result: None,
        };
        (StatusCode::UNAUTHORIZED, Json(json_error))
    })?
    .claims;

    req.extensions_mut().insert(claims);

    Ok(next.run(req).await)
}

pub fn get_member_routes(app_state: Arc<AppState>) -> Router {
    Router::new()
        .route("/send-otp", post(send_otp_handler))
        .route("/verify-otp", post(verify_otp_handler))
        .route("/", post(register_handler))
        .route("/login", post(login_handler))
        .route("/refresh-token", post(refresh_token_handler))
        .with_state(app_state)
}

pub async fn local_now_handle() -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)>
{
    Ok(chrono::Local::now().to_rfc3339())
}

pub fn create_routes(app_state: Arc<AppState>) -> Router {
    Router::new()
        .route("/now", get(local_now_handle))
        .nest("/member", get_member_routes(app_state))
        .layer(CorsLayer::permissive())
}
