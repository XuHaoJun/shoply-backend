use chrono::{DateTime, Utc};
use entity::member_auth::OtpType;
use serde::{Deserialize, Serialize};
use serde_repr::*;
use ts_rs::TS;


#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginForm {
    pub email_or_phone: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: String,
}

#[derive(Debug, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct SendOtpForm {
    pub email_or_phone: String,
    pub otp_type: OtpType,
}

#[derive(Debug, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct SendOtpResponse {
    pub expired_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct VerifyOtpForm {
    pub email_or_phone: String,
    pub otp_type: OtpType,

    pub otp: String,
}

#[derive(Debug, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct RegisterForm {
    pub name: String,
    pub email_or_phone: String,

    pub password: String,
    pub confirm_password: String,

    pub otp_type: OtpType,
    pub otp: String,
}

#[derive(Debug, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct RefreshTokenForm {
    pub access_token: String,
    pub refresh_token: String,
}
