use crate::dto::*;
use ::entity::prelude::*;
use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
};
use jsonwebtoken::{encode, EncodingKey, Header};
use rand::Rng;
use sea_orm::*;
use serde::{Deserialize, Serialize};
use shoply_service::dto::*;
use std::{default, ops::Add};

pub struct Mutation;

impl Mutation {
    pub async fn send_otp(db: &DbConn, body: SendOtpForm) -> Result<SendOtpResponse, CommonError> {
        match body.otp_type {
            ::entity::member_auth::OtpType::RegisterActionByEmail => {
                // TODO
                // do send otp
                let maybe_auth = MemberAuth::find()
                    .filter(
                        ::entity::member_auth::Column::Email
                            .eq(body.email_or_phone.to_ascii_lowercase()),
                    )
                    .one(db)
                    .await
                    .map_err(|err| {
                        println!("{}", err.to_string());
                        return CommonError {
                            http_status: 500,
                            error_code: 100000,
                            result: None,
                        };
                    })?;

                match maybe_auth {
                    None => {
                        let now = chrono::Utc::now();
                        let email_otp_exipred_at = now + chrono::Duration::minutes(30);
                        // let num = rand::thread_rng().gen_range(1..1000000);
                        // let otp = format!("{:0>6}", num.to_string());
                        let otp = "123456".to_owned();
                        let new_auth = ::entity::member_auth::ActiveModel {
                            otp_type: Set(::entity::member_auth::OtpType::RegisterActionByEmail),
                            email: Set(Some(body.email_or_phone.to_ascii_lowercase())),
                            otp: Set(otp),
                            exipred_at: Set(email_otp_exipred_at.clone()),
                            last_send_at: Set(now),
                            ..Default::default()
                        };
                        MemberAuth::insert(new_auth).exec(db).await.map_err(|err| {
                            println!("{}", err.to_string());
                            return CommonError {
                                http_status: 500,
                                error_code: 100000,
                                result: None,
                            };
                        })?;
                        return Ok(SendOtpResponse {
                            expired_at: email_otp_exipred_at.clone(),
                        });
                    }
                    Some(auth) => todo!(),
                }
            }
            ::entity::member_auth::OtpType::RegisterActionByPhone => todo!(),
        }
    }

    pub async fn verify_otp(
        db: &DbConn,
        body: VerifyOtpForm,
    ) -> Result<::entity::member_auth::Model, CommonError> {
        let auth: ::entity::member_auth::Model = MemberAuth::find()
            .filter(
                Condition::all()
                    .add(::entity::member_auth::Column::OtpType.eq(body.otp_type))
                    .add(::entity::member_auth::Column::Otp.eq(body.otp))
                    .add(
                        Condition::any()
                            .add(
                                ::entity::member_auth::Column::Email
                                    .eq(body.email_or_phone.clone().to_ascii_lowercase()),
                            )
                            .add(
                                ::entity::member_auth::Column::Phone
                                    .eq(body.email_or_phone.clone()),
                            ),
                    ),
            )
            .one(db)
            .await
            .map_err(|_| CommonError {
                http_status: 500,
                error_code: 100000,
                result: None,
            })?
            .ok_or_else(|| CommonError {
                http_status: 400,
                error_code: 100001,
                result: None,
            })?;
        let now = chrono::Utc::now();
        if now > auth.exipred_at {
            MemberAuth::delete_by_id(auth.id)
                .exec(db)
                .await
                .map_err(|err| CommonError {
                    http_status: 400,
                    error_code: 100001,
                    result: None,
                })?;
            return Err(CommonError {
                http_status: 400,
                error_code: 100001,
                result: None,
            });
        }
        Ok(auth)
    }

    pub async fn register(db: &DbConn, body: RegisterForm) -> Result<(), CommonError> {
        let verify_otp = VerifyOtpForm {
            email_or_phone: body.email_or_phone.clone(),
            otp_type: body.otp_type.clone(),
            otp: body.otp,
        };
        let auth = Self::verify_otp(db, verify_otp).await?;

        let salt = SaltString::generate(&mut OsRng);
        let hashed_password = Argon2::default()
            .hash_password(body.password.as_bytes(), &salt)
            .map_err(|e| CommonError {
                http_status: 500,
                error_code: 100000,
                result: None,
            })
            .map(|hash| hash.to_string())?;
        let email = match body.otp_type {
            ::entity::member_auth::OtpType::RegisterActionByEmail => {
                Some(body.email_or_phone.to_ascii_lowercase())
            }
            ::entity::member_auth::OtpType::RegisterActionByPhone => None,
        };
        let phone = match body.otp_type {
            ::entity::member_auth::OtpType::RegisterActionByEmail => None,
            ::entity::member_auth::OtpType::RegisterActionByPhone => Some(body.email_or_phone),
        };
        let new_member = ::entity::member::ActiveModel {
            password: Set(hashed_password),
            email: Set(email),
            phone: Set(phone),
            auth_status: ::entity::member::MemberAuthStatus::Active,
            ..Default::default()
        };
        Member::insert(new_member)
            .exec(db)
            .await
            .map_err(|_| CommonError {
                http_status: 500,
                error_code: 100000,
                result: None,
            })?;

        MemberAuth::delete_by_id(auth.id).exec(db).await;

        Ok(())
    }
}
