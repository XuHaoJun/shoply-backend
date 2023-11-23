use crate::dto::*;
use ::entity::prelude::*;
use argon2::{password_hash::{SaltString, rand_core::OsRng}, Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use jsonwebtoken::{encode, EncodingKey, Header};
use sea_orm::*;
use serde::{Deserialize, Serialize};
use shoply_service::dto::*;
use std::{default, ops::Add};

pub struct Mutation;

impl Mutation {
    pub async fn send_otp(db: &DbConn, body: SendOtpForm) -> Result<SendOtpResponse, CommonError> {
        match body.otp_type {
            ::entity::member_auth::OtpType::Email => {
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
                        let email_otp_exipred_at =
                            chrono::Utc::now() + chrono::Duration::minutes(30);
                        let new_auth = ::entity::member_auth::ActiveModel {
                            otp_type: Set(::entity::member_auth::OtpType::Email),
                            email: Set(Some(body.email_or_phone.to_ascii_lowercase())),
                            otp: Set("123456".to_owned()),
                            exipred_at: Set(email_otp_exipred_at.clone()),
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
            ::entity::member_auth::OtpType::Phone => todo!(),
        }
    }

    pub async fn verify_otp(db: &DbConn, body: VerifyOtpForm) -> Result<(), CommonError> {
        let auth = MemberAuth::find()
            .filter(
                Condition::all()
                    .add(::entity::member_auth::Column::OtpType.eq(body.otp_type))
                    .add(::entity::member_auth::Column::Otp.eq(body.otp))
                    .add(
                        Condition::any()
                            .add(
                                ::entity::member_auth::Column::Email
                                    .eq(body.email_or_phone.clone()),
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

        if !auth.is_verified {
            let mut update_auth: ::entity::member_auth::ActiveModel = auth.into();
            update_auth.is_verified = Set(true);
            update_auth.update(db).await.map_err(|_| CommonError {
                http_status: 500,
                error_code: 100000,
                result: None,
            })?;
        }

        Ok(())
    }

    pub async fn register(db: &DbConn, body: RegisterForm) -> Result<(), CommonError> {
        let verify_otp = VerifyOtpForm {
            email_or_phone: body.email.clone().unwrap(),
            otp_type: body.otp_type,
            otp: body.otp,
        };
        Self::verify_otp(db, verify_otp).await?;

        let salt = SaltString::generate(&mut OsRng);
        let hashed_password = Argon2::default()
            .hash_password(body.password.as_bytes(), &salt)
            .map_err(|e| CommonError {
                http_status: 500,
                error_code: 100000,
                result: None,
            })
            .map(|hash| hash.to_string())?;
        let new_member = ::entity::member::ActiveModel {
            password: Set(hashed_password),
            email: Set(body.email.clone().and_then(|x| Some(x.to_ascii_lowercase()))),
            phone: Set(body.phone),
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
        Ok(())
    }
}
