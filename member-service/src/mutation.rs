use crate::dto::*;
use ::entity::prelude::*;
use argon2::{password_hash::SaltString, Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
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
                        ::entity::member_auth::Column::Email.eq(body.email_or_phone.to_lowercase()),
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
                            chrono::Utc::now() + chrono::Duration::minutes(2);
                        let new_auth = ::entity::member_auth::ActiveModel {
                            otp_type: Set(::entity::member_auth::OtpType::Email),
                            email: Set(Some(body.email_or_phone.to_lowercase().to_owned())),
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


}
