use crate::dto::*;
use ::entity::prelude::*;
use argon2::{password_hash::SaltString, Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use jsonwebtoken::{encode, EncodingKey, Header};
use sea_orm::*;
use serde::{Deserialize, Serialize};
use shoply_service::dto::*;
use std::{default, ops::Add};

pub struct Query;

impl Query {

    pub async fn login(db: &DbConn, body: LoginForm) -> Result<LoginResponse, CommonError> {
        #[derive(FromQueryResult)]
        struct PartialMember {
            pub id: String,
            pub password: String,
        }
        let member = Member::find()
            .filter(
                Condition::any()
                    .add(::entity::member::Column::Email.eq(body.email_or_phone.to_lowercase()))
                    .add(::entity::member::Column::Phone.eq(body.email_or_phone)),
            )
            .select_only()
            .column(::entity::member::Column::Id)
            .column(::entity::member::Column::Password)
            .into_model::<PartialMember>()
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

        let is_valid = match PasswordHash::new(&member.password) {
            Ok(parsed_hash) => Argon2::default()
                .verify_password(body.password.as_bytes(), &parsed_hash)
                .map_or(false, |_| true),
            Err(_) => false,
        };
        if !is_valid {
            return Err(CommonError {
                http_status: 400,
                error_code: 1000001,
                result: None,
            });
        }

        let now = chrono::Utc::now();
        let iat = now.timestamp() as usize;
        let jti = uuid::Uuid::now_v7().to_string();

        let claims: TokenClaims = {
            let exp = (now + chrono::Duration::minutes(60)).timestamp() as usize;
            TokenClaims {
                sub: member.id.to_string(),
                exp,
                iat,
                jti: jti.clone(),
                acjti: None,
            }
        };

        let refresh_claims: TokenClaims = {
            let exp = (now + chrono::Duration::minutes(180)).timestamp() as usize;
            TokenClaims {
                sub: member.id.to_string(),
                exp,
                iat,
                jti: uuid::Uuid::now_v7().to_string(),
                acjti: Some(jti.clone()),
            }
        };

        let access_token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret("my_secret".as_ref()),
        )
        .unwrap();
        let refresh_token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret("my_secret".as_ref()),
        )
        .unwrap();

        Ok(LoginResponse {
            access_token,
            refresh_token,
        })
    }
}
