use std::default;

use crate::dto::*;
use ::entity::member::Entity as Member;
use argon2::{password_hash::SaltString, Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use jsonwebtoken::{encode, EncodingKey, Header};
use sea_orm::*;
use serde::{Deserialize, Serialize};
use shoply_service::dto::TokenClaims;

#[derive(Debug, Serialize, Deserialize)]
pub struct CommonError {
    pub http_status: i32,
    pub error_code: i32,
}

pub struct Mutation;

impl Mutation {
    pub async fn login(db: &DbConn, body: LoginForm) -> Result<LoginResponse, CommonError> {
        #[derive(FromQueryResult)]
        struct PartialMember {
            pub id: String,
            pub password: String,
        }
        let member = Member::find()
            .filter(::entity::member::Column::Username.eq(body.username))
            .select_only()
            .column(::entity::member::Column::Id)
            .column(::entity::member::Column::Password)
            .into_model::<PartialMember>()
            .one(db)
            .await
            .map_err(|_| CommonError {
                http_status: 500,
                error_code: 100000,
            })?
            .ok_or_else(|| CommonError {
                http_status: 400,
                error_code: 100001,
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
