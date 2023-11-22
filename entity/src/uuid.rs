//! This module defines a wrapper around [`uuid::Uuid`] to ensure that [`Default`] returns an initialized value.
//!
//! Instead of returning [`uuid::Uuid::nil()`], this newtype's [`Default`] implementation returns [`Uuid::new_v4()`].
//!
//! This is used to avoid mistakes that could result in a nil Uuid being inserted into the database.
//! (Although the database disallows `NULL` values, a nil Uuid (all zeros) is a valid Uuid from Postgres' point of view.)
//!
//! This type should not be needed after the database handles generating Uuid values for primary keys.
use std::fmt::Display;

use sea_orm::{ActiveValue::NotSet, IntoActiveValue, Set};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A version 4 UUID.
///
/// This is a newtype wrapping [`uuid::Uuid`] to provide a [`Default`] implementation that returns [`Uuid::new_v4()`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UuidV7(Uuid);

impl UuidV7 {
    pub fn new() -> Self {
        Self::now_v7()
    }

    pub fn new_v7() -> Self {
        Self(Uuid::now_v7())
    }

    pub fn now_v7() -> Self {
        Self(Uuid::now_v7())
    }

    pub fn is_nil(&self) -> bool {
        self.0.is_nil()
    }
}

/// Defaults to an initialized value ([`Uuid::new_v4()`]) instead of [`Uuid`]'s behavior defaulting to [`Uuid::nil()`].
///
/// This implementation helps avoid insertion of nil uuids into the database (and is the reason [`UuidV4`] is used over [`Uuid`]).
impl Default for UuidV7 {
    fn default() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Display for UuidV7 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl From<uuid::Uuid> for UuidV7 {
    fn from(uuid: uuid::Uuid) -> Self {
        Self(uuid)
    }
}

impl From<UuidV7> for Uuid {
    fn from(uuid_v7: UuidV7) -> Self {
        uuid_v7.0
    }
}

impl IntoActiveValue<UuidV7> for UuidV7 {
    fn into_active_value(self) -> sea_orm::ActiveValue<UuidV7> {
        if self.is_nil() {
            NotSet
        } else {
            Set(self)
        }
    }
}

macro_rules! impl_try_from_u64_err {
    ($newtype: ident) => {
        impl sea_orm::TryFromU64 for $newtype {
            fn try_from_u64(_n: u64) -> Result<Self, sea_orm::DbErr> {
                Err(sea_orm::DbErr::ConvertFromU64(stringify!($newtype)))
            }
        }
    };
}

macro_rules! into_sea_query_value {
    ($newtype: ident: Box($name: ident)) => {
        impl From<$newtype> for sea_orm::Value {
            fn from(source: $newtype) -> Self {
                sea_orm::Value::$name(Some(Box::new(source.into())))
            }
        }

        impl sea_orm::TryGetable for $newtype {
            fn try_get_by<I: sea_orm::ColIdx>(
                res: &sea_orm::QueryResult,
                idx: I,
            ) -> Result<Self, sea_orm::TryGetError> {
                let val: $name = res.try_get_by(idx).map_err(sea_orm::TryGetError::DbErr)?;
                Ok($newtype(val))
            }
        }

        impl sea_orm::sea_query::Nullable for $newtype {
            fn null() -> sea_orm::Value {
                sea_orm::Value::$name(None)
            }
        }

        impl sea_orm::sea_query::ValueType for $newtype {
            fn try_from(v: sea_orm::Value) -> Result<Self, sea_orm::sea_query::ValueTypeErr> {
                match v {
                    sea_orm::Value::$name(Some(x)) => Ok($newtype(*x)),
                    _ => Err(sea_orm::sea_query::ValueTypeErr),
                }
            }

            fn type_name() -> String {
                stringify!($newtype).to_owned()
            }

            fn array_type() -> sea_orm::sea_query::ArrayType {
                sea_orm::sea_query::ArrayType::$name
            }

            fn column_type() -> sea_orm::sea_query::ColumnType {
                sea_orm::sea_query::ColumnType::$name
            }
        }
    };
}

into_sea_query_value!(UuidV7: Box(Uuid));
impl_try_from_u64_err!(UuidV7);
