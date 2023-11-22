//! `SeaORM` Entity. Generated by sea-orm-codegen 0.12.6

use sea_orm::entity::{prelude::*, Set};

use crate::Uuid;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "member_address")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub member_id: Uuid,

    pub recipient_name: String,
    pub phone: String,

    pub is_default: bool,

    pub line1: String,
    pub line2: String,
    pub region: String,
    pub county: String,
    pub district: String,
    pub street: String,
    pub zip_3: String,
    pub zip_5: String,
    pub zip_or_postal_code: String,

    pub created_at: DateTime,
    pub updated_at: DateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::member::Entity",
        from = "Column::MemberId",
        to = "super::member::Column::Id"
    )]
    Member,
}

impl Related<super::member::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Member.def()
    }
}

impl ActiveModelBehavior for ActiveModel {
    fn new() -> Self {
        Self {
            id: Set(Uuid::now_v7()),
            ..ActiveModelTrait::default()
        }
    }
}
