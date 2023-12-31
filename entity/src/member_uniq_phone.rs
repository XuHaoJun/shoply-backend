//! `SeaORM` Entity. Generated by sea-orm-codegen 0.12.6

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "member_uniq_phone")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub value: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
