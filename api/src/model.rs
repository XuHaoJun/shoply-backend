use shoply_service::sea_orm::{Database, DatabaseConnection, Schema};

#[derive(Clone)]
pub struct AppState {
    pub conn: DatabaseConnection,
}
