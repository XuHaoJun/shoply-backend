//! Run with
//!
//! ```not_rust
//! cargo run -p example-rest-grpc-multiplex
//! ```

use crate::{model::*, routes::create_routes};

use self::multiplex_service::MultiplexService;
use axum::{routing::get, Router};
use migration::ConnectionTrait;
use proto::{
    greeter_server::{Greeter, GreeterServer},
    HelloReply, HelloRequest,
};
use serde::Deserialize;
use shoply_service::{sea_orm::{Database, DatabaseConnection, Schema}, dto::AppConfig};
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::signal;
use tonic::{Response as TonicResponse, Status};
use tonic_web::GrpcWebLayer;
use tower_http::cors::CorsLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod model;
mod multiplex_service;
mod routes;

mod proto {
    tonic::include_proto!("helloworld");

    pub(crate) const FILE_DESCRIPTOR_SET: &[u8] =
        tonic::include_file_descriptor_set!("helloworld_descriptor");
}

#[derive(Default)]
struct GrpcServiceImpl {}

#[tonic::async_trait]
impl Greeter for GrpcServiceImpl {
    async fn say_hello(
        &self,
        request: tonic::Request<HelloRequest>,
    ) -> Result<TonicResponse<HelloReply>, Status> {
        tracing::info!("Got a request from {:?}", request.remote_addr());

        let reply = HelloReply {
            message: format!("Hello {}!", request.into_inner().name),
        };

        Ok(TonicResponse::new(reply))
    }
}

async fn web_root() -> &'static str {
    "Hello, World!"
}

#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
struct AppConfig2 {
    host: String,
    // list: Vec<String>,
}

#[tokio::main]
pub async fn main() {
    // initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "shoply_api=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    dotenvy::dotenv().ok();

    let s = config::Config::builder()
        .add_source(config::File::with_name("shoplyrc").required(false))
        .add_source(
            config::Environment::default()
                .try_parsing(true)
                .separator("__"), // .list_separator(",")
                                  // .with_list_parse_key("cors"),
        )
        .build()
        .unwrap();

    let app_config: AppConfig = s.try_deserialize().unwrap();

    let db_url = app_config.database_url.clone();

    let conn = Database::connect(db_url)
        .await
        .expect("Database connection failed");
    let backend = conn.get_database_backend();
    let schema = Schema::new(backend);
    let table_create_statement = schema.create_table_from_entity(entity::member::Entity);
    let table_create_result = conn.execute(backend.build(&table_create_statement)).await;
    let _ = conn
        .execute(backend.build(&schema.create_table_from_entity(entity::member_auth::Entity)))
        .await;
    let _ = conn
        .execute(backend.build(&schema.create_table_from_entity(entity::member_address::Entity)))
        .await;
    let _ = conn
        .execute(backend.build(&schema.create_table_from_entity(entity::member_uniq_email::Entity)))
        .await;
    let _ = conn
        .execute(backend.build(&schema.create_table_from_entity(entity::member_uniq_phone::Entity)))
        .await;

    let app_state = Arc::new(AppState {
        conn: conn.clone(),
        config: app_config.clone(),
    });

    // build the rest service
    let rest = create_routes(app_state);

    // build the grpc service
    let reflection_service = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(proto::FILE_DESCRIPTOR_SET)
        .build()
        .unwrap();

    let grpc = tonic::transport::Server::builder()
        .accept_http1(true)
        .layer(CorsLayer::permissive())
        .layer(GrpcWebLayer::new())
        .add_service(reflection_service)
        .add_service(GreeterServer::new(GrpcServiceImpl::default()))
        .into_service();

    // combine them into one service
    let service = MultiplexService::new(rest, grpc);

    let addr: SocketAddr = (app_config.host + ":" + app_config.port.as_ref())
        .parse()
        .unwrap();
    tracing::debug!("listening on {addr}");
    hyper::Server::bind(&addr)
        .serve(tower::make::Shared::new(service))
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    println!("signal received, starting graceful shutdown");
}
