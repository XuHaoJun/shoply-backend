//! Run with
//!
//! ```not_rust
//! cargo run -p example-rest-grpc-multiplex
//! ```

use self::multiplex_service::MultiplexService;
use axum::{routing::get, Router};
use proto::{
    greeter_server::{Greeter, GreeterServer},
    HelloReply, HelloRequest,
};
use std::net::SocketAddr;
use tonic::{Response as TonicResponse, Status};
use tonic_web::GrpcWebLayer;
use tower_http::cors::CorsLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod multiplex_service;

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

    // build the rest service
    let rest = Router::new()
        .route("/", get(web_root))
        .layer(CorsLayer::permissive());

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

    let addr = SocketAddr::from(([0, 0, 0, 0], 5000));
    tracing::debug!("listening on {addr}");
    hyper::Server::bind(&addr)
        .serve(tower::make::Shared::new(service))
        .await
        .unwrap();
}
