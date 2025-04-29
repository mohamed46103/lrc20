use axum::Router;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum_server::tls_rustls::RustlsConfig;
use bitcoin_client::BitcoinRpcClient;
use event_bus::EventBus;
use hyper::Method;
use jsonrpsee::core::Serialize;
use jsonrpsee::server::Server as JsonRpcServer;
use lrc20_storage::traits::{
    IndexerNodeStorage, Lrc20NodeStorage, MempoolNodeStorage, SparkNodeStorage,
};
use prometheus::TextEncoder;
use protos::rpc::v1::spark_service_server::SparkServiceServer;
use serde::Deserialize;
use spark::SparkRpcServer;
use std::path::PathBuf;
use std::{net::SocketAddr, str::FromStr, sync::Arc};
use tokio_util::sync::CancellationToken;
use tonic::service::Routes;
use tower_http::cors::{Any, CorsLayer};
use tracing::{error, info};

use lrc20_rpc_api::transactions::Lrc20TransactionsRpcServer;
use lrc20_storage::PgDatabaseConnectionManager;
use protos::rpc::v1;

use crate::middleware::grpc::GrpcMetricsLayer;
use crate::middleware::jsonrpc::JsonRpcMetricsLayer;
use crate::transactions::TransactionsController;

mod middleware;
pub mod spark;
pub mod transactions;

pub struct ServerConfig {
    /// JSON RPC address at which the server will listen for incoming connections.
    pub json_rpc_address: String,
    /// gRPC address at which the server will listen for incoming connections.
    pub grpc_address: String,
    /// TLS configuration
    pub tls_config: Option<TlsConfig>,
    /// Max number of items to request/process per incoming request.
    pub max_items_per_request: usize,
    /// Max size of incoming request in kilobytes.
    pub max_request_size_kb: u32,
    pub page_size: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Path to PEM encoded X509 Certificate file
    pub cert_path: PathBuf,

    /// Path to a private key file for a TLS certificate
    pub key_path: PathBuf,
}

/// Runs LRC20 Node's RPC server.
pub async fn run_server<NS>(
    ServerConfig {
        json_rpc_address,
        grpc_address,
        tls_config,
        max_items_per_request,
        max_request_size_kb,
        page_size,
    }: ServerConfig,
    node_storage: NS,
    full_event_bus: EventBus,
    bitcoin_client: Arc<BitcoinRpcClient>,
    cancellation: CancellationToken,
    enforce_announcements: bool,
) -> eyre::Result<()>
where
    NS: PgDatabaseConnectionManager
        + Lrc20NodeStorage
        + SparkNodeStorage
        + MempoolNodeStorage
        + IndexerNodeStorage
        + Clone
        + Send
        + Sync
        + 'static,
{
    let cors = CorsLayer::new()
        .allow_methods([Method::POST])
        .allow_origin(Any)
        .allow_headers([hyper::header::CONTENT_TYPE]);
    let middleware = tower::ServiceBuilder::new()
        .layer(cors)
        .layer(JsonRpcMetricsLayer);

    // The multiplication of average transaction size and max number of items
    // per request approximately gives the maximum JSON RPC request size.
    //
    // See `providelistlrc20proofs`
    let server = JsonRpcServer::builder()
        .max_request_body_size(max_request_size_kb * 1024)
        .set_middleware(middleware)
        .build(json_rpc_address.clone())
        .await?;

    info!("Starting JSONRPC server on {}", json_rpc_address);
    let handle = server.start(
        TransactionsController::new(
            node_storage.clone(),
            full_event_bus.clone(),
            Arc::clone(&bitcoin_client),
            max_items_per_request,
            page_size,
        )
        .into_rpc(),
    );
    info!("JSONRPC server started");

    let http_routes = Router::new().route("/metrics", axum::routing::get(metrics));

    let spark_server = SparkRpcServer::new(
        full_event_bus,
        node_storage.clone(),
        Arc::clone(&bitcoin_client),
        node_storage,
        enforce_announcements,
    );

    let reflection_service = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(v1::FILE_DESCRIPTOR_SET)
        .build_v1alpha()?;

    let mut grpc_builder = Routes::builder();
    grpc_builder.add_service(SparkServiceServer::new(spark_server));
    grpc_builder.add_service(reflection_service);
    let grpc_routes = grpc_builder
        .routes()
        .into_axum_router()
        .layer(GrpcMetricsLayer);

    let app = http_routes.merge(grpc_routes);

    if let Some(TlsConfig {
        cert_path,
        key_path,
    }) = tls_config
    {
        let config = RustlsConfig::from_pem_file(cert_path, key_path)
            .await
            .inspect_err(|err| error!("Failed to create TLS config: {}", err))?;

        info!("Starting gRPC server (w/ TLS) on {}", grpc_address);
        axum_server::bind_rustls(SocketAddr::from_str(&grpc_address)?, config)
            .serve(app.into_make_service())
            .await?;
    } else {
        info!("Starting gRPC server (w/o TLS) on {}", grpc_address);
        axum_server::bind(SocketAddr::from_str(&grpc_address)?)
            .serve(app.into_make_service())
            .await?;
    }

    info!("gRPC server started");

    // Await until stop message received
    cancellation.cancelled().await;

    // Send stop message to server
    if let Err(err) = handle.stop() {
        tracing::trace!("Failed to stop server: {}", err);
    }

    // Wait until server stopped
    handle.stopped().await;

    Ok(())
}

async fn metrics() -> impl IntoResponse {
    let metrics = prometheus::gather();
    let encoder = TextEncoder::new();

    encoder
        .encode_to_string(&metrics)
        .map(|resp| (StatusCode::OK, resp))
        .unwrap_or_else(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))
}
