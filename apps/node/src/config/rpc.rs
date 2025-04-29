use lrc20_rpc_server::TlsConfig;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(Serialize, Deserialize)]
pub struct RpcConfig {
    /// Address to listen of incoming connections
    pub address: SocketAddr,

    /// Address to listen of incoming connections
    pub grpc_address: SocketAddr,

    /// TLS config
    #[serde(flatten)]
    pub tls_config: Option<TlsConfig>,

    /// Maximum number of items per list request
    #[serde(default = "default_max_items_per_request")]
    pub max_items_per_request: usize,

    /// Maximum request size in kilobytes
    #[serde(default = "default_max_request_size_kb")]
    pub max_request_size_kb: u32,
}

fn default_max_items_per_request() -> usize {
    50
}

fn default_max_request_size_kb() -> u32 {
    20480
}
