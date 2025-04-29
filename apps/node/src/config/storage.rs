use serde::{Deserialize, Serialize};
use std::time::Duration;
pub const DEFAULT_TX_PER_PAGE: u64 = 100;

#[derive(Serialize, Deserialize, Clone)]
pub struct StorageConfig {
    /// Transactions per one page
    #[serde(default = "default_tx_per_page")]
    pub tx_per_page: u64,

    /// Is announcements should be validated(by default false)
    #[serde(default = "default_validate_announcements")]
    pub validate_announcements: bool,

    /// Database URL for node storage. Should also include credentials if any.
    pub database_url: String,

    /// Enables sea-orm-query logging
    pub logging: Option<bool>,

    /// Maximum number of connections for a pool
    pub max_connections: Option<u32>,

    /// Minimum number of connections for a pool
    pub min_connections: Option<u32>,

    /// Connection timeout
    pub connect_timeout: Option<Duration>,
}

fn default_tx_per_page() -> u64 {
    DEFAULT_TX_PER_PAGE
}

fn default_validate_announcements() -> bool {
    false
}
