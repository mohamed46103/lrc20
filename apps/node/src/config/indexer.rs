use std::time::Duration;

use bitcoin::BlockHash;
use lrc20_indexers::{BlockLoaderConfig, IndexingParams};
use lrc20_types::DEFAULT_CONFIRMATIONS_NUMBER;
use serde::Deserialize;

pub const DEFAULT_POLLING_PERIOD: Duration = Duration::from_secs(5);

/// One day:
pub const DEFAULT_MAX_CONFIRMATION_TIME: Duration = Duration::from_secs(60 * 60 * 24);
/// Default interval of checking if the transactions that are waiting for the confirmation should be deleted from the queue.
pub const DEFAULT_CLEAN_UP_INTERVAL: Duration = Duration::from_secs(60 * 10 * 10);

/// Default interval between attempts of restarting the indexer.
pub const DEFAULT_RESTART_INTERVAL: Duration = Duration::from_secs(5);
/// Default number of attempts to restart the indexer.
pub const MAX_RESTART_ATTEMPTS: u32 = 10;

#[derive(Clone, Deserialize)]
pub struct IndexerConfig {
    #[serde(default = "default_polling_period")]
    pub polling_period: Duration,

    #[serde(default)]
    pub liveness_period: Option<Duration>,

    #[serde(default)]
    pub starting_block: Option<BlockHash>,

    #[serde(default)]
    pub force_reindex: Option<bool>,

    #[serde(default = "default_max_confirmation_time")]
    pub max_confirmation_time: Duration,

    #[serde(default = "default_clean_up_interval")]
    pub clean_up_interval: Duration,

    #[serde(default)]
    pub blockloader: BlockLoaderConfig,

    #[serde(default = "default_restart_interval")]
    pub restart_interval: Duration,

    #[serde(default = "default_max_restart_attempts")]
    pub max_restart_attempts: u32,

    #[serde(default = "default_confirmations_number")]
    pub confirmations_number: u8,

    #[serde(default)]
    pub enforce_announcements: Option<bool>,
}

fn default_polling_period() -> Duration {
    DEFAULT_POLLING_PERIOD
}

fn default_max_confirmation_time() -> Duration {
    DEFAULT_MAX_CONFIRMATION_TIME
}

fn default_restart_interval() -> Duration {
    DEFAULT_RESTART_INTERVAL
}

fn default_max_restart_attempts() -> u32 {
    MAX_RESTART_ATTEMPTS
}

fn default_clean_up_interval() -> Duration {
    DEFAULT_CLEAN_UP_INTERVAL
}

fn default_confirmations_number() -> u8 {
    DEFAULT_CONFIRMATIONS_NUMBER
}

impl From<IndexerConfig> for IndexingParams {
    fn from(value: IndexerConfig) -> Self {
        Self {
            starting_block_hash: value.starting_block,
            force_reindex: value.force_reindex,
        }
    }
}

impl Default for IndexerConfig {
    fn default() -> Self {
        Self {
            polling_period: default_polling_period(),
            liveness_period: None,
            starting_block: Default::default(),
            force_reindex: Default::default(),
            max_confirmation_time: default_max_confirmation_time(),
            blockloader: BlockLoaderConfig::default(),
            restart_interval: default_restart_interval(),
            max_restart_attempts: default_max_restart_attempts(),
            clean_up_interval: default_clean_up_interval(),
            confirmations_number: Default::default(),
            enforce_announcements: Default::default(),
        }
    }
}
