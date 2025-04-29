use serde::Deserialize;
use std::time::Duration;

#[derive(Deserialize, Clone)]
pub struct GraphBuilderConfig {
    /// Period of time after which [`lrc20_tx_attach::GraphBuilder`] will cleanup transactions
    /// that are _too old_.
    #[serde(default = "default_cleanup_period")]
    pub cleanup_period: Duration,

    /// Period of time, after which we consider transaction _too old_
    /// or _outdated_.
    #[serde(default = "default_tx_outdated_duration")]
    pub tx_outdated_duration: Duration,
}

fn default_cleanup_period() -> Duration {
    Duration::from_secs(60 * 60)
}

fn default_tx_outdated_duration() -> Duration {
    Duration::from_secs(60 * 60 * 24)
}

impl Default for GraphBuilderConfig {
    fn default() -> Self {
        Self {
            cleanup_period: default_cleanup_period(),
            tx_outdated_duration: default_tx_outdated_duration(),
        }
    }
}
