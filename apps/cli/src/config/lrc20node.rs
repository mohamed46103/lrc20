use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct Lrc20NodeConfig {
    pub url: String,
}
