use std::time::Duration;

use bitcoin::BlockHash;

/// Parameters to specify for initial indexing of blocks,
/// that node have skipped.
#[derive(Default)]
pub struct IndexingParams {
    /// The hash of block from which indexing should start.
    pub starting_block_hash: Option<BlockHash>,
    /// Forces the indexer to start indexing from starting_block_hash (if specified) even if the
    /// last indexed block height is bigger than the starting_block_hash height.
    pub force_reindex: Option<bool>,
}

/// Parameters that are passed to the `run` method of the indexer.
#[derive(Debug)]
pub struct RunParams {
    /// Period of time to wait between polling new blocks from Bitcoin.
    pub polling_period: Duration,
}

impl Default for RunParams {
    fn default() -> Self {
        Self {
            polling_period: Duration::from_secs(10),
        }
    }
}
