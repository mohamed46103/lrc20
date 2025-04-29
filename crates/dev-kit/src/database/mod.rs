use std::pin::Pin;

use bitcoin::{OutPoint, TxOut};
use futures::{Stream, TryStreamExt};
use jsonrpsee::core::async_trait;
use lrc20_receipts::ReceiptProof;

#[cfg(feature = "inmemory")]
pub mod inmemory;
#[cfg(feature = "sqlite")]
pub mod sqlite;
pub mod wrapper;

#[cfg(feature = "inmemory")]
pub use inmemory::in_memory;

pub trait WalletStorage: Lrc20OutputsStorage + KeyValueStorage + Clone + Send + Sync {}

impl<T> WalletStorage for T where T: Lrc20OutputsStorage + KeyValueStorage + Clone + Send + Sync {}

type StorageStream<'a, T> = Pin<Box<dyn Stream<Item = eyre::Result<T>> + Send + 'a>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
#[repr(u8)]
pub enum Lrc20OutputState {
    #[default]
    Unspent = 0,
    Spent = 1,
    Frozen = 2,
}

impl TryFrom<u8> for Lrc20OutputState {
    type Error = eyre::Error;

    fn try_from(value: u8) -> eyre::Result<Self> {
        match value {
            0 => Ok(Lrc20OutputState::Unspent),
            1 => Ok(Lrc20OutputState::Spent),
            2 => Ok(Lrc20OutputState::Frozen),
            val => Err(eyre::eyre!("Invalid Lrc20OutputState, got: {val})")),
        }
    }
}

/// Provider of user outpoints from storage.
#[async_trait]
pub trait Lrc20OutputsStorage {
    /// Get the unspent lrc20 output for the given outpoint. If the outpoint is
    /// not found, return None.
    async fn try_get_unspent_lrc20_output(
        &self,
        outpoint: OutPoint,
    ) -> eyre::Result<Option<(ReceiptProof, TxOut)>>;

    /// Get the unspent lrc20 output for the given outpoint, return error if not
    /// found.
    async fn get_unspent_lrc20_output(
        &self,
        outpoint: OutPoint,
    ) -> eyre::Result<(ReceiptProof, TxOut)> {
        self.try_get_unspent_lrc20_output(outpoint)
            .await?
            .ok_or_else(|| eyre::eyre!("Unspent lrc20 outpoint not found {}", outpoint))
    }

    /// Insert the lrc20 output for the given outpoint
    async fn insert_unspent_lrc20_output(
        &self,
        outpoint: OutPoint,
        receipt_proof: ReceiptProof,
        txout: TxOut,
    ) -> eyre::Result<()>;

    async fn set_lrc20_output_state(
        &self,
        outpoint: OutPoint,
        state: Lrc20OutputState,
    ) -> eyre::Result<()>;

    async fn mark_lrc20_output_as_spent(&self, outpoint: OutPoint) -> eyre::Result<()> {
        self.set_lrc20_output_state(outpoint, Lrc20OutputState::Spent)
            .await
    }

    async fn mark_lrc20_output_as_frozen(&self, outpoint: OutPoint) -> eyre::Result<()> {
        self.set_lrc20_output_state(outpoint, Lrc20OutputState::Frozen)
            .await
    }

    /// Iterate through all unspent lrc20 outputs of the user
    async fn stream_unspent_lrc20_outputs<'a>(
        &'a self,
    ) -> StorageStream<'a, (OutPoint, (ReceiptProof, TxOut))>;

    /// Consume all unspent lrc20 outputs into a collection
    async fn collect_unspent_lrc20_outputs<T>(&self) -> eyre::Result<T>
    where
        T: Default + Extend<(OutPoint, (ReceiptProof, TxOut))> + Send,
    {
        self.stream_unspent_lrc20_outputs()
            .await
            .try_collect()
            .await
    }
}

/// Provider of simple key value parameters required for the application.
///
/// Here should be placed all parameters which won't required separate DB
/// instance.
#[async_trait]
pub trait KeyValueStorage {
    /// Get the last indexed page number
    async fn last_indexed_page_number(&self) -> eyre::Result<u64>;

    /// Put the last indexed page number
    async fn put_last_indexed_page_number(&self, page_number: u64) -> eyre::Result<()>;

    /// Get the unique identifier of the node to which the application
    /// previously synced.
    async fn connected_node_id(&self) -> eyre::Result<Option<String>>;

    /// Put the unique identifier of the node to which the application
    /// previously synced.
    async fn put_connected_node_id(&self, node_id: String) -> eyre::Result<()>;
}
