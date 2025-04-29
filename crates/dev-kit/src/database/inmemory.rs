//! This module provides in-memory ([`HashMap`] based) implementation of the storage traits.

use std::{collections::HashMap, sync::Arc};

use bitcoin::{OutPoint, TxOut};
use eyre::bail;
use futures::stream;
use jsonrpsee::core::async_trait;
use lrc20_receipts::ReceiptProof;
use tokio::sync::Mutex;

use super::{KeyValueStorage, Lrc20OutputState, Lrc20OutputsStorage, StorageStream};

/// Return instance of safe in-memory database storage.
pub fn in_memory() -> SafeInMemoryDB {
    Arc::new(Mutex::new(InMemoryDB::default()))
}

/// In-memory database storage with `Arc` and `Mutex` for cloning and thread
/// safety.
pub type SafeInMemoryDB = Arc<Mutex<InMemoryDB>>;

#[derive(Clone)]
pub(crate) struct Lrc20Output {
    receipt_proof: ReceiptProof,
    txout: TxOut,
    state: Lrc20OutputState,
}

/// In-memory database storage.
///
/// Implementation of wallet storage for tests and quick prototyping.
#[derive(Clone, Default)]
pub struct InMemoryDB {
    pub(crate) lrc20_outputs: HashMap<OutPoint, Lrc20Output>,
    pub(crate) last_indexed_page_number: u64,
    pub(crate) connected_node_id: Option<String>,
}

/// Provider of unspent user outpoints which have not been spent yet.
#[async_trait]
impl Lrc20OutputsStorage for SafeInMemoryDB {
    /// Get the unspent lrc20 outpoint for the given outpoint
    async fn try_get_unspent_lrc20_output(
        &self,
        outpoint: OutPoint,
    ) -> eyre::Result<Option<(ReceiptProof, TxOut)>> {
        Ok(self
            .lock()
            .await
            .lrc20_outputs
            .get(&outpoint)
            .map(|e| (e.receipt_proof.clone(), e.txout.clone())))
    }

    /// Insert the unspent lrc20 outpoint for the given outpoint
    async fn insert_unspent_lrc20_output(
        &self,
        outpoint: OutPoint,
        receipt_proof: ReceiptProof,
        txout: TxOut,
    ) -> eyre::Result<()> {
        self.lock().await.lrc20_outputs.insert(
            outpoint,
            Lrc20Output {
                receipt_proof,
                txout,
                state: Lrc20OutputState::Unspent,
            },
        );
        Ok(())
    }

    /// Iterate through all unspent lrc20 outpoints of the user
    async fn stream_unspent_lrc20_outputs<'a>(
        &'a self,
    ) -> StorageStream<'a, (OutPoint, (ReceiptProof, TxOut))> {
        let storage = self.lock().await;

        Box::pin(stream::iter(
            storage
                .lrc20_outputs
                .iter()
                .filter(|(_, v)| v.state == Lrc20OutputState::Unspent)
                .map(|(k, v)| Ok((*k, (v.receipt_proof.clone(), v.txout.clone()))))
                .collect::<Vec<_>>(),
        ))
    }

    async fn set_lrc20_output_state(
        &self,
        outpoint: OutPoint,
        state: Lrc20OutputState,
    ) -> eyre::Result<()> {
        let mut outputs = self.lock().await;

        let Some(entry) = outputs.lrc20_outputs.get_mut(&outpoint) else {
            bail!("Outpoint not found");
        };

        entry.state = state;

        Ok(())
    }
}

/// Provider of simple key value parameters required for the application.
///
/// Here should be placed all parameters which won't required separate DB
/// instance.
#[async_trait]
impl KeyValueStorage for Arc<Mutex<InMemoryDB>> {
    /// Get the last indexed page number
    async fn last_indexed_page_number(&self) -> eyre::Result<u64> {
        Ok(self.lock().await.last_indexed_page_number)
    }

    /// Put the last indexed page number
    async fn put_last_indexed_page_number(&self, page_number: u64) -> eyre::Result<()> {
        self.lock().await.last_indexed_page_number = page_number;
        Ok(())
    }

    /// Get the unique identifier of the node to which the application
    /// previously synced.
    async fn connected_node_id(&self) -> eyre::Result<Option<String>> {
        Ok(self.lock().await.connected_node_id.clone())
    }

    /// Put the unique identifier of the node to which the application
    /// previously synced.
    async fn put_connected_node_id(&self, node_id: String) -> eyre::Result<()> {
        self.lock().await.connected_node_id = Some(node_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::WalletStorage;

    #[test]
    fn test_check_inmemory_implements_wallet_storage() {
        fn assert_impl<T: WalletStorage>() {}

        assert_impl::<SafeInMemoryDB>();
    }
}
