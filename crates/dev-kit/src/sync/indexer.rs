use std::sync::Arc;

use bdk::blockchain::{AnyBlockchain, GetHeight};
use bitcoin::{OutPoint, secp256k1::PublicKey};
use futures::TryStreamExt;
use hashbrown::HashSet;
use jsonrpsee::core::params::BatchRequestBuilder;
use lrc20_receipts::ReceiptProof;
use lrc20_receipts::TokenPubkey;
use lrc20_rpc_api::transactions::{Lrc20TransactionsRpcClient, Lrc20TransactionsRpcClientExt};
use lrc20_types::Lrc20Transaction;
use tracing::{debug, error, instrument};

use crate::database::WalletStorage;

/// Indexer of LRC20 transactions got from LRC20 node.
pub struct Lrc20TransactionsIndexer<Lrc20RpcClient, WalletStorage> {
    /// Fetcher of transactions to LRC20 node.
    node_client: Lrc20RpcClient,

    /// Bitcoin RPC Blockchain.
    blockchain: Arc<AnyBlockchain>,

    /// Storage for LRC20 transactions
    storage: WalletStorage,

    /// Public key of the user we are searching UTXOs
    pubkey: PublicKey,

    /// Node id to which we are syncing to.
    node_id: String,
}

impl<C, WS> Lrc20TransactionsIndexer<C, WS>
where
    C: Lrc20TransactionsRpcClient + Clone + Send + Sync + 'static,
    WS: WalletStorage,
{
    pub fn new(
        lrc20_client: C,
        blockchain: Arc<AnyBlockchain>,
        storage: WS,
        pubkey: PublicKey,
        node_id: String,
    ) -> Self {
        Self {
            node_client: lrc20_client,
            blockchain,
            storage,
            pubkey,
            node_id,
        }
    }

    #[instrument(skip_all)]
    pub async fn sync(self) -> eyre::Result<()> {
        let starting_page_number = self.starting_page_number().await?;
        debug!("Starting sync from page: {}", starting_page_number);

        let mut pages_stream = self
            .node_client
            .transaction_pages_stream(starting_page_number);

        while let Some((page_number, txs)) = pages_stream.try_next().await? {
            debug!("Processing page: {}", page_number);
            if txs.is_empty() {
                break;
            }

            for tx in txs {
                self.index_transaction(tx.into()).await?;
            }

            self.storage
                .put_last_indexed_page_number(page_number)
                .await?;
        }

        self.mark_frozen_outputs().await?;

        Ok(())
    }

    /// Return the page number from which the indexing should be started.
    ///
    /// Usually the value should be the last indexed page got from node, but
    /// as the order of transactions in pages between different LRC20 nodes varies,
    /// when `connected_node_id` changes from last sync, the indexer restarts from
    /// first one.
    async fn starting_page_number(&self) -> eyre::Result<u64> {
        let last_indexed_page_number = self
            .storage
            .last_indexed_page_number()
            .await?
            .saturating_sub(1);

        let last_connected_node_id = self
            .storage
            .connected_node_id()
            .await?
            .unwrap_or_else(|| self.node_id.clone());

        // if last stored value of `connected_node_id` changed:
        if last_connected_node_id != self.node_id {
            self.storage
                .put_connected_node_id(self.node_id.clone())
                .await?;
            return Ok(0); // start from the first one instead
        }

        Ok(last_indexed_page_number)
    }

    /// Go through all outputs of current transactions and add them
    /// as indexed, then go through all inputs and mark outputs as spend.
    #[instrument(skip_all, fields(txid = %tx.bitcoin_tx.txid()))]
    async fn index_transaction(&self, tx: Lrc20Transaction) -> eyre::Result<()> {
        let txid = tx.bitcoin_tx.txid();
        let outpoints = tx
            .bitcoin_tx
            .output
            .into_iter()
            .enumerate()
            .map(|(index, txout)| (OutPoint::new(txid, index as u32), txout))
            .collect::<Vec<_>>();

        // Skip announcement transactions that has no outputs
        let Some(output_proofs) = tx.tx_type.output_proofs() else {
            return Ok(());
        };

        for (outpoint, txout) in outpoints {
            let Some(output_proof) = output_proofs.get(&outpoint.vout) else {
                continue; // NOTE: This should never happen
            };

            if !output_proof.spender_keys().contains(&self.pubkey) {
                continue;
            }

            if let ReceiptProof::SparkExit(spark_proof) = output_proof {
                let locktime = spark_proof.script.locktime;
                let current_height = self.blockchain.get_height()?;

                if locktime > current_height {
                    continue;
                }
            }

            debug!("Adding output: {:?}", outpoint);
            self.storage
                .insert_unspent_lrc20_output(outpoint, output_proof.clone(), txout)
                .await?;
        }

        // We found input which spents one which we added previously.
        for input in &tx.bitcoin_tx.input {
            let op = input.previous_output;
            // skip outpoint if it's not in our storage.
            if self
                .storage
                .try_get_unspent_lrc20_output(op)
                .await?
                .is_none()
            {
                continue;
            }
            debug!("Marking as spent: {:?}", op);
            self.storage.mark_lrc20_output_as_spent(op).await?;
        }

        Ok(())
    }

    async fn mark_frozen_outputs(&self) -> eyre::Result<()> {
        let mut stream = self
            .storage
            .stream_unspent_lrc20_outputs()
            .await
            .try_chunks(40);

        let mut frozen_token_pubkeys = HashSet::new();
        let pubkey = self.pubkey;

        while let Some(outputs) = stream.try_next().await? {
            let outpoints = outputs.iter().map(|output| output.0).collect::<Vec<_>>();
            let token_pubkeys = outputs
                .iter()
                .map(|output| output.1.0.receipt().token_pubkey)
                .collect::<Vec<_>>();
            let unique_token_pubkeys = token_pubkeys.iter().cloned().collect::<HashSet<_>>();

            for token_pubkey in unique_token_pubkeys {
                if !frozen_token_pubkeys.contains(&token_pubkey) {
                    let is_frozen = self
                        .send_is_pubkey_frozen_request(&pubkey, &token_pubkey)
                        .await?;
                    if is_frozen {
                        frozen_token_pubkeys.insert(token_pubkey);
                    }
                }
            }

            let are_outpoints_frozen = self
                .send_is_outpoints_frozen_batch_request(&outpoints)
                .await?;

            // Ordering of requests and responses should be same:
            let frozen_outpoints = outpoints
                .into_iter()
                .enumerate()
                .filter(|(i, _)| {
                    are_outpoints_frozen[*i] || frozen_token_pubkeys.contains(&token_pubkeys[*i])
                })
                .map(|(_, op)| op)
                .collect::<Vec<_>>();

            for outpoint in frozen_outpoints {
                self.storage.mark_lrc20_output_as_frozen(outpoint).await?;
            }
        }
        Ok(())
    }

    async fn send_is_outpoints_frozen_batch_request(
        &self,
        outpoints: &[OutPoint],
    ) -> Result<Vec<bool>, eyre::Error> {
        let mut req = BatchRequestBuilder::new();

        for outpoint in outpoints {
            req.insert("islrc20txoutfrozen", (outpoint.txid, outpoint.vout))?;
        }

        let response = self.node_client.batch_request::<bool>(req).await?;

        let is_outpoints_frozen = response
            .into_ok()
            .map_err(|errors| {
                let errors = errors.collect::<Vec<_>>();
                error!("Some of requests in batch failed: {errors:?}");

                eyre::eyre!(
                    "Failed to send batch request about frozen txs. Maybe server is unavaliable?"
                )
            })?
            .collect::<Vec<_>>();

        Ok(is_outpoints_frozen)
    }

    async fn send_is_pubkey_frozen_request(
        &self,
        pubkey: &PublicKey,
        token_pubkey: &TokenPubkey,
    ) -> Result<bool, eyre::Error> {
        let mut req = BatchRequestBuilder::new();

        req.insert("ispubkeyfrozen", (pubkey, token_pubkey))?;

        let response = self.node_client.batch_request::<bool>(req).await?;

        let is_pubkey_frozen = response
            .into_ok()
            .map_err(|errors| {
                let errors = errors.collect::<Vec<_>>();
                error!("Some of requests in batch failed: {errors:?}");

                eyre::eyre!(
                    "Failed to send batch request about frozen txs. Maybe server is unavaliable?"
                )
            })?
            .collect::<Vec<_>>();

        Ok(is_pubkey_frozen[0])
    }
}
