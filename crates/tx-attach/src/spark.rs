use event_bus::{EventBus, typeid};
use eyre::WrapErr;
use std::collections::{HashMap, HashSet};
use std::default::Default;
use std::time::{Duration, SystemTime};
use tokio_util::sync::CancellationToken;
use tracing::error;

use lrc20_storage::PgDatabaseConnectionManager;
use lrc20_storage::traits::SparkNodeStorage;
use lrc20_types::ControllerMessage;
use lrc20_types::messages::SparkGraphBuilderMessage;
use lrc20_types::spark::spark_hash::SparkHash;
use lrc20_types::spark::{TokenLeafToSpend, TokenTransaction};

/// Service which handles attaching of transactions to the graph.
///
/// Accepts batches of checked transactions, and attaches
/// history of transactions, and if all dependencies (parents) are attached,
/// then marks transaction as attached, and stores it in [`SparkTransactionsStorage`].
pub struct SparkGraphBuilder<NodeStorage> {
    /// Storage of transactions, where attached transactions are stored.
    //tx_storage: SparkTransactionStorage,
    tx_storage: NodeStorage,

    /// Event bus for simplifying communication with services.
    event_bus: EventBus,

    /// Map of inverse dependencies between transactions. Key is a transaction
    /// id, and value is transactions that depend on this transaction.
    inverse_deps: HashMap<SparkHash, HashSet<SparkHash>>,

    /// Map of dependencies between transactions. Key is a transaction id, and
    /// value is transactions that this transaction depends on.
    deps: HashMap<SparkHash, HashSet<SparkHash>>,

    /// Stored txs that are not verified yet, with point in time in which
    /// transaction was stored.
    stored_txs: HashMap<SparkHash, (TokenTransaction, SystemTime)>,

    /// Period of time after which [`Self`] will cleanup transactions
    /// that are _too old_.
    cleanup_period: Duration,

    /// Period of time, after which we consider transaction _too old_
    /// or _outdated_.
    tx_outdated_duration: Duration,
}

impl<STS> SparkGraphBuilder<STS>
where
    STS: PgDatabaseConnectionManager + SparkNodeStorage + Send + Sync + 'static,
{
    pub fn new(
        tx_storage: STS,
        full_event_bus: &EventBus,
        cleanup_period: Duration,
        tx_outdated_duration: Duration,
    ) -> Self {
        let event_bus = full_event_bus
            .extract(
                &typeid![ControllerMessage],
                &typeid![SparkGraphBuilderMessage],
            )
            .expect("event channels must be presented");

        Self {
            tx_storage,
            event_bus,
            inverse_deps: Default::default(),
            deps: Default::default(),
            stored_txs: Default::default(),
            cleanup_period,
            tx_outdated_duration,
        }
    }

    /// Starts attach incoming [`transactions`](TokenTransaction).
    pub async fn run(mut self, cancellation: CancellationToken) {
        let events = self.event_bus.subscribe::<SparkGraphBuilderMessage>();
        let mut timer = tokio::time::interval(self.cleanup_period);

        loop {
            tokio::select! {
                event = events.recv() => {
                    let Ok(event) = event else {
                        tracing::trace!("Channel for incoming events is dropped, stopping...");
                        return;
                    };

                    if let Err(err) = self.handle_event(event).await {
                        error!("Failed to handle event: {:?}", err);
                    }
                },
                _ = cancellation.cancelled() => {
                    tracing::trace!("Cancellation received, stopping graph builder");
                    return;
                },
                _ = timer.tick() => {
                    if let Err(err) = self.handle_cleanup().await {
                        tracing::error!("Failed to do cleanup: {:?}", err);
                    }
                }
            }
        }
    }

    /// Handles incoming [`events`](SparkGraphBuilderMessage).
    async fn handle_event(&mut self, event: SparkGraphBuilderMessage) -> eyre::Result<()> {
        match event {
            SparkGraphBuilderMessage::CheckedTxs(txs) => self
                .attach_txs(&txs)
                .await
                .wrap_err("failed to attach transactions")?,
        }

        Ok(())
    }

    /// Clean up transactions that are _outdated_ and all transactions that are related to them.
    async fn handle_cleanup(&mut self) -> eyre::Result<()> {
        let now = SystemTime::now();

        let mut outdated_txs = Vec::new();

        for (txid, (_, created_at)) in self.stored_txs.iter() {
            let since_created_at = now
                .duration_since(*created_at)
                .wrap_err("failed to calculate duration since")?;

            if since_created_at > self.tx_outdated_duration {
                outdated_txs.push(*txid);
            }
        }

        for txid in outdated_txs {
            tracing::debug!("Tx {} is outdated", txid.to_string());
            self.remove_tx(txid).await?;
        }

        Ok(())
    }

    /// Remove transaction from storage and all transactions that are related to it.
    async fn remove_tx(&mut self, txid: SparkHash) -> eyre::Result<()> {
        let mut txs_to_remove = vec![txid];

        let mut removed_txs_set = HashSet::<SparkHash>::new();
        removed_txs_set.insert(txid);

        while !txs_to_remove.is_empty() {
            let txid = txs_to_remove.remove(0);

            self.stored_txs.remove(&txid);
            self.remove_tx_from_deps(txid).await?;

            let Some(inverse_deps) = self.inverse_deps.remove(&txid) else {
                continue;
            };

            for inv_dep in inverse_deps {
                if !removed_txs_set.contains(&inv_dep) {
                    txs_to_remove.push(inv_dep);
                    removed_txs_set.insert(inv_dep);
                }
            }
        }

        Ok(())
    }

    /// Remove tx from all inverse deps. If there is no inverse deps left, then remove it.
    async fn remove_tx_from_deps(&mut self, txid: SparkHash) -> eyre::Result<()> {
        let mut txs_to_remove = Vec::from([txid]);
        let deps = self.deps.remove(&txid).unwrap_or_default();

        for dep in deps {
            let Some(inverse_deps) = self.inverse_deps.get_mut(&dep) else {
                continue;
            };

            inverse_deps.remove(&txid);
            txs_to_remove.push(dep);

            if inverse_deps.is_empty() {
                self.inverse_deps.remove(&dep);
            }
        }

        Ok(())
    }

    /// Accepts part of the graph of transactions, and attaches them if can.
    ///
    /// If transaction can't be attached, because lack of info (no parent txs),
    /// [`SparkGraphBuilder`] stores them in temporary storage, and waits for them
    /// in next calls of this method.
    ///
    /// If transaction can be attached, then it is stored in [`SparkTransactionsStorage`].
    pub async fn attach_txs(&mut self, checked_txs: &[TokenTransaction]) -> eyre::Result<()> {
        let mut queued_txs: HashSet<SparkHash> = HashSet::new();
        let mut attached_txs: Vec<TokenTransaction> = Vec::new();

        for spark_tx in checked_txs {
            let token_tx = spark_tx.clone();
            let child = spark_tx.clone();
            let child_id = token_tx.hash();

            match &token_tx.input {
                lrc20_types::spark::TokenTransactionInput::Mint { .. } => {
                    attached_txs.push(child);

                    let Some(ids) = self.inverse_deps.remove(&child_id) else {
                        continue;
                    };

                    // Add to queue for next iteration of graph builder.
                    queued_txs.extend(ids);
                }
                lrc20_types::spark::TokenTransactionInput::Transfer {
                    outputs_to_spend: leaves_to_spend,
                } => {
                    self.handle_transfer(
                        spark_tx,
                        leaves_to_spend.to_vec(),
                        child_id,
                        &mut queued_txs,
                        &mut attached_txs,
                    )
                    .await
                    .wrap_err("Failed handling of transfer")?;
                }
            }
        }

        // Attach transactions until there is nothing to do:
        let mut attached_txids: Vec<SparkHash> = attached_txs.iter().map(SparkHash::from).collect();
        while !queued_txs.is_empty() {
            let mut local_queue = HashSet::new();

            for txid in queued_txs {
                // Find deps of current node that are attached:
                let is_empty = self.remove_attached_parents(txid, &attached_txids).await?;

                // If we still dependent on some transactions, then we can't attach this tx.
                if !is_empty {
                    continue;
                }

                // Remove from locally stored txs, and deps:
                let Some((tx, _)) = self.stored_txs.remove(&txid) else {
                    debug_assert!(
                        false,
                        "All parents are attached, but no tx found for {}",
                        *txid
                    );
                    continue;
                };
                self.deps.remove(&txid);

                // Add tx to attached storage:
                attached_txs.push(tx);
                attached_txids.push(txid);

                // Add transactions that depends on this transaction to the queue,
                // so we can remove their deps on next iteration:
                let Some(inv_deps) = self.inverse_deps.remove(&txid) else {
                    continue;
                };

                local_queue.extend(inv_deps);
            }

            queued_txs = local_queue;
        }

        self.handle_fully_attached_txs(attached_txs).await?;

        Ok(())
    }

    /// Handle fully validated transactions, add them to pagination storage and
    /// send event about verified transactions to message handler.
    async fn handle_fully_attached_txs(
        &mut self,
        attached_txs: Vec<TokenTransaction>,
    ) -> eyre::Result<()> {
        if attached_txs.is_empty() {
            return Ok(());
        }

        self.event_bus
            .send(ControllerMessage::AttachedSparkTxs(attached_txs))
            .await;

        Ok(())
    }

    /// Removes attached parents from dependencies of the transaction, returns
    /// `true` if there is no deps left.
    async fn remove_attached_parents(
        &mut self,
        txid: SparkHash,
        attached_txs: &[SparkHash],
    ) -> eyre::Result<bool> {
        let Some(txids) = self.deps.get_mut(&txid) else {
            return Ok(true);
        };

        let mut ids_to_remove = Vec::new();

        // TODO(Velnbur): this could be done in batch with array of futures, but
        // it's not critical for now.
        for txid in txids.iter() {
            let is_attached = attached_txs.contains(txid)
                || self
                    .tx_storage
                    .get_spark_transaction_model_by_hash(*txid)
                    .await?
                    .is_some();

            if is_attached {
                ids_to_remove.push(*txid);
            }
        }

        for id in ids_to_remove {
            txids.remove(&id);
        }

        Ok(txids.is_empty())
    }

    /// Handle transfer transactions by it's elements (inputs and outputs) to
    /// plain, and inverse dependencies between them.
    ///
    /// If parent of the current tx is attached, skip adding to deps, if all
    /// are attached, then attach current transaction too.
    async fn handle_transfer(
        &mut self,
        spark_tx: &TokenTransaction,
        leaves_to_spend: Vec<TokenLeafToSpend>,
        child_id: SparkHash,
        queued_txs: &mut HashSet<SparkHash>,
        attached_txs: &mut Vec<TokenTransaction>,
    ) -> eyre::Result<()> {
        let attached_txids: HashMap<SparkHash, TokenTransaction> = attached_txs
            .iter_mut()
            .map(|tx| (tx.hash(), tx.to_owned()))
            .collect();
        for leaf_to_spend in leaves_to_spend {
            let parent_id = leaf_to_spend.parent_output_hash.into();
            let is_attached = attached_txids.contains_key(&parent_id)
                || self
                    .tx_storage
                    .get_spark_transaction_model_by_hash(parent_id)
                    .await?
                    .is_some();

            if !is_attached {
                // If there is no parent transaction in the storage, then
                // we need to find it in checked txs or wait for it (add to storage).
                self.inverse_deps
                    .entry(parent_id)
                    .or_default()
                    .insert(child_id);

                self.deps.entry(child_id).or_default().insert(parent_id);
            }
        }

        // May be, we already removed all deps that are attached, so we can check if we can add child
        let all_parents_attached = self.deps.entry(child_id).or_default().is_empty();

        if all_parents_attached {
            // If all parents are attached, then we can attach this transaction.
            attached_txs.push(spark_tx.clone());

            self.deps.remove(&child_id);

            let Some(ids) = self.inverse_deps.remove(&child_id) else {
                // no reason to add to queue, as there is no deps.
                return Ok(());
            };

            // Add to queue for next iteration of graph builder.
            queued_txs.extend(ids);

            return Ok(());
        }

        // If not all parents are attached, then we need to wait for them.
        self.stored_txs
            .insert(child_id, (spark_tx.clone(), SystemTime::now()));

        Ok(())
    }
}
