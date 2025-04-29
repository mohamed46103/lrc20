#![doc = include_str!("../README.md")]

mod spark;

use std::collections::{HashMap, HashSet};
use std::default::Default;
use std::time::{Duration, SystemTime};

use bitcoin::Txid;
use event_bus::{EventBus, typeid};
use eyre::WrapErr;
use lrc20_storage::traits::Lrc20NodeStorage;
use tokio_util::sync::CancellationToken;
use tracing::error;

use lrc20_storage::PgDatabaseConnectionManager;

use lrc20_types::{
    ControllerMessage, GraphBuilderMessage, Lrc20Transaction, Lrc20TxType, ProofMap,
};

pub use spark::SparkGraphBuilder;

/// Service which handles attaching of transactions to the graph.
///
/// Accepts batches of checked transactions, and attaches
/// history of transactions, and if all dependencies (parents) are attached,
/// then marks transaction as attached, and stores it in [`TransactionsStorage`].
pub struct GraphBuilder<NodeStorage> {
    /// Persistent storage,
    node_storage: NodeStorage,

    /// Event bus for simplifying communication with services.
    event_bus: EventBus,

    /// Map of inverse dependencies between transactions. Key is a transaction
    /// id, and value is transactions that depend on this transaction.
    inverse_deps: HashMap<Txid, HashSet<Txid>>,

    /// Map of dependencies between transactions. Key is a transaction id, and
    /// value is transactions that this transaction depends on.
    deps: HashMap<Txid, HashSet<Txid>>,

    /// Stored txs that are not verified yet, with point in time in which
    /// transaction was stored.
    stored_txs: HashMap<Txid, (Lrc20Transaction, SystemTime)>,

    /// Period of time after which [`Self`] will cleanup transactions
    /// that are _too old_.
    cleanup_period: Duration,

    /// Period of time, after which we consider transaction _too old_
    /// or _outdated_.
    tx_outdated_duration: Duration,
}

impl<NS> GraphBuilder<NS>
where
    NS: PgDatabaseConnectionManager + Lrc20NodeStorage + Send + Sync + 'static,
{
    pub fn new(
        node_storage: NS,
        full_event_bus: &EventBus,
        cleanup_period: Duration,
        tx_outdated_duration: Duration,
    ) -> Self {
        let event_bus = full_event_bus
            .extract(&typeid![ControllerMessage], &typeid![GraphBuilderMessage])
            .expect("event channels must be presented");

        Self {
            node_storage,
            event_bus,
            inverse_deps: Default::default(),
            deps: Default::default(),
            stored_txs: Default::default(),
            cleanup_period,
            tx_outdated_duration,
        }
    }

    /// Starts attach incoming [`transactions`](Lrc20Transaction).
    pub async fn run(mut self, cancellation: CancellationToken) {
        let events = self.event_bus.subscribe::<GraphBuilderMessage>();
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

    /// Handles incoming [`events`](GraphBuilderMessage).
    async fn handle_event(&mut self, event: GraphBuilderMessage) -> eyre::Result<()> {
        match event {
            GraphBuilderMessage::CheckedTxs(txs) => self
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
            tracing::debug!("Tx {} is outdated", txid);
            self.remove_outdated_tx(txid).await?;
        }

        Ok(())
    }

    /// Remove outdated transaction from storage and all transactions that are related to it.
    async fn remove_outdated_tx(&mut self, txid: Txid) -> eyre::Result<()> {
        let mut txs_to_remove = vec![txid];

        let mut removed_txs_set = HashSet::<Txid>::new();
        removed_txs_set.insert(txid);

        while !txs_to_remove.is_empty() {
            let txid = txs_to_remove.remove(0);

            self.stored_txs.remove(&txid);
            self.remove_tx_from_deps(&txid).await?;

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
    async fn remove_tx_from_deps(&mut self, txid: &Txid) -> eyre::Result<()> {
        let mut txs_to_remove = Vec::from([*txid]);
        let deps = self.deps.remove(txid).unwrap_or_default();

        for dep in deps {
            let Some(inverse_deps) = self.inverse_deps.get_mut(&dep) else {
                continue;
            };

            inverse_deps.remove(txid);
            txs_to_remove.push(dep);

            if inverse_deps.is_empty() {
                self.inverse_deps.remove(&dep);
            }
        }

        self.remove_outdated_txs_from_mempool(txs_to_remove).await?;

        Ok(())
    }

    /// Removes outdates transactions.
    async fn remove_outdated_txs_from_mempool(&mut self, txids: Vec<Txid>) -> eyre::Result<()> {
        self.node_storage
            .delete_list_lrc20_transactions(txids)
            .await?;

        Ok(())
    }

    /// Accepts part of the graph of transactions, and attaches them if can.
    ///
    /// If transaction can't be attached, because lack of info (no parent txs),
    /// [`GraphBuilder`] stores them in temporary storage, and waits for them
    /// in next calls of this method.
    ///
    /// If transaction can be attached, then it is stored in [`TransactionsStorage`].
    pub async fn attach_txs(&mut self, checked_txs: &[Lrc20Transaction]) -> eyre::Result<()> {
        let mut queued_txs = HashSet::new();
        let mut attached_txs = Vec::new();

        for lrc20_tx in checked_txs {
            let child_id = lrc20_tx.bitcoin_tx.txid();

            match &lrc20_tx.tx_type {
                // if issuance is attached, there is no reason to wait for it's parents.
                Lrc20TxType::Issue { .. } => {
                    attached_txs.push(lrc20_tx.bitcoin_tx.txid());

                    let Some(ids) = self.inverse_deps.remove(&child_id) else {
                        continue;
                    };

                    // Add to queue for next iteration of graph builder.
                    queued_txs.extend(ids);
                }
                Lrc20TxType::Transfer { input_proofs, .. } => {
                    self.handle_transfer(
                        input_proofs,
                        lrc20_tx,
                        child_id,
                        &mut queued_txs,
                        &mut attached_txs,
                    )
                    .await
                    .wrap_err("Failed handling of transfer")?;
                }
                // Skip storing inv for announcement transactions (as they are not broadcasted via P2P).
                Lrc20TxType::Announcement { .. } => {}
                Lrc20TxType::SparkExit { output_proofs } => {
                    self.handle_spark_exit(
                        output_proofs,
                        lrc20_tx,
                        child_id,
                        &mut queued_txs,
                        &mut attached_txs,
                    )
                    .await
                    .wrap_err("Failed handling of spark exit")?;
                }
            }
        }

        // Attach transactions until there is nothing to do:
        while !queued_txs.is_empty() {
            let mut local_queue = HashSet::new();

            for txid in queued_txs {
                // Find deps of current node that are attached:
                let is_empty = self.remove_attached_parents(txid, &attached_txs).await?;

                // If we still dependent on some transactions, then we can't attach this tx.
                if !is_empty {
                    continue;
                }

                // Remove from locally stored txs, and deps:
                let Some((tx, _)) = self.stored_txs.remove(&txid) else {
                    debug_assert!(
                        false,
                        "All parents are attached, but no tx found for {}",
                        txid
                    );
                    continue;
                };
                self.deps.remove(&txid);

                // Add tx to attached storage:
                attached_txs.push(tx.bitcoin_tx.txid());

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
    async fn handle_fully_attached_txs(&mut self, attached_txs: Vec<Txid>) -> eyre::Result<()> {
        if attached_txs.is_empty() {
            return Ok(());
        }

        self.event_bus
            .send(ControllerMessage::AttachedTxs(attached_txs))
            .await;

        Ok(())
    }

    /// Removes attached parents from dependencies of the transaction, returns
    /// `true` if there is no deps left.
    async fn remove_attached_parents(
        &mut self,
        txid: Txid,
        attached_txs: &[Txid],
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
                    .node_storage
                    .get_lrc20_transaction_by_id(*txid)
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
        input_proofs: &ProofMap,
        lrc20_tx: &Lrc20Transaction,
        child_id: Txid,
        queued_txs: &mut HashSet<Txid>,
        attached_txs: &mut Vec<Txid>,
    ) -> eyre::Result<()> {
        for (vout, proof) in input_proofs {
            // We skip it to the next input since it is not necessary to have a parent for
            // an empty receipt proof.
            if proof.is_empty_receiptproof() {
                continue;
            }

            let Some(parent) = lrc20_tx.bitcoin_tx.input.get(*vout as usize) else {
                debug_assert!(false, "Output proof index is out of bounds");
                continue;
            };

            let parent_txid = parent.previous_output.txid;

            let is_attached = attached_txs.contains(&parent_txid)
                || self
                    .node_storage
                    .get_lrc20_transaction_by_id(parent_txid)
                    .await?
                    .is_some();

            if !is_attached {
                // If there is no parent transaction in the storage, then
                // we need to find it in checked txs or wait for it (add to storage).
                self.inverse_deps
                    .entry(parent_txid)
                    .or_default()
                    .insert(child_id);

                self.deps.entry(child_id).or_default().insert(parent_txid);
            }
        }

        // May be, we already removed all deps that are attached, so we can check if we can add child
        let all_parents_attached = self.deps.entry(child_id).or_default().is_empty();

        if all_parents_attached {
            // If all parents are attached, then we can attach this transaction.
            attached_txs.push(lrc20_tx.bitcoin_tx.txid());

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
            .insert(child_id, (lrc20_tx.clone(), SystemTime::now()));

        Ok(())
    }

    async fn handle_spark_exit(
        &mut self,
        _output_proofs: &ProofMap,
        lrc20_tx: &Lrc20Transaction,
        _child_id: Txid,
        _queued_txs: &mut HashSet<Txid>,
        attached_txs: &mut Vec<Txid>,
    ) -> eyre::Result<()> {
        // TODO: wait for token transactions
        attached_txs.push(lrc20_tx.bitcoin_tx.txid());

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, str::FromStr};

    use bitcoin::{
        PrivateKey, PublicKey, Sequence, Transaction, Witness,
        blockdata::locktime::absolute::LockTime, secp256k1::Secp256k1, transaction::Version,
    };
    use lrc20_controller::Controller;
    use lrc20_p2p::client::handle::MockHandle;
    use lrc20_receipts::{Receipt, ReceiptProof, SigReceiptProof};
    use lrc20_storage::{PgDatabase, traits::MempoolNodeStorage};
    use lrc20_types::{IndexerMessage, TxCheckerMessage, TxConfirmMessage};
    use once_cell::sync::Lazy;
    use serde_json::json;

    use super::*;

    static DUMMY_RECEIPT_PROOF: Lazy<ReceiptProof> = Lazy::new(|| {
        let seckey = PrivateKey::from_str("L43rfkoMRAznnzbFfCXUauvVEqigmkMYxrRPEy91arnofHEUnGiP")
            .expect("Should be valid");

        let key = PublicKey::from_private_key(&Secp256k1::new(), &seckey);

        let metadata = json!({
            "type": "SparkDeposit",
            "deposit_pubkey": "035dbc016089977223ebc5db0398ce0988e44645e4a16e5129601e1f09cc9751fa"
        });

        ReceiptProof::Sig(SigReceiptProof::new(
            Receipt::new(10, key),
            key.inner,
            Some(metadata),
        ))
    });

    const DATABASE_URL: &str = "http://localhost:18443";

    // FIXME: ignore until postgres mock implemented
    #[ignore]
    #[tokio::test]
    async fn test_example_from_doc() {
        let lrc20_node_storage = PgDatabase::new(DATABASE_URL, false, None, None, None)
            .await
            .unwrap();

        let mut event_bus = EventBus::default();
        // Register all the messages for the controller to work
        event_bus.register::<TxCheckerMessage>(Some(100));
        event_bus.register::<GraphBuilderMessage>(Some(100));
        event_bus.register::<ControllerMessage>(Some(100));
        event_bus.register::<TxConfirmMessage>(Some(100));
        event_bus.register::<IndexerMessage>(Some(100));

        let mut mocked_p2p = MockHandle::new();
        // Just expect all messages to be sent successfully
        mocked_p2p.expect_send_inv().times(..).returning(|_| Ok(()));
        mocked_p2p
            .expect_send_get_data()
            .times(..)
            .returning(|_, _| Ok(()));
        mocked_p2p.expect_ban_peer().times(..).returning(|_| Ok(()));
        let mut controller = Controller::new(&event_bus, lrc20_node_storage.clone(), mocked_p2p);

        let mut graph_builder = GraphBuilder::new(
            lrc20_node_storage.clone(),
            &event_bus,
            Duration::from_secs(5),
            Duration::from_secs(10),
        );

        let tx1 = Lrc20Transaction {
            bitcoin_tx: Transaction {
                version: Version::ONE,
                lock_time: LockTime::from_height(1).expect("failed to create lock time"),
                input: vec![],
                output: vec![],
            },

            tx_type: Lrc20TxType::default(),
        };
        dbg!(tx1.bitcoin_tx.txid());

        let tx2 = Lrc20Transaction {
            bitcoin_tx: Transaction {
                version: Version::ONE,
                lock_time: LockTime::from_height(2).expect("failed to create lock time"),
                input: vec![],
                output: vec![],
            },

            tx_type: Lrc20TxType::default(),
        };
        dbg!(tx2.bitcoin_tx.txid());

        let tx6 = Lrc20Transaction {
            bitcoin_tx: Transaction {
                version: Version::ONE,
                lock_time: LockTime::from_height(3).expect("failed to create lock time"),
                input: vec![],
                output: vec![],
            },

            tx_type: Lrc20TxType::default(),
        };
        dbg!(tx6.bitcoin_tx.txid());

        lrc20_node_storage
            .insert_lrc20_transaction(tx1.clone())
            .await
            .unwrap();
        lrc20_node_storage
            .insert_lrc20_transaction(tx2.clone())
            .await
            .unwrap();
        lrc20_node_storage
            .insert_lrc20_transaction(tx6.clone())
            .await
            .unwrap();

        let tx3 = Lrc20Transaction {
            bitcoin_tx: Transaction {
                version: Version::ONE,
                lock_time: LockTime::from_height(4).expect("failed to create lock time"),
                input: vec![
                    bitcoin::TxIn {
                        previous_output: bitcoin::OutPoint::new(tx1.bitcoin_tx.txid(), 0),
                        script_sig: bitcoin::ScriptBuf::default(),
                        sequence: Sequence(0),
                        witness: Witness::default(),
                    },
                    bitcoin::TxIn {
                        previous_output: bitcoin::OutPoint::new(tx2.bitcoin_tx.txid(), 0),
                        script_sig: bitcoin::ScriptBuf::default(),
                        sequence: Sequence(0),
                        witness: Witness::default(),
                    },
                ],
                output: vec![],
            },

            tx_type: Lrc20TxType::Transfer {
                input_proofs: {
                    let mut map = BTreeMap::new();

                    map.insert(0, DUMMY_RECEIPT_PROOF.clone());
                    map.insert(1, DUMMY_RECEIPT_PROOF.clone());

                    map
                },
                output_proofs: Default::default(),
            },
        };
        dbg!(tx3.bitcoin_tx.txid());

        let tx7 = Lrc20Transaction {
            bitcoin_tx: Transaction {
                version: Version::ONE,
                lock_time: LockTime::from_height(5).expect("failed to create lock time"),
                input: vec![],
                output: vec![],
            },

            tx_type: Lrc20TxType::default(),
        };
        dbg!(tx7.bitcoin_tx.txid());

        let tx4 = Lrc20Transaction {
            bitcoin_tx: Transaction {
                version: Version::ONE,
                lock_time: LockTime::from_height(6).expect("failed to create lock time"),
                input: vec![
                    bitcoin::TxIn {
                        previous_output: bitcoin::OutPoint::new(tx3.bitcoin_tx.txid(), 0),
                        script_sig: bitcoin::ScriptBuf::default(),
                        sequence: Sequence(0),
                        witness: Witness::default(),
                    },
                    bitcoin::TxIn {
                        previous_output: bitcoin::OutPoint::new(tx7.bitcoin_tx.txid(), 0),
                        script_sig: bitcoin::ScriptBuf::default(),
                        sequence: Sequence(0),
                        witness: Witness::default(),
                    },
                    bitcoin::TxIn {
                        previous_output: bitcoin::OutPoint::new(tx6.bitcoin_tx.txid(), 0),
                        script_sig: bitcoin::ScriptBuf::default(),
                        sequence: Sequence(0),
                        witness: Witness::default(),
                    },
                ],
                output: vec![],
            },

            tx_type: Lrc20TxType::Transfer {
                input_proofs: {
                    let mut map = BTreeMap::new();

                    map.insert(0, DUMMY_RECEIPT_PROOF.clone());
                    map.insert(1, DUMMY_RECEIPT_PROOF.clone());
                    map.insert(2, DUMMY_RECEIPT_PROOF.clone());

                    map
                },
                output_proofs: Default::default(),
            },
        };
        dbg!(tx4.bitcoin_tx.txid());

        let tx5 = Lrc20Transaction {
            bitcoin_tx: Transaction {
                version: Version::ONE,
                lock_time: LockTime::from_height(7).expect("failed to create lock time"),
                input: vec![bitcoin::TxIn {
                    previous_output: bitcoin::OutPoint::new(tx4.bitcoin_tx.txid(), 0),
                    script_sig: bitcoin::ScriptBuf::default(),
                    sequence: Sequence(0),
                    witness: Witness::default(),
                }],
                output: vec![],
            },

            tx_type: Lrc20TxType::Transfer {
                input_proofs: {
                    let mut map = BTreeMap::new();

                    map.insert(0, DUMMY_RECEIPT_PROOF.clone());

                    map
                },
                output_proofs: Default::default(),
            },
        };
        dbg!(tx5.bitcoin_tx.txid());

        let txs = vec![tx5.clone(), tx4.clone(), tx3.clone(), tx7.clone()];

        graph_builder.attach_txs(&txs).await.unwrap();

        for tx in &txs {
            lrc20_node_storage
                .put_mempool_transaction(tx.bitcoin_tx.txid(), None)
                .await
                .unwrap();
        }

        let events = event_bus.subscribe::<ControllerMessage>();
        tokio::select! {
            event = events.recv() => {
                let ControllerMessage::AttachedTxs(attached_txs) = event.unwrap() else {
                    panic!("Message should be present");
                };
                controller.handle_attached_txs(attached_txs).await.unwrap();
            }
            _ = tokio::time::sleep(Duration::from_secs(1)) => {
                panic!("No attached txs arrived");
            }
        }

        for tx in &txs {
            let got_tx = lrc20_node_storage
                .get_lrc20_transaction_by_id(tx.bitcoin_tx.txid())
                .await
                .unwrap();

            assert_eq!(
                got_tx,
                Some(tx.clone()),
                "Transaction {} must be attached",
                tx.bitcoin_tx.txid()
            );
        }

        assert!(
            graph_builder.deps.is_empty(),
            "Deps must be empty: {:?}",
            graph_builder.deps
        );
        assert!(
            graph_builder.inverse_deps.is_empty(),
            "Inverse deps must be empty: {:?}",
            graph_builder.inverse_deps
        );
        assert!(graph_builder.stored_txs.is_empty());
    }

    #[tokio::test]
    #[ignore]
    async fn test_cleanup() -> eyre::Result<()> {
        let lrc20_node_storage = PgDatabase::new(DATABASE_URL, false, None, None, None)
            .await
            .unwrap();

        let mut event_bus = EventBus::default();
        event_bus.register::<GraphBuilderMessage>(Some(100));
        event_bus.register::<ControllerMessage>(Some(100));

        let mut graph_builder = GraphBuilder::new(
            lrc20_node_storage,
            &event_bus,
            Duration::from_secs(0),
            Duration::from_secs(0),
        );

        let tx1 = Lrc20Transaction {
            bitcoin_tx: Transaction {
                version: Version::ONE,
                lock_time: LockTime::from_height(0).expect("failed to create lock time"),
                input: vec![],
                output: vec![],
            },

            tx_type: Lrc20TxType::default(),
        };
        dbg!(tx1.bitcoin_tx.txid());

        let tx2 = Lrc20Transaction {
            bitcoin_tx: Transaction {
                version: Version::ONE,
                lock_time: LockTime::from_height(1).expect("failed to create lock time"),
                input: vec![],
                output: vec![],
            },

            tx_type: Lrc20TxType::default(),
        };
        dbg!(tx2.bitcoin_tx.txid());

        let tx6 = Lrc20Transaction {
            bitcoin_tx: Transaction {
                version: Version::ONE,
                lock_time: LockTime::from_height(2).expect("failed to create lock time"),
                input: vec![],
                output: vec![],
            },

            tx_type: Lrc20TxType::default(),
        };
        dbg!(tx6.bitcoin_tx.txid());

        let tx3 = Lrc20Transaction {
            bitcoin_tx: Transaction {
                version: Version::ONE,
                lock_time: LockTime::from_height(3).expect("failed to create lock time"),
                input: vec![
                    bitcoin::TxIn {
                        previous_output: bitcoin::OutPoint::new(tx1.bitcoin_tx.txid(), 0),
                        script_sig: bitcoin::ScriptBuf::default(),
                        sequence: Sequence(0),
                        witness: Witness::default(),
                    },
                    bitcoin::TxIn {
                        previous_output: bitcoin::OutPoint::new(tx2.bitcoin_tx.txid(), 0),
                        script_sig: bitcoin::ScriptBuf::default(),
                        sequence: Sequence(0),
                        witness: Witness::default(),
                    },
                ],
                output: vec![],
            },

            tx_type: Lrc20TxType::Transfer {
                input_proofs: {
                    let mut map = BTreeMap::new();

                    map.insert(0, DUMMY_RECEIPT_PROOF.clone());
                    map.insert(1, DUMMY_RECEIPT_PROOF.clone());

                    map
                },
                output_proofs: Default::default(),
            },
        };
        dbg!(tx3.bitcoin_tx.txid());

        let tx7 = Lrc20Transaction {
            bitcoin_tx: Transaction {
                version: Version::ONE,
                lock_time: LockTime::from_height(4).expect("failed to create lock time"),
                input: vec![],
                output: vec![],
            },

            tx_type: Lrc20TxType::default(),
        };
        dbg!(tx7.bitcoin_tx.txid());

        let tx4 = Lrc20Transaction {
            bitcoin_tx: Transaction {
                version: Version::ONE,
                lock_time: LockTime::from_height(5).expect("failed to create lock time"),
                input: vec![
                    bitcoin::TxIn {
                        previous_output: bitcoin::OutPoint::new(tx3.bitcoin_tx.txid(), 0),
                        script_sig: bitcoin::ScriptBuf::default(),
                        sequence: Sequence(0),
                        witness: Witness::default(),
                    },
                    bitcoin::TxIn {
                        previous_output: bitcoin::OutPoint::new(tx7.bitcoin_tx.txid(), 0),
                        script_sig: bitcoin::ScriptBuf::default(),
                        sequence: Sequence(0),
                        witness: Witness::default(),
                    },
                    bitcoin::TxIn {
                        previous_output: bitcoin::OutPoint::new(tx6.bitcoin_tx.txid(), 0),
                        script_sig: bitcoin::ScriptBuf::default(),
                        sequence: Sequence(0),
                        witness: Witness::default(),
                    },
                ],
                output: vec![],
            },

            tx_type: Lrc20TxType::Transfer {
                input_proofs: {
                    let mut map = BTreeMap::new();

                    map.insert(0, DUMMY_RECEIPT_PROOF.clone());
                    map.insert(1, DUMMY_RECEIPT_PROOF.clone());
                    map.insert(2, DUMMY_RECEIPT_PROOF.clone());

                    map
                },
                output_proofs: Default::default(),
            },
        };
        dbg!(tx4.bitcoin_tx.txid());

        let tx5 = Lrc20Transaction {
            bitcoin_tx: Transaction {
                version: Version::ONE,
                lock_time: LockTime::from_height(6).expect("failed to create lock time"),
                input: vec![bitcoin::TxIn {
                    previous_output: bitcoin::OutPoint::new(tx4.bitcoin_tx.txid(), 0),
                    script_sig: bitcoin::ScriptBuf::default(),
                    sequence: Sequence(0),
                    witness: Witness::default(),
                }],
                output: vec![],
            },

            tx_type: Lrc20TxType::Transfer {
                input_proofs: {
                    let mut map = BTreeMap::new();

                    map.insert(0, DUMMY_RECEIPT_PROOF.clone());

                    map
                },
                output_proofs: Default::default(),
            },
        };
        dbg!(tx5.bitcoin_tx.txid());

        graph_builder
            .attach_txs(&vec![
                tx6.clone(),
                tx2.clone(),
                tx5.clone(),
                tx4.clone(),
                tx3.clone(),
                tx7.clone(),
            ])
            .await?;

        assert!(
            !graph_builder.deps.is_empty(),
            "Deps mustn't be empty before cleaning"
        );
        assert!(
            !graph_builder.inverse_deps.is_empty(),
            "InvDeps mustn't be empty before cleaning"
        );
        assert!(
            !graph_builder.stored_txs.is_empty(),
            "StoredTxs mustn't be empty before cleaning"
        );

        graph_builder.handle_cleanup().await?;

        assert!(
            graph_builder.deps.is_empty(),
            "Deps must be empty after cleaning: {:?}",
            graph_builder.deps
        );
        assert!(
            graph_builder.inverse_deps.is_empty(),
            "InvDeps must be empty after cleaning: {:?}",
            graph_builder.inverse_deps
        );
        assert!(
            graph_builder.stored_txs.is_empty(),
            "StoredTxs must be empty after cleaning: {:?}",
            graph_builder.stored_txs
        );

        Ok(())
    }
}
