use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bitcoin::hashes::Hash;
use bitcoin::hashes::sha256::Hash as Sha256Hash;
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::{self, All, Message, ThirtyTwoByteHash};
use bitcoin::{OutPoint, TxIn, Txid, secp256k1::PublicKey};
use bitcoin_client::BitcoinRpcApi;
use event_bus::{EventBus, typeid};
use eyre::{Context, Result, eyre};

use lrc20_storage::traits::{Lrc20NodeStorage, MempoolNodeStorage, SparkNodeStorage};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use lrc20_receipts::{ReceiptProof, SparkExitMetadata, TaprootProof, TokenPubkey};
use lrc20_storage::PgDatabaseConnectionManager;
use lrc20_types::announcements::{
    IssueAnnouncement, PubkeyFreezeAnnouncement, TokenLogoAnnouncement, TokenPubkeyAnnouncement,
    TokenPubkeyInfo, TransferOwnershipAnnouncement, TxFreezeAnnouncement,
};
use lrc20_types::messages::p2p::Inventory;
use lrc20_types::spark::signature::{SPARK_THRESHOLD, SparkSignatureData, SparkSignatureLeafData};
use tracing::debug;

use lrc20_types::spark::spark_hash::SparkHash;
use lrc20_types::spark::{
    OperatorSpecificOwnerSignature, SparkOutPoint, TokenLeafOutput, TokenLeafToSpend,
    TokenTransaction, TokenTransactionInput, TokenTransactionStatus, TokensFreezeData,
};
use lrc20_types::{
    Announcement, ControllerMessage, GraphBuilderMessage, Lrc20Transaction, Lrc20TxType, ProofMap,
    TxCheckerMessage,
};

use crate::check_transaction;
use crate::errors::CheckError;
use crate::isolated_checks::{check_p2tr_proof, find_owner_in_txinputs};

/// Async implementation of [`TxChecker`] for node implementation.
///
/// Accepts [`Lrc20Transaction`]s from channel, check them and sends to graph builder.
///
/// [`TxChecker`]: struct.TxChecker.html
pub struct TxChecker<NodeStorage, BitcoinClient> {
    /// Node persistent storage.
    pub(crate) node_storage: NodeStorage,
    /// Event bus for simplifying communication with services
    event_bus: EventBus,
    /// Bitcoin RPC Client used to get transactions from the network.
    bitcoin_client: Arc<BitcoinClient>,

    /// FIXME: remove this field after L1 is released
    validate_announcement: bool,

    spark_queue: HashMap<SparkHash, (SparkChild, SystemTime)>,

    cleanup_interval: Duration,
    tx_outdated_duration: Duration,
}

enum SparkChild {
    TokenTx(TokenTransaction),
    ExitTx(Lrc20Transaction),
}

impl<NS, BC> TxChecker<NS, BC>
where
    NS: PgDatabaseConnectionManager
        + Lrc20NodeStorage
        + SparkNodeStorage
        + MempoolNodeStorage
        + Clone
        + Send
        + Sync
        + 'static,
    BC: BitcoinRpcApi + Send + Sync + 'static,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        full_event_bus: EventBus,
        node_storage: NS,
        bitcoin_client: Arc<BC>,
        validate_announcement: bool,
        cleanup_interval: Duration,
        tx_outdated_duration: Duration,
    ) -> Self {
        let event_bus = full_event_bus
            .extract(
                &typeid![GraphBuilderMessage, ControllerMessage, TxCheckerMessage],
                &typeid![TxCheckerMessage],
            )
            .expect("event channels must be presented");

        Self {
            event_bus,
            node_storage,
            bitcoin_client,
            validate_announcement,
            spark_queue: HashMap::default(),
            cleanup_interval,
            tx_outdated_duration,
        }
    }

    pub async fn run(mut self, cancellation: CancellationToken) {
        let events = self.event_bus.subscribe::<TxCheckerMessage>();
        let mut timer = tokio::time::interval(self.cleanup_interval);

        loop {
            tokio::select! {
                event_received = events.recv() => {
                    let Ok(event) = event_received else {
                        tracing::trace!("All incoming events senders are dropped");
                        return;
                    };

                    if let Err(err) = self.handle_event(event).await {
                        tracing::error!("Failed to handle an event: {}", err);

                        // Error usually occurs when there is no connection established with the
                        // Bitcoin RPC. In this case the node should gracefully shutdown.
                        cancellation.cancel()
                    }
                }
                _ = timer.tick() => {
                    if !self.spark_queue.is_empty() {
                        if let Err(err) = self.handle_cleanup().await {
                            tracing::error!("Failed to do spark child transactions cleanup: {:?}", err);
                        }
                    }
                }
                _ = cancellation.cancelled() => {
                    tracing::trace!("Cancellation received, stopping TxCheckerWorker");
                    return;
                }
            }
        }
    }

    async fn handle_event(&mut self, event: TxCheckerMessage) -> Result<()> {
        match event {
            TxCheckerMessage::FullCheck(txs) => self.check_txs_full(txs).await?,
            TxCheckerMessage::IsolatedCheck(txs) => self
                .check_txs_isolated(txs)
                .await
                .wrap_err("failed to perform the isolated check of transactions")?,
            TxCheckerMessage::SparkCheck((txs, sender, callback)) => self
                .check_spark_txs(txs, sender, callback)
                .await
                .map_err(|err| {
                    eyre!("failed to perform the check of Spark transactions: {}", err)
                })?,
            TxCheckerMessage::SparkSignatureCheck(request, callback) => self
                .check_spark_signatures(request, callback)
                .await
                .map_err(|err| eyre!("failed to perform the check of Spark signatures: {}", err))?,
            TxCheckerMessage::TokensFreezeCheck(request) => {
                self.check_token_freezes(request).await.map_err(|err| {
                    eyre!(
                        "failed to perform the check of Spark token freezes: {}",
                        err
                    )
                })?
            }
        }

        Ok(())
    }

    async fn handle_cleanup(&mut self) -> eyre::Result<()> {
        let now = SystemTime::now();

        let mut outdated_child_txs = Vec::new();
        let mut invalid_txs = Vec::new();
        for (txid, (spark_child, created_at)) in &self.spark_queue {
            let since_created_at = now
                .duration_since(*created_at)
                .wrap_err("failed to calculate duration since")?;

            if since_created_at > self.tx_outdated_duration {
                match spark_child {
                    SparkChild::TokenTx { .. } => {
                        tracing::debug!("Token tx {} is outdated", txid);
                    }
                    SparkChild::ExitTx(exit_tx) => {
                        tracing::debug!("Exit tx {} is outdated", txid);
                        // We currently handle only LRC20 invalid transactions, so TokenTx it not
                        // added to invalid_txs.
                        invalid_txs.push(exit_tx.clone());
                    }
                }

                outdated_child_txs.push(*txid);
            }
        }

        for outdated_child_txid in outdated_child_txs {
            self.spark_queue.remove(&outdated_child_txid);
        }

        self.handle_invalid_txs(invalid_txs).await?;

        Ok(())
    }

    /// Fully check the transaction depends on its type. It inform the controller about the invalid
    /// transactions or request missing parent transactions (in case of [`Lrc20TxType::Transfer`]).
    /// It also sends valid [`Lrc20TxType::Issue`] and [`Lrc20TxType::Transfer`]
    /// transactions to the graph builder.
    pub async fn check_txs_full(
        &mut self,
        txs: Vec<(Lrc20Transaction, Option<SocketAddr>)>,
    ) -> Result<()> {
        let mut checked_txs = BTreeMap::new();
        let mut invalid_txs = Vec::new();
        let mut not_found_parents = HashMap::new();

        let txids: Vec<Txid> = txs.iter().map(|(tx, _)| tx.bitcoin_tx.txid()).collect();
        tracing::debug!("Checking txs full: {:?}", txids);

        for (tx, sender) in txs {
            let (is_valid, is_waiting_for_parent) = self
                .check_lrc20_transaction(
                    tx.clone(),
                    sender,
                    &mut checked_txs,
                    &mut not_found_parents,
                )
                .await?;

            // This can happen if a spark exit transaction is waiting for parent token transaction
            if is_waiting_for_parent {
                continue;
            }

            if !is_valid {
                invalid_txs.push(tx.clone());

                continue;
            }

            checked_txs.insert(tx.bitcoin_tx.txid(), tx);
        }

        // Send checked transactions to next worker:
        if !checked_txs.is_empty() {
            self.event_bus
                .send(ControllerMessage::FullyCheckedTxs(
                    checked_txs.values().cloned().collect::<Vec<_>>(),
                ))
                .await;
        }

        // Notify about invalid transactions:
        self.handle_invalid_txs(invalid_txs).await?;

        // If there is no info about parent transactions, request them:
        for (receiver, missing_parents) in not_found_parents {
            let inventory = missing_parents
                .iter()
                .map(|txid| Inventory::Ltx(*txid))
                .collect();

            let get_data_msg = ControllerMessage::GetData {
                inv: inventory,
                receiver,
            };

            self.event_bus.send(get_data_msg).await;
        }

        Ok(())
    }

    /// Partially check the transactions, i.e. perform the isolated check. It informs the controller about the invalid
    /// transactions. It also sends valid [`Lrc20TxType::Issue`] and [`Lrc20TxType::Transfer`]
    /// transactions to the tx confirmator.
    pub async fn check_txs_isolated(&mut self, txs: Vec<Lrc20Transaction>) -> Result<()> {
        let mut checked_txs = Vec::new();
        let mut invalid_txs = Vec::new();

        let txids: Vec<Txid> = txs.iter().map(|tx| tx.bitcoin_tx.txid()).collect();
        tracing::debug!("Checking txs isolated: {:?}", txids);

        for tx in txs {
            let is_valid = check_transaction(&tx)
                .inspect_err(
                    |err| debug!(txid = ?tx.bitcoin_tx.txid(), %err, "Invalid transaction"),
                )
                .is_ok();

            if !is_valid {
                invalid_txs.push(tx.clone());
                continue;
            }

            checked_txs.push(tx.bitcoin_tx.txid());
        }

        // Send checked transactions for confirmation:
        if !checked_txs.is_empty() {
            self.event_bus
                .send(ControllerMessage::PartiallyCheckedTxs(checked_txs))
                .await;
        }

        // Notify about invalid transactions:
        self.handle_invalid_txs(invalid_txs).await?;

        Ok(())
    }

    /// Partially check the transactions, i.e. perform the isolated check. It informs the controller about the invalid
    /// transactions. It also sends valid [`Lrc20TxType::Issue`] and [`Lrc20TxType::Transfer`]
    /// transactions to the tx confirmator.
    pub async fn check_spark_txs(
        &mut self,
        txs: Vec<TokenTransaction>,
        sender: Option<SocketAddr>,
        callback: Option<mpsc::Sender<bool>>,
    ) -> Result<()> {
        let mut checked_txs = BTreeMap::new();
        let mut spent_leaves = BTreeSet::new();
        let mut new_leaves = BTreeSet::new();
        let mut invalid_txs = Vec::new();
        let mut not_found_parents = HashMap::new();

        for tx in txs {
            let spark_tx_hash = tx.hash();

            tracing::debug!("Checking spark tx isolated: {}", spark_tx_hash.to_string());

            let is_valid = self
                .check_spark_transaction(
                    &tx,
                    sender,
                    &mut checked_txs,
                    &mut spent_leaves,
                    &mut new_leaves,
                    &mut not_found_parents,
                )
                .await?;

            if !is_valid {
                if let Some(callback) = callback.clone() {
                    if let Err(e) = callback.send(false).await {
                        tracing::error!("Failed to send callback message: {}", e);
                    }
                }

                invalid_txs.push(tx.clone());
                continue;
            }

            checked_txs.insert(*spark_tx_hash, tx.clone());
        }

        if let Some(callback) = callback.clone() {
            if let Err(e) = callback.send(true).await {
                tracing::error!("Failed to send callback message: {}", e);
            }
        }

        // Send checked transactions to next worker:
        if !checked_txs.is_empty() {
            self.event_bus
                .send(ControllerMessage::CheckedSparkTxs(
                    checked_txs.values().cloned().collect::<Vec<_>>(),
                ))
                .await;

            self.handle_child_spark_transactions(
                checked_txs
                    .keys()
                    .cloned()
                    .map(SparkHash)
                    .collect::<Vec<_>>(),
            )
            .await?;
        }

        // Notify about invalid transactions:
        // self.handle_invalid_txs(invalid_txs).await?;

        // If there is no info about parent transactions, request them:
        for (receiver, missing_parents) in not_found_parents {
            let inventory = missing_parents
                .iter()
                .map(|txid| Inventory::SparkTx(*txid))
                .collect();

            let get_data_msg = ControllerMessage::GetData {
                inv: inventory,
                receiver,
            };

            self.event_bus.send(get_data_msg).await;
        }

        Ok(())
    }

    async fn handle_child_spark_transactions(
        &mut self,
        parent_txids: Vec<SparkHash>,
    ) -> eyre::Result<()> {
        let mut exit_txs = Vec::new();
        let mut token_txs = Vec::new();

        for parent_txid in parent_txids {
            let Some((child, _)) = self.spark_queue.remove(&parent_txid) else {
                continue;
            };

            match child {
                SparkChild::TokenTx(token_transaction) => {
                    tracing::info!(
                        "Found parent for token transaction {}",
                        token_transaction.hash()
                    );

                    token_txs.push(token_transaction);
                }
                SparkChild::ExitTx(lrc20_transaction) => {
                    tracing::info!(
                        "Found parent for exit transaction {}",
                        lrc20_transaction.bitcoin_tx.txid()
                    );

                    exit_txs.push((lrc20_transaction, None));
                }
            }
        }

        if !exit_txs.is_empty() {
            tracing::info!(
                "Sending {} exit transactions for a repeated check",
                exit_txs.len()
            );

            self.event_bus
                .send(TxCheckerMessage::FullCheck(exit_txs))
                .await;
        }

        if !token_txs.is_empty() {
            tracing::info!(
                "Sending {} token transactions for a repeated check",
                token_txs.len()
            );

            self.event_bus
                .send(TxCheckerMessage::SparkCheck((token_txs, None, None)))
                .await;
        }

        Ok(())
    }

    async fn check_spark_signature_data(
        &self,
        ctx: &Secp256k1<All>,
        sig_data: &SparkSignatureData,
    ) -> Result<bool> {
        let token_tx_opt = self
            .node_storage
            .get_spark_tx_with_outputs(sig_data.token_tx_hash)
            .await?;

        let Some(token_tx) = token_tx_opt else {
            tracing::debug!(
                hash = sig_data.token_tx_hash.to_string(),
                "Spark signature data is invalid: tx is not found",
            );
            return Ok(false);
        };

        let token_tx_hash = token_tx.hash();
        let message = Message::from_digest(token_tx_hash.into_32());

        // Verify the operator signature.
        if !token_tx
            .spark_operator_identity_public_keys
            .contains(&sig_data.operator_pubkey)
        {
            tracing::debug!(
                hash = sig_data.token_tx_hash.to_string(),
                operator_key = sig_data.operator_pubkey.to_string(),
                "Spark signature data is invalid: unknown operator identity public key",
            );
            return Ok(false);
        }

        if !sig_data.operator_signature.verify_with_ctx(
            ctx,
            &sig_data.operator_pubkey,
            &message,
            None,
        ) {
            tracing::debug!(
                hash = sig_data.token_tx_hash.to_string(),
                operator_key = sig_data.operator_pubkey.to_string(),
                "Spark signature data is invalid: invalid operator signature",
            );
            return Ok(false);
        }

        let TokenTransactionInput::Transfer { outputs_to_spend } = token_tx.input else {
            return Ok(true);
        };

        // Verify the owner signature
        if let Some(operator_specific_owner_signature) = sig_data.operator_specific_owner_signature
        {
            let Some((_, signing_output)) = self
                .get_spark_prevout(
                    outputs_to_spend.clone(),
                    operator_specific_owner_signature
                        .input_index
                        .unwrap_or_default() as usize,
                )
                .await?
            else {
                tracing::debug!("Owner Spark signature data is invalid: prevout not found");
                return Ok(false);
            };

            let verifying_key = &signing_output.owner_public_key;

            if !operator_specific_owner_signature
                .owner_signature
                .verify_with_ctx(
                    ctx,
                    verifying_key,
                    &message,
                    operator_specific_owner_signature.operator_identity_public_key,
                )
            {
                tracing::debug!(
                    hash = sig_data.token_tx_hash.to_string(),
                    "Spark signature data is invalid: invalid owner signature",
                );
                return Ok(false);
            }
        }

        if !sig_data.outputs_to_spend_data.is_empty() {
            tracing::debug!(
                tx_hash = sig_data.token_tx_hash.to_string(),
                "Checking revocation secrets for spark tx: {:?}",
                sig_data.outputs_to_spend_data
            );
        }

        for leaf_data in &sig_data.outputs_to_spend_data {
            let Some(revocation_private_key) = &leaf_data.revocation_secret else {
                continue;
            };

            let Some((parent_out_point, parent_output)) = self
                .get_spark_prevout(
                    outputs_to_spend.clone(),
                    leaf_data.token_tx_leaf_index as usize,
                )
                .await?
            else {
                tracing::debug!(
                    hash = sig_data.token_tx_hash.to_string(),
                    "Spark signature data is invalid: previous leaf to create is not found",
                );
                return Ok(false);
            };

            let revocation_public_key = revocation_private_key.public_key(ctx);

            if revocation_public_key.serialize().to_vec()
                != parent_output.revocation_public_key.serialize()
            {
                tracing::debug!(
                    hash = sig_data.token_tx_hash.to_string(),
                    "Spark signature data is invalid: revocation key is invalid",
                );
                return Ok(false);
            }

            tracing::debug!(
                tx_hash = sig_data.token_tx_hash.to_string(),
                "Inserting revocation secret for spark prevout {}:{}",
                parent_out_point.token_transaction_hash.to_string(),
                parent_out_point.output_index,
            );

            self.node_storage
                .set_revocation_secret_key(
                    parent_out_point.token_transaction_hash,
                    parent_out_point.output_index,
                    *revocation_private_key,
                )
                .await?;

            tracing::debug!(
                tx_hash = sig_data.token_tx_hash.to_string(),
                "Inserted revocation secret for spark prevout {}:{}",
                parent_out_point.token_transaction_hash.to_string(),
                parent_out_point.output_index,
            );
        }

        Ok(true)
    }

    async fn get_spark_prevout(
        &self,
        leaves_to_spend: Vec<TokenLeafToSpend>,
        leaf_index: usize,
    ) -> Result<Option<(SparkOutPoint, TokenLeafOutput)>> {
        let Some(prev_output_data) = leaves_to_spend.get(leaf_index) else {
            return Ok(None);
        };

        let Some(prev_token_tx) = self
            .node_storage
            .get_spark_tx_with_outputs(prev_output_data.parent_output_hash.into())
            .await?
        else {
            return Ok(None);
        };

        Ok(prev_token_tx
            .leaves_to_create
            .get(prev_output_data.parent_output_vout as usize)
            .map(|output| {
                (
                    SparkOutPoint::new(prev_token_tx.hash(), prev_output_data.parent_output_vout),
                    output.clone(),
                )
            }))
    }

    async fn check_spark_signatures(
        &mut self,
        sigs: Vec<SparkSignatureData>,
        callback: Option<mpsc::Sender<bool>>,
    ) -> Result<()> {
        tracing::debug!(
            "[check_spark_signatures] Starting with {} signatures",
            sigs.len()
        );
        let mut invalid_sigs = Vec::new();
        let ctx = Secp256k1::new();

        for signature in &sigs {
            tracing::debug!(
                "[check_spark_signatures] Checking signature for token tx hash: {}",
                signature.token_tx_hash
            );
            let is_valid = self.check_spark_signature_data(&ctx, signature).await?;

            if !is_valid {
                tracing::debug!(
                    "[check_spark_signatures] Signature for token tx hash {} is invalid",
                    signature.token_tx_hash
                );
                if let Some(callback) = callback.clone() {
                    tracing::debug!("[check_spark_signatures] Sending invalid signature callback");
                    if let Err(e) = callback.send(false).await {
                        tracing::error!(
                            "[check_spark_signatures] Failed to send callback message: {}",
                            e
                        );
                    }
                }

                invalid_sigs.push(signature);
                continue;
            }

            tracing::debug!(
                "[check_spark_signatures] Signature for token tx hash {} is valid, inserting into storage",
                signature.token_tx_hash
            );
            self.node_storage
                .insert_signature_data(signature.clone())
                .await?;
        }

        tracing::debug!(
            "[check_spark_signatures] Found {} invalid signatures",
            invalid_sigs.len()
        );
        let mut finalized_txids = Vec::new();
        for signature in &sigs {
            tracing::debug!(
                "[check_spark_signatures] Checking if token tx {} is finalized",
                signature.token_tx_hash
            );
            let Some(token_tx) = self
                .node_storage
                .get_spark_tx_with_outputs(signature.token_tx_hash)
                .await?
            else {
                tracing::debug!(
                    "[check_spark_signatures] Token tx {} not found in storage",
                    signature.token_tx_hash
                );
                continue;
            };

            tracing::debug!(
                "[check_spark_signatures] Getting signatures for token tx {}",
                signature.token_tx_hash
            );
            let signatures = self
                .node_storage
                .get_spark_signatures(signature.token_tx_hash)
                .await?;
            tracing::debug!(
                "[check_spark_signatures] Found {} signatures for token tx {}",
                signatures.len(),
                signature.token_tx_hash
            );

            tracing::debug!(
                "[check_spark_signatures] Getting revocation secrets for token tx {}",
                signature.token_tx_hash
            );
            let revocation_secrets = self
                .node_storage
                .get_revocation_secret_keys(signature.token_tx_hash)
                .await?;
            tracing::debug!(
                "[check_spark_signatures] Found {} revocation secrets for token tx {}",
                revocation_secrets.len(),
                signature.token_tx_hash
            );

            let inputs_count = match &token_tx.input {
                TokenTransactionInput::Mint { .. } => {
                    tracing::debug!(
                        "[check_spark_signatures] Token tx {} is a mint transaction with 0 inputs",
                        signature.token_tx_hash
                    );
                    0
                }
                TokenTransactionInput::Transfer { outputs_to_spend } => {
                    tracing::debug!(
                        "[check_spark_signatures] Token tx {} is a transfer transaction with {} inputs",
                        signature.token_tx_hash,
                        outputs_to_spend.len()
                    );
                    outputs_to_spend.len()
                }
            };

            tracing::debug!(
                "[check_spark_signatures] Checking finalization status for token tx {}",
                signature.token_tx_hash
            );
            let tx_status =
                check_spark_tx_finalization(inputs_count, &signatures, &revocation_secrets)?;
            tracing::debug!(
                "[check_spark_signatures] Token tx {} status: {:?}",
                signature.token_tx_hash,
                tx_status
            );

            self.node_storage
                .set_token_transaction_status(token_tx.hash(), tx_status.into())
                .await?;

            if matches!(tx_status, TokenTransactionStatus::Finalized) {
                tracing::debug!(
                    "[check_spark_signatures] Token tx {} is finalized, adding to finalized_txids",
                    signature.token_tx_hash
                );
                finalized_txids.push(signature.token_tx_hash);
            }
        }

        if let Some(callback) = callback {
            tracing::debug!("[check_spark_signatures] Sending successful callback");
            if let Err(e) = callback.send(true).await {
                tracing::error!(
                    "[check_spark_signatures] Failed to send callback message: {}",
                    e
                );
            }
        }

        if !finalized_txids.is_empty() {
            tracing::debug!(
                "[check_spark_signatures] Processing {} finalized transactions",
                finalized_txids.len()
            );
            self.handle_child_spark_transactions(finalized_txids)
                .await?;
        } else {
            tracing::debug!("[check_spark_signatures] No finalized transactions to process");
        }

        tracing::debug!("[check_spark_signatures] Completed successfully");
        Ok(())
    }

    async fn check_token_freezes(&self, freezes: Vec<TokensFreezeData>) -> Result<()> {
        let ctx = Secp256k1::new();
        let mut valid_freezes = Vec::new();

        for freeze_data in freezes {
            let is_valid = self.check_token_freeze(&freeze_data, &ctx).await?;

            if is_valid {
                valid_freezes.push(freeze_data);
            }
        }

        if !valid_freezes.is_empty() {
            self.event_bus
                .send(ControllerMessage::CheckedSparkFreezeData(valid_freezes))
                .await;
        }

        Ok(())
    }

    async fn check_token_freeze(
        &self,
        freeze_data: &TokensFreezeData,
        ctx: &Secp256k1<All>,
    ) -> Result<bool> {
        if !freeze_data.issuer_signature.verify_with_ctx(
            ctx,
            freeze_data.token_public_key.pubkey(),
            &Message::from_digest(freeze_data.hash().into_32()),
            None,
        ) {
            tracing::info!(
                "Spark token freeze of pubkey {} for token_pubkey {} is invalid: invalid signature",
                freeze_data.owner_public_key,
                freeze_data.token_public_key,
            );

            return Ok(false);
        }

        let token_pubkey_bytes = freeze_data.token_public_key.to_bytes();
        let leaves = self
            .node_storage
            .get_spark_outputs_by_owner_pubkey(&freeze_data.owner_public_key.serialize())
            .await?;

        let freeze_token_leaves = leaves
            .into_iter()
            .filter(|leaf| {
                leaf.receipt.token_pubkey
                    == TokenPubkey::from_bytes(&token_pubkey_bytes).unwrap_or_else(|_| {
                        tracing::error!("Invalid token pubkey bytes: {:?}", token_pubkey_bytes);
                        panic!("Failed to parse token pubkey from bytes");
                    })
            })
            .collect::<Vec<_>>();

        for leaf in freeze_token_leaves {
            self.node_storage
                .udpate_spark_output_freeze_status(leaf.id.clone(), !freeze_data.should_unfreeze)
                .await?;
        }

        Ok(true)
    }

    async fn handle_invalid_txs(&self, invalid_txs: Vec<Lrc20Transaction>) -> Result<()> {
        if invalid_txs.is_empty() {
            return Ok(());
        }

        let invalid_txs_ids = invalid_txs.iter().map(|tx| tx.bitcoin_tx.txid()).collect();
        self.event_bus
            .send(ControllerMessage::InvalidTxs(invalid_txs_ids))
            .await;

        Ok(())
    }

    /// Do the corresponding checks for the transaction based on its type.
    async fn check_lrc20_transaction(
        &mut self,
        tx: Lrc20Transaction,
        sender: Option<SocketAddr>,
        checked_txs: &mut BTreeMap<Txid, Lrc20Transaction>,
        not_found_parents: &mut HashMap<SocketAddr, Vec<Txid>>,
    ) -> Result<(bool, bool)> {
        let mut is_waiting_for_parent = false;
        let is_valid = match &tx.tx_type {
            Lrc20TxType::Issue { announcement, .. } => {
                self.check_issuance(&tx, announcement).await?
            }
            Lrc20TxType::Announcement(announcement) => {
                self.check_announcements(&tx, announcement).await?
            }
            Lrc20TxType::Transfer { input_proofs, .. } => {
                self.check_transfer(&tx, sender, input_proofs, checked_txs, not_found_parents)
                    .await?
            }
            Lrc20TxType::SparkExit { output_proofs } => {
                let (is_valid, not_found_parent) = self
                    .check_spark_exit_transaction(&tx, sender, output_proofs)
                    .await?;

                is_waiting_for_parent = not_found_parent;
                is_valid
            }
        };

        Ok((is_valid, is_waiting_for_parent))
    }

    async fn check_spark_transaction(
        &mut self,
        tx: &TokenTransaction,
        sender: Option<SocketAddr>,
        checked_txs: &mut BTreeMap<Sha256Hash, TokenTransaction>,
        spent_leaves: &mut BTreeSet<(Sha256Hash, usize)>,
        new_leaves: &mut BTreeSet<String>,
        not_found_parents: &mut HashMap<SocketAddr, Vec<Sha256Hash>>,
    ) -> Result<bool> {
        let is_valid = match &tx.input {
            TokenTransactionInput::Mint {
                issuer_public_key,
                issuer_signature,
                ..
            } => {
                self.check_spark_issue(tx, issuer_public_key, issuer_signature, new_leaves)
                    .await?
            }
            TokenTransactionInput::Transfer {
                outputs_to_spend: leaves_to_spend,
            } => {
                self.check_spark_transfer(
                    tx,
                    sender,
                    checked_txs,
                    leaves_to_spend.to_vec(),
                    spent_leaves,
                    new_leaves,
                    not_found_parents,
                )
                .await?
            }
        };

        Ok(is_valid)
    }

    #[allow(clippy::too_many_arguments)]
    async fn check_spark_transfer(
        &mut self,
        tx: &TokenTransaction,
        sender: Option<SocketAddr>,
        checked_txs: &BTreeMap<Sha256Hash, TokenTransaction>,
        outputs_to_spend: Vec<TokenLeafToSpend>,
        spent_leaves: &mut BTreeSet<(Sha256Hash, usize)>,
        new_leaves: &mut BTreeSet<String>,
        not_found_parents: &mut HashMap<SocketAddr, Vec<Sha256Hash>>,
    ) -> Result<bool> {
        let mut input_leaves: Vec<TokenLeafOutput> = Vec::new();
        let tx_hash = tx.hash();

        for parent_output in &outputs_to_spend {
            if spent_leaves.contains(&(
                parent_output.parent_output_hash,
                parent_output.parent_output_vout as usize,
            )) {
                tracing::debug!(
                    "Double spend of input leaf found: {}:{}",
                    parent_output.parent_output_hash,
                    parent_output.parent_output_vout
                );
                return Ok(false);
            }

            let parent_txid = parent_output.parent_output_hash.into();
            let parent_tx = self
                .node_storage
                .get_spark_tx_with_outputs(parent_txid)
                .await?;

            let parent_tx = match parent_tx {
                Some(tx) => Some(tx),
                None => checked_txs.get(&*parent_txid).cloned(),
            };

            let Some(parent_tx) = parent_tx else {
                if let Some(sender) = sender {
                    let txids = not_found_parents.entry(sender).or_default();
                    txids.push(parent_output.parent_output_hash);
                }

                tracing::debug!("Spark Transfer tx {} is invalid: parent not found", tx_hash);

                self.spark_queue.insert(
                    parent_txid,
                    (SparkChild::TokenTx(tx.clone()), SystemTime::now()),
                );

                return Ok(false);
            };

            let parent_tx_operator_keys = parent_tx.spark_operator_identity_public_keys;
            let current_tx_operator_keys = tx.spark_operator_identity_public_keys.clone();

            if current_tx_operator_keys != parent_tx_operator_keys {
                tracing::debug!(
                    "Spark Transfer tx {} is invalid: operators list doesn't match parent transaction operators list",
                    tx.hash()
                );

                return Ok(false);
            }

            let Some(input_leaf) = parent_tx
                .leaves_to_create
                .get(parent_output.parent_output_vout as usize)
            else {
                tracing::debug!(
                    "Spark Transfer tx {} is invalid: leaf {}:{} not found",
                    tx.hash(),
                    parent_output.parent_output_vout,
                    parent_output.parent_output_vout
                );
                return Ok(false);
            };

            if input_leaf.is_frozen.unwrap_or_default() {
                tracing::debug!(
                    "Spark Transfer tx {} is invalid: input leaf {}:{} is frozen",
                    tx_hash,
                    parent_output.parent_output_vout,
                    parent_output.parent_output_vout
                );
                return Ok(false);
            }

            input_leaves.push(input_leaf.clone());

            let spent_leaf = self
                .node_storage
                .get_spent_output(
                    parent_output.parent_output_hash.into(),
                    parent_output.parent_output_vout as usize,
                )
                .await?;

            // If the leaf is marked as spent, check the spend tx finalization status
            if let Some(_spent_leaf) = spent_leaf {
                // let spend_tx_hash =
                //     Sha256Hash::from_slice(parent_leaf.parent_leaf_hash.as_byte_array())?;
                // // TODO: consider adding memoization
                // if let Some(spend_tx) = self
                //     .node_storage
                //     .get_spark_tx_with_outputs(spend_tx_hash.into())
                //     .await?
                // {
                //     let spark_hash = spend_tx_hash.into();
                //     let spend_tx_signatures = self
                //         .node_storage
                //         .get_spark_signatures(&[spark_hash])
                //         .await?;

                //     let revocation_keys = self
                //         .node_storage
                //         .get_revocation_secret_keys(spark_hash)
                //         .await?;

                //     let spend_tx_status = check_spark_tx_finalization(
                //         match spend_tx.input {
                //             TokenTransactionInput::Mint { .. } => 0,
                //             TokenTransactionInput::Transfer { leaves_to_spend } => {
                //                 leaves_to_spend.len()
                //             }
                //         },
                //         &spend_tx_signatures,
                //         &revocation_keys,
                //     )?;

                //     if matches!(spend_tx_status, TokenTransactionStatus::Finalized) {
                //         tracing::info!(
                //             "Spark Transfer tx {} is invalid: leaf {}:{} is already spent",
                //             tx_hash,
                //             parent_leaf.parent_leaf_hash,
                //             parent_leaf.parent_leaf_index,
                //         );
                //         return Ok(false);
                //     }
                // };
            }

            spent_leaves.insert((
                parent_output.parent_output_hash,
                parent_output.parent_output_vout as usize,
            ));
        }

        for new_leaf in &tx.leaves_to_create {
            if new_leaves.contains(&new_leaf.id) {
                tracing::info!(
                    "Spark Transfer tx {} is invalid: leaf with id {} already exists in the same transaction",
                    tx_hash,
                    new_leaf.id
                );
                return Ok(false);
            }

            if let Some(stored_leaf) = self
                .node_storage
                .get_spark_output_model(new_leaf.id.clone())
                .await?
            {
                if stored_leaf.tx_hash != tx_hash.to_byte_array().to_vec() {
                    tracing::info!(
                        "Spark Transfer tx {} is invalid: leaf with id {} already exists in another transaction",
                        tx.hash(),
                        new_leaf.id
                    );
                    return Ok(false);
                }
            };

            new_leaves.insert(new_leaf.id.clone());
        }

        if !check_spark_conservation_rules(&input_leaves, &tx.leaves_to_create) {
            tracing::info!(
                "Spark Transfer tx {} is invalid: conservation rules violated",
                tx.hash(),
            );

            return Ok(false);
        };

        Ok(true)
    }

    async fn check_spark_issue(
        &mut self,
        tx: &TokenTransaction,
        issuer_pubkey: &secp256k1::PublicKey,
        issuer_signature: &Option<OperatorSpecificOwnerSignature>,
        new_leaves: &mut BTreeSet<String>,
    ) -> Result<bool> {
        let ctx = Secp256k1::new();
        let message =
            Message::from_digest(SparkHash::hash_token_transaction(tx, false).0.into_32());

        let Some(issuer_signature) = issuer_signature else {
            tracing::debug!(
                "Spark Issue tx {} is invalid: missing issuer signature",
                tx.hash(),
            );
            return Ok(false);
        };

        if !issuer_signature.owner_signature.verify_with_ctx(
            &ctx,
            issuer_pubkey,
            &message,
            issuer_signature.operator_identity_public_key,
        ) {
            tracing::debug!(
                "Spark Issue tx {} is invalid: invalid issuer signature",
                tx.hash(),
            );
            return Ok(false);
        }

        let tx_hash = tx.hash();

        for new_leaf in &tx.leaves_to_create {
            if new_leaves.contains(&new_leaf.id) {
                tracing::info!(
                    "Spark Issue tx {} is invalid: leaf with id {} already exists in the same transaction",
                    tx_hash,
                    new_leaf.id
                );
                return Ok(false);
            }

            if let Some(stored_leaf) = self
                .node_storage
                .get_spark_output_model(new_leaf.id.clone())
                .await?
            {
                if stored_leaf.tx_hash != tx_hash.to_byte_array().to_vec() {
                    tracing::info!(
                        "Spark Issue tx {} is invalid: leaf with id {} already exists in another transaction",
                        tx_hash,
                        new_leaf.id
                    );
                    return Ok(false);
                }
            };

            let token_public_key = new_leaf.receipt.token_pubkey;
            if token_public_key.pubkey() != issuer_pubkey {
                tracing::info!(
                    "Spark Issue tx {} is invalid: leaf token pubkey {} doesn't match issuer pubkey {}",
                    tx_hash,
                    token_public_key,
                    issuer_pubkey,
                );
                return Ok(false);
            }

            if self.validate_announcement {
                let Some(token_pubkey_info) = self
                    .node_storage
                    .get_token_pubkey_info(new_leaf.receipt.token_pubkey)
                    .await?
                else {
                    tracing::info!(
                        "Spark Issue tx {} is invalid: no token pubkey info found for token pubkey {}",
                        tx_hash,
                        new_leaf.receipt.token_pubkey
                    );
                    return Ok(false);
                };

                if token_pubkey_info.announcement.is_none() {
                    tracing::info!(
                        "Spark Issue tx {} is invalid: token pubkey info for token pubkey {} doesn't have announcement info",
                        tx_hash,
                        new_leaf.receipt.token_pubkey
                    );
                    return Ok(false);
                }
            }

            new_leaves.insert(new_leaf.id.clone());
        }

        Ok(true)
    }

    async fn check_issuance(
        &self,
        tx: &Lrc20Transaction,
        announcement: &IssueAnnouncement,
    ) -> Result<bool> {
        if !self.check_issue_announcement(tx, announcement).await? {
            return Ok(false);
        }

        self.node_storage
            .insert_lrc20_transaction(tx.clone())
            .await?;

        Ok(true)
    }

    async fn check_transfer(
        &mut self,
        tx: &Lrc20Transaction,
        sender: Option<SocketAddr>,
        input_proofs: &ProofMap,
        checked_txs: &BTreeMap<Txid, Lrc20Transaction>,
        not_found_parents: &mut HashMap<SocketAddr, Vec<Txid>>,
    ) -> Result<bool> {
        for (parent_id, proof) in input_proofs {
            let Some(txin) = tx.bitcoin_tx.input.get(*parent_id as usize) else {
                return Err(CheckError::InputNotFound.into());
            };

            let parent = txin.previous_output;

            if self.is_output_frozen(&parent, proof).await? {
                tracing::info!(
                    "Transfer tx {} is invalid: output {} is frozen",
                    tx.bitcoin_tx.txid(),
                    parent,
                );

                return Ok(false);
            }

            if let Some(frozen_key) = self.is_sender_frozen(proof).await? {
                tracing::info!(
                    "Transfer tx {} is invalid: sender public key {} is frozen",
                    tx.bitcoin_tx.txid(),
                    frozen_key,
                );

                return Ok(false);
            }

            // TODO: move this check to isolated checks
            if let ReceiptProof::P2TR(taproot_proof) = proof {
                if !self.is_p2tr_proof_valid(taproot_proof, &parent).await? {
                    tracing::info!(
                        "Transfer tx {} is invalid: one of p2tr input proofs is invalid",
                        tx.bitcoin_tx.txid(),
                    );

                    return Ok(false);
                }
            }

            let is_in_storage = self
                .node_storage
                .get_lrc20_transaction_by_id(parent.txid)
                .await?
                .is_some();
            if !is_in_storage && !checked_txs.contains_key(&parent.txid) {
                if let Some(sender) = sender {
                    let txids = not_found_parents.entry(sender).or_default();
                    txids.push(parent.txid);
                }
            }
        }

        Ok(true)
    }

    async fn check_spark_exit(
        &mut self,
        tx: &Lrc20Transaction,
        _sender: Option<SocketAddr>,
        output_proofs: &ProofMap,
    ) -> Result<(bool, bool)> {
        let tx_info = self
            .bitcoin_client
            .get_raw_transaction_info(&tx.bitcoin_tx.txid(), None)
            .await?;
        let block_info = match tx_info.blockhash {
            Some(hash) => self.bitcoin_client.get_block_header_info(&hash).await?,
            None => {
                tracing::error!("Missing transaction info for {}", tx.bitcoin_tx.txid());
                return Ok((false, false));
            }
        };

        for (i, proof) in output_proofs {
            if matches!(proof, ReceiptProof::EmptyReceipt { .. }) {
                continue;
            }

            let ReceiptProof::SparkExit(spark_exit_proof) = proof else {
                tracing::info!(
                    "Spark exit tx {} is invalid: tx contains non-exit output proofs",
                    tx.bitcoin_tx.txid(),
                );

                return Ok((false, false));
            };

            // First check that the corresponding leaf is not spent.
            let Some(metadata) = &spark_exit_proof.metadata else {
                tracing::info!(
                    "Spark exit tx {} is invalid: spark exit proof output has no metadata",
                    tx.bitcoin_tx.txid(),
                );

                return Ok((false, false));
            };

            let Ok(spark_exit_metadata) =
                serde_json::from_value::<SparkExitMetadata>(metadata.clone())
            else {
                tracing::info!(
                    "Spark exit tx {} is invalid: couldn't parse spark exit metadata",
                    tx.bitcoin_tx.txid(),
                );

                return Ok((false, false));
            };

            let spent_leaf = self
                .node_storage
                .get_spark_output_model(spark_exit_metadata.token_tx_hash.to_string()) // here should be id of leaf and not a tx_hash
                .await?;

            if spent_leaf.is_some() {
                tracing::info!(
                    "Spark exit tx {} is invalid: trying to exit with a spent token tx leaf {}:{}",
                    tx.bitcoin_tx.txid(),
                    spark_exit_metadata.token_tx_hash,
                    spark_exit_metadata.exit_leaf_index,
                );
                return Ok((false, false));
            }

            let Some(token_tx) = self
                .node_storage
                .get_spark_tx_with_outputs(spark_exit_metadata.token_tx_hash.into())
                .await?
            else {
                tracing::info!(
                    "Spark exit tx {} is invalid: token transaction {} doesn't exist",
                    tx.bitcoin_tx.txid(),
                    spark_exit_metadata.token_tx_hash,
                );

                self.spark_queue.insert(
                    spark_exit_metadata.token_tx_hash.into(),
                    (SparkChild::ExitTx(tx.clone()), SystemTime::now()),
                );

                return Ok((false, true));
            };

            let spark_hash = spark_exit_metadata.token_tx_hash.into();
            let tx_status = self
                .node_storage
                .get_token_transaction_status(spark_hash)
                .await?;

            if !matches!(tx_status, TokenTransactionStatus::Finalized) {
                tracing::debug!(
                    "Spark exit tx {} is invalid: token transaction {} is not finalized",
                    tx.bitcoin_tx.txid(),
                    spark_exit_metadata.token_tx_hash,
                );

                self.spark_queue.insert(
                    spark_exit_metadata.token_tx_hash.into(),
                    (SparkChild::ExitTx(tx.clone()), SystemTime::now()),
                );

                return Ok((false, true));
            }

            let Some(exit_leaf) = token_tx
                .leaves_to_create
                .iter()
                .find(|leaf| leaf.id == spark_exit_metadata.exit_leaf_index.to_string())
            else {
                tracing::info!(
                    "Spark exit tx {} is invalid: token transaction {} doesnt have leaf at index {}",
                    tx.bitcoin_tx.txid(),
                    spark_exit_metadata.token_tx_hash,
                    spark_exit_metadata.exit_leaf_index,
                );
                return Ok((false, false));
            };

            if exit_leaf.is_frozen.unwrap_or_default() || exit_leaf.withdraw_txid.is_some() {
                tracing::info!(
                    "Spark exit tx {} is invalid: leaf {}:{} is either already withdrawn or frozen",
                    tx.bitcoin_tx.txid(),
                    spark_exit_metadata.token_tx_hash,
                    spark_exit_metadata.exit_leaf_index,
                );
                return Ok((false, false));
            }

            if exit_leaf.receipt != proof.receipt() {
                tracing::info!(
                    "Spark exit tx {} is invalid: leaf receipt doesn't match proof's receipt",
                    tx.bitcoin_tx.txid(),
                );
                return Ok((false, false));
            }

            if exit_leaf.revocation_public_key != spark_exit_proof.script.revocation_key {
                tracing::info!(
                    "Spark exit tx {} is invalid: leaf revocation key doesn't match proof's revocation key",
                    tx.bitcoin_tx.txid(),
                );
                return Ok((false, false));
            }

            if exit_leaf.owner_public_key != spark_exit_proof.script.delay_key {
                tracing::info!(
                    "Spark exit tx {} is invalid: leaf owner key doesn't match proof's delay key",
                    tx.bitcoin_tx.txid(),
                );
                return Ok((false, false));
            }

            if let Err(e) = self
                .node_storage
                .mark_spark_output_as_withdrawn(
                    exit_leaf.id.clone(),
                    tx.bitcoin_tx.txid(),
                    *i as i32,
                    block_info.hash,
                )
                .await
            {
                tracing::error!(
                    "Failed to insert exit tx {} data: {}",
                    tx.bitcoin_tx.txid(),
                    e
                );
                return Ok((false, false));
            }
        }

        Ok((true, false))
    }

    async fn is_p2tr_proof_valid(
        &self,
        taproot_proof: &TaprootProof,
        parent: &OutPoint,
    ) -> Result<bool> {
        let Ok(prev_tx) = self
            .bitcoin_client
            .get_raw_transaction(&parent.txid, None)
            .await
        else {
            return Ok(false);
        };

        let Some(prev_output) = prev_tx.output.get(parent.vout as usize) else {
            return Ok(false);
        };

        Ok(check_p2tr_proof(&prev_output.script_pubkey, taproot_proof).is_ok())
    }

    /// Check if transaction is frozen.
    async fn is_output_frozen(&self, outpoint: &OutPoint, proof: &ReceiptProof) -> Result<bool> {
        let token_pubkey = &proof.receipt().token_pubkey;

        if let Some(token_pubkey_info) = self
            .node_storage
            .get_token_pubkey_info(*token_pubkey)
            .await?
        {
            if let Some(announcement) = token_pubkey_info.announcement {
                if !announcement.is_freezable {
                    return Ok(false);
                }
            }
        }

        let is_frozen = self
            .node_storage
            .is_proof_frozen(outpoint.txid, outpoint.vout)
            .await?;

        Ok(is_frozen)
    }

    /// Check if pubkey is frozen.
    async fn is_sender_frozen(&self, proof: &ReceiptProof) -> Result<Option<PublicKey>> {
        let token_pubkey = proof.receipt().token_pubkey;
        let pubkeys = proof.spender_keys();

        if let Some(token_pubkey_info) = self
            .node_storage
            .get_token_pubkey_info(token_pubkey)
            .await?
        {
            if let Some(announcement) = token_pubkey_info.announcement {
                if !announcement.is_freezable {
                    return Ok(None);
                }
            }
        }

        for pubkey in pubkeys {
            let is_pubkey_frozen = self
                .node_storage
                .is_pubkey_frozen(pubkey, token_pubkey.into())
                .await?;

            if is_pubkey_frozen {
                return Ok(Some(pubkey));
            }
        }

        Ok(None)
    }

    /// Check that all the [`Announcement`]s in transcation are valid.
    ///
    /// For more details see checks for specific types of announcement.
    ///
    /// # Returns
    ///
    /// - `Ok(true)` - if all the announcements are valid.
    /// - `Ok(false)` - if at least one of the announcements is invalid.
    /// - `Err(err)` - if an error occurred during the check.
    async fn check_announcements(
        &self,
        tx: &Lrc20Transaction,
        announcement: &Announcement,
    ) -> Result<bool> {
        match announcement {
            Announcement::TokenPubkey(announcement) => {
                self.check_token_pubkey_announcement(tx, announcement).await
            }
            Announcement::TokenLogo(announcement) => {
                self.check_token_logo_announcement(tx, announcement).await
            }
            Announcement::TxFreeze(announcement) => {
                self.check_tx_freeze_announcement(tx, announcement).await
            }
            Announcement::PubkeyFreeze(announcement) => {
                self.check_pubkey_freeze_announcement(tx, announcement)
                    .await
            }
            Announcement::Issue(announcement) => {
                self.check_issue_announcement(tx, announcement).await
            }
            Announcement::TransferOwnership(announcement) => {
                self.check_transfer_ownership_announcement(tx, announcement)
                    .await
            }
        }
    }

    /// Check that [TokenPubkeyAnnouncement] is valid.
    ///
    /// The token_pubkey announcement is considered valid if:
    /// 1. One of the inputs of the announcement transaction is signed by the issuer of the token_pubkey.
    /// 2. Max supply is bigger than the current total supply.
    async fn check_token_pubkey_announcement(
        &self,
        announcement_tx: &Lrc20Transaction,
        announcement: &TokenPubkeyAnnouncement,
    ) -> Result<bool> {
        let announcement_tx_inputs = &announcement_tx.bitcoin_tx.input;
        let token_pubkey = &announcement.token_pubkey;

        let owner_input = self
            .find_owner_in_txinputs(announcement_tx_inputs, token_pubkey)
            .await?;
        if owner_input.is_none() {
            tracing::debug!(
                tx = announcement_tx.bitcoin_tx.txid().to_string(),
                "TokenPubkey announcement tx is invalid: none of the inputs has owner, removing it",
            );

            return Ok(false);
        }

        if let Some(token_pubkey_info) = self
            .node_storage
            .get_token_pubkey_info(announcement.token_pubkey)
            .await?
        {
            if token_pubkey_info.announcement.is_some() {
                tracing::debug!(
                    "TokenPubkey announcement tx {} is invalid: announcement for TokenPubkey {} already exists",
                    announcement_tx.bitcoin_tx.txid(),
                    announcement.token_pubkey
                );

                return Ok(false);
            }

            if announcement.max_supply != 0
                && token_pubkey_info.total_supply > announcement.max_supply
            {
                tracing::debug!(
                    "TokenPubkey announcement tx {} is invalid: current total supply {} exceeds max supply {}",
                    announcement_tx.bitcoin_tx.txid(),
                    token_pubkey_info.total_supply,
                    announcement.max_supply,
                );

                return Ok(false);
            }
        };

        Ok(true)
    }

    /// Check that [TokenLogoAnnouncement] is valid.
    ///
    /// The token_pubkey logo announcement is considered valid if:
    /// 1. One of the inputs of the announcement transaction is signed by the issuer of the token_pubkey.
    /// 2. Token pubkey was previously announced.
    async fn check_token_logo_announcement(
        &self,
        announcement_tx: &Lrc20Transaction,
        announcement: &TokenLogoAnnouncement,
    ) -> Result<bool> {
        let announcement_tx_inputs = &announcement_tx.bitcoin_tx.input;
        let token_pubkey = &announcement.token_pubkey;

        let owner_input = self
            .find_owner_in_txinputs(announcement_tx_inputs, token_pubkey)
            .await?;
        if owner_input.is_none() {
            tracing::debug!(
                tx = announcement_tx.bitcoin_tx.txid().to_string(),
                "TokenLogo announcement tx is invalid: none of the inputs has owner, removing it",
            );

            return Ok(false);
        }

        let Some(token_pubkey_info) = self
            .node_storage
            .get_token_pubkey_info(announcement.token_pubkey)
            .await?
        else {
            tracing::debug!(
                "TokenLogo announcement tx {} is invalid: announcement for TokenPubkey {} doesn't exist",
                announcement_tx.bitcoin_tx.txid(),
                announcement.token_pubkey
            );

            return Ok(false);
        };

        if token_pubkey_info.announcement.is_none() {
            tracing::debug!(
                "TokenLogo announcement tx {} is invalid: announcement for TokenPubkey {} already exists",
                announcement_tx.bitcoin_tx.txid(),
                announcement.token_pubkey
            );

            return Ok(false);
        }

        Ok(true)
    }

    /// Check that [TxFreezeAnnouncement] is valid.
    ///
    /// The tx freeze announcement is considered valid if:
    /// 1. The transaction that is being frozen exists in the storage. If the output that is being
    ///    frozen doesn't exist in the transaction then it's an invalid freeze announcement. But we
    ///    can just skip it because it doesn't break the protocol's rules.
    /// 2. The output that is being frozen is an existing LRC20 output.
    /// 3. One of the inputs of the announcement freeze transaction is signed by the owner of the
    ///    token_pubkey that is being frozen.
    /// 4. The freezes are allowed by the TokenPubkey announcement.
    async fn check_tx_freeze_announcement(
        &self,
        announcement_tx: &Lrc20Transaction,
        announcement: &TxFreezeAnnouncement,
    ) -> Result<bool> {
        let freeze_txid = announcement.freeze_txid();
        let token_pubkey = announcement.token_pubkey;

        if let Some(token_pubkey_info) = self
            .node_storage
            .get_token_pubkey_info(token_pubkey)
            .await?
        {
            if let Some(token_pubkey_announcement) = token_pubkey_info.announcement {
                if !token_pubkey_announcement.is_freezable {
                    tracing::info!(
                        "Freeze tx {} is invalid: token_pubkey {} doesn't allow freezes, removing it",
                        freeze_txid,
                        token_pubkey,
                    );

                    return Ok(false);
                }
            }
        }

        // Check signer of the freeze tx is issuer of the token_pubkey which frozen tx has.
        let owner_input = self
            .find_owner_in_txinputs(&announcement_tx.bitcoin_tx.input, &token_pubkey)
            .await?;
        if owner_input.is_none() {
            tracing::info!(
                tx = freeze_txid.to_string(),
                "Freeze tx is invalid: none of the inputs has owner, removing it",
            );

            return Ok(false);
        }

        self.node_storage
            .toggle_proof_freeze(announcement.freeze_txid(), announcement.freeze_vout())
            .await?;

        Ok(true)
    }

    /// Check that [PubkeyFreezeAnnouncement] is valid.
    ///
    /// The pubkey freeze announcement is considered valid if:
    /// 1. One of the inputs of the announcement freeze transaction is signed by the owner of the
    ///    token_pubkey that is being frozen.
    /// 2. The freezes are allowed by the TokenPubkey announcement.
    async fn check_pubkey_freeze_announcement(
        &self,
        announcement_tx: &Lrc20Transaction,
        announcement: &PubkeyFreezeAnnouncement,
    ) -> Result<bool> {
        let token_pubkey = announcement.token_pubkey;
        let freeze_txid = announcement_tx.bitcoin_tx.txid();

        if let Some(token_pubkey_info) = self
            .node_storage
            .get_token_pubkey_info(token_pubkey)
            .await?
        {
            if let Some(token_pubkey_announcement) = token_pubkey_info.announcement {
                if !token_pubkey_announcement.is_freezable {
                    tracing::info!(
                        "Pubkey freeze tx {} is invalid: token_pubkey {} doesn't allow freezes, removing it",
                        freeze_txid,
                        token_pubkey,
                    );

                    return Ok(false);
                }
            }
        }

        // Check signer of the freeze tx is issuer of the token_pubkey which frozen tx has.
        let owner_input = self
            .find_owner_in_txinputs(&announcement_tx.bitcoin_tx.input, &token_pubkey)
            .await?;
        if owner_input.is_none() {
            tracing::info!(
                tx = freeze_txid.to_string(),
                "Freeze tx is invalid: none of the inputs has owner, removing it",
            );

            return Ok(false);
        }

        Ok(true)
    }

    /// Check that [IssueAnnouncement] is valid.
    ///
    /// The issue announcement is considered valid if:
    /// 1. One of the inputs of the issue announcement transaction is signed by the owner
    ///    of the token_pubkey.
    /// 2. Issue amount doesn't exceed the max supply specified in the token_pubkey announcement
    ///    (if announced).
    async fn check_issue_announcement(
        &self,
        announcement_lrc20_tx: &Lrc20Transaction,
        announcement: &IssueAnnouncement,
    ) -> Result<bool> {
        let announcement_tx = &announcement_lrc20_tx.bitcoin_tx;
        let token_pubkey = &announcement.token_pubkey;
        let issue_amount = announcement.amount;

        let is_tx_already_exists = self
            .node_storage
            .get_lrc20_transaction_by_id(announcement_tx.txid())
            .await?
            .is_some();
        if is_tx_already_exists {
            return Ok(true);
        }

        let owner_input = self
            .find_owner_in_txinputs(&announcement_tx.input, token_pubkey)
            .await?;
        if owner_input.is_none() {
            tracing::debug!(
                tx = announcement_lrc20_tx.bitcoin_tx.txid().to_string(),
                "Issue announcement tx is invalid: none of the inputs has owner, removing it",
            );

            return Ok(false);
        }

        // Bulletproof issuance announcements don't update the total supply so they
        // can be skipped.
        // Non-bulletproof issuance must be checked.
        #[cfg(feature = "bulletproof")]
        if announcement_lrc20_tx.is_bulletproof() {
            return Ok(true);
        }

        let token_pubkey_info_opt = self
            .node_storage
            .get_token_pubkey_info(*token_pubkey)
            .await?;
        if let Some(TokenPubkeyInfo {
            announcement: Some(TokenPubkeyAnnouncement { max_supply, .. }),
            total_supply,
            ..
        }) = token_pubkey_info_opt
        {
            let new_total_supply = total_supply + issue_amount;

            if max_supply != 0 && max_supply < new_total_supply {
                tracing::info!(
                    "Issue announcement tx {} is invalid: current supply {} + announcement amount {} is higher than the max supply {}",
                    announcement_tx.txid(),
                    total_supply,
                    issue_amount,
                    max_supply,
                );

                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Check that [TransferOwnershipAnnouncement] is valid.
    ///
    /// The transfer ownership announcement is considered valid if one of the inputs of the
    /// announcement transaction is signed by the current owner of the token_pubkey.
    async fn check_transfer_ownership_announcement(
        &self,
        announcement_lrc20_tx: &Lrc20Transaction,
        announcement: &TransferOwnershipAnnouncement,
    ) -> Result<bool> {
        let announcement_tx = &announcement_lrc20_tx.bitcoin_tx;
        let token_pubkey = &announcement.token_pubkey;

        let owner_input = self
            .find_owner_in_txinputs(&announcement_tx.input, token_pubkey)
            .await?;
        if owner_input.is_none() {
            tracing::debug!(
                tx = announcement_lrc20_tx.bitcoin_tx.txid().to_string(),
                "Transfer ownership announcement tx is invalid: none of the inputs has owner, removing it",
            );

            return Ok(false);
        }

        tracing::debug!(
            "Changed owner for token_pubkey {}",
            announcement.token_pubkey
        );

        Ok(true)
    }

    /// Find owner of the `TokenPubkey` in the inputs.
    async fn find_owner_in_txinputs<'a>(
        &self,
        inputs: &'a [TxIn],
        token_pubkey: &TokenPubkey,
    ) -> eyre::Result<Option<&'a TxIn>> {
        let token_pubkey_info = self
            .node_storage
            .get_token_pubkey_info(*token_pubkey)
            .await?;

        find_owner_in_txinputs(
            inputs,
            token_pubkey,
            token_pubkey_info,
            Arc::clone(&self.bitcoin_client),
        )
        .await
    }

    /// Check that [Lrc20TxType::SparkExit] is valid.
    async fn check_spark_exit_transaction(
        &mut self,
        spark_exit_lrc20_tx: &Lrc20Transaction,
        sender: Option<SocketAddr>,
        output_proofs: &ProofMap,
    ) -> Result<(bool, bool)> {
        self.check_spark_exit(spark_exit_lrc20_tx, sender, output_proofs)
            .await
    }
}

pub fn check_spark_conservation_rules(
    leaves_to_spend: &[TokenLeafOutput],
    leaves_to_create: &[TokenLeafOutput],
) -> bool {
    let input_token_pubkeys = sum_amount_by_token_pubkey(leaves_to_spend);
    let output_token_pubkeys = sum_amount_by_token_pubkey(leaves_to_create);

    input_token_pubkeys == output_token_pubkeys
}

fn sum_amount_by_token_pubkey(leaves: &[TokenLeafOutput]) -> Option<HashMap<TokenPubkey, u128>> {
    let mut token_pubkeys: HashMap<TokenPubkey, u128> = HashMap::new();

    for leaf in leaves {
        let receipt = leaf.receipt;

        let token_pubkey_sum = token_pubkeys.entry(receipt.token_pubkey).or_insert(0);
        *token_pubkey_sum = token_pubkey_sum.checked_add(receipt.token_amount.amount)?;
    }

    Some(token_pubkeys)
}

pub fn check_spark_tx_finalization(
    tx_leaf_count: usize,
    signatures: &[SparkSignatureData],
    signature_leaf_data: &[SparkSignatureLeafData],
) -> Result<TokenTransactionStatus> {
    tracing::debug!(
        "[check_spark_tx_finalization] Starting with tx_leaf_count={}, signatures={}, signature_leaf_data={}",
        tx_leaf_count,
        signatures.len(),
        signature_leaf_data.len()
    );

    let mut operator_pubkeys = BTreeSet::new();
    for sig in signatures {
        operator_pubkeys.insert(sig.operator_pubkey);
        tracing::debug!(
            "[check_spark_tx_finalization] Adding operator pubkey {} for tx hash {}",
            sig.operator_pubkey,
            sig.token_tx_hash
        );
    }

    let operator_signatures_count = operator_pubkeys.len();
    tracing::debug!(
        "[check_spark_tx_finalization] Found {} unique operator pubkeys (threshold is {})",
        operator_signatures_count,
        SPARK_THRESHOLD
    );

    // This condition is supposed to be true only if issuance is checked.
    if tx_leaf_count == 0 {
        let is_finalized = operator_signatures_count >= SPARK_THRESHOLD;
        tracing::debug!(
            "[check_spark_tx_finalization] Issuance transaction (tx_leaf_count=0): operator_signatures={}/{} required, status={}",
            operator_signatures_count,
            SPARK_THRESHOLD,
            if is_finalized { "Finalized" } else { "Started" }
        );
        return match is_finalized {
            true => Ok(TokenTransactionStatus::Finalized),
            false => Ok(TokenTransactionStatus::Started),
        };
    }

    if operator_signatures_count < SPARK_THRESHOLD {
        tracing::debug!(
            "[check_spark_tx_finalization] Operator signatures count {} is less than threshold {}, returning Started status",
            operator_signatures_count,
            SPARK_THRESHOLD
        );
        return Ok(TokenTransactionStatus::Started);
    }

    let parent_leaves_revocation_keys_indexes: HashSet<Vec<u8>> = signature_leaf_data
        .iter()
        .filter_map(|leaf_data| {
            let result = leaf_data
                .revocation_secret
                .map(|secret_key| secret_key.secret_bytes().to_vec());

            if result.is_some() {
                tracing::debug!(
                    "[check_spark_tx_finalization] Found revocation secret for leaf index {}",
                    leaf_data.token_tx_leaf_index
                );
            }

            result
        })
        .collect();

    tracing::debug!(
        "[check_spark_tx_finalization] Collected {} unique revocation secrets (need {} for all leaves)",
        parent_leaves_revocation_keys_indexes.len(),
        tx_leaf_count
    );

    let is_finalized = parent_leaves_revocation_keys_indexes.len() >= tx_leaf_count;
    tracing::debug!(
        "[check_spark_tx_finalization] Finalization check: revocation_secrets={}/{} required",
        parent_leaves_revocation_keys_indexes.len(),
        tx_leaf_count,
    );

    let result = if is_finalized {
        tracing::debug!("[check_spark_tx_finalization] Transaction is FINALIZED");
        TokenTransactionStatus::Finalized
    } else {
        tracing::debug!(
            "[check_spark_tx_finalization] Transaction is SIGNED but not finalized: missing {} revocation secrets",
            tx_leaf_count.saturating_sub(parent_leaves_revocation_keys_indexes.len()),
        );
        TokenTransactionStatus::Signed
    };

    Ok(result)
}
