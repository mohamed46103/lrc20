use std::net::SocketAddr;
use std::time::Duration;

use bitcoin::Txid;
use event_bus::{EventBus, typeid};
use eyre::{ContextCompat, Result, WrapErr};
use lrc20_storage::entities::sea_orm_active_enums::{L1TxStatus, MempoolStatus};
use lrc20_storage::traits::{
    InventoryStorage, Lrc20NodeStorage, MempoolNodeStorage, SparkNodeStorage,
};
use lrc20_types::spark::signature::SparkSignatureData;
use lrc20_types::spark::spark_hash::SparkHash;
use lrc20_types::spark::{TokenTransaction, TokenTransactionStatus, TokensFreezeData};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::trace;

use lrc20_p2p::client::handle::Handle as ClientHandle;
use lrc20_storage::PgDatabaseConnectionManager;
use lrc20_types::messages::SparkGraphBuilderMessage;
use lrc20_types::{Announcement, GraphBuilderMessage, IndexerMessage, TxCheckerMessage};
use lrc20_types::{
    ControllerMessage, ControllerP2PMessage, Lrc20Transaction, Lrc20TxType, TxConfirmMessage,
    messages::p2p::Inventory,
};

/// Default inventory size.
const DEFAULT_INV_SIZE: usize = 100;

/// Default inventory sharing interval in seconds.
const DEFAULT_INV_SHARE_INTERVAL: Duration = Duration::from_millis(500);

/// Controller handles Inv, GetData, Lrc20Tx P2P methods. Selects new transactions from outside
/// and provides it to the TransactionChecker.
#[derive(Clone)]
pub struct Controller<NodeStorage, P2pClient>
where
    NodeStorage: PgDatabaseConnectionManager + Lrc20NodeStorage + Clone,
    P2pClient: ClientHandle,
{
    /// Node's persistent storage.
    node_storage: NodeStorage,

    /// Event bus for simplifying communication with services.
    event_bus: EventBus,

    /// Max inventory size.
    max_inv_size: usize,

    /// Inventory sharing interval.
    inv_sharing_interval: Duration,

    /// P2P handle which is used for sending messages to other peers.
    p2p_handle: P2pClient,
}

impl<NS, P2P> Controller<NS, P2P>
where
    NS: PgDatabaseConnectionManager
        + Lrc20NodeStorage
        + SparkNodeStorage
        + MempoolNodeStorage
        + InventoryStorage
        + Send
        + Sync
        + Clone
        + 'static,
    P2P: ClientHandle + Send + Sync + Clone + 'static,
{
    pub fn new(full_event_bus: &EventBus, node_storage: NS, p2p_handle: P2P) -> Self {
        let event_bus = full_event_bus
            .extract(
                &typeid![
                    TxConfirmMessage,
                    TxCheckerMessage,
                    SparkGraphBuilderMessage,
                    GraphBuilderMessage,
                    IndexerMessage
                ],
                &typeid![ControllerMessage],
            )
            .expect("event channels must be presented");

        Self {
            node_storage,
            max_inv_size: DEFAULT_INV_SIZE,
            inv_sharing_interval: DEFAULT_INV_SHARE_INTERVAL,
            event_bus,
            p2p_handle,
        }
    }

    /// Sets max inventory size.
    pub fn set_max_inv_size(mut self, max_inv_size: usize) -> Self {
        self.max_inv_size = max_inv_size;

        self
    }

    /// Sets inventory sharing interval.
    pub fn set_inv_sharing_interval(mut self, interval: Duration) -> Self {
        self.inv_sharing_interval = interval;

        self
    }

    /// Runs the Controller. It listens to the events from the event bus to handle and
    /// inventory interval timer to share inventory.
    pub async fn run(mut self, cancellation: CancellationToken) {
        let events = self.event_bus.subscribe::<ControllerMessage>();
        let mut inv_ticker = tokio::time::interval(self.inv_sharing_interval);

        loop {
            tokio::select! {
                event_received = events.recv() => {
                    let Ok(event) = event_received else {
                        trace!("All incoming event senders are dropped");
                        return;
                    };

                    if let Err(err) = self.handle_event(event).await {
                        tracing::error!("Failed to handle an event: {}", err);
                    }
                }
                _ = inv_ticker.tick() => {
                    if let Err(err) = self.share_inv().await {
                        tracing::error!("Failed to share an inventory: {}", err);
                    }
                }
                _ = cancellation.cancelled() => {
                    trace!("Cancellation received, stopping controller");
                    return;
                }
            }
        }
    }

    /// Handles new events from the event bus.
    async fn handle_event(&mut self, event: ControllerMessage) -> Result<()> {
        use ControllerMessage as Message;
        trace!("New event: {:?}", event);

        match event {
            Message::InvalidTxs(tx_ids) => self
                .handle_invalid_txs(tx_ids)
                .await
                .wrap_err("failed to handle invalid txs")?,
            Message::GetData { inv, receiver } => self
                .send_get_data(receiver, inv.clone())
                .await
                .wrap_err("failed to handle get lrc20 tx data")?,
            Message::AttachedTxs(tx_ids) => self
                .handle_attached_txs(tx_ids.clone())
                .await
                .wrap_err_with(move || {
                    format!("failed to handle attached txs; txs={:?}", tx_ids)
                })?,
            Message::P2P(p2p_event) => self
                .handle_p2p_msg(p2p_event)
                .await
                .wrap_err("failed to handle p2p event")?,
            Message::InitializeTxs(txs) => self
                .handle_new_lrc20_txs(txs, None)
                .await
                .wrap_err("failed to handle transactions to initialize")?,
            Message::PartiallyCheckedTxs(txids) => {
                self.handle_partially_checked_txs(txids)
                    .await
                    .wrap_err("failed to handle partially checked transactions")?
            }
            Message::MinedTxs(txids) => self
                .handle_mined_txs(txids)
                .await
                .wrap_err("failed to handle mined transactions")?,
            Message::FullyCheckedTxs(txs) => self
                .handle_fully_checked_txs(txs)
                .await
                .wrap_err("failed to handle fully checked txs")?,
            Message::ConfirmedTxs(txids) => self
                .handle_confirmed_txs(txids)
                .await
                .wrap_err("failed to handle confirmed transactions")?,
            Message::Reorganization {
                txs,
                new_indexing_height,
            } => self
                .handle_reorganization(txs, new_indexing_height)
                .await
                .wrap_err("failed to handle reorged transactions")?,
            Message::InitialIndexingFinished => self
                .handle_initial_sync_finished()
                .await
                .wrap_err("failed to handle the initial indexing")?,
            Message::NewSparkTxs(spark_txs, callback) => self
                .handle_new_spark_txs(spark_txs, None, callback)
                .await
                .wrap_err("failed to handle new spark txs")?,
            Message::NewSparkSignaturesRequest(request, callback) => self
                .handle_spark_token_tx_signature(request, None, callback)
                .await
                .wrap_err("failed to handle spark tx finalization")?,
            Message::NewFreezeTokensRequest(request) => self
                .handle_tokens_freeze_request(request, None)
                .await
                .wrap_err("failed to handle spark tx finalization")?,
            Message::CheckedSparkTxs(spark_txs) => {
                self.handle_checked_spark_txs(spark_txs)
                    .await
                    .wrap_err("failed to handle checked spark txs")?
            }
            Message::CheckedSparkFreezeData(data) => self
                .handle_checked_spark_freeze_data(data)
                .await
                .wrap_err("failed to handle checked spark freezes")?,
            Message::AttachedSparkTxs(txs) => self
                .handle_attached_spark_txs(txs)
                .await
                .wrap_err("failed to handle attached spark txs")?,
        }

        Ok(())
    }

    /// Handles a P2P event.
    pub async fn handle_p2p_msg(&mut self, message: ControllerP2PMessage) -> Result<()> {
        match message {
            ControllerP2PMessage::Inv { inv, sender } => self
                .handle_inv(inv, sender)
                .await
                .wrap_err("failed to handle inbound inv")?,
            ControllerP2PMessage::GetData { inv, sender } => self
                .handle_get_data(inv, sender)
                .await
                .wrap_err("failed to handle inbound get data")?,
            ControllerP2PMessage::Lrc20Tx { txs, sender } => self
                .handle_new_lrc20_txs(txs, Some(sender))
                .await
                .wrap_err("failed to handle lrc20 txs")?,
            ControllerP2PMessage::SparkTxs { txs, sender } => self
                .handle_new_spark_txs(txs, Some(sender), None)
                .await
                .wrap_err("failed to handle spark txs")?,
            ControllerP2PMessage::SparkSignatureData { data, sender } => self
                .handle_spark_token_tx_signature(data, Some(sender), None)
                .await
                .wrap_err("failed to handle spark signature data")?,
        };

        Ok(())
    }

    /// Fetch transactions from the mempool and distribute them among the workers depending on
    /// their statuses.
    pub async fn handle_mempool_txs(&mut self) -> eyre::Result<()> {
        let raw_mempool = self.node_storage.get_mempool().await?;
        if raw_mempool.is_empty() {
            tracing::debug!("No transactions found in the mempool");
            return Ok(());
        }

        let mut txs_for_check = Vec::new();
        let mut txs_for_attach = Vec::new();
        let mut txs_for_confirm = Vec::new();
        for (tx, status, _) in raw_mempool {
            match status {
                #[allow(deprecated)]
                MempoolStatus::Initialized | MempoolStatus::Pending => {
                    txs_for_check.push(tx);
                }
                MempoolStatus::Attaching => {
                    txs_for_attach.push(tx);
                }
                // If the transaction is mined or waiting to be mined, just send it back to the
                // confrimator.
                _ => {
                    txs_for_confirm.push(tx.bitcoin_tx.txid());
                }
            }
        }

        if !txs_for_check.is_empty() {
            self.event_bus
                .send(TxCheckerMessage::IsolatedCheck(txs_for_check))
                .await
        }
        if !txs_for_attach.is_empty() {
            self.event_bus
                .send(GraphBuilderMessage::CheckedTxs(txs_for_attach))
                .await
        }
        if !txs_for_confirm.is_empty() {
            self.event_bus
                .send(TxConfirmMessage::Txs(txs_for_confirm))
                .await;
        }

        Ok(())
    }

    /// Handles invalid transactions. It removes them from the
    /// [`handling_txs`](Controller::handling_txs) and if the transaction was received from the
    /// network, it will send event to the network service that the sender peer is malicious.
    async fn handle_invalid_txs(&self, txids: Vec<Txid>) -> Result<()> {
        let mempool = self
            .node_storage
            .get_mempool_by_txids(txids.clone())
            .await?;
        self.node_storage.delete_mempool_txs(txids).await?;

        for (tx, _, sender) in mempool {
            let txid = tx.bitcoin_tx.txid();

            tracing::debug!(
                txid = txid.to_string(),
                "Deleting invalid tx from the mempool"
            );

            if let Some(sender) = sender {
                self.p2p_handle.ban_peer(sender).await.wrap_err_with(|| {
                    format!("failed to punish peer; malicious_peer={:?}", sender,)
                })?;
            };

            if matches!(tx.tx_type, Lrc20TxType::Issue { .. }) {
                self.node_storage
                    .set_lrc20_tx_status(txid, L1TxStatus::InvalidIssue)
                    .await?;

                continue;
            }

            self.node_storage.delete_lrc20_transaction(txid).await?;
        }

        Ok(())
    }

    /// Shares inventory with the network.
    async fn share_inv(&self) -> Result<()> {
        let mut txid_inv = self
            .node_storage
            .get_lrc20_inventory(self.max_inv_size)
            .await?
            .iter()
            .map(Inventory::from)
            .collect::<Vec<_>>();

        let mut spark_inv: Vec<Inventory> = self
            .node_storage
            .get_token_txs_inventory(self.max_inv_size)
            .await?
            .iter()
            .map(|hash| Inventory::SparkTx(**hash))
            .collect();

        let mut freezes_inv: Vec<Inventory> = self
            .node_storage
            .get_spark_freezes_inventory()
            .await?
            .iter()
            .map(|freeze| Inventory::SparkFreeze(*freeze))
            .collect();

        txid_inv.append(&mut spark_inv);
        txid_inv.append(&mut freezes_inv);

        self.p2p_handle
            .send_inv(txid_inv.clone())
            .await
            .wrap_err_with(|| format!("failed to share inventory; inv={:?}", txid_inv))?;

        tracing::trace!("Inventory has been shared");

        Ok(())
    }

    /// Handles an inv message from the network. It checks if the transaction is already
    /// handled. If not, it will request the transaction from the [`Inv`] sender.
    async fn handle_inv(&mut self, inv: Vec<Inventory>, sender: SocketAddr) -> Result<()> {
        tracing::trace!("Received inv from peer: {:?}", sender);

        let mut missing_tx_payload = Vec::<Inventory>::default();

        for inv_msg in inv {
            match inv_msg {
                Inventory::Ltx(ltx_id) => {
                    let existing_tx_opt = self
                        .is_tx_exist(&ltx_id)
                        .await
                        .wrap_err("failed to check if tx exist")?;

                    let Some(existing_tx) = existing_tx_opt else {
                        missing_tx_payload.push(Inventory::Ltx(ltx_id));
                        continue;
                    };

                    let is_announcement = matches!(
                        existing_tx.tx_type,
                        Lrc20TxType::Announcement(Announcement::Issue(_))
                    );

                    if is_announcement {
                        missing_tx_payload.push(Inventory::Ltx(ltx_id));
                    }
                }
                Inventory::SparkTx(hash) | Inventory::SparkSignatures(hash) => {
                    if self
                        .node_storage
                        .get_spark_tx_with_outputs(SparkHash(hash))
                        .await?
                        .is_none()
                    {
                        missing_tx_payload.push(Inventory::SparkTx(hash));
                        continue;
                    };

                    let spark_hash = hash.into();
                    let tx_status = self
                        .node_storage
                        .get_token_transaction_status(spark_hash)
                        .await?;

                    if !matches!(tx_status, TokenTransactionStatus::Finalized) {
                        missing_tx_payload.push(Inventory::SparkSignatures(hash));
                    }
                }
                Inventory::SparkFreeze(data) => {
                    let is_frozen = self
                        .node_storage
                        .is_pubkey_frozen(data.owner_public_key, data.token_public_key.into())
                        .await?;

                    let should_handle_freeze = (data.should_unfreeze && is_frozen)
                        || (!data.should_unfreeze && !is_frozen);

                    if should_handle_freeze {
                        self.handle_tokens_freeze_request(vec![data], Some(sender))
                            .await?;
                    }
                }
            }
        }

        if !missing_tx_payload.is_empty() {
            tracing::debug!(
                "Requesting txs from peer {:?}: {:?}",
                sender,
                missing_tx_payload
            );

            self.p2p_handle
                .send_get_data(missing_tx_payload, sender)
                .await
                .wrap_err("failed to send getdata message")?;
        }

        Ok(())
    }

    /// Handles a get data message from the network. It checks if the transaction is presented
    /// in the storage. If yes, it sends the transaction to the [`GetData`] message sender.
    async fn handle_get_data(&mut self, payload: Vec<Inventory>, sender: SocketAddr) -> Result<()> {
        let mut response_lrc20_txs = Vec::new();
        let mut response_spark_txs = Vec::new();
        let mut response_spark_signatures = Vec::new();

        for payload_msg in payload {
            match payload_msg {
                Inventory::Ltx(ltx_id) => {
                    let lrc20_tx = self
                        .node_storage
                        .get_lrc20_transaction_by_id(ltx_id)
                        .await?;

                    if let Some(tx) = lrc20_tx {
                        response_lrc20_txs.push(tx);
                    };
                }
                Inventory::SparkTx(hash) => {
                    let spark_hash = SparkHash(hash);
                    let spark_tx = self
                        .node_storage
                        .get_spark_tx_with_outputs(spark_hash)
                        .await?;

                    if let Some(spark_tx) = spark_tx {
                        response_spark_txs.push(spark_tx);
                    }
                }
                Inventory::SparkSignatures(hash) => {
                    let spark_hash = SparkHash(hash);
                    let spark_sigs = self.node_storage.get_spark_signatures(spark_hash).await?;

                    response_spark_signatures.extend(spark_sigs);
                }
                Inventory::SparkFreeze { .. } => {
                    unreachable!(
                        "Nodes should not request freeze data as it is already included in the shareinv message"
                    )
                }
            }
        }

        if !response_lrc20_txs.is_empty() {
            self.p2p_handle
                .send_lrc20_txs(response_lrc20_txs, sender)
                .await
                .wrap_err("failed to send lrc20tx message")?;
        }
        if !response_spark_txs.is_empty() {
            self.p2p_handle
                .send_spark_txs(response_spark_txs, sender)
                .await
                .wrap_err("failed to send sparktx message")?;
        }
        if !response_spark_signatures.is_empty() {
            self.p2p_handle
                .send_spark_signatures(response_spark_signatures, sender)
                .await
                .wrap_err("failed to send sparksig message")?;
        }
        tracing::info!("Received get data from peer: {:?}", sender);

        Ok(())
    }

    /// Handles lrc20 txs from the network. It checks if the transaction is already handled. If
    /// not, it sends the transaction to the `TxChecker`.
    async fn handle_new_lrc20_txs(
        &mut self,
        lrc20_txs: Vec<Lrc20Transaction>,
        sender: Option<SocketAddr>,
    ) -> Result<()> {
        let mut new_txs = Vec::new();

        for lrc20_tx in lrc20_txs {
            let tx_id = lrc20_tx.bitcoin_tx.txid();
            let existing_tx_opt = self
                .is_tx_exist(&tx_id)
                .await
                .wrap_err("failed to check if tx exists")?;

            let Some(existing_tx) = existing_tx_opt else {
                self.node_storage
                    .insert_lrc20_transaction(lrc20_tx.clone())
                    .await?;

                self.node_storage
                    .put_mempool_transaction(lrc20_tx.bitcoin_tx.txid(), sender)
                    .await?;

                tracing::debug!(
                    txid = tx_id.to_string(),
                    "Added initialized tx to the mempool"
                );

                new_txs.push(lrc20_tx);

                continue;
            };

            // If the newly arrived tx is an issuance, and an issue announcement for this
            // issue has been previously indexed, we should still handle the transaction
            // to override the issue announcement with an actual issuance.
            let is_issuance = matches!(lrc20_tx.tx_type, Lrc20TxType::Issue { .. });
            let does_announcement_exist = matches!(
                existing_tx.tx_type,
                Lrc20TxType::Announcement(Announcement::Issue(..))
            );
            if !(is_issuance && does_announcement_exist) {
                tracing::debug!(txid = tx_id.to_string(), "Tx exists in the storage");
                continue;
            }

            self.node_storage
                .insert_lrc20_transaction(lrc20_tx.clone())
                .await?;
            self.node_storage
                .put_mempool_transaction(tx_id, sender)
                .await?;

            new_txs.push(lrc20_tx);
        }

        if !new_txs.is_empty() {
            let txids: Vec<Txid> = new_txs.iter().map(|tx| tx.bitcoin_tx.txid()).collect();
            if let Some(sender) = sender {
                tracing::debug!("Received new lrc20 txs from {}: {:?}", sender, txids);
            } else {
                tracing::debug!("Received new lrc20 txs: {:?}", txids);
            }

            self.event_bus
                .send(TxCheckerMessage::IsolatedCheck(new_txs))
                .await;
        }

        Ok(())
    }

    /// Handles LRC20 transactions that passed the isolated checks and changes their statuses from
    /// `Initialized` to `WaitingMined`, then sends them to the tx confirmator.
    pub async fn handle_partially_checked_txs(&mut self, txids: Vec<Txid>) -> Result<()> {
        let mut lrc20_txs = Vec::new();

        for txid in txids {
            self.node_storage
                .update_mempool_tx_status(txid, MempoolStatus::WaitingMined)
                .await?;

            tracing::debug!(
                txid = txid.to_string(),
                "Tx has passed the isolated check and is waiting to be mined"
            );

            lrc20_txs.push(txid);
        }

        self.event_bus.send(TxConfirmMessage::Txs(lrc20_txs)).await;

        Ok(())
    }

    /// Handles LRC20 transactions that passed the full check and changes their statuses from
    /// `Mined` to `Attaching`, then sends them to the graph builder.
    pub async fn handle_fully_checked_txs(
        &mut self,
        lrc20_txs: Vec<Lrc20Transaction>,
    ) -> Result<()> {
        let mut non_announcement_txs = Vec::new();
        let mut announcement_txs = Vec::new();

        for lrc20_tx in lrc20_txs {
            tracing::debug!(
                txid = lrc20_tx.bitcoin_tx.txid().to_string(),
                "Tx has passed the full check and is waiting to be attached"
            );

            if matches!(lrc20_tx.tx_type, Lrc20TxType::Announcement(_)) {
                announcement_txs.push(lrc20_tx);
                continue;
            }

            self.node_storage
                .update_mempool_tx_status(lrc20_tx.bitcoin_tx.txid(), MempoolStatus::Attaching)
                .await?;

            non_announcement_txs.push(lrc20_tx);
        }

        if !announcement_txs.is_empty() {
            self.handle_checked_announcements(announcement_txs).await?;
        }

        if !non_announcement_txs.is_empty() {
            self.event_bus
                .send(GraphBuilderMessage::CheckedTxs(non_announcement_txs))
                .await;
        }

        Ok(())
    }

    /// Sends transactions that appeared in reorged blocks back to the confirmator.
    pub async fn handle_reorganization(
        &mut self,
        txids: Vec<Txid>,
        new_indexing_height: usize,
    ) -> Result<()> {
        self.event_bus
            .send(IndexerMessage::Reorganization(new_indexing_height))
            .await;

        if txids.is_empty() {
            return Ok(());
        }

        tracing::debug!("Reorged LRC20 transactions: {:?}", txids);

        for txid in &txids {
            self.node_storage
                .update_mempool_tx_status(*txid, MempoolStatus::WaitingMined)
                .await?;
        }

        self.event_bus.send(TxConfirmMessage::Txs(txids)).await;

        Ok(())
    }

    /// Handles LRC20 transactions that reached enough confirmations and sends them to the tx checker
    /// for a full check.
    pub async fn handle_confirmed_txs(&mut self, txids: Vec<Txid>) -> Result<()> {
        let mut announcement_lrc20_txs = Vec::new();
        let mut lrc20_txs = Vec::new();

        let mempool_entries = self.node_storage.get_mempool_by_txids(txids).await?;

        for (tx, _, sender) in mempool_entries {
            tracing::debug!(
                txid = tx.bitcoin_tx.txid().to_string(),
                "Tx has reached enough confirmations"
            );

            if matches!(tx.tx_type, Lrc20TxType::Announcement(_)) {
                announcement_lrc20_txs.push((tx, sender));
            } else {
                lrc20_txs.push((tx, sender));
            }
        }

        announcement_lrc20_txs.extend(lrc20_txs);
        self.event_bus
            .send(TxCheckerMessage::FullCheck(announcement_lrc20_txs))
            .await;

        Ok(())
    }

    pub async fn handle_spark_token_tx_signature(
        &mut self,
        request: Vec<SparkSignatureData>,
        _sender: Option<SocketAddr>,
        callback: Option<mpsc::Sender<bool>>,
    ) -> Result<()> {
        self.event_bus
            .send(TxCheckerMessage::SparkSignatureCheck(request, callback))
            .await;

        Ok(())
    }

    pub async fn handle_tokens_freeze_request(
        &mut self,
        request: Vec<TokensFreezeData>,
        _sender: Option<SocketAddr>,
    ) -> Result<()> {
        self.event_bus
            .send(TxCheckerMessage::TokensFreezeCheck(request))
            .await;

        Ok(())
    }

    /// Handles new Spark transactions and sends them to the tx checker
    /// for a full check.
    pub async fn handle_new_spark_txs(
        &mut self,
        txs: Vec<TokenTransaction>,
        sender: Option<SocketAddr>,
        callback: Option<mpsc::Sender<bool>>,
    ) -> Result<()> {
        let mut new_spark_txs = Vec::new();
        for tx in &txs {
            let spark_tx_hash = tx.hash();
            if self
                .node_storage
                .get_spark_transaction_model_by_hash(spark_tx_hash)
                .await?
                .is_some()
            {
                tracing::info!(
                    hash = spark_tx_hash.to_string(),
                    "Skipping existing Spark transaction"
                );

                continue;
            }

            self.node_storage.insert_spark_transaction(tx).await?;

            tracing::info!(
                hash = spark_tx_hash.to_string(),
                "Got a new Spark transaction"
            );

            new_spark_txs.push(tx.clone());
        }

        self.event_bus
            .send(TxCheckerMessage::SparkCheck((
                new_spark_txs,
                sender,
                callback,
            )))
            .await;

        Ok(())
    }

    pub async fn handle_checked_spark_txs(
        &mut self,
        spark_txs: Vec<TokenTransaction>,
    ) -> Result<()> {
        for spark_tx in &spark_txs {
            tracing::debug!(
                hash = spark_tx.hash().to_string(),
                "Spark tx has passed the full check and is waiting to be attached"
            );
        }

        if !spark_txs.is_empty() {
            self.event_bus
                .send(SparkGraphBuilderMessage::CheckedTxs(spark_txs))
                .await;
        }

        Ok(())
    }

    pub async fn handle_checked_spark_freeze_data(
        &mut self,
        freeze_data: Vec<TokensFreezeData>,
    ) -> Result<()> {
        for freeze in &freeze_data {
            tracing::info!(
                owner_pubkey = freeze.owner_public_key.to_string(),
                token_pubkey = freeze.token_public_key.to_string(),
                should_unfreeze = freeze.should_unfreeze,
                "Spark freeze data is valid"
            );

            let _is_frozen = self
                .node_storage
                .is_pubkey_frozen(freeze.owner_public_key, freeze.token_public_key.into())
                .await?;

            // TODO: handle pubkey freeze
            // self.state_storage
            //     .put_frozen_pubkey(&freeze.owner_public_key, entry)
            //     .await?;
        }

        tracing::info!("Inventory has been updated with checked freeze data");

        Ok(())
    }

    /// Handles LRC20 transactions that reached one confirmation and changes their statuses from
    /// `WaitingMined` to `Mined`, then adds them to the inventory so they can be broadcasted
    /// via P2P.
    pub async fn handle_mined_txs(&mut self, txids: Vec<Txid>) -> Result<()> {
        let mut txids_to_share = Vec::new();

        for txid in txids {
            let (tx, _, _) = self
                .node_storage
                .get_mempool_transaction(txid)
                .await?
                .wrap_err("Waiting tx is not present in the mempool")?;

            if !matches!(tx.tx_type, Lrc20TxType::Announcement(_)) {
                txids_to_share.push(txid);
            }

            self.node_storage
                .update_mempool_tx_status(txid, MempoolStatus::Mined)
                .await?;
        }

        tracing::info!("Inventory has been updated with checked and mined txs");

        Ok(())
    }

    /// Handles attached transactions by removing them from the mempool.
    pub async fn handle_attached_txs(&mut self, txids: Vec<Txid>) -> Result<()> {
        for txid in &txids {
            tracing::info!(txid = txid.to_string(), "Tx is attached");
            tracing::debug!(?txid, "Deleting attached tx from the mempool");

            self.node_storage
                .set_lrc20_tx_status(*txid, L1TxStatus::Attached)
                .await?;
            self.node_storage.delete_mempool_entry(*txid).await?;
        }

        Ok(())
    }

    // Handles attached transactions
    // Todo: this function is useless
    pub async fn handle_attached_spark_txs(&mut self, txs: Vec<TokenTransaction>) -> Result<()> {
        let mut hashes_to_share = Vec::new();

        for tx in txs {
            if self
                .node_storage
                .get_spark_transaction_model_by_hash(tx.hash())
                .await?
                .is_some()
            {
                continue;
            }

            let hash: SparkHash = tx.hash();
            hashes_to_share.push(*hash);
            tracing::info!(txid = hash.to_string(), "Spark tx is attached");
        }

        Ok(())
    }

    /// Handles checked announcement. It removes it from the mempool.
    pub async fn handle_checked_announcements(
        &mut self,
        announcement_txs: Vec<Lrc20Transaction>,
    ) -> Result<()> {
        for announcement_tx in announcement_txs {
            let announcement_txid = announcement_tx.bitcoin_tx.txid();
            tracing::debug!(
                txid = announcement_txid.to_string(),
                "Removing announcement from mempool"
            );

            self.node_storage
                .delete_mempool_entry(announcement_txid)
                .await?;

            self.node_storage
                .set_lrc20_tx_status(announcement_txid, L1TxStatus::Attached)
                .await?;

            tracing::info!(
                txid = announcement_txid.to_string(),
                "Announcement is handled"
            );
        }

        Ok(())
    }

    pub async fn send_get_data(
        &mut self,
        receiver: SocketAddr,
        tx_ids: Vec<Inventory>,
    ) -> Result<()> {
        self.p2p_handle
            .send_get_data(tx_ids.clone(), receiver)
            .await
            .wrap_err_with(|| {
                format!(
                    "failed to send get data request; receiver={:?}; tx_ids={:?}",
                    receiver.clone(),
                    tx_ids,
                )
            })?;

        tracing::info!("Sent get data request to peer: {:?}", receiver);

        Ok(())
    }

    /// Handles the finish of the initial sync. Sends a message to the P2P indicating that it can
    /// start handling events.
    async fn handle_initial_sync_finished(&self) -> Result<()> {
        tracing::info!("Handling the initial sync");

        self.p2p_handle.start().await?;

        tracing::info!("Handled the initial sync");

        Ok(())
    }

    async fn is_tx_exist(&self, tx_id: &Txid) -> Result<Option<Lrc20Transaction>> {
        let lrc20_tx = self
            .node_storage
            .get_lrc20_transaction_by_id(*tx_id)
            .await?;

        if let Some(lrc20_tx) = lrc20_tx {
            return Ok(Some(lrc20_tx));
        }

        Ok(None)
    }
}
