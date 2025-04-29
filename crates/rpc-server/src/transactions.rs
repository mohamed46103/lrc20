use async_trait::async_trait;
use bitcoin::{Amount, BlockHash, OutPoint, Txid, secp256k1::PublicKey};
use bitcoin_client::{BitcoinRpcApi, Error as BitcoinClientError, JsonRpcError};
use event_bus::{EventBus, typeid};
use jsonrpsee::{
    core::RpcResult,
    types::{
        ErrorObject, ErrorObjectOwned,
        error::{INTERNAL_ERROR_CODE, INVALID_REQUEST_CODE},
    },
};
use lrc20_receipts::{ReceiptProof, TokenPubkey};
use lrc20_rpc_api::transactions::{
    EmulateLrc20TransactionResponse, GetRawLrc20TransactionResponseHex,
    GetRawLrc20TransactionResponseJson, Lrc20TransactionResponse, Lrc20TransactionStatus,
    Lrc20TransactionsRpcServer, ProvideLrc20ProofRequest,
};
use lrc20_storage::{
    PgDatabaseConnectionManager,
    traits::{Lrc20NodeStorage, MempoolNodeStorage},
};
use lrc20_tx_check::{CheckError, check_p2tr_proof, check_transaction};
use lrc20_types::{
    ControllerMessage, Lrc20Transaction, Lrc20TxType, ProofMap, announcements::TokenPubkeyInfo,
};
use sea_orm::DbErr;
use std::sync::Arc;

/// Bitcoin rpc error code which identifies that transaction is already in chain.
const BTC_RPC_VERIFY_ALREADY_IN_CHAIN: i32 = -27;

// TODO: Rename to "RpcController"
/// Controller for transactions from RPC.
pub struct TransactionsController<NodeStorage, BitcoinClient> {
    /// Max items per request
    max_items_per_request: usize,
    /// Page size for querying paginated data
    page_size: u64,
    /// Node persistent storage.
    node_storage: NodeStorage,
    /// Event bus for simplifying communication with services.
    event_bus: EventBus,
    /// Bitcoin RPC Client.
    bitcoin_client: Arc<BitcoinClient>,
}

impl<NS, BC> TransactionsController<NS, BC>
where
    NS: PgDatabaseConnectionManager + Lrc20NodeStorage + MempoolNodeStorage + Send + Sync + 'static,
    BC: BitcoinRpcApi + Send + Sync + 'static,
{
    pub fn new(
        node_storage: NS,
        full_event_bus: EventBus,
        bitcoin_client: Arc<BC>,
        max_items_per_request: usize,
        page_size: u64,
    ) -> Self {
        let event_bus = full_event_bus
            .extract(&typeid![ControllerMessage], &typeid![])
            .expect("event channels must be presented");

        Self {
            max_items_per_request,
            node_storage,
            event_bus,
            bitcoin_client,
            page_size,
        }
    }
}

impl<NS, BC> TransactionsController<NS, BC>
where
    NS: PgDatabaseConnectionManager + Lrc20NodeStorage + Send + Sync + 'static,
    BC: BitcoinRpcApi + Send + Sync + 'static,
{
    async fn send_txs_to_confirm(&self, lrc20_txs: Vec<Lrc20Transaction>) -> RpcResult<()> {
        // Send message to message handler about new tx with proof.
        self.event_bus
            .try_send(ControllerMessage::InitializeTxs(lrc20_txs))
            .await
            // If we failed to send message to message handler, then it's dead.
            .map_err(|_| {
                tracing::error!("failed to send message to message handler");
                ErrorObjectOwned::owned(
                    INTERNAL_ERROR_CODE,
                    "Service is dead",
                    Option::<Vec<u8>>::None,
                )
            })?;

        Ok(())
    }
}

#[async_trait]
impl<NS, BC> Lrc20TransactionsRpcServer for TransactionsController<NS, BC>
where
    NS: PgDatabaseConnectionManager
        + Lrc20NodeStorage
        + MempoolNodeStorage
        + Clone
        + Send
        + Sync
        + 'static,
    BC: BitcoinRpcApi + Send + Sync + 'static,
{
    /// Handle new LRC20 transaction with proof to check.
    async fn provide_lrc20_proof(&self, lrc20_tx: Lrc20Transaction) -> RpcResult<bool> {
        // Send message to message handler to wait its confirmation.
        self.send_txs_to_confirm(vec![lrc20_tx]).await?;

        Ok(true)
    }

    /// Handle new LRC20 transaction with proof to check.
    async fn provide_lrc20_proof_short(
        &self,
        txid: Txid,
        tx_type: String,
        blockhash: Option<BlockHash>,
    ) -> RpcResult<bool> {
        let tx_type = Lrc20TxType::from_hex(tx_type).map_err(|err| {
            tracing::error!("Failed to parse tx type hex: {err}");
            ErrorObjectOwned::owned(
                INVALID_REQUEST_CODE,
                "Hex parse error",
                Option::<Vec<u8>>::None,
            )
        })?;

        self.provide_list_lrc20_proofs(vec![ProvideLrc20ProofRequest::new(
            txid, tx_type, blockhash,
        )])
        .await
    }

    async fn provide_list_lrc20_proofs(
        &self,
        proofs: Vec<ProvideLrc20ProofRequest>,
    ) -> RpcResult<bool> {
        if proofs.len() > self.max_items_per_request {
            return Err(ErrorObject::owned(
                INVALID_REQUEST_CODE,
                format!(
                    "Too many lrc20_txs, max amount is {}",
                    self.max_items_per_request
                ),
                Option::<Vec<u8>>::None,
            ));
        }

        let mut lrc20_txs = Vec::with_capacity(proofs.len());
        for proof in proofs {
            let bitcoin_tx = self
                .bitcoin_client
                .get_raw_transaction(&proof.txid, proof.blockhash)
                .await
                .map_err(map_bitcoin_error)?;

            let lrc20_tx = Lrc20Transaction::new(bitcoin_tx, proof.tx_type);
            lrc20_txs.push(lrc20_tx);
        }

        // Send message to message handler to wait its confirmation.
        self.send_txs_to_confirm(lrc20_txs).await?;

        Ok(true)
    }

    async fn get_raw_lrc20_transaction(
        &self,
        txid: Txid,
    ) -> RpcResult<GetRawLrc20TransactionResponseJson> {
        let tx = self
            .node_storage
            .get_lrc20_transaction_by_id(txid)
            .await
            .map_err(|e| {
                ErrorObject::owned(INTERNAL_ERROR_CODE, e.to_string(), Option::<Vec<u8>>::None)
            })?;

        match tx {
            Some(tx) => Ok(GetRawLrc20TransactionResponseJson::new(
                Lrc20TransactionStatus::Attached,
                Some(tx.into()),
            )),
            None => Ok(GetRawLrc20TransactionResponseJson::new(
                Lrc20TransactionStatus::None,
                None,
            )),
        }
    }

    async fn get_lrc20_transaction(
        &self,
        txid: Txid,
    ) -> RpcResult<GetRawLrc20TransactionResponseHex> {
        let tx = self
            .node_storage
            .get_lrc20_transaction_by_id(txid)
            .await
            .map_err(|e| {
                ErrorObject::owned(INTERNAL_ERROR_CODE, e.to_string(), Option::<Vec<u8>>::None)
            })?;

        match tx {
            Some(tx) => Ok(GetRawLrc20TransactionResponseHex::new(
                Lrc20TransactionStatus::Attached,
                Some(tx.into()),
            )),
            None => Ok(GetRawLrc20TransactionResponseHex::new(
                Lrc20TransactionStatus::None,
                None,
            )),
        }
    }

    async fn get_raw_lrc20_mempool(&self) -> RpcResult<Vec<GetRawLrc20TransactionResponseHex>> {
        let mempool = self.node_storage.get_mempool().await.map_err(|e| {
            tracing::error!("Failed to get the mempool: {e}");
            ErrorObject::owned(
                INTERNAL_ERROR_CODE,
                "Mempool is not available",
                Option::<Vec<u8>>::None,
            )
        })?;

        let mut mempool_response = Vec::new();
        for mempool_entry in mempool {
            let status = mempool_entry.1;
            let tx = mempool_entry.0;
            let raw_lrc20_tx_response =
                GetRawLrc20TransactionResponseHex::new(status.into(), Some(tx.into()));

            mempool_response.push(raw_lrc20_tx_response)
        }

        Ok(mempool_response)
    }

    async fn get_list_raw_lrc20_transactions(
        &self,
        txids: Vec<Txid>,
    ) -> RpcResult<Vec<Lrc20TransactionResponse>> {
        if txids.len() > self.max_items_per_request {
            return Err(ErrorObject::owned(
                INVALID_REQUEST_CODE,
                format!(
                    "Too many txids, max amount is {}",
                    self.max_items_per_request
                ),
                Option::<Vec<u8>>::None,
            ));
        }

        let mut result = Vec::new();

        for txid in &txids {
            let tx = self
                .node_storage
                .get_lrc20_transaction_by_id(*txid)
                .await
                .map_err(|e| {
                    ErrorObject::owned(INTERNAL_ERROR_CODE, e.to_string(), Option::<Vec<u8>>::None)
                })?;

            if let Some(tx) = tx {
                result.push(tx.into())
            };
        }

        Ok(result)
    }

    async fn get_list_lrc20_transactions(
        &self,
        txids: Vec<Txid>,
    ) -> RpcResult<Vec<GetRawLrc20TransactionResponseHex>> {
        if txids.len() > self.max_items_per_request {
            return Err(ErrorObject::owned(
                INVALID_REQUEST_CODE,
                format!(
                    "Too many txids, max amount is {}",
                    self.max_items_per_request
                ),
                Option::<Vec<u8>>::None,
            ));
        }

        let mut result: Vec<GetRawLrc20TransactionResponseHex> = Vec::new();

        for txid in txids {
            result.push(self.get_lrc20_transaction(txid).await?)
        }

        Ok(result)
    }

    async fn list_lrc20_transactions(&self, page: u64) -> RpcResult<Vec<Lrc20TransactionResponse>> {
        let txs = self
            .node_storage
            .get_lrc_20_transactions(self.page_size, page)
            .await
            .map_err(|e| {
                tracing::error!("Failed to get lrc20 txs: {e}");
                ErrorObject::owned(
                    INTERNAL_ERROR_CODE,
                    "Storage is not available",
                    Option::<Vec<u8>>::None,
                )
            })?;

        Ok(txs
            .into_iter()
            .map(Lrc20TransactionResponse::from)
            .collect())
    }

    /// Send signed LRC20 transaction to Bitcoin network and validate it after it's confirmed.
    async fn send_lrc20_tx(
        &self,
        lrc20_tx: String,
        max_burn_amount: Option<u64>,
    ) -> RpcResult<bool> {
        let max_burn_amount_btc: Option<f64> = max_burn_amount
            .map(|max_burn_amount_sat| Amount::from_sat(max_burn_amount_sat).to_btc());

        let lrc20_tx = Lrc20Transaction::from_hex(lrc20_tx).map_err(|err| {
            tracing::error!("Failed to parse LRC20 tx hex: {err}");
            ErrorObjectOwned::owned(
                INVALID_REQUEST_CODE,
                "Hex parse error",
                Option::<Vec<u8>>::None,
            )
        })?;

        let send_tx_result = self
            .bitcoin_client
            .send_raw_transaction_opts(&lrc20_tx.bitcoin_tx, None, max_burn_amount_btc)
            .await;

        match send_tx_result {
            Ok(_) => {}
            Err(bitcoin_client::Error::JsonRpc(JsonRpcError::Rpc(err)))
                if err.code == BTC_RPC_VERIFY_ALREADY_IN_CHAIN => {}
            Err(err) => return Err(map_bitcoin_error(err)),
        }

        // Send message to message handler to wait its confirmation.
        self.send_txs_to_confirm(vec![lrc20_tx]).await?;

        Ok(true)
    }

    /// Send signed raw LRC20 transaction to Bitcoin network and validate it after it's confirmed.
    ///
    /// NOTE: this method will soon accept only hex encoded LRC20 txs.
    async fn send_raw_lrc20_tx(
        &self,
        lrc20_tx: Lrc20Transaction,
        max_burn_amount_sat: Option<u64>,
    ) -> RpcResult<bool> {
        let max_burn_amount_btc: Option<f64> = max_burn_amount_sat
            .map(|max_burn_amount_sat| Amount::from_sat(max_burn_amount_sat).to_btc());

        let send_tx_result = self
            .bitcoin_client
            .send_raw_transaction_opts(&lrc20_tx.bitcoin_tx, None, max_burn_amount_btc)
            .await;

        match send_tx_result {
            Ok(_) => {}
            Err(bitcoin_client::Error::JsonRpc(JsonRpcError::Rpc(err)))
                if err.code == BTC_RPC_VERIFY_ALREADY_IN_CHAIN => {}
            Err(err) => return Err(map_bitcoin_error(err)),
        }

        // Send message to message handler to wait its confirmation.
        self.send_txs_to_confirm(vec![lrc20_tx]).await?;

        Ok(true)
    }

    async fn is_lrc20_txout_frozen(&self, txid: Txid, vout: u32) -> RpcResult<bool> {
        let is_frozen = self
            .node_storage
            .is_proof_frozen(txid, vout)
            .await
            .map_err(|e| {
                tracing::error!("Failed to get frozen tx: {e}");
                ErrorObject::owned(
                    INTERNAL_ERROR_CODE,
                    "Storage is not available",
                    Option::<Vec<u8>>::None,
                )
            })?;

        Ok(is_frozen)
    }

    async fn is_pubkey_frozen(
        &self,
        pubkey: PublicKey,
        token_pubkey: TokenPubkey,
    ) -> RpcResult<bool> {
        let is_frozen = self
            .node_storage
            .is_pubkey_frozen(pubkey, *token_pubkey.pubkey())
            .await
            .map_err(|e| {
                tracing::error!("Failed to get frozen pubkey: {e}");
                ErrorObject::owned(
                    INTERNAL_ERROR_CODE,
                    "Storage is not available",
                    Option::<Vec<u8>>::None,
                )
            })?;

        Ok(is_frozen)
    }

    /// Check that transaction could be accpeted by node.
    ///
    /// For that uses [`TransactionEmulator`] to check that transaction is valid
    /// ([see](TransactionEmulator::emulate_lrc20_transaction))) for more info.
    async fn emulate_lrc20_transaction(
        &self,
        lrc20_tx: Lrc20Transaction,
    ) -> RpcResult<EmulateLrc20TransactionResponse> {
        let emulator = TransactionEmulator::new(self.node_storage.clone());

        match emulator.emulate_lrc20_transaction(&lrc20_tx).await {
            // Transaction could be accepted by node.
            Ok(()) => Ok(EmulateLrc20TransactionResponse::Valid),
            // Storage is dead:
            Err(EmulateLrc20TransactionError::PersistentStorageNotAvailable(err)) => {
                tracing::error!("Storage error: {err}");

                Err(ErrorObject::owned(
                    INTERNAL_ERROR_CODE,
                    "Storage is not available",
                    Option::<Vec<u8>>::None,
                ))
            }
            // Error that encountered during emulating:
            Err(err) => Ok(EmulateLrc20TransactionResponse::Invalid {
                reason: err.to_string(),
            }),
        }
    }

    async fn get_token_pubkey_info(
        &self,
        token_pubkey: TokenPubkey,
    ) -> RpcResult<Option<TokenPubkeyInfo>> {
        self.node_storage
            .get_token_pubkey_info(token_pubkey)
            .await
            .map_err(|e| {
                tracing::error!("Failed to get token_pubkey info: {e}");
                ErrorObject::owned(
                    INTERNAL_ERROR_CODE,
                    "Storage is not available",
                    Option::<Vec<u8>>::None,
                )
            })
    }
}

/// Map Bitcoin client error to JSON-RPC error returned by LRC20 node API.
///
/// This is required to check for bitcoin RPC specific errors and handle them
/// properly.
fn map_bitcoin_error(err: BitcoinClientError) -> ErrorObjectOwned {
    match err {
        BitcoinClientError::JsonRpc(JsonRpcError::Rpc(err)) => {
            ErrorObjectOwned::owned(INVALID_REQUEST_CODE, err.message, err.data)
        }
        err => {
            tracing::error!("Failed to send transaction to Bitcoin network: {:#?}", err);
            ErrorObjectOwned::owned(
                INTERNAL_ERROR_CODE,
                "Service is dead",
                Option::<Vec<u8>>::None,
            )
        }
    }
}

/// Entity that emulates transactions by checking if the one violates any of
/// this checks:
///
/// 1. All proofs are valid for this transaction;
/// 2. Transaction is not violating any conservation rules;
/// 3. None of the inputs are already frozen;
/// 4. That all parents are already attached in internal node storage.
///
/// If any of them encountered, return an error on method [`emulate_lrc20_transaction`].
///
/// [`emulate_lrc20_transaction`]: TransactionEmulator::emulate_lrc20_transaction
// TODO: This could be moved to separate module.
pub struct TransactionEmulator<NodeStorage> {
    /// Internal storage of transactions.
    storage: NodeStorage,
}

#[derive(Debug, thiserror::Error)]
pub enum EmulateLrc20TransactionError {
    #[error("Transaction check error: {0}")]
    CheckFailed(#[from] CheckError),

    #[error("Parent transaction is not found: {txid}")]
    ParentTransactionNotFound { txid: Txid },

    #[error("Parent UTXO is not found: {txid}:{vout}")]
    ParentUtxoNotFound { txid: Txid, vout: u32 },

    #[error("Parent transaction is frozen: {txid}:{vout}")]
    ParentTransactionFrozen { txid: Txid, vout: u32 },

    #[error("Storage is not available: {0}")]
    PersistentStorageNotAvailable(#[from] DbErr),
}

impl<NS> TransactionEmulator<NS>
where
    NS: Lrc20NodeStorage + Send + Sync + 'static,
{
    pub fn new(storage: NS) -> Self {
        Self { storage }
    }

    /// Emulate transaction check and attach without actuall broadcasting or
    /// mining. See [`TransactionEmulator`] for more info.
    pub async fn emulate_lrc20_transaction(
        &self,
        lrc20_tx: &Lrc20Transaction,
    ) -> Result<(), EmulateLrc20TransactionError> {
        // Check first two bullets.
        check_transaction(lrc20_tx)?;

        let Some(parents) = extract_parents(lrc20_tx) else {
            return Ok(());
        };

        self.check_parents(parents).await?;

        // TODO: move this check to isolated checks.
        self.check_p2tr_input_proofs(lrc20_tx).await?;

        Ok(())
    }

    // TODO: remove after moving Taproot proofs check to isolated checks.
    async fn check_p2tr_input_proofs(
        &self,
        lrc20_tx: &Lrc20Transaction,
    ) -> Result<(), EmulateLrc20TransactionError> {
        let Some(input_proofs) = lrc20_tx.tx_type.input_proofs() else {
            return Ok(());
        };

        for (vout, proof) in input_proofs {
            let ReceiptProof::P2TR(taproot_proof) = proof else {
                continue;
            };

            let txin = lrc20_tx.bitcoin_tx.input.get(*vout as usize).ok_or(
                EmulateLrc20TransactionError::CheckFailed(CheckError::InputNotFound),
            )?;

            let prev_outpoint = txin.previous_output;
            let Some(tx) = self
                .storage
                .get_lrc20_transaction_by_id(prev_outpoint.txid)
                .await?
            else {
                return Err(EmulateLrc20TransactionError::ParentTransactionNotFound {
                    txid: prev_outpoint.txid,
                });
            };

            let Some(prev_out) = tx.bitcoin_tx.output.get(prev_outpoint.vout as usize) else {
                return Err(EmulateLrc20TransactionError::ParentUtxoNotFound {
                    txid: prev_outpoint.txid,
                    vout: prev_outpoint.vout,
                });
            };

            check_p2tr_proof(&prev_out.script_pubkey, taproot_proof)?;
        }

        Ok(())
    }

    /// Check that all parent transactions are not spent or frozen.
    async fn check_parents(
        &self,
        parents: Vec<OutPoint>,
    ) -> Result<(), EmulateLrc20TransactionError> {
        use EmulateLrc20TransactionError as Error;

        for parent in parents {
            let tx_entry = self
                .storage
                .get_lrc20_transaction_by_id(parent.txid)
                .await?;

            // Return an error if parent transaction not found.
            let Some(tx) = tx_entry else {
                return Err(Error::ParentTransactionNotFound { txid: parent.txid });
            };

            let Some(output_proofs) = tx.tx_type.output_proofs() else {
                continue;
            };

            // Return an error if parent transaction output not found.
            if output_proofs.get(&parent.vout).is_none() {
                return Err(Error::ParentUtxoNotFound {
                    txid: parent.txid,
                    vout: parent.vout,
                });
            }

            // Return an error if parent transaction output is already frozen.
            self.is_parent_frozen(parent).await?;
        }

        Ok(())
    }

    /// Check if parent UTXO is frozen or not.
    async fn is_parent_frozen(&self, parent: OutPoint) -> Result<(), EmulateLrc20TransactionError> {
        let is_frozen = self
            .storage
            .is_proof_frozen(parent.txid, parent.vout)
            .await?;

        if is_frozen {
            Err(EmulateLrc20TransactionError::ParentTransactionFrozen {
                txid: parent.txid,
                vout: parent.vout,
            })
        } else {
            Ok(())
        }
    }
}

fn extract_parents(lrc20_tx: &Lrc20Transaction) -> Option<Vec<OutPoint>> {
    match &lrc20_tx.tx_type {
        // Issuance check was above, so we skip it.
        Lrc20TxType::Issue { .. } | Lrc20TxType::SparkExit { .. } => None,
        // In case of transfer, parent transaction are one that are used as
        // inputs in input proofs.
        Lrc20TxType::Transfer { input_proofs, .. } => {
            collect_transfer_parents(lrc20_tx, input_proofs).into()
        }
        // In case of freezes, parent transaction are one that are being frozen.
        Lrc20TxType::Announcement(_) => {
            tracing::warn!("Announcement emulating is not implemented yet");
            None
        }
    }
}

/// Extract outpoint from inputs that are in the input proofs.
fn collect_transfer_parents(lrc20_tx: &Lrc20Transaction, input_proofs: &ProofMap) -> Vec<OutPoint> {
    lrc20_tx
        .bitcoin_tx
        .input
        .iter()
        .enumerate()
        .filter_map(|(vin, input)| {
            input_proofs
                .get(&(vin as u32))
                .map(|_proof| input.previous_output)
        })
        .collect::<Vec<_>>()
}
