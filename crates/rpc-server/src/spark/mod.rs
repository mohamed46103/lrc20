use bitcoin::Amount;
use bitcoin::BlockHash;
use bitcoin::hashes::{Hash, sha256::Hash as Sha256Hash};
use bitcoin_client::BitcoinRpcApi;
use bitcoin_client::JsonRpcError;
use event_bus::{EventBus, typeid};
use eyre::OptionExt;
use lrc20_receipts::TokenPubkey;
use lrc20_storage::PgDatabaseConnectionManager;
use lrc20_storage::traits::IndexerNodeStorage;
use lrc20_storage::traits::Lrc20NodeStorage;
use lrc20_storage::traits::SparkNodeStorage;
use lrc20_tx_check::{check_spark_conservation_rules, check_spark_tx_finalization};
use lrc20_types::spark::TokenTransactionStatus;
use lrc20_types::spark::{
    TokenLeafOutput, TokenLeafToSpend, TokenTransactionInput, TokensFreezeData,
};
use lrc20_types::{
    ControllerMessage, Lrc20Transaction,
    spark::{TokenTransaction, signature::SparkSignatureData, spark_hash::SparkHash},
};
use protos::rpc::v1::{
    BlockInfo, BlockInfoResponse, FreezeTokensRequest, FreezeTokensResponse,
    GetTokenPubkeyInfoRequest, GetTokenPubkeyInfoResponse, Layer, ListAllTokenTransactionsCursor,
    ListAllTokenTransactionsRequest, ListAllTokenTransactionsResponse, ListSparkTxsRequest,
    ListWithdrawnOutputsRequest, ListWithdrawnOutputsResponse, OperationType, SendRawTxRequest,
    SparkTransaction, TokenPubkeyInfo, TokenTransactionResponse, Transaction,
};
use protos::util::into_token_outputs_to_create_from_proto;
use protos::util::{into_token_leaf, into_token_tx_status, parse_tokens_freeze_request};
use protos::{
    rpc::v1::{
        GetSparkTxRequest, GetSparkTxResponse, ListSparkTxsResponse, SendSparkSignatureRequest,
        VerifySparkTxRequest, spark_service_server::SparkService,
    },
    util::{
        into_token_transaction, parse_get_spark_tx_request, parse_send_signature_request,
        parse_token_transaction,
    },
};
use tokio::sync::mpsc;

use lrc20_storage::converters::spark::create_spark_issue_model_from_token_tx;
use sea_orm::DbErr;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;

const DEFAULT_PAGE_SIZE: u32 = 100;
const BTC_RPC_VERIFY_ALREADY_IN_CHAIN: i32 = -27;

pub struct SparkRpcServer<NodeStorage, BitcoinClient> {
    /// Event bus for simplifying communication with services.
    event_bus: EventBus,

    /// Node persistent storage.
    node_storage: NodeStorage,

    //spark_tx_storage: SparkTransactionsStorage,
    spark_tx_storage: NodeStorage,

    bitcoin_client: Arc<BitcoinClient>,

    enforce_announcement: bool,
}

#[tonic::async_trait]
impl<NS, BC> SparkService for SparkRpcServer<NS, BC>
where
    NS: PgDatabaseConnectionManager
        + SparkNodeStorage
        + Lrc20NodeStorage
        + IndexerNodeStorage
        + Clone
        + Send
        + Sync
        + 'static,
    BC: BitcoinRpcApi + Send + Sync + 'static,
{
    async fn send_spark_signature(
        &self,
        request: tonic::Request<SendSparkSignatureRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
        let start_time = Instant::now();
        tracing::info!(elapsed = ?start_time.elapsed(), "[send_spark_signature] Starting request processing");

        let request = request.into_inner();
        let (signature_datas, parsed_tx) = parse_send_signature_request(request).map_err(|e| {
            tracing::error!(elapsed = ?start_time.elapsed(), "[send_spark_signature] Failed to parse request: {:?}", e);
            tonic::Status::invalid_argument(format!("Failed to parse request: {}", e))
        })?;

        tracing::info!(
            tx_hash = ?parsed_tx.hash().to_string(),
            signature_count = signature_datas.len(),
            "[send_spark_signature] Processing transaction with {} signatures",
            signature_datas.len()
        );

        if signature_datas
            .iter()
            .any(|signature_data| signature_data.token_tx_hash != parsed_tx.hash())
        {
            tracing::error!(
                tx_hash = ?parsed_tx.hash().to_string(),
                "[send_spark_signature] Hash mismatch between signature data and transaction"
            );
            return Err(tonic::Status::invalid_argument("Hash mismatch"));
        }

        if self.enforce_announcement {
            if let TokenTransactionInput::Mint {
                issuer_public_key,
                issuer_signature,
                issuer_provided_timestamp,
            } = &parsed_tx.input
            {
                // Ensuring that the token is already announced
                let token_info_option = self
                    .node_storage
                    .get_token_pubkey_info(issuer_public_key.into())
                    .await
                    .map_err(|e| {
                        tracing::error!("Failed to get token pubkey info: {e}");
                        tonic::Status::internal(format!("Failed to get token pubkey info: {e}"))
                    })?;

                if token_info_option.is_none() {
                    return Err(tonic::Status::invalid_argument(
                        "Token pubkey is not yet announced",
                    ));
                }

                if let Some(token_info) = token_info_option {
                    tracing::info!(elapsed = ?start_time.elapsed(), "[send_spark_signature] Checking token supply limits");
                    let max_supply = token_info.announcement.as_ref().unwrap().max_supply.to_be();
                    tracing::info!(elapsed = ?start_time.elapsed(), "[send_spark_signature] Max supply: {}", max_supply);

                    let issue_leaves = self
                        .node_storage
                        .get_issue_leaves_by_token_pubkey(&issuer_public_key.serialize())
                        .await
                        .map_err(|err| {
                            tracing::error!(elapsed = ?start_time.elapsed(), "[send_spark_signature] Failed to select issue leaves: {}", err);
                            tonic::Status::internal(format!(
                                "Failed to select issue leaves: {}",
                                err
                            ))
                        })?;

                    let mut total_supply: u128 = issue_leaves
                        .iter()
                        .map(|leaf| leaf.receipt.token_amount.amount)
                        .sum();
                    tracing::info!(elapsed = ?start_time.elapsed(), "[send_spark_signature] Current total supply: {}", total_supply);

                    if max_supply > 0 {
                        let added_supply = parsed_tx
                            .leaves_to_create
                            .iter()
                            .fold(0, |acc: u128, leaf| {
                                acc.saturating_add(leaf.receipt.token_amount.amount)
                            });
                        tracing::info!(elapsed = ?start_time.elapsed(), "[send_spark_signature] Added supply in this transaction: {}", added_supply);

                        total_supply = total_supply.saturating_add(added_supply);
                        tracing::info!(elapsed = ?start_time.elapsed(), "[send_spark_signature] New total supply after transaction: {}", total_supply);

                        if total_supply > max_supply {
                            tracing::info!(elapsed = ?start_time.elapsed(), "[send_spark_signature] Supply limit exceeded: {} > {}", total_supply, max_supply);
                            return Err(tonic::Status::invalid_argument(
                                "Total supply exceeds max supply",
                            ));
                        }
                        tracing::info!(elapsed = ?start_time.elapsed(), "[send_spark_signature] Supply check passed");
                    }
                }
            }
        }

        let (callback_tx, mut callback_rx) = mpsc::channel::<bool>(1);

        let token_tx = self
            .node_storage
            .get_spark_tx_with_outputs(parsed_tx.hash())
            .await
            .map_err(|err| {
                tracing::error!(
                    tx_hash = ?parsed_tx.hash().to_string(),
                    error = ?err,
                    "[send_spark_signature] Failed to select token transaction"
                );
                tonic::Status::internal(format!("Failed to select token transaction: {}", err))
            })?;

        tracing::info!(
            tx_hash = ?parsed_tx.hash().to_string(),
            tx_exists = token_tx.is_some(),
            "[send_spark_signature] Transaction existence check: {}",
            if token_tx.is_some() { "exists" } else { "new transaction" }
        );

        if token_tx.is_none() {
            tracing::info!(
                tx_hash = ?parsed_tx.hash().to_string(),
                "[send_spark_signature] Sending new transaction for checking"
            );

            self.send_spark_txs_to_check(vec![parsed_tx.clone()], Some(callback_tx))
                .await?;

            let callback_result = callback_rx.recv().await.unwrap_or_default();
            tracing::info!(
                tx_hash = ?parsed_tx.hash().to_string(),
                success = callback_result,
                "[send_spark_signature] Transaction check result: {}",
                if callback_result { "success" } else { "failure" }
            );

            if !callback_result {
                return Err(tonic::Status::internal(
                    "Transaction was not successfully handled",
                ));
            }
        }

        tracing::info!(
            tx_hash = ?parsed_tx.hash().to_string(),
            "[send_spark_signature] Sending signature data for checking"
        );

        let (callback_tx, mut callback_rx) = mpsc::channel::<bool>(1);

        self.send_spark_signature_data_to_check(signature_datas, Some(callback_tx))
            .await
            .map_err(|e| {
                tracing::error!(
                    tx_hash = ?parsed_tx.hash().to_string(),
                    error = ?e,
                    "[send_spark_signature] Failed to send signature data"
                );
                e
            })?;

        let callback_result = callback_rx.recv().await.unwrap_or_default();
        tracing::info!(
            tx_hash = ?parsed_tx.hash().to_string(),
            success = callback_result,
            "[send_spark_signature] Signature data check result: {}",
            if callback_result { "success" } else { "failure" }
        );

        if !callback_result {
            return Err(tonic::Status::internal(
                "Signature data was not successfully handled",
            ));
        }

        tracing::info!(
            tx_hash = ?parsed_tx.hash().to_string(),
            elapsed = ?start_time.elapsed(),
            "[send_spark_signature] Request completed successfully"
        );

        Ok(tonic::Response::new(()))
    }

    async fn list_transactions(
        &self,
        request: tonic::Request<ListAllTokenTransactionsRequest>,
    ) -> Result<tonic::Response<ListAllTokenTransactionsResponse>, tonic::Status> {
        let start_time = Instant::now();
        tracing::info!(elapsed = ?start_time.elapsed(), "[list_transactions] Starting request processing");

        let ListAllTokenTransactionsRequest {
            cursor,
            page_size,
            owner_public_key,
            token_public_key,
            before_timestamp: _,
            after_timestamp: _,
            operation_types,
        } = request.into_inner();

        let page_size = page_size.unwrap_or(DEFAULT_PAGE_SIZE) as usize;
        tracing::info!(
            page_size = page_size,
            has_cursor = cursor.is_some(),
            has_owner = owner_public_key.is_some(),
            has_token = token_public_key.is_some(),
            op_types_count = operation_types.len(),
            "[list_transactions] Request parameters"
        );

        let page_token = cursor
            .map(|cursor| {
                Sha256Hash::from_slice(&cursor.last_transaction_hash)
                    .map(SparkHash)
                    .map_err(|e| tonic::Status::invalid_argument(format!("Invalid cursor: {}", e)))
            })
            .transpose()?;

        let stored_txs = self
            .spark_tx_storage
            .get_token_transactions_by_page(
                page_token,
                page_size,
                owner_public_key,
                token_public_key,
                operation_types,
            )
            .await
            .map_err(|err| {
                tracing::error!(
                    error = ?err,
                    "[list_transactions] Failed to select transactions"
                );
                tonic::Status::internal(format!("Failed to select the transactions: {}", err))
            })?;

        tracing::info!(
            tx_count = stored_txs.len(),
            "[list_transactions] Retrieved {} transactions",
            stored_txs.len()
        );

        let next_cursor = stored_txs
            .get(page_size)
            .cloned()
            .map(|tx: TokenTransaction| ListAllTokenTransactionsCursor {
                last_transaction_hash: tx.hash().as_byte_array().to_vec(),
                layer: Layer::Spark.into(),
            });

        let page_txs: Vec<_> = stored_txs.iter().take(page_size).collect();
        let mut parent_transactions: HashMap<SparkHash, TokenTransaction> = HashMap::default();

        let mut transactions = Vec::new();
        for page_tx in page_txs {
            let hash = SparkHash::from(page_tx);
            let leaves_to_spend = match &page_tx.input {
                TokenTransactionInput::Transfer { outputs_to_spend } => outputs_to_spend,
                TokenTransactionInput::Mint { .. } => &Vec::new(),
            };

            let mut parent_leaves = Vec::new();
            for leaf_to_spend in leaves_to_spend {
                let parent_hash = leaf_to_spend.parent_output_hash;

                let parent_index = leaf_to_spend.parent_output_vout;

                let parent_transaction = match parent_transactions.get(&parent_hash.into()) {
                    Some(parent_tx) => parent_tx.clone(),
                    None => {
                        let parent_tx_opt = self
                            .spark_tx_storage
                            .get_spark_tx_with_outputs(parent_hash.into())
                            .await
                            .map_err(|err| {
                                tonic::Status::internal(format!(
                                    "Failed to select the parent transaction: {}",
                                    err
                                ))
                            })?;

                        let Some(parent_tx) = parent_tx_opt else {
                            return Err(tonic::Status::invalid_argument(format!(
                                "Parent tx {} not found",
                                parent_hash
                            )));
                        };

                        parent_transactions.insert(parent_hash.into(), parent_tx.clone());

                        parent_tx
                    }
                };

                let Some(parent_leaf) = parent_transaction
                    .leaves_to_create
                    .get(parent_index as usize)
                else {
                    return Err(tonic::Status::invalid_argument(format!(
                        "Parent leaf {}:{} not found",
                        parent_hash, parent_index
                    )));
                };

                parent_leaves.push(
                    into_token_leaf(
                        parent_leaf,
                        leaf_to_spend.parent_output_hash.to_byte_array().to_vec(),
                        parent_index,
                    )
                    .map_err(|err| {
                        tonic::Status::internal(format!("Failed to serialize the leaf: {}", err))
                    })?,
                );
            }

            let operation_type = match page_tx.input {
                TokenTransactionInput::Mint { .. } => OperationType::IssuerMint,
                TokenTransactionInput::Transfer { .. } => OperationType::UserTransfer,
            };

            let status = self
                .spark_tx_storage
                .get_token_transaction_status(hash)
                .await
                .map_err(|err| {
                    tonic::Status::internal(format!(
                        "Failed to get the transaction status: {}",
                        err
                    ))
                })?;

            let leaves_to_create = page_tx
                .leaves_to_create
                .iter()
                .enumerate()
                .map(|(index, leaf)| {
                    let index = index as u32;
                    let leaf = into_token_leaf(
                        leaf,
                        SparkHash::from(page_tx).as_byte_array().to_vec(),
                        index,
                    )
                    .map_err(|err| {
                        tonic::Status::internal(format!("Failed to serialize the leaf: {}", err))
                    })?;

                    Ok(leaf)
                })
                .collect::<Result<Vec<_>, tonic::Status>>()?;

            let spark_tx = SparkTransaction {
                operation_type: operation_type.into(),
                transaction_hash: SparkHash::from(page_tx).as_byte_array().to_vec(),
                status: into_token_tx_status(status).into(),
                confirmed_at: None,
                leaves_to_create,
                leaves_to_spend: parent_leaves,
                spark_operator_identity_public_keys: page_tx
                    .spark_operator_identity_public_keys
                    .iter()
                    .map(|pubkey| pubkey.serialize().to_vec())
                    .collect(),
            };

            let token_tx = Transaction {
                transaction: Some(protos::rpc::v1::transaction::Transaction::Spark(spark_tx)),
            };

            transactions.push(token_tx);
        }

        tracing::info!(
            elapsed = ?start_time.elapsed(),
            tx_count = transactions.len(),
            has_next_cursor = next_cursor.is_some(),
            "[list_transactions] Request completed with {} transactions",
            transactions.len()
        );

        Ok(tonic::Response::new(ListAllTokenTransactionsResponse {
            transactions,
            next_cursor,
        }))
    }

    async fn list_spark_txs(
        &self,
        request: tonic::Request<ListSparkTxsRequest>,
    ) -> Result<tonic::Response<ListSparkTxsResponse>, tonic::Status> {
        let ListSparkTxsRequest {
            page_token,
            page_size,
        } = request.into_inner();

        let page_size = page_size.unwrap_or(DEFAULT_PAGE_SIZE) as usize;
        let page_token = page_token
            .map(|bytes| {
                Sha256Hash::from_slice(&bytes).map(SparkHash).map_err(|e| {
                    tonic::Status::invalid_argument(format!("Invalid page_token: {}", e))
                })
            })
            .transpose()?;

        let stored_txs = self
            .spark_tx_storage
            .get_token_transactions_by_page(page_token, page_size, None, None, Vec::new())
            .await
            .map_err(|err| {
                tonic::Status::internal(format!("Failed to select the transactions: {}", err))
            })?;

        let mut finalization_statuses = HashMap::new();
        for tx in &stored_txs {
            let txid = SparkHash::from(tx);
            let status = self
                .spark_tx_storage
                .get_token_transaction_status(txid)
                .await
                .map_err(|err| {
                    tonic::Status::internal(format!(
                        "Failed to get the transaction status: {}",
                        err
                    ))
                })?;

            finalization_statuses.insert(txid, status);
        }

        let next_page_token = stored_txs
            .get(page_size)
            .cloned()
            .map(|tx| tx.hash().as_byte_array().to_vec());

        let txs: Vec<_> = stored_txs.into_iter().take(page_size).collect();

        let token_transactions = txs
            .into_iter()
            .map(|tx| {
                let txid = SparkHash::from(&tx);
                let tx = into_token_transaction(tx)?;
                let tx_status = *finalization_statuses
                    .get(&txid)
                    .ok_or_eyre("Finalization status not found")?;

                Ok(TokenTransactionResponse {
                    finalized: matches!(tx_status, TokenTransactionStatus::Finalized),
                    final_token_transaction: Some(tx),
                    final_token_transaction_hash: txid.as_byte_array().to_vec(),
                })
            })
            .collect::<eyre::Result<Vec<_>>>()
            .map_err(|err| {
                tonic::Status::internal(format!("Failed to serialize transactions: {}", err))
            })?;

        Ok(tonic::Response::new(ListSparkTxsResponse {
            token_transactions,
            next_page_token,
        }))
    }

    async fn freeze_tokens(
        &self,
        request: tonic::Request<FreezeTokensRequest>,
    ) -> Result<tonic::Response<FreezeTokensResponse>, tonic::Status> {
        let freeze_data = parse_tokens_freeze_request(request.into_inner()).map_err(|e| {
            tonic::Status::invalid_argument(format!("Failed to parse request: {}", e))
        })?;

        if self.enforce_announcement {
            // Check if the token is freezable
            let token_pubkey = &freeze_data.token_public_key;
            let token_info_option = self
                .node_storage
                .get_token_pubkey_info(token_pubkey.clone())
                .await
                .map_err(|e| {
                    tracing::error!("Failed to get token pubkey info: {e}");
                    tonic::Status::internal(format!("Failed to get token pubkey info: {e}"))
                })?;

            if let Some(token_info) = token_info_option {
                if let Some(announcement) = &token_info.announcement {
                    if !announcement.is_freezable {
                        return Err(tonic::Status::invalid_argument(
                            "Token is not freezable according to its announcement",
                        ));
                    }
                } else {
                    return Err(tonic::Status::invalid_argument(
                        "Token has no announcement data",
                    ));
                }
            } else {
                return Err(tonic::Status::invalid_argument(
                    "Token pubkey is not announced",
                ));
            }
        }

        self.send_tokens_freeze_request_to_check(freeze_data)
            .await?;

        Ok(tonic::Response::new(FreezeTokensResponse {
            impacted_output_ids: vec![],
            impacted_token_amount: vec![],
        }))
    }

    async fn list_withdrawn_outputs(
        &self,
        request: tonic::Request<ListWithdrawnOutputsRequest>,
    ) -> Result<tonic::Response<ListWithdrawnOutputsResponse>, tonic::Status> {
        let ListWithdrawnOutputsRequest {
            blockhash,
            page_token,
            page_size,
        } = request.into_inner();

        let page_size = page_size.unwrap_or(DEFAULT_PAGE_SIZE) as usize;
        let height = match blockhash {
            Some(mut hash) => {
                hash.reverse();
                let blockhash = BlockHash::from_slice(&hash).map_err(|e| {
                    tonic::Status::invalid_argument(format!("Invalid block hash: {}", e))
                })?;

                let block_info = self
                    .bitcoin_client
                    .get_block_info(&blockhash)
                    .await
                    .map_err(|e| {
                        tonic::Status::internal(format!(
                            "Failed to get block info for specified block hash: {}",
                            e
                        ))
                    })?;

                Some(block_info.block_data.height as i32)
            }
            None => None,
        };

        let stored_leaves = self
            .spark_tx_storage
            .get_withdrawn_leaves_by_page(page_token, height, page_size)
            .await
            .map_err(|err| tonic::Status::internal(format!("Failed to select outputs: {}", err)))?;

        let next_page_token = stored_leaves.get(page_size).cloned().map(|leaf| leaf.id);

        let outputs: Vec<_> = stored_leaves.into_iter().take(page_size).collect();

        let outputs = into_token_outputs_to_create_from_proto(outputs).map_err(|err| {
            tonic::Status::internal(format!("Failed to serialize leaves: {}", err))
        })?;

        Ok(tonic::Response::new(ListWithdrawnOutputsResponse {
            outputs,
            next_page_token,
        }))
    }

    async fn verify_spark_tx(
        &self,
        request: tonic::Request<VerifySparkTxRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
        let start_time = Instant::now();
        tracing::info!(elapsed = ?start_time.elapsed(), "[verify_spark_tx] Starting request processing");

        let token_tx = request
            .into_inner()
            .final_token_transaction
            .ok_or_else(|| {
                let err_msg = "Missing token transaction";
                tracing::error!("[verify_spark_tx] Request error: {}", err_msg);
                tonic::Status::invalid_argument(err_msg)
            })?;

        let parsed_token_tx = parse_token_transaction(token_tx, vec![]).map_err(|e| {
            tracing::error!(
                "[verify_spark_tx] Failed to parse token transaction: {:?}",
                e
            );
            tonic::Status::invalid_argument(format!("Failed to parse token transaction: {}", e))
        })?;

        tracing::info!(
            tx_hash = ?parsed_token_tx.hash().to_string(),
            tx_type = ?match &parsed_token_tx.input {
                TokenTransactionInput::Mint { .. } => "Mint",
                TokenTransactionInput::Transfer { .. } => "Transfer",
            },
            leaves_count = parsed_token_tx.leaves_to_create.len(),
            "[verify_spark_tx] Verifying transaction"
        );

        if self.enforce_announcement {
            if let TokenTransactionInput::Mint {
                issuer_public_key,
                issuer_signature: _,
                issuer_provided_timestamp: _,
            } = &parsed_token_tx.input
            {
                // Ensuring that the token is already announced
                let token_info_option = self
                    .node_storage
                    .get_token_pubkey_info(issuer_public_key.into())
                    .await
                    .map_err(|e| {
                        tracing::error!("Failed to get token pubkey info: {e}");
                        tonic::Status::internal(format!("Failed to get token pubkey info: {e}"))
                    })?;

                if token_info_option.is_none() {
                    return Err(tonic::Status::invalid_argument(
                        "Token pubkey is not yet announced",
                    ));
                }

                if let Some(token_info) = token_info_option {
                    let max_supply = token_info.announcement.as_ref().unwrap().max_supply.to_be();
                    tracing::info!(
                        "[verify_spark_tx] Token: {}, Max supply: {}",
                        issuer_public_key,
                        max_supply
                    );

                    let issue_leaves = self
                        .node_storage
                        .get_issue_leaves_by_token_pubkey(&issuer_public_key.serialize())
                        .await
                        .map_err(|err| {
                            tonic::Status::internal(format!(
                                "Failed to select issue leaves: {}",
                                err
                            ))
                        })?;

                    let mut total_supply: u128 = issue_leaves
                        .iter()
                        .map(|leaf| leaf.receipt.token_amount.amount)
                        .sum();

                    tracing::info!(
                        "[verify_spark_tx] Token: {}, Current total supply: {}",
                        issuer_public_key,
                        total_supply
                    );

                    if max_supply > 0 {
                        let added_supply = parsed_token_tx
                            .leaves_to_create
                            .iter()
                            .fold(0, |acc: u128, leaf| {
                                acc.saturating_add(leaf.receipt.token_amount.amount)
                            });

                        tracing::info!(
                            "[verify_spark_tx] Token: {}, Added supply in this tx: {}",
                            issuer_public_key,
                            added_supply
                        );

                        total_supply = total_supply.saturating_add(added_supply);
                        tracing::info!(
                            "[verify_spark_tx] Token: {}, New total supply: {}, Max supply: {}",
                            issuer_public_key,
                            total_supply,
                            max_supply
                        );

                        if total_supply > max_supply {
                            tracing::info!(
                                "[verify_spark_tx] Supply limit exceeded! Token: {}, Total: {} > Max: {}",
                                issuer_public_key,
                                total_supply,
                                max_supply
                            );
                            return Err(tonic::Status::invalid_argument(
                                "Total supply exceeds max supply",
                            ));
                        }
                    }
                }
            }
        }

        let emulator = SparkTxEmulator::new(self.spark_tx_storage.clone());

        tracing::info!(
            tx_hash = ?parsed_token_tx.hash().to_string(),
            "[verify_spark_tx] Starting transaction emulation"
        );

        match emulator.check_spark_tx(parsed_token_tx.clone()).await {
            Ok(_) => {
                tracing::info!(
                    tx_hash = ?parsed_token_tx.hash().to_string(),
                    elapsed = ?start_time.elapsed(),
                    "[verify_spark_tx] Transaction verification successful"
                );
                Ok(tonic::Response::new(()))
            }
            Err(e) => {
                tracing::error!(
                    tx_hash = ?parsed_token_tx.hash().to_string(),
                    error = ?e,
                    elapsed = ?start_time.elapsed(),
                    "[verify_spark_tx] Transaction verification failed"
                );
                Err(e.into())
            }
        }
    }

    async fn get_spark_tx(
        &self,
        request: tonic::Request<GetSparkTxRequest>,
    ) -> std::result::Result<tonic::Response<GetSparkTxResponse>, tonic::Status> {
        let hash = parse_get_spark_tx_request(request.into_inner()).map_err(|e| {
            tonic::Status::invalid_argument(format!("Failed to parse request: {}", e))
        })?;

        let token_tx_opt = self
            .spark_tx_storage
            .get_spark_tx_with_outputs(hash)
            .await
            .map_err(|err| {
                tonic::Status::internal(format!("Failed to select token transaction: {}", err))
            })?;

        let Some(token_tx) = token_tx_opt else {
            return Err(tonic::Status::not_found(format!(
                "Token transaction {} not found",
                hash
            )));
        };

        let token_tx = into_token_transaction(token_tx).map_err(|err| {
            tonic::Status::internal(format!("Failed to serialize transaction: {}", err))
        })?;

        Ok(tonic::Response::new(GetSparkTxResponse {
            final_token_transaction: Some(token_tx),
        }))
    }

    async fn get_last_indexed_block_info(
        &self,
        _request: tonic::Request<()>,
    ) -> std::result::Result<tonic::Response<BlockInfoResponse>, tonic::Status> {
        let last_block_hash_opt = self
            .node_storage
            .get_last_indexed_block_hash()
            .await
            .map_err(|err| {
                tonic::Status::internal(format!(
                    "Failed to get last block hash from storage: {}",
                    err
                ))
            })?;

        let Some(last_block_hash) = last_block_hash_opt else {
            return Err(tonic::Status::not_found("Last indexed block is missing"));
        };

        let block_info = self
            .bitcoin_client
            .get_block_header_info(&last_block_hash)
            .await
            .map_err(|err| {
                tonic::Status::internal(format!(
                    "Failed to get block info from Bitcoin RPC: {}",
                    err
                ))
            })?;

        let timestamp = prost_types::Timestamp {
            seconds: block_info.time as i64,
            nanos: 0,
        };

        Ok(tonic::Response::new(BlockInfoResponse {
            block_info: Some(BlockInfo {
                block_hash: last_block_hash.to_byte_array().to_vec(),
                block_height: block_info.height as u32,
                mined_at: Some(timestamp),
            }),
        }))
    }

    async fn get_token_pubkey_info(
        &self,
        request: tonic::Request<GetTokenPubkeyInfoRequest>,
    ) -> Result<tonic::Response<GetTokenPubkeyInfoResponse>, tonic::Status> {
        let start_time = Instant::now();
        tracing::info!(elapsed = ?start_time.elapsed(), "[get_token_pubkey_info] Starting request processing");

        let request_inner = request.into_inner();
        let pubkeys = request_inner.public_keys;

        tracing::info!(
            pubkey_count = pubkeys.len(),
            "[get_token_pubkey_info] Processing {} token pubkeys",
            pubkeys.len()
        );

        let mut token_infos: Vec<TokenPubkeyInfo> = Vec::new();

        for (idx, pubkey_bytes) in pubkeys.iter().enumerate() {
            tracing::info!(
                "[get_token_pubkey_info] Processing token pubkey {}/{}",
                idx + 1,
                pubkeys.len()
            );

            let token_pubkey = TokenPubkey::from_bytes(pubkey_bytes).map_err(|err| {
                tracing::error!("[get_token_pubkey_info] Failed to parse token pubkey: {err}");
                tonic::Status::invalid_argument(format!("Failed to parse token pubkey: {err}"))
            })?;

            tracing::info!(
                "[get_token_pubkey_info] Fetching token info for pubkey: {:?}",
                token_pubkey
            );

            let token_info_option = self
                .node_storage
                .get_token_pubkey_info(token_pubkey)
                .await
                .map_err(|e| {
                    tracing::error!("[get_token_pubkey_info] Failed to get token pubkey info: {e}");
                    tonic::Status::not_found(format!("Failed to get token pubkey info: {e}"))
                })?;

            if let Some(mut token_info) = token_info_option {
                tracing::info!(
                    "[get_token_pubkey_info] Found token info, initial total_supply: {}",
                    token_info.total_supply
                );

                tracing::info!("[get_token_pubkey_info] Fetching issue leaves for token pubkey");

                let issue_leaves = self
                    .node_storage
                    .get_issue_leaves_by_token_pubkey(pubkey_bytes)
                    .await
                    .map_err(|err| {
                        tracing::error!(
                            "[get_token_pubkey_info] Failed to select issue leaves: {}",
                            err
                        );
                        tonic::Status::internal(format!("Failed to select issue leaves: {}", err))
                    })?;

                tracing::info!(
                    "[get_token_pubkey_info] Found {} issue leaves for token pubkey",
                    issue_leaves.len()
                );

                let spark_supply: u128 = issue_leaves
                    .iter()
                    .map(|leaf| leaf.receipt.token_amount.amount)
                    .sum();

                tracing::info!(
                    "[get_token_pubkey_info] Calculated spark_supply: {}",
                    spark_supply
                );

                let original_total_supply = token_info.total_supply;
                token_info.total_supply =
                    token_info.total_supply.saturating_add(spark_supply).to_be();

                tracing::info!(
                    "[get_token_pubkey_info] Updated total_supply: {} (original: {} + spark: {})",
                    token_info.total_supply,
                    original_total_supply,
                    spark_supply
                );

                token_infos.push(token_info.into());
                tracing::info!("[get_token_pubkey_info] Added token info to response");
            } else {
                tracing::info!("[get_token_pubkey_info] Token pubkey info not found, skipping");
            }
            // Skip not found token pubkeys instead of returning an error
        }

        if token_infos.is_empty() {
            tracing::info!("[get_token_pubkey_info] No token pubkey info found, returning error");
            return Err(tonic::Status::not_found("No token pubkey info found"));
        }

        tracing::info!(
            elapsed = ?start_time.elapsed(),
            "[get_token_pubkey_info] Completed get_token_pubkey_info request with {} token infos",
            token_infos.len()
        );

        Ok(tonic::Response::new(GetTokenPubkeyInfoResponse {
            token_pubkey_infos: token_infos,
        }))
    }

    async fn send_raw_lrc_transaction(
        &self,
        request: tonic::Request<SendRawTxRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
        let request = request.into_inner();
        let max_burn_amount_btc: Option<f64> = request
            .max_burn_amount
            .map(|max_burn_amount_sat| Amount::from_sat(max_burn_amount_sat).to_btc());

        let lrc_tx = Lrc20Transaction::from_hex(request.tx).map_err(|err| {
            tracing::error!("Failed to parse LRC20 tx hex: {err}");
            tonic::Status::invalid_argument("Failed to parse lrc20 tx hex")
        })?;

        let send_tx_result = self
            .bitcoin_client
            .send_raw_transaction_opts(&lrc_tx.bitcoin_tx, None, max_burn_amount_btc)
            .await;

        match send_tx_result {
            Ok(_) => {}
            Err(bitcoin_client::Error::JsonRpc(JsonRpcError::Rpc(err)))
                if err.code == BTC_RPC_VERIFY_ALREADY_IN_CHAIN => {}
            Err(err) => {
                return Err(tonic::Status::internal(format!(
                    "internal error, while sending transaction to bitcoin occurs: {err}"
                )));
            }
        }

        self.send_txs_to_confirm(vec![lrc_tx]).await?;

        Ok(tonic::Response::new(()))
    }
}

impl<NS, BC> SparkRpcServer<NS, BC>
where
    BC: BitcoinRpcApi + Send + Sync + 'static,
    NS: PgDatabaseConnectionManager + SparkNodeStorage + Send + Sync + 'static,
{
    pub fn new(
        event_bus: EventBus,
        spark_tx_storage: NS,
        bitcoin_client: Arc<BC>,
        node_storage: NS,
        enforce_announcement: bool,
    ) -> Self {
        let event_bus = event_bus
            .extract(&typeid![ControllerMessage], &typeid![])
            .expect("event channels must be presented");

        Self {
            event_bus,
            spark_tx_storage,
            bitcoin_client,
            node_storage,
            enforce_announcement,
        }
    }

    async fn send_spark_txs_to_check(
        &self,
        token_txs: Vec<TokenTransaction>,
        callback: Option<mpsc::Sender<bool>>,
    ) -> Result<(), tonic::Status> {
        tracing::info!(
            tx_count = token_txs.len(),
            tx_hashes = ?token_txs.iter().map(|tx| tx.hash().to_string()).collect::<Vec<_>>(),
            "[send_spark_txs_to_check] Sending {} transactions to check",
            token_txs.len()
        );

        // Send message to message handler about new spark txs.
        self.event_bus
            .try_send(ControllerMessage::NewSparkTxs(token_txs, callback))
            .await
            // If we failed to send message to message handler, then it's dead.
            .map_err(|_| {
                tracing::error!(
                    "[send_spark_txs_to_check] Failed to send message to message handler"
                );
                tonic::Status::internal("Service is dead")
            })?;

        tracing::info!("[send_spark_txs_to_check] Successfully sent transactions to check");
        Ok(())
    }

    async fn send_spark_signature_data_to_check(
        &self,
        request: Vec<SparkSignatureData>,
        callback: Option<mpsc::Sender<bool>>,
    ) -> Result<(), tonic::Status> {
        tracing::info!(
            signature_count = request.len(),
            "[send_spark_signature_data_to_check] Sending {} signatures to check",
            request.len()
        );

        // Send message to message handler about new spark signatures.
        self.event_bus
            .try_send(ControllerMessage::NewSparkSignaturesRequest(
                request, callback,
            ))
            .await
            // If we failed to send message to message handler, then it's dead.
            .map_err(|_| {
                tracing::error!(
                    "[send_spark_signature_data_to_check] Failed to send message to message handler"
                );
                tonic::Status::internal("Service is dead")
            })?;

        tracing::info!(
            "[send_spark_signature_data_to_check] Successfully sent signatures to check"
        );
        Ok(())
    }

    async fn send_tokens_freeze_request_to_check(
        &self,
        request: TokensFreezeData,
    ) -> Result<(), tonic::Status> {
        // Send message to message handler about new spark freezes.
        self.event_bus
            .try_send(ControllerMessage::NewFreezeTokensRequest(vec![request]))
            .await
            // If we failed to send message to message handler, then it's dead.
            .map_err(|_| {
                tracing::error!("failed to send message to message handler");
                tonic::Status::internal("Service is dead")
            })?;

        Ok(())
    }

    async fn send_txs_to_confirm(
        &self,
        lrc20_txs: Vec<Lrc20Transaction>,
    ) -> Result<(), tonic::Status> {
        // Send message to message handler about new tx with proof.
        self.event_bus
            .try_send(ControllerMessage::InitializeTxs(lrc20_txs))
            .await
            // If we failed to send message to message handler, then it's dead.
            .map_err(|_| {
                tracing::error!("failed to send message to message handler");
                tonic::Status::internal("failed to send message to message handler")
            })?;

        Ok(())
    }
}

#[derive(Debug)]
pub enum EmulationError {
    Storage(sea_orm::DbErr),
    Internal(eyre::Error),
    DoubleSpend {
        parent_hash: SparkHash,
        index: u32,
    },
    ParentTransactionNotFound(SparkHash),
    LeafNotFound {
        parent_hash: SparkHash,
        index: u32,
    },
    LeafIsSpent {
        parent_hash: SparkHash,
        index: u32,
        child_tx: SparkHash,
    },
    ConservationRulesViolated,
    InvalidInputLeavesNumber {
        expected: usize,
        got: usize,
    },
    DuplicateLeafId(String),
    LeafExists(String),
    ParentTransactionNotFinalized(SparkHash),
}

impl From<EmulationError> for tonic::Status {
    fn from(err: EmulationError) -> Self {
        match err {
            EmulationError::Storage(error) => {
                tonic::Status::internal(format!("Storage error: {}", error))
            }
            EmulationError::Internal(report) => {
                tonic::Status::internal(format!("Internal error: {}", report))
            }
            EmulationError::DoubleSpend { parent_hash, index } => tonic::Status::invalid_argument(
                format!("Double spending of input leaf {}:{}", parent_hash, index),
            ),
            EmulationError::ParentTransactionNotFound(spark_hash) => {
                tonic::Status::not_found(format!("Parent transaction {} is not found", spark_hash))
            }
            EmulationError::LeafNotFound { parent_hash, index } => {
                tonic::Status::not_found(format!(
                    "Input leaf {} is not found in the parent transaction {}",
                    index, parent_hash
                ))
            }
            EmulationError::LeafIsSpent {
                parent_hash,
                index,
                child_tx,
            } => tonic::Status::invalid_argument(format!(
                "Input leaf {}:{} is already spent tried to {}",
                parent_hash, index, child_tx
            )),
            EmulationError::ConservationRulesViolated => {
                tonic::Status::invalid_argument("Conservation rules violated")
            }
            EmulationError::InvalidInputLeavesNumber { expected, got } => {
                tonic::Status::invalid_argument(format!(
                    "Invalid number of input leaves, expected {}, got {}",
                    expected, got
                ))
            }
            EmulationError::DuplicateLeafId(id) => {
                tonic::Status::invalid_argument(format!("Duplicate output leaf id: {}", id))
            }
            EmulationError::LeafExists(id) => {
                tonic::Status::invalid_argument(format!("Leaf {} already exists", id))
            }
            EmulationError::ParentTransactionNotFinalized(spark_hash) => {
                tonic::Status::invalid_argument(format!(
                    "Parent transaction {} is not finalized",
                    spark_hash
                ))
            }
        }
    }
}

impl From<eyre::Error> for EmulationError {
    fn from(e: eyre::Error) -> Self {
        EmulationError::Internal(e)
    }
}

impl From<sea_orm::DbErr> for EmulationError {
    fn from(e: sea_orm::DbErr) -> Self {
        EmulationError::Storage(e)
    }
}

struct SparkTxEmulator<STS> {
    spark_txs_storage: STS,
}

impl<STS> SparkTxEmulator<STS>
where
    STS: PgDatabaseConnectionManager + SparkNodeStorage + Send + Sync + 'static,
{
    pub fn new(spark_txs_storage: STS) -> Self {
        Self { spark_txs_storage }
    }

    pub async fn check_spark_tx(&self, tx: TokenTransaction) -> Result<(), EmulationError> {
        let tx_hash = tx.hash().to_string();
        tracing::info!(
            tx_hash = ?tx_hash,
            tx_type = ?match &tx.input {
                TokenTransactionInput::Mint { .. } => "Mint",
                TokenTransactionInput::Transfer { .. } => "Transfer",
            },
            leaves_count = tx.leaves_to_create.len(),
            "[check_spark_tx] Starting transaction check"
        );

        match &tx.input {
            TokenTransactionInput::Mint { .. } => {
                tracing::info!(
                    tx_hash = ?tx_hash,
                    "[check_spark_tx] Processing mint transaction"
                );
            }
            TokenTransactionInput::Transfer { outputs_to_spend } => {
                tracing::info!(
                    tx_hash = ?tx_hash,
                    inputs_count = outputs_to_spend.len(),
                    "[check_spark_tx] Processing transfer transaction with {} inputs",
                    outputs_to_spend.len()
                );
                self.check_spark_transfer(&tx, outputs_to_spend).await?
            }
        };

        let spark_hash = tx.hash();
        tracing::info!(
            tx_hash = ?tx_hash,
            "[check_spark_tx] Checking if transaction already exists"
        );

        let token_tx = self
            .spark_txs_storage
            .get_spark_tx_with_outputs(spark_hash)
            .await?;

        let should_check_existing_leaves = match token_tx {
            Some(existing_tx) => {
                tracing::info!(
                    tx_hash = ?tx_hash,
                    "[check_spark_tx] Transaction already exists, checking compatibility"
                );

                if let TokenTransactionInput::Transfer { outputs_to_spend } = &tx.input {
                    let expected_len = match &existing_tx.input {
                        TokenTransactionInput::Mint { .. } => 0,
                        TokenTransactionInput::Transfer { outputs_to_spend } => {
                            outputs_to_spend.len()
                        }
                    };

                    if expected_len != outputs_to_spend.len() {
                        tracing::error!(
                            tx_hash = ?tx_hash,
                            expected = expected_len,
                            got = outputs_to_spend.len(),
                            "[check_spark_tx] Invalid number of input leaves"
                        );

                        return Err(EmulationError::InvalidInputLeavesNumber {
                            expected: expected_len,
                            got: outputs_to_spend.len(),
                        });
                    }

                    let status = self
                        .spark_txs_storage
                        .get_token_transaction_status(spark_hash)
                        .await?;

                    tracing::info!(
                        tx_hash = ?tx_hash,
                        status = ?status,
                        "[check_spark_tx] Transaction status: {:?}",
                        status
                    );

                    matches!(status, TokenTransactionStatus::Finalized)
                } else {
                    true
                }
            }
            None => {
                tracing::info!(
                    tx_hash = ?tx_hash,
                    "[check_spark_tx] Transaction does not exist yet"
                );
                true
            }
        };

        tracing::info!(
            tx_hash = ?tx_hash,
            should_check = should_check_existing_leaves,
            leaves_count = tx.leaves_to_create.len(),
            "[check_spark_tx] Checking created leaves (should check existing: {})",
            should_check_existing_leaves
        );

        self.check_created_leaves(&tx.leaves_to_create, should_check_existing_leaves)
            .await?;

        tracing::info!(
            tx_hash = ?tx_hash,
            "[check_spark_tx] Transaction check completed successfully"
        );

        Ok(())
    }

    pub async fn check_spark_transfer(
        &self,
        tx: &TokenTransaction,
        leaves_to_spend: &[TokenLeafToSpend],
    ) -> Result<(), EmulationError> {
        let tx_hash = tx.hash().to_string();
        tracing::info!(
            tx_hash = ?tx_hash,
            inputs_count = leaves_to_spend.len(),
            "[check_spark_transfer] Checking transfer inputs"
        );

        let mut input_leaf_ids = HashSet::new();
        let mut input_leaves: Vec<TokenLeafOutput> = Vec::new();

        for (idx, parent_leaf) in leaves_to_spend.iter().enumerate() {
            let parent_hash = parent_leaf.parent_output_hash.to_string();
            let parent_vout = parent_leaf.parent_output_vout;

            tracing::info!(
                tx_hash = ?tx_hash,
                input_idx = idx,
                parent_hash = ?parent_hash,
                parent_vout = parent_vout,
                "[check_spark_transfer] Checking input #{} ({}:{})",
                idx, parent_hash, parent_vout
            );

            if input_leaf_ids.contains(&(
                parent_leaf.parent_output_hash,
                parent_leaf.parent_output_vout,
            )) {
                tracing::error!(
                    tx_hash = ?tx_hash,
                    parent_hash = ?parent_hash,
                    parent_vout = parent_vout,
                    "[check_spark_transfer] Double spend detected"
                );

                return Err(EmulationError::DoubleSpend {
                    parent_hash: parent_leaf.parent_output_hash.into(),
                    index: parent_leaf.parent_output_vout,
                })?;
            }

            let parent_txid = parent_leaf.parent_output_hash.into();

            tracing::info!(
                tx_hash = ?tx_hash,
                parent_hash = ?parent_hash,
                "[check_spark_transfer] Fetching parent transaction"
            );

            let parent_tx = self
                .spark_txs_storage
                .get_spark_tx_with_outputs(parent_txid)
                .await?;

            let parent_tx =
                parent_tx.ok_or(EmulationError::ParentTransactionNotFound(parent_txid))?;

            tracing::info!(
                tx_hash = ?tx_hash,
                parent_hash = ?parent_hash,
                "[check_spark_transfer] Parent transaction found"
            );

            let Some(input_leaf) = parent_tx
                .leaves_to_create
                .get(parent_leaf.parent_output_vout as usize)
            else {
                tracing::error!(
                    tx_hash = ?tx_hash,
                    parent_hash = ?parent_hash,
                    parent_vout = parent_vout,
                    "[check_spark_transfer] Leaf not found in parent transaction"
                );

                return Err(EmulationError::LeafNotFound {
                    parent_hash: parent_leaf.parent_output_hash.into(),
                    index: parent_leaf.parent_output_vout,
                })?;
            };

            tracing::info!(
                tx_hash = ?tx_hash,
                parent_hash = ?parent_hash,
                parent_vout = parent_vout,
                "[check_spark_transfer] Checking parent transaction status"
            );

            let parent_sigs = self
                .spark_txs_storage
                .get_spark_signatures(parent_txid)
                .await
                .unwrap_or_default();

            let parent_revocation_keys = self
                .spark_txs_storage
                .get_revocation_secret_keys(parent_txid)
                .await
                .map_err(|err| {
                    tonic::Status::internal(format!("Failed to select revocation keys: {}", err))
                })
                .unwrap_or_default();

            let parent_tx_status = check_spark_tx_finalization(
                match parent_tx.clone().input {
                    TokenTransactionInput::Mint { .. } => 0,
                    TokenTransactionInput::Transfer { outputs_to_spend } => outputs_to_spend.len(),
                },
                &parent_sigs,
                &parent_revocation_keys,
            )?;

            if !matches!(parent_tx_status, TokenTransactionStatus::Finalized) {
                tracing::error!(
                    tx_hash = ?tx_hash,
                    parent_hash = ?parent_hash,
                    parent_status = ?parent_tx_status,
                    "[check_spark_transfer] Parent transaction is not finalized"
                );

                return Err(EmulationError::ParentTransactionNotFinalized(parent_txid));
            }

            tracing::info!(
                tx_hash = ?tx_hash,
                parent_hash = ?parent_hash,
                parent_vout = parent_vout,
                "[check_spark_transfer] Parent transaction is finalized"
            );

            input_leaves.push(input_leaf.to_owned());

            tracing::info!(
                tx_hash = ?tx_hash,
                parent_hash = ?parent_hash,
                parent_vout = parent_vout,
                "[check_spark_transfer] Checking if leaf is already spent"
            );

            let spent_leaf = self
                .spark_txs_storage
                .get_spent_output(
                    parent_leaf.parent_output_hash.into(),
                    parent_leaf.parent_output_vout as usize,
                )
                .await?;

            if let Some(spent_leaf) = spent_leaf {
                tracing::error!(
                    tx_hash = ?tx_hash,
                    parent_hash = ?parent_hash,
                    parent_vout = parent_vout,
                    "[check_spark_transfer] Leaf is already spent"
                );
                // Additional error handling logic here
            }

            input_leaf_ids.insert((
                parent_leaf.parent_output_hash,
                parent_leaf.parent_output_vout,
            ));
        }

        tracing::info!(
            tx_hash = ?tx_hash,
            inputs_count = input_leaves.len(),
            outputs_count = tx.leaves_to_create.len(),
            "[check_spark_transfer] Checking conservation rules"
        );

        if !check_spark_conservation_rules(&input_leaves, &tx.leaves_to_create) {
            tracing::error!(
                tx_hash = ?tx_hash,
                "[check_spark_transfer] Conservation rules violated"
            );

            return Err(EmulationError::ConservationRulesViolated)?;
        };

        tracing::info!(
            tx_hash = ?tx_hash,
            "[check_spark_transfer] Transfer check completed successfully"
        );

        Ok(())
    }

    pub async fn check_created_leaves(
        &self,
        leaves: &[TokenLeafOutput],
        should_check_existing_leaves: bool,
    ) -> Result<(), EmulationError> {
        tracing::info!(
            leaves_count = leaves.len(),
            should_check = should_check_existing_leaves,
            "[check_created_leaves] Checking {} created leaves (should check existing: {})",
            leaves.len(),
            should_check_existing_leaves
        );

        let mut leaf_ids = HashSet::new();

        for (idx, new_leaf) in leaves.iter().enumerate() {
            tracing::info!(
                leaf_idx = idx,
                leaf_id = ?new_leaf.id,
                "[check_created_leaves] Checking leaf #{} with ID {}",
                idx,
                new_leaf.id
            );

            if leaf_ids.contains(&new_leaf.id) {
                tracing::error!(
                    leaf_id = ?new_leaf.id,
                    "[check_created_leaves] Duplicate leaf ID detected"
                );

                return Err(EmulationError::DuplicateLeafId(new_leaf.id.clone()))?;
            }

            leaf_ids.insert(new_leaf.id.clone());

            // Skip checking leaves existance for non-finalized transactions
            if !should_check_existing_leaves {
                tracing::info!(
                    leaf_id = ?new_leaf.id,
                    "[check_created_leaves] Skipping existence check for leaf"
                );
                continue;
            }

            tracing::info!(
                leaf_id = ?new_leaf.id,
                "[check_created_leaves] Checking if leaf already exists"
            );

            let stored_leaf = self
                .spark_txs_storage
                .get_spark_output_model(new_leaf.id.clone())
                .await?;

            if stored_leaf.is_some() {
                tracing::error!(
                    leaf_id = ?new_leaf.id,
                    "[check_created_leaves] Leaf already exists"
                );

                return Err(EmulationError::LeafExists(new_leaf.id.clone()))?;
            }

            tracing::info!(
                leaf_id = ?new_leaf.id,
                "[check_created_leaves] Leaf does not exist yet"
            );
        }

        tracing::info!(
            leaves_count = leaves.len(),
            "[check_created_leaves] All leaves checked successfully"
        );

        Ok(())
    }
}
