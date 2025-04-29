use bitcoin::secp256k1::PublicKey;
use jsonrpsee::proc_macros::rpc;

#[cfg(feature = "server")]
use jsonrpsee::core::RpcResult;

#[cfg(feature = "client")]
use {
    futures::{StreamExt, future::BoxFuture, stream::BoxStream},
    jsonrpsee::core::Error,
};

use lrc20_receipts::TokenPubkey;
use lrc20_types::Lrc20Transaction;
use lrc20_types::announcements::TokenPubkeyInfo;

use crate::transactions::{
    BlockHash, EmulateLrc20TransactionResponse, GetRawLrc20TransactionResponseJson,
    Lrc20TransactionResponse, ProvideLrc20ProofRequest, Txid,
};

use super::GetRawLrc20TransactionResponseHex;

/// RPC methods for transactions.
#[cfg_attr(all(feature = "client", not(feature = "server")), rpc(client))]
#[cfg_attr(all(feature = "server", not(feature = "client")), rpc(server))]
#[cfg_attr(all(feature = "server", feature = "client"), rpc(server, client))]
#[async_trait::async_trait]
pub trait Lrc20TransactionsRpc {
    /// Provide LRC20 proofs to LRC20 transaction by full LRC20 transaction.
    #[method(name = "providelrc20proof")]
    async fn provide_lrc20_proof(&self, lrc20_tx: Lrc20Transaction) -> RpcResult<bool>;

    /// Provide proofs to LRC20 transaction by LRC20 proofs and Txid.
    #[method(name = "providelrc20proofshort")]
    async fn provide_lrc20_proof_short(
        &self,
        txid: Txid,
        tx_type: String,
        blockhash: Option<BlockHash>,
    ) -> RpcResult<bool>;

    /// Provide LRC20 transactions to LRC20 node without submitting them on-chain.
    #[method(name = "providelistlrc20proofs")]
    async fn provide_list_lrc20_proofs(
        &self,
        proofs: Vec<ProvideLrc20ProofRequest>,
    ) -> RpcResult<bool>;

    /// Get LRC20 transaction by id and return its proofs.
    #[method(name = "getrawlrc20transaction")]
    #[deprecated(since = "0.6.0", note = "use `getlrc20transaction` instead")]
    async fn get_raw_lrc20_transaction(
        &self,
        txid: Txid,
    ) -> RpcResult<GetRawLrc20TransactionResponseJson>;

    /// Get HEX encoded LRC20 transaction by id and return its proofs.
    #[method(name = "getlrc20transaction")]
    async fn get_lrc20_transaction(
        &self,
        txid: Txid,
    ) -> RpcResult<GetRawLrc20TransactionResponseHex>;

    /// Get HEX encoded LRC20 transactions that are currently in the LRC20 node's mempool.
    #[method(name = "getrawlrc20mempool")]
    async fn get_raw_lrc20_mempool(&self) -> RpcResult<Vec<GetRawLrc20TransactionResponseHex>>;

    /// Get list of LRC20 transactions by id and return its proofs. If requested transactions aren't
    /// exist the response array will be empty.
    #[method(name = "getlistrawlrc20transactions")]
    async fn get_list_raw_lrc20_transactions(
        &self,
        txids: Vec<Txid>,
    ) -> RpcResult<Vec<Lrc20TransactionResponse>>;

    /// Get list of LRC20 transactions by id and return its proofs encoded in hex and status.
    /// If requested transactions aren't exist the response array will be empty.
    #[method(name = "getlistlrc20transactions")]
    async fn get_list_lrc20_transactions(
        &self,
        txids: Vec<Txid>,
    ) -> RpcResult<Vec<GetRawLrc20TransactionResponseHex>>;

    /// Get transaction list by page number.
    #[method(name = "listlrc20transactions")]
    async fn list_lrc20_transactions(&self, page: u64) -> RpcResult<Vec<Lrc20TransactionResponse>>;

    /// Send LRC20 transaction to Bitcoin network.
    #[method(name = "sendrawlrc20transaction")]
    #[deprecated(since = "0.6.0", note = "use `sendlrc20transaction` instead")]
    async fn send_raw_lrc20_tx(
        &self,
        lrc20_tx: Lrc20Transaction,
        max_burn_amount: Option<u64>,
    ) -> RpcResult<bool>;

    /// Send LRC20 transaction HEX to Bitcoin network.
    #[method(name = "sendlrc20transaction")]
    async fn send_lrc20_tx(
        &self,
        lrc20_tx: String,
        max_burn_amount: Option<u64>,
    ) -> RpcResult<bool>;

    /// Check if LRC20 transaction is frozen or not.
    #[method(name = "islrc20txoutfrozen")]
    async fn is_lrc20_txout_frozen(&self, txid: Txid, vout: u32) -> RpcResult<bool>;

    /// Check if public key is frozen or not.
    #[method(name = "ispubkeyfrozen")]
    async fn is_pubkey_frozen(
        &self,
        pubkey: PublicKey,
        token_pubkey: TokenPubkey,
    ) -> RpcResult<bool>;

    /// Emulate transaction check and attach without actuall broadcasting or
    /// mining it to the network.
    ///
    /// This method is useful for checking if node can immidiatelly check and
    /// attach transaction to internal storage.
    #[method(name = "emulatelrc20transaction")]
    async fn emulate_lrc20_transaction(
        &self,
        lrc20_tx: Lrc20Transaction,
    ) -> RpcResult<EmulateLrc20TransactionResponse>;

    /// Get the [TokenPubkeyInfo] that contains the information about the token.
    #[method(name = "gettoken_pubkeyinfo")]
    async fn get_token_pubkey_info(
        &self,
        token_pubkey: TokenPubkey,
    ) -> RpcResult<Option<TokenPubkeyInfo>>;
}

#[cfg(feature = "client")]
/// The same as `BoxStream`, but `Result` with `Ok` and `Err` is an `Item`.
pub type BoxTryStream<'a, Ok, Err> = BoxStream<'a, Result<Ok, Err>>;

#[cfg(feature = "client")]
/// The same as `BoxFuture`, but `Result` with `Ok` and `Err` is an `Item`.
pub type BoxTryFuture<'a, Ok, Err> = BoxFuture<'a, Result<Ok, Err>>;

#[cfg(feature = "client")]
/// `try_buffered` requires items to be `Futures`, that's why `Ok = BoxTryFuture` here.
pub type BoxBufferableTryStream<'a, Ok, Err> = BoxTryStream<'a, BoxTryFuture<'a, Ok, Err>, Err>;

#[cfg(feature = "client")]
pub type BufferableTransactionPagesStream<'a> =
    BoxBufferableTryStream<'a, (u64, Vec<Lrc20TransactionResponse>), Error>;

#[cfg(feature = "client")]
/// Extension for transaction client with other usefull methods.
pub trait Lrc20TransactionsRpcClientExt: Lrc20TransactionsRpcClient + Clone + Send + Sync {
    /// Returns a stream of pages of [`Lrc20Transaction`] with it's page number.
    fn transaction_pages_stream(
        &self,
        start: u64,
    ) -> BoxTryStream<(u64, Vec<Lrc20TransactionResponse>), Error> {
        futures::stream::try_unfold(start, move |prev_page_num| async move {
            let page = self.list_lrc20_transactions(prev_page_num).await?;

            if page.is_empty() {
                return Ok(None);
            }

            let next_page_num = prev_page_num + 1;

            Ok(Some(((prev_page_num, page), next_page_num)))
        })
        .boxed()
    }
}

#[cfg(feature = "client")]
impl<T> Lrc20TransactionsRpcClientExt for T where T: Lrc20TransactionsRpcClient + Clone + Send + Sync
{}
