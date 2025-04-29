use std::{
    collections::HashMap,
    future,
    sync::{Arc, RwLock},
};

use bdk::{
    Balance, LocalUtxo, SignOptions,
    blockchain::{
        AnyBlockchainConfig, Blockchain, RpcConfig, esplora::EsploraBlockchainConfig,
        rpc::RpcSyncParams,
    },
    descriptor,
    wallet::wallet_name_from_descriptor,
};
use bitcoin::{
    Address, Network, OutPoint, PrivateKey, PublicKey,
    secp256k1::{self, All, Secp256k1},
};
use eyre::Context;
use futures::TryStreamExt;
use lrc20_receipts::{Receipt, ReceiptProof, TokenPubkey};
use lrc20_rpc_api::transactions::Lrc20TransactionsRpcClient;
use lrc20_types::{Announcement, Lrc20Transaction};

use crate::{
    bitcoin_provider::{BitcoinProvider, BitcoinProviderConfig, TxOutputStatus},
    database::WalletStorage,
    sync::indexer::Lrc20TransactionsIndexer,
    txbuilder::{IssuanceTransactionBuilder, SweepTransactionBuilder, TransferTransactionBuilder},
    types::{FeeRateStrategy, Lrc20Balances},
};

#[cfg(feature = "sqlite")]
mod storage;
#[cfg(feature = "sqlite")]
pub use storage::{StorageWallet, StorageWalletConfig};

#[cfg(feature = "inmemory")]
mod inmemory;
#[cfg(feature = "inmemory")]
pub use inmemory::MemoryWallet;

pub const DEFAULT_FEE_RATE_STRATEGY: FeeRateStrategy = FeeRateStrategy::TryEstimate {
    fee_rate: 1.0,
    target: 2,
};

/// Configuration parameters requried to construct [`Wallet`].
#[derive(Clone, Debug)]
pub struct WalletConfig {
    /// Private key of the user.
    pub privkey: PrivateKey,

    /// Network of the wallet.
    pub network: Network,

    /// Bitcoin provider config
    pub bitcoin_provider: BitcoinProviderConfig,

    // == LRC20 node RPC ==
    /// URL of LRC20 node RPC API.
    pub lrc20_url: String,
}

impl TryFrom<WalletConfig> for AnyBlockchainConfig {
    type Error = eyre::Error;

    fn try_from(config: WalletConfig) -> Result<Self, Self::Error> {
        let secp_ctx = Secp256k1::new();

        let wallet_name = wallet_name_from_descriptor(
            descriptor!(wpkh(config.privkey))?,
            None,
            config.network,
            &secp_ctx,
        )?;

        let res = match config.bitcoin_provider {
            BitcoinProviderConfig::Esplora(cfg) => {
                AnyBlockchainConfig::Esplora(EsploraBlockchainConfig::new(cfg.url, cfg.stop_gap))
            }
            BitcoinProviderConfig::BitcoinRpc(cfg) => AnyBlockchainConfig::Rpc(RpcConfig {
                url: cfg.url,
                auth: cfg.auth,
                network: cfg.network,
                wallet_name,
                sync_params: Some(RpcSyncParams {
                    start_time: cfg.start_time,
                    ..Default::default()
                }),
            }),
        };

        Ok(res)
    }
}

unsafe impl<YPC, YTD, BP, BTDB> Sync for Wallet<YPC, YTD, BP, BTDB>
where
    YPC: Sync,
    YTD: Sync,
    BP: Sync,
    BTDB: Sync,
{
}

unsafe impl<YPC, YTD, BP, BTDB> Send for Wallet<YPC, YTD, BP, BTDB>
where
    YPC: Send,
    YTD: Send,
    BP: Send,
    BTDB: Send,
{
}

pub struct SyncOptions {
    pub inner: bdk::SyncOptions,
    /// Sync LRC20 wallet, defaults to true
    pub sync_lrc20_wallet: bool,
    /// Sync Bitcoin wallet, defaults to true
    pub sync_bitcoin_wallet: bool,
}

impl Default for SyncOptions {
    fn default() -> Self {
        Self {
            inner: Default::default(),
            sync_lrc20_wallet: true,
            sync_bitcoin_wallet: true,
        }
    }
}

impl SyncOptions {
    /// Sync only inner Bitcoin wallet without LRC20 wallet.
    pub fn bitcoin_only() -> Self {
        Self {
            sync_lrc20_wallet: false,
            ..Default::default()
        }
    }

    /// Sync only LRC20 wallet without inner Bitcoin wallet.
    pub fn lrc20_only() -> Self {
        Self {
            sync_bitcoin_wallet: false,
            ..Default::default()
        }
    }
}

/// A wallet that can manage LRC20 UTXOs and create transactions for LRC20 protocol.
#[derive(Clone)]
pub struct Wallet<Lrc20RpcClient, WalletStorage, BitcoinProvider, BitcoinTxsDB> {
    pub(crate) config: WalletConfig,

    /// Global wallet context used for internal operations on curve.
    pub(crate) secp_ctx: Secp256k1<All>,

    /// Private key of the user.
    pub(crate) signer_key: PrivateKey,
    pub(crate) network: Network,

    /// Client to access LRC20 node RPC API.
    pub(crate) lrc20_client: Lrc20RpcClient,

    /// Storage of transactions.
    pub(crate) storage: WalletStorage,

    /// Client to Bitcoin RPC.
    pub(crate) bitcoin_provider: BitcoinProvider,

    /// Bitcoin wallet
    pub(crate) bitcoin_wallet: Arc<RwLock<bdk::Wallet<BitcoinTxsDB>>>,
}

impl<YC, WS, BP, BTDB> Wallet<YC, WS, BP, BTDB>
where
    YC: Lrc20TransactionsRpcClient + Clone + Send + Sync + 'static,
    WS: WalletStorage,
    BP: BitcoinProvider + Clone + Send + Sync + 'static,
    BTDB: bdk::database::BatchDatabase + Clone + Send + Sync,
{
    pub fn new(
        config: WalletConfig,
        privkey: PrivateKey,
        network: Network,
        lrc20_client: YC,
        lrc20_txs_storage: WS,
        bitcoin_provider: BP,
        bitcoin_txs_storage: BTDB,
    ) -> eyre::Result<Self> {
        let bitcoin_wallet = bdk::Wallet::<BTDB>::new(
            descriptor!(wpkh(privkey))?,
            None,
            network,
            bitcoin_txs_storage,
        )
        .wrap_err("Failed to initialize wallet")?;

        Ok(Self {
            config,
            secp_ctx: Secp256k1::new(),
            signer_key: privkey,
            network,
            lrc20_client,
            storage: lrc20_txs_storage,
            bitcoin_provider,
            bitcoin_wallet: Arc::new(RwLock::new(bitcoin_wallet)),
        })
    }

    /// Synchronize from LRC20 node all unspent outpoints and sync the internal bitcoin wallet
    /// database with the blockchain
    pub async fn sync(&self, opts: SyncOptions) -> eyre::Result<()> {
        if opts.sync_bitcoin_wallet {
            self.bitcoin_wallet
                .write()
                .unwrap()
                .sync(&self.bitcoin_provider.blockchain(), opts.inner)?;
        }

        // Skip syncing of LRC20 wallet if we don't need that.
        if !opts.sync_lrc20_wallet {
            return Ok(());
        }

        let pubkey = self.signer_key.public_key(&self.secp_ctx).inner;

        Lrc20TransactionsIndexer::new(
            self.lrc20_client.clone(),
            Arc::clone(&self.bitcoin_provider.blockchain()),
            self.storage.clone(),
            pubkey,
            self.config.lrc20_url.clone(),
        )
        .sync()
        .await
        .wrap_err("Failed to sync LRC20 transactions from node")?;

        self.mark_spent_utxos().await?;

        Ok(())
    }

    pub fn address(&self) -> eyre::Result<Address> {
        let addr = Address::p2wpkh(&self.signer_key.public_key(&self.secp_ctx), self.network)?;

        Ok(addr)
    }

    pub fn public_key(&self) -> PublicKey {
        self.signer_key.public_key(&self.secp_ctx)
    }

    pub fn bitcoin_provider(&self) -> BP {
        self.bitcoin_provider.clone()
    }

    /// Return the reference to inner [`bdk::Wallet`] which handles the indexing of
    /// Bitcoins for us.
    ///
    /// # Safety
    ///
    /// This methods is marked as unsafe as it's related to unsafe
    /// implementations for [`Wallet`] of `Send` and `Sync`. The problem is,
    /// that [`bdk::Wallet`] has `RefCell` inside of it, because of which we
    /// cannot borrow and use it in async context. But still [`bdk::Wallet`]
    /// wallet has getter method for database [`bdk::Wallet::database`] which is
    /// not recommended to use.
    pub unsafe fn bitcoin_wallet(&self) -> Arc<RwLock<bdk::Wallet<BTDB>>> {
        Arc::clone(&self.bitcoin_wallet)
    }

    /// By calling [`gettxout`] for each unspent LRC20 transaction got from node,
    /// check if transaction is already spent on Bitcoin.
    ///
    /// This could happen when proofs were not brought to node in time, so this
    /// function prevents this.
    ///
    /// [`gettxout`]: https://developer.bitcoin.org/reference/rpc/gettxout.html
    async fn mark_spent_utxos(&self) -> eyre::Result<()> {
        let mut stream = self.storage.stream_unspent_lrc20_outputs().await;

        while let Some((outpoint, _)) = stream.try_next().await? {
            let output_status = self
                .bitcoin_provider
                .get_tx_out_status(outpoint)
                .wrap_err("failed to get tx output")?;

            match output_status {
                TxOutputStatus::Spent | TxOutputStatus::NotFound => {
                    tracing::debug!("UTXO {} is spent", outpoint);
                    self.storage.mark_lrc20_output_as_spent(outpoint).await?;
                    continue;
                }
                TxOutputStatus::Unspent => {}
            }
        }

        Ok(())
    }

    /// Calculate current balances by iterating through transactions from
    /// intenal storage.
    pub async fn balances(&self) -> eyre::Result<Lrc20Balances> {
        let mut lrc20_balances = HashMap::new();
        #[cfg(feature = "bulletproof")]
        let mut bulletproof_balances = HashMap::new();
        let mut tweaked_satoshis_balances = 0;

        let utxos: Vec<_> = self.storage.collect_unspent_lrc20_outputs().await?;

        for (_, (proof, txout)) in utxos {
            if proof.is_empty_receiptproof() {
                tweaked_satoshis_balances += txout.value.to_sat();
                continue;
            }

            let receipt = proof.receipt();

            #[cfg(feature = "bulletproof")]
            if proof.is_bulletproof() {
                *bulletproof_balances
                    .entry(receipt.token_pubkey)
                    .or_insert(0) += receipt.token_amount.amount;
                continue;
            }

            *lrc20_balances.entry(receipt.token_pubkey).or_insert(0) += receipt.token_amount.amount;
        }

        Ok(Lrc20Balances {
            lrc20: lrc20_balances,
            tweaked_satoshis: tweaked_satoshis_balances,
            #[cfg(feature = "bulletproof")]
            bulletproof: bulletproof_balances,
        })
    }

    /// Get Bitcoin balances.
    pub fn bitcoin_balances(&self) -> eyre::Result<Balance> {
        Ok(self.bitcoin_wallet.read().unwrap().get_balance()?)
    }

    /// Get all unspent Bitcoin outputs.
    pub fn bitcoin_utxos(&self) -> eyre::Result<Vec<LocalUtxo>> {
        Ok(self.bitcoin_wallet.read().unwrap().list_unspent()?)
    }

    /// Get all unspent LRC20 transactions outputs with given [`TokenPubkey`].
    pub async fn utxos_by_token_pubkey(
        &self,
        token_pubkey: TokenPubkey,
    ) -> eyre::Result<Vec<(OutPoint, u128)>> {
        self.storage
            .stream_unspent_lrc20_outputs()
            .await
            .try_filter(|(_, (proof, _))| {
                future::ready(proof.receipt().token_pubkey == token_pubkey)
            })
            .map_ok(|(op, (proof, _))| (op, proof.receipt().token_amount.amount))
            .try_collect()
            .await
    }

    /// Get unspent LRC20 transactions with the given filter.
    async fn utxos<P>(&self, filter: P) -> eyre::Result<HashMap<OutPoint, ReceiptProof>>
    where
        P: Fn(&OutPoint, &ReceiptProof) -> bool + Send,
    {
        self.storage
            .stream_unspent_lrc20_outputs()
            .await
            .map_ok(|(op, (proof, _))| (op, proof))
            .try_filter(|(op, proof)| future::ready(filter(op, proof)))
            .try_collect()
            .await
    }

    /// Get all unspent LRC20 transactions outputs.
    pub async fn lrc20_utxos(&self) -> eyre::Result<HashMap<OutPoint, ReceiptProof>> {
        self.utxos(|_, proof| !proof.is_empty_receiptproof()).await
    }

    /// Get unspent tweaked Bitcoin outputs.
    ///
    /// Note: all the tweaked unspent outputs are tweaked by the same zero token_pubkey.
    pub async fn tweaked_satoshi_utxos(&self) -> eyre::Result<HashMap<OutPoint, ReceiptProof>> {
        self.utxos(|_, proof| proof.is_empty_receiptproof()).await
    }

    /// Return [`Lrc20TxType::Transfer`] transaction builder for creating
    /// transaction by LRC20 protocol.
    ///
    /// [`Lrc20TxType::Transfer`]: lrc20_types::Lrc20TxType::Transfer
    pub fn build_transfer(&self) -> eyre::Result<TransferTransactionBuilder<WS, BTDB>> {
        TransferTransactionBuilder::try_from(self)
    }

    /// Return [`Lrc20TxType::Issue`] transaction builder for creating
    /// issuance transaction by LRC20 protocol
    ///
    /// [`Lrc20TxType::Issue`]: lrc20_types::Lrc20TxType::Issue
    pub fn build_issuance(
        &self,
        token_pubkey: Option<TokenPubkey>,
    ) -> eyre::Result<IssuanceTransactionBuilder<WS, BTDB>> {
        IssuanceTransactionBuilder::new(self, token_pubkey)
    }

    /// Return a sweep transaction builder for creating
    /// a sweep transaction by LRC20 protocol.
    pub fn build_sweep(&self) -> eyre::Result<SweepTransactionBuilder<WS, BTDB>> {
        SweepTransactionBuilder::try_from(self)
    }

    /// Create funding lightning transaction from:
    ///
    /// * `funding_receipt` - token_pubkey and amount that will be in Lightning Network
    ///    funding transaction.
    /// * `holder_pubkey` - funding pubkey of the holder.
    /// * `counterparty_pubkey` - funding pubkey of the counterparty.
    /// * `satoshis` - value of satoshis that will be included in funding transaction
    ///    with `funding_receipt`.
    /// * optional `fee_rate_strategy` which defaults to `TryEstimate` with `fee_rate = 1.0`.
    ///
    /// The keys will be sorted in lexical order, and the first one after that will be tweaked
    ///  by `funding_receipt`.
    ///
    /// # Returns
    ///
    /// Returns [`Lrc20Transaction`] with 2 of 2 multisig which has specified
    /// `satoshis` value and receipt from `funding_receipt`, `holder_pubkey` and
    /// `counterparty_pubkey` as spenders and filled Bitcoin and LRC20 inputs with
    ///  some additional outputs for change.
    pub async fn lightning_funding_tx(
        &self,
        funding_receipt: Receipt,
        holder_pubkey: secp256k1::PublicKey,
        counterparty_pubkey: secp256k1::PublicKey,
        satoshis: u64,
        fee_rate_strategy: Option<FeeRateStrategy>,
    ) -> eyre::Result<Lrc20Transaction> {
        let fee_rate_strategy = fee_rate_strategy.unwrap_or(DEFAULT_FEE_RATE_STRATEGY);

        let mut tx_builder = self
            .build_transfer()
            .wrap_err("failed to init transaction builder")?;

        tx_builder
            .add_multisig_recipient(
                vec![holder_pubkey, counterparty_pubkey],
                2,
                funding_receipt.token_amount.amount,
                funding_receipt.token_pubkey,
                satoshis,
            )
            .set_fee_rate_strategy(fee_rate_strategy);

        let lrc20_transaction = tx_builder
            .finish(&self.bitcoin_provider.blockchain())
            .await
            .wrap_err("failed to build lrc20 transaction")?;

        Ok(lrc20_transaction)
    }

    /// Create a simple transfer to given recipient with given receipt.
    pub async fn create_transfer(
        &self,
        receipt: Receipt,
        recipient: secp256k1::PublicKey,
        fee_rate_strategy: Option<FeeRateStrategy>,
    ) -> eyre::Result<Lrc20Transaction> {
        let fee_rate_strategy = fee_rate_strategy.unwrap_or(DEFAULT_FEE_RATE_STRATEGY);

        let mut tx_builder = self
            .build_transfer()
            .wrap_err("failed to init transaction builder")?;

        tx_builder
            .add_recipient(
                receipt.token_pubkey,
                &recipient,
                receipt.token_amount.amount,
                1000,
            )
            .set_fee_rate_strategy(fee_rate_strategy);

        let lrc20_tx = tx_builder
            .finish(&self.bitcoin_provider.blockchain())
            .await
            .wrap_err("failed to build lrc20 transaction")?;

        Ok(lrc20_tx)
    }

    /// Create LRC20 [`Announcement`] transaction for given [`Announcement`].
    pub fn create_announcement_tx(
        &self,
        announcement: Announcement,
        fee_rate_strategy: FeeRateStrategy,
        blockchain: &impl Blockchain,
    ) -> eyre::Result<Lrc20Transaction> {
        let tx = {
            let wallet = self.bitcoin_wallet.read().unwrap();
            let mut builder = wallet.build_tx();

            let fee_rate = fee_rate_strategy
                .get_fee_rate(blockchain)
                .wrap_err("failed to estimate fee")?;

            builder
                .add_recipient(announcement.to_script(), 0)
                .fee_rate(fee_rate)
                .allow_dust(true);

            let (mut psbt, _) = builder.finish()?;

            wallet.sign(&mut psbt, SignOptions::default())?;

            psbt.extract_tx()?
        };

        Ok(Lrc20Transaction::new(tx, announcement.into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that [`Wallet`] implements `Sync` and `Send`.
    #[test]
    fn wallet_is_sync_and_send() {
        fn assert_sync<T: Sync>() {}
        fn assert_send<T: Send>() {}

        assert_sync::<MemoryWallet>();
        assert_send::<MemoryWallet>();

        assert_sync::<StorageWallet>();
        assert_send::<StorageWallet>();
    }
}
