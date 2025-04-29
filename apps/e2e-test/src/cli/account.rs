use std::{collections::HashMap, sync::Arc, time::Duration};

use tokio::sync::mpsc::UnboundedSender;

use bdk::blockchain::{EsploraBlockchain, RpcBlockchain};
use bitcoin::{
    Address, PrivateKey,
    secp256k1::{
        Secp256k1,
        rand::{seq::IteratorRandom, thread_rng},
    },
};
use jsonrpsee::http_client::HttpClient;
use lrc20_receipts::{Receipt, TokenPubkey};
use lrc20_rpc_api::transactions::Lrc20TransactionsRpcClient;
use lrc20_types::{Lrc20Transaction, Lrc20TxType};
use lrcdk::{
    types::FeeRateStrategy,
    wallet::{MemoryWallet, SyncOptions},
};
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::e2e::NETWORK;

/// Minimum transfer amount.
const TRANSFER_LOWER_BOUND: u128 = 1000;
const TRANFERS_PER_ISSUANCE: u32 = 6;

/// Amount of tokens to issue.
///
/// The formula is `ISSUE_AMOUNT=Q*2**N` where `Q` is `TRANSFER_LOWER_BOUND` and `N` is the desired number of transactions
/// that can be performed from a single issuance.
/// This makes sense as at each iteration it is checked if the balance is higher than `TRANSFER_LOWER_BOUND`.
/// If it is, then half the balance is sent. Otherwise - the whole balance is sent.
const ISSUE_AMOUNT: u128 = TRANSFER_LOWER_BOUND * 2u128.pow(TRANFERS_PER_ISSUANCE);

/// Amount of satoshis to put into each LRC20 output.
const SATOSHIS_AMOUNT: u64 = 1000;

const ERROR_SLEEP_DURATION: Duration = Duration::from_secs(1);
const CANCELLATION_DURATION: Duration = Duration::from_secs(5);
const TX_SENDING_INTERVAL: Duration = Duration::from_secs(1);

pub(crate) static FEE_RATE_STARTEGY: FeeRateStrategy = FeeRateStrategy::Manual { fee_rate: 1.2 };

pub(crate) struct Account {
    private_key: PrivateKey,

    lrc20_client: HttpClient,
    esplora: EsploraBlockchain,
    rpc_blockchain: Option<RpcBlockchain>,

    wallet: MemoryWallet,
}

impl Account {
    pub fn new(
        private_key: PrivateKey,
        lrc20_client: HttpClient,
        esplora: EsploraBlockchain,
        rpc_blockchain: Option<RpcBlockchain>,
        wallet: MemoryWallet,
    ) -> Self {
        Self {
            private_key,
            lrc20_client,
            esplora,
            rpc_blockchain,
            wallet,
        }
    }

    /// Start sending transactions.
    pub async fn run(
        self,
        recipients: Arc<[PrivateKey]>,
        tx_sender: UnboundedSender<Lrc20Transaction>,
        balance_sender: UnboundedSender<(PrivateKey, HashMap<TokenPubkey, u128>)>,
        cancellation_token: CancellationToken,
    ) -> eyre::Result<()> {
        info!("Started sending transactions");

        let mut timer = tokio::time::interval(TX_SENDING_INTERVAL);

        loop {
            tokio::select! {
                _ = timer.tick() => {},
                // If a cancellation is received, stop sending transaction and send the balances to the `tx-checker`.
                _ = cancellation_token.cancelled() => {
                    self.finish(balance_sender).await?;
                    return Ok(());
                }
            }

            // Sync the wallet.
            self.wallet.sync(SyncOptions::default()).await?;

            // Create a raw LRC20 transaction.
            let tx: Lrc20Transaction = match self.build_transaction(&recipients).await {
                Ok(tx) => tx,
                // Report the error and sleep.
                Err(e) => {
                    warn!("tx failed: {}, sleeping", e);
                    sleep(ERROR_SLEEP_DURATION).await;
                    continue;
                }
            };

            let txid = tx.bitcoin_tx.txid();
            // Send the transaction.
            let response = self.lrc20_client.send_lrc20_tx(tx.hex(), None).await;
            if response.is_ok() {
                let tx_type = tx_type(&tx.tx_type);
                info!("{} tx sent | Txid: {}", tx_type, txid);

                // Send the TX to the tx checker.
                tx_sender.send(tx)?;
                continue;
            }

            warn!("Mempool conflict | Txid: {}", txid);
        }
    }

    async fn finish(
        mut self,
        balance_sender: UnboundedSender<(PrivateKey, HashMap<TokenPubkey, u128>)>,
    ) -> eyre::Result<()> {
        debug!("Finished sending transactions, sending balances to the Tx checker and stopping");
        tokio::time::sleep(CANCELLATION_DURATION).await;

        self.send_balances(balance_sender).await
    }

    /// Builds a random LRC20 transaction.
    ///
    /// If there are no balances, it builds an issuance TX with a random recipient.
    /// If the address has balances, a transfer transaction will be built.
    async fn build_transaction(
        &self,
        recipients: &Arc<[PrivateKey]>,
    ) -> eyre::Result<Lrc20Transaction> {
        // Choose a random recipient.
        let recipient = recipients
            .iter()
            .choose(&mut thread_rng())
            .expect("Recipients should not be empty");

        let balances = self.wallet.balances().await?;
        // If there are no LRC20 tokens, issue some to the previously picked recipient.
        // Else send a transfer TX.
        if balances.lrc20.is_empty() {
            self.issue(recipient).await
        } else {
            // Pick random TokenPubkey and TokenAmount.
            let (token_pubkey, token_amount) = balances
                .lrc20
                .iter()
                .choose(&mut thread_rng())
                .expect("At least one receipt should be present");

            self.transfer(recipient, Receipt::new(*token_amount, *token_pubkey))
                .await
        }
    }

    /// Issue tokens to a random recipient.
    async fn issue(&self, recipient: &PrivateKey) -> eyre::Result<Lrc20Transaction> {
        let mut builder = self.wallet.build_issuance(None)?;
        let secp = Secp256k1::new();

        builder
            .add_recipient(
                &recipient.public_key(&secp).inner,
                ISSUE_AMOUNT,
                SATOSHIS_AMOUNT,
            )
            .set_fee_rate_strategy(FEE_RATE_STARTEGY)
            .set_drain_tweaked_satoshis(true);

        match &self.rpc_blockchain {
            Some(bc) => builder.finish(bc).await,
            None => builder.finish(&self.esplora).await,
        }
    }

    /// Transfer tokens to a random recipient.
    async fn transfer(
        &self,
        recipient: &PrivateKey,
        receipt: Receipt,
    ) -> eyre::Result<Lrc20Transaction> {
        let token_amount = receipt.token_amount.amount;

        // If the balance is bigger than the lower bound, send half of it.
        // Otherwise - send the whole balance in a single transfer.
        let amount = if token_amount > TRANSFER_LOWER_BOUND {
            token_amount / 2
        } else {
            token_amount
        };

        let mut builder = self.wallet.build_transfer()?;
        let secp = Secp256k1::new();

        builder
            .add_recipient(
                receipt.token_pubkey,
                &recipient.public_key(&secp).inner,
                amount,
                SATOSHIS_AMOUNT,
            )
            .set_fee_rate_strategy(FEE_RATE_STARTEGY)
            .set_drain_tweaked_satoshis(true);

        match &self.rpc_blockchain {
            Some(bc) => builder.finish(bc).await,
            None => builder.finish(&self.esplora).await,
        }
    }

    /// `send_balances` sends the actual balances of the address to the `tx-checker` after the cancellation received.
    async fn send_balances(
        &mut self,
        balance_sender: UnboundedSender<(PrivateKey, HashMap<TokenPubkey, u128>)>,
    ) -> eyre::Result<()> {
        self.wallet.sync(SyncOptions::lrc20_only()).await?;

        let balances = self.wallet.balances().await?;
        balance_sender.send((self.private_key(), balances.lrc20))?;

        Ok(())
    }

    // ==vvv== Getter methods ==vvv==

    pub(crate) fn private_key(&self) -> PrivateKey {
        self.private_key
    }

    pub(crate) fn wallet(&self) -> &MemoryWallet {
        &self.wallet
    }

    pub(crate) fn p2wpkh_address(&self) -> eyre::Result<Address> {
        let pubkey = self.private_key().public_key(&Secp256k1::new());
        Ok(Address::p2wpkh(&pubkey, NETWORK)?)
    }

    pub(crate) fn lrc20_client(&self) -> &HttpClient {
        &self.lrc20_client
    }

    pub(crate) fn connection_method(&self) -> String {
        if self.rpc_blockchain.is_some() {
            "RPC".into()
        } else {
            "Esplora".into()
        }
    }
}

/// String representation of the LRC20 transaction type.
pub(crate) fn tx_type(tx_type: &Lrc20TxType) -> String {
    match tx_type {
        Lrc20TxType::Issue { .. } => "Issuance".into(),
        Lrc20TxType::Transfer { .. } => "Transfer".into(),
        Lrc20TxType::Announcement(_) => "Announcement".into(),
        Lrc20TxType::SparkExit { .. } => "SparkExit".into(),
    }
}
