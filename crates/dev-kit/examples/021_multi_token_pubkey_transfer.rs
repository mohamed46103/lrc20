//! This example demonstrates how to make a transfer with two different tokens in one transaction.

use bitcoin::{
    OutPoint,
    secp256k1::{PublicKey, Secp256k1},
};
use jsonrpsee::http_client::HttpClientBuilder;

use lrc20_receipts::TokenPubkey;
use lrc20_rpc_api::transactions::Lrc20TransactionsRpcClient;
use lrcdk::{
    types::FeeRateStrategy,
    wallet::{MemoryWallet, SyncOptions},
};

pub mod common;
use common::LOCAL_LRC20_URL;
use lrc20_types::Lrc20Transaction;

use crate::common::{
    ALICE, BOB, EUR_ISSUER, RPC_BLOCKCHAIN, USD_ISSUER, fund_address, mine_blocks,
    wait_until_reject_or_attach, wallet_from_private_key,
};

#[tokio::main(flavor = "current_thread")]
async fn main() -> eyre::Result<()> {
    let secp_ctx = Secp256k1::new();

    // For this we'll use client to LRC20d node RPC to broadcast the transction.
    let lrc20_client = HttpClientBuilder::new().build(LOCAL_LRC20_URL)?;

    // Initialize participants keys:
    let alice_private_key = *ALICE;
    let usd_issuer_private_key = *USD_ISSUER;
    let eur_issuer_private_key = *EUR_ISSUER;

    // Create their wallest
    let alice_wallet = wallet_from_private_key(alice_private_key)?;
    let usd_issuer_wallet = wallet_from_private_key(usd_issuer_private_key)?;
    let eur_issuer_wallet = wallet_from_private_key(eur_issuer_private_key)?;

    // Get Alice pubkey as recipient:
    let alice_pubkey = alice_private_key.public_key(&secp_ctx).inner;

    let eur_issuance = create_issuance_from_wallet(&eur_issuer_wallet, alice_pubkey).await?;
    let usd_issuance = create_issuance_from_wallet(&usd_issuer_wallet, alice_pubkey).await?;

    // broadcast issuances through LRC20d node
    lrc20_client.send_lrc20_tx(usd_issuance.hex(), None).await?;
    lrc20_client.send_lrc20_tx(eur_issuance.hex(), None).await?;
    // Mine blocks, so the issuances are mined too
    mine_blocks(6).await?;
    // Let's wait until the transactions are rejected or attached on the LRC20d node.
    wait_until_reject_or_attach(usd_issuance.bitcoin_tx.txid(), &lrc20_client).await?;
    wait_until_reject_or_attach(eur_issuance.bitcoin_tx.txid(), &lrc20_client).await?;

    // Alice must have this transaction after sync:
    alice_wallet.sync(SyncOptions::default()).await?;

    assert!(
        alice_wallet
            .lrc20_utxos()
            .await?
            // Here we know that the outpoint is the second one in the issuance transaction,
            // As usually the first one is announcement. If this doesn't work, change the vout:
            .contains_key(&OutPoint::new(usd_issuance.bitcoin_tx.txid(), 1)),
        "Alice must have issuance UTXO after sync",
    );
    assert!(
        alice_wallet
            .lrc20_utxos()
            .await?
            // Here we know that the outpoint is the second one in the issuance transaction,
            // As usually the first one is announcement. If this doesn't work, change the vout:
            .contains_key(&OutPoint::new(eur_issuance.bitcoin_tx.txid(), 1)),
        "Alice must have issuance UTXO after sync",
    );

    let transfer = {
        let mut txbuilder = alice_wallet.build_transfer()?;

        let usd_issuer_token_pubkey =
            TokenPubkey::from(usd_issuer_private_key.public_key(&secp_ctx).inner);
        let eur_issuer_token_pubkey =
            TokenPubkey::from(eur_issuer_private_key.public_key(&secp_ctx).inner);

        // Add two outputs for BOB for each token we have:
        let bob_pubkey = BOB.public_key(&secp_ctx).inner;
        txbuilder
            .add_recipient(
                // use USD as token in one output
                usd_issuer_token_pubkey,
                // Send to Bob's public key
                &bob_pubkey,
                // Half of the amount
                50_000,
                // With minimal sats amount
                1000,
            )
            .add_recipient(
                // use EUR as token for another output
                eur_issuer_token_pubkey,
                &bob_pubkey,
                50_000,
                1000,
            )
            // For regtest, only manual fee rate strategy is available, so we set it 2 sats per byte.
            .set_fee_rate_strategy(FeeRateStrategy::Manual { fee_rate: 2.0 });

        txbuilder.finish(&*RPC_BLOCKCHAIN).await?
    };

    println!("Transfer txid: {}", transfer.bitcoin_tx.txid());
    println!("tx in hex: {}", transfer.hex());
    println!(
        "Serialized tx: {}",
        serde_json::to_string_pretty(&transfer)?
    );

    Ok(())
}

async fn create_issuance_from_wallet(
    wallet: &MemoryWallet,
    recipient: PublicKey,
) -> eyre::Result<Lrc20Transaction> {
    // Make sure that issuer has enough Bitcoins for issue transaction:
    if wallet.bitcoin_balances()?.get_spendable() < 10_000 {
        fund_address(&wallet.address()?).await?;
        wallet.sync(SyncOptions::bitcoin_only()).await?;
    }

    let issuance = {
        let mut txbuilder = wallet.build_issuance(None)?;

        // Issue 100_000 to Alice with satoshis so that she can pay for next transaction.
        txbuilder
            .add_recipient(&recipient, 100_000, 5000)
            .set_fee_rate_strategy(FeeRateStrategy::Manual { fee_rate: 2.0 });

        txbuilder.finish(&*RPC_BLOCKCHAIN).await?
    };

    Ok(issuance)
}
