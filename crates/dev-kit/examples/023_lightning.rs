//! Example of how this wallet is used in LRC20 lightning implementation.
//!
//! In previous example, we created a multisig transfer with 2-of-2 keys,
//! in this one we will create a Lightning funding transaction.

use bitcoin::secp256k1::Secp256k1;
use jsonrpsee::http_client::HttpClientBuilder;

use lrc20_receipts::{Receipt, TokenPubkey};
use lrc20_rpc_api::transactions::Lrc20TransactionsRpcClient;
use lrcdk::{types::FeeRateStrategy, wallet::SyncOptions};

pub mod common;
use common::LOCAL_LRC20_URL;

use crate::common::{
    ALICE, BOB, RPC_BLOCKCHAIN, USD_ISSUER, fund_address, mine_blocks, wait_until_reject_or_attach,
    wallet_from_private_key,
};

#[tokio::main(flavor = "current_thread")]
async fn main() -> eyre::Result<()> {
    let secp_ctx = Secp256k1::new();

    // For this we'll use client to LRC20d node RPC to broadcast the transction.
    let lrc20_client = HttpClientBuilder::new().build(LOCAL_LRC20_URL)?;

    // Initialize participants keys:
    let alice_private_key = *ALICE;
    let issuer_private_key = *USD_ISSUER;

    // Create their wallest
    let alice_wallet = wallet_from_private_key(alice_private_key)?;
    let issuer_wallet = wallet_from_private_key(issuer_private_key)?;

    issuer_wallet.sync(SyncOptions::bitcoin_only()).await?;

    // Make sure that issuer has enough Bitcoins for issue transaction:
    if issuer_wallet.bitcoin_balances()?.get_spendable() < 10_000 {
        fund_address(&issuer_wallet.address()?).await?;
        issuer_wallet.sync(SyncOptions::bitcoin_only()).await?;
    }

    let issuance = {
        let mut txbuilder = issuer_wallet.build_issuance(None)?;

        // Issue 100_000 USD to Alice with satoshis so that she can pay for next transaction.
        txbuilder
            .add_recipient(
                &alice_private_key.public_key(&secp_ctx).inner,
                100_000,
                5000,
            )
            .set_fee_rate_strategy(FeeRateStrategy::Manual { fee_rate: 2.0 });

        txbuilder.finish(&*RPC_BLOCKCHAIN).await?
    };

    // broadcast issuance through LRC20d node
    lrc20_client.send_lrc20_tx(issuance.hex(), None).await?;
    // Mine blocks, so the issuance is mined too
    mine_blocks(6).await?;
    // Let's wait until the transactions is rejected or attached on the LRC20d node.
    wait_until_reject_or_attach(issuance.bitcoin_tx.txid(), &lrc20_client).await?;

    // Alice must have this transaction after sync:
    alice_wallet.sync(SyncOptions::default()).await?;

    // ===================================================
    // From now assume that Alice wants to create a Lightning
    // channel with Bob. For that we'll show how Alice can
    // create a funding transaction.
    // ===================================================

    // Token type of the issuance above:
    let issuer_token_pubkey = TokenPubkey::from(issuer_private_key.public_key(&secp_ctx).inner);

    // Counterparty public key
    let bob_pubkey = BOB.public_key(&secp_ctx).inner;

    // For more complex transfers you can use `build_transfer` and specify all parameters by yourself:
    let funding_tx = alice_wallet
        .lightning_funding_tx(
            // Funding receipt of the channel
            Receipt::new(3000, issuer_token_pubkey),
            // holder (our) pubkey
            alice_private_key.public_key(&secp_ctx).inner,
            // counterparty (Bob's) pubkey
            bob_pubkey,
            // amount of satoshis in channel
            5000,
            // optional fee rate strategy
            None,
        )
        .await?;

    println!("Funding tx txid: {}", funding_tx.bitcoin_tx.txid());
    println!("tx in hex: {}", funding_tx.hex());
    println!(
        "Serialized tx: {}",
        serde_json::to_string_pretty(&funding_tx)?
    );

    Ok(())
}
