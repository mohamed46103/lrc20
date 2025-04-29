//! This example demonstrates how users can create transactions with multisig
//! output and how users can spend it later.

use bitcoin::{OutPoint, secp256k1::Secp256k1};
use jsonrpsee::http_client::HttpClientBuilder;

use lrc20_receipts::TokenPubkey;
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
    let bob_private_key = *BOB;
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

    let alice_pubkey = alice_private_key.public_key(&secp_ctx).inner;
    let bob_pubkey = bob_private_key.public_key(&secp_ctx).inner;

    let issuance = {
        let mut txbuilder = issuer_wallet.build_issuance(None)?;

        // Issue 100_000 USD to Multisig
        txbuilder
            .add_multisig_recipient(
                // participants' public jkeys
                vec![alice_pubkey, bob_pubkey],
                // number of required signatures (up to 15)
                2,
                // amount in LRC20
                100_000,
                // amount in sats
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

    assert!(
        alice_wallet
            .lrc20_utxos()
            .await?
            // Here we know that the outpoint is the second one in the issuance transaction,
            // As usually the first one is announcement. If this doesn't work, change the vout:
            .contains_key(&OutPoint::new(issuance.bitcoin_tx.txid(), 1)),
        "Alice must have issuance UTXO after sync",
    );

    let transfer = {
        let mut txbuilder = alice_wallet.build_transfer()?;

        let issuer_token_pubkey = TokenPubkey::from(issuer_private_key.public_key(&secp_ctx).inner);

        // Add a recipient and specify valid `TokenPubkey`, receiver's `PublicKey`, LRC20 token amount and Satoshis amount.
        txbuilder
            .add_2x2multisig_input(
                // outpoint of the issuance with multisig output
                OutPoint::new(issuance.bitcoin_tx.txid(), 1),
                // The second's spender private key to sign 2x2 multisig input
                *BOB,
            )
            // Split one multisig input into two outputs for both participants:
            .add_recipient(issuer_token_pubkey, &alice_pubkey, 50_000, 2500)
            .add_recipient(issuer_token_pubkey, &bob_pubkey, 50_000, 2500)
            // For regtest, only manual fee rate strategy is available, so we set it 2 sats per byte.
            .set_fee_rate_strategy(FeeRateStrategy::Manual { fee_rate: 2.0 });

        txbuilder.finish(&*RPC_BLOCKCHAIN).await?
    };

    println!("Transfer txid: {}", transfer.bitcoin_tx.txid());
    println!("tx in hex: {}", transfer.hex());

    // broadcast multisig spending tx through LRC20d node
    lrc20_client.send_lrc20_tx(transfer.hex(), None).await?;
    // Mine blocks, so the issuance is mined too
    mine_blocks(6).await?;
    // Let's wait until the transactions is rejected or attached on the LRC20d node.
    wait_until_reject_or_attach(transfer.bitcoin_tx.txid(), &lrc20_client).await?;

    // Alice must have this transaction after sync:
    alice_wallet.sync(SyncOptions::default()).await?;

    assert!(
        alice_wallet
            .lrc20_utxos()
            .await?
            // Here we know that the outpoint is the second one in the issuance transaction,
            // As usually the first one is announcement. If this doesn't work, change the vout:
            .contains_key(&OutPoint::new(transfer.bitcoin_tx.txid(), 0)),
        "Alice must have issuance UTXO after sync",
    );

    println!(
        "Serialized tx: {}",
        serde_json::to_string_pretty(&transfer)?
    );

    Ok(())
}
