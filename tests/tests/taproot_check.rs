//! This module provides intergration tests for creating taproot LRC20 transactions.

use bdk::bitcoincore_rpc::RpcApi;
use bitcoin::{OutPoint, PrivateKey};
use bitcoin_client::RawTx;
use lrc20_rpc_api::transactions::{EmulateLrc20TransactionResponse, Lrc20TransactionsRpcClient};
use lrcdk::{types::FeeRateStrategy, wallet::SyncOptions};
use once_cell::sync::Lazy;
use serde_json::{Value, json};

mod common;
use common::*;

static USD_ISSUER: Lazy<PrivateKey> = Lazy::new(|| {
    "cNMMXcLoM65N5GaULU7ct2vexmQnJ5i5j3Sjc6iNnEF18vY7gzn9"
        .parse()
        .expect("Should be valid key")
});

static EUR_ISSUER: Lazy<PrivateKey> = Lazy::new(|| {
    "cN1NpxBSM8cZiQAyvAdZAPjzYJdy2CbJ13DyQwZ7bmzDi3Pg62MF"
        .parse()
        .expect("Should be valid key")
});

static ALICE: Lazy<PrivateKey> = Lazy::new(|| {
    "cUK2ZdLQWWpKeFcrrD7BBjiUsEns9M3MFBTkmLTXyzs66TQN72eX"
        .parse()
        .expect("Should be valid key")
});

static BOB: Lazy<PrivateKey> = Lazy::new(|| {
    "cQDWeEdUKaSes7bug41nzJSzNKKWXm3buHutFvnmwood1RfYx6ps"
        .parse()
        .expect("Should be valid key")
});

#[tokio::test]
async fn test_create_taproot_transaction() -> eyre::Result<()> {
    test_taproot_transactions(&USD_ISSUER, &ALICE, None).await
}

#[tokio::test]
async fn test_create_taproot_transaction_with_metadata() -> eyre::Result<()> {
    let metadata = json!({
        "field": "value",
    });

    test_taproot_transactions(&EUR_ISSUER, &BOB, Some(metadata)).await
}

async fn test_taproot_transactions(
    issuer: &PrivateKey,
    user: &PrivateKey,
    metadata: Option<Value>,
) -> eyre::Result<()> {
    let blockchain_rpc = setup_rpc_blockchain(issuer)?;

    let provider_cfg = bitcoin_provider_config(false);
    let blockchain = setup_blockchain(&provider_cfg);

    let lrc20_client = setup_lrc20_client(LRC20_NODE_URL)?;

    let issuer = setup_wallet_from_provider(*issuer, provider_cfg.clone()).await?;

    let user = setup_wallet_from_provider(*user, provider_cfg.clone()).await?;

    issuer.sync(SyncOptions::bitcoin_only()).await?;
    if issuer.bitcoin_balances()?.get_spendable() < 100_000 {
        blockchain_rpc.generate_to_address(101, &issuer.address()?)?;
    }
    if user.bitcoin_balances()?.get_spendable() < 100_000 {
        blockchain_rpc.generate_to_address(101, &user.address()?)?;
    }
    issuer.sync(SyncOptions::default()).await?;

    let user_pubkey = user.public_key();

    const ISSUANCE_AMOUNT: u128 = 1000;

    let fee_rate_strategy = FeeRateStrategy::Manual { fee_rate: 2.0 };

    // Create issuance with one taproot output to ALICE
    let issuance = {
        let mut builder = issuer.build_issuance(None)?;

        match metadata {
            Some(metadata) => {
                builder.add_taproot_recipient_with_metadata(
                    &user_pubkey.inner,
                    ISSUANCE_AMOUNT,
                    100000,
                    metadata,
                )?;
            }
            None => {
                builder.add_taproot_recipient(&user_pubkey.inner, ISSUANCE_AMOUNT, 100000);
            }
        }

        builder.set_fee_rate_strategy(fee_rate_strategy);

        builder.finish(&blockchain).await?
    };

    dbg!(&issuance.tx_type);

    let txid = issuance.bitcoin_tx.txid();

    if let EmulateLrc20TransactionResponse::Invalid { reason } = lrc20_client
        .emulate_lrc20_transaction(issuance.clone())
        .await?
    {
        panic!("Issuance is invalid: {}", reason)
    }

    lrc20_client.send_lrc20_tx(issuance.hex(), None).await?;

    // Add block with issuance to the chain
    blockchain_rpc.generate_to_address(6, &issuer.address()?)?;

    let tx = wait_until_reject_or_attach(txid, &lrc20_client).await?;

    assert_attached!(tx, "Issuance was not accepted by LRC20 node");

    user.sync(SyncOptions::default()).await?;

    const TRANSFER_AMOUNT: u128 = 100;

    // Create transfer with one taproot input from Alice
    let transfer = {
        let token_pubkey = issuer.public_key().into();

        let mut builder = user.build_transfer()?;

        builder
            .add_taproot_input(OutPoint::new(txid, 1))
            .add_recipient(
                token_pubkey,
                &issuer.public_key().inner,
                TRANSFER_AMOUNT,
                1000,
            )
            .set_fee_rate_strategy(fee_rate_strategy);

        builder.finish(&blockchain).await?
    };

    println!("{}", transfer.bitcoin_tx.raw_hex());
    dbg!(&transfer.tx_type);

    let txid = transfer.bitcoin_tx.txid();

    if let EmulateLrc20TransactionResponse::Invalid { reason } = lrc20_client
        .emulate_lrc20_transaction(transfer.clone())
        .await?
    {
        panic!("Transfer is invalid: {}", reason)
    }
    lrc20_client.send_lrc20_tx(transfer.hex(), None).await?;

    // Add block with transfer to the chain and sign it
    blockchain_rpc.generate_to_address(6, &user.address()?)?;

    // Check that the transfer was accepted by LRC20 node
    let tx = wait_until_reject_or_attach(txid, &lrc20_client).await?;

    assert_attached!(tx, "Transfer was not accepted by LRC20 node");

    Ok(())
}
