//! This intergration test checks that flow from `lrc20-cli` documentation works
//! as expected.

use bdk::bitcoin::{OutPoint, PrivateKey, secp256k1::Secp256k1};
use bdk::bitcoincore_rpc::RpcApi;
use once_cell::sync::Lazy;
use serde_json::json;

mod common;
use common::*;

use lrc20_rpc_api::transactions::Lrc20TransactionsRpcClient;
use lrcdk::types::FeeRateStrategy;
use lrcdk::wallet::{MemoryWallet, SyncOptions};

static USD_ISSUER: Lazy<PrivateKey> = Lazy::new(|| {
    "cNMMXcLoM65N5GaULU7ct2vexmQnJ5i5j3Sjc6iNnEF18vY7gzn9"
        .parse()
        .expect("Should be valid key")
});

static EUR_ISSUER: Lazy<PrivateKey> = Lazy::new(|| {
    "cUK2ZdLQWWpKeFcrrD7BBjiUsEns9M3MFBTkmLTXyzs66TQN72eX"
        .parse()
        .expect("Should be valid key")
});

static ALICE: Lazy<PrivateKey> = Lazy::new(|| {
    "cQb7JarJTBoeu6eLvyDnHYNr6Hz4AuAnELutxcY478ySZy2i29FA"
        .parse()
        .expect("Should be valid key")
});

static BOB: Lazy<PrivateKey> = Lazy::new(|| {
    "cUrMc62nnFeQuzXb26KPizCJQPp7449fsPsqn5NCHTwahSvqqRkV"
        .parse()
        .expect("Should be valid key")
});

#[tokio::test]
async fn test_cli_flow() -> eyre::Result<()> {
    color_eyre::install()?;
    let rpc_blockchain = setup_rpc_blockchain(&USD_ISSUER)?;
    let lrc20_client = setup_lrc20_client(LRC20_NODE_URL)?;

    let provider_cfg = bitcoin_provider_config(false);
    let blockchain = setup_blockchain(&provider_cfg);

    let usd_issuer = setup_wallet_from_provider(*USD_ISSUER, provider_cfg.clone()).await?;

    let eur_issuer = setup_wallet_from_provider(*EUR_ISSUER, provider_cfg.clone()).await?;

    let alice = setup_wallet_from_provider(*ALICE, provider_cfg.clone()).await?;

    let bob = setup_wallet_from_provider(*BOB, provider_cfg.clone()).await?;

    let secp = Secp256k1::new();

    usd_issuer.sync(SyncOptions::bitcoin_only()).await?;
    if usd_issuer.bitcoin_balances()?.get_spendable() < 100_000 {
        rpc_blockchain.generate_to_address(101, &usd_issuer.address()?)?;
    }
    usd_issuer.sync(SyncOptions::default()).await?;

    const ISSUANCE_AMOUNT: u128 = 10_000;

    let alice_pubkey = ALICE.public_key(&secp);
    let eur_pubkey = EUR_ISSUER.public_key(&secp);

    let fee_rate_strategy = FeeRateStrategy::Manual { fee_rate: 2.0 };

    // =============================
    // 1. Issue USD tokens to ALICE
    // =============================
    let usd_issuance = {
        let mut builder = usd_issuer.build_issuance(None)?;

        builder
            .add_recipient(&alice_pubkey.inner, ISSUANCE_AMOUNT, 1000)
            // Fund alice with 10_000 sats
            .add_sats_recipient(&alice_pubkey.inner, 10_000)
            // Fund eur issuer with 10_000 sats for further issuance
            .add_sats_recipient(&eur_pubkey.inner, 10_000)
            .set_fee_rate_strategy(fee_rate_strategy);

        builder.finish(&blockchain).await?
    };

    // let fee_rate = fee_rate_strategy.get_fee_rate(&provider)?;

    // TODO: Failed estimation on regtest
    // assert_fee_matches_difference(&usd_issuance, &provider, fee_rate, true)?;

    let usd_txid = usd_issuance.bitcoin_tx.txid();

    lrc20_client.send_lrc20_tx(usd_issuance.hex(), None).await?;

    // Add block with issuance to the chain
    rpc_blockchain.generate_to_address(7, &alice.address()?)?;

    let tx = wait_until_reject_or_attach(usd_txid, &lrc20_client).await?;

    assert_attached!(tx, "USD issuance should be attached");
    println!("USD issuance attached");

    // To sync output with satoshis for next transaction.
    eur_issuer.sync(SyncOptions::bitcoin_only()).await?;
    if eur_issuer.bitcoin_balances()?.get_spendable() < 100_000 {
        rpc_blockchain.generate_to_address(101, &eur_issuer.address()?)?;
    }
    eur_issuer.sync(SyncOptions::default()).await?;

    // =============================
    // 2. Issue EUR tokens with metadata to ALICE
    // =============================
    let eur_issuance = {
        let mut builder = eur_issuer.build_issuance(None)?;

        let metadata = json!({
            "name": "Euro Coin"
        });

        builder
            .add_recipient_with_metadata(&alice_pubkey.inner, ISSUANCE_AMOUNT, 1000, metadata)?
            .set_fee_rate_strategy(fee_rate_strategy);

        builder.finish(&blockchain).await?
    };

    // TODO: Failed estimation on regtest
    // assert_fee_matches_difference(&eur_issuance, &provider, fee_rate, true)?;

    let eur_txid = eur_issuance.bitcoin_tx.txid();

    lrc20_client.send_lrc20_tx(eur_issuance.hex(), None).await?;

    // Add block with issuance to the chain
    rpc_blockchain.generate_to_address(7, &alice.address()?)?;

    let tx = wait_until_reject_or_attach(eur_txid, &lrc20_client).await?;

    assert_attached!(tx, "EUR issuance should be attached");
    println!("EUR issuance attached");

    alice.sync(SyncOptions::default()).await?;

    assert_wallet_has_utxo!(
        alice,
        usd_txid,
        1,
        "Alice should have USD issuance utxo, txid={usd_txid}"
    );
    assert_wallet_has_utxo!(
        alice,
        eur_txid,
        1,
        "Alice should have EUR issuance utxo, txid={eur_txid}"
    );

    let bob_pubkey = BOB.public_key(&secp);

    const TRANSFER_AMOUNT: u128 = 100;

    // =============================
    // 3. Transfer USD tokens from ALICE to BOB
    // =============================
    let alice_bob_transfer = {
        let usd_token_pubkey = USD_ISSUER.public_key(&secp).into();
        let eur_token_pubkey = EUR_ISSUER.public_key(&secp).into();

        let mut builder = alice.build_transfer()?;

        builder
            .add_recipient(usd_token_pubkey, &bob_pubkey.inner, TRANSFER_AMOUNT, 1000)
            .add_recipient(eur_token_pubkey, &bob_pubkey.inner, TRANSFER_AMOUNT, 1000)
            .set_fee_rate_strategy(fee_rate_strategy);

        builder.finish(&blockchain).await?
    };

    // TODO: Failed estimation on regtest
    // assert_fee_matches_difference(&alice_bob_transfer, &provider, fee_rate, false)?;

    let txid = alice_bob_transfer.bitcoin_tx.txid();

    println!("Alice -> Bob transfer txid: {}", txid);
    lrc20_client
        .send_lrc20_tx(alice_bob_transfer.hex(), None)
        .await?;

    // Add block with transfer to the chain
    rpc_blockchain.generate_to_address(7, &alice.address()?)?;

    let tx = wait_until_reject_or_attach(txid, &lrc20_client).await?;

    assert_attached!(tx, "USD transfer should be attached");

    bob.sync(SyncOptions::default()).await?;

    assert_wallet_has_utxo!(bob, txid, 0, "Bob should have utxo from transfer");

    Ok(())
}

pub async fn find_in_utxos(wallet: &MemoryWallet, outpoint: OutPoint) -> eyre::Result<()> {
    let utxos = wallet.lrc20_utxos().await?;

    let _utxo = utxos
        .iter()
        .find(|(outpoint_, _)| *outpoint_ == &outpoint)
        .ok_or_else(|| eyre::eyre!("UTXO not found"))?;

    Ok(())
}
