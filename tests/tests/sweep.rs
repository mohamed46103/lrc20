//! This intergration test checks that tweaked Bitcoin UTXOs sweep works
//! as expected.

use bdk::bitcoin::{PrivateKey, secp256k1::Secp256k1};
use bdk::bitcoincore_rpc::RpcApi;
use bdk::blockchain::Blockchain;
use bitcoin::Txid;
use eyre::OptionExt;
use once_cell::sync::Lazy;

mod common;
use common::*;

use lrc20_rpc_api::transactions::Lrc20TransactionsRpcClient;
use lrcdk::types::FeeRateStrategy;
use lrcdk::wallet::{MemoryWallet, SyncOptions};

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
async fn test_sweep() -> eyre::Result<()> {
    let rpc_blockchain = setup_rpc_blockchain(&ALICE)?;
    let lrc20_client = setup_lrc20_client(LRC20_NODE_URL)?;

    let provider_cfg = bitcoin_provider_config(false);
    let blockchain = setup_blockchain(&provider_cfg);

    let alice = setup_wallet_from_provider(*ALICE, provider_cfg.clone()).await?;

    let secp = Secp256k1::new();

    alice.sync(SyncOptions::bitcoin_only()).await?;
    if alice.bitcoin_balances()?.get_spendable() < 100_000 {
        rpc_blockchain.generate_to_address(101, &alice.address()?)?;
    }
    alice.sync(SyncOptions::default()).await?;

    const ISSUANCE_AMOUNT: u128 = 10_000;

    let bob_pubkey = BOB.public_key(&secp);

    let fee_rate_strategy = FeeRateStrategy::Manual { fee_rate: 2.0 };

    // ========================================
    // 1. Issue tokens to BOB
    //
    // This transaction should create a tweaked
    // Bitcoin output
    // ========================================
    let issuance = {
        let mut builder = alice.build_issuance(None)?;

        builder
            .add_recipient(&bob_pubkey.inner, ISSUANCE_AMOUNT, 1000)
            .set_fee_rate_strategy(fee_rate_strategy);

        builder.finish(&blockchain).await?
    };

    let txid = issuance.bitcoin_tx.txid();

    lrc20_client.send_lrc20_tx(issuance.hex(), None).await?;

    rpc_blockchain.generate_to_address(7, &alice.address()?)?;

    let tx = wait_until_reject_or_attach(txid, &lrc20_client).await?;

    assert_attached!(tx, "Issuance should be attached");
    println!("Issuance attached");

    alice.sync(SyncOptions::default()).await?;

    // =============================================================
    // 2. Sweep tweaked Bitcoin UTXOs back to Alice's p2wpkh address
    // =============================================================
    let sweep = {
        let mut builder = alice.build_sweep()?;

        builder.set_fee_rate_strategy(fee_rate_strategy);

        builder.finish(&blockchain).await?
    }
    .ok_or_eyre("Address should have tweaked outpoints")?;

    let sweep_txid = sweep.txid();

    blockchain.broadcast(&sweep)?;

    rpc_blockchain.generate_to_address(7, &alice.address()?)?;

    alice.sync(SyncOptions::bitcoin_only()).await?;

    find_in_utxos(&alice, sweep_txid)?;

    Ok(())
}

fn find_in_utxos(wallet: &MemoryWallet, txid: Txid) -> eyre::Result<()> {
    let utxos = wallet.bitcoin_utxos()?;

    let _utxo = utxos
        .iter()
        .find(|utxo| utxo.outpoint.txid == txid)
        .ok_or_else(|| eyre::eyre!("UTXO not found"))?;

    Ok(())
}
