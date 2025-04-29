//! This example show how using [`lrcdk::Wallet`] user can create issuance transactions
//! for it's token.

use bitcoin::{Address, Network, secp256k1::Secp256k1};
use common::{
    ALICE, BOB, LOCAL_BITCOIN_PROVIDER, LOCAL_LRC20_URL, RPC_BLOCKCHAIN, USD_ISSUER, fund_address,
};
use lrcdk::{
    types::FeeRateStrategy,
    wallet::{MemoryWallet, SyncOptions, WalletConfig},
};

pub mod common;

#[tokio::main(flavor = "current_thread")]
async fn main() -> eyre::Result<()> {
    let secp_ctx = Secp256k1::new();
    let network = Network::Regtest;

    // Parsed private key of USD issuer.
    let issuer_private_key = *USD_ISSUER;

    // Set up the wallet config.
    let wallet_config = WalletConfig {
        privkey: issuer_private_key, // Replace `private_key` with the actual private key.
        network: bitcoin::Network::Regtest, // Specify the desired network.
        bitcoin_provider: LOCAL_BITCOIN_PROVIDER.clone(), // Provide a valid Bitcoin provider. Could be either `BitcoinRpcConfig` or `EsploraConfig`.
        lrc20_url: LOCAL_LRC20_URL.to_string(), // Provide a valid, accessible LRC20 node URL.
    };

    // Build a wallet from the config.
    let issuer_wallet = MemoryWallet::from_config(wallet_config).expect("Couldn't init the wallet");

    // Synchronize both LRC20 and Bitcoin utxos.
    issuer_wallet
        .sync(SyncOptions {
            sync_lrc20_wallet: true,
            sync_bitcoin_wallet: true,
            ..Default::default()
        })
        .await?;

    // If issuer has less the 20_000 satoshis, fund it.
    if issuer_wallet.bitcoin_balances().unwrap().get_spendable() < 20_000 {
        // Fund issuer with bitcoins by giving reward from blocks to it.
        //
        // Wallet uses WPKH address type, so we need to fund it with P2WPKH address.
        fund_address(&Address::p2wpkh(
            &issuer_private_key.public_key(&secp_ctx),
            network,
        )?)
        .await?;

        // And sync bitcoins only this time.
        issuer_wallet.sync(SyncOptions::bitcoin_only()).await?;
    }

    let issuance = {
        // Provide `None` here to use token_pubkey derived from public key of the issuer.
        let mut txbuilder = issuer_wallet.build_issuance(None)?;

        // Add the recipient of the issuance.
        txbuilder.add_recipient(&ALICE.public_key(&secp_ctx).inner, 100_000, 1000);

        // You can add multiple recipients too:
        for _ in 0..10 {
            txbuilder.add_recipient(&BOB.public_key(&secp_ctx).inner, 100_000, 1000);
        }

        // For local regtest node, estimation will fail, so we set it manually.
        txbuilder.set_fee_rate_strategy(FeeRateStrategy::Manual { fee_rate: 2.0 });

        txbuilder.finish(&*RPC_BLOCKCHAIN).await?
    };

    println!("Issuance txid: {}", issuance.bitcoin_tx.txid());
    println!("tx in hex: {}", issuance.hex());
    println!(
        "Serialized tx: {}",
        serde_json::to_string_pretty(&issuance)?
    );

    Ok(())
}
