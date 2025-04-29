//! This example shows examples of interaction with the wallet for retrieving balances.

use bitcoin::{Network, OutPoint, secp256k1::Secp256k1};
use common::{ALICE, LOCAL_BITCOIN_PROVIDER, LOCAL_LRC20_URL};
use lrc20_receipts::TokenPubkey;
use lrcdk::wallet::{MemoryWallet, SyncOptions, WalletConfig};

use crate::common::USD_ISSUER;

pub mod common;

#[tokio::main(flavor = "current_thread")]
async fn main() -> eyre::Result<()> {
    let network = Network::Regtest;

    // Parsed private key of the Alice user:
    let private_key = *ALICE;

    // Set up the wallet config.
    let wallet_config = WalletConfig {
        privkey: private_key, // Replace `private_key` with the actual private key.
        network,              // Specify the desired network.
        // Provide a valid Bitcoin provider. Could be either `BitcoinRpcConfig` or `EsploraConfig`.
        bitcoin_provider: LOCAL_BITCOIN_PROVIDER.clone(),
        lrc20_url: LOCAL_LRC20_URL.to_string(), // Provide a valid, accessible LRC20 node URL.
    };

    // Build a wallet from the config.
    let wallet = MemoryWallet::from_config(wallet_config).expect("Couldn't init the wallet");

    // For wallet using inner BDK wallet we can sync only Bitcoin balance in satohis:
    wallet.sync(SyncOptions::bitcoin_only()).await?;

    // Or only LRC20 balances:
    wallet.sync(SyncOptions::lrc20_only()).await?;

    // Or both using default sync options:
    wallet.sync(SyncOptions::default()).await?;

    // [`lrcdk::Wallet`] operates these types of balances
    //
    // - ordinary Bitcoin balances of the P2WPKH address created from the private key;
    println!(
        "Bitcoin balance: {}",
        wallet.bitcoin_balances()?.get_spendable()
    );
    // - lrc20 balances, which are retreived from LRC20 node by searching for ReceiptProofs
    //   which has inner_key the same as user's public derived from private one.
    let balances = wallet.balances().await?;

    for (token_pubkey, amount) in balances.lrc20 {
        println!(
            "LRC20 Balances token_pubkey: {} amount: {}",
            token_pubkey, amount
        );
    }

    // - And the "tweaked satoshis" or empty receipt proofs, which don't have any LRC20 value,
    //   but store change sats and sent to inner_key tweaked by "zero" key (also synced from
    //   node).
    println!("Tweaked sats: {}", balances.tweaked_satoshis);

    // Also wallet has method for retreiving all user's LRC20 utxos directly:
    for (outpoint, proof) in wallet.lrc20_utxos().await? {
        println!(
            "LRC20 utxo: {}, token_pubkey: {} amount: {}",
            outpoint,
            proof.receipt().token_pubkey,
            proof.amount()
        );
    }
    // or you can get all utxos for particular token_pubkey:
    let usd_token_pubkey = TokenPubkey::from((*USD_ISSUER).public_key(&Secp256k1::new()).inner);
    let _utxos_by_token_pubkey: Vec<(OutPoint, u128)> =
        wallet.utxos_by_token_pubkey(usd_token_pubkey).await?;

    // The same for tweaked satoshis:
    for (outpoint, _) in wallet.lrc20_utxos().await? {
        println!("Tweaked satoshis utxo: {}", outpoint);
    }

    Ok(())
}
