//! This example show how using [`lrcdk::Wallet`] user can create sweep transactions.

use bdk::blockchain::Blockchain as _;
use common::{ALICE, RPC_BLOCKCHAIN};
use lrcdk::wallet::SyncOptions;

use crate::common::wallet_from_private_key;

pub mod common;

#[tokio::main(flavor = "current_thread")]
async fn main() -> eyre::Result<()> {
    let wallet = wallet_from_private_key(*ALICE)?;

    // Synchronize both LRC20 and Bitcoin utxos.
    wallet.sync(SyncOptions::default()).await?;

    // Sweep transaction is a transaction which spents "tweaked satoshi"
    // outputs or as you also may them know as "empty" proofs.
    //
    // By protocol rules, a "tweaked satoshis" output is created for Bitcoin change
    // so all outputs are tweaked in LRC20 transaction. That's why after dozens of
    // LRC20 transaction user may have many unspent "tweaked satoshi" outputs
    //
    // To spend all of them in one go to P2WPKH address of the wallet,
    //  wallet provides "sweep" transaction builder:
    let sweep_tx = {
        let mut txbuilder = wallet.build_sweep()?;

        txbuilder.set_fee_rate_strategy(lrcdk::types::FeeRateStrategy::Manual { fee_rate: 2.0 });

        let Some(sweep_tx) = txbuilder.finish(&*RPC_BLOCKCHAIN).await? else {
            // Of `None` is returned, that means that there are no "tweaked satoshi" outputs
            println!("No 'tweaked satoshi' outputs were found. Nothing to sweep.");
            return Ok(());
        };

        sweep_tx
    };

    println!("Txid: {}", sweep_tx.txid());
    println!(
        "Sweep transaction: {}",
        serde_json::to_string_pretty(&sweep_tx)?,
    );

    // Also, sweep transaction is normal Bitcoin transaction, so
    // you directly broadcast it to the Bitcoin network:
    (*RPC_BLOCKCHAIN).broadcast(&sweep_tx)?;

    Ok(())
}
