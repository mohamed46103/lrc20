use bdk::blockchain::Blockchain;
use color_eyre::eyre::{self, Context as EyreContext};
use lrc20_types::Announcement;

use crate::context::Context;

/// Creates an announcement from the args and broadcasts it.
pub async fn broadcast_announcement(
    announcement: Announcement,
    mut context: Context,
) -> eyre::Result<()> {
    let blockchain = context.blockchain()?;

    let wallet = context.wallet().await?;
    let config = context.config()?;

    let lrc20_tx = wallet
        .create_announcement_tx(announcement, config.fee_rate_strategy, &blockchain)
        .wrap_err("failed to create announcement tx")?;

    blockchain
        .broadcast(&lrc20_tx.bitcoin_tx)
        .wrap_err("failed to broadcast tx")?;

    println!("Transaction broadcasted: {}", lrc20_tx.bitcoin_tx.txid());

    Ok(())
}
