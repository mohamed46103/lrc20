use std::str::FromStr;

use crate::context::Context;
use bdk::blockchain::Blockchain;
use clap::Args;
use color_eyre::eyre::{self, Ok};
use lrc20_rpc_api::transactions::Lrc20TransactionsRpcClient;

use super::types::LRC20Pubkey;

const DEFAULT_SATOSHIS: u64 = 1000;

#[derive(Args, Debug)]
pub struct BurnArgs {
    /// Amount to burn.
    #[clap(long, short)]
    pub amount: u128,

    /// Satoshis to spend.
    #[clap(long, short, default_value_t = DEFAULT_SATOSHIS)]
    pub satoshis: u64,

    /// Type of the token.
    ///
    /// It can be specified either as a public key or an untweaked P2TR address with optional
    /// parity. Default parity is even.
    ///
    /// If you want to specify the parity along with an address, use the following format:
    /// `<address>:<parity>`, where parity is either `0` for even or `1` for odd.
    #[clap(long, short, value_parser = LRC20Pubkey::from_str)]
    pub token_pubkey: LRC20Pubkey,

    /// Provide proof of the transaction to LRC20 node or not.
    #[clap(long)]
    pub do_not_provide_proofs: bool,

    /// Drain tweaked satoshis to use for fees, instead of using regular satoshis.
    ///
    /// It's worth noting that change from regular satoshis will be tweaked.
    #[clap(long)]
    pub drain_tweaked_satoshis: bool,
}

pub async fn run(
    BurnArgs {
        amount,
        satoshis,
        token_pubkey,
        do_not_provide_proofs,
        drain_tweaked_satoshis,
    }: BurnArgs,
    mut ctx: Context,
) -> eyre::Result<()> {
    let wallet = ctx.wallet().await?;
    let blockchain = ctx.blockchain()?;
    let cfg = ctx.config()?;

    let tx = {
        let mut builder = wallet.build_transfer()?;

        builder.set_burn_amount(token_pubkey.into(), amount, satoshis);

        builder
            .set_fee_rate_strategy(cfg.fee_rate_strategy)
            .set_drain_tweaked_satoshis(drain_tweaked_satoshis);

        builder.finish(&blockchain).await?
    };

    if do_not_provide_proofs {
        blockchain.broadcast(&tx.bitcoin_tx)?;
    } else {
        let client = ctx.lrc20_client()?;

        client.send_lrc20_tx(tx.hex(), None).await?;
    }

    println!("tx id: {}", tx.bitcoin_tx.txid());

    println!("tx hex: {}", tx.hex());

    Ok(())
}
