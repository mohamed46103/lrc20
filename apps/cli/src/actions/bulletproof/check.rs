use std::str::FromStr;

use bitcoin::OutPoint;
use bulletproof::util::ecdh;
use clap::Args;
use color_eyre::eyre::{self, OptionExt, bail};
use lrc20_receipts::generate_bulletproof;
use lrc20_rpc_api::transactions::{Lrc20TransactionStatus, Lrc20TransactionsRpcClient};

use crate::{actions::types::LRC20Pubkey, context::Context};

#[derive(Args, Debug)]
pub struct CheckArgs {
    /// Amount to check
    #[clap(long)]
    pub amount: u128,

    #[clap(long)]
    pub outpoint: OutPoint,

    /// Sender pubkey.
    /// It can be specified either as a public key or an untweaked P2TR address with optional
    /// parity. Default parity is even.
    ///
    /// If you want to specify the parity along with an address, use the following format:
    /// `<address>:<parity>`, where parity is either `0` for even or `1` for odd.
    #[clap(long, value_parser = LRC20Pubkey::from_str)]
    pub sender: LRC20Pubkey,
}

pub async fn run(
    CheckArgs {
        amount,
        outpoint,
        sender,
    }: CheckArgs,
    mut context: Context,
) -> eyre::Result<()> {
    let config = context.config()?;
    let lrc20_client = context.lrc20_client()?;

    let dh_key = ecdh(config.private_key, sender.into(), config.network())?;

    let raw_dh_key: [u8; 32] = dh_key
        .to_bytes()
        .try_into()
        .expect("should convert to array");
    let (_, commit) = generate_bulletproof(amount, raw_dh_key);

    let lrc20_tx = lrc20_client.get_lrc20_transaction(outpoint.txid).await?;
    if lrc20_tx.status != Lrc20TransactionStatus::Attached {
        bail!(
            "Transaction {txid} is not attached by LRC20 node",
            txid = outpoint.txid
        )
    }

    let Some(attached_tx) = lrc20_tx.data else {
        bail!(
            "Transaction {txid} is not present in the node's storage",
            txid = outpoint.txid
        )
    };

    let output_proofs = attached_tx
        .tx_type
        .output_proofs()
        .ok_or_eyre("The outpoint is frozen")?;

    let proof = output_proofs
        .get(&outpoint.vout)
        .ok_or_eyre("The tx vout is not valid")?;

    let bulletproof = proof
        .get_bulletproof()
        .ok_or_eyre("The tx receipt proof is not bulletproof")?;

    if commit != bulletproof.commitment {
        return Err(eyre::eyre!("Invalid commitment"));
    }

    println!("Commit valid!");

    Ok(())
}
