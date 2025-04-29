use std::str::FromStr;

use super::types::AddrType;
use crate::{check_equal_lengths, context::Context};
use bdk::blockchain::Blockchain;
use clap::Args;
use color_eyre::eyre::{self, Ok, bail};
use lrc20_rpc_api::transactions::Lrc20TransactionsRpcClient;

use super::types::LRC20Pubkey;

const DEFAULT_SATOSHIS: u64 = 1000;

#[derive(Args, Debug)]
pub struct TransferArgs {
    /// Amount to send.
    #[clap(long, short, num_args = 1..)]
    pub amount: Vec<u128>,

    /// Satoshis to spend. Specify it either once to override the default,
    /// or per token_pubkey to use a different number of satoshis in each output.
    #[clap(long, short, num_args = 1.., default_values_t = vec![DEFAULT_SATOSHIS])]
    pub satoshis: Vec<u64>,

    /// Type of the token.
    ///
    /// It can be specified either as a public key or an untweaked P2TR address with optional
    /// parity. Default parity is even.
    ///
    /// If you want to specify the parity along with an address, use the following format:
    /// `<address>:<parity>`, where parity is either `0` for even or `1` for odd.
    #[clap(long, short, num_args = 1.., value_parser = LRC20Pubkey::from_str)]
    pub token_pubkey: Vec<LRC20Pubkey>,

    /// Recipient address types, by default set to p2wpkh.
    /// If there are multiple recipients, should be set for everyone independently.
    #[clap(long = "addr", default_values_t = vec![AddrType::P2WPKH], value_parser = AddrType::from_str)]
    pub address_types: Vec<AddrType>,

    /// The recipient of the payment.
    ///
    /// It can be specified either as a public key or an untweaked P2TR address with optional
    /// parity. Default parity is even.
    ///
    /// If you want to specify the parity along with an address, use the following format:
    /// `<address>:<parity>`, where parity is either `0` for even or `1` for odd.
    #[clap(long, short, num_args = 1.., value_parser = LRC20Pubkey::from_str)]
    pub recipient: Vec<LRC20Pubkey>,

    /// Provide proof of the transaction to LRC20 node or not.
    #[clap(long)]
    pub do_not_provide_proofs: bool,

    /// Drain tweaked satoshis to use for fees, instead of using regular satoshis.
    ///
    /// It's worth noting that change from regular satoshis will be tweaked.
    #[clap(long)]
    pub drain_tweaked_satoshis: bool,
}

// TODO(Velnbur): refactor this, please...
pub async fn run(
    TransferArgs {
        amount,
        satoshis,
        token_pubkey,
        address_types,
        recipient,
        do_not_provide_proofs,
        drain_tweaked_satoshis,
    }: TransferArgs,
    mut ctx: Context,
) -> eyre::Result<()> {
    let address_types = process_addr_types(address_types, recipient.len())?;
    check_equal_lengths!(amount, token_pubkey, recipient);

    let wallet = ctx.wallet().await?;
    let satoshis = process_satoshis(satoshis, token_pubkey.len())?;
    let blockchain = ctx.blockchain()?;
    let cfg = ctx.config()?;

    let tx = {
        let mut builder = wallet.build_transfer()?;

        for i in 0..token_pubkey.len() {
            match address_types[i] {
                AddrType::P2TR => {
                    builder.add_taproot_recipient(
                        token_pubkey[i].into(),
                        &recipient[i].into(),
                        amount[i],
                        satoshis[i],
                    );
                }
                AddrType::P2WPKH => {
                    builder.add_recipient(
                        token_pubkey[i].into(),
                        &recipient[i].into(),
                        amount[i],
                        satoshis[i],
                    );
                }
            }
        }

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

pub(crate) fn process_satoshis(
    satoshis: Vec<u64>,
    required_length: usize,
) -> eyre::Result<Vec<u64>> {
    match satoshis.len() {
        len if len == required_length => Ok(satoshis),
        1 => Ok(vec![satoshis[0]; required_length]),
        _ => eyre::bail!("wrong number of 'satoshis' specified"),
    }
}

pub(crate) fn process_addr_types(
    types: Vec<AddrType>,
    required_length: usize,
) -> eyre::Result<Vec<AddrType>> {
    match types.len() {
        len if len == required_length => Ok(types),
        1 => Ok(vec![types[0]; required_length]),
        _ => bail!("Address type should be provided for every recipient"),
    }
}
