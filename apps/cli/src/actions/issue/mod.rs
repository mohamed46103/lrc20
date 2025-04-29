use std::str::FromStr;

use bdk::blockchain::Blockchain;
use clap::Args;
use color_eyre::eyre::{self, bail};
use lrc20_rpc_api::transactions::Lrc20TransactionsRpcClient;

use crate::actions::transfer::process_addr_types;

use crate::{actions::transfer::process_satoshis, context::Context};

use super::types::{AddrType, LRC20Pubkey};

pub const DEFAULT_SATOSHIS: u64 = 1000;

#[derive(Args, Debug)]
pub struct IssueArgs {
    /// [LRC20Pubkey] of the token to issue.
    ///
    /// If not specified, the [LRC20Pubkey] will be the same as the X only key derived from the
    /// private key.
    ///
    /// It can be specified either as a public key or an untweaked P2TR address with optional
    /// parity. Default parity is even.
    ///
    /// If you want to specify the parity along with an address, use the following format:
    /// `<address>:<parity>`, where parity is either `0` for even or `1` for odd.
    #[clap(long, value_parser = LRC20Pubkey::from_str)]
    pub token_pubkey: Option<LRC20Pubkey>,

    /// Amount in satoshis that will be added to LRC20 UTXO.
    ///
    /// Default is 10,000 satoshis, if only one amount is provided it will be
    /// used for all recipients.
    #[clap(long, short, num_args = 1.., default_values_t = vec![DEFAULT_SATOSHIS])]
    pub satoshis: Vec<u64>,

    /// LRC20 token amount
    #[clap(long = "amount", num_args = 1..)]
    pub amounts: Vec<u128>,

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
    #[clap(long = "recipient", num_args = 1.., value_parser = LRC20Pubkey::from_str)]
    pub recipients: Vec<LRC20Pubkey>,

    /// Provide proof of the transaction to LRC20 node.
    #[clap(long)]
    pub do_not_provide_proofs: bool,

    /// Drain tweaked satoshis to use for fees, instead of using regular satoshis.
    ///
    /// It's worth noting that change from regular satoshis will be tweaked.
    #[clap(long)]
    pub drain_tweaked_satoshis: bool,
}

pub async fn run(
    IssueArgs {
        amounts,
        recipients,
        satoshis,
        do_not_provide_proofs,
        drain_tweaked_satoshis,
        address_types,
        token_pubkey,
    }: IssueArgs,
    mut ctx: Context,
) -> eyre::Result<()> {
    let address_types = process_addr_types(address_types, recipients.len())?;

    if amounts.len() != recipients.len() {
        bail!("Amounts and recipients must have the same length");
    }

    let satoshis = process_satoshis(satoshis, amounts.len())?;

    let wallet = ctx.wallet().await?;
    let blockchain = ctx.blockchain()?;
    let cfg = ctx.config()?;

    let tx = {
        let mut builder = wallet.build_issuance(token_pubkey.map(|r| r.into()))?;
        for (i, recipient) in recipients.iter().enumerate() {
            match address_types[i] {
                AddrType::P2WPKH => {
                    builder.add_recipient(&recipient.into(), amounts[i], satoshis[i]);
                }
                AddrType::P2TR => {
                    builder.add_taproot_recipient(&recipient.into(), amounts[i], satoshis[i]);
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
