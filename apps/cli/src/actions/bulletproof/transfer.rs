use std::{collections::HashSet, str::FromStr};

use crate::{actions::types::LRC20Pubkey, check_equal_lengths};

use bitcoin::OutPoint;
use clap::Args;
use color_eyre::eyre::{self, bail};
use lrcdk::txbuilder::BulletproofRecipientParameters;

use lrc20_rpc_api::transactions::Lrc20TransactionsRpcClient;

use crate::context::Context;

#[derive(Args, Debug)]
pub struct TransferArgs {
    /// Value to transfer
    #[clap(long, num_args = 1..)]
    pub amount: Vec<u128>,

    /// Value to transfer to sender
    #[clap(long, num_args = 1..)]
    pub residual: Vec<u128>,

    #[clap(long, num_args = 1..)]
    /// Satoshis to transfer
    pub satoshis: Vec<u64>,

    #[clap(long, num_args = 1..)]
    /// satoshis to transfer to sender
    pub residual_satoshis: Vec<u64>,

    /// Type of the token, public key of the issuer.
    #[clap(long, num_args = 1.., value_parser = LRC20Pubkey::from_str)]
    pub token_pubkey: Vec<LRC20Pubkey>,

    /// The recipient of the payment.
    /// It can be specified either as a public key or an untweaked P2TR address with optional
    /// parity. Default parity is even.
    ///
    /// If you want to specify the parity along with an address, use the following format:
    /// `<address>:<parity>`, where parity is either `0` for even or `1` for odd.
    #[clap(long = "recipient", num_args = 1.., value_parser = LRC20Pubkey::from_str)]
    pub recipients: Vec<LRC20Pubkey>,

    /// The input tx id and vout seperated with `:` symbol. For example `dcdd...eda45:0`
    #[clap(long, num_args = 1..)]
    pub outpoint: Vec<OutPoint>,
}

pub async fn run(
    TransferArgs {
        amount,
        residual,
        satoshis,
        residual_satoshis,
        token_pubkey,
        recipients,
        outpoint,
    }: TransferArgs,
    mut context: Context,
) -> eyre::Result<()> {
    check_equal_lengths!(
        amount,
        residual,
        satoshis,
        residual_satoshis,
        token_pubkey,
        recipients,
        outpoint
    );

    if HashSet::<OutPoint>::from_iter(outpoint.clone()).len() != outpoint.len() {
        bail!("A bulletproof transfer cannot contain the same outpoint multiple times")
    }

    let config = context.config()?;
    let wallet = context.wallet().await?;
    let blockchain = context.blockchain()?;
    let lrc20_client = context.lrc20_client()?;

    let mut builder = wallet.build_transfer()?;
    // Add the input tx
    builder.manual_selected_only();
    let sender = config.private_key.public_key(context.secp_ctx()).inner;

    for i in 0..token_pubkey.len() {
        builder.add_recipient_with_bulletproof(
            outpoint[i],
            token_pubkey[i].into(),
            BulletproofRecipientParameters {
                recipient: recipients[i].into(),
                amount: amount[i],
                satoshis: satoshis[i],
            },
        )?;

        if residual[i] != 0 && residual_satoshis[i] != 0 {
            builder.add_recipient_with_bulletproof(
                outpoint[i],
                token_pubkey[i].into(),
                BulletproofRecipientParameters {
                    recipient: sender,
                    amount: residual[i],
                    satoshis: residual_satoshis[i],
                },
            )?;
        }
    }

    builder.set_fee_rate_strategy(config.fee_rate_strategy);

    let tx = builder.finish(&blockchain).await?;

    println!("{}", tx.bitcoin_tx.txid());

    lrc20_client.send_lrc20_tx(tx.hex(), None).await?;

    Ok(())
}
