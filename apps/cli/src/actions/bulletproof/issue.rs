use std::str::FromStr;

use clap::Args;
use color_eyre::eyre;
use lrc20_rpc_api::transactions::Lrc20TransactionsRpcClient;
use lrcdk::txbuilder::BulletproofRecipientParameters;

use crate::{actions::types::LRC20Pubkey, context::Context};

const DEFAULT_SATOSHIS: u64 = 10_000;

#[derive(Args, Debug)]
pub struct IssueArgs {
    /// [TokenPubkey] of the token to issue.
    ///
    /// If not specified, the [TokenPubkey] will be the same as the public key derived from the
    /// private key.
    ///
    /// It can be specified either as a public key or an untweaked P2TR address with optional
    /// parity. Default parity is even.
    ///
    /// If you want to specify the parity along with an address, use the following format:
    /// `<address>:<parity>`, where parity is either `0` for even or `1` for odd.
    #[clap(long, value_parser = LRC20Pubkey::from_str)]
    pub token_pubkey: Option<LRC20Pubkey>,

    #[clap(long, short, default_value_t = DEFAULT_SATOSHIS)]
    pub satoshis: u64,

    /// Amount to issue
    #[clap(long)]
    pub amount: u128,

    /// The recipient of the payment.
    /// It can be specified either as a public key or an untweaked P2TR address with optional
    /// parity. Default parity is even.
    ///
    /// If you want to specify the parity along with an address, use the following format:
    /// `<address>:<parity>`, where parity is either `0` for even or `1` for odd.
    #[clap(long = "recipient", value_parser = LRC20Pubkey::from_str)]
    pub recipient: LRC20Pubkey,
}

pub async fn run(
    IssueArgs {
        satoshis,
        amount,
        recipient,
        token_pubkey,
    }: IssueArgs,
    mut context: Context,
) -> eyre::Result<()> {
    let config = context.config()?;
    let wallet = context.wallet().await?;
    let blockchain = context.blockchain()?;
    let lrc20_client = context.lrc20_client()?;

    let mut builder = wallet.build_issuance(token_pubkey.map(|r| r.into()))?;
    builder
        .add_recipient_with_bulletproof(BulletproofRecipientParameters {
            recipient: recipient.into(),
            satoshis,
            amount,
        })?
        .set_fee_rate_strategy(config.fee_rate_strategy);

    let tx = builder.finish(&blockchain).await?;

    println!("{}", tx.bitcoin_tx.txid());

    lrc20_client.send_lrc20_tx(tx.hex(), None).await?;

    Ok(())
}
