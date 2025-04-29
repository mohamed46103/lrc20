use std::str::FromStr;

use bitcoin::{OutPoint, secp256k1::PublicKey};
use clap::Args;

use color_eyre::eyre::{self};
use lrc20_receipts::TokenPubkey;
use lrc20_types::Announcement;

use crate::{actions::announcement_args::broadcast_announcement, context::Context};

use super::types::LRC20Pubkey;

#[derive(Args, Clone, Debug)]
pub struct FreezeToggleArgs {
    /// The [`TokenPubkey`] to freeze
    ///
    /// It can be specified either as a public key or an untweaked P2TR address with optional
    /// parity. Default parity is even.
    ///
    /// If you want to specify the parity along with an address, use the following format:
    /// `<address>:<parity>`, where parity is either `0` for even or `1` for odd.
    #[clap(long, short, value_parser = LRC20Pubkey::from_str)]
    pub token_pubkey: Option<LRC20Pubkey>,

    /// Outpoint or pubkey to freeze
    #[clap(flatten)]
    pub freeze_arg: FreezeArgs,
}

#[derive(Debug, Args, Clone)]
#[group(required = true, multiple = false)]
pub struct FreezeArgs {
    /// Outpoint to freeze
    #[clap(short, long)]
    outpoint: Option<OutPoint>,

    /// Public key to freeze
    #[clap(short, long)]
    pubkey: Option<PublicKey>,
}

pub async fn run(args: FreezeToggleArgs, mut context: Context) -> eyre::Result<()> {
    let wallet = context.wallet().await?;
    let token_pubkey: TokenPubkey = args
        .token_pubkey
        .map_or_else(|| wallet.public_key().into(), |r| r.into());

    if let Some(outpoint) = args.freeze_arg.outpoint {
        broadcast_announcement(
            Announcement::tx_freeze_announcement(token_pubkey, outpoint),
            context,
        )
        .await
    } else if let Some(pubkey) = args.freeze_arg.pubkey {
        broadcast_announcement(
            Announcement::pubkey_freeze_announcement(token_pubkey, pubkey),
            context,
        )
        .await
    } else {
        // The function is expected to only be used with clap, and clap requires at least one
        // optional param to be Some, so this branch is unreachable.
        unreachable!();
    }
}
