use std::str::FromStr;

use crate::actions::types::LRC20Pubkey;
use crate::{actions::announcement_args::broadcast_announcement, context::Context};
use clap::Args;
use color_eyre::eyre::{self};
use lrc20_receipts::TokenPubkey;
use lrc20_types::Announcement;

/// Arguments to make a logo announcement. See [`lrc20_types::announcements::TokenLogoAnnouncement`].
#[derive(Clone, Args, Debug)]
pub struct LogoArgs {
    /// The token_pubkey to transfer.
    ///
    /// It can be specified either as a public key or an untweaked P2TR address with optional
    /// parity. Default parity is even.
    ///
    /// If you want to specify the parity along with an address, use the following format:
    /// `<address>:<parity>`, where parity is either `0` for even or `1` for odd.
    #[clap(long, short, value_parser = TokenPubkey::from_str)]
    pub token_pubkey: Option<LRC20Pubkey>,
    /// The logo URL for specified token pubkey.
    #[clap(long, short)]
    pub logo_url: String,
}

pub async fn run(args: LogoArgs, mut context: Context) -> eyre::Result<()> {
    let wallet = context.wallet().await?;
    let token_pubkey: TokenPubkey = args
        .token_pubkey
        .map_or_else(|| wallet.public_key().into(), |r| r.into());

    let announcement = Announcement::token_logo_announcement(token_pubkey, args.logo_url)?;
    broadcast_announcement(announcement, context).await
}
