use std::str::FromStr;

use crate::{
    actions::{announcement_args::broadcast_announcement, types::LRC20Pubkey},
    context::Context,
};

use clap::Args;
use color_eyre::eyre::{self};
use lrc20_receipts::TokenPubkey;
use lrc20_types::Announcement;

/// Arguments to make a token_pubkey announcement. See [`lrc20_types::announcements::TokenPubkeyAnnouncement`].
#[derive(Clone, Args, Debug)]
pub struct TokenPubkeyAnnnouncementArgs {
    /// The [`TokenPubkey`] to announce.
    ///
    /// It can be specified either as a public key or an untweaked P2TR address with optional
    /// parity. Default parity is even.
    ///
    /// If you want to specify the parity along with an address, use the following format:
    /// `<address>:<parity>`, where parity is either `0` for even or `1` for odd.
    #[clap(long, short, value_parser = LRC20Pubkey::from_str)]
    pub token_pubkey: Option<LRC20Pubkey>,
    /// The name of the token.
    #[clap(long, short)]
    pub name: String,
    /// The symbol of the token.
    #[clap(long)]
    pub symbol: String,
    /// The decimals of the token.
    #[clap(long, short, default_value_t = 0)]
    pub decimal: u8,
    /// The maximum supply of the token. 0 - supply is unlimited.
    #[clap(long, default_value_t = 0)]
    pub max_supply: u128,
    /// Indicates whether the token can be frozen by the issuer.
    #[clap(long, default_value_t = true)]
    pub is_freezable: bool,
}

pub async fn run(args: TokenPubkeyAnnnouncementArgs, mut context: Context) -> eyre::Result<()> {
    let wallet = context.wallet().await?;
    let token_pubkey: TokenPubkey = args
        .token_pubkey
        .map_or_else(|| wallet.public_key().into(), |r| r.into());

    let announcement = Announcement::token_pubkey_announcement(
        token_pubkey,
        args.name,
        args.symbol,
        args.decimal,
        args.max_supply,
        args.is_freezable,
    )?;

    broadcast_announcement(announcement, context).await
}
