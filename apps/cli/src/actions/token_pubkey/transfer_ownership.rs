use std::str::FromStr;

use crate::actions::types::LRC20Pubkey;
use crate::{actions::announcement_args::broadcast_announcement, context::Context};
use bitcoin::{Address, AddressType};
use clap::Args;
use color_eyre::Report;
use color_eyre::eyre::{self};
use lrc20_receipts::TokenPubkey;
use lrc20_types::Announcement;

/// Arguments to make a transfer ownership announcement. See [`lrc20_types::announcements::TransferOwnershipAnnouncement`].
#[derive(Clone, Args, Debug)]
pub struct TransferOwnershipArgs {
    /// The token_pubkey to transfer.
    ///
    /// It can be specified either as a public key or an untweaked P2TR address with optional
    /// parity. Default parity is even.
    ///
    /// If you want to specify the parity along with an address, use the following format:
    /// `<address>:<parity>`, where parity is either `0` for even or `1` for odd.
    #[clap(long, short, value_parser = TokenPubkey::from_str)]
    pub token_pubkey: Option<LRC20Pubkey>,
    /// The address of the new owner of the token_pubkey.
    #[clap(long, short)]
    pub new_owner: String,
}

pub async fn run(args: TransferOwnershipArgs, mut context: Context) -> eyre::Result<()> {
    let wallet = context.wallet().await?;
    let token_pubkey: TokenPubkey = args
        .token_pubkey
        .map_or_else(|| wallet.public_key().into(), |r| r.into());

    let new_owner_address = Address::from_str(&args.new_owner)?.assume_checked();

    if let Some(address_type) = new_owner_address.address_type() {
        if address_type == AddressType::P2tr {
            return Err(Report::msg(
                "Can't create ownership transfer on P2tr address.",
            ));
        }
    }

    let announcement = Announcement::transfer_ownership_announcement(
        token_pubkey,
        new_owner_address.script_pubkey(),
    );
    broadcast_announcement(announcement, context).await
}
