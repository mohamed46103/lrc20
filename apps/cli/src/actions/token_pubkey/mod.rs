use crate::context::Context;
use clap::Subcommand;
use color_eyre::eyre;

mod announcement;
mod info;
mod logo;
mod transfer_ownership;

#[derive(Subcommand, Debug)]
pub enum TokenPubkeyCommands {
    /// Make the TokenPubkey announcement.
    Announcement(announcement::TokenPubkeyAnnnouncementArgs),
    /// Get the information about the token by its TokenPubkey.
    Info(info::InfoArgs),
    /// Transfer ownership of the token_pubkey to another address.
    TransferOwnership(transfer_ownership::TransferOwnershipArgs),
    /// Add a logo for token.
    Logo(logo::LogoArgs),
}

pub async fn run(cmd: TokenPubkeyCommands, context: Context) -> eyre::Result<()> {
    match cmd {
        TokenPubkeyCommands::Announcement(args) => announcement::run(args, context).await,
        TokenPubkeyCommands::Info(args) => info::run(args, context).await,
        TokenPubkeyCommands::TransferOwnership(args) => {
            transfer_ownership::run(args, context).await
        }
        TokenPubkeyCommands::Logo(args) => logo::run(args, context).await,
    }
}
