use std::str::FromStr;

use bitcoin::{Network, OutPoint};
use clap::Args;
use color_eyre::eyre;
use lrc20_receipts::TokenPubkey;
use lrcdk::wallet::StorageWallet;

use crate::context::Context;

use super::types::LRC20Pubkey;

#[derive(Args, Debug)]
pub struct UtxosArgs {
    /// TokenPubkey of the token
    ///
    /// It can be specified either as a public key or an untweaked P2TR address with optional
    /// parity. Default parity is even.
    ///
    /// If you want to specify the parity along with an address, use the following format:
    /// `<address>:<parity>`, where parity is either `0` for even or `1` for odd.
    #[clap(long, value_parser = LRC20Pubkey::from_str)]
    pub token_pubkey: Option<LRC20Pubkey>,
}

pub async fn run(UtxosArgs { token_pubkey }: UtxosArgs, mut ctx: Context) -> eyre::Result<()> {
    let wallet = ctx.wallet().await?;

    match token_pubkey {
        Some(token_pubkey) => {
            show_utxos_by_token_pubkey(&wallet, token_pubkey.into()).await?;
        }
        None => {
            show_all_utxos(&wallet, ctx.config()?.network()).await?;
        }
    }

    Ok(())
}

async fn show_all_utxos(wallet: &StorageWallet, network: Network) -> eyre::Result<()> {
    let utxos = wallet.lrc20_utxos().await?;

    for (OutPoint { txid, vout }, proof) in utxos {
        let receipt = proof.receipt();
        let (_pubkey, parity) = receipt.token_pubkey.pubkey().x_only_public_key();

        println!(
            "{txid}:{vout:0>2} {token_pubkey}:{parity} {amount}",
            token_pubkey = receipt.token_pubkey.to_address(network),
            parity = parity.to_u8(),
            amount = receipt.token_amount.amount
        );
    }
    Ok(())
}

async fn show_utxos_by_token_pubkey(
    wallet: &StorageWallet,
    token_pubkey: TokenPubkey,
) -> eyre::Result<()> {
    let utxos = wallet.utxos_by_token_pubkey(token_pubkey).await?;

    for (OutPoint { txid, vout }, amount) in utxos {
        println!("{}:{} {}", txid, vout, amount);
    }

    Ok(())
}
