use std::str::FromStr;

use crate::{actions::types::LRC20Pubkey, context::Context};
use bitcoin::Address;
use clap::Args;
use color_eyre::eyre;
use lrc20_rpc_api::transactions::Lrc20TransactionsRpcClient;

/// Arguments to request the information about the token from LRC20 node by its [`LRC20Pubkey`].
#[derive(Clone, Args, Debug)]
pub struct InfoArgs {
    /// The [`LRC20Pubkey`] of the token to get the information about.
    ///
    /// It can be specified either as a public key or an untweaked P2TR address with optional
    /// parity. Default parity is even.
    ///
    /// If you want to specify the parity along with an address, use the following format:
    /// `<address>:<parity>`, where parity is either `0` for even or `1` for odd.
    #[clap(long, short, value_parser = LRC20Pubkey::from_str)]
    pub token_pubkey: LRC20Pubkey,
}

pub async fn run(args: InfoArgs, mut context: Context) -> eyre::Result<()> {
    let client = context.lrc20_client()?;
    let config = context.config()?;
    let token_pubkey = args.token_pubkey.into();

    let token_pubkey_info_opt = client.get_token_pubkey_info(token_pubkey).await?;

    let Some(token_pubkey_info) = token_pubkey_info_opt else {
        println!("Token info not found");

        return Ok(());
    };

    println!("TokenPubkey: {}", token_pubkey.to_address(config.network()));

    if let Some(announcement) = token_pubkey_info.announcement {
        println!("Name: {}", announcement.name);
        println!("Symbol: {}", announcement.symbol);
        println!("Decimal: {}", announcement.decimal);

        let max_supply = if announcement.max_supply == 0 {
            "unlimited".to_owned()
        } else {
            announcement.max_supply.to_string()
        };
        println!("Max supply: {}", max_supply);
        println!("Is freezable: {}", announcement.is_freezable);
    };

    println!("Total supply: {}", token_pubkey_info.total_supply);

    let network = config.network();
    let address = if let Some(owner_script) = token_pubkey_info.owner {
        Address::from_script(&owner_script, network)?
    } else {
        token_pubkey.to_address(network)
    };
    println!("Owner address: {}", address);

    if let Some(logo) = token_pubkey_info.logo_url {
        println!("Logo URL: {}", logo);
    }

    Ok(())
}
