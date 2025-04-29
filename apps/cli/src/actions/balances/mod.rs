use std::collections::HashMap;

use crate::context::Context;
use bitcoin::Network;
use color_eyre::eyre;
use lrc20_receipts::TokenPubkey;

pub async fn run(mut ctx: Context) -> eyre::Result<()> {
    let wallet = ctx.wallet().await?;
    let network = ctx.config()?.network();
    let balances = wallet.balances().await?;

    println!("LRC20 balances:");
    print_balances(balances.lrc20, network);

    #[cfg(feature = "bulletproof")]
    {
        println!("Bulletproof balances:");
        print_balances(balances.bulletproof, network);
    }

    println!("Tweaked satoshis: {}", balances.tweaked_satoshis);

    Ok(())
}

fn print_balances(balances: HashMap<TokenPubkey, u128>, network: Network) {
    for (token_pubkey, balance) in balances.iter() {
        let (_pubkey, parity) = token_pubkey.pubkey().x_only_public_key();
        println!(
            "{}:{}: {}",
            token_pubkey.to_address(network),
            parity.to_u8(),
            balance
        );
    }
}
