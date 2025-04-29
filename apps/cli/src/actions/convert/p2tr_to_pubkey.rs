use clap::Args;
use color_eyre::eyre;
use lrc20_receipts::TokenPubkey;

#[derive(Args, Debug)]
pub struct P2trToPubkeyArgs {
    /// A Taproot address to be converted to a public key.
    #[clap(long, short, value_parser = |s: &str| TokenPubkey::from_address(s, None))]
    pub address: TokenPubkey,
}

pub(crate) fn run(P2trToPubkeyArgs { address }: P2trToPubkeyArgs) -> eyre::Result<()> {
    println!("{}", address.pubkey());

    Ok(())
}
