use bdk::miniscript::ToPublicKey;
use bitcoin::{Address, Network, PublicKey};
use clap::Args;
use color_eyre::eyre;
use lrc20_receipts::{Receipt, ReceiptKey};

#[derive(Args, Debug)]
/// Generate P2WPKH LRC20 address from public key, amount and token_pubkey.
pub struct GenerateAddressArgs {
    /// Public key in hex format.
    #[clap(long)]
    pub pubkey: PublicKey,
    /// Amount of tokens to send.
    #[clap(long)]
    pub amount: u128,
    /// TokenPubkey of the receipt.
    #[clap(long)]
    pub token_pubkey: PublicKey,
    /// Network to use.
    #[clap(long, short, default_value = "regtest")]
    pub network: Network,
}

pub(crate) fn run(
    GenerateAddressArgs {
        pubkey,
        amount,
        token_pubkey,
        network,
    }: GenerateAddressArgs,
) -> eyre::Result<()> {
    let receipt = Receipt::new(amount, token_pubkey);

    let receipt_key = ReceiptKey::new(receipt, &pubkey.inner)?;

    let address = Address::p2wpkh(&receipt_key.to_public_key(), network)?;

    println!("Address: {}", address);

    Ok(())
}
