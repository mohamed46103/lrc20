use bitcoin::PublicKey;
use clap::Args;
use color_eyre::eyre;
use lrc20_receipts::{Receipt, ReceiptHash};

#[derive(Args, Debug)]
/// Generate LRC20 receipt hash from amount and token_pubkey.
pub struct GenerateReceiptHashArgs {
    /// Amount of tokens to send.
    #[clap(long)]
    pub amount: u128,
    /// TokenPubkey of the receipt.
    #[clap(long)]
    pub token_pubkey: PublicKey,
}

pub(crate) fn run(
    GenerateReceiptHashArgs {
        amount,
        token_pubkey,
    }: GenerateReceiptHashArgs,
) -> eyre::Result<()> {
    let receipt = Receipt::new(amount, token_pubkey);

    let receipt_hash = ReceiptHash::from(receipt);

    println!("Receipt hash: {}", *receipt_hash);

    Ok(())
}
