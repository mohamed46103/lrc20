use bdk::miniscript::ToPublicKey;
use bitcoin::{
    Address, Network, PrivateKey, WitnessProgram, WitnessVersion, address::Payload,
    secp256k1::rand::thread_rng,
};
use clap::Args;
use color_eyre::eyre;

use crate::context::Context;

#[derive(Args, Debug)]
/// Generate P2WPKH LRC20 address from public key, amount and token_pubkey.
pub struct GenerateKeypairArgs {
    /// Network to use.
    #[clap(long, short, default_value = "regtest")]
    pub network: Network,
}

/// Generate key, and print it to stdout.
pub fn run(
    GenerateKeypairArgs { network }: GenerateKeypairArgs,
    context: Context,
) -> eyre::Result<()> {
    let secp_ctx = context.secp_ctx();

    let (seckey, pubkey) = secp_ctx.generate_keypair(&mut thread_rng());

    let privkey = PrivateKey::new(seckey, network);

    let p2tr = Address::new(
        network,
        Payload::WitnessProgram(
            WitnessProgram::new(
                WitnessVersion::V1,
                pubkey.x_only_public_key().0.serialize().to_vec(),
            )
            .expect("Should be valid program"),
        ),
    );

    println!("Private key: {}", privkey);
    println!("Public key: {}", pubkey);
    println!("P2TR address: {}", p2tr);

    let address = Address::p2wpkh(&pubkey.to_public_key(), network)?;
    println!("P2WPKH address: {}", address);

    Ok(())
}
