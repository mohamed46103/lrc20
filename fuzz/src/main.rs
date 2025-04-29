#[macro_use]
extern crate afl;

use bitcoin::hashes::sha256d::Hash;
use bitcoin::hashes::Hash as BitcoinHash;
use bitcoin::secp256k1::rand::rngs::StdRng;
use bitcoin::secp256k1::rand::SeedableRng;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey, ThirtyTwoByteHash};
use once_cell::sync::Lazy;
use std::str::FromStr;
use lrc20_receipts::{TokenPubkey, Receipt, ReceiptHash, ReceiptKey, ReceiptPrivateKey};

static ISSUER: Lazy<PublicKey> = Lazy::new(|| {
    PublicKey::from_str("02ef156c4ebfbf48fc4849915f65dc46a782ee837c7efd834e9d24d975d07784b8")
        .expect("Should be valid public key")
});

fn pad_to_seed_length(input: &[u8]) -> [u8; 32] {
    let mut result = [0; 32];

    let copy_length = input.len().min(32);
    result[..copy_length].copy_from_slice(&input[..copy_length]);

    result
}

pub fn generate_keypair(data: &[u8]) -> (SecretKey, PublicKey) {
    let seed = {
        let mut bytes: [u8; 32] = [0; 32];
        if data.len() > 32 {
            bytes.copy_from_slice(&Hash::hash(data).into_32());
        } else {
            bytes.copy_from_slice(&pad_to_seed_length(data));
        }
        bytes
    };

    let mut rng = StdRng::from_seed(seed);
    let secp = Secp256k1::new();

    secp.generate_keypair(&mut rng)
}

fn main() {
    let receipt = Receipt::new(100, &ISSUER.clone().into());
    let ctx = Secp256k1::new();

    fuzz!(|data: &[u8]| {
        let (recipient_priv_key, recipient_pub_key) = generate_keypair(data);

        let receipt_key = ReceiptKey::new_with_ctx(receipt, &recipient_pub_key, &ctx).unwrap();

        let pxsk = ReceiptPrivateKey::new_with_ctx(receipt, &recipient_priv_key, &ctx).unwrap();

        let derived = pxsk.0.public_key(&ctx);

        if !derived.eq(&receipt_key.0.inner) {
            panic!("public key derived from the private key MUST be equal to the public key got from the hash");
        };
    });

    fuzz!(|data: &[u8]| {
        let (_priv_key, pub_key) = generate_keypair(data);

        let (xonly, _parity) = pub_key.x_only_public_key();

        let receipt = Receipt::new(100, TokenPubkey::from(xonly));

        if let Err(e) = ReceiptKey::new(ReceiptHash::from(receipt), &pub_key) {
            panic!("failed to create receipt key: {}", e);
        }
    });
}
