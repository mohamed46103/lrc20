#![doc = include_str!("../README.md")]
#![cfg_attr(feature = "no-std", no_std)]

extern crate alloc;

#[cfg(feature = "bulletproof")]
pub use bulletproof::{
    RangeProof, generate as generate_bulletproof, k256, verify as verify_bulletproof,
};
pub use errors::{
    ReceiptKeyError, ReceiptParseError, ReceiptProofError, TokenAmountParseError,
    TokenPubkeyParseError,
};
pub use hash::ReceiptHash;
pub use keys::{ReceiptKey, ReceiptPrivateKey};
#[cfg(feature = "bulletproof")]
pub use proof::bulletproof::{
    Bulletproof, errors::BulletproofError, signing as bulletproof_signing,
};
pub use proof::common::lightning::commitment::{
    LightningCommitmentProof,
    script::LightningCommitmentProofData,
    witness::{LightningCommitmentWitness, LightningCommitmentWitnessStack},
};
pub use proof::common::lightning::htlc::{
    HtlcScriptKind, LightningHtlcData, LightningHtlcProof, LightningHtlcScript,
};
pub use proof::common::multisig::{MultisigReceiptProof, witness::MultisigWitness};
pub use proof::empty::EmptyReceiptProof;
pub use proof::p2tr::TaprootProof;
pub use proof::p2wpkh::{P2WPKHProof, SigReceiptProof, witness::P2WPKHWitness};
pub use proof::p2wsh::{P2WSHProof, witness::P2WSHWitness};
pub use proof::spark::exit::{
    SparkExitMetadata, SparkExitProof, SparkExitScript, witness::TaprootSparkWitness,
};
pub use proof::{CheckableProof, ReceiptProof};
pub use receipt::{
    BLINDING_FACTOR_SIZE, RECEIPT_SIZE, Receipt, TOKEN_AMOUNT_SIZE, TOKEN_PUBKEY_SIZE, TokenAmount,
    TokenPubkey, ZERO_PUBLIC_KEY,
};
pub use tweakable::Tweakable;

#[cfg(feature = "serde")]
use {
    alloc::{format, string::String, vec::Vec},
    bitcoin::{
        XOnlyPublicKey,
        key::{
            Parity,
            constants::{PUBLIC_KEY_SIZE, SCHNORR_PUBLIC_KEY_SIZE},
        },
        secp256k1::PublicKey,
    },
    core::str::FromStr,
    serde::Deserialize,
};

#[cfg(not(any(feature = "std", feature = "no-std")))]
compile_error!("at least one of the `std` or `no-std` features must be enabled");

#[cfg(feature = "consensus")]
pub mod consensus;

mod errors;
mod hash;
mod keys;
mod proof;
mod receipt;
mod tweakable;

mod metadata;

#[cfg(all(feature = "serde", feature = "bulletproof"))]
pub(crate) struct HexVisitor;

#[cfg(all(feature = "serde", feature = "bulletproof"))]
impl<'de> serde::de::Visitor<'de> for HexVisitor {
    type Value = alloc::string::String;

    fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
        formatter.write_str("a hex string")
    }

    fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(s.into())
    }
}

#[cfg(feature = "serde")]
pub(crate) fn deserialize_public_key<'de, D>(deserializer: D) -> Result<PublicKey, D::Error>
where
    D: serde::Deserializer<'de>,
{
    if deserializer.is_human_readable() {
        let s = String::deserialize(deserializer)?;

        if s.len() == PUBLIC_KEY_SIZE * 2 {
            let public_key = PublicKey::from_str(&s)
                .map_err(|e| serde::de::Error::custom(format!("Invalid token_pubkey: {}", e)))?;
            return Ok(public_key);
        }

        if s.len() == SCHNORR_PUBLIC_KEY_SIZE * 2 {
            let x_only_public_key = XOnlyPublicKey::from_str(&s)
                .map_err(|e| serde::de::Error::custom(format!("Invalid token_pubkey: {}", e)))?;
            let public_key = PublicKey::from_x_only_public_key(x_only_public_key, Parity::Even);
            return Ok(public_key);
        }

        return Err(serde::de::Error::custom("Invalid token_pubkey length"));
    }

    let bytes = Vec::<u8>::deserialize(deserializer)?;

    if bytes.len() == PUBLIC_KEY_SIZE {
        let public_key = PublicKey::from_slice(&bytes)
            .map_err(|e| serde::de::Error::custom(format!("Invalid token_pubkey: {}", e)))?;
        return Ok(public_key);
    }

    if bytes.len() == SCHNORR_PUBLIC_KEY_SIZE {
        let x_only_public_key = XOnlyPublicKey::from_slice(&bytes)
            .map_err(|e| serde::de::Error::custom(format!("Invalid token_pubkey: {}", e)))?;
        let public_key = PublicKey::from_x_only_public_key(x_only_public_key, Parity::Even);
        return Ok(public_key);
    }

    Err(serde::de::Error::custom("Invalid token_pubkey length"))
}
