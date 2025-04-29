use bitcoin::secp256k1::constants::SCHNORR_PUBLIC_KEY_SIZE;
use core::fmt;

use bitcoin::{WitnessVersion, secp256k1};

#[cfg(feature = "bulletproof")]
use crate::proof::bulletproof::errors::BulletproofError;
use crate::proof::common::lightning::commitment::errors::LightningCommitmentProofError;
use crate::proof::common::lightning::htlc::LightningHtlcProofError;
use crate::proof::common::multisig::errors::MultisigReceiptProofError;
use crate::proof::p2tr::errors::TaprootProofError;
use crate::proof::p2wpkh::errors::P2WPKHProofError;
use crate::proof::p2wsh::errors::P2WSHProofError;
use crate::proof::spark::exit::errors::SparkExitProofError;
use crate::{RECEIPT_SIZE, TOKEN_PUBKEY_SIZE};

#[derive(Debug)]
pub enum ReceiptHashError {
    InvalidMetadata(serde_json::Error),
}

impl fmt::Display for ReceiptHashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReceiptHashError::InvalidMetadata(e) => write!(f, "Serialization error: {}", e),
        }
    }
}

#[cfg(not(feature = "no-std"))]
impl std::error::Error for ReceiptHashError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ReceiptHashError::InvalidMetadata(e) => Some(e),
        }
    }
}

impl From<serde_json::Error> for ReceiptHashError {
    fn from(err: serde_json::Error) -> Self {
        ReceiptHashError::InvalidMetadata(err)
    }
}

#[derive(Debug)]
pub enum ReceiptKeyError {
    Secp256k1(secp256k1::Error),

    /// Error during operations with key.
    PublicKeyError(bitcoin::key::Error),

    /// Error during computation of receipt hash
    ReceiptHashError(ReceiptHashError),

    /// Scalar created from receipt hash is out of range.
    /// NOTE: usually this should never happen, but it's better to handle this case.
    ReceiptHashOutOfRange,

    /// Uncompressed public key used when only compressed one is supported
    UncompressedKey,
}

impl fmt::Display for ReceiptKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReceiptKeyError::Secp256k1(e) => write!(f, "Secp256k1 error: {}", e),
            ReceiptKeyError::PublicKeyError(e) => write!(f, "Failed to decode public key: {}", e),
            ReceiptKeyError::ReceiptHashError(e) => {
                write!(f, "Failed to compute receipt hash: {}", e)
            }
            ReceiptKeyError::ReceiptHashOutOfRange => write!(f, "Receipt hash is out of range"),
            ReceiptKeyError::UncompressedKey => write!(f, "Uncompressed key"),
        }
    }
}

#[cfg(not(feature = "no-std"))]
impl std::error::Error for ReceiptKeyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ReceiptKeyError::Secp256k1(e) => Some(e),
            ReceiptKeyError::PublicKeyError(e) => Some(e),
            ReceiptKeyError::ReceiptHashError(e) => Some(e),
            ReceiptKeyError::ReceiptHashOutOfRange => None,
            ReceiptKeyError::UncompressedKey => None,
        }
    }
}

impl From<secp256k1::Error> for ReceiptKeyError {
    fn from(err: secp256k1::Error) -> Self {
        ReceiptKeyError::Secp256k1(err)
    }
}

impl From<bitcoin::key::Error> for ReceiptKeyError {
    fn from(err: bitcoin::key::Error) -> Self {
        ReceiptKeyError::PublicKeyError(err)
    }
}

impl From<ReceiptHashError> for ReceiptKeyError {
    fn from(err: ReceiptHashError) -> Self {
        ReceiptKeyError::ReceiptHashError(err)
    }
}

#[derive(Debug)]
pub enum TokenAmountParseError {
    InvalidSize(usize),
}

impl fmt::Display for TokenAmountParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenAmountParseError::InvalidSize(size) => {
                write!(f, "Invalid token_amount size: {}", size)
            }
        }
    }
}

#[cfg(not(feature = "no-std"))]
impl std::error::Error for TokenAmountParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TokenAmountParseError::InvalidSize(_) => None,
        }
    }
}

#[derive(Debug)]
pub enum ReceiptParseError {
    IncorrectSize(usize),
    InvalidTokenAmount(TokenAmountParseError),
    InvalidTokenPubkey(TokenPubkeyParseError),
}

impl fmt::Display for ReceiptParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReceiptParseError::IncorrectSize(size) => {
                write!(
                    f,
                    "Invalid receipt size: {}, required: {}",
                    size, RECEIPT_SIZE
                )
            }
            ReceiptParseError::InvalidTokenAmount(e) => write!(f, "Invalid token_amount: {}", e),
            ReceiptParseError::InvalidTokenPubkey(e) => write!(f, "Invalid token_pubkey: {}", e),
        }
    }
}

#[cfg(not(feature = "no-std"))]
impl std::error::Error for ReceiptParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ReceiptParseError::IncorrectSize(_) => None,
            ReceiptParseError::InvalidTokenAmount(e) => Some(e),
            ReceiptParseError::InvalidTokenPubkey(e) => Some(e),
        }
    }
}

impl From<TokenAmountParseError> for ReceiptParseError {
    fn from(err: TokenAmountParseError) -> Self {
        ReceiptParseError::InvalidTokenAmount(err)
    }
}

impl From<TokenPubkeyParseError> for ReceiptParseError {
    fn from(err: TokenPubkeyParseError) -> Self {
        ReceiptParseError::InvalidTokenPubkey(err)
    }
}

#[derive(Debug)]
pub enum TokenPubkeyParseError {
    InvalidSize(usize),
    InvalidPublicKey(secp256k1::Error),
    InvalidAddressType,
    InvalidWitnessProgramVersion(WitnessVersion),
    InvalidWitnessProgramLength(usize),
}

impl fmt::Display for TokenPubkeyParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenPubkeyParseError::InvalidSize(size) => {
                write!(
                    f,
                    "Invalid bytes size: {}, required: {}",
                    size, TOKEN_PUBKEY_SIZE
                )
            }
            TokenPubkeyParseError::InvalidPublicKey(e) => {
                write!(f, "Invalid public key structure: {}", e)
            }
            TokenPubkeyParseError::InvalidAddressType => {
                write!(f, "Invalid address type")
            }
            TokenPubkeyParseError::InvalidWitnessProgramVersion(version) => {
                write!(f, "Invalid witness program version: {}", version)
            }
            TokenPubkeyParseError::InvalidWitnessProgramLength(length) => {
                write!(
                    f,
                    "Invalid witness program length: {}, expected {}",
                    length, SCHNORR_PUBLIC_KEY_SIZE
                )
            }
        }
    }
}

#[cfg(not(feature = "no-std"))]
impl std::error::Error for TokenPubkeyParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TokenPubkeyParseError::InvalidSize(_) => None,
            TokenPubkeyParseError::InvalidPublicKey(e) => Some(e),
            TokenPubkeyParseError::InvalidAddressType => None,
            TokenPubkeyParseError::InvalidWitnessProgramVersion(_) => None,
            TokenPubkeyParseError::InvalidWitnessProgramLength(_) => None,
        }
    }
}

impl From<secp256k1::Error> for TokenPubkeyParseError {
    fn from(err: secp256k1::Error) -> Self {
        TokenPubkeyParseError::InvalidPublicKey(err)
    }
}

#[derive(Debug)]
pub enum ReceiptProofError {
    /// P2WPKH error
    P2WPKH(P2WPKHProofError),

    /// P2WSH error
    P2WSH(P2WSHProofError),

    /// P2TR error
    P2TR(TaprootProofError),

    /// EmptyReceiptProof
    EmptyReceipt(P2WPKHProofError),

    Multisig(MultisigReceiptProofError),

    Lightning(LightningCommitmentProofError),

    LightningHtlc(LightningHtlcProofError),

    SparkExit(SparkExitProofError),

    #[cfg(feature = "bulletproof")]
    /// Bulletproof error
    Bulletproof(BulletproofError),
}

impl From<MultisigReceiptProofError> for ReceiptProofError {
    fn from(v: MultisigReceiptProofError) -> Self {
        Self::Multisig(v)
    }
}

impl From<TaprootProofError> for ReceiptProofError {
    fn from(v: TaprootProofError) -> Self {
        Self::P2TR(v)
    }
}

impl From<LightningHtlcProofError> for ReceiptProofError {
    fn from(v: LightningHtlcProofError) -> Self {
        Self::LightningHtlc(v)
    }
}

impl From<LightningCommitmentProofError> for ReceiptProofError {
    fn from(v: LightningCommitmentProofError) -> Self {
        Self::Lightning(v)
    }
}

impl fmt::Display for ReceiptProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReceiptProofError::P2WPKH(e) => write!(f, "P2WPKH: {}", e),
            ReceiptProofError::P2WSH(e) => write!(f, "P2WSH: {}", e),
            ReceiptProofError::P2TR(e) => write!(f, "P2TR: {}", e),
            ReceiptProofError::EmptyReceipt(e) => write!(f, "EmptyReceipt: {}", e),
            ReceiptProofError::Multisig(e) => write!(f, "Multisig: {}", e),
            ReceiptProofError::Lightning(e) => write!(f, "Lightning: {}", e),
            ReceiptProofError::LightningHtlc(e) => write!(f, "LightningHtlc: {}", e),
            ReceiptProofError::SparkExit(e) => write!(f, "SparkExit: {}", e),
            #[cfg(feature = "bulletproof")]
            ReceiptProofError::Bulletproof(e) => write!(f, "Bulletproof: {}", e),
        }
    }
}

#[cfg(not(feature = "no-std"))]
impl std::error::Error for ReceiptProofError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ReceiptProofError::P2WPKH(e) => Some(e),
            ReceiptProofError::P2WSH(e) => Some(e),
            ReceiptProofError::P2TR(e) => Some(e),
            ReceiptProofError::EmptyReceipt(e) => Some(e),
            ReceiptProofError::Multisig(e) => Some(e),
            ReceiptProofError::Lightning(e) => Some(e),
            ReceiptProofError::LightningHtlc(e) => Some(e),
            ReceiptProofError::SparkExit(e) => Some(e),
            #[cfg(feature = "bulletproof")]
            ReceiptProofError::Bulletproof(e) => Some(e),
        }
    }
}

impl From<P2WPKHProofError> for ReceiptProofError {
    fn from(err: P2WPKHProofError) -> Self {
        ReceiptProofError::P2WPKH(err)
    }
}

impl From<P2WSHProofError> for ReceiptProofError {
    fn from(err: P2WSHProofError) -> Self {
        ReceiptProofError::P2WSH(err)
    }
}

impl From<SparkExitProofError> for ReceiptProofError {
    fn from(err: SparkExitProofError) -> Self {
        ReceiptProofError::SparkExit(err)
    }
}

#[cfg(feature = "bulletproof")]
impl From<BulletproofError> for ReceiptProofError {
    fn from(err: BulletproofError) -> Self {
        ReceiptProofError::Bulletproof(err)
    }
}
