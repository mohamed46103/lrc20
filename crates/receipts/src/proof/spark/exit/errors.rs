use alloc::fmt;
use bitcoin::{ScriptBuf, secp256k1, taproot::TaprootBuilderError};

use crate::ReceiptKeyError;

#[derive(Debug)]
pub enum SparkExitProofError {
    UnavailableTapSpendInfo,
    ReceiptKeyError(ReceiptKeyError),
    TaprootError(TaprootBuilderError),
    ScriptPubkeyMismatch { expected: ScriptBuf, got: ScriptBuf },
    LocktimeError(bitcoin::blockdata::locktime::absolute::Error),
}

impl fmt::Display for SparkExitProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SparkExitProofError::UnavailableTapSpendInfo => {
                write!(f, "Couldn't retrieve taproot spend info")
            }
            SparkExitProofError::ReceiptKeyError(e) => {
                write!(f, "Failed to create receipt key: {}", e)
            }
            SparkExitProofError::TaprootError(e) => {
                write!(f, "Failed to build taproot script: {}", e)
            }
            SparkExitProofError::ScriptPubkeyMismatch { expected, got } => {
                write!(
                    f,
                    "Invalid scriptpubkey, expected {} but got {}",
                    expected.to_hex_string(),
                    got.to_hex_string()
                )
            }
            SparkExitProofError::LocktimeError(e) => {
                write!(f, "Invalid locktime: {}", e)
            }
        }
    }
}

#[cfg(not(feature = "no-std"))]
impl std::error::Error for SparkExitProofError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SparkExitProofError::ReceiptKeyError(e) => Some(e),
            SparkExitProofError::TaprootError(e) => Some(e),
            SparkExitProofError::LocktimeError(e) => Some(e),
            SparkExitProofError::ScriptPubkeyMismatch { .. } => None,
            SparkExitProofError::UnavailableTapSpendInfo => None,
        }
    }
}

impl From<ReceiptKeyError> for SparkExitProofError {
    fn from(err: ReceiptKeyError) -> Self {
        SparkExitProofError::ReceiptKeyError(err)
    }
}

impl From<TaprootBuilderError> for SparkExitProofError {
    fn from(err: TaprootBuilderError) -> Self {
        Self::TaprootError(err)
    }
}

impl From<bitcoin::blockdata::locktime::absolute::Error> for SparkExitProofError {
    fn from(err: bitcoin::blockdata::locktime::absolute::Error) -> Self {
        Self::LocktimeError(err)
    }
}

#[derive(Debug)]
pub enum TaprootWitnessParseError {
    MissingWitnessSignature,
    Signature(secp256k1::Error),
}

impl fmt::Display for TaprootWitnessParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TaprootWitnessParseError::MissingWitnessSignature => {
                write!(f, "Missing signature as the first witness stack element")
            }
            TaprootWitnessParseError::Signature(e) => write!(f, "Invalid Schnorr signature: {}", e),
        }
    }
}

#[cfg(not(feature = "no-std"))]
impl std::error::Error for TaprootWitnessParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TaprootWitnessParseError::Signature(e) => Some(e),
            TaprootWitnessParseError::MissingWitnessSignature => None,
        }
    }
}

impl From<secp256k1::Error> for TaprootWitnessParseError {
    fn from(err: secp256k1::Error) -> Self {
        TaprootWitnessParseError::Signature(err)
    }
}
