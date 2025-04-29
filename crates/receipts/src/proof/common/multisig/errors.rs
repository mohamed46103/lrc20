use alloc::fmt;
use bitcoin::secp256k1;

use crate::{ReceiptKeyError, proof::p2wsh::errors::P2WSHWitnessParseError};

#[derive(Debug)]
pub enum MultisigReceiptProofError {
    /// The witness does not contain a valid receipt key.
    ReceiptKeyError(ReceiptKeyError),

    /// The number of inner keys in the witness does not match the number of
    /// keys in the inner script.
    InvalidNumberOfInnerKeys(usize, usize),

    /// Failed to parse witness
    WitnessParseError(P2WSHWitnessParseError),

    /// The number of signatures in the witness does not match the number of
    /// keys in the inner script.
    InvalidNumberOfSignatures(usize, usize),

    /// Mismatch of redeem scripts in witness and inner script
    RedeemScriptMismatch,
}

impl From<ReceiptKeyError> for MultisigReceiptProofError {
    fn from(e: ReceiptKeyError) -> Self {
        MultisigReceiptProofError::ReceiptKeyError(e)
    }
}

impl From<P2WSHWitnessParseError> for MultisigReceiptProofError {
    fn from(e: P2WSHWitnessParseError) -> Self {
        MultisigReceiptProofError::WitnessParseError(e)
    }
}

impl fmt::Display for MultisigReceiptProofError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MultisigReceiptProofError::ReceiptKeyError(e) => write!(f, "Receipt key error: {}", e),
            MultisigReceiptProofError::InvalidNumberOfInnerKeys(expected, actual) => write!(
                f,
                "Invalid number of inner keys: expected {}, got {}",
                expected, actual
            ),
            MultisigReceiptProofError::WitnessParseError(e) => {
                write!(f, "Witness parse error: {}", e)
            }
            MultisigReceiptProofError::InvalidNumberOfSignatures(expected, actual) => write!(
                f,
                "Invalid number of signatures: expected {}, got {}",
                expected, actual
            ),
            MultisigReceiptProofError::RedeemScriptMismatch => {
                write!(f, "Mismatch of redeem scripts in witness and inner script")
            }
        }
    }
}

#[cfg(not(feature = "no-std"))]
impl std::error::Error for MultisigReceiptProofError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            MultisigReceiptProofError::ReceiptKeyError(e) => Some(e),
            MultisigReceiptProofError::InvalidNumberOfInnerKeys(_, _) => None,
            MultisigReceiptProofError::InvalidNumberOfSignatures(_, _) => None,
            MultisigReceiptProofError::WitnessParseError(e) => Some(e),
            MultisigReceiptProofError::RedeemScriptMismatch => None,
        }
    }
}

#[derive(Debug)]
pub enum MultisigScriptError {
    /// Invalid structure of multisig script
    InvalidScript,

    /// Failed to parse pubkey from p2wsh redeem script
    ParsePubkeyError(secp256k1::Error),
}

impl From<secp256k1::Error> for MultisigScriptError {
    fn from(e: secp256k1::Error) -> Self {
        MultisigScriptError::ParsePubkeyError(e)
    }
}

impl fmt::Display for MultisigScriptError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MultisigScriptError::InvalidScript => write!(f, "Invalid multisig script"),
            MultisigScriptError::ParsePubkeyError(e) => {
                write!(f, "Failed to parse pubkey from p2wsh redeem script: {}", e)
            }
        }
    }
}

#[cfg(not(feature = "no-std"))]
impl std::error::Error for MultisigScriptError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            MultisigScriptError::InvalidScript => None,
            MultisigScriptError::ParsePubkeyError(e) => Some(e),
        }
    }
}
