use crate::{ReceiptKeyError, proof::p2wpkh::errors::P2WPKHWitnessParseError};

#[derive(Debug)]
pub enum BulletproofError {
    /// Error related to tweaking the receipt key
    ReceiptKeyError(ReceiptKeyError),

    /// Error parsing the witness
    WitnessParseError(P2WPKHWitnessParseError),

    /// The range proof is invalid
    InvalidRangeProof,

    /// Mismatch of provided script and the script in the witness
    ScriptMismatch,

    /// The public key in the witness does not match the public key in the script
    PublicKeyMismatch,

    TokenAmountMismatch,
}

impl From<ReceiptKeyError> for BulletproofError {
    fn from(err: ReceiptKeyError) -> Self {
        Self::ReceiptKeyError(err)
    }
}

impl From<P2WPKHWitnessParseError> for BulletproofError {
    fn from(err: P2WPKHWitnessParseError) -> Self {
        Self::WitnessParseError(err)
    }
}

impl core::fmt::Display for BulletproofError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ReceiptKeyError(err) => write!(f, "ReceiptKeyError: {}", err),
            Self::WitnessParseError(err) => write!(f, "WitnessParseError: {}", err),
            Self::InvalidRangeProof => write!(f, "Invalid range proof"),
            Self::ScriptMismatch => write!(
                f,
                "Mismatch of provided script and the script in the witness"
            ),
            Self::PublicKeyMismatch => write!(
                f,
                "The public key in the witness does not match the public key in the script"
            ),
            Self::TokenAmountMismatch => {
                write!(f, "TokenAmount doesn't match the proof and commitment")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for BulletproofError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ReceiptKeyError(err) => Some(err),
            Self::WitnessParseError(err) => Some(err),
            Self::InvalidRangeProof => None,
            Self::PublicKeyMismatch => None,
            Self::ScriptMismatch => None,
            Self::TokenAmountMismatch => None,
        }
    }
}
