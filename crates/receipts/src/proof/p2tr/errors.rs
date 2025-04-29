use crate::ReceiptKeyError;
use alloc::fmt;

#[derive(Debug)]
pub enum TaprootProofError {
    /// Error related to tweaking the public key
    ReceiptKeyError(ReceiptKeyError),

    /// Provided and expected script pubkeys mismatch
    ScriptPubKeyMismatch,

    /// Mismatch of public keys in witness and provided public key.
    PublicKeyMismatch,

    /// Invalid metadata
    InvalidMetadata,

    /// Metadata bytes length is greater than [METADATA_MAX_SIZE]
    MetadataBytesOverflow,
}

impl fmt::Display for TaprootProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TaprootProofError::ReceiptKeyError(e) => {
                write!(f, "Failed to create receipt key: {}", e)
            }
            TaprootProofError::ScriptPubKeyMismatch => write!(f, "Script pubkey mismatch"),
            TaprootProofError::PublicKeyMismatch => write!(f, "Public key mismatch"),
            TaprootProofError::InvalidMetadata => write!(f, "Failed to parse metadata"),
            TaprootProofError::MetadataBytesOverflow => write!(f, "Metadata is too large"),
        }
    }
}

#[cfg(not(feature = "no-std"))]
impl std::error::Error for TaprootProofError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TaprootProofError::ReceiptKeyError(e) => Some(e),
            TaprootProofError::ScriptPubKeyMismatch => None,
            TaprootProofError::PublicKeyMismatch => None,
            TaprootProofError::InvalidMetadata => None,
            TaprootProofError::MetadataBytesOverflow => None,
        }
    }
}

impl From<ReceiptKeyError> for TaprootProofError {
    fn from(err: ReceiptKeyError) -> Self {
        TaprootProofError::ReceiptKeyError(err)
    }
}
