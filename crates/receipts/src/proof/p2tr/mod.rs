use bitcoin::{ScriptBuf, TxIn, TxOut, key::Secp256k1, secp256k1::PublicKey};
use errors::TaprootProofError;
use serde_json::Value;

use super::CheckableProof;
use crate::metadata::check_metadata_size;
use crate::{Receipt, ReceiptHash, ReceiptKey, ReceiptKeyError};

#[cfg(feature = "serde")]
use crate::deserialize_public_key;

#[cfg(feature = "consensus")]
pub mod consensus;
pub mod errors;

/// The proof of ownership with Shcnorr signature.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TaprootProof {
    /// Receipt that proof verifies.
    pub receipt: Receipt,
    /// Public key of current owner of the receipt.
    #[cfg_attr(feature = "serde", serde(deserialize_with = "deserialize_public_key"))]
    pub inner_key: PublicKey,
    /// Optional metadata
    pub metadata: Option<Value>,
}

impl TaprootProof {
    pub const fn new(receipt: Receipt, inner_key: PublicKey, metadata: Option<Value>) -> Self {
        Self {
            receipt,
            inner_key,
            metadata,
        }
    }

    pub fn to_witness_script(&self) -> Result<ScriptBuf, TaprootProofError> {
        let pxh: ReceiptHash = ReceiptHash::try_from(self).map_err(ReceiptKeyError::from)?;
        let receipt_key = ReceiptKey::new(pxh, &self.inner_key)?;
        let (x_only_receipt_key, _) = receipt_key.x_only_public_key();
        Ok(ScriptBuf::new_p2tr(
            &Secp256k1::new(),
            x_only_receipt_key,
            None,
        ))
    }
}

impl CheckableProof for TaprootProof {
    type Error = TaprootProofError;

    fn checked_check_by_input(&self, _txin: &TxIn) -> Result<(), Self::Error> {
        // TODO: add isolated proof check. Currently it's not possible to do so
        // without querying the Bitcoin node.
        Ok(())
    }

    fn checked_check_by_output(&self, txout: &TxOut) -> Result<(), Self::Error> {
        let pxh: ReceiptHash = self.try_into().map_err(ReceiptKeyError::from)?;
        let receipt_key = ReceiptKey::new(pxh, &self.inner_key)?;
        let (x_only_receipt_key, _) = receipt_key.x_only_public_key();
        let expected_script_pubkey =
            ScriptBuf::new_p2tr(&Secp256k1::new(), x_only_receipt_key, None);

        if txout.script_pubkey != expected_script_pubkey {
            return Err(TaprootProofError::ScriptPubKeyMismatch);
        }

        if !check_metadata_size(&self.metadata).map_err(|_| TaprootProofError::InvalidMetadata)? {
            return Err(TaprootProofError::MetadataBytesOverflow);
        }

        Ok(())
    }
}
