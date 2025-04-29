use self::{errors::P2WPKHProofError, witness::P2WPKHWitness};
use crate::metadata::check_metadata_size;
use crate::{CheckableProof, Receipt, ReceiptHash, ReceiptKey, ReceiptKeyError};
use bitcoin::{TxIn, TxOut, ecdsa::Signature, secp256k1::PublicKey};
use serde_json::Value;

#[cfg(feature = "consensus")]
pub mod consensus;
pub mod errors;
pub mod witness;

pub type SigReceiptProof = P2WPKHProof;

/// The proof of ownership with single signature.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct P2WPKHProof {
    /// Receipt that proof verifies.
    pub receipt: Receipt,
    /// Key of current owner of the receipt.
    pub inner_key: PublicKey,
    /// Optional metadata
    pub metadata: Option<Value>,
}

impl P2WPKHProof {
    pub fn empty(pubkey: impl Into<PublicKey>) -> Self {
        Self::new(Receipt::empty(), pubkey.into(), None)
    }

    pub const fn new(receipt: Receipt, inner_key: PublicKey, metadata: Option<Value>) -> Self {
        Self {
            receipt,
            inner_key,
            metadata,
        }
    }

    /// Check proof by parsed witness data.
    pub(crate) fn check_by_parsed_witness_data(
        &self,
        _signature: &Signature,
        pubkey: &PublicKey,
    ) -> Result<(), P2WPKHProofError> {
        let pxh: ReceiptHash = self.try_into().map_err(ReceiptKeyError::from)?;
        let receipt_key = ReceiptKey::new(pxh, &self.inner_key)?;

        if *receipt_key != *pubkey {
            return Err(P2WPKHProofError::PublicKeyMismatch);
        }

        // TODO(Velnbur): verify signature.

        Ok(())
    }
}

impl CheckableProof for P2WPKHProof {
    type Error = P2WPKHProofError;

    /// Get from input witness signature and public key and check that public
    /// key is equal to the tweaked one from proof.
    fn checked_check_by_input(&self, txin: &TxIn) -> Result<(), Self::Error> {
        let data = P2WPKHWitness::from_witness(&txin.witness)?;

        self.check_by_parsed_witness_data(&data.signature, &data.pubkey)?;

        Ok(())
    }

    /// Get from transaction output `script_pubkey` and create P2WPKH script
    /// from tweaked public key from proof and compare it with `script_pubkey`.
    ///
    /// # Errors
    ///
    /// To prevent history mismatch between nodes, we prevent users from creating
    /// a proof with zero value (empty) and tweaked by zero key receipt, that's why
    /// in this situation this method returns an error.
    fn checked_check_by_output(&self, txout: &TxOut) -> Result<(), Self::Error> {
        if self.receipt == Receipt::empty() {
            return Err(P2WPKHProofError::EmptyReceiptUsage);
        }

        let pxh: ReceiptHash = self.try_into().map_err(ReceiptKeyError::from)?;
        let receipt_key = ReceiptKey::new(pxh, &self.inner_key)?;

        let expected_script_pubkey = receipt_key
            .to_p2wpkh()
            .ok_or(ReceiptKeyError::UncompressedKey)?;

        if txout.script_pubkey != expected_script_pubkey {
            return Err(P2WPKHProofError::ScriptPubKeyMismatch);
        }

        if !check_metadata_size(&self.metadata).map_err(|_| P2WPKHProofError::InvalidMetadata)? {
            return Err(P2WPKHProofError::MetadataBytesOverflow);
        }

        Ok(())
    }
}
