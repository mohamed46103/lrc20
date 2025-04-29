use bitcoin::{TxIn, TxOut, secp256k1};

use crate::{CheckableProof, P2WPKHWitness, Receipt, ReceiptKey, ReceiptKeyError, ReceiptProof};

use super::p2wpkh::errors::P2WPKHProofError;
#[cfg(feature = "consensus")]
pub mod consensus;

/// The proof of ownership of the change output.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EmptyReceiptProof {
    /// Key of current owner of the receipt.
    pub inner_key: secp256k1::PublicKey,
}

impl EmptyReceiptProof {
    pub fn new(inner_key: secp256k1::PublicKey) -> Self {
        Self { inner_key }
    }

    pub(crate) fn check_by_parsed_witness_data(
        &self,
        pubkey: &secp256k1::PublicKey,
    ) -> Result<(), P2WPKHProofError> {
        let receipt_key = ReceiptKey::new(Receipt::empty(), &self.inner_key)?;

        if *receipt_key != *pubkey {
            return Err(P2WPKHProofError::PublicKeyMismatch);
        }

        Ok(())
    }
}

impl From<EmptyReceiptProof> for ReceiptProof {
    fn from(value: EmptyReceiptProof) -> Self {
        Self::EmptyReceipt(value)
    }
}

impl CheckableProof for EmptyReceiptProof {
    type Error = P2WPKHProofError;

    /// Get from input witness signature and public key and check that public
    /// key is equal to the tweaked one from proof.
    fn checked_check_by_input(&self, txin: &TxIn) -> Result<(), Self::Error> {
        let data = P2WPKHWitness::from_witness(&txin.witness)?;

        self.check_by_parsed_witness_data(&data.pubkey)?;

        Ok(())
    }

    /// Get from transaction output `script_pubkey` and create P2WPKH script
    /// from tweaked public key from proof and compare it with `script_pubkey`.
    fn checked_check_by_output(&self, txout: &TxOut) -> Result<(), Self::Error> {
        let receipt_key = ReceiptKey::new(Receipt::empty(), &self.inner_key)?;

        let expected_script_pubkey = receipt_key
            .to_p2wpkh()
            .ok_or(ReceiptKeyError::UncompressedKey)?;

        if txout.script_pubkey != expected_script_pubkey {
            return Err(P2WPKHProofError::ScriptPubKeyMismatch);
        }

        Ok(())
    }
}
