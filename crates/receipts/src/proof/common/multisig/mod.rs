//! Implementation of Multisig proof which can be converted into P2WSH proof.

use alloc::vec::Vec;
use bitcoin::ecdsa::Signature;
use bitcoin::secp256k1::PublicKey;
use bitcoin::{ScriptBuf, TxIn, TxOut, secp256k1};

use crate::proof::p2wsh::P2WSHProof;
use crate::{CheckableProof, Receipt, ReceiptKey};

use self::errors::MultisigReceiptProofError;
use self::script::MultisigScript;
use self::witness::MultisigWitness;

#[cfg(feature = "consensus")]
pub mod consensus;
pub mod errors;
pub mod script;
pub mod witness;

/// Receipt proof for multisignature transaction that uses P2WSH script.
///
/// The main difference from normal multisignature transaction that it uses
/// tweaked with receipt public key as firstr key. The order of the is defined
/// lexigraphically.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MultisigReceiptProof {
    /// Receipt for the first tweaked key.
    pub receipt: Receipt,

    /// Public keys that participate in the transaction.
    pub inner_keys: Vec<secp256k1::PublicKey>,

    /// Number of required signatures.
    pub m: u8,
}

impl CheckableProof for MultisigReceiptProof {
    type Error = MultisigReceiptProofError;

    /// Check proof, as it's was provided for the Bitcoin transaction input, by
    /// parsed from witness (or script) values.
    fn checked_check_by_input(&self, txin: &TxIn) -> Result<(), Self::Error> {
        let data = MultisigWitness::from_witness(&txin.witness)?;

        self.check_by_parsed_witness_data(&data.stack.0, &data.redeem_script)?;

        Ok(())
    }

    /// Check by proof by transaction output by comparing expected and got `script_pubkey`.
    fn checked_check_by_output(&self, txout: &TxOut) -> Result<(), MultisigReceiptProofError> {
        let expected_redeem_script = self.create_multisig_redeem_script()?;

        if txout.script_pubkey != expected_redeem_script.to_p2wsh() {
            return Err(MultisigReceiptProofError::RedeemScriptMismatch);
        }

        Ok(())
    }
}

impl MultisigReceiptProof {
    pub fn new(
        receipt: impl Into<Receipt>,
        mut inner_keys: Vec<secp256k1::PublicKey>,
        m: u8,
    ) -> Self {
        // Sort public keys lexigraphically
        inner_keys.sort();

        Self {
            receipt: receipt.into(),
            inner_keys,
            m,
        }
    }

    /// From known public keys of participants create `reedem_script` and check
    /// that it's equal to the script that was provided in the transaction. Also
    /// check that the number of signatures is correct.
    pub(crate) fn check_by_parsed_witness_data(
        &self,
        signatures: &[Signature],
        redeem_script: &ScriptBuf,
    ) -> Result<(), MultisigReceiptProofError> {
        // Number of provided signatures must be equal to number of participants.
        if signatures.len() != self.m as usize {
            return Err(MultisigReceiptProofError::InvalidNumberOfSignatures(
                signatures.len(),
                self.m as usize,
            ));
        }

        let expected_script = self.create_multisig_redeem_script()?;

        // Redeem script in transaction is not equal to expected one.
        if expected_script != *redeem_script {
            return Err(MultisigReceiptProofError::RedeemScriptMismatch);
        }

        // TODO(Velnbur): check signatures.

        Ok(())
    }

    /// Return copy of inner keys sorted lexigraphically with first key tweaked.
    pub(crate) fn sort_and_tweak_keys(&self) -> Result<Vec<PublicKey>, MultisigReceiptProofError> {
        let mut keys = self.inner_keys.clone();

        keys.sort();

        let Some(first_key) = keys.first() else {
            return Err(MultisigReceiptProofError::InvalidNumberOfInnerKeys(0, 1));
        };

        let receipt_key = ReceiptKey::new(self.receipt, first_key)?;

        // Replace first key with tweaked one.
        keys[0] = *receipt_key;

        Ok(keys)
    }

    /// Tweak first key from proof and create multisig redeem script from it and
    /// other keys.
    pub(crate) fn create_multisig_redeem_script(
        &self,
    ) -> Result<ScriptBuf, MultisigReceiptProofError> {
        let keys = self.sort_and_tweak_keys()?;

        Ok(MultisigScript::new(self.m, keys).to_script())
    }

    pub fn to_script_pubkey(&self) -> Result<ScriptBuf, MultisigReceiptProofError> {
        self.create_multisig_redeem_script()
            .map(|script| script.to_p2wsh())
    }

    pub fn to_reedem_script(&self) -> Result<ScriptBuf, MultisigReceiptProofError> {
        self.create_multisig_redeem_script()
    }
}

impl TryFrom<MultisigReceiptProof> for P2WSHProof {
    type Error = MultisigReceiptProofError;

    fn try_from(proof: MultisigReceiptProof) -> Result<Self, Self::Error> {
        let keys = proof.sort_and_tweak_keys()?;

        let first = keys
            .first()
            .ok_or(MultisigReceiptProofError::InvalidNumberOfInnerKeys(0, 1))?;

        Ok(P2WSHProof::new(
            proof.receipt,
            *first,
            proof.to_reedem_script()?,
        ))
    }
}
