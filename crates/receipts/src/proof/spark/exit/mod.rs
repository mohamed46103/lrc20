pub mod errors;

pub mod witness;

#[cfg(feature = "consensus")]
pub mod consensus;

use bitcoin::{
    ScriptBuf,
    absolute::LockTime,
    hashes::sha256::Hash,
    key::Secp256k1,
    opcodes,
    script::Builder,
    secp256k1::PublicKey,
    taproot::{TaprootBuilder, TaprootSpendInfo},
};
use errors::SparkExitProofError;
use serde_json::Value;

use crate::{CheckableProof, Receipt, ReceiptKey};

/// The proof of ownership of a Spark exit tx.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SparkExitProof {
    pub receipt: Receipt,

    pub script: SparkExitScript,

    /// Optional metadata
    pub metadata: Option<Value>,
}

/// The proof of ownership with single signature.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SparkExitScript {
    /// Revocation key that can spend the output anytime using the key spend way.
    pub revocation_key: PublicKey,
    /// Delay key that can spend the output only after specific block height using the script path
    /// way.
    pub delay_key: PublicKey,
    /// Absoulte locktime (height).
    pub locktime: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SparkExitMetadata {
    pub token_tx_hash: Hash,
    pub exit_leaf_index: u32,
}

impl SparkExitScript {
    pub fn new(revocation_key: PublicKey, locktime: u32, delay_key: PublicKey) -> Self {
        Self {
            revocation_key,
            delay_key,
            locktime,
        }
    }

    pub fn timelock_script(&self, receipt: Receipt) -> Result<ScriptBuf, SparkExitProofError> {
        let receipt_key = ReceiptKey::new(receipt, &self.delay_key)?;
        let script = Builder::new()
            .push_lock_time(LockTime::from_height(self.locktime)?)
            .push_opcode(opcodes::all::OP_CLTV)
            .push_opcode(opcodes::all::OP_DROP)
            .push_x_only_key(&receipt_key.x_only_public_key().0)
            .push_opcode(opcodes::all::OP_CHECKSIG)
            .into_script();

        Ok(script)
    }
}

impl SparkExitProof {
    pub fn new(receipt: Receipt, script: SparkExitScript, metadata: Option<Value>) -> Self {
        Self {
            receipt,
            script,
            metadata,
        }
    }

    pub fn tap_spend_info(&self) -> Result<TaprootSpendInfo, SparkExitProofError> {
        let timelock_script = self.script.timelock_script(self.receipt)?;
        let (internal_key, _parity) = self.script.revocation_key.x_only_public_key();
        let ctx = Secp256k1::new();

        let info = TaprootBuilder::new()
            .add_leaf(0, timelock_script)?
            .finalize(&ctx, internal_key)
            .map_err(|_| SparkExitProofError::UnavailableTapSpendInfo)?;

        Ok(info)
    }
}

impl CheckableProof for SparkExitProof {
    type Error = SparkExitProofError;

    fn checked_check_by_input(&self, _txin: &bitcoin::TxIn) -> Result<(), Self::Error> {
        Ok(())
    }

    fn checked_check_by_output(&self, txout: &bitcoin::TxOut) -> Result<(), Self::Error> {
        let tap_spend_info = self.tap_spend_info()?;
        let expected_script = ScriptBuf::new_p2tr_tweaked(tap_spend_info.output_key());

        if expected_script != txout.script_pubkey {
            return Err(SparkExitProofError::ScriptPubkeyMismatch {
                expected: expected_script,
                got: txout.script_pubkey.clone(),
            });
        }

        Ok(())
    }
}
