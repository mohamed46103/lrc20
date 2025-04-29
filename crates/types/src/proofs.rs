use alloc::collections::BTreeMap;
use lrc20_receipts::ReceiptProof;

/// Contains proofs for inputs or outputs of the LRC20 Transaction.
///
/// Maps inputs or outputs ids to [`ReceiptProof`]s.
pub type ProofMap = BTreeMap<u32, ReceiptProof>;

/// Contains proofs for inputs and outputs of the LRC20 Transaction.
#[derive(Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TransferProofs {
    #[cfg_attr(feature = "serde", serde(default))]
    pub input: ProofMap,
    pub output: ProofMap,
}

/// Checks if any of the proofs is bulletproof.
#[cfg(feature = "bulletproof")]
pub fn is_bulletproof<'a>(proofs: impl IntoIterator<Item = &'a ReceiptProof>) -> bool {
    proofs
        .into_iter()
        .any(|receipt_proof| receipt_proof.is_bulletproof())
}
