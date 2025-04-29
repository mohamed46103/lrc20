use lrc20_receipts::{ReceiptProof, ReceiptProofError};

/// Errors that can occur during the transaction checking.
#[derive(thiserror::Error, Debug)]
pub enum CheckError {
    /// Proof provided to transaction is not valid.
    #[error("Invalid proof {proof:?} for {vout}: {error}")]
    InvalidProof {
        /// Proof that is not valid.
        ///
        /// `Box` is used here to reduce size of the enum.
        proof: Box<ReceiptProof>,
        /// Number of output in the transaction.
        vout: u32,
        /// Error that occurred during transaction checking.
        error: ReceiptProofError,
    },

    #[error("Number of receipt proofs must be the same as the number of Bitcoin outputs")]
    NotEnoughProofs { provided: usize, required: usize },

    /// Input and/or output proofs has different token_pubkey.
    #[error("TokenPubkey of proofs is not the same")]
    NotSameTokenPubkey,

    /// Sum of inputs is not equal to sum of outputs.
    #[error("Sum of inputs is not equal to sum of outputs")]
    ConservationRulesViolated,

    #[error("Input transaction not found")]
    InputNotFound,

    /// Proof mapped to not existing input or outputm, which is considered as
    /// invalid proof for that transaction.
    #[error("Proof mapped to not existing input/output")]
    ProofMappedToNotExistingInputOutput,

    #[cfg(feature = "bulletproof")]
    /// Transaction has the bulletproof receipt proofs and non-bulletproof one
    #[error("Mixed bulletproofs and non-bulletproofs")]
    MixedBulletproofsAndNonBulletproofs,

    #[cfg(feature = "bulletproof")]
    #[error("Public key to verify a signature not found")]
    PublicKeyNotFound,

    #[cfg(feature = "bulletproof")]
    #[error("Message to verify a signature not found")]
    MessageKeyNotFound,

    #[cfg(feature = "bulletproof")]
    #[error("Transaction type is not bulletproof")]
    NotBulletproof,

    #[cfg(feature = "bulletproof")]
    #[error("Commitments result in an invalid public key")]
    InvalidPublicKey,

    #[error("Announced amount {0} does not match to amount in receipt proofs {1}")]
    AnnouncedAmountDoesNotMatch(u128, u128),

    #[error("Provided announcement mismatch with the announcement in transaction")]
    IssueAnnouncementMismatch,

    #[error("Provided transaction doesn't have an announcement")]
    IssueAnnouncementNotProvided,

    #[error("Trying to spend from the burn address")]
    BurntTokensSpending,

    #[error("Sum of amounts overflow")]
    AmountsSumOverflow,

    // TODO: move p2tr proof check to isolated checks and use CheckError::InvalidProof
    // instead of this error.
    #[error("P2TR proof is invalid")]
    InvalidP2TRProof,

    #[error("Script type mismatch")]
    ScriptTypeMismatch,

    #[error("ScriptPubKey not found in the previous output")]
    ScriptPubKeyNotFound,

    #[error("Public key tweaking result is an invalid receipt key")]
    InvalidReceiptKey,

    #[error("P2TR address in new owner script")]
    NewOwnerP2TRAddress,

    #[error("Invalid deposit amount. Should be greater than 0")]
    ZeroAmount,
}
