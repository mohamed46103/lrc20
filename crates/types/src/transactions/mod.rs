use bitcoin::Transaction;

use crate::ProofMap;
use crate::announcements::{Announcement, IssueAnnouncement};

#[cfg(feature = "consensus")]
pub mod consensus;

#[cfg(feature = "bulletproof")]
use crate::is_bulletproof;

/// Represents entries of the LRC20 transaction inside the node's storage and
/// P2P communication inventory
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Lrc20Transaction {
    pub bitcoin_tx: Transaction,
    pub tx_type: Lrc20TxType,
}

impl Lrc20Transaction {
    /// Create a new LRC20 transaction.
    pub fn new(bitcoin_tx: Transaction, tx_type: Lrc20TxType) -> Self {
        Self {
            bitcoin_tx,
            tx_type,
        }
    }

    /// Checks if the transaction is bulletproof.
    ///
    /// Returns `true` if it is a bulletproof transaction, `false` otherwise.
    #[cfg(feature = "bulletproof")]
    pub fn is_bulletproof(&self) -> bool {
        match self.tx_type.output_proofs() {
            Some(proofs) => is_bulletproof(proofs.values()),
            None => false,
        }
    }

    /// Checks if the transaction is burning tokens.
    ///
    /// Returns `true` if it is a burn transaction, `false` otherwise.
    pub fn is_burn(&self) -> bool {
        let Some(output_proofs) = self.tx_type.output_proofs() else {
            return false;
        };

        for proof in output_proofs.values() {
            if proof.is_burn() {
                return true;
            }
        }

        false
    }

    /// Checks if the transaction is a spark exit transaction.
    ///
    /// Returns `true` if it is a spark exit transaction, `false` otherwise.
    pub fn is_spark_exit(&self) -> bool {
        matches!(self.tx_type, Lrc20TxType::SparkExit { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "type", content = "data"))]
pub enum Lrc20TxType {
    Issue {
        output_proofs: Option<ProofMap>,
        announcement: IssueAnnouncement,
    },
    Transfer {
        input_proofs: ProofMap,
        output_proofs: ProofMap,
    },
    Announcement(Announcement),
    SparkExit {
        output_proofs: ProofMap,
    },
}

impl Lrc20TxType {
    /// Return output proofs if possible
    pub fn output_proofs(&self) -> Option<&ProofMap> {
        match self {
            Self::Issue { output_proofs, .. } => output_proofs.as_ref(),
            Self::Transfer { output_proofs, .. } => Some(output_proofs),
            Self::SparkExit { output_proofs } => Some(output_proofs),
            _ => None,
        }
    }

    /// Return input proofs if possible
    pub fn input_proofs(&self) -> Option<&ProofMap> {
        match self {
            Self::Transfer { input_proofs, .. } => Some(input_proofs),
            _ => None,
        }
    }
}

impl Default for Lrc20TxType {
    fn default() -> Self {
        Self::Transfer {
            output_proofs: Default::default(),
            input_proofs: Default::default(),
        }
    }
}

impl From<Announcement> for Lrc20TxType {
    fn from(value: Announcement) -> Self {
        Self::Announcement(value)
    }
}
