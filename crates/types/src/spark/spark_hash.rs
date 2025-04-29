use core::fmt::{Display, Formatter};
use core::ops::Deref;

use bitcoin::hashes::{FromSliceError, Hash, HashEngine, sha256::Hash as Sha256Hash};

use super::{TokenLeafOutput, TokenLeafToSpend, TokenTransaction};

/// A hash of the LRC20 receipt data that uniquely identifies a receipt (coin).
///
/// Defined as: `PXH = hash(hash(Y) || UV)`, where `Y` - is token_amount (amount),
/// and `UV` - is token type (issuer public key).
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SparkHash(pub Sha256Hash);

impl Deref for SparkHash {
    type Target = Sha256Hash;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for SparkHash {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        let hash = self.0;
        write!(f, "{hash}")
    }
}

impl From<Sha256Hash> for SparkHash {
    fn from(hash: Sha256Hash) -> Self {
        Self(hash)
    }
}

impl SparkHash {
    pub fn hash_token_transaction(token_tx: &TokenTransaction, is_partial_hash: bool) -> Self {
        let mut hash_engine = Sha256Hash::engine();

        // Hash inputs
        match &token_tx.input {
            super::TokenTransactionInput::Transfer { outputs_to_spend } => {
                for output in outputs_to_spend {
                    hash_engine.input(
                        SparkHash::hash_token_leaf_to_spend(output)
                            .0
                            .as_byte_array(),
                    );
                }
            }
            super::TokenTransactionInput::Mint {
                issuer_public_key,
                issuer_provided_timestamp,
                ..
            } => {
                let mut mint_hash_engine = Sha256Hash::engine();
                mint_hash_engine.input(&issuer_public_key.serialize());
                mint_hash_engine.input(&(*issuer_provided_timestamp).to_le_bytes());
                hash_engine.input(Sha256Hash::from_engine(mint_hash_engine).as_byte_array());
            }
        }

        // Hash output leaves
        for output in &token_tx.leaves_to_create {
            hash_engine.input(
                SparkHash::hash_token_leaf_output(output, is_partial_hash)
                    .0
                    .as_byte_array(),
            );
        }

        let mut so_pubkeys = token_tx.spark_operator_identity_public_keys.clone();
        so_pubkeys.sort();
        // Hash spark operator identity public keys
        for key in &so_pubkeys {
            hash_engine.input(Sha256Hash::hash(&key.serialize()).as_byte_array());
        }

        if let Some(network) = token_tx.network {
            hash_engine.input(Sha256Hash::hash(&network.to_be_bytes()).as_byte_array());
        }

        Self(Sha256Hash::from_engine(hash_engine))
    }

    pub fn hash_token_leaf_to_spend(leaf: &TokenLeafToSpend) -> Self {
        let mut hash_engine = Sha256Hash::engine();

        hash_engine.input(leaf.parent_output_hash.as_byte_array());
        hash_engine.input(&leaf.parent_output_vout.to_be_bytes());

        Self(Sha256Hash::from_engine(hash_engine))
    }

    pub fn hash_token_leaf_output(leaf: &TokenLeafOutput, is_partial_hash: bool) -> Self {
        let mut hash_engine = Sha256Hash::engine();

        if !is_partial_hash {
            hash_engine.input(leaf.id.as_bytes());
        }
        hash_engine.input(&leaf.owner_public_key.serialize());
        if !is_partial_hash {
            hash_engine.input(&leaf.revocation_public_key.serialize());
            hash_engine.input(&leaf.withdrawal_bond_sats.to_be_bytes());
            hash_engine.input(&(leaf.withdrawal_locktime.to_consensus_u32() as u64).to_be_bytes());
        }
        hash_engine.input(&leaf.receipt.token_pubkey.to_bytes());
        hash_engine.input(&leaf.receipt.token_amount.amount.to_be_bytes());

        Self(Sha256Hash::from_engine(hash_engine))
    }
}

impl From<&TokenTransaction> for SparkHash {
    fn from(token_tx: &TokenTransaction) -> Self {
        Self::hash_token_transaction(token_tx, false)
    }
}

impl TryFrom<&[u8]> for SparkHash {
    type Error = FromSliceError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let hash = Sha256Hash::from_slice(bytes)?;

        Ok(Self(hash))
    }
}

#[cfg(test)]
mod test {
    use alloc::vec;
    use core::str::FromStr;

    use bitcoin::{
        hashes::sha256::Hash,
        secp256k1::{self},
    };
    use lrc20_receipts::{Receipt, TokenPubkey};
    use once_cell::sync::Lazy;

    use crate::spark::{
        TokenLeafOutput, TokenLeafToSpend, TokenTransaction, TokenTransactionInput,
    };

    use super::SparkHash;

    static PUBKEY: Lazy<secp256k1::PublicKey> = Lazy::new(|| {
        secp256k1::PublicKey::from_str(
            "0339e911f5985821c0061401b1d57cc2340822ec2e17b91b0c54c9f2b8b1cbd72a",
        )
        .unwrap()
    });

    #[test]
    fn test_issue_token_tx_hash() {
        let token_tx = TokenTransaction {
            input: TokenTransactionInput::Mint {
                issuer_public_key: *PUBKEY,
                issuer_signature: None,
                issuer_provided_timestamp: 12345,
            },
            leaves_to_create: vec![
                TokenLeafOutput {
                    id: "test-leaf".into(),
                    owner_public_key: *PUBKEY,
                    revocation_public_key: *PUBKEY,
                    withdrawal_bond_sats: 10000,
                    withdrawal_locktime: bitcoin::absolute::LockTime::from_height(1000).unwrap(),
                    receipt: Receipt::new(11111, TokenPubkey::new(*PUBKEY)),
                    is_frozen: Some(false),
                    withdraw_height: None,
                    withdraw_txid: None,
                    withdraw_tx_vout: None,
                    withdraw_block_hash: None,
                },
                TokenLeafOutput {
                    id: "test-leaf".into(),
                    owner_public_key: *PUBKEY,
                    revocation_public_key: *PUBKEY,
                    withdrawal_bond_sats: 10000,
                    withdrawal_locktime: bitcoin::absolute::LockTime::from_height(1000).unwrap(),
                    receipt: Receipt::new(11111, TokenPubkey::new(*PUBKEY)),
                    is_frozen: Some(false),
                    withdraw_height: None,
                    withdraw_txid: None,
                    withdraw_tx_vout: None,
                    withdraw_block_hash: None,
                },
            ],
            spark_operator_identity_public_keys: vec![*PUBKEY],
            network: Some(1),
        };

        let spark_hash = SparkHash::from(&token_tx);

        assert_eq!(
            spark_hash.0,
            Hash::from_str("2092b68ac7f9bd77e7e8335dbd0d39855ea3f836102ff70522f5a3e87ab1dd69")
                .unwrap()
        );
    }

    #[test]
    fn test_transfer_token_tx_hash() {
        let token_tx = TokenTransaction {
            input: TokenTransactionInput::Transfer {
                outputs_to_spend: vec![
                    TokenLeafToSpend {
                        parent_output_hash: Hash::from_str(
                            "60c3d19464506ed3d57162a01cb086f367ce26deba0dbd77d00dc7453c4d2357",
                        )
                        .unwrap(),
                        parent_output_vout: 1,
                    },
                    TokenLeafToSpend {
                        parent_output_hash: Hash::from_str(
                            "60c3d19464506ed3d57162a01cb086f367ce26deba0dbd77d00dc7453c4d2357",
                        )
                        .unwrap(),
                        parent_output_vout: 1,
                    },
                ],
            },
            leaves_to_create: vec![
                TokenLeafOutput {
                    id: "test-leaf".into(),
                    owner_public_key: *PUBKEY,
                    revocation_public_key: *PUBKEY,
                    withdrawal_bond_sats: 10000,
                    withdrawal_locktime: bitcoin::absolute::LockTime::from_height(1000).unwrap(),
                    receipt: Receipt::new(11111, TokenPubkey::new(*PUBKEY)),
                    is_frozen: Some(false),
                    withdraw_height: None,
                    withdraw_txid: None,
                    withdraw_tx_vout: None,
                    withdraw_block_hash: None,
                },
                TokenLeafOutput {
                    id: "test-leaf".into(),
                    owner_public_key: *PUBKEY,
                    revocation_public_key: *PUBKEY,
                    withdrawal_bond_sats: 10000,
                    withdrawal_locktime: bitcoin::absolute::LockTime::from_height(1000).unwrap(),
                    receipt: Receipt::new(11111, TokenPubkey::new(*PUBKEY)),
                    is_frozen: Some(false),
                    withdraw_height: None,
                    withdraw_txid: None,
                    withdraw_tx_vout: None,
                    withdraw_block_hash: None,
                },
            ],
            spark_operator_identity_public_keys: vec![*PUBKEY],
            network: Some(1),
        };

        let spark_hash = SparkHash::from(&token_tx);

        assert_eq!(
            spark_hash.0,
            Hash::from_str("9ca63f46181a7aaffd6e889f615bff17c8926d0aeb6b11428bea050ea20b601d")
                .unwrap()
        );
    }
}
