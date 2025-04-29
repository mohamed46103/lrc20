use alloc::{string::String, vec::Vec};
use bitcoin::{
    BlockHash, Txid,
    absolute::LockTime,
    consensus::{Decodable, Encodable, encode::Error as EncodeError},
    hashes::sha256::Hash,
    key::constants::{PUBLIC_KEY_SIZE, SECRET_KEY_SIZE},
    secp256k1::{PublicKey, SecretKey, ecdsa, schnorr},
};
use core2::io;
use lrc20_receipts::{Receipt, TOKEN_PUBKEY_SIZE, TokenPubkey};

use super::{
    OperatorSpecificOwnerSignature, SparkSignature, TokenLeafOutput, TokenLeafToSpend,
    TokenTransaction, TokenTransactionInput, TokensFreezeData, signature::SparkSignatureData,
};
use crate::consensus::OptionWrapper;
use crate::spark::signature::SparkSignatureLeafData;

const ISSUE_INPUT_TYPE: u8 = 0u8;
const TRANSFER_INPUT_TYPE: u8 = 1u8;

const ECDSA_SIG_TYPE: u8 = 0u8;
const SCHNORR_SIG_TYPE: u8 = 1u8;

impl Encodable for SparkSignature {
    fn consensus_encode<W: io::Write + ?Sized>(&self, writer: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;

        match self {
            SparkSignature::ECDSA(signature) => {
                len += ECDSA_SIG_TYPE.consensus_encode(writer)?;
                len += signature
                    .serialize_compact()
                    .to_vec()
                    .consensus_encode(writer)?
            }
            SparkSignature::Schnorr(signature) => {
                len += SCHNORR_SIG_TYPE.consensus_encode(writer)?;
                len += signature.serialize().to_vec().consensus_encode(writer)?
            }
        }

        Ok(len)
    }
}

impl Decodable for SparkSignature {
    fn consensus_decode<R: io::Read + ?Sized>(reader: &mut R) -> Result<Self, EncodeError> {
        let sig_flag: u8 = Decodable::consensus_decode(reader)?;

        match sig_flag {
            ECDSA_SIG_TYPE => {
                let ecdsa_bytes: Vec<u8> = Decodable::consensus_decode(reader)?;

                Ok(ecdsa::Signature::from_compact(&ecdsa_bytes)
                    .map_err(|_e| {
                        EncodeError::ParseFailed("Failed to parse ECDSA signature bytes")
                    })?
                    .into())
            }
            SCHNORR_SIG_TYPE => {
                let schnorr_bytes: Vec<u8> = Decodable::consensus_decode(reader)?;

                Ok(schnorr::Signature::from_slice(&schnorr_bytes)
                    .map_err(|_e| {
                        EncodeError::ParseFailed("Failed to parse Schnorr signature bytes")
                    })?
                    .into())
            }
            _ => Err(EncodeError::ParseFailed(
                "Unsupported token transaction input",
            )),
        }
    }
}

impl Encodable for OperatorSpecificOwnerSignature {
    fn consensus_encode<W: io::Write + ?Sized>(&self, writer: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;

        len += OptionWrapper(self.operator_identity_public_key.map(|pk| pk.serialize()))
            .consensus_encode(writer)?;
        len += self.owner_signature.consensus_encode(writer)?;

        Ok(len)
    }
}

impl Decodable for OperatorSpecificOwnerSignature {
    fn consensus_decode<R: io::Read + ?Sized>(reader: &mut R) -> Result<Self, EncodeError> {
        let operator_key_bytes = OptionWrapper::<[u8; PUBLIC_KEY_SIZE]>::consensus_decode(reader)?;
        let operator_pubkey = match operator_key_bytes.0 {
            Some(operator_key_bytes) => {
                let operator_pubkey = PublicKey::from_slice(&operator_key_bytes)
                    .map_err(|_e| EncodeError::ParseFailed("Failed to parse public key bytes"))?;

                Some(operator_pubkey)
            }
            None => None,
        };
        let input_index = OptionWrapper::<u32>::consensus_decode(reader)?.0;
        let signature: SparkSignature = Decodable::consensus_decode(reader)?;

        Ok(Self::new(signature, operator_pubkey, input_index))
    }
}

impl Encodable for TokenTransaction {
    fn consensus_encode<W: io::Write + ?Sized>(&self, writer: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;

        len += (self.leaves_to_create.len() as u32).consensus_encode(writer)?;
        for leaf_to_create in &self.leaves_to_create {
            len += leaf_to_create.consensus_encode(writer)?;
        }

        match &self.input {
            super::TokenTransactionInput::Mint {
                issuer_public_key,
                issuer_signature,
                issuer_provided_timestamp,
            } => {
                len += ISSUE_INPUT_TYPE.consensus_encode(writer)?;
                len += issuer_public_key.serialize().consensus_encode(writer)?;
                len += issuer_provided_timestamp.consensus_encode(writer)?;
                len += OptionWrapper(*issuer_signature).consensus_encode(writer)?;
            }
            super::TokenTransactionInput::Transfer {
                outputs_to_spend: leaves_to_spend,
            } => {
                len += TRANSFER_INPUT_TYPE.consensus_encode(writer)?;
                len += (leaves_to_spend.len() as u32).consensus_encode(writer)?;
                for leaf_to_spend in leaves_to_spend {
                    len += leaf_to_spend.consensus_encode(writer)?;
                }
            }
        }

        len += (self.spark_operator_identity_public_keys.len() as u32).consensus_encode(writer)?;
        for operator_public_key in &self.spark_operator_identity_public_keys {
            len += operator_public_key.serialize().consensus_encode(writer)?;
        }

        len += OptionWrapper(self.network).consensus_encode(writer)?;

        Ok(len)
    }
}

impl Decodable for TokenTransaction {
    fn consensus_decode<R: io::Read + ?Sized>(reader: &mut R) -> Result<Self, EncodeError> {
        let leaves_to_create_len: u32 = Decodable::consensus_decode(reader)?;
        let mut leaves_to_create = Vec::new();

        for _ in 0..leaves_to_create_len {
            leaves_to_create.push(Decodable::consensus_decode(reader)?);
        }

        let input_type: u8 = Decodable::consensus_decode(reader)?;

        let input = match input_type {
            ISSUE_INPUT_TYPE => {
                let issuer_public_key_bytes: [u8; bitcoin::key::constants::PUBLIC_KEY_SIZE] =
                    Decodable::consensus_decode(reader)?;
                let issuer_public_key = PublicKey::from_slice(&issuer_public_key_bytes)
                    .map_err(|_e| EncodeError::ParseFailed("Failed to parse public key bytes"))?;

                let issuer_provided_timestamp: u64 = Decodable::consensus_decode(reader)?;
                let issuer_signature =
                    OptionWrapper::<OperatorSpecificOwnerSignature>::consensus_decode(reader)?;

                TokenTransactionInput::Mint {
                    issuer_public_key,
                    issuer_signature: issuer_signature.0,
                    issuer_provided_timestamp,
                }
            }
            TRANSFER_INPUT_TYPE => {
                let leaves_to_spend_len: u32 = Decodable::consensus_decode(reader)?;
                let leaves_to_spend = (0..leaves_to_spend_len)
                    .map(|_i| Decodable::consensus_decode(reader))
                    .collect::<Result<Vec<_>, EncodeError>>()?;

                TokenTransactionInput::Transfer {
                    outputs_to_spend: leaves_to_spend,
                }
            }
            _ => {
                return Err(EncodeError::ParseFailed(
                    "Unsupported token transaction input",
                ));
            }
        };

        let keys_len: u32 = Decodable::consensus_decode(reader)?;
        let spark_operator_identity_public_keys = (0..keys_len)
            .map(|_| {
                let public_key_bytes: [u8; bitcoin::key::constants::PUBLIC_KEY_SIZE] =
                    Decodable::consensus_decode(reader)?;

                PublicKey::from_slice(&public_key_bytes)
                    .map_err(|_e| EncodeError::ParseFailed("Failed to parse public key bytes"))
            })
            .collect::<Result<Vec<_>, EncodeError>>()?;

        let network = OptionWrapper::<u32>::consensus_decode(reader)?.0;

        Ok(TokenTransaction {
            input,
            leaves_to_create,
            spark_operator_identity_public_keys,
            network,
        })
    }
}

impl Encodable for TokenLeafToSpend {
    fn consensus_encode<W: io::Write + ?Sized>(&self, writer: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;

        len += self.parent_output_hash.consensus_encode(writer)?;
        len += self.parent_output_vout.consensus_encode(writer)?;

        Ok(len)
    }
}

impl Decodable for TokenLeafToSpend {
    fn consensus_decode<R: io::Read + ?Sized>(reader: &mut R) -> Result<Self, EncodeError> {
        let parent_leaf_hash: Hash = Decodable::consensus_decode(reader)?;
        let parent_leaf_index: u32 = Decodable::consensus_decode(reader)?;

        Ok(TokenLeafToSpend {
            parent_output_hash: parent_leaf_hash,
            parent_output_vout: parent_leaf_index,
        })
    }
}

impl Encodable for TokenLeafOutput {
    fn consensus_encode<W: io::Write + ?Sized>(&self, writer: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;

        len += self.id.clone().into_bytes().consensus_encode(writer)?;
        len += self.owner_public_key.serialize().consensus_encode(writer)?;
        len += self.receipt.consensus_encode(writer)?;
        len += self
            .revocation_public_key
            .serialize()
            .consensus_encode(writer)?;

        len += self.withdrawal_bond_sats.consensus_encode(writer)?;
        len += self.withdrawal_locktime.consensus_encode(writer)?;
        len += OptionWrapper(self.is_frozen).consensus_encode(writer)?;
        len += OptionWrapper(self.withdraw_txid).consensus_encode(writer)?;
        len += OptionWrapper(self.withdraw_tx_vout).consensus_encode(writer)?;
        len += OptionWrapper(self.withdraw_height).consensus_encode(writer)?;
        len += OptionWrapper(self.withdraw_block_hash).consensus_encode(writer)?;

        Ok(len)
    }
}

impl Decodable for TokenLeafOutput {
    fn consensus_decode<R: io::Read + ?Sized>(reader: &mut R) -> Result<Self, EncodeError> {
        let id_bytes: Vec<u8> = Decodable::consensus_decode(reader)?;
        let id = String::from_utf8(id_bytes)
            .map_err(|_e| EncodeError::ParseFailed("Failed to parse id bytes"))?;
        let owner_public_key: [u8; PUBLIC_KEY_SIZE] = Decodable::consensus_decode(reader)?;
        let owner_public_key = PublicKey::from_slice(&owner_public_key).map_err(|_e| {
            EncodeError::ParseFailed("Failed to parse owner signing public key bytes")
        })?;
        let receipt: Receipt = Decodable::consensus_decode(reader)?;
        let revocation_public_key_bytes: [u8; PUBLIC_KEY_SIZE] =
            Decodable::consensus_decode(reader)?;
        let revocation_public_key =
            PublicKey::from_slice(&revocation_public_key_bytes).map_err(|_e| {
                EncodeError::ParseFailed("Failed to parse revocation public key bytes")
            })?;

        let withdrawal_bond_sats: u64 = Decodable::consensus_decode(reader)?;
        let withdrawal_locktime: LockTime = Decodable::consensus_decode(reader)?;
        let is_frozen: OptionWrapper<bool> = Decodable::consensus_decode(reader)?;
        let withdraw_txid: OptionWrapper<Txid> = Decodable::consensus_decode(reader)?;
        let withdraw_tx_vout: OptionWrapper<u32> = Decodable::consensus_decode(reader)?;
        let withdraw_height: OptionWrapper<u32> = Decodable::consensus_decode(reader)?;
        let withdraw_block_hash: OptionWrapper<BlockHash> = Decodable::consensus_decode(reader)?;

        Ok(TokenLeafOutput {
            id,
            owner_public_key,
            revocation_public_key,
            withdrawal_bond_sats,
            withdrawal_locktime,
            receipt,
            is_frozen: is_frozen.0,
            withdraw_txid: withdraw_txid.0,
            withdraw_tx_vout: withdraw_tx_vout.0,
            withdraw_height: withdraw_height.0,
            withdraw_block_hash: withdraw_block_hash.0,
        })
    }
}

impl Encodable for SparkSignatureData {
    fn consensus_encode<W: io::Write + ?Sized>(&self, writer: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;

        len += self.token_tx_hash.consensus_encode(writer)?;
        len += self.operator_pubkey.serialize().consensus_encode(writer)?;
        len += self.operator_signature.consensus_encode(writer)?;
        len += OptionWrapper(self.operator_specific_owner_signature).consensus_encode(writer)?;
        len += (self.outputs_to_spend_data.len() as u32).consensus_encode(writer)?;
        for data in &self.outputs_to_spend_data {
            len += data.token_tx_leaf_index.consensus_encode(writer)?;
            len += OptionWrapper(data.revocation_secret.map(|key| key.secret_bytes()))
                .consensus_encode(writer)?;
        }

        Ok(len)
    }
}

impl Decodable for SparkSignatureData {
    fn consensus_decode<R: io::Read + ?Sized>(reader: &mut R) -> Result<Self, EncodeError> {
        let token_tx_hash: Hash = Decodable::consensus_decode(reader)?;

        let operator_pubkey_bytes: [u8; PUBLIC_KEY_SIZE] = Decodable::consensus_decode(reader)?;
        let operator_pubkey = PublicKey::from_slice(&operator_pubkey_bytes)
            .map_err(|_e| EncodeError::ParseFailed("Failed to parse operator public key bytes"))?;
        let operator_signature = Decodable::consensus_decode(reader)?;

        let operator_specific_data: OptionWrapper<OperatorSpecificOwnerSignature> =
            Decodable::consensus_decode(reader)?;

        let leaf_data_len: u32 = Decodable::consensus_decode(reader)?;

        let mut leaves_to_spend_data = Vec::new();
        for _ in 0..leaf_data_len {
            let token_tx_leaf_index: u32 = Decodable::consensus_decode(reader)?;
            let revocation_private_key: OptionWrapper<[u8; SECRET_KEY_SIZE]> =
                Decodable::consensus_decode(reader)?;

            leaves_to_spend_data.push(SparkSignatureLeafData {
                token_tx_leaf_index,
                revocation_secret: revocation_private_key
                    .0
                    .and_then(|key_bytes| SecretKey::from_slice(&key_bytes).ok()),
            })
        }

        Ok(SparkSignatureData {
            token_tx_hash: token_tx_hash.into(),
            operator_specific_owner_signature: operator_specific_data.0,
            operator_pubkey,
            operator_signature,
            outputs_to_spend_data: leaves_to_spend_data,
        })
    }
}

impl Encodable for TokensFreezeData {
    fn consensus_encode<W: io::Write + ?Sized>(&self, writer: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;

        len += self.issuer_signature.consensus_encode(writer)?;
        len += self.owner_public_key.serialize().consensus_encode(writer)?;
        len += self
            .operator_identity_public_key
            .serialize()
            .consensus_encode(writer)?;
        len += self.should_unfreeze.consensus_encode(writer)?;
        len += self.token_public_key.to_bytes().consensus_encode(writer)?;
        len += self.timestamp.consensus_encode(writer)?;

        Ok(len)
    }
}

impl Decodable for TokensFreezeData {
    fn consensus_decode<R: io::Read + ?Sized>(reader: &mut R) -> Result<Self, EncodeError> {
        let issuer_signature = Decodable::consensus_decode(reader)?;
        let owner_public_key_bytes: [u8; bitcoin::key::constants::PUBLIC_KEY_SIZE] =
            Decodable::consensus_decode(reader)?;
        let owner_public_key = PublicKey::from_slice(&owner_public_key_bytes)
            .map_err(|_e| EncodeError::ParseFailed("Failed to parse public key bytes"))?;
        let operator_identity_public_key_bytes: [u8; bitcoin::key::constants::PUBLIC_KEY_SIZE] =
            Decodable::consensus_decode(reader)?;
        let operator_identity_public_key =
            PublicKey::from_slice(&operator_identity_public_key_bytes)
                .map_err(|_e| EncodeError::ParseFailed("Failed to parse public key bytes"))?;
        let should_unfreeze = Decodable::consensus_decode(reader)?;
        let token_public_key_bytes: [u8; TOKEN_PUBKEY_SIZE] = Decodable::consensus_decode(reader)?;
        let token_public_key = TokenPubkey::from_bytes(&token_public_key_bytes)
            .map_err(|_e| EncodeError::ParseFailed("Failed to parse public key bytes"))?;
        let timestamp = Decodable::consensus_decode(reader)?;

        Ok(TokensFreezeData {
            owner_public_key,
            operator_identity_public_key,
            token_public_key,
            should_unfreeze,
            issuer_signature,
            timestamp,
        })
    }
}

#[cfg(all(test, feature = "serde", feature = "messages", feature = "std"))]
mod tests {
    extern crate serde_json;

    use core::str::FromStr;

    use alloc::vec;
    use alloc::vec::Vec;

    use bitcoin::{
        BlockHash, Txid,
        absolute::LockTime,
        consensus::{Decodable, Encodable},
        hashes::sha256::Hash,
        secp256k1::{PublicKey, SecretKey, schnorr},
    };
    use lrc20_receipts::{Receipt, TokenPubkey};
    use once_cell::sync::Lazy;

    use crate::spark::{
        OperatorSpecificOwnerSignature, SparkSignature, TokenLeafOutput, TokenLeafToSpend,
        TokenTransaction, TokenTransactionInput, signature::SparkSignatureData,
    };
    use crate::spark::{TokensFreezeData, signature::SparkSignatureLeafData};

    static PUBKEY: Lazy<PublicKey> = Lazy::new(|| {
        PublicKey::from_str("03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd")
            .unwrap()
    });

    static LEAF_TO_SPEND: Lazy<TokenLeafToSpend> = Lazy::new(|| TokenLeafToSpend {
        parent_output_hash: Hash::from_str(
            "63e7487c274aa618552071b468bb7f9ef2c34fda93de28b49fa9b9baf1b2f1a9",
        )
        .unwrap(),
        parent_output_vout: 1,
    });

    static SIGNATURE: Lazy<schnorr::Signature> = Lazy::new(|| {
        schnorr::Signature::from_str("e8b610834f14a776253c182311da157232369499ffa8692439e7b9e0a511849df7e3c1ba18f2a7663ada96ad0fcb0fadee98107fac6ef1019e2944408a373ecd").expect("Valid ECDSA signature")
    });

    static SIGNATURE_DATA: Lazy<SparkSignatureData> = Lazy::new(|| SparkSignatureData {
        token_tx_hash: Hash::from_str(
            "63e7487c274aa618552071b468bb7f9ef2c34fda93de28b49fa9b9baf1b2f1a9",
        )
        .unwrap()
        .into(),
        operator_specific_owner_signature: Some(OperatorSpecificOwnerSignature::new(
            SparkSignature::from(*SIGNATURE),
            Some(*PUBKEY),
            Some(5),
        )),
        operator_pubkey: *PUBKEY,
        operator_signature: SparkSignature::from(*SIGNATURE),
        outputs_to_spend_data: vec![SparkSignatureLeafData {
            token_tx_leaf_index: 2,
            revocation_secret: Some(
                SecretKey::from_str(
                    "6e2f532ed6004643abed0ba94b8f36f7040d86ac5f1a34a7a65f718aedacd428",
                )
                .unwrap(),
            ),
        }],
    });

    static LEAF_TO_CREATE: Lazy<TokenLeafOutput> = Lazy::new(|| TokenLeafOutput {
        id: "12345".into(),
        owner_public_key: *PUBKEY,
        revocation_public_key: *PUBKEY,
        withdrawal_bond_sats: 12345,
        withdrawal_locktime: LockTime::from_height(12345).unwrap(),
        receipt: Receipt::empty(),
        is_frozen: Some(false),
        withdraw_height: Some(12345),
        withdraw_txid: Some(
            Txid::from_str("63e7487c274aa618552071b468bb7f9ef2c34fda93de28b49fa9b9baf1b2f1a9")
                .unwrap(),
        ),
        withdraw_tx_vout: Some(0),
        withdraw_block_hash: Some(
            BlockHash::from_str("63e7487c274aa618552071b468bb7f9ef2c34fda93de28b49fa9b9baf1b2f1a9")
                .unwrap(),
        ),
    });

    static TOKEN_TXS: Lazy<Vec<TokenTransaction>> = Lazy::new(|| {
        vec![
            TokenTransaction {
                input: TokenTransactionInput::Mint {
                    issuer_public_key: *PUBKEY,
                    issuer_signature: Some(OperatorSpecificOwnerSignature::new(
                        SparkSignature::from(*SIGNATURE),
                        Some(*PUBKEY),
                        Some(0),
                    )),
                    issuer_provided_timestamp: 12345,
                },
                leaves_to_create: vec![
                    LEAF_TO_CREATE.clone(),
                    LEAF_TO_CREATE.clone(),
                    LEAF_TO_CREATE.clone(),
                ],
                spark_operator_identity_public_keys: vec![*PUBKEY, *PUBKEY, *PUBKEY],
                network: Some(1),
            },
            TokenTransaction {
                input: TokenTransactionInput::Transfer {
                    outputs_to_spend: vec![
                        LEAF_TO_SPEND.clone(),
                        LEAF_TO_SPEND.clone(),
                        LEAF_TO_SPEND.clone(),
                    ],
                },
                leaves_to_create: vec![
                    LEAF_TO_CREATE.clone(),
                    LEAF_TO_CREATE.clone(),
                    LEAF_TO_CREATE.clone(),
                ],
                spark_operator_identity_public_keys: vec![*PUBKEY, *PUBKEY, *PUBKEY],
                network: Some(1),
            },
        ]
    });

    static TOKEN_FREEZE: Lazy<TokensFreezeData> = Lazy::new(|| TokensFreezeData {
        owner_public_key: *PUBKEY,
        token_public_key: TokenPubkey::from(*PUBKEY),
        should_unfreeze: true,
        issuer_signature: SparkSignature::from(*SIGNATURE),
        operator_identity_public_key: *PUBKEY,
        timestamp: 12345678,
    });

    #[test]
    fn test_leaf_to_spend_consensus_encode() {
        let mut bytes: Vec<u8> = Vec::new();
        LEAF_TO_SPEND
            .consensus_encode(&mut bytes)
            .expect("failed to encode leaf to spend");

        let decoded_leaf = TokenLeafToSpend::consensus_decode(&mut bytes.as_slice())
            .expect("failed to decode leaf to spend");

        assert_eq!(
            *LEAF_TO_SPEND, decoded_leaf,
            "Converting back and forth should work"
        )
    }

    #[test]
    fn test_leaf_to_create_consensus_encode() {
        let mut bytes: Vec<u8> = Vec::new();
        LEAF_TO_CREATE
            .consensus_encode(&mut bytes)
            .expect("failed to encode leaf to create");

        let decoded_leaf = TokenLeafOutput::consensus_decode(&mut bytes.as_slice())
            .expect("failed to decode leaf to create");

        assert_eq!(
            *LEAF_TO_CREATE, decoded_leaf,
            "Converting back and forth should work"
        )
    }

    #[ignore]
    #[test]
    fn test_token_tx_consensus_encode() {
        for token_tx in TOKEN_TXS.clone() {
            let mut bytes: Vec<u8> = Vec::new();
            token_tx
                .consensus_encode(&mut bytes)
                .expect("failed to encode the tx");

            let decoded_tx = TokenTransaction::consensus_decode(&mut bytes.as_slice())
                .expect("failed to decode the tx");

            assert_eq!(
                token_tx, decoded_tx,
                "Converting back and forth should work"
            )
        }
    }

    #[ignore]
    #[test]
    fn test_signature_data_consensus_encode() {
        let mut bytes: Vec<u8> = Vec::new();
        SIGNATURE_DATA
            .consensus_encode(&mut bytes)
            .expect("failed to encode the data");

        let decoded_data = SparkSignatureData::consensus_decode(&mut bytes.as_slice())
            .expect("failed to decode the data");

        assert_eq!(
            decoded_data, *SIGNATURE_DATA,
            "Converting back and forth should work"
        )
    }

    #[test]
    fn test_tokens_freeze_consensus_encode() {
        let mut bytes: Vec<u8> = Vec::new();
        TOKEN_FREEZE
            .consensus_encode(&mut bytes)
            .expect("failed to encode the freeze data");

        let decoded_data = TokensFreezeData::consensus_decode(&mut bytes.as_slice())
            .expect("failed to decode the freeze data");

        assert_eq!(
            decoded_data, *TOKEN_FREEZE,
            "Converting back and forth should work"
        )
    }
}
