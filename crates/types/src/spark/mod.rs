use alloc::{string::String, vec::Vec};
use bitcoin::{
    BlockHash, Txid,
    absolute::LockTime,
    hashes::{Hash as _, HashEngine, sha256::Hash},
    key::Secp256k1,
    secp256k1::{self, All, Message, SecretKey, ThirtyTwoByteHash, ecdsa, schnorr},
};
use lrc20_receipts::{Receipt, TokenPubkey};
use spark_hash::SparkHash;

#[cfg(feature = "consensus")]
pub mod consensus;
pub mod signature;
pub mod spark_hash;

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TokenTransaction {
    pub input: TokenTransactionInput,
    pub leaves_to_create: Vec<TokenLeafOutput>,
    pub spark_operator_identity_public_keys: Vec<secp256k1::PublicKey>,
    pub network: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TokenTransactionInput {
    Mint {
        issuer_public_key: secp256k1::PublicKey,
        issuer_signature: Option<OperatorSpecificOwnerSignature>,
        issuer_provided_timestamp: u64,
    },
    Transfer {
        outputs_to_spend: Vec<TokenLeafToSpend>,
    },
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TokenTransactionStatus {
    Started,
    Signed,
    Finalized,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OperatorSpecificOwnerSignature {
    pub operator_identity_public_key: Option<secp256k1::PublicKey>,
    pub owner_signature: SparkSignature,
    pub input_index: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SparkSignature {
    ECDSA(ecdsa::Signature),
    Schnorr(schnorr::Signature),
}

impl From<ecdsa::Signature> for SparkSignature {
    fn from(sig: ecdsa::Signature) -> Self {
        Self::ECDSA(sig)
    }
}

impl From<schnorr::Signature> for SparkSignature {
    fn from(sig: schnorr::Signature) -> Self {
        Self::Schnorr(sig)
    }
}

impl SparkSignature {
    /// Try to deserialize bytes to either ECDSA or Schnorr signature. None is returned if failed
    /// to deserialize.
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, secp256k1::Error> {
        if let Ok(ecdsa_sig) = ecdsa::Signature::from_der(bytes) {
            return Ok(ecdsa_sig.into());
        }

        if let Ok(schnorr_sig) = schnorr::Signature::from_slice(bytes) {
            return Ok(schnorr_sig.into());
        }

        if let Ok(ecdsa_sig) = ecdsa::Signature::from_compact(bytes) {
            return Ok(ecdsa_sig.into());
        }

        Err(secp256k1::Error::InvalidSignature)
    }

    pub fn bytes(&self) -> [u8; 64] {
        match self {
            SparkSignature::ECDSA(signature) => signature.serialize_compact(),
            SparkSignature::Schnorr(signature) => signature.serialize(),
        }
    }

    pub fn verify(
        &self,
        pubkey: &secp256k1::PublicKey,
        message: &secp256k1::Message,
        operator_identity_public_key: Option<secp256k1::PublicKey>,
    ) -> bool {
        let ctx = Secp256k1::new();

        self.verify_with_ctx(&ctx, pubkey, message, operator_identity_public_key)
    }

    pub fn verify_with_ctx(
        &self,
        ctx: &Secp256k1<All>,
        pubkey: &secp256k1::PublicKey,
        message: &secp256k1::Message,
        operator_identity_public_key: Option<secp256k1::PublicKey>,
    ) -> bool {
        let message = match operator_identity_public_key {
            Some(operator_pubkey) => {
                let mut engine = Hash::engine();

                engine.input(Hash::hash(message.as_ref().as_slice()).as_byte_array());
                engine.input(Hash::hash(&operator_pubkey.serialize()).as_byte_array());

                let operator_specific_message = Hash::from_engine(engine);

                &Message::from_digest(operator_specific_message.into_32())
            }
            None => message,
        };

        match self {
            SparkSignature::ECDSA(signature) => {
                ctx.verify_ecdsa(message, &signature, pubkey).is_ok()
            }
            SparkSignature::Schnorr(signature) => {
                let (xonly, _) = pubkey.x_only_public_key();
                ctx.verify_schnorr(&signature, message, &xonly).is_ok()
            }
        }
    }
}

impl OperatorSpecificOwnerSignature {
    pub fn new(
        signature: impl Into<SparkSignature>,
        identity_public_key: Option<secp256k1::PublicKey>,
        input_index: Option<u32>,
    ) -> Self {
        Self {
            operator_identity_public_key: identity_public_key,
            owner_signature: signature.into(),
            input_index,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TokenTransactionFinalizationRequest {
    pub final_token_transaction_hash: SparkHash,
    // List of ordered revocation keys that map 1:1 with leaves being spent in the
    // token transaction.
    pub leaf_to_spend_revocation_keys: Vec<SecretKey>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TokenLeafToSpend {
    pub parent_output_hash: Hash,
    pub parent_output_vout: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TokenLeafOutput {
    pub id: String,
    pub owner_public_key: secp256k1::PublicKey,
    pub revocation_public_key: secp256k1::PublicKey,
    pub withdrawal_bond_sats: u64,
    pub withdrawal_locktime: LockTime,
    pub receipt: Receipt,
    pub is_frozen: Option<bool>,
    pub withdraw_txid: Option<Txid>,
    pub withdraw_tx_vout: Option<u32>,
    pub withdraw_height: Option<u32>,
    pub withdraw_block_hash: Option<BlockHash>,
}

impl From<&TokenTransaction> for Hash {
    fn from(tx: &TokenTransaction) -> Self {
        *SparkHash::from(tx)
    }
}

impl TokenTransaction {
    pub fn hash(&self) -> SparkHash {
        self.into()
    }
}

#[derive(Hash, Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TokensFreezeData {
    pub operator_identity_public_key: secp256k1::PublicKey,
    pub owner_public_key: secp256k1::PublicKey,
    pub token_public_key: TokenPubkey,
    pub should_unfreeze: bool,
    pub issuer_signature: SparkSignature,
    pub timestamp: u64,
}

impl TokensFreezeData {
    pub fn hash(&self) -> Hash {
        let mut engine = Hash::engine();

        engine.input(Hash::hash(&self.owner_public_key.serialize()).as_byte_array());
        engine.input(Hash::hash(&self.token_public_key.to_bytes()).as_byte_array());
        engine.input(Hash::hash(&self.timestamp.to_le_bytes()).as_byte_array());
        engine.input(Hash::hash(&self.operator_identity_public_key.serialize()).as_byte_array());

        Hash::from_engine(engine)
    }
}

#[derive(Hash, Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SparkOutPoint {
    pub token_transaction_hash: SparkHash,
    pub output_index: u32,
}

impl SparkOutPoint {
    pub fn new(token_transaction_hash: SparkHash, output_index: u32) -> Self {
        Self {
            token_transaction_hash,
            output_index,
        }
    }
}

pub fn get_length_of_leaves_to_spend(tx: &TokenTransaction) -> usize {
    match &tx.input {
        TokenTransactionInput::Mint { .. } => 0,
        TokenTransactionInput::Transfer { outputs_to_spend } => outputs_to_spend.len(),
    }
}
