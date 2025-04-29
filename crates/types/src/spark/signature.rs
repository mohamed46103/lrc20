use alloc::vec::Vec;
use bitcoin::secp256k1::{self, SecretKey};

use super::{OperatorSpecificOwnerSignature, SparkSignature, spark_hash::SparkHash};
use core::hash;

pub const SPARK_THRESHOLD: usize = 3;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SparkSignatureData {
    pub operator_specific_owner_signature: Option<OperatorSpecificOwnerSignature>,
    pub operator_pubkey: secp256k1::PublicKey,
    pub operator_signature: SparkSignature,
    pub token_tx_hash: SparkHash,
    pub outputs_to_spend_data: Vec<SparkSignatureLeafData>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SparkSignatureLeafData {
    pub token_tx_leaf_index: u32,
    pub revocation_secret: Option<SecretKey>,
}

impl hash::Hash for SparkSignatureLeafData {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.token_tx_leaf_index.hash(state);
        if let Some(key) = &self.revocation_secret {
            key.secret_bytes().hash(state);
        }
    }
}

impl SparkSignatureData {
    pub fn new(
        token_tx_hash: SparkHash,
        operator_pubkey: secp256k1::PublicKey,
        operator_signature: SparkSignature,
        operator_specific_owner_signature: Option<OperatorSpecificOwnerSignature>,
        outputs_to_spend_data: Vec<SparkSignatureLeafData>,
    ) -> Self {
        Self {
            token_tx_hash,
            operator_specific_owner_signature,
            operator_pubkey,
            operator_signature,
            outputs_to_spend_data,
        }
    }
}
