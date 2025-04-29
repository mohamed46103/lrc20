use bitcoin::{
    TxIn, TxOut,
    ecdsa::Signature,
    hashes::{Hash as BitcoinHash, HashEngine, sha256::Hash as Sha256Hash},
    secp256k1::{self, PublicKey, schnorr::Signature as SchnorrSignature},
};
#[cfg(feature = "serde")]
use bulletproof::k256::elliptic_curve::sec1::FromEncodedPoint;
use bulletproof::{
    RangeProof,
    k256::{EncodedPoint, ProjectivePoint, elliptic_curve::group::GroupEncoding},
};
use core::hash::Hash;
use core::hash::Hasher;

use crate::{CheckableProof, Receipt, ReceiptKey, ReceiptKeyError, TokenAmount};

use self::errors::BulletproofError;

use super::{ReceiptProof, p2wpkh::witness::P2WPKHWitness};

#[cfg(feature = "consensus")]
pub mod consensus;
pub mod errors;
pub mod signing;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Bulletproof {
    /// Receipt that proof verifies.
    pub receipt: Receipt,
    /// Key of current owner of the receipt.
    pub inner_key: secp256k1::PublicKey,
    /// Key of of the sender.
    pub sender_key: secp256k1::PublicKey,
    /// Pedersen commitment of the receipt amount.
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "commitment_to_hex",
            deserialize_with = "hex_to_commitment"
        )
    )]
    pub commitment: ProjectivePoint,
    /// Bulletproof proof itself .
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "rangeproof_to_hex",
            deserialize_with = "hex_to_rangeproof"
        )
    )]
    pub proof: RangeProof,
    pub signature: SchnorrSignature,
    pub token_pubkey_signature: SchnorrSignature,
}

impl From<Bulletproof> for ReceiptProof {
    fn from(value: Bulletproof) -> Self {
        Self::Bulletproof(alloc::boxed::Box::new(value))
    }
}

impl Hash for Bulletproof {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.receipt.hash(state);
        self.inner_key.serialize().hash(state);

        let encoded_point = EncodedPoint::from(self.commitment.to_affine());

        encoded_point.hash(state);

        self.proof.hash(state);
    }
}

impl Bulletproof {
    pub fn new(
        receipt: Receipt,
        inner_key: secp256k1::PublicKey,
        sender_key: secp256k1::PublicKey,
        commitment: ProjectivePoint,
        proof: RangeProof,
        signature: SchnorrSignature,
        token_pubkey_signature: SchnorrSignature,
    ) -> Self {
        Self {
            receipt,
            inner_key,
            sender_key,
            commitment,
            proof,
            signature,
            token_pubkey_signature,
        }
    }

    /// Check proof by parsed witness data.
    pub(crate) fn check_by_parsed_witness_data(
        &self,
        _signature: &Signature,
        pubkey: &PublicKey,
    ) -> Result<(), BulletproofError> {
        let receipt_key = ReceiptKey::new(self.receipt, &self.inner_key)?;

        if *receipt_key != *pubkey {
            return Err(BulletproofError::PublicKeyMismatch);
        }

        Ok(())
    }

    pub(crate) fn check_token_amount(&self) -> bool {
        let mut hash_engine = Sha256Hash::engine();

        hash_engine.input(&self.commitment.to_bytes());
        hash_engine.input(&self.proof.to_bytes());

        let bytes = Sha256Hash::from_engine(hash_engine);
        let value_proof_hash = bytes.to_byte_array();

        TokenAmount::from(value_proof_hash) == self.receipt.token_amount
    }
}

impl CheckableProof for Bulletproof {
    type Error = BulletproofError;

    fn checked_check_by_input(&self, txin: &TxIn) -> Result<(), Self::Error> {
        let data = P2WPKHWitness::from_witness(&txin.witness)?;

        self.check_by_parsed_witness_data(&data.signature, &data.pubkey)?;

        if !bulletproof::verify(self.commitment, self.proof.clone()) {
            return Err(BulletproofError::InvalidRangeProof);
        }

        Ok(())
    }

    fn checked_check_by_output(&self, txout: &TxOut) -> Result<(), Self::Error> {
        let receipt_key = ReceiptKey::new(self.receipt, &self.inner_key)?;

        let expected_script_pubkey = receipt_key
            .to_p2wpkh()
            .ok_or(ReceiptKeyError::UncompressedKey)?;

        if txout.script_pubkey != expected_script_pubkey {
            return Err(BulletproofError::ScriptMismatch);
        }

        if !self.check_token_amount() {
            return Err(BulletproofError::TokenAmountMismatch);
        }

        if !bulletproof::verify(self.commitment, self.proof.clone()) {
            return Err(BulletproofError::InvalidRangeProof);
        }

        Ok(())
    }
}

#[cfg(feature = "serde")]
pub fn commitment_to_hex<S>(commitment: &ProjectivePoint, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let encoded_point = EncodedPoint::from(commitment.to_affine());

    serializer.serialize_str(&hex::encode(encoded_point))
}

#[cfg(feature = "serde")]
pub fn hex_to_commitment<'de, D>(deserializer: D) -> Result<ProjectivePoint, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: alloc::string::String = deserializer.deserialize_string(crate::HexVisitor)?;
    let data = hex::decode(s).map_err(serde::de::Error::custom)?;

    let encoded_point = EncodedPoint::from_bytes(data).map_err(serde::de::Error::custom)?;

    if let Some(commit) = ProjectivePoint::from_encoded_point(&encoded_point).into() {
        return Ok(commit);
    }

    Err(serde::de::Error::custom("invalid commitment received"))
}

#[cfg(feature = "serde")]
pub fn rangeproof_to_hex<S>(rangeproof: &RangeProof, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&hex::encode(rangeproof.to_bytes()))
}

#[cfg(feature = "serde")]
pub fn hex_to_rangeproof<'de, D>(deserializer: D) -> Result<RangeProof, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: alloc::string::String = deserializer.deserialize_string(crate::HexVisitor)?;
    let data = hex::decode(s).map_err(serde::de::Error::custom)?;

    let proof =
        RangeProof::from_bytes(&data).ok_or(serde::de::Error::custom("invalid proof received"))?;

    Ok(proof)
}
