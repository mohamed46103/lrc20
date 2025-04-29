use bitcoin::{
    consensus::{Decodable, Encodable, encode::Error},
    secp256k1::{
        self,
        constants::{PUBLIC_KEY_SIZE, SCHNORR_SIGNATURE_SIZE},
    },
};
use bulletproof::{
    RangeProof,
    k256::{ProjectivePoint, elliptic_curve::group::GroupEncoding},
};
use core2::io;

use crate::Receipt;

use super::Bulletproof;

impl Encodable for Bulletproof {
    fn consensus_encode<W: io::Write + ?Sized>(&self, writer: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;

        len += self.receipt.consensus_encode(writer)?;

        len += writer.write(&self.inner_key.serialize())?;

        len += writer.write(&self.sender_key.serialize())?;

        let commitment_bytes = self.commitment.to_bytes();
        len += commitment_bytes.to_vec().consensus_encode(writer)?;

        len += self.proof.to_bytes().consensus_encode(writer)?;

        len += writer.write(self.signature.as_ref())?;

        len += writer.write(self.token_pubkey_signature.as_ref())?;

        Ok(len)
    }
}

impl Decodable for Bulletproof {
    fn consensus_decode<R: io::Read + ?Sized>(reader: &mut R) -> Result<Self, Error> {
        let receipt: Receipt = Decodable::consensus_decode(reader)?;

        let mut bytes = [0u8; PUBLIC_KEY_SIZE];
        reader.read_exact(&mut bytes)?;
        let inner_key = secp256k1::PublicKey::from_slice(&bytes)
            .map_err(|_| Error::ParseFailed("Failed to parse the public key"))?;

        let mut bytes = [0u8; PUBLIC_KEY_SIZE];
        reader.read_exact(&mut bytes)?;
        let sender_key = secp256k1::PublicKey::from_slice(&bytes)
            .map_err(|_| Error::ParseFailed("Failed to parse the public key"))?;

        let commitment_bytes: Vec<u8> = Decodable::consensus_decode(reader)?;
        let commitment: Option<ProjectivePoint> =
            ProjectivePoint::from_bytes(commitment_bytes.as_slice().into()).into();

        let mut bytes = [0u8; PUBLIC_KEY_SIZE];
        reader.read_exact(&mut bytes)?;

        let bytes: Vec<u8> = Decodable::consensus_decode(reader)?;
        let proof: RangeProof = RangeProof::from_bytes(bytes.as_slice())
            .ok_or_else(|| Error::ParseFailed("Failed to parse the range proof"))?;

        let mut bytes = [0u8; SCHNORR_SIGNATURE_SIZE];
        reader.read_exact(&mut bytes)?;
        let signature = bitcoin::secp256k1::schnorr::Signature::from_slice(&bytes)
            .map_err(|_e| Error::ParseFailed("Failed to parse the signature"))?;

        let mut bytes = [0u8; SCHNORR_SIGNATURE_SIZE];
        reader.read_exact(&mut bytes)?;
        let token_pubkey_signature = bitcoin::secp256k1::schnorr::Signature::from_slice(&bytes)
            .map_err(|_e| Error::ParseFailed("Failed to parse the token_pubkey signature"))?;

        Ok(Bulletproof::new(
            receipt,
            inner_key,
            sender_key,
            commitment.ok_or(Error::ParseFailed("Failed to parse the commitment"))?,
            proof,
            signature,
            token_pubkey_signature,
        ))
    }
}
