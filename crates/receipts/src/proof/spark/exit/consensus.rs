use bitcoin::{
    consensus::{Decodable, Encodable},
    key::constants::PUBLIC_KEY_SIZE,
    secp256k1,
};
use core2::io;

use crate::{
    Receipt,
    metadata::{try_read_metadata, try_write_metadata},
};

use super::{SparkExitProof, SparkExitScript};

impl Encodable for SparkExitProof {
    fn consensus_encode<W: io::Write + ?Sized>(&self, writer: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;

        len += self.receipt.consensus_encode(writer)?;

        len += writer.write(&self.script.revocation_key.serialize())?;

        len += self.script.locktime.consensus_encode(writer)?;

        len += writer.write(&self.script.delay_key.serialize())?;

        len += try_write_metadata(writer, &self.metadata)?;

        Ok(len)
    }
}

impl Decodable for SparkExitProof {
    fn consensus_decode<R: io::Read + ?Sized>(
        reader: &mut R,
    ) -> Result<Self, bitcoin::consensus::encode::Error> {
        let receipt: Receipt = Decodable::consensus_decode(reader)?;

        let mut bytes = [0u8; PUBLIC_KEY_SIZE];
        reader.read_exact(&mut bytes)?;
        let revocation_pubkey = secp256k1::PublicKey::from_slice(&bytes).map_err(|_| {
            bitcoin::consensus::encode::Error::ParseFailed("Failed to parse the public key")
        })?;

        let locktime: u32 = Decodable::consensus_decode(reader)?;

        let mut bytes = [0u8; PUBLIC_KEY_SIZE];
        reader.read_exact(&mut bytes)?;
        let delay_pubkey = secp256k1::PublicKey::from_slice(&bytes).map_err(|_| {
            bitcoin::consensus::encode::Error::ParseFailed("Failed to parse the public key")
        })?;

        let metadata = try_read_metadata(reader)?;

        Ok(SparkExitProof {
            receipt,
            script: SparkExitScript::new(revocation_pubkey, locktime, delay_pubkey),
            metadata,
        })
    }
}
