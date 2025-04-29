use super::TaprootProof;
use crate::metadata::{try_read_metadata, try_write_metadata};
use bitcoin::{
    consensus::{Decodable, Encodable, encode::Error},
    key::constants::PUBLIC_KEY_SIZE,
    secp256k1::PublicKey,
};
use core2::io;

impl Encodable for TaprootProof {
    fn consensus_encode<W: io::Write + ?Sized>(&self, writer: &mut W) -> Result<usize, io::Error> {
        let mut len = self.receipt.consensus_encode(writer)?;

        len += writer.write(&self.inner_key.serialize())?;

        len += try_write_metadata(writer, &self.metadata)?;

        Ok(len)
    }
}

impl Decodable for TaprootProof {
    fn consensus_decode<R: io::Read + ?Sized>(reader: &mut R) -> Result<Self, Error> {
        let receipt = Decodable::consensus_decode(reader)?;

        let mut buf = [0u8; PUBLIC_KEY_SIZE];
        reader.read_exact(&mut buf)?;
        let inner_key = PublicKey::from_slice(&buf)
            .map_err(|_err| Error::ParseFailed("Failed to parse public key bytes"))?;

        let metadata = try_read_metadata(reader)?;

        Ok(Self {
            receipt,
            inner_key,
            metadata,
        })
    }
}
