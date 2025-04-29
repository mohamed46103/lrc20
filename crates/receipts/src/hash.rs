use crate::errors::ReceiptHashError;
use crate::{P2WPKHProof, Receipt, ReceiptProof, TaprootProof};
use bitcoin::hashes::{Hash, HashEngine, sha256, sha256::Hash as Sha256Hash};
use core::ops::Deref;

#[cfg(feature = "no-std")]
use crate::alloc::borrow::ToOwned;

/// A hash of the LRC20 receipt data that uniquely identifies a receipt (coin).
///
/// Defined as: `PXH = hash(hash(Y) || UV || hash (metadata))`, where `Y` - is token_amount (amount),
/// `UV` - is token type (issuer public key), and metadata - is an optional auxiliary data
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ReceiptHash(pub Sha256Hash);

impl Deref for ReceiptHash {
    type Target = Sha256Hash;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Receipt> for ReceiptHash {
    fn from(receipt: Receipt) -> Self {
        Self::from(&receipt)
    }
}

impl From<Sha256Hash> for ReceiptHash {
    fn from(hash: Sha256Hash) -> Self {
        Self(hash)
    }
}

impl From<&Receipt> for ReceiptHash {
    fn from(receipt: &Receipt) -> Self {
        let hash_engine = receipt_hash_engine(receipt);

        let pxh = Sha256Hash::from_engine(hash_engine);

        Self(pxh)
    }
}

impl TryFrom<&ReceiptProof> for ReceiptHash {
    type Error = ReceiptHashError;

    fn try_from(proof: &ReceiptProof) -> Result<Self, Self::Error> {
        let mut hash_engine = receipt_hash_engine(&proof.receipt());

        if let Some(metadata) = &proof.metadata() {
            let mut metadata_hash_engine = Sha256Hash::engine();
            let metadata_bytes = serde_json::to_vec(metadata)?;

            metadata_hash_engine.input(&metadata_bytes);

            let metadata_hash = Sha256Hash::from_engine(metadata_hash_engine);

            hash_engine.input(metadata_hash.as_byte_array());
        };

        let pxh = Sha256Hash::from_engine(hash_engine);

        Ok(Self(pxh))
    }
}

impl TryFrom<&P2WPKHProof> for ReceiptHash {
    type Error = ReceiptHashError;

    fn try_from(proof: &P2WPKHProof) -> Result<Self, Self::Error> {
        let proof = &ReceiptProof::from(proof.to_owned());

        proof.try_into()
    }
}

impl TryFrom<&TaprootProof> for ReceiptHash {
    type Error = ReceiptHashError;

    fn try_from(proof: &TaprootProof) -> Result<Self, Self::Error> {
        let proof = &ReceiptProof::from(proof.to_owned());

        proof.try_into()
    }
}

fn receipt_hash_engine(receipt: &Receipt) -> sha256::HashEngine {
    let mut hash_engine = Sha256Hash::engine();

    hash_engine.input(&receipt.token_amount.to_bytes());
    // hash(Y)
    let amount_hashed = Sha256Hash::from_engine(hash_engine);

    let mut hash_engine = Sha256Hash::engine();
    // hash(hash(Y) || UV || Optional hash(metadata))
    hash_engine.input(amount_hashed.as_byte_array());

    // Skip first byte of the public key (0x02 or 0x03) and hash the rest.
    hash_engine.input(&receipt.token_pubkey.pubkey().serialize());

    hash_engine
}

#[cfg(test)]
mod tests {
    use crate::receipt::BLINDING_FACTOR_SIZE;
    use crate::{Receipt, ReceiptHash, SigReceiptProof, TokenAmount};
    use bitcoin::hashes::Hash as BitcoinHash;
    use bitcoin::hashes::sha256::Hash;
    use bitcoin::secp256k1::PublicKey;
    use core::str::FromStr;
    use once_cell::sync::Lazy;
    use serde_json::json;

    const AMOUNT: u128 = 100;

    static PUBKEY: Lazy<PublicKey> = Lazy::new(|| {
        PublicKey::from_str("03ab5575d69e46968a528cd6fa2a35dd7808fea24a12b41dc65c7502108c75f9a9")
            .unwrap()
    });

    static MOCKED_HASH_STR: Lazy<Hash> = Lazy::new(|| {
        Hash::from_slice(
            &hex::decode("9f18510d5f6e2fcd156ad036bb5a838373a5bb6f5a522cb426e8cfb90a21ee35")
                .unwrap(),
        )
        .unwrap()
    });

    static MOCKED_METADATA_HASH_STR: Lazy<Hash> = Lazy::new(|| {
        Hash::from_slice(
            &hex::decode("c5bb20c1ae8b458db56f8c90dac51039bcc0e0f06b469f185d0ef15b1fca8195")
                .unwrap(),
        )
        .unwrap()
    });

    #[test]
    fn test_hash() {
        let receipt = Receipt::new(TokenAmount::new(AMOUNT, [0; BLINDING_FACTOR_SIZE]), *PUBKEY);

        assert_eq!(ReceiptHash::from(&receipt).0, *MOCKED_HASH_STR);
    }

    #[test]
    fn test_metadata_hash() {
        let receipt = Receipt::new(TokenAmount::new(AMOUNT, [0; BLINDING_FACTOR_SIZE]), *PUBKEY);

        let metadata = json!({
            "field1": "value1",
            "field2": "value2",
            "field3": "value3",
        });

        let proof = SigReceiptProof::new(receipt, *PUBKEY, Some(metadata));
        let pxh = ReceiptHash::try_from(&proof).unwrap();

        assert_eq!(pxh.0, *MOCKED_METADATA_HASH_STR);
    }
}
