use bitcoin::ScriptBuf;
use bitcoin::hashes::{Hash, HashEngine, sha256::Hash as Sha256Hash};
use bitcoin::{
    self,
    secp256k1::{self, PublicKey, Scalar, Secp256k1, Signing, Verification},
};

use core::ops::Deref;

use crate::ReceiptHash;
use crate::errors::ReceiptKeyError;

/// Public key that can spend a receipt.
///
/// Defined as: `Receipt key = hash(PXH, Pk) * G + P_{B}`,
/// where `Pk` is owner's public key (coin inner key).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ReceiptKey(secp256k1::PublicKey);

impl Deref for ReceiptKey {
    type Target = secp256k1::PublicKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ReceiptKey {
    pub fn new(
        pxh: impl Into<ReceiptHash>,
        inner_key: &secp256k1::PublicKey,
    ) -> Result<Self, ReceiptKeyError> {
        let ctx = Secp256k1::new();

        Self::new_with_ctx(pxh, inner_key, &ctx)
    }

    pub fn new_with_ctx<C>(
        pxh: impl Into<ReceiptHash>,
        inner_key: &secp256k1::PublicKey,
        ctx: &Secp256k1<C>,
    ) -> Result<Self, ReceiptKeyError>
    where
        C: Signing + Verification,
    {
        // hash(PXH, P_{B})
        let pxh_b = receipt_hash_pubkey_scalar(&pxh.into(), inner_key)?;

        // P_{B} + hash(PXH, P_{B}) * G (where G - generator point).
        //
        // `add_exp_tweak` multiplies by G the hash (scalar).
        let receipt_key = inner_key.add_exp_tweak(ctx, &pxh_b)?;

        Ok(Self(receipt_key))
    }

    pub fn new_unchecked(inner_key: secp256k1::PublicKey) -> Self {
        Self(inner_key)
    }

    pub fn to_p2wpkh(&self) -> Option<ScriptBuf> {
        let pubkey_hash = bitcoin::PublicKey::from(self.0).wpubkey_hash()?;

        Some(ScriptBuf::new_p2wpkh(&pubkey_hash))
    }
}

/// Calculates: `sha256(PXH || Pk)`
///
/// where `PXH` - hash of the receipt (see [`ReceiptHash`]),
///       `Pk` - public key of current owner.
fn receipthash_pubkey_hash(pxh: &ReceiptHash, pubkey: &secp256k1::PublicKey) -> Sha256Hash {
    let mut hash_engine = Sha256Hash::engine();

    // By putting hash and key after each other into "hash engine",
    // the "engine" will hash the concatenation.
    hash_engine.input(pxh.as_byte_array());
    hash_engine.input(&pubkey.serialize());

    Sha256Hash::from_engine(hash_engine)
}

/// The same as [`receipthash_pubkey_hash`], but returns the scalar.
fn receipt_hash_pubkey_scalar(
    pxh: &ReceiptHash,
    pubkey: &secp256k1::PublicKey,
) -> Result<Scalar, ReceiptKeyError> {
    let hash = receipthash_pubkey_hash(pxh, pubkey);

    Scalar::from_be_bytes(*hash.as_byte_array()).map_err(|_| ReceiptKeyError::ReceiptHashOutOfRange)
}

/// Private key that can spend a LRC20 UTXO.
///
/// Defined as: `Sk_{B} + hash(PXH || Pk)`, where `Sk_{B}` - is
/// a secret key of current owner of the coin, `PXH` is
/// [`ReceiptHash`], and `Pk` is derived from `Sk` public key.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ReceiptPrivateKey(pub secp256k1::SecretKey);

impl Deref for ReceiptPrivateKey {
    type Target = secp256k1::SecretKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ReceiptPrivateKey {
    pub fn new(
        pxh: impl Into<ReceiptHash>,
        inner_key: &secp256k1::SecretKey,
    ) -> Result<Self, ReceiptKeyError> {
        let ctx = Secp256k1::signing_only();

        Self::new_with_ctx(pxh, inner_key, &ctx)
    }

    /// Create [`ReceiptPrivateKey`] from [`ReceiptHash`] and secret key of the LRC20 UTXO owner.
    ///
    /// `ctx` is required if you want to be sure that operations are done
    /// only in secure parts of the memory. Otherwise use [`Self::new`].
    pub fn new_with_ctx<C>(
        pxh: impl Into<ReceiptHash>,
        inner_key: &secp256k1::SecretKey,
        ctx: &Secp256k1<C>,
    ) -> Result<Self, ReceiptKeyError>
    where
        C: Signing,
    {
        let pubkey: secp256k1::PublicKey = inner_key.public_key(ctx);

        // hash(PXH, P_{B})
        let pxh_b = receipt_hash_pubkey_scalar(&pxh.into(), &pubkey)?;

        // (Sk_{B} + hash(PXH, P_{B})) mod P, where `P` curve order.
        //
        // `add_tweak` also does the `mod P` operation
        let spending_key = inner_key.add_tweak(&pxh_b)?;

        Ok(Self(spending_key))
    }
}

impl From<ReceiptKey> for PublicKey {
    fn from(receipt_key: ReceiptKey) -> Self {
        *receipt_key
    }
}

impl From<&ReceiptKey> for PublicKey {
    fn from(receipt_key: &ReceiptKey) -> Self {
        **receipt_key
    }
}

impl From<ReceiptKey> for bitcoin::PublicKey {
    fn from(receipt_key: ReceiptKey) -> Self {
        Self::from(*receipt_key)
    }
}

impl From<&ReceiptKey> for bitcoin::PublicKey {
    fn from(receipt_key: &ReceiptKey) -> Self {
        Self::from(**receipt_key)
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use bitcoin::secp256k1::PublicKey;
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::secp256k1::SecretKey;
    use once_cell::sync::Lazy;

    use crate::{Receipt, ReceiptKey, ReceiptPrivateKey};

    static ISSUER: Lazy<PublicKey> = Lazy::new(|| {
        PublicKey::from_str("036a5e3a83f0b2bdfb2f874c6f4679dc02568deb8987d11314a36bceacb569ad8e")
            .expect("Should be valid public key")
    });

    static RECIPIENT_SECRET_EVEN: Lazy<SecretKey> = Lazy::new(|| {
        SecretKey::from_str("f9e17ee5b837fece0695f9782253604586ab1daf42ecf2762573243c7a6979f4")
            .expect("Should be valid secret")
    });

    static RECIPIENT_SECRET_ODD: Lazy<SecretKey> = Lazy::new(|| {
        SecretKey::from_str("f8e17ee5b837fece0695f9782253604586ab1daf42ecf2762573243c7a6979f4")
            .expect("Should be valid secret")
    });

    #[test]
    fn test_derived_even_public_key_eq_receipt_key() {
        let receipt = Receipt::new(100, *ISSUER);

        let ctx = Secp256k1::new();

        let receipt_key =
            ReceiptKey::new_with_ctx(receipt, &RECIPIENT_SECRET_EVEN.public_key(&ctx), &ctx)
                .unwrap();

        let pxsk = ReceiptPrivateKey::new_with_ctx(receipt, &RECIPIENT_SECRET_EVEN, &ctx).unwrap();

        let derived = pxsk.0.public_key(&ctx);

        assert_eq!(
            derived, *receipt_key,
            "derived from private key, and public key got from hash MUST be equal"
        );
    }

    #[test]
    fn test_derived_odd_public_key_eq_receipt_key() {
        let receipt = Receipt::new(100, *ISSUER);

        let ctx = Secp256k1::new();

        let receipt_key =
            ReceiptKey::new_with_ctx(receipt, &RECIPIENT_SECRET_ODD.public_key(&ctx), &ctx)
                .unwrap();

        let pxsk = ReceiptPrivateKey::new_with_ctx(receipt, &RECIPIENT_SECRET_ODD, &ctx).unwrap();

        let derived = pxsk.0.public_key(&ctx);

        assert_eq!(
            derived, *receipt_key,
            "derived from private key, and public key got from hash MUST be equal"
        );
    }

    #[test]
    fn test_receipt_key() {
        let p = Receipt::new(100, *ISSUER);

        let receipt_key = ReceiptKey::new(p, &ISSUER).unwrap();

        assert!(receipt_key.to_p2wpkh().is_some());
    }
}
