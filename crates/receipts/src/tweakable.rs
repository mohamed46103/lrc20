//! Provides general trait for all entities that can be tweaked by receipt.
//!
//! For example, [`PublicKey`] can be tweaked by [`ReceiptKey`], [`SecretKey`]
//! can be tweaked to [`ReceiptPrivateKey`].

use bitcoin::secp256k1::{PublicKey, SecretKey};

use crate::{ReceiptHash, ReceiptKey, ReceiptPrivateKey};

/// For entities that can be tweaked by receipt.
///
/// For example, [`PublicKey`] can be tweaked into [`PublicKey`]:
///
/// ```
/// use lrc20_receipts::Tweakable;
/// use std::str::FromStr;
/// use lrc20_receipts::ReceiptKey;
///
/// let pubkey = bitcoin::PublicKey::from_str(
///    "036a5e3a83f0b2bdfb2f874c6f4679dc02568deb8987d11314a36bceacb569ad8e",
/// ).expect("Should be valid public key");
///
/// let receipt = lrc20_receipts::Receipt::new(100, pubkey);
///
/// let tweaked: bitcoin::secp256k1::PublicKey = pubkey.inner.tweak(receipt);
/// ```
///
/// The same for [`SecretKey`]:
///
/// ```
/// use std::str::FromStr;
/// use lrc20_receipts::Tweakable;
/// use bitcoin::secp256k1::SecretKey;
/// use bitcoin::secp256k1::Secp256k1;
///
/// let ctx = Secp256k1::new();
///
/// let private_key = bitcoin::PrivateKey::from_str(
///     "cUrMc62nnFeQuzXb26KPizCJQPp7449fsPsqn5NCHTwahSvqqRkV"
/// ).expect("Should be valid private key");
///
/// let pubkey = private_key.public_key(&ctx);
///
/// let receipt = lrc20_receipts::Receipt::new(100, pubkey);
///
/// let tweaked: SecretKey = private_key.inner.tweak(receipt);
/// ```
pub trait Tweakable<P: Into<ReceiptHash>> {
    fn tweak(self, receipt: P) -> Self
    where
        Self: Sized;

    fn maybe_tweak(self, optional_receipt: Option<P>) -> Self
    where
        Self: Sized,
    {
        if let Some(receipt) = optional_receipt {
            return self.tweak(receipt);
        }

        self
    }
}

const EXPECT_MSG: &str = "Error will encounter only in rear cases of memory corruption";

impl<P> Tweakable<P> for PublicKey
where
    P: Into<ReceiptHash>,
{
    fn tweak(self, receipt: P) -> PublicKey {
        let key: ReceiptKey = ReceiptKey::new(receipt, &self).expect(EXPECT_MSG);

        *key
    }
}

impl<P> Tweakable<P> for SecretKey
where
    P: Into<ReceiptHash>,
{
    fn tweak(self, receipt: P) -> SecretKey {
        let seckey = ReceiptPrivateKey::new(receipt, &self).expect(EXPECT_MSG);

        *seckey
    }
}

impl<P> Tweakable<P> for bitcoin::PublicKey
where
    P: Into<ReceiptHash>,
{
    fn tweak(self, receipt: P) -> Self
    where
        Self: Sized,
    {
        let tweaked = self.inner.tweak(receipt);

        bitcoin::PublicKey::new(tweaked)
    }
}

impl<P> Tweakable<P> for bitcoin::PrivateKey
where
    P: Into<ReceiptHash>,
{
    fn tweak(self, receipt: P) -> Self
    where
        Self: Sized,
    {
        let tweaked = self.inner.tweak(receipt);

        bitcoin::PrivateKey::new(tweaked, self.network)
    }
}
