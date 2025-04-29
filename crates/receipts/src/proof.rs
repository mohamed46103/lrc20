use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::hash::Hash;
use spark::exit::{SparkExitProof, SparkExitScript};

use crate::errors::ReceiptProofError;
use crate::{
    LightningCommitmentProof, LightningHtlcData, MultisigReceiptProof, P2WPKHProof, Receipt,
};
use bitcoin::{ScriptBuf, TxIn, TxOut, secp256k1};
use serde_json::Value;

use self::common::lightning::htlc::LightningHtlcProof;
use self::empty::EmptyReceiptProof;
use self::p2tr::TaprootProof;
use self::p2wpkh::SigReceiptProof;
use self::p2wsh::P2WSHProof;

#[cfg(feature = "no-std")]
use crate::alloc::borrow::ToOwned;

#[cfg(feature = "bulletproof")]
pub mod bulletproof;
pub mod common;
pub mod empty;
pub mod p2tr;
pub mod p2wpkh;
pub mod p2wsh;
pub mod spark;

/// The proof of ownership that user brings to check and attach particular transaction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "type", content = "data"))]
pub enum ReceiptProof {
    /// The proof of ownership of the satoshis only output.
    ///
    /// This type of proof doesn't hold a receipt.
    EmptyReceipt(EmptyReceiptProof),

    /// The proof of ownership with single signature.
    Sig(SigReceiptProof),

    /// Receipt proof for multisignature transaction that uses P2WSH script.
    Multisig(MultisigReceiptProof),

    /// Proof for transaction for Lightning network protocol commitment
    /// transaction.
    ///
    /// TODO: rename to `LightningCommitment`.
    Lightning(LightningCommitmentProof),

    /// Proof for spending lightning HTLC output at force-close.
    LightningHtlc(LightningHtlcProof),

    /// The proof for arbitary P2WSH address script.
    P2WSH(Box<p2wsh::P2WSHProof>),

    /// The proof of ownership of a Taproot output.
    P2TR(TaprootProof),

    /// The proof of ownership of a Spark exit output.
    SparkExit(SparkExitProof),

    /// The bulletproof with a corresponsing Pedersen commitment
    #[cfg(feature = "bulletproof")]
    Bulletproof(alloc::boxed::Box<bulletproof::Bulletproof>),
}

impl ReceiptProof {
    #[inline]
    pub fn receipt(&self) -> Receipt {
        match self {
            Self::Sig(proof) => proof.receipt,
            Self::P2WSH(proof) => proof.receipt,
            Self::P2TR(proof) => proof.receipt,
            #[cfg(feature = "bulletproof")]
            Self::Bulletproof(bulletproof) => bulletproof.receipt,
            Self::EmptyReceipt(_) => Receipt::empty(),
            Self::Multisig(proof) => proof.receipt,
            Self::Lightning(proof) => proof.receipt,
            Self::LightningHtlc(proof) => proof.receipt,
            Self::SparkExit(proof) => proof.receipt,
        }
    }

    #[inline]
    pub fn metadata(&self) -> Option<Value> {
        match self {
            Self::Sig(proof) => proof.metadata.to_owned(),
            Self::P2TR(proof) => proof.metadata.to_owned(),
            #[cfg(feature = "bulletproof")]
            Self::Bulletproof(_) => None,
            _ => None,
        }
    }

    pub fn p2wsh(
        receipt: impl Into<Receipt>,
        inner_key: secp256k1::PublicKey,
        script: impl Into<ScriptBuf>,
    ) -> Self {
        Self::P2WSH(Box::new(p2wsh::P2WSHProof::new(
            receipt.into(),
            inner_key,
            script.into(),
        )))
    }

    pub fn p2tr(
        receipt: impl Into<Receipt>,
        inner_key: secp256k1::PublicKey,
        metadata: Option<Value>,
    ) -> Self {
        Self::P2TR(TaprootProof::new(receipt.into(), inner_key, metadata))
    }

    pub fn sig(
        receipt: impl Into<Receipt>,
        inner_key: secp256k1::PublicKey,
        metadata: Option<Value>,
    ) -> Self {
        Self::Sig(P2WPKHProof::new(receipt.into(), inner_key, metadata))
    }

    pub fn empty(inner_key: impl Into<secp256k1::PublicKey>) -> Self {
        Self::EmptyReceipt(empty::EmptyReceiptProof::new(inner_key.into()))
    }

    pub fn lightning_commitment(
        receipt: impl Into<Receipt>,
        revocation_pubkey: impl Into<secp256k1::PublicKey>,
        to_self_delay: u16,
        local_delayed_pubkey: impl Into<secp256k1::PublicKey>,
    ) -> Self {
        Self::Lightning(LightningCommitmentProof::new(
            receipt.into(),
            revocation_pubkey.into(),
            to_self_delay,
            local_delayed_pubkey.into(),
        ))
    }

    pub fn lightning_htlc(receipt: impl Into<Receipt>, data: LightningHtlcData) -> Self {
        Self::LightningHtlc(LightningHtlcProof::new(receipt.into(), data))
    }

    pub fn spark_exit(
        receipt: impl Into<Receipt>,
        revocation_pubkey: impl Into<secp256k1::PublicKey>,
        locktime: u32,
        delay_pubkey: impl Into<secp256k1::PublicKey>,
        metadata: Option<Value>,
    ) -> Self {
        Self::SparkExit(SparkExitProof::new(
            receipt.into(),
            SparkExitScript::new(revocation_pubkey.into(), locktime, delay_pubkey.into()),
            metadata,
        ))
    }

    pub fn amount(&self) -> u128 {
        self.receipt().token_amount.amount
    }

    /// Returns `true` if the proof amount is zero
    pub fn is_zero_amount(&self) -> bool {
        self.amount() == 0
    }

    #[cfg(feature = "bulletproof")]
    pub fn bulletproof(bulletproof: bulletproof::Bulletproof) -> Self {
        Self::Bulletproof(alloc::boxed::Box::new(bulletproof))
    }

    #[cfg(feature = "bulletproof")]
    pub fn is_bulletproof(&self) -> bool {
        matches!(self, Self::Bulletproof(_))
    }

    pub fn is_burn(&self) -> bool {
        let ReceiptProof::Sig(inner) = self else {
            return false;
        };

        inner.inner_key == *crate::ZERO_PUBLIC_KEY
    }

    pub fn is_empty_receiptproof(&self) -> bool {
        matches!(self, Self::EmptyReceipt(_))
    }

    /// Return keys that could spend this output.
    pub fn spender_keys(&self) -> Vec<secp256k1::PublicKey> {
        match self {
            Self::Sig(sig_proof) => vec![sig_proof.inner_key],
            Self::Multisig(multisig_proof) => multisig_proof.inner_keys.clone(),
            Self::P2TR(taproot_proof) => vec![taproot_proof.inner_key],
            Self::Lightning(lightning_proof) => vec![
                lightning_proof.data.revocation_pubkey,
                lightning_proof.data.local_delayed_pubkey,
            ],
            #[cfg(feature = "bulletproof")]
            Self::Bulletproof(bulletproof) => {
                vec![bulletproof.inner_key, bulletproof.sender_key]
            }
            Self::LightningHtlc(htlc) => vec![htlc.data.remote_htlc_key, htlc.data.local_htlc_key],
            Self::EmptyReceipt(empty_receiptproof) => {
                vec![empty_receiptproof.inner_key]
            }
            Self::P2WSH(p2wsh_proof) => vec![p2wsh_proof.inner_key],
            Self::SparkExit(spark_exit_proof) => vec![spark_exit_proof.script.delay_key],
        }
    }

    #[cfg(feature = "bulletproof")]
    pub fn get_bulletproof(&self) -> Option<&bulletproof::Bulletproof> {
        match self {
            Self::Bulletproof(bulletproof) => Some(bulletproof),
            _ => None,
        }
    }
}

/// Trait for proof that can be checked by transaction input or output.
pub trait CheckableProof {
    /// Check the proof by transaction with fallback to `false` on error.
    fn check_by_input(&self, txin: &TxIn) -> bool {
        self.checked_check_by_input(txin).is_ok()
    }

    /// Check the proof by transaction with fallback to `false` on error.
    fn check_by_output(&self, txout: &TxOut) -> bool {
        self.checked_check_by_output(txout).is_ok()
    }

    /// Error type that can be returned by check methods.
    type Error;

    /// Check the proof by transaction input.
    fn checked_check_by_input(&self, txin: &TxIn) -> Result<(), Self::Error>;

    /// Check the proof by transaction output.
    fn checked_check_by_output(&self, txout: &TxOut) -> Result<(), Self::Error>;
}

impl CheckableProof for ReceiptProof {
    type Error = ReceiptProofError;

    fn checked_check_by_input(&self, txin: &TxIn) -> Result<(), Self::Error> {
        match self {
            Self::Sig(proof) => proof.checked_check_by_input(txin)?,
            Self::P2WSH(proof) => proof.checked_check_by_input(txin)?,
            Self::P2TR(proof) => proof.checked_check_by_input(txin)?,
            Self::EmptyReceipt(proof) => proof.checked_check_by_input(txin)?,
            Self::Multisig(proof) => proof.checked_check_by_input(txin)?,
            Self::Lightning(proof) => proof.checked_check_by_input(txin)?,
            Self::LightningHtlc(proof) => proof.checked_check_by_input(txin)?,
            Self::SparkExit(proof) => proof.checked_check_by_input(txin)?,
            #[cfg(feature = "bulletproof")]
            Self::Bulletproof(bulletproof) => bulletproof.checked_check_by_input(txin)?,
        };

        Ok(())
    }

    fn checked_check_by_output(&self, txout: &TxOut) -> Result<(), Self::Error> {
        match self {
            Self::Sig(proof) => proof.checked_check_by_output(txout)?,
            Self::EmptyReceipt(proof) => proof.checked_check_by_output(txout)?,
            Self::Multisig(proof) => proof.checked_check_by_output(txout)?,
            Self::P2TR(proof) => proof.checked_check_by_output(txout)?,
            Self::Lightning(proof) => proof.checked_check_by_output(txout)?,
            Self::LightningHtlc(proof) => proof.checked_check_by_output(txout)?,
            Self::P2WSH(proof) => proof.checked_check_by_output(txout)?,
            Self::SparkExit(proof) => proof.checked_check_by_output(txout)?,
            #[cfg(feature = "bulletproof")]
            Self::Bulletproof(bulletproof) => bulletproof.checked_check_by_output(txout)?,
        };

        Ok(())
    }
}

impl From<P2WPKHProof> for ReceiptProof {
    fn from(proof: P2WPKHProof) -> Self {
        Self::Sig(proof)
    }
}

impl<T> From<T> for ReceiptProof
where
    T: Into<P2WSHProof>,
{
    fn from(proof: T) -> Self {
        Self::P2WSH(Box::new(proof.into()))
    }
}

macro_rules! impl_from {
    ($proof:ty, $variant:ident) => {
        impl From<$proof> for ReceiptProof {
            fn from(proof: $proof) -> Self {
                Self::$variant(proof)
            }
        }
    };
}

impl_from!(MultisigReceiptProof, Multisig);
impl_from!(TaprootProof, P2TR);
impl_from!(SparkExitProof, SparkExit);
impl_from!(LightningCommitmentProof, Lightning);
impl_from!(LightningHtlcProof, LightningHtlc);
