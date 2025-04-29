use alloc::string::ToString;
use alloc::vec::Vec;

use bitcoin::ecdsa;

use crate::proof::p2wsh::{
    errors::P2WSHWitnessParseError,
    witness::{FromWitnessStack, IntoWitnessStack, P2WSHWitness},
};

pub type MultisigWitness = P2WSHWitness<MultisigWitnessStack>;

/// A wrapper around vector of signatures. Required as implementation
/// of both [`FromWintessStack`] and [`IntoWintessStack`] require adding
/// a 0x00 byte at the beginning of the stack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultisigWitnessStack(pub Vec<ecdsa::Signature>);

impl From<Vec<ecdsa::Signature>> for MultisigWitnessStack {
    fn from(value: Vec<ecdsa::Signature>) -> Self {
        Self(value)
    }
}

impl FromWitnessStack for MultisigWitnessStack {
    fn from_witness_stack(stack: &[Vec<u8>]) -> Result<Self, P2WSHWitnessParseError> {
        // first stack element must be a 0x00 (an empty byte vector)
        let _ = stack.first().ok_or_else(|| {
            P2WSHWitnessParseError::Custom("Empty stack element is missing".to_string())
        })?;

        // Other stack elements must be signatures
        let rest = stack.get(1..).ok_or_else(|| {
            P2WSHWitnessParseError::Custom(
                "At least one signature in Musig must be presented".to_string(),
            )
        })?;

        // parse the rest of the stack elements as signatures
        Ok(MultisigWitnessStack(Vec::from_witness_stack(rest)?))
    }
}

impl IntoWitnessStack for MultisigWitnessStack {
    fn into_witness_stack(self) -> Vec<Vec<u8>> {
        // first stack element must be a 0x00 (an empty byte vector),
        // and the rest are signatures
        let mut stack = Vec::with_capacity(self.0.len() + 1);

        // empty vec
        stack.push(Vec::new());
        // signatures
        stack.extend(self.0.into_witness_stack());

        stack
    }
}
