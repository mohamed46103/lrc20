use bitcoin::{Witness, secp256k1::schnorr::Signature};

use super::errors::TaprootWitnessParseError;

/// Data that spends a Taproot output.
pub enum TaprootSparkWitness {
    KeySpend(Signature),
    ScriptPath(Signature),
}

impl TaprootSparkWitness {
    /// Parse a witness into a [`TaprootSparkWitness`].
    pub fn from_witness(witness: &Witness) -> Result<Self, TaprootWitnessParseError> {
        let mut witness_iter = witness.iter();
        let signature_bytes = witness_iter
            .next()
            .ok_or(TaprootWitnessParseError::MissingWitnessSignature)?;

        let signature = Signature::from_slice(signature_bytes)?;

        if witness.len() == 1 {
            Ok(Self::KeySpend(signature))
        } else {
            Ok(Self::ScriptPath(signature))
        }
    }
}

impl TryFrom<&Witness> for TaprootSparkWitness {
    type Error = TaprootWitnessParseError;

    fn try_from(witness: &Witness) -> Result<Self, Self::Error> {
        TaprootSparkWitness::from_witness(witness)
    }
}
