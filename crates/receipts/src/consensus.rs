use alloc::boxed::Box;
use bitcoin::consensus::{Decodable, Encodable, encode::Error as EncodeError};
use core2::io;

#[cfg(feature = "bulletproof")]
use crate::proof::bulletproof::Bulletproof;
use crate::{
    EmptyReceiptProof, LightningCommitmentProof, LightningHtlcProof, MultisigReceiptProof,
    RECEIPT_SIZE, Receipt,
    proof::{
        ReceiptProof, p2tr::TaprootProof, p2wpkh::P2WPKHProof, p2wsh::P2WSHProof,
        spark::exit::SparkExitProof,
    },
};

/// Receipt proof flags
const P2WPKH_FLAG: u8 = 0u8;
const MULTISIG_FLAG: u8 = 1u8;
const LIGHTNING_FLAG: u8 = 2u8;
const LIGHTNING_HTLC_FLAG: u8 = 3u8;
#[cfg(feature = "bulletproof")]
const BULLETPROOF_FLAG: u8 = 4u8;
const EMPTY_RECEIPT_FLAG: u8 = 5u8;
const P2WSH_FLAG: u8 = 6u8;
const P2TR_FLAG: u8 = 7u8;
const SPARK_EXIT_FLAG: u8 = 8u8;

impl Encodable for Receipt {
    fn consensus_encode<W: io::Write + ?Sized>(&self, writer: &mut W) -> Result<usize, io::Error> {
        writer.write_all(&self.to_bytes())?;
        Ok(RECEIPT_SIZE)
    }
}

impl Decodable for Receipt {
    fn consensus_decode<R: io::Read + ?Sized>(reader: &mut R) -> Result<Self, EncodeError> {
        let mut bytes = [0u8; RECEIPT_SIZE];
        reader.read_exact(&mut bytes)?;

        Receipt::from_bytes(&bytes)
            .map_err(|_| EncodeError::ParseFailed("failed to parse the Receipt"))
    }
}

impl Encodable for ReceiptProof {
    fn consensus_encode<W: io::Write + ?Sized>(&self, writer: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;

        match self {
            ReceiptProof::Sig(proof) => {
                len += P2WPKH_FLAG.consensus_encode(writer)?;
                len += proof.consensus_encode(writer)?;
            }
            ReceiptProof::P2WSH(proof) => {
                len += P2WSH_FLAG.consensus_encode(writer)?;
                len += proof.consensus_encode(writer)?;
            }
            ReceiptProof::P2TR(proof) => {
                len += P2TR_FLAG.consensus_encode(writer)?;
                len += proof.consensus_encode(writer)?;
            }
            #[cfg(feature = "bulletproof")]
            ReceiptProof::Bulletproof(bulletproof) => {
                len += BULLETPROOF_FLAG.consensus_encode(writer)?;
                len += bulletproof.consensus_encode(writer)?;
            }
            ReceiptProof::EmptyReceipt(proof) => {
                len += EMPTY_RECEIPT_FLAG.consensus_encode(writer)?;
                len += proof.consensus_encode(writer)?;
            }
            ReceiptProof::Multisig(proof) => {
                len += MULTISIG_FLAG.consensus_encode(writer)?;
                len += proof.consensus_encode(writer)?;
            }
            ReceiptProof::Lightning(proof) => {
                len += LIGHTNING_FLAG.consensus_encode(writer)?;
                len += proof.consensus_encode(writer)?;
            }
            ReceiptProof::LightningHtlc(proof) => {
                len += LIGHTNING_HTLC_FLAG.consensus_encode(writer)?;
                len += proof.consensus_encode(writer)?;
            }
            ReceiptProof::SparkExit(proof) => {
                len += SPARK_EXIT_FLAG.consensus_encode(writer)?;
                len += proof.consensus_encode(writer)?;
            }
        }

        Ok(len)
    }
}

impl Decodable for ReceiptProof {
    fn consensus_decode<R: io::Read + ?Sized>(reader: &mut R) -> Result<Self, EncodeError> {
        let flag: u8 = Decodable::consensus_decode(reader)?;

        match flag {
            P2WPKH_FLAG => {
                let proof: P2WPKHProof = Decodable::consensus_decode(reader)?;
                Ok(ReceiptProof::Sig(proof))
            }
            P2WSH_FLAG => {
                let proof: P2WSHProof = Decodable::consensus_decode(reader)?;
                Ok(ReceiptProof::P2WSH(Box::new(proof)))
            }
            P2TR_FLAG => {
                let proof: TaprootProof = Decodable::consensus_decode(reader)?;
                Ok(ReceiptProof::P2TR(proof))
            }
            #[cfg(feature = "bulletproof")]
            BULLETPROOF_FLAG => {
                let proof: Bulletproof = Decodable::consensus_decode(reader)?;
                Ok(ReceiptProof::Bulletproof(Box::new(proof)))
            }
            EMPTY_RECEIPT_FLAG => {
                let proof: EmptyReceiptProof = Decodable::consensus_decode(reader)?;
                Ok(ReceiptProof::EmptyReceipt(proof))
            }
            MULTISIG_FLAG => {
                let proof: MultisigReceiptProof = Decodable::consensus_decode(reader)?;
                Ok(ReceiptProof::Multisig(proof))
            }
            LIGHTNING_FLAG => {
                let proof: LightningCommitmentProof = Decodable::consensus_decode(reader)?;
                Ok(ReceiptProof::Lightning(proof))
            }
            LIGHTNING_HTLC_FLAG => {
                let proof: LightningHtlcProof = Decodable::consensus_decode(reader)?;
                Ok(ReceiptProof::LightningHtlc(proof))
            }
            SPARK_EXIT_FLAG => {
                let proof: SparkExitProof = Decodable::consensus_decode(reader)?;
                Ok(ReceiptProof::SparkExit(proof))
            }
            _ => Err(EncodeError::ParseFailed("Unknown receipt proof")),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;
    use core::str::FromStr;

    use bitcoin::{
        consensus::{Decodable, Encodable},
        hashes::hash160,
        secp256k1,
    };
    use once_cell::sync::Lazy;

    #[cfg(feature = "bulletproof")]
    use crate::Bulletproof;
    use crate::LightningCommitmentProof;
    use crate::MultisigReceiptProof;
    use crate::Receipt;
    use crate::ReceiptProof;
    use crate::SigReceiptProof;
    use crate::{
        LightningHtlcData,
        proof::common::lightning::{commitment::script::ToLocalScript, htlc},
    };
    use crate::{LightningHtlcProof, TokenPubkey};
    #[cfg(feature = "bulletproof")]
    use bitcoin::secp256k1::schnorr::Signature;
    use serde_json::json;

    static PUBKEY: Lazy<secp256k1::PublicKey> = Lazy::new(|| {
        secp256k1::PublicKey::from_str(
            "03ab5575d69e46968a528cd6fa2a35dd7808fea24a12b41dc65c7502108c75f9a9",
        )
        .unwrap()
    });

    static HASH: Lazy<hash160::Hash> =
        Lazy::new(|| hash160::Hash::from_str("321ac998e78433e57a85171aa77bfad1d205ee3d").unwrap());

    #[cfg(feature = "bulletproof")]
    static SIG: Lazy<Signature> = Lazy::new(|| {
        Signature::from_str("32445f89b0fefe7dac06c6716c926ccd603cec8dd365a14ecb190a035617ec2700f0adad05e0d9912fb2eeaa336afd76fd752a1842c66d556d82f9f8c6e504aa")
            .unwrap()
    });

    #[cfg(feature = "bulletproof")]
    const BLINDING: [u8; 32] = [
        3, 123, 39, 117, 182, 201, 184, 57, 234, 12, 107, 82, 90, 37, 40, 13, 64, 45, 75, 160, 31,
        125, 243, 23, 141, 174, 13, 35, 231, 242, 197, 49,
    ];

    #[test]
    fn test_sig_receipt_proof_consensus_encode() {
        let token_pubkey = TokenPubkey::new(*PUBKEY);
        let receipt = Receipt::new(100, token_pubkey);

        let proof = SigReceiptProof::new(receipt, *PUBKEY, None);

        let mut bytes = Vec::new();

        proof
            .consensus_encode(&mut bytes)
            .expect("failed to encode the proof");

        let decoded_proof = SigReceiptProof::consensus_decode(&mut bytes.as_slice())
            .expect("failed to decode the proof");

        assert_eq!(
            proof, decoded_proof,
            "Converting back and forth should work"
        );
    }

    #[test]
    fn test_sig_receipt_proof_with_metadata_consensus_encode() {
        let token_pubkey = TokenPubkey::new(*PUBKEY);
        let receipt = Receipt::new(100, token_pubkey);

        let metadata = json!({
            "type": "SparkDeposit",
            "deposit_pubkey": "035dbc016089977223ebc5db0398ce0988e44645e4a16e5129601e1f09cc9751fa"
        });

        let proof = SigReceiptProof::new(receipt, *PUBKEY, Some(metadata));

        let mut bytes = Vec::new();

        proof
            .consensus_encode(&mut bytes)
            .expect("failed to encode the proof");

        let decoded_proof = SigReceiptProof::consensus_decode(&mut bytes.as_slice())
            .expect("failed to decode the proof");

        assert_eq!(
            proof, decoded_proof,
            "Converting back and forth should work"
        );
    }

    #[test]
    fn test_multisig_receipt_proof_consensus_encode() {
        let token_pubkey = TokenPubkey::new(*PUBKEY);
        let receipt = Receipt::new(100, token_pubkey);
        let inner_keys = vec![*PUBKEY, *PUBKEY, *PUBKEY];

        let proof = MultisigReceiptProof::new(receipt, inner_keys, 2);

        let mut bytes = Vec::new();

        proof
            .consensus_encode(&mut bytes)
            .expect("failed to encode the proof");

        let decoded_proof = MultisigReceiptProof::consensus_decode(&mut bytes.as_slice())
            .expect("failed to decode the proof");

        assert_eq!(
            proof, decoded_proof,
            "Converting back and forth should work"
        );
    }

    #[test]
    fn test_lightning_commitment_proof_consensus_encode() {
        let token_pubkey = TokenPubkey::new(*PUBKEY);
        let receipt = Receipt::new(100, token_pubkey);

        let proof = LightningCommitmentProof {
            receipt,
            data: ToLocalScript::new(*PUBKEY, 100, *PUBKEY),
        };

        let mut bytes = Vec::new();

        proof
            .consensus_encode(&mut bytes)
            .expect("failed to encode the proof");

        let decoded_proof = LightningCommitmentProof::consensus_decode(&mut bytes.as_slice())
            .expect("failed to decode the proof");

        assert_eq!(
            proof, decoded_proof,
            "Converting back and forth should work"
        );
    }

    #[test]
    fn test_lightning_htlc_proof_consensus_encode() {
        let token_pubkey = TokenPubkey::new(*PUBKEY);
        let receipt = Receipt::new(100, token_pubkey);

        let proof = LightningHtlcProof::new(
            receipt,
            LightningHtlcData::new(
                *HASH,
                *PUBKEY,
                *PUBKEY,
                *HASH,
                htlc::HtlcScriptKind::Received { cltv_expiry: 100 },
            ),
        );

        let mut bytes = Vec::new();

        proof
            .consensus_encode(&mut bytes)
            .expect("failed to encode the proof");

        let decoded_proof = LightningHtlcProof::consensus_decode(&mut bytes.as_slice())
            .expect("failed to decode the proof");

        assert_eq!(
            proof, decoded_proof,
            "Converting back and forth should work"
        );
    }

    #[test]
    #[cfg(feature = "bulletproof")]
    fn test_bulletproof_consensus_encode() {
        let token_pubkey = TokenPubkey::new(*PUBKEY);
        let receipt = Receipt::new(100, token_pubkey);

        let (range_proof, point) = bulletproof::generate(100, BLINDING);

        let proof = Bulletproof::new(receipt, *PUBKEY, *PUBKEY, point, range_proof, *SIG, *SIG);

        let mut bytes = Vec::new();

        proof
            .consensus_encode(&mut bytes)
            .expect("failed to encode the proof");

        let decoded_proof = Bulletproof::consensus_decode(&mut bytes.as_slice())
            .expect("failed to decode the proof");

        assert_eq!(
            proof, decoded_proof,
            "Converting back and forth should work"
        );
    }

    #[test]
    fn test_receipt_proofs_consensus_encode() {
        let token_pubkey = TokenPubkey::new(*PUBKEY);
        let receipt = Receipt::new(100, token_pubkey);

        #[cfg(feature = "bulletproof")]
        let (range_proof, point) = bulletproof::generate(100, BLINDING);

        let proofs: Vec<ReceiptProof> = vec![
            ReceiptProof::Sig(SigReceiptProof::new(receipt, *PUBKEY, None)),
            ReceiptProof::Multisig(MultisigReceiptProof::new(
                receipt,
                vec![*PUBKEY, *PUBKEY, *PUBKEY],
                2,
            )),
            ReceiptProof::Lightning(LightningCommitmentProof {
                receipt,
                data: ToLocalScript::new(*PUBKEY, 100, *PUBKEY),
            }),
            ReceiptProof::LightningHtlc(LightningHtlcProof::new(
                receipt,
                LightningHtlcData::new(
                    *HASH,
                    *PUBKEY,
                    *PUBKEY,
                    *HASH,
                    htlc::HtlcScriptKind::Received { cltv_expiry: 100 },
                ),
            )),
            #[cfg(feature = "bulletproof")]
            ReceiptProof::Bulletproof(Box::new(Bulletproof::new(
                receipt,
                *PUBKEY,
                *PUBKEY,
                point,
                range_proof,
                *SIG,
                *SIG,
            ))),
        ];

        for proof in &proofs {
            let mut bytes = Vec::new();

            proof
                .consensus_encode(&mut bytes)
                .expect("failed to encode the proof");

            let decoded_proof = ReceiptProof::consensus_decode(&mut bytes.as_slice())
                .expect("failed to decode the proof");

            assert_eq!(
                proof, &decoded_proof,
                "Converting back and forth should work"
            );
        }
    }

    #[test]
    fn test_receipt_consensus_parsing() {
        let receipt = Receipt::new(100, *PUBKEY);

        let mut bytes = Vec::new();

        receipt
            .consensus_encode(&mut bytes)
            .expect("failed to encode receipt");

        let decoded_receipt =
            Receipt::consensus_decode(&mut bytes.as_slice()).expect("failed to decode receipt");

        assert_eq!(
            receipt, decoded_receipt,
            "Converting back and forth should work"
        );
    }
}
